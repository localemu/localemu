"""Redshift provider with optional Docker-backed Postgres clusters.

Default (no env var): moto fallback. The API succeeds, the endpoint
hostname is the AWS-style ``<cluster>.<hash>.<region>.redshift.amazonaws.com``,
but the hostname doesn't resolve so psql / JDBC drivers can't reach
anything. Matches the historical LocalEmu behavior.

With ``REDSHIFT_DOCKER_BACKEND=1``: ``CreateCluster`` boots a real
``postgres:15`` container and surfaces ``localhost:<host_port>`` as the
endpoint. Redshift's wire protocol is Postgres-compatible, so psql and
JDBC clients connect for real.
"""

from __future__ import annotations

import logging
import os
import threading

from moto.redshift.models import redshift_backends

from localemu import config
from localemu.aws.api import RequestContext, ServiceRequest, ServiceResponse, handler
from localemu.aws.api.redshift import (
    ClusterSecurityGroupMessage,
    DescribeClusterSecurityGroupsMessage,
    RedshiftApi,
)
from localemu.services.moto import call_moto
from localemu.state import AssetDirectory, StateVisitor

LOG = logging.getLogger(__name__)


_cluster_manager = None
_cluster_manager_lock = threading.Lock()


def _init_cluster_manager():
    """Lazy-init the docker manager. ``REDSHIFT_DOCKER_BACKEND=1`` opt-in."""
    global _cluster_manager
    if _cluster_manager is not None:
        return _cluster_manager
    with _cluster_manager_lock:
        if _cluster_manager is not None:
            return _cluster_manager
        if os.environ.get("REDSHIFT_DOCKER_BACKEND", "").strip() != "1":
            return None
        try:
            from localemu.services.redshift.docker.cluster_manager import (
                DockerClusterManager,
            )
            from localemu.utils.docker_utils import DOCKER_CLIENT

            if DOCKER_CLIENT.has_docker():
                _cluster_manager = DockerClusterManager()
                LOG.info("Redshift Docker backend enabled.")
            else:
                LOG.warning(
                    "REDSHIFT_DOCKER_BACKEND=1 but Docker is not available; "
                    "falling back to metadata-only mode.",
                )
        except Exception as e:
            LOG.warning("Failed to initialize Redshift Docker backend: %s", e)
        return _cluster_manager


class RedshiftProvider(RedshiftApi):
    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(redshift_backends)
        visitor.visit(AssetDirectory(self.service, os.path.join(config.dirs.data, "redshift")))

    @handler("CreateCluster", expand=False)
    def create_cluster(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        """CreateCluster: let moto record it, then boot a Postgres container."""
        result = call_moto(context)
        mgr = _init_cluster_manager()
        if mgr is None or not result.get("Cluster"):
            return result

        cluster = result["Cluster"]
        cluster_id = cluster.get("ClusterIdentifier") or request.get("ClusterIdentifier")
        if not cluster_id:
            return result

        master_user = request.get("MasterUsername") or cluster.get("MasterUsername") or "admin"
        master_pwd = request.get("MasterUserPassword") or ""
        db_name = request.get("DBName") or cluster.get("DBName") or "dev"

        try:
            info = mgr.create_cluster(
                cluster_id=cluster_id,
                master_username=master_user,
                master_password=master_pwd,
                db_name=db_name,
            )
            # Surface a reachable endpoint instead of moto's fake AWS hostname.
            cluster.setdefault("Endpoint", {})
            cluster["Endpoint"]["Address"] = "localhost"
            cluster["Endpoint"]["Port"] = info.host_port
            cluster["ClusterStatus"] = "available"
            cluster["ClusterAvailabilityStatus"] = "Available"
        except ValueError as e:
            LOG.warning("Redshift CreateCluster ID conflict: %s", e)
        except Exception as e:
            LOG.warning("Redshift Docker create failed for %s: %s", cluster_id, e)
            try:
                cluster["ClusterStatus"] = "create-failed"
            except Exception:
                pass
        return result

    @handler("DeleteCluster", expand=False)
    def delete_cluster(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        cluster_id = request.get("ClusterIdentifier")
        result = call_moto(context)
        mgr = _init_cluster_manager()
        if mgr is not None and cluster_id:
            try:
                mgr.delete_cluster(cluster_id)
            except Exception:
                LOG.debug("Redshift delete-cluster docker cleanup failed", exc_info=True)
        return result

    @handler("DescribeClusters", expand=False)
    def describe_clusters(self, context: RequestContext, request: ServiceRequest) -> ServiceResponse:
        """DescribeClusters: overlay the real docker endpoint when present."""
        result = call_moto(context)
        mgr = _init_cluster_manager()
        if mgr is None or not isinstance(result, dict):
            return result
        for cluster in result.get("Clusters", []) or []:
            cid = cluster.get("ClusterIdentifier")
            info = mgr.get_cluster_info(cid) if cid else None
            if info is None:
                continue
            cluster.setdefault("Endpoint", {})
            cluster["Endpoint"]["Address"] = "localhost"
            cluster["Endpoint"]["Port"] = info.host_port
            cluster["ClusterStatus"] = info.status
        return result

    @handler("DescribeClusterSecurityGroups", expand=False)
    def describe_cluster_security_groups(
        self,
        context: RequestContext,
        request: DescribeClusterSecurityGroupsMessage,
    ) -> ClusterSecurityGroupMessage:
        result = call_moto(context)
        backend = redshift_backends[context.account_id][context.region]
        for group in result.get("ClusterSecurityGroups", []):
            if group.get("IPRanges"):
                continue
            name = group.get("ClusterSecurityGroupName")
            if not name:
                # Malformed entry — skip silently instead of crashing the
                # entire describe call with an AttributeError on None.
                continue
            sgroup = backend.security_groups.get(name)
            if sgroup is None:
                continue
            group["IPRanges"] = [
                {"Status": "authorized", "CIDRIP": ip} for ip in sgroup.ingress_rules
            ]
        return result
