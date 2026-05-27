"""Amazon MSK (Managed Streaming for Apache Kafka) — real broker backend.

Moto's kafka backend keeps metadata only. CreateCluster returns a fake
ARN and the cluster sits in ``CREATING`` forever; any
``GetBootstrapBrokers`` call returns an empty string and a real
``kafka-python`` connect from a test client hits nothing on the wire.

This provider replaces the moto stub: CreateCluster boots a real
Apache Kafka 3.7.1 container in KRaft mode, the bootstrap-brokers
response points at ``127.0.0.1:<allocated-port>``, and DeleteCluster
removes the container. Opt-in via ``MSK_DOCKER_BACKEND=1``; with the
flag off the provider stays metadata-only via the moto fallback.
"""

from __future__ import annotations

import logging
import os

from localemu.aws.api import RequestContext
from localemu.aws.api.kafka import (
    BrokerNodeGroupInfo,
    ClientAuthentication,
    ConfigurationInfo,
    CreateClusterResponse,
    DeleteClusterResponse,
    DescribeClusterResponse,
    EncryptionInfo,
    EnhancedMonitoring,
    GetBootstrapBrokersResponse,
    KafkaApi,
    ListClustersResponse,
    ListNodesResponse,
    LoggingInfo,
    OpenMonitoringInfo,
    Rebalancing,
    StorageMode,
)
from localemu.services.moto import call_moto
from localemu.services.plugins import ServiceLifecycleHook
from localemu.services.kafka.docker.cluster_manager import (
    BrokerInfo,
    ClusterManager,
)
from localemu.state import StateVisitor

LOG = logging.getLogger(__name__)


def _docker_enabled() -> bool:
    """Opt-in flag. Apache Kafka image is ~600 MB so default-on would
    be a surprise. Mirrors RDS / MQ."""
    return os.environ.get("MSK_DOCKER_BACKEND", "").strip().lower() in {"1", "true"}


class KafkaProvider(KafkaApi, ServiceLifecycleHook):
    """Custom MSK provider with Docker-backed cluster lifecycle."""

    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.kafka.models import kafka_backends

        visitor.visit(kafka_backends)

    # ------------------------------------------------------------------
    # Cluster lifecycle
    # ------------------------------------------------------------------
    def create_cluster(
        self,
        context: RequestContext,
        broker_node_group_info: BrokerNodeGroupInfo,
        kafka_version: str,
        number_of_broker_nodes: int,
        cluster_name: str,
        rebalancing: Rebalancing | None = None,
        client_authentication: ClientAuthentication | None = None,
        configuration_info: ConfigurationInfo | None = None,
        encryption_info: EncryptionInfo | None = None,
        enhanced_monitoring: EnhancedMonitoring | None = None,
        open_monitoring: OpenMonitoringInfo | None = None,
        logging_info: LoggingInfo | None = None,
        tags: dict[str, str] | None = None,
        storage_mode: StorageMode | None = None,
        **kwargs,
    ) -> CreateClusterResponse:
        result = call_moto(context)
        cluster_arn = result.get("ClusterArn")
        if not cluster_arn or not _docker_enabled():
            if cluster_arn and not _docker_enabled():
                LOG.info(
                    "MSK_DOCKER_BACKEND not set; cluster %s recorded in moto only. "
                    "Set MSK_DOCKER_BACKEND=1 to boot a real Kafka container.",
                    cluster_arn,
                )
            return result
        moto_cluster = self._moto_cluster(context, cluster_arn)
        if moto_cluster is None:
            return result
        try:
            ClusterManager.instance().create_cluster(
                cluster_arn=cluster_arn,
                cluster_id=moto_cluster.cluster_id,
                kafka_version=kafka_version,
                number_of_brokers=number_of_broker_nodes,
            )
            moto_cluster.state = "ACTIVE"
        except Exception:
            LOG.warning(
                "CreateCluster %s docker provisioning failed", cluster_arn, exc_info=True,
            )
            moto_cluster.state = "FAILED"
        return result

    def describe_cluster(
        self, context: RequestContext, cluster_arn: str, **kwargs,
    ) -> DescribeClusterResponse:
        # Moto's DescribeCluster raises a bare KeyError on an unknown
        # ClusterArn — the skeleton surfaces it as InternalError 500
        # instead of the AWS-shaped NotFoundException 404. Pre-check the
        # backend so a polled-after-delete describe gets the right
        # error code (clients commonly retry until they see 404).
        backend = self._moto_kafka_backend(context)
        if backend is not None and cluster_arn not in getattr(backend, "clusters", {}):
            from localemu.aws.api import CommonServiceException

            raise CommonServiceException(
                "NotFoundException",
                f"Cluster {cluster_arn!r} does not exist.",
                status_code=404,
            )
        result = call_moto(context)
        if not _docker_enabled() or not isinstance(result, dict):
            return result
        info = result.get("ClusterInfo") or {}
        brokers = ClusterManager.instance().get_cluster(cluster_arn)
        if brokers:
            info["State"] = "ACTIVE"
            info["NumberOfBrokerNodes"] = len(brokers)
        result["ClusterInfo"] = info
        return result

    def list_clusters(
        self,
        context: RequestContext,
        cluster_name_filter: str | None = None,
        max_results: int | None = None,
        next_token: str | None = None,
        **kwargs,
    ) -> ListClustersResponse:
        result = call_moto(context)
        if not _docker_enabled() or not isinstance(result, dict):
            return result
        mgr = ClusterManager.instance()
        for entry in result.get("ClusterInfoList", []) or []:
            arn = entry.get("ClusterArn", "")
            if mgr.get_cluster(arn):
                entry["State"] = "ACTIVE"
        return result

    def delete_cluster(
        self,
        context: RequestContext,
        cluster_arn: str,
        current_version: str | None = None,
        **kwargs,
    ) -> DeleteClusterResponse:
        if _docker_enabled():
            try:
                ClusterManager.instance().delete_cluster(cluster_arn)
            except Exception:
                LOG.debug(
                    "delete_cluster docker cleanup failed for %s",
                    cluster_arn, exc_info=True,
                )
        return call_moto(context)

    def get_bootstrap_brokers(
        self, context: RequestContext, cluster_arn: str, **kwargs,
    ) -> GetBootstrapBrokersResponse:
        if not _docker_enabled():
            return {"BootstrapBrokerString": ""}
        bootstrap = ClusterManager.instance().bootstrap_brokers(cluster_arn)
        return {"BootstrapBrokerString": bootstrap}

    def list_nodes(
        self,
        context: RequestContext,
        cluster_arn: str,
        max_results: int | None = None,
        next_token: str | None = None,
        **kwargs,
    ) -> ListNodesResponse:
        if not _docker_enabled():
            return {"NodeInfoList": []}
        brokers = ClusterManager.instance().get_cluster(cluster_arn) or []
        return {
            "NodeInfoList": [_node_info(b) for b in brokers],
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _moto_cluster(context: RequestContext, cluster_arn: str):
        try:
            from moto.kafka.models import kafka_backends

            backend = kafka_backends[context.account_id][context.region]
            return backend.clusters.get(cluster_arn)
        except Exception:
            LOG.debug("could not access moto kafka backend", exc_info=True)
            return None

    @staticmethod
    def _moto_kafka_backend(context: RequestContext):
        try:
            from moto.kafka.models import kafka_backends

            return kafka_backends[context.account_id][context.region]
        except Exception:
            return None


def _node_info(broker: BrokerInfo) -> dict:
    """Shape the AWS ListNodes API expects per node."""
    return {
        "BrokerNodeInfo": {
            "BrokerId": float(broker.broker_id),
            "ClientSubnet": "",
            "ClientVpcIpAddress": "127.0.0.1",
            "Endpoints": [f"127.0.0.1:{broker.host_plain_port}"],
        },
        "InstanceType": "kafka.m5.large",
        "NodeARN": f"{broker.cluster_arn}/broker/{broker.broker_id}",
        "NodeType": "BROKER",
        "AddedToClusterTime": "",
    }


def create_kafka_service():
    """Service factory wired from ``services/providers.py:kafka``."""
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.plugins import Service

    return Service.for_provider(
        KafkaProvider(), dispatch_table_factory=MotoFallbackDispatcher,
    )
