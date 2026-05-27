"""EKS provider with optional k3d-backed Kubernetes clusters.

Wraps Moto's EKS backend for CRUD operations and adds real k3s
Kubernetes clusters via k3d when EKS_K8S_PROVIDER=k3d. Each EKS
CreateCluster call starts a real Kubernetes control plane.

Architecture (same pattern as EC2/ECS Docker backends):
  1. Moto owns all state: clusters, nodegroups, metadata, ARNs.
  2. k3d provides execution: real k3s Kubernetes cluster in Docker.
  3. On CreateCluster, Moto creates the record, then k3d creates the
     real cluster. If k3d fails, the cluster status is set to CREATE_FAILED.
"""

import logging
import os
import threading

import moto.backends as moto_backends

from localemu.aws.api import RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.http import Response
from localemu.services.edge import ROUTER
from localemu.services.moto import _proxy_moto, call_moto
from localemu.services.plugins import Service, ServiceLifecycleHook

LOG = logging.getLogger(__name__)

_cluster_manager = None


def _init_cluster_manager():
    """Initialize the k3d-backed Kubernetes manager.

    Default is "k3d when the ``k3d`` binary is on PATH", matching the
    ECS / RDS Docker-backend posture: an EKS CreateCluster call should
    produce a kubectl-usable control plane out of the box. The legacy
    metadata-only mode is still reachable via ``EKS_K8S_PROVIDER=off``
    (or =none, =metadata, =moto). ``=k3d`` keeps working for users with
    automation that sets it explicitly.
    """
    global _cluster_manager
    if _cluster_manager is not None:
        return _cluster_manager

    setting = os.environ.get("EKS_K8S_PROVIDER", "").strip().lower()
    if setting in ("off", "none", "metadata", "moto", "disabled"):
        return None
    if setting and setting != "k3d":
        LOG.info(
            "EKS_K8S_PROVIDER=%r is not recognised; falling back to k3d when available.",
            setting,
        )

    # k3d binary check — if absent, stay metadata-only silently. We do
    # not want EKS CreateCluster to start failing on hosts without k3d
    # just because the default changed.
    import shutil

    if shutil.which("k3d") is None:
        if setting == "k3d":
            LOG.error("EKS_K8S_PROVIDER=k3d but the k3d binary is not on PATH.")
        else:
            LOG.debug(
                "k3d binary not found on PATH; EKS stays metadata-only. "
                "Install k3d (https://k3d.io/) for kubectl-usable clusters.",
            )
        return None

    try:
        from localemu.services.eks.cluster_manager import K3dClusterManager

        _cluster_manager = K3dClusterManager()
        LOG.info(
            "EKS k3d backend enabled. Set EKS_K8S_PROVIDER=off to disable.",
        )
    except Exception as e:
        LOG.error("Failed to initialize EKS k3d backend: %s", e)

    return _cluster_manager


def _handle_create_cluster(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """CreateCluster: let Moto create the record, then start a real k3d cluster.

    PARITY-09: Return CREATING status immediately, create cluster in background thread.
    PARITY-02: Pass version to k3d.
    """
    result = call_moto(context)

    mgr = _init_cluster_manager()
    if mgr and result.get("cluster"):
        cluster = result["cluster"]
        cluster_name = cluster.get("name")
        # PARITY-02: Extract Kubernetes version from request
        kubernetes_version = request.get("version")

        if cluster_name:
            # PARITY-09: Return CREATING status immediately, create in
            # background. The status has to be written into moto's stored
            # cluster object (not just the response dict) so DescribeCluster
            # returns CREATING for subsequent polls — otherwise the test
            # driver sees ACTIVE 0 s after CreateCluster and races the
            # k3d cluster create (which takes ~60-90 s).
            cluster["status"] = "CREATING"
            try:
                eks_backend = moto_backends.get_backend("eks")[context.account_id][context.region]
                moto_cluster_stored = eks_backend.clusters.get(cluster_name)
                if moto_cluster_stored:
                    moto_cluster_stored.status = "CREATING"
            except Exception:
                LOG.debug("Failed to write CREATING status into moto", exc_info=True)

            def _create_in_background():
                try:
                    info = mgr.create_cluster(
                        name=cluster_name,
                        kubernetes_version=kubernetes_version,
                        account_id=context.account_id,
                        region=context.region,
                    )
                    # BUG-05: Update the Moto cluster object with endpoint and CA cert
                    try:
                        eks_backend = moto_backends.get_backend("eks")[context.account_id][context.region]
                        moto_cluster = eks_backend.clusters.get(cluster_name)
                        if moto_cluster:
                            moto_cluster.endpoint = info.endpoint
                            moto_cluster.certificate_authority = info.ca_cert_data
                            moto_cluster.status = "ACTIVE"
                            # QUALITY-02: Store kubeconfig on the Moto object
                            moto_cluster.kubeconfig = info.kubeconfig
                    except Exception as e:
                        LOG.debug("Failed to update Moto cluster state: %s", e)

                    LOG.info(
                        "EKS cluster %s ready at %s",
                        cluster_name,
                        info.endpoint,
                    )
                except Exception as e:
                    LOG.error(
                        "k3d cluster creation failed for %s: %s",
                        cluster_name,
                        e,
                    )
                    try:
                        eks_backend = moto_backends.get_backend("eks")[context.account_id][context.region]
                        moto_cluster = eks_backend.clusters.get(cluster_name)
                        if moto_cluster:
                            moto_cluster.status = "CREATE_FAILED"
                    except Exception:
                        pass

            thread = threading.Thread(
                target=_create_in_background,
                name=f"eks-create-{cluster_name}",
                daemon=True,
            )
            thread.start()

    return result


def _handle_delete_cluster(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DeleteCluster: let Moto delete the record, then remove the k3d cluster.

    PARITY-08: Return DELETING status, delete in background thread.
    """
    # Extract cluster name from the request path before Moto processes it
    cluster_name = _extract_cluster_name_from_path(context)

    result = call_moto(context)

    # PARITY-08: Set DELETING status in response
    if result.get("cluster"):
        result["cluster"]["status"] = "DELETING"

    mgr = _init_cluster_manager()
    if mgr and cluster_name:
        def _delete_in_background():
            try:
                mgr.delete_cluster(
                    cluster_name,
                    account_id=context.account_id,
                    region=context.region,
                )
            except Exception as e:
                LOG.warning("Failed to delete k3d cluster for %s: %s", cluster_name, e)

        thread = threading.Thread(
            target=_delete_in_background,
            name=f"eks-delete-{cluster_name}",
            daemon=True,
        )
        thread.start()

    return result


def _handle_describe_cluster(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DescribeCluster: let Moto return the record, then enrich with real details.

    PARITY-03: Add platformVersion, kubernetesNetworkConfig, identity.oidc.
    QUALITY-02/BUG-13: Expose kubeconfig via response.
    """
    result = call_moto(context)

    mgr = _init_cluster_manager()
    if mgr and result.get("cluster"):
        cluster = result["cluster"]
        cluster_name = cluster.get("name")
        if cluster_name:
            info = mgr.get_cluster_info(
                cluster_name,
                account_id=context.account_id,
                region=context.region,
            )
            if info:
                cluster["endpoint"] = info.endpoint
                cluster["certificateAuthority"] = {"data": info.ca_cert_data}
                cluster["status"] = info.status
                # QUALITY-02/BUG-13: Expose kubeconfig for tools that need it
                if info.kubeconfig:
                    cluster["kubeconfig"] = info.kubeconfig

    # PARITY-03: Add missing fields that AWS returns
    if result.get("cluster"):
        cluster = result["cluster"]
        if "platformVersion" not in cluster:
            cluster["platformVersion"] = "eks.local"
        if "kubernetesNetworkConfig" not in cluster:
            cluster["kubernetesNetworkConfig"] = {
                "serviceIpv4Cidr": "10.100.0.0/16",
                "ipFamily": "ipv4",
            }
        if "identity" not in cluster:
            cluster_name = cluster.get("name", "unknown")
            account_id = context.account_id
            region = context.region
            cluster["identity"] = {
                "oidc": {
                    "issuer": f"https://oidc.eks.{region}.amazonaws.com/id/{cluster_name.upper()}"
                }
            }

    return result


def _handle_create_nodegroup(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """CreateNodegroup: let Moto create the record, then add k3d agent nodes.

    PARITY-04: Nodegroups are no longer metadata-only — they create real k3d agent nodes.
    """
    result = call_moto(context)

    mgr = _init_cluster_manager()
    if mgr and result.get("nodegroup"):
        nodegroup = result["nodegroup"]
        cluster_name = nodegroup.get("clusterName")
        nodegroup_name = nodegroup.get("nodegroupName")
        scaling_config = nodegroup.get("scalingConfig", {})
        desired_size = scaling_config.get("desiredSize", 1)

        if cluster_name and nodegroup_name:
            try:
                mgr.add_agent_nodes(
                    cluster_name=cluster_name,
                    nodegroup_name=nodegroup_name,
                    count=desired_size,
                    account_id=context.account_id,
                    region=context.region,
                )
                nodegroup["status"] = "ACTIVE"
            except Exception as e:
                LOG.warning(
                    "Failed to add k3d agent nodes for nodegroup %s/%s: %s",
                    cluster_name, nodegroup_name, e,
                )

    return result


def _extract_cluster_name_from_path(context: RequestContext) -> str:
    """Extract the EKS cluster name from the request URL path.

    EKS REST paths follow the pattern: /clusters/{name}
    """
    path = context.request.path or ""
    parts = [p for p in path.split("/") if p]
    # Expected: ["clusters", "<cluster-name>"] or ["clusters", "<name>", "sub-resource", ...]
    # BUG-04 fix: always extract parts[1] (the cluster name), never fall back to last segment
    if len(parts) >= 2 and parts[0] == "clusters":
        return parts[1]
    return ""


_INTERCEPTED_OPS = {
    "CreateCluster": _handle_create_cluster,
    "DeleteCluster": _handle_delete_cluster,
    "DescribeCluster": _handle_describe_cluster,
    "CreateNodegroup": _handle_create_nodegroup,
}


def EksDispatcher(service_model) -> DispatchTable:
    """Create dispatch table for EKS.

    Intercepted operations manage k3d clusters when EKS_K8S_PROVIDER=k3d.
    All other operations route to Moto.
    """
    table = {}
    for op in service_model.operation_names:
        if op in _INTERCEPTED_OPS:
            table[op] = _INTERCEPTED_OPS[op]
        else:
            table[op] = _proxy_moto
    return table


class EksLifecycleHook(ServiceLifecycleHook):
    """Bridges LocalEmu's persistence engine to the EKS provider.

    Without a non-default ``on_after_state_load`` override the persistence
    engine skips the service at load time, leaving persisted EKS clusters
    with metadata but no backing k3d cluster.
    """

    def on_after_state_load(self) -> None:  # noqa: D401 — hook
        _eks_on_after_state_load()


def _eks_on_after_state_load() -> None:
    """Reconcile persisted EKS records with live k3d clusters.

    Only meaningful when ``EKS_K8S_PROVIDER=k3d`` is set. Without that
    env var ``_init_cluster_manager`` returns ``None`` and we no-op — the
    persisted moto records still answer DescribeCluster but there was
    never any Kubernetes backing them to lose in the first place.
    """
    mgr = _init_cluster_manager()
    if not mgr:
        LOG.debug("EKS k3d backend disabled — skipping post-load reconcile")
        return

    moto_clusters: list[tuple[str, str, str]] = []
    try:
        bd = moto_backends.get_backend("eks")
    except Exception:
        LOG.warning("Could not access moto EKS backend", exc_info=True)
        return

    for acct, region_map in list(bd.items()):
        if not isinstance(region_map, dict):
            continue
        for region, backend in list(region_map.items()):
            clusters = getattr(backend, "clusters", {}) or {}
            for cluster_name in list(clusters.keys()):
                moto_clusters.append((acct, region, cluster_name))

    if not moto_clusters:
        LOG.info("EKS reconcile: no persisted clusters")
        return
    try:
        mgr.reattach_from_disk(moto_clusters)
    except Exception:
        LOG.warning("EKS reattach_from_disk failed", exc_info=True)


_kubeconfig_route_registered = False


def _handle_kubeconfig_route(request, cluster_name: str):
    """Serve the k3d-issued kubeconfig for an EKS cluster.

    AWS's ``eks update-kubeconfig`` emits an ``exec: aws eks get-token``
    auth section that depends on the real AWS CLI + STS — not workable
    against LocalEmu, where the cluster is a local k3d. The
    ``cluster.kubeconfig`` field LocalEmu attaches to DescribeCluster
    can't survive moto's response schema either (botocore strips fields
    not in the service model). This route exposes the kubeconfig
    verbatim so

        curl http://localhost:4566/_localemu/eks/<name>/kubeconfig > kc.yaml
        kubectl --kubeconfig kc.yaml get nodes

    just works.
    """
    mgr = _init_cluster_manager()
    if mgr is None:
        return Response(
            response="EKS k3d backend not initialised on this LocalEmu",
            status=404, content_type="text/plain",
        )
    info = None
    try:
        # Account/region are not in the URL — pick the first match. Real
        # multi-account testing should disambiguate via a query param.
        for (acct, region) in [(a, r) for a in ["000000000000"] for r in ["us-east-1"]]:
            info = mgr.get_cluster_info(
                name=cluster_name, account_id=acct, region=region,
            )
            if info:
                break
    except Exception:
        info = None
    if info is None or not getattr(info, "kubeconfig", ""):
        return Response(
            response=f"No kubeconfig for cluster {cluster_name!r}",
            status=404, content_type="text/plain",
        )
    return Response(
        response=info.kubeconfig,
        status=200,
        content_type="application/yaml",
    )


def _register_kubeconfig_route() -> None:
    global _kubeconfig_route_registered
    if _kubeconfig_route_registered:
        return
    try:
        # The /_localemu/* namespace is handled by an earlier middleware
        # that 404s before the edge ROUTER sees the request, so the route
        # lives outside that prefix.
        ROUTER.add(
            path="/_localemu_eks/<cluster_name>/kubeconfig",
            endpoint=_handle_kubeconfig_route,
            methods=["GET"],
        )
        _kubeconfig_route_registered = True
        LOG.debug("EKS kubeconfig route registered at /_localemu_eks/<name>/kubeconfig")
    except Exception:
        LOG.debug("Failed to register EKS kubeconfig route", exc_info=True)


def create_eks_service() -> Service:
    """Create the EKS service with optional k3d-backed clusters."""
    from localemu.aws.spec import load_service

    _register_kubeconfig_route()
    service_model = load_service("eks")
    dispatch_table = EksDispatcher(service_model)
    skeleton = Skeleton(service_model, dispatch_table)
    return Service(
        name="eks",
        skeleton=skeleton,
        lifecycle_hook=EksLifecycleHook(),
    )
