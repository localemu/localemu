"""OpenSearch provider with Docker-backed search clusters.

Wraps Moto's OpenSearch backend for CRUD operations and adds real Docker
containers running OpenSearch when OPENSEARCH_DOCKER_BACKEND=1. Each domain
gets a real search engine with full indexing, query, and aggregation support.
"""

import logging
import os
import re

from localemu.aws.api import CommonServiceException, RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.services.moto import _proxy_moto, call_moto
from localemu.services.plugins import Service

# Domain name validation (parity with OpensearchProvider)
_domain_name_pattern = re.compile(r"^[a-z][a-z0-9\-]{2,27}$")

LOG = logging.getLogger(__name__)

_cluster_manager = None


def _persist_security_options(context: RequestContext, domain_status: dict) -> None:
    """Persist AdvancedSecurityOptions from the request into Moto's domain record.

    The Docker provider delegates CRUD to Moto via call_moto, but Moto's OpenSearch
    backend may not fully persist AdvancedSecurityOptions. This function ensures
    the options are stored so DescribeDomain returns them correctly.
    """
    domain_name = domain_status.get("DomainName")
    if not domain_name:
        return
    try:
        import json
        body = context.request.data
        if not body:
            return
        parsed = json.loads(body)
        security_opts = parsed.get("AdvancedSecurityOptions")
        if not security_opts:
            return

        import moto.backends as moto_backends
        backend = moto_backends.get_backend("opensearch")[context.account_id][context.region]
        moto_domain = backend.domains.get(domain_name)
        if moto_domain:
            moto_domain.advanced_security_options = security_opts
            # Also include it in the response
            domain_status["AdvancedSecurityOptions"] = {
                "Enabled": security_opts.get("Enabled", False),
                "InternalUserDatabaseEnabled": security_opts.get("InternalUserDatabaseEnabled", False),
            }
            LOG.debug("Persisted AdvancedSecurityOptions for domain %s", domain_name)
    except Exception:
        LOG.debug("Could not persist AdvancedSecurityOptions for %s", domain_name, exc_info=True)


def _init_cluster_manager():
    """Initialize the Docker cluster manager.

    Automatically enabled when Docker is available — no env var needed.
    Each OpenSearch domain gets a real Docker container with full
    indexing and search support (same pattern as RDS and EC2).
    """
    global _cluster_manager
    if _cluster_manager is not None:
        return _cluster_manager

    try:
        from localemu.services.opensearch.docker.cluster_manager import DockerClusterManager
        from localemu.utils.docker_utils import DOCKER_CLIENT

        if DOCKER_CLIENT.has_docker():
            _cluster_manager = DockerClusterManager()
            LOG.info("OpenSearch Docker backend enabled.")
        else:
            LOG.info("Docker not available — OpenSearch domains will be metadata-only.")
    except Exception as e:
        LOG.warning("Failed to initialize OpenSearch Docker backend: %s", e)

    return _cluster_manager


def _handle_create_domain(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """CreateDomain: let Moto create the record, then start a Docker container.

    Validates domain name before calling Moto (parity with OpensearchProvider).
    Persists AdvancedSecurityOptions into Moto domain.
    """
    # Validate domain name before creating
    domain_name = request.get("DomainName") if request else None
    if not domain_name:
        # Try to extract from the raw request body
        try:
            import json
            body = context.request.data
            if body:
                parsed = json.loads(body)
                domain_name = parsed.get("DomainName")
        except Exception:
            pass
    if domain_name and not _domain_name_pattern.match(domain_name):
        raise CommonServiceException(
            "ValidationException",
            "Member must satisfy regular expression pattern: [a-z][a-z0-9\\-]+",
            status_code=400,
        )

    result = call_moto(context)

    # Persist AdvancedSecurityOptions into Moto's domain record
    if result.get("DomainStatus"):
        _persist_security_options(context, result["DomainStatus"])

    mgr = _init_cluster_manager()
    if mgr and result.get("DomainStatus"):
        domain = result["DomainStatus"]
        domain_name = domain.get("DomainName")
        engine_version = domain.get("EngineVersion")

        if domain_name:
            try:
                info = mgr.create_cluster(
                    domain_name=domain_name,
                    engine_version=engine_version,
                )
                # Update endpoint in response and persist in Moto store.
                # Non-VPC domains must have Endpoint set and Endpoints NULL.
                # Terraform validates this — setting both causes a 10-minute
                # timeout then "expected to have null Endpoints value" error.
                endpoint = f"localhost:{info.host_port}"
                domain["Endpoint"] = endpoint
                if domain.get("VPCOptions"):
                    domain["Endpoints"] = {"vpc": endpoint}
                else:
                    domain.pop("Endpoints", None)
                domain["Processing"] = info.status != "active"

                # Persist endpoint into Moto's backend so DescribeDomain
                # returns it without needing the Docker manager to patch.
                try:
                    import moto.backends as moto_backends
                    backend = moto_backends.get_backend("opensearch")[
                        context.account_id][context.region]
                    moto_domain = backend.domains.get(domain_name)
                    if moto_domain:
                        moto_domain.endpoint = endpoint
                        # Clear Endpoints for non-VPC domains (Terraform validates this)
                        if not domain.get("VPCOptions"):
                            moto_domain.endpoints = {}
                except Exception:
                    LOG.debug("Could not persist endpoint in Moto store for %s", domain_name)
                LOG.info(
                    "OpenSearch domain %s ready at localhost:%s",
                    domain_name, info.host_port,
                )
            except Exception as e:
                LOG.warning("Docker cluster failed for %s: %s", domain_name, e)
                # LOW-04: Mark Moto domain as failed so DescribeDomain
                # reflects the error instead of showing a healthy domain.
                try:
                    import moto.backends as moto_backends
                    backend = moto_backends.get_backend("opensearch")[
                        context.account_id][context.region]
                    moto_domain = backend.domains.get(domain_name)
                    if moto_domain:
                        moto_domain.processing = False
                        # Store a hint that creation failed
                        moto_domain.engine_version = (
                            getattr(moto_domain, "engine_version", "") or ""
                        ) + " (create-failed)"
                except Exception:
                    LOG.debug("Could not mark Moto domain %s as failed", domain_name)

    return result


def _handle_delete_domain(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DeleteDomain: let Moto delete the record, then remove the Docker container."""
    # Extract domain name from URL path (DELETE requests have no body)
    domain_name = ""
    path = context.request.path or ""
    parts = [p for p in path.split("/") if p]
    if len(parts) >= 3:
        domain_name = parts[-1]

    result = call_moto(context)

    mgr = _init_cluster_manager()
    if mgr and domain_name:
        try:
            mgr.delete_cluster(domain_name)
        except Exception as e:
            LOG.warning("Failed to delete Docker cluster for %s: %s", domain_name, e)

    return result


def _handle_describe_domain(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DescribeDomain: let Moto return the record, then patch the endpoint."""
    result = call_moto(context)

    mgr = _init_cluster_manager()
    if mgr and result.get("DomainStatus"):
        domain = result["DomainStatus"]
        domain_name = domain.get("DomainName")
        if domain_name:
            info = mgr.get_cluster_info(domain_name)
            if info:
                domain["Endpoint"] = f"localhost:{info.host_port}"
                if domain.get("VPCOptions"):
                    domain["Endpoints"] = {"vpc": f"localhost:{info.host_port}"}
                else:
                    domain.pop("Endpoints", None)
                domain["Processing"] = info.status != "active"

    return result


def _handle_describe_domains(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    """DescribeDomains: patch endpoints for all domains."""
    result = call_moto(context)

    mgr = _init_cluster_manager()
    if mgr and result.get("DomainStatusList"):
        for domain in result["DomainStatusList"]:
            domain_name = domain.get("DomainName")
            if domain_name:
                info = mgr.get_cluster_info(domain_name)
                if info:
                    domain["Endpoint"] = f"localhost:{info.host_port}"
                    if domain.get("VPCOptions"):
                        domain["Endpoints"] = {"vpc": f"localhost:{info.host_port}"}
                    else:
                        domain.pop("Endpoints", None)

    return result


_INTERCEPTED_OPS = {
    "CreateDomain": _handle_create_domain,
    "DeleteDomain": _handle_delete_domain,
    "DescribeDomain": _handle_describe_domain,
    "DescribeDomains": _handle_describe_domains,
}


def OpenSearchDispatcher(service_model) -> DispatchTable:
    """Create dispatch table for OpenSearch.

    Intercepted operations manage Docker containers.
    All other operations route to Moto.
    """
    table = {}
    for op in service_model.operation_names:
        if op in _INTERCEPTED_OPS:
            table[op] = _INTERCEPTED_OPS[op]
        else:
            table[op] = _proxy_moto
    return table


def create_opensearch_service() -> Service:
    """Create the OpenSearch service with Docker-backed clusters."""
    from localemu.aws.spec import load_service

    service_model = load_service("opensearch")
    dispatch_table = OpenSearchDispatcher(service_model)
    skeleton = Skeleton(service_model, dispatch_table)
    return Service(name="opensearch", skeleton=skeleton)
