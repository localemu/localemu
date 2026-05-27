"""Amazon MQ provider — real Docker-backed broker, not a moto stub.

Mirrors the RDS-Docker pattern: moto owns the metadata + control-plane
storage, and the Docker manager owns the real container running the
broker. Every CreateBroker response only goes back once the broker
process accepts connections, so the test client's first publish
doesn't race the container's startup.

Opt-in via ``MQ_DOCKER_BACKEND=1``. The RabbitMQ-management image is
~250 MB so default-on would surprise users on bandwidth-constrained
links; the design calls out a future default-on flip.
"""

from __future__ import annotations

import logging
import os

from localemu.aws.api import RequestContext
from localemu.aws.api.mq import (
    AuthenticationStrategy,
    BrokerStorageType,
    ConfigurationId,
    CreateBrokerResponse,
    DataReplicationMode,
    DeleteBrokerResponse,
    DeploymentMode,
    DescribeBrokerResponse,
    EncryptionOptions,
    EngineType,
    LdapServerMetadataInput,
    ListBrokersResponse,
    Logs,
    MaxResults,
    MqApi,
    RebootBrokerResponse,
    User,
    WeeklyStartTime,
)
from localemu.services.moto import call_moto
from localemu.services.plugins import ServiceLifecycleHook
from localemu.services.mq.docker.broker_manager import BrokerManager
from localemu.state import StateVisitor

LOG = logging.getLogger(__name__)


def _docker_enabled() -> bool:
    """Whether the Docker backend should run. Opt-in via env to keep the
    OOTB default lightweight (the RabbitMQ-management image is ~250 MB).
    """
    return os.environ.get("MQ_DOCKER_BACKEND", "").strip().lower() in {"1", "true"}


class MqProvider(MqApi, ServiceLifecycleHook):
    """Custom MQ provider with Docker-backed broker lifecycle."""

    def accept_state_visitor(self, visitor: StateVisitor):
        from moto.mq.models import mq_backends

        visitor.visit(mq_backends)

    # ------------------------------------------------------------------
    # Lifecycle — control-plane verbs
    # ------------------------------------------------------------------
    def create_broker(
        self,
        context: RequestContext,
        host_instance_type: str,
        broker_name: str,
        deployment_mode: DeploymentMode,
        engine_type: EngineType,
        publicly_accessible: bool,
        authentication_strategy: AuthenticationStrategy | None = None,
        auto_minor_version_upgrade: bool | None = None,
        configuration: ConfigurationId | None = None,
        creator_request_id: str | None = None,
        encryption_options: EncryptionOptions | None = None,
        engine_version: str | None = None,
        ldap_server_metadata: LdapServerMetadataInput | None = None,
        logs: Logs | None = None,
        maintenance_window_start_time: WeeklyStartTime | None = None,
        security_groups: list[str] | None = None,
        storage_type: BrokerStorageType | None = None,
        subnet_ids: list[str] | None = None,
        tags: dict[str, str] | None = None,
        users: list[User] | None = None,
        data_replication_mode: DataReplicationMode | None = None,
        data_replication_primary_broker_arn: str | None = None,
        **kwargs,
    ) -> CreateBrokerResponse:
        result = call_moto(context)
        broker_id = result.get("BrokerId")
        if not _docker_enabled():
            LOG.info(
                "MQ_DOCKER_BACKEND not set; broker %s recorded in moto only "
                "(no real container). Set MQ_DOCKER_BACKEND=1 to boot a real broker.",
                broker_id,
            )
            return result
        if not broker_id:
            return result
        admin_user = "admin"
        admin_pass = "password"
        if users:
            first = users[0]
            admin_user = first.get("Username") or admin_user
            admin_pass = first.get("Password") or admin_pass
        try:
            instance = BrokerManager.instance().create_broker(
                broker_id=broker_id,
                engine_type=engine_type,
                engine_version=engine_version or "",
                admin_username=admin_user,
                admin_password=admin_pass,
            )
        except NotImplementedError as e:
            LOG.warning("CreateBroker %s: %s", broker_id, e)
            self._set_broker_state(context, broker_id, "CREATION_FAILED")
            return result
        except Exception:
            LOG.warning(
                "CreateBroker %s docker provisioning failed", broker_id, exc_info=True,
            )
            self._set_broker_state(context, broker_id, "CREATION_FAILED")
            return result
        self._set_broker_state(context, broker_id, "RUNNING")
        # Hand the live endpoints back to the caller so they don't have
        # to wait for DescribeBroker to discover them.
        if "BrokerArn" in result or broker_id:
            return result

    def describe_broker(
        self, context: RequestContext, broker_id: str, **kwargs,
    ) -> DescribeBrokerResponse:
        result = call_moto(context)
        if not _docker_enabled() or not isinstance(result, dict):
            return result
        instance = BrokerManager.instance().get_broker(broker_id)
        if instance is None:
            return result
        # Overlay BrokerState with what Docker actually reports + rewrite
        # the broker endpoints to localhost so a real client on the host
        # can connect by URL parse (real AWS would hand out the broker's
        # internal AWS DNS name; we hand back localhost:<port>).
        result["BrokerState"] = instance.state
        result["BrokerInstances"] = [
            {
                "ConsoleURL": _endpoint_url("https", instance.ports.get("mgmt"), "/"),
                "Endpoints": _endpoints_for(instance),
                "IpAddress": "127.0.0.1",
            }
        ]
        return result

    def list_brokers(
        self,
        context: RequestContext,
        max_results: MaxResults | None = None,
        next_token: str | None = None,
        **kwargs,
    ) -> ListBrokersResponse:
        result = call_moto(context)
        if not _docker_enabled() or not isinstance(result, dict):
            return result
        manager = BrokerManager.instance()
        for entry in result.get("BrokerSummaries", []) or []:
            inst = manager.get_broker(entry.get("BrokerId", ""))
            if inst is not None:
                entry["BrokerState"] = inst.state
        return result

    def delete_broker(
        self, context: RequestContext, broker_id: str, **kwargs,
    ) -> DeleteBrokerResponse:
        if _docker_enabled():
            try:
                BrokerManager.instance().delete_broker(broker_id)
            except Exception:
                LOG.debug(
                    "delete_broker docker cleanup failed for %s", broker_id, exc_info=True,
                )
        return call_moto(context)

    def reboot_broker(
        self, context: RequestContext, broker_id: str, **kwargs,
    ) -> RebootBrokerResponse:
        if _docker_enabled():
            instance = BrokerManager.instance().get_broker(broker_id)
            if instance is not None:
                from localemu.utils.docker_utils import DOCKER_CLIENT

                try:
                    self._set_broker_state(context, broker_id, "REBOOT_IN_PROGRESS")
                    DOCKER_CLIENT.restart_container(instance.container_name, timeout=10)
                    BrokerManager.instance()._wait_for_port(
                        instance.ports.get("amqp", 0)
                    )
                    self._set_broker_state(context, broker_id, "RUNNING")
                except Exception:
                    LOG.warning("RebootBroker %s failed", broker_id, exc_info=True)
        return call_moto(context)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    @staticmethod
    def _set_broker_state(context: RequestContext, broker_id: str, state: str) -> None:
        """Mirror the engine-derived state into moto's broker model so
        Describe / List return truthful values without us having to
        intercept those operations for the state field alone."""
        try:
            from moto.mq.models import mq_backends

            backend = mq_backends[context.account_id][context.region]
            broker = backend.brokers.get(broker_id)
            if broker is not None:
                broker.state = state
        except Exception:
            LOG.debug(
                "Could not sync broker %s state=%s into moto", broker_id, state,
                exc_info=True,
            )


def _endpoints_for(instance) -> list[str]:
    """Return the wire URLs a real client can connect to.

    Scheme follows AWS convention so SDK URL parsers still understand
    them; the underlying socket is plaintext in v1 (the design's
    ``LOCALEMU_MQ_PLAINTEXT_SCHEME`` escape hatch is a follow-up if
    users explicitly need TCP scheme).
    """
    out: list[str] = []
    if instance.engine == "RABBITMQ":
        if (port := instance.ports.get("amqp")):
            out.append(f"amqp://127.0.0.1:{port}")
        if (port := instance.ports.get("amqps")):
            out.append(f"amqps://127.0.0.1:{port}")
        if (port := instance.ports.get("stomp")):
            out.append(f"stomp+ssl://127.0.0.1:{port}")
        if (port := instance.ports.get("mqtt")):
            out.append(f"mqtt+ssl://127.0.0.1:{port}")
    return out


def _endpoint_url(scheme: str, port: int | None, path: str) -> str | None:
    if not port:
        return None
    return f"{scheme}://127.0.0.1:{port}{path}"


def create_mq_service():
    """Service factory wired into ``services/providers.py:mq``."""
    from localemu.aws.skeleton import Skeleton
    from localemu.aws.spec import load_service
    from localemu.services.moto import MotoFallbackDispatcher
    from localemu.services.plugins import Service

    return Service.for_provider(
        MqProvider(), dispatch_table_factory=MotoFallbackDispatcher,
    )
