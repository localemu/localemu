"""
LocalEmu client stack.

This module provides the interface to perform cross-service communication between
LocalEmu providers.
"""

import json
import logging
import os
import re
import secrets
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from functools import lru_cache, partial
from random import choice
from socket import socket
from typing import Any, Generic, TypedDict, TypeVar

import dns.message
import dns.query
import dns.resolver
from boto3.session import Session
from botocore.awsrequest import (
    AWSHTTPConnection,
    AWSHTTPConnectionPool,
    AWSHTTPSConnection,
    AWSHTTPSConnectionPool,
)
from botocore.client import BaseClient
from botocore.config import Config
from botocore.httpsession import URLLib3Session
from botocore.waiter import Waiter

from localemu import config as localemu_config
from localemu.aws.spec import LOCALEMU_BUILTIN_DATA_PATH
from localemu.constants import (
    AWS_REGION_US_EAST_1,
    INTERNAL_AWS_ACCESS_KEY_ID,
    INTERNAL_AWS_SECRET_ACCESS_KEY,
    MAX_POOL_CONNECTIONS,
)
from localemu.utils.aws.aws_stack import get_s3_hostname
from localemu.utils.aws.client_types import ServicePrincipal, TypedServiceClientFactory
from localemu.utils.patch import patch
from localemu.utils.strings import short_uid

LOG = logging.getLogger(__name__)


@patch(target=Waiter.wait, pass_target=True)
def my_patch(fn, self, **kwargs):
    """
    We're patching defaults in here that will override the defaults specified in the waiter spec since these are usually way too long

    Alternatively we could also try to find a solution where we patch the loader used in the generated clients
    so that we can dynamically fix the waiter config when it's loaded instead of when it's being used for wait execution
    """

    if localemu_config.DISABLE_CUSTOM_BOTO_WAITER_CONFIG:
        return fn(self, **kwargs)
    else:
        patched_kwargs = {
            **kwargs,
            "WaiterConfig": {
                "Delay": localemu_config.BOTO_WAITER_DELAY,
                "MaxAttempts": localemu_config.BOTO_WAITER_MAX_ATTEMPTS,
                **kwargs.get(
                    "WaiterConfig", {}
                ),  # we still allow client users to override these defaults
            },
        }
        return fn(self, **patched_kwargs)


# patch the botocore.Config object to be comparable and hashable.
# this solution does not validates the hashable (https://docs.python.org/3/glossary.html#term-hashable) definition on python
# It would do so only when someone accesses the internals of the Config option to change the dict directly.
# Since this is not a proper way to use the config object (but via config.merge), this should be fine
def make_hash(o):
    if isinstance(o, (set, tuple, list)):
        return tuple([make_hash(e) for e in o])

    elif not isinstance(o, dict):
        return hash(o)

    new_o = {}
    for k, v in o.items():
        new_o[k] = make_hash(v)

    return hash(frozenset(sorted(new_o.items())))


def config_equality_patch(self, other: object) -> bool:
    return type(self) is type(other) and self._user_provided_options == other._user_provided_options


def config_hash_patch(self):
    return make_hash(self._user_provided_options)


Config.__eq__ = config_equality_patch
Config.__hash__ = config_hash_patch


def attribute_name_to_service_name(attribute_name):
    """
    Converts a python-compatible attribute name to the boto service name
    :param attribute_name: Python compatible attribute name using the following replacements:
                            a) Add an underscore suffix `_` to any reserved Python keyword (PEP-8).
                            b) Replace any dash `-` with an underscore `_`
    :return:
    """
    if attribute_name.endswith("_"):
        # lambda_ -> lambda
        attribute_name = attribute_name[:-1]
    # replace all _ with -: cognito_idp -> cognito-idp
    return attribute_name.replace("_", "-")


def get_service_endpoint() -> str | None:
    """
    Returns the endpoint the client should target.

    :return: Endpoint url
    """
    if localemu_config.DISTRIBUTED_MODE:
        return None
    return localemu_config.internal_service_url()


#
# Data transfer object
#

INTERNAL_REQUEST_PARAMS_HEADER = "x-localemu-data"
"""Request header which contains the data transfer object."""

INTERNAL_REQUEST_AUTH_HEADER = "x-localemu-data-auth"
"""Request header carrying the process-local auth token that proves the DTO
header was produced by an in-process :class:`InternalClientFactory`."""

INTERNAL_REQUEST_AUTH_TOKEN = (
    os.environ.get("LOCALEMU_INTERNAL_AUTH_TOKEN", "").strip()
    or secrets.token_hex(32)
)
"""Process-local bearer token validating the DTO header. Generated fresh at
import; overridable via ``LOCALEMU_INTERNAL_AUTH_TOKEN`` for distributed
deployments where every node must agree on the same value."""


class InternalRequestParameters(TypedDict):
    """
    LocalEmu Data Transfer Object.

    This is sent with every internal request and contains any additional information
    LocalEmu might need for the purpose of policy enforcement. It is serialised
    into text and sent in the request header.

    Attributes can be added as needed. The keys should roughly correspond to:
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
    """

    source_arn: str | None
    """ARN of resource which is triggering the call"""

    service_principal: str | None
    """Service principal making this call"""


def dump_dto(data: InternalRequestParameters) -> str:
    # To produce a compact JSON representation of DTO, remove spaces from separators
    # If possible, we could use a custom encoder to further decrease header size in the future
    return json.dumps(data, separators=(",", ":"))


def load_dto(data: str) -> InternalRequestParameters:
    return json.loads(data)


T = TypeVar("T")


class MetadataRequestInjector(Generic[T]):
    def __init__(self, client: T, params: dict[str, str] | None = None):
        self._client = client
        self._params = params

    def __getattr__(self, item):
        target = getattr(self._client, item)
        if not isinstance(target, Callable):
            return target
        if self._params:
            return partial(target, **self._params)
        else:
            return target

    def request_metadata(
        self, source_arn: str | None = None, service_principal: str | None = None
    ) -> T:
        """
        Returns a new client instance preset with the given request metadata.
        Identical to providing _ServicePrincipal and _SourceArn directly as operation arguments but typing
        compatible.

        Raw example: lambda_client.invoke(FunctionName="fn", _SourceArn="...")
        Injector example: lambda_client.request_metadata(source_arn="...").invoke(FunctionName="fn")
        Cannot be called on objects where the parameters are already set.

        :param source_arn: Arn on which behalf the calls of this client shall be made
        :param service_principal: Service principal on which behalf the calls of this client shall be made
        :return: A new version of the MetadataRequestInjector
        """
        if self._params is not None:
            raise TypeError("Request_data cannot be called on it's own return value")
        params = {}
        if source_arn:
            params["_SourceArn"] = source_arn
        if service_principal:
            params["_ServicePrincipal"] = service_principal
        return MetadataRequestInjector(client=self._client, params=params)


#
# Factory
#
class ServiceLevelClientFactory(TypedServiceClientFactory):
    """
    A service level client factory, preseeded with parameters for the boto3 client creation.
    Will create any service client with parameters already provided by the ClientFactory.
    """

    def __init__(
        self,
        *,
        factory: "ClientFactory",
        client_creation_params: dict[str, str | Config | None],
        request_wrapper_clazz: type,
    ):
        self._factory = factory
        self._client_creation_params = client_creation_params
        self._request_wrapper_clazz = request_wrapper_clazz

    def get_client(self, service: str):
        return self._request_wrapper_clazz(
            client=self._factory.get_client(service_name=service, **self._client_creation_params)
        )

    def __getattr__(self, service: str):
        service = attribute_name_to_service_name(service)
        return self._request_wrapper_clazz(
            client=self._factory.get_client(service_name=service, **self._client_creation_params)
        )


class ClientFactory(ABC):
    """
    Factory to build the AWS client.

    Boto client creation is resource intensive. This class caches all Boto
    clients it creates and must be used instead of directly using boto lib.
    """

    def __init__(
        self,
        use_ssl: bool = False,
        verify: bool | str = False,
        session: Session = None,
        config: Config = None,
        endpoint: str = None,
    ):
        """
        :param use_ssl: Whether to use SSL
        :param verify: Whether to verify SSL certificates
        :param session: Session to be used for client creation. Will create a new session if not provided.
            Please note that sessions are not generally thread safe.
            Either create a new session for each factory or make sure the session is not shared with another thread.
            The factory itself has a lock for the session, so as long as you only use the session in one factory,
            it should be fine using the factory in a multithreaded context.
        :param config: Config used as default for client creation.
        """
        self._use_ssl = use_ssl
        self._verify = verify
        self._config: Config = config or Config(max_pool_connections=MAX_POOL_CONNECTIONS)
        self._session: Session = session or Session()
        self._endpoint = endpoint

        # make sure we consider our custom data paths for legacy specs (like SQS query protocol)
        if LOCALEMU_BUILTIN_DATA_PATH not in self._session._loader.search_paths:
            self._session._loader.search_paths.insert(0, LOCALEMU_BUILTIN_DATA_PATH)

        self._create_client_lock = threading.RLock()

    def __call__(
        self,
        *,
        region_name: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        endpoint_url: str = None,
        config: Config = None,
    ) -> ServiceLevelClientFactory:
        """
        Get back an object which lets you select the typed service you want to access with the given attributes

        :param region_name: Name of the AWS region to be associated with the client
            If set to None, loads from botocore session.
        :param aws_access_key_id: Access key to use for the client.
            If set to None, loads from botocore session.
        :param aws_secret_access_key: Secret key to use for the client.
            If set to None, loads from botocore session.
        :param aws_session_token: Session token to use for the client.
            Not being used if not set.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalEmu endpoint.
        :param config: Boto config for advanced use.
        :return: Service Region Client Creator
        """
        params = {
            "region_name": region_name,
            "aws_access_key_id": aws_access_key_id,
            "aws_secret_access_key": aws_secret_access_key,
            "aws_session_token": aws_session_token,
            "endpoint_url": endpoint_url,
            "config": config,
        }
        return ServiceLevelClientFactory(
            factory=self,
            client_creation_params=params,
            request_wrapper_clazz=MetadataRequestInjector,
        )

    def with_assumed_role(
        self,
        *,
        role_arn: str,
        service_principal: ServicePrincipal | None = None,
        session_name: str | None = None,
        region_name: str | None = None,
        endpoint_url: str | None = None,
        config: Config | None = None,
    ) -> ServiceLevelClientFactory:
        """
        Create a service level client factory with credentials from assuming the given role ARN.
        The service_principal will only be used for the assume_role call, for all succeeding calls it has to be provided
        separately, either as call attribute or using request_metadata()

        :param role_arn: Role to assume
        :param service_principal: Service the role should be assumed as, must not be set for test clients
        :param session_name: Session name for the role session
        :param region_name: Region for the returned client
        :param endpoint_url: Endpoint for both the assume_role call and the returned client
        :param config: Config for both the assume_role call and the returned client
        :return: Service Level Client Factory
        """
        session_name = session_name or f"session-{short_uid()}"
        sts_client = self(endpoint_url=endpoint_url, config=config, region_name=region_name).sts

        metadata = {}
        if service_principal:
            metadata["service_principal"] = service_principal

        sts_client = sts_client.request_metadata(**metadata)
        credentials = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)[
            "Credentials"
        ]

        return self(
            region_name=region_name,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            endpoint_url=endpoint_url,
            config=config,
        )

    @abstractmethod
    def get_client(
        self,
        service_name: str,
        region_name: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        endpoint_url: str | None = None,
        config: Config | None = None,
    ):
        raise NotImplementedError()

    def _get_client_post_hook(self, client: BaseClient) -> BaseClient:
        """
        This is called after the client is created by Boto.

        Any modifications to the client can be implemented here in subclasses
        without affecting the caching mechanism.
        """
        return client

    # TODO @lru_cache here might result in a memory leak, as it keeps a reference to `self`
    # We might need an alternative caching decorator with a weak ref to `self`
    # Otherwise factories might never be garbage collected
    @lru_cache(maxsize=256)
    def _get_client(
        self,
        service_name: str,
        region_name: str,
        use_ssl: bool,
        verify: bool | None,
        endpoint_url: str | None,
        aws_access_key_id: str | None,
        aws_secret_access_key: str | None,
        aws_session_token: str | None,
        config: Config,
    ) -> BaseClient:
        """
        Returns a boto3 client with the given configuration, and the hooks added by `_get_client_post_hook`.
        This is a cached call, so modifications to the used client will affect others.
        Please use another instance of the factory, should you want to modify clients.
        Client creation is behind a lock as it is not generally thread safe.

        :param service_name: Service to build the client for, eg. `s3`
        :param region_name: Name of the AWS region to be associated with the client
            If set to None, loads from botocore session.
        :param aws_access_key_id: Access key to use for the client.
            If set to None, loads from botocore session.
        :param aws_secret_access_key: Secret key to use for the client.
            If set to None, loads from botocore session.
        :param aws_session_token: Session token to use for the client.
            Not being used if not set.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalEmu endpoint.
        :param config: Boto config for advanced use.
        :return: Boto3 client.
        """
        with self._create_client_lock:
            default_config = (
                Config(retries={"max_attempts": 0})
                if localemu_config.DISABLE_BOTO_RETRIES
                else Config()
            )

            client = self._session.client(
                service_name=service_name,
                region_name=region_name,
                use_ssl=use_ssl,
                verify=verify,
                endpoint_url=endpoint_url,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                config=config.merge(default_config),
            )

        return self._get_client_post_hook(client)

    #
    # Boto session utilities
    #
    def _get_session_region(self) -> str:
        """
        Return AWS region as set in the Boto session.
        """
        return self._session.region_name

    def _get_region(self) -> str:
        """
        Return the AWS region name from following sources, in order of availability.
        - LocalEmu request context
        - Boto session
        - us-east-1
        """
        return self._get_session_region() or AWS_REGION_US_EAST_1


class InternalClientFactory(ClientFactory):
    def _get_client_post_hook(self, client: BaseClient) -> BaseClient:
        """
        Register handlers that enable internal data object transfer mechanism
        for internal clients.
        """
        client.meta.events.register(
            "provide-client-params.*.*", handler=_handler_create_request_parameters
        )

        client.meta.events.register("before-call.*.*", handler=_handler_inject_dto_header)

        if localemu_config.IN_MEMORY_CLIENT:
            # this make the client call the gateway directly
            from localemu.aws.client import GatewayShortCircuit
            from localemu.runtime import get_current_runtime

            GatewayShortCircuit.modify_client(client, get_current_runtime().components.gateway)

        return client

    def get_client(
        self,
        service_name: str,
        region_name: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        endpoint_url: str | None = None,
        config: Config | None = None,
    ) -> BaseClient:
        """
        Build and return client for connections originating within LocalEmu.

        All API operation methods (such as `.list_buckets()` or `.run_instances()`
        take additional args that start with `_` prefix. These are used to pass
        additional information to LocalEmu server during internal calls.

        :param service_name: Service to build the client for, eg. `s3`
        :param region_name: Region name. See note above.
            If set to None, loads from botocore session.
        :param aws_access_key_id: Access key to use for the client.
            Defaults to LocalEmu internal credentials.
        :param aws_secret_access_key: Secret key to use for the client.
            Defaults to LocalEmu internal credentials.
        :param aws_session_token: Session token to use for the client.
            Not being used if not set.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalEmu endpoint.
        :param config: Boto config for advanced use.
        """

        if config is None:
            config = self._config
        else:
            config = self._config.merge(config)

        # Force path-style for internal S3 clients to avoid virtual-host DNS issues.
        # Without this, boto3 sends Host: bucket.s3.localhost:4566 which requires
        # DNS resolution of *.s3.localhost subdomains. Path-style uses Host: localhost:4566
        # with the bucket name in the URL path, which always works.
        if service_name == "s3":
            from botocore.config import Config as BotoConfig

            config = config.merge(BotoConfig(s3={"addressing_style": "path"}))

        endpoint_url = endpoint_url or self._endpoint or get_service_endpoint()
        if (
            endpoint_url
            and service_name == "s3"
            and re.match(r"https?://localhost(:[0-9]+)?", endpoint_url)
        ):
            endpoint_url = endpoint_url.replace("://localhost", f"://{get_s3_hostname()}")

        return self._get_client(
            service_name=service_name,
            region_name=region_name or self._get_region(),
            use_ssl=self._use_ssl,
            verify=self._verify,
            endpoint_url=endpoint_url,
            aws_access_key_id=aws_access_key_id or INTERNAL_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=aws_secret_access_key or INTERNAL_AWS_SECRET_ACCESS_KEY,
            aws_session_token=aws_session_token,
            config=config,
        )


class ExternalClientFactory(ClientFactory):
    def get_client(
        self,
        service_name: str,
        region_name: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        endpoint_url: str | None = None,
        config: Config | None = None,
    ) -> BaseClient:
        """
        Build and return client for connections originating outside LocalEmu and targeting Localemu.

        If the region is set to None, it is loaded from following
        locations:
        - AWS environment variables
        - Credentials file `~/.aws/credentials`
        - Config file `~/.aws/config`

        :param service_name: Service to build the client for, eg. `s3`
        :param region_name: Name of the AWS region to be associated with the client
            If set to None, loads from botocore session.
        :param aws_access_key_id: Access key to use for the client.
            If set to None, loads from botocore session.
        :param aws_secret_access_key: Secret key to use for the client.
            If set to None, uses a placeholder value
        :param aws_session_token: Session token to use for the client.
            Not being used if not set.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalEmu endpoint.
        :param config: Boto config for advanced use.
        """
        if config is None:
            config = self._config
        else:
            config = self._config.merge(config)

        # Boto has an odd behaviour when using a non-default (any other region than us-east-1) in config
        # If the region in arg is non-default, it gives the arg the precedence
        # But if the region in arg is default (us-east-1), it gives precedence to one in config
        # Below: always give precedence to arg region
        if (
            config
            and config.region_name != AWS_REGION_US_EAST_1
            and region_name == AWS_REGION_US_EAST_1
        ):
            config = config.merge(Config(region_name=region_name))

        endpoint_url = endpoint_url or self._endpoint or get_service_endpoint()
        if (
            endpoint_url
            and service_name == "s3"
            and re.match(r"https?://localhost(:[0-9]+)?", endpoint_url)
        ):
            endpoint_url = endpoint_url.replace("://localhost", f"://{get_s3_hostname()}")

        # Prevent `PartialCredentialsError` when only access key ID is provided
        # The value of secret access key is insignificant and can be set to anything
        if aws_access_key_id:
            aws_secret_access_key = aws_secret_access_key or INTERNAL_AWS_SECRET_ACCESS_KEY

        return self._get_client(
            service_name=service_name,
            region_name=region_name or config.region_name or self._get_region(),
            use_ssl=self._use_ssl,
            verify=self._verify,
            endpoint_url=endpoint_url,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            config=config,
        )


class ExternalAwsClientFactory(ClientFactory):
    def get_client(
        self,
        service_name: str,
        region_name: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        endpoint_url: str | None = None,
        config: Config | None = None,
    ) -> BaseClient:
        """
        Build and return client for connections originating outside LocalEmu and targeting AWS.

        If either of the access keys or region are set to None, they are loaded from following
        locations:
        - AWS environment variables
        - Credentials file `~/.aws/credentials`
        - Config file `~/.aws/config`

        :param service_name: Service to build the client for, eg. `s3`
        :param region_name: Name of the AWS region to be associated with the client
            If set to None, loads from botocore session.
        :param aws_access_key_id: Access key to use for the client.
            If set to None, loads from botocore session.
        :param aws_secret_access_key: Secret key to use for the client.
            If set to None, loads from botocore session.
        :param aws_session_token: Session token to use for the client.
            Not being used if not set.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate AWS endpoint.
        :param config: Boto config for advanced use.
        """
        if config is None:
            config = self._config
        else:
            config = self._config.merge(config)

        return self._get_client(
            config=config,
            service_name=service_name,
            region_name=region_name or self._get_session_region(),
            endpoint_url=endpoint_url,
            use_ssl=True,
            verify=True,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
        )


def resolve_dns_from_upstream(hostname: str) -> str:
    # Resolve via the host's configured upstream resolver (read from
    # /etc/resolv.conf by dnspython) rather than any local loopback
    # resolution. The whole ExternalBypassDns* class chain exists
    # precisely to reach real AWS endpoints, so we must not loop back
    # into the local resolver here.
    nameservers = dns.resolver.get_default_resolver().nameservers
    if not nameservers:
        raise RuntimeError("No upstream DNS resolver configured on host")
    upstream_dns = nameservers[0]

    request = dns.message.make_query(hostname, "A")
    response = dns.query.udp(request, upstream_dns, port=53, timeout=5)
    if len(response.answer) == 0:
        raise ValueError(f"No DNS response found for hostname '{hostname}'")

    ip_addresses = []
    for answer in response.answer:
        if answer.match(dns.rdataclass.IN, dns.rdatatype.A, dns.rdatatype.NONE):
            ip_addresses.extend(answer.items.keys())

    if not ip_addresses:
        raise ValueError(f"No DNS records of type 'A' found for hostname '{hostname}'")

    return choice(ip_addresses).address


class ExternalBypassDnsClientFactory(ExternalAwsClientFactory):
    """
    Client factory for requests against real AWS: hostnames are resolved via the
    host's upstream resolver so they are not redirected to localhost.
    """

    def __init__(
        self,
        session: Session = None,
        config: Config = None,
    ):
        if ca_cert := os.getenv("REQUESTS_CA_BUNDLE"):
            LOG.debug("Creating External AWS Client with REQUESTS_CA_BUNDLE=%s", ca_cert)

        proxy_config = Config(
            proxies={
                "http": localemu_config.OUTBOUND_HTTP_PROXY,
                "https": localemu_config.OUTBOUND_HTTPS_PROXY,
            }
        )

        super().__init__(
            use_ssl=localemu_config.is_env_not_false("USE_SSL"),
            verify=ca_cert or True,
            session=session,
            config=config.merge(proxy_config) if config else proxy_config,
        )

    def _get_client_post_hook(self, client: BaseClient) -> BaseClient:
        client = super()._get_client_post_hook(client)
        client._endpoint.http_session = ExternalBypassDnsSession(
            verify=self._verify, proxies=self._config.proxies
        )
        return client


class ExternalBypassDnsHTTPConnection(AWSHTTPConnection):
    """
    Connection class that resolves AWS hostnames via the host's upstream resolver for HTTP connections
    """

    def _new_conn(self) -> socket:
        orig_host = self._dns_host
        try:
            self._dns_host = resolve_dns_from_upstream(self._dns_host)
            return super()._new_conn()
        finally:
            self._dns_host = orig_host


class ExternalBypassDnsHTTPSConnection(AWSHTTPSConnection):
    """
    Connection class that resolves AWS hostnames via the host's upstream resolver for HTTPS connections
    """

    def _new_conn(self) -> socket:
        orig_host = self._dns_host
        try:
            self._dns_host = resolve_dns_from_upstream(self._dns_host)
            return super()._new_conn()
        finally:
            self._dns_host = orig_host


class ExternalBypassDnsHTTPConnectionPool(AWSHTTPConnectionPool):
    ConnectionCls = ExternalBypassDnsHTTPConnection


class ExternalBypassDnsHTTPSConnectionPool(AWSHTTPSConnectionPool):
    ConnectionCls = ExternalBypassDnsHTTPSConnection


class ExternalBypassDnsSession(URLLib3Session):
    """
    urllib3 session wrapper that uses our custom connection pool.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._pool_classes_by_scheme["https"] = ExternalBypassDnsHTTPSConnectionPool
        self._pool_classes_by_scheme["http"] = ExternalBypassDnsHTTPConnectionPool


connect_to = InternalClientFactory(use_ssl=localemu_config.DISTRIBUTED_MODE)
connect_externally_to = ExternalClientFactory()


#
# Handlers
#


def _handler_create_request_parameters(params: dict[str, Any], context: dict[str, Any], **kwargs):
    """
    Construct the data transfer object at the time of parsing the client
    parameters and proxy it via the Boto context dict.

    This handler enables the use of additional keyword parameters in Boto API
    operation functions.

    It uses the `InternalRequestParameters` type annotations to handle supported parameters.
    The keys supported by this type will be converted to method parameters by prefixing it with an underscore `_`
    and converting the snake case to camel case.
    Example:
        service_principal -> _ServicePrincipal
    """

    # Names of arguments that can be passed to Boto API operation functions.
    # These must correspond to entries on the data transfer object.
    dto = InternalRequestParameters()
    for member in InternalRequestParameters.__annotations__.keys():
        parameter = f"_{''.join([part.title() for part in member.split('_')])}"
        if parameter in params:
            dto[member] = params.pop(parameter)

    context["_localemu"] = dto


def _handler_inject_dto_header(params: dict[str, Any], context: dict[str, Any], **kwargs):
    """
    Retrieve the data transfer object from the Boto context dict and serialise
    it as part of the request headers.
    """
    if (dto := context.pop("_localemu", None)) is not None:
        params["headers"][INTERNAL_REQUEST_PARAMS_HEADER] = dump_dto(dto)
        params["headers"][INTERNAL_REQUEST_AUTH_HEADER] = INTERNAL_REQUEST_AUTH_TOKEN
