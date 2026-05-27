import logging
import os
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from localemu.aws.accounts import (
    get_account_id_from_access_key_id,
)
from localemu.constants import (
    ANONYMOUS_ACCESS_KEY_ID,
    AWS_REGION_US_EAST_1,
    DEFAULT_AWS_ACCOUNT_ID,
)
from localemu.http import Response
from localemu.utils.aws.request_context import (
    extract_access_key_id_from_auth_header,
    mock_aws_request_headers,
)

from ..api import CommonServiceException, RequestContext
from ..chain import Handler, HandlerChain

LOG = logging.getLogger(__name__)


def _has_presigned_credentials(context: RequestContext) -> bool:
    """True if the request carries a presigned credential in the query string.

    Covers SigV4 presigned URLs (``X-Amz-Credential`` / ``X-Amz-Signature``)
    and the legacy SigV2 form (``AWSAccessKeyId`` + ``Signature``). Such a
    request is signed even though it has no Authorization header, so it must
    not be stamped with the anonymous sentinel.
    """
    try:
        qs = parse_qs(urlparse(context.request.url).query)
    except Exception:
        return False
    if "X-Amz-Credential" in qs or "X-Amz-Signature" in qs:
        return True
    if "AWSAccessKeyId" in qs and "Signature" in qs:
        return True
    return False


class MissingAuthHeaderInjector(Handler):
    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # Requests that reach the gateway without any credentials get an
        # Authorization header stamped with the ANONYMOUS sentinel key, so the
        # downstream signing / account-resolution path has something to work
        # with. Under IAM enforcement this sentinel resolves to the anonymous
        # principal (resource-policy-only evaluation: public allowed, private
        # denied), matching AWS semantics for unsigned requests.
        if not context.service:
            return

        api = context.service.service_name
        headers = context.request.headers

        if headers.get("Authorization"):
            return

        # A presigned URL carries its credential in the query string, not the
        # Authorization header. Stamping the anonymous sentinel here would mask
        # that real credential and mis-classify a signed request as anonymous,
        # so leave presigned requests untouched and let their query-string
        # credential flow through to the enforcer.
        if _has_presigned_credentials(context):
            return

        headers["Authorization"] = mock_aws_request_headers(
            api, aws_access_key_id=ANONYMOUS_ACCESS_KEY_ID, region_name=AWS_REGION_US_EAST_1
        )["Authorization"]


class TemporaryCredentialValidator(Handler):
    """EMU-02 / EMU-05: Validates temporary credentials (SessionToken presence
    and expiration) before service dispatch.

    Only active when IAM_ENFORCEMENT is enabled.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        mode = os.environ.get("IAM_ENFORCEMENT", "").strip().lower()
        if mode not in ("1", "soft"):
            return

        if not context.service:
            return

        access_key_id = extract_access_key_id_from_auth_header(context.request.headers)
        if not access_key_id:
            return

        # Temporary credentials have ASIA/LSIA prefix — they MUST include a SessionToken
        is_temp = access_key_id.startswith(("ASIA", "LSIA"))
        if not is_temp:
            return

        # EMU-02: Check SessionToken presence for temporary credentials
        headers = context.request.headers
        # SigV4 sends X-Amz-Security-Token header; presigned URLs use query param
        security_token = headers.get("X-Amz-Security-Token", "")
        if not security_token:
            try:
                qs = parse_qs(urlparse(context.request.url).query)
                security_token = qs.get("X-Amz-Security-Token", [None])[0] or ""
            except Exception:
                security_token = ""

        if not security_token:
            msg = "Request is missing required security token"
            if mode == "soft":
                LOG.warning("IAM AUDIT: %s (key=%s)", msg, access_key_id[:8])
                return
            raise CommonServiceException(
                code="AccessDenied",
                message=msg,
                status_code=403,
            )

        # EMU-05: Check credential expiration
        try:
            from localemu.services.sts.models import sts_stores, sts_store_lock
            account_id = context.account_id or get_account_id_from_access_key_id(access_key_id)
            store = sts_stores[account_id]["us-east-1"]
            with sts_store_lock:
                session_cfg = store.sessions.get(access_key_id)
            if session_cfg and session_cfg.get("expiration"):
                exp = session_cfg["expiration"]
                if isinstance(exp, datetime) and exp < datetime.now(timezone.utc):
                    msg = f"The security token included in the request is expired"
                    if mode == "soft":
                        LOG.warning("IAM AUDIT: %s (key=%s, expired=%s)", msg, access_key_id[:8], exp.isoformat())
                        return
                    raise CommonServiceException(
                        code="ExpiredTokenException",
                        message=msg,
                        status_code=403,
                    )
        except CommonServiceException:
            raise
        except Exception as e:
            LOG.debug("Failed to check credential expiration for %s: %s", access_key_id[:8], e)


class AccountIdEnricher(Handler):
    """
    A handler that sets the AWS account of the request in the RequestContext.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # Obtain the access key ID
        access_key_id = (
            extract_access_key_id_from_auth_header(context.request.headers)
            or DEFAULT_AWS_ACCOUNT_ID
        )

        # Obtain the account ID from access key ID
        context.account_id = get_account_id_from_access_key_id(access_key_id)

        # Make Moto use the same Account ID as LocalEmu
        context.request.headers.add("x-moto-account-id", context.account_id)
