import logging
import re
from urllib.parse import urlparse

from localemu import config, constants
from localemu.aws.connect import connect_to
from localemu.services.cloudformation.engine.validations import ValidationError
from localemu.services.s3.utils import (
    extract_bucket_name_and_key_from_headers_and_path,
    normalize_bucket_name,
)
from localemu.utils.functions import run_safe
from localemu.utils.http import safe_requests
from localemu.utils.strings import to_str
from localemu.utils.urls import localemu_host

LOG = logging.getLogger(__name__)


def prepare_template_body(req_data: dict) -> str | bytes | None:  # TODO: mutating and returning
    template_url = req_data.get("TemplateURL")
    if template_url:
        req_data["TemplateURL"] = convert_s3_to_local_url(template_url)
    url = req_data.get("TemplateURL", "")
    if is_local_service_url(url):
        modified_template_body = get_template_body(req_data)
        if modified_template_body:
            req_data.pop("TemplateURL", None)
            req_data["TemplateBody"] = modified_template_body
    modified_template_body = get_template_body(req_data)
    if modified_template_body:
        req_data["TemplateBody"] = modified_template_body
    return modified_template_body


def extract_template_body(request: dict) -> str:
    """
    Given a request payload, fetch the body of the template either from S3 or from the payload itself
    """
    if template_body := request.get("TemplateBody"):
        if request.get("TemplateURL"):
            raise ValidationError(
                "Specify exactly one of 'TemplateBody' or 'TemplateUrl'"
            )  # TODO: check proper message

        return template_body

    elif template_url := request.get("TemplateURL"):
        template_url = convert_s3_to_local_url(template_url)
        return get_remote_template_body(template_url)

    else:
        raise ValidationError(
            "Specify exactly one of 'TemplateBody' or 'TemplateUrl'"
        )  # TODO: check proper message


# AWS maximum template size for URL-sourced templates (460,800 bytes)
MAX_TEMPLATE_SIZE_URL = 460_800


def get_remote_template_body(url: str) -> str:
    response = run_safe(lambda: safe_requests.get(url, verify=False))
    # check error codes, and code 301 - fixes https://github.com/localstack/localstack/issues/1884
    status_code = 0 if response is None else response.status_code
    if 200 <= status_code < 300:
        body = response.text
        if len(body.encode("utf-8")) > MAX_TEMPLATE_SIZE_URL:
            raise ValidationError(
                f"Template body is too long. The maximum template size for URL-sourced templates is {MAX_TEMPLATE_SIZE_URL} bytes."
            )
        return body
    elif response is None or status_code == 301 or status_code >= 400:
        # check if this is an S3 URL, then get the file directly from there
        url = convert_s3_to_local_url(url)
        if is_local_service_url(url):
            parsed_path = urlparse(url).path.lstrip("/")
            parts = parsed_path.partition("/")
            client = connect_to().s3
            LOG.debug(
                "Download CloudFormation template content from local S3: %s - %s",
                parts[0],
                parts[2],
            )
            result = client.get_object(Bucket=parts[0], Key=parts[2])
            body = to_str(result["Body"].read())
            if len(body.encode("utf-8")) > MAX_TEMPLATE_SIZE_URL:
                raise ValidationError(
                    f"Template body is too long. The maximum template size for URL-sourced templates is {MAX_TEMPLATE_SIZE_URL} bytes."
                )
            return body
        raise RuntimeError(f"Unable to fetch template body (code {status_code}) from URL {url}")
    else:
        raise RuntimeError(
            f"Bad status code from fetching template from url '{url}' ({status_code})",
            url,
            status_code,
        )


def get_template_body(req_data: dict) -> str:
    body = req_data.get("TemplateBody")
    if body:
        return body
    url = req_data.get("TemplateURL")
    if url:
        return get_remote_template_body(url)
    raise Exception(f"Unable to get template body from input: {req_data}")


def is_local_service_url(url: str) -> bool:
    if not url:
        return False
    candidates = (
        constants.LOCALHOST,
        constants.LOCALHOST_HOSTNAME,
        localemu_host().host,
    )
    if any(re.match(rf"^[^:]+://[^:/]*{host}([:/]|$)", url) for host in candidates):
        return True
    host = url.split("://")[-1].split("/")[0]
    return "localhost" in host


def convert_s3_to_local_url(url: str) -> str:
    from localemu.services.cloudformation.provider import ValidationError

    url_parsed = urlparse(url)
    path = url_parsed.path

    headers = {"host": url_parsed.netloc}
    bucket_name, key_name = extract_bucket_name_and_key_from_headers_and_path(headers, path)

    if url_parsed.scheme == "s3":
        # s3:// URLs use the netloc as bucket name and path as key
        bucket_name = url_parsed.netloc
        key_name = url_parsed.path.lstrip("/")
        if not bucket_name or not key_name:
            raise ValidationError(
                f"S3 error: Invalid s3:// URL format: {url}"
            )

    if not bucket_name or not key_name:
        if not (url_parsed.netloc.startswith("s3.") or ".s3." in url_parsed.netloc):
            raise ValidationError("TemplateURL must be a supported URL.")

    # note: make sure to normalize the bucket name here!
    bucket_name = normalize_bucket_name(bucket_name)
    local_url = f"{config.internal_service_url()}/{bucket_name}/{key_name}"
    return local_url


def validate_stack_name(stack_name):
    pattern = r"[a-zA-Z][-a-zA-Z0-9]*|arn:[-a-zA-Z0-9:/._+]*"
    return re.match(pattern, stack_name) is not None
