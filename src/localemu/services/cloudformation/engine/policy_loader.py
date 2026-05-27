import logging

from samtranslator.translator.managed_policy_translator import ManagedPolicyLoader

from localemu.aws.connect import connect_to

LOG = logging.getLogger(__name__)


_policy_loaders: dict[tuple[str, str], ManagedPolicyLoader] = {}


def create_policy_loader(
    account_id: str | None = None, region_name: str | None = None
) -> ManagedPolicyLoader:
    cache_key = (account_id or "", region_name or "")
    if cache_key not in _policy_loaders:
        iam_client = connect_to(
            aws_access_key_id=account_id, region_name=region_name
        ).iam
        _policy_loaders[cache_key] = ManagedPolicyLoader(iam_client=iam_client)
    return _policy_loaders[cache_key]
