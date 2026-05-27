from localemu.aws.api.opensearch import DomainStatus
from localemu.services.stores import (
    AccountRegionBundle,
    BaseStore,
    LocalAttribute,
)
from localemu.utils.tagging import Tags


class OpenSearchStore(BaseStore):
    # storage for domain resources (access should be protected with the _domain_mutex)
    opensearch_domains: dict[str, DomainStatus] = LocalAttribute(default=dict)
    tags: Tags = LocalAttribute(default=Tags)


opensearch_stores = AccountRegionBundle("opensearch", OpenSearchStore)
