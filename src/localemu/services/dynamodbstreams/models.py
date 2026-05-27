import dataclasses

from localemu.aws.api.dynamodbstreams import StreamDescription
from localemu.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


@dataclasses.dataclass
class StreamWrapper:
    """Wrapper for the API stub and additional information about a store"""

    StreamDescription: StreamDescription
    shards_id_map: dict[str, str] = dataclasses.field(default_factory=dict)


class DynamoDbStreamsStore(BaseStore):
    ddb_streams: dict[str, StreamWrapper] = LocalAttribute(default=dict)


dynamodbstreams_stores = AccountRegionBundle("dynamodbstreams", DynamoDbStreamsStore)
