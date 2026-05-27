import random
import string
from contextlib import contextmanager

from moto.utilities import id_generator as moto_id_generator
from moto.utilities.id_generator import MotoIdManager, ResourceIdentifier, moto_id
from moto.utilities.id_generator import ResourceIdentifier as MotoResourceIdentifier

from localemu.utils.strings import long_uid, short_uid

ExistingIds = list[str] | None
Tags = dict[str, str] | None


class LocalemuIdManager(MotoIdManager):
    def set_custom_id_by_unique_identifier(self, unique_identifier: str, custom_id: str):
        with self._lock:
            self._custom_ids[unique_identifier] = custom_id

    @contextmanager
    def custom_id(self, resource_identifier: ResourceIdentifier, custom_id: str) -> None:
        try:
            yield self.set_custom_id(resource_identifier, custom_id)
        finally:
            self.unset_custom_id(resource_identifier)


localemu_id_manager = LocalemuIdManager()
moto_id_generator.moto_id_manager = localemu_id_manager
localemu_id = moto_id

ResourceIdentifier = MotoResourceIdentifier


@localemu_id
def generate_uid(
    resource_identifier: ResourceIdentifier,
    existing_ids: ExistingIds = None,
    tags: Tags = None,
    length=36,
) -> str:
    return long_uid()[:length]


@localemu_id
def generate_short_uid(
    resource_identifier: ResourceIdentifier,
    existing_ids: ExistingIds = None,
    tags: Tags = None,
) -> str:
    return short_uid()


@localemu_id
def generate_str_id(
    resource_identifier: ResourceIdentifier,
    existing_ids: ExistingIds = None,
    tags: Tags = None,
    length=8,
) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(length))
