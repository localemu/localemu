import re
from collections.abc import Iterable
from typing import TypeVar

import pytest

from localemu.services.cloudformation.v2.utils import is_v2_engine
from localemu.testing.aws.util import is_aws_cloud
from localemu.utils.collections import optional_list

SKIP_TYPE_RE = re.compile(r"^CFNV2\((?P<reason>[^\)]+)\)")


def skip_if_legacy_engine(reason: str | None = None):
    return pytest.mark.skipif(
        condition=not is_v2_engine() and not is_aws_cloud(),
        reason=reason or "Not implemented in legacy engine",
    )


T = TypeVar("T")


def skipped_v2_items(*items: Iterable[T]) -> list[T]:
    return optional_list(is_v2_engine(), items)
