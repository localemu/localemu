import io
import json
import logging
import os
from collections.abc import Iterator
from datetime import datetime, timezone
from enum import Enum
from json import JSONDecodeError
from pathlib import Path
from re import Pattern
from typing import Dict, List, Optional

from deepdiff import DeepDiff
from jsonpath_ng import DatumInContext
from jsonpath_ng.ext import parse

from localemu.testing.snapshots.transformer import (
    KeyValueBasedTransformer,
    RegexTransformer,
    TransformContext,
    Transformer,
)
from localemu.testing.snapshots.encoding import CustomJsonEncoder

from .transformer_utility import TransformerUtility

SNAPSHOT_LOGGER = logging.getLogger(__name__)
SNAPSHOT_LOGGER.setLevel(logging.DEBUG if os.environ.get("DEBUG_SNAPSHOT") else logging.WARNING)

_SKIP_PLACEHOLDER_VALUE = "$__to_be_skipped__$"


class SnapshotMatchResult:
    def __init__(self, a: dict, b: dict, key: str = ""):
        self.a = a
        self.b = b
        self.result = DeepDiff(a, b, verbose_level=2, view="tree")
        self.key = key

    def __bool__(self) -> bool:
        return not self.result

    def __repr__(self):
        return self.result.pretty()


class SnapshotAssertionError(AssertionError):
    def __init__(self, msg: str, result: List[SnapshotMatchResult]):
        self.msg = msg
        self.result = result
        super(SnapshotAssertionError, self).__init__(msg)


class SnapshotSession:
    """
    snapshot handler for a single test function with potentially multiple assertions\
    Since it technically only  modifies a subset of the underlying snapshot file,
    it assumes that a single snapshot file is only being written to sequentially
    """

    results: list[SnapshotMatchResult]
    recorded_state: dict[str, dict]  # previously persisted state
    observed_state: dict[str, dict]  # current state from match calls

    called_keys: set[str]
    transformers: list[(Transformer, int)]  # (transformer, priority)

    transform: TransformerUtility

    skip_verification_paths: list[str]

    def __init__(
        self,
        *,
        base_file_path: str,
        scope_key: str,
        update: Optional[bool] = False,  # TODO: find a way to remove this
        verify: Optional[bool] = False,  # TODO: find a way to remove this
        raw: Optional[bool] = False,
    ):
        self.verify = verify
        self.update = update
        self.file_path = f"{base_file_path}.snapshot.json"
        self.raw_file_path = f"{base_file_path}.raw.snapshot.json"
        self.raw = raw
        self.scope_key = scope_key

        self.called_keys = set()
        self.results = []
        self.transformers = []

        self.observed_state = {}
        self.recorded_state = self._load_state()

        self.transform = TransformerUtility

    def add_transformers_list(
        self, transformer_list: list[Transformer], priority: Optional[int] = 0
    ):
        for transformer in transformer_list:
            self.transformers.append((transformer, priority))  # TODO

    def add_transformer(
        self, transformer: Transformer | list[Transformer], *, priority: Optional[int] = 0
    ):
        if isinstance(transformer, list):
            self.add_transformers_list(transformer, priority)
        else:
            self.transformers.append((transformer, priority or 0))

    def _persist_state(self) -> None:
        if self.update:
            Path(self.file_path).touch()
            with open(self.file_path, "r+") as fd:
                try:
                    content = fd.read()
                    full_state = json.loads(content or "{}")
                    recorded = {
                        "recorded-date": datetime.now(tz=timezone.utc).strftime(
                            "%d-%m-%Y, %H:%M:%S"
                        ),
                        "recorded-content": self.observed_state,
                    }
                    full_state[self.scope_key] = recorded
                    state_to_dump = json.dumps(full_state, indent=2)
                    fd.seek(0)
                    fd.truncate()
                    # add line ending to be compatible with pre-commit-hooks (end-of-file-fixer)
                    fd.write(f"{state_to_dump}\n")
                except Exception as e:
                    SNAPSHOT_LOGGER.exception(e)

    def _persist_raw(self, raw_state: dict) -> None:
        if self.raw:
            Path(self.raw_file_path).touch()
            with open(self.raw_file_path, "r+") as fd:
                try:
                    content = fd.read()
                    full_state = json.loads(content or "{}")
                    recorded = {
                        "recorded-date": datetime.now(tz=timezone.utc).strftime(
                            "%d-%m-%Y, %H:%M:%S"
                        ),
                        "recorded-content": raw_state,
                    }
                    full_state[self.scope_key] = recorded
                    # need to use CustomEncoder to handle datetime objects
                    state_to_dump = json.dumps(full_state, indent=2, cls=CustomJsonEncoder)
                    fd.seek(0)
                    fd.truncate()
                    # add line ending to be compatible with pre-commit-hooks (end-of-file-fixer)
                    fd.write(f"{state_to_dump}\n")
                except Exception as e:
                    SNAPSHOT_LOGGER.exception(e)

    def _load_state(self) -> dict:
        try:
            with open(self.file_path, "r") as fd:
                content = fd.read()
                if content:
                    recorded = json.loads(content).get(self.scope_key, {})
                    return recorded.get("recorded-content", None)
                else:
                    return {}
        except FileNotFoundError:
            return {}

    def _update(self, key: str, obj_state: dict) -> None:
        self.observed_state[key] = obj_state

    def match_object(self, key: str, obj: object) -> None:
        def _convert_object_to_dict(obj_):
            if isinstance(obj_, dict):
                # Serialize the values of the dictionary, while skipping any private keys (starting with '_')
                return {
                    key_: _convert_object_to_dict(obj_[key_])
                    for key_ in obj_
                    if not key_.startswith("_")
                }
            elif isinstance(obj_, (list, Iterator)):
                return [_convert_object_to_dict(val) for val in obj_]
            elif isinstance(obj_, Enum):
                return obj_.value
            elif hasattr(obj_, "__dict__"):
                # This is an object - let's try to convert it to a dictionary
                # A naive approach would be to use the '__dict__' object directly, but that only lists the attributes.
                # In order to also serialize the properties, we use the __dir__() method
                # Filtering by everything that is not a method gives us both attributes and properties
                # We also (still) skip private attributes/properties, so everything that starts with an underscore.
                return {
                    k: _convert_object_to_dict(getattr(obj_, k))
                    for k in obj_.__dir__()
                    if (
                        # Skip private attributes
                        not k.startswith("_")
                        # Skip everything that's not a method
                        and type(getattr(obj_, k, "")).__name__ != "method"
                        # Skip everything that refers to itself (identity functions), as that leads to recursion
                        and getattr(obj_, k) != obj_
                    )
                }
            return obj_

        return self.match(key, _convert_object_to_dict(obj))

    def match(self, key: str, obj: dict) -> None:
        if key in self.called_keys:
            raise Exception(
                f"Key {key} used multiple times in the same test scope"
            )  # TODO: custom exc.

        self.called_keys.add(key)

        # order the obj to guarantee reference replacement works as expected
        self.observed_state[key] = self._order_dict(obj)
        # TODO: track them separately since the transformation is now done *just* before asserting

        if not self.update and (not self.recorded_state or self.recorded_state.get(key) is None):
            raise Exception(
                f"No state for {self.scope_key} recorded. Please (re-)generate the snapshot for this test."
            )

        # TODO: we should return something meaningful here
        return True

    def _assert_all(
        self, verify_test_case: bool = True, skip_verification_paths: Optional[list[str]] = None
    ) -> List[SnapshotMatchResult]:
        """use after all match calls to get a combined diff"""
        results = []

        if not self.verify:
            SNAPSHOT_LOGGER.warning("Snapshot verification disabled.")
            return results

        if self.verify and not verify_test_case and not skip_verification_paths:
            self.verify = False
            SNAPSHOT_LOGGER.warning("Snapshot verification disabled for this test case.")

        self.skip_verification_paths = skip_verification_paths or []
        if skip_verification_paths:
            SNAPSHOT_LOGGER.warning(
                "Snapshot verification disabled for paths: %s", skip_verification_paths
            )

        if self.update:
            self.observed_state = self._transform(self.observed_state)
            return []

        # TODO: separate these states
        a_all = self.recorded_state
        if not self.observed_state:
            # match was never called, so we must assume this isn't a "real" snapshot test
            # e.g. test_sqs uses the snapshot fixture to configure it via another fixture on module scope
            #   but might not use them in some individual tests
            return []

        if not a_all and not self.update:
            raise Exception(
                f"No state for {self.scope_key} recorded. Please (re-)generate the snapshot for this test."
            )

        self._remove_skip_verification_paths(a_all)
        self.observed_state = b_all = self._transform(self.observed_state)

        for key in self.called_keys:
            a = a_all.get(
                key
            )  # if this is None, a new key was added since last updating => usage error
            if a is None:
                raise Exception(
                    f"State for {key=} missing in {self.scope_key}. Please (re-)generate the snapshot for this test."
                )
            b = b_all[key]
            result = SnapshotMatchResult(a, b, key=key)
            results.append(result)

        if any(not result for result in results) and self.verify:
            raise SnapshotAssertionError("Parity snapshot failed", result=results)
        return results

    def _transform_dict_to_parseable_values(self, original):
        """recursively goes through dict and tries to resolve values to strings (& parse them as json if possible)"""
        for k, v in original.items():
            if isinstance(v, io.IOBase):
                # update v for json parsing below
                # TODO: patch boto client so this doesn't break any further read() calls
                original[k] = v = v.read().decode("utf-8")
            if isinstance(v, list) and v:
                for item in v:
                    if isinstance(item, dict):
                        self._transform_dict_to_parseable_values(item)
            if isinstance(v, Dict):
                self._transform_dict_to_parseable_values(v)

            if isinstance(v, str) and v.startswith("{"):
                # Doesn't handle JSON arrays and nested JSON strings. See JsonStringTransformer.
                # TODO for the major release consider having JSON parsing in one place only: either here or in JsonStringTransformer
                try:
                    json_value = json.loads(v)
                    original[k] = json_value
                except JSONDecodeError:
                    pass  # parsing error can be ignored

    def _transform(self, tmp: dict) -> dict:
        """build a persistable state definition that can later be compared against"""
        self._transform_dict_to_parseable_values(tmp)

        # persist tmp
        if self.raw:
            self._persist_raw(tmp)

        ctx = TransformContext()
        for transformer, _ in sorted(self.transformers, key=lambda p: p[1]):
            tmp = transformer.transform(tmp, ctx=ctx)

        if not self.update:
            self._remove_skip_verification_paths(tmp)

        replaced_tmp = {}
        # avoid replacements in snapshot keys
        for key, value in tmp.items():
            dumped_value = json.dumps(value, default=str)
            for sr in ctx.serialized_replacements:
                dumped_value = sr(dumped_value)

            assert dumped_value
            try:
                replaced_tmp[key] = json.loads(dumped_value)
            except JSONDecodeError:
                SNAPSHOT_LOGGER.error("could not decode json-string:\n%s", tmp)
                return {}

        return replaced_tmp

    def _order_dict(self, response) -> dict:
        if isinstance(response, dict):
            ordered_dict = {}
            for key, val in sorted(response.items()):
                if isinstance(val, dict):
                    ordered_dict[key] = self._order_dict(val)
                elif isinstance(val, list):
                    ordered_dict[key] = [self._order_dict(entry) for entry in val]
                else:
                    ordered_dict[key] = val

            # put the ResponseMetadata back at the end of the response
            if "ResponseMetadata" in ordered_dict:
                ordered_dict["ResponseMetadata"] = ordered_dict.pop("ResponseMetadata")

            return ordered_dict
        else:
            return response

    # LEGACY API
    def register_replacement(self, pattern: Pattern[str], value: str):
        self.add_transformer(RegexTransformer(pattern, value))

    def skip_key(self, pattern: Pattern[str], value: str):
        self.add_transformer(
            KeyValueBasedTransformer(
                lambda k, v: v if bool(pattern.match(k)) else None,
                replacement=value,
                replace_reference=False,
            )
        )

    def replace_value(self, pattern: Pattern[str], value: str):
        self.add_transformer(
            KeyValueBasedTransformer(
                lambda _, v: v if bool(pattern.match(v)) else None,
                replacement=value,
                replace_reference=False,
            )
        )

    def _remove_skip_verification_paths(self, tmp: Dict):
        """Removes all keys from the dict, that match the given json-paths in self.skip_verification_path"""

        def build_full_path_nodes(field_match: DatumInContext):
            """Traverse the matched Datum to build the path field by field"""
            full_path_nodes = [str(field_match.path).replace("'", "")]
            next_node = field_match
            while next_node.context is not None:
                full_path_nodes.append(str(next_node.context.path))
                next_node = next_node.context

            return full_path_nodes[::-1][1:]  # reverse the list and remove Root()/$

        def _remove_placeholder(_tmp):
            """Traverse the object and remove any values in a list that would be equal to the placeholder"""
            if isinstance(_tmp, dict):
                for k, v in _tmp.items():
                    if isinstance(v, dict):
                        _remove_placeholder(v)
                    elif isinstance(v, list):
                        _tmp[k] = _remove_placeholder(v)
            elif isinstance(_tmp, list):
                return [
                    _remove_placeholder(item) for item in _tmp if item != _SKIP_PLACEHOLDER_VALUE
                ]

            return _tmp

        has_placeholder = False

        for path in self.skip_verification_paths:
            matches = parse(path).find(tmp) or []
            for m in matches:
                full_path = build_full_path_nodes(m)
                helper = tmp
                if len(full_path) > 1:
                    for p in full_path[:-1]:
                        if isinstance(helper, list) and p.lstrip("[").rstrip("]").isnumeric():
                            helper = helper[int(p.lstrip("[").rstrip("]"))]
                        elif isinstance(helper, dict):
                            helper = helper.get(p, None)
                            if not helper:
                                continue

                if (
                    isinstance(helper, dict) and full_path[-1] in helper.keys()
                ):  # might have been deleted already
                    del helper[full_path[-1]]
                elif isinstance(helper, list):
                    try:
                        index = int(full_path[-1].lstrip("[").rstrip("]"))
                        # we need to set a placeholder value as the skips are based on index
                        # if we are to pop the values, the next skip index will have shifted and won't be correct
                        helper[index] = _SKIP_PLACEHOLDER_VALUE
                        has_placeholder = True
                    except ValueError:
                        SNAPSHOT_LOGGER.warning(
                            "Snapshot skip path '%s' was not applied as it was invalid for that snapshot",
                            path,
                            exc_info=SNAPSHOT_LOGGER.isEnabledFor(logging.DEBUG),
                        )

        if has_placeholder:
            _remove_placeholder(tmp)
