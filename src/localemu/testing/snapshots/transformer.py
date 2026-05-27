import copy
import json
import logging
import os
import re
from datetime import datetime
from json import JSONDecodeError
from re import Pattern
from typing import Any, Callable, Optional, Protocol

from jsonpath_ng.ext import parse

SNAPSHOT_LOGGER = logging.getLogger(__name__)
SNAPSHOT_LOGGER.setLevel(logging.DEBUG if os.environ.get("DEBUG_SNAPSHOT") else logging.WARNING)

# Types

GlobalReplacementFn = Callable[[str], str]


class TransformerException(Exception):
    pass


class TransformContext:
    _cache: dict
    replacements: list[GlobalReplacementFn]
    scoped_tokens: dict[str, int]

    def __init__(self):
        self.replacements = []
        self.scoped_tokens = {}
        self._cache = {}

    @property
    def serialized_replacements(self) -> list[GlobalReplacementFn]:  # TODO: naming
        return self.replacements

    def register_serialized_replacement(self, fn: GlobalReplacementFn):  # TODO: naming
        self.replacements.append(fn)

    def new_scope(self, scope: str) -> int:
        """retrieve new enumeration value for a given scope key (e.g. for tokens such as <fn-name:1>"""
        current_counter = self.scoped_tokens.setdefault(scope, 1)
        self.scoped_tokens[scope] += 1
        return current_counter


def _register_serialized_reference_replacement(
    transform_context: TransformContext, *, reference_value: str, replacement: str
):
    # Provide a better error message for the TypeError if the reference value is not iterable (e.g., float)
    # Example: `TypeError: argument of type 'float' is not iterable`
    # Using a list would throw an AttributeError because `.replace` is not applicable.
    # The snapshot library currently only supports strings for reference replacements
    if not isinstance(reference_value, str):
        message = (
            f"The reference value {reference_value} of type {type(reference_value)} is not a string."
            f" Consider using `reference_replacement=False` in your transformer"
            f" for the replacement {replacement} because reference replacements are only supported for strings."
        )
        SNAPSHOT_LOGGER.error(message)
        raise TransformerException(message)

    if '"' in reference_value:
        reference_value = reference_value.replace('"', '\\"')

    cache = transform_context._cache.setdefault("regexcache", set())
    cache_key = reference_value
    if cache_key not in cache:
        actual_replacement = f"<{replacement}:{transform_context.new_scope(replacement)}>"
        cache.add(cache_key)

        def _helper(bound_result, bound_replacement):
            def replace_val(s):
                SNAPSHOT_LOGGER.debug(
                    f"Replacing '{bound_result}' in snapshot with '{bound_replacement}'"
                )
                return s.replace(bound_result, bound_replacement, -1)

            return replace_val

        SNAPSHOT_LOGGER.debug(
            f"Registering reference replacement for value: '{reference_value:.200s}' -> '{actual_replacement}'"
        )
        transform_context.register_serialized_replacement(
            _helper(reference_value, actual_replacement)
        )


class Transformer(Protocol):
    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        ...


# Transformers


class ResponseMetaDataTransformer:
    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        for k, v in input_data.items():
            if k == "ResponseMetadata":
                metadata = v
                http_headers = metadata.get("HTTPHeaders")
                if not isinstance(http_headers, dict):
                    continue

                # TODO "x-amz-bucket-region"
                # TestS3.test_region_header_exists -> verifies bucket-region

                # FIXME: proper value is `content-type` with no underscore in lowercase, but this will necessitate a
                #  refresh of all snapshots
                headers_to_collect = ["content_type"]
                simplified_headers = {}
                for h in headers_to_collect:
                    if http_headers.get(h):
                        simplified_headers[h] = http_headers[h]
                simplified_metadata = {
                    "HTTPHeaders": simplified_headers,
                }
                # HTTPStatusCode might be removed for marker skip_snapshot_verify
                if status_code := metadata.get("HTTPStatusCode"):
                    simplified_metadata["HTTPStatusCode"] = status_code
                input_data[k] = simplified_metadata
            elif isinstance(v, dict):
                input_data[k] = self.transform(v, ctx=ctx)
        return input_data


class JsonpathTransformer:
    def __init__(self, jsonpath: str, replacement: str, replace_reference: bool = True) -> None:
        self.jsonpath = jsonpath
        self.replacement = replacement
        self.replace_references = replace_reference

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        pattern = parse(self.jsonpath)

        if self.replace_references:
            res = pattern.find(input_data)
            if not res:
                SNAPSHOT_LOGGER.debug(f"No match found for JsonPath '{self.jsonpath}'")
                return input_data
            for r in res:
                value_to_replace = r.value
                _register_serialized_reference_replacement(
                    ctx, reference_value=value_to_replace, replacement=self.replacement
                )
        else:
            original = copy.deepcopy(input_data)
            pattern.update(input_data, self.replacement)
            if original != input_data:
                SNAPSHOT_LOGGER.debug(
                    f"Replacing JsonPath '{self.jsonpath}' in snapshot with '{self.replacement}'"
                )
            else:
                SNAPSHOT_LOGGER.debug(f"No match found for JsonPath '{self.jsonpath}'")

        return input_data

    def _add_jsonpath_replacement(self, jsonpath, replacement):
        self.json_path_replacement_list.append((jsonpath, replacement))


class RegexTransformer:
    def __init__(self, regex: str | Pattern[str], replacement: str):
        self.regex = regex
        self.replacement = replacement

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        compiled_regex = re.compile(self.regex) if isinstance(self.regex, str) else self.regex

        def _regex_replacer_helper(pattern: Pattern[str], repl: str):
            def replace_val(s):
                result = re.sub(pattern, repl, s)
                if result != s:
                    SNAPSHOT_LOGGER.debug(
                        f"Replacing regex '{pattern.pattern:.200s}' with '{repl}'"
                    )
                else:
                    SNAPSHOT_LOGGER.debug(f"No match found for regex '{pattern.pattern:.200s}'")
                return result

            return replace_val

        ctx.register_serialized_replacement(
            _regex_replacer_helper(compiled_regex, self.replacement)
        )
        SNAPSHOT_LOGGER.debug(
            f"Registering regex pattern '{compiled_regex.pattern:.200s}' in snapshot with '{self.replacement}'"
        )
        return input_data


class KeyValueBasedTransformerFunctionReplacement:
    def __init__(
        self,
        match_fn: Callable[[str, Any], Optional[str]],
        replacement_function: [Callable[[str, Any], str]],
        replace_reference: bool = True,
    ):
        self.match_fn = match_fn
        self.replacement_function = replacement_function
        self.replace_reference = replace_reference

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        for k, v in input_data.items():
            if (match_result := self.match_fn(k, v)) is not None:
                replacement = self.replacement_function(k, v)
                if self.replace_reference:
                    _register_serialized_reference_replacement(
                        ctx, reference_value=match_result, replacement=replacement
                    )
                else:
                    if isinstance(v, str):
                        SNAPSHOT_LOGGER.debug(
                            f"Replacing value for key '{k}': Match result '{match_result:.200s}' with '{replacement}'. (Original value: {str(v)})"
                        )
                        input_data[k] = v.replace(match_result, replacement)
                    else:
                        SNAPSHOT_LOGGER.debug(
                            f"Replacing value for key '{k}' with '{replacement}'. (Original value: {str(v)})"
                        )
                        input_data[k] = replacement
            elif isinstance(v, list) and len(v) > 0:
                for i in range(0, len(v)):
                    if isinstance(v[i], dict):
                        v[i] = self.transform(v[i], ctx=ctx)
            elif isinstance(v, dict):
                input_data[k] = self.transform(v, ctx=ctx)

        return input_data


class KeyValueBasedTransformer(KeyValueBasedTransformerFunctionReplacement):
    def __init__(
        self,
        match_fn: Callable[[str, Any], Optional[str]],
        replacement: str,
        replace_reference: bool = True,
    ):
        super().__init__(
            match_fn=match_fn,
            replacement_function=lambda k, v: replacement,
            replace_reference=replace_reference,
        )


class GenericTransformer:
    def __init__(self, fn: Callable[[dict, TransformContext], dict]):
        self.fn = fn

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        return self.fn(input_data, ctx)


class SortingTransformer:
    key: str
    sorting_fn: Optional[Callable[[...], Any]]

    # TODO: add support for jsonpath
    def __init__(self, key: str, sorting_fn: Optional[Callable[[...], Any]] = None):
        """Sorts a list at `key` with the given `sorting_fn` (argument for `sorted(list, key=sorting_fn)`)"""
        self.key = key
        self.sorting_fn = sorting_fn

    def _transform_dict(self, input_data: dict, ctx: TransformContext = None) -> dict:
        for k, v in input_data.items():
            if k == self.key:
                if not isinstance(v, list):
                    raise ValueError("SortingTransformer should only be applied to lists.")
                input_data[k] = sorted(self._transform(v, ctx=ctx), key=self.sorting_fn)
            else:
                input_data[k] = self._transform(v, ctx=ctx)
        return input_data

    def _transform_list(self, input_data: list, ctx: TransformContext = None) -> list:
        return [self._transform(e, ctx=ctx) for e in input_data]

    def _transform(self, input_data: Any, ctx: TransformContext = None) -> Any:
        if isinstance(input_data, dict):
            return self._transform_dict(input_data, ctx=ctx)
        elif isinstance(input_data, list):
            return self._transform_list(input_data, ctx=ctx)
        else:
            return input_data

    def transform(self, input_data: dict, *, ctx: TransformContext = None) -> dict:
        return self._transform_dict(input_data, ctx=ctx)


class RegexMatcher:
    def __init__(self, regex: str | re.Pattern, representation: str):
        if isinstance(regex, str):
            self.regex = re.compile(regex)
        elif isinstance(regex, re.Pattern):
            self.regex = regex
        else:
            raise Exception("Invalid")

        self.representation = representation


REFERENCE_DATE = (
    "2022-07-13T13:48:01Z"  # v1.0.0 commit timestamp cf26bd9199354a9a55e0b65e312ceee4c407f6c0
)
PATTERN_ISO8601 = re.compile(
    r"(?:[1-9]\d{3}-(?:(?:0[1-9]|1[0-2])-(?:0[1-9]|1\d|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02])-31)|(?:[1-9]\d(?:0[48]|[2468][048]|[13579][26])|(?:[2468][048]|[13579][26])00)-02-29)T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-][01]\d:?([0-5]\d)?)"
)


class TimestampTransformer:
    matchers: list[RegexMatcher]

    def __init__(self):
        """
        Create a timestamp transformer which will replace normal datetimes with <datetime> and string timestamps with their representative format.

        The reference date which is used for replacements is "2022-07-13T13:48:01Z", the commit date for the v1.0.0 tag of the original project.
        """

        # Add your matcher here
        self.matchers = [
            RegexMatcher(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z", "2022-07-13T13:48:01.000Z"
            ),  # stepfunctions internal
            RegexMatcher(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}\+\d{4}", "2022-07-13T13:48:01.000+0000"
            ),  # lambda
            RegexMatcher(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{6}\+\d{2}:\d{2}",
                "2022-07-13T13:48:01.000000+00:00",
            ),  # stepfunctions external, also cloudformation
            RegexMatcher(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                "2022-07-13T13:48:01Z",
            ),  # s3
            # RegexMatcher(
            #     PATTERN_ISO8601, "generic-iso8601"
            # ),  # very generic iso8601, this should technically always be fixed so we could also think about removing it here
        ]

    def transform(self, input_data: dict, *, ctx: TransformContext = None) -> dict:
        return self._transform_dict(input_data, ctx=ctx)

    def _transform(self, input_data: Any, ctx: TransformContext = None) -> Any:
        if isinstance(input_data, dict):
            return self._transform_dict(input_data, ctx=ctx)
        elif isinstance(input_data, list):
            return self._transform_list(input_data, ctx=ctx)
        elif isinstance(input_data, datetime):
            return "<datetime>"
        elif isinstance(input_data, str):
            return self._transform_timestamp(input_data)
        return input_data

    def _transform_timestamp(self, timestamp: str) -> str:
        for matcher in self.matchers:
            if matcher.regex.match(timestamp):
                return f"<timestamp:{matcher.representation}>"
        return timestamp

    def _transform_dict(self, input_data: dict, ctx: TransformContext = None) -> dict:
        for k, v in input_data.items():
            input_data[k] = self._transform(v, ctx=ctx)
        return input_data

    def _transform_list(self, input_data: list, ctx: TransformContext = None) -> list:
        return [self._transform(e, ctx=ctx) for e in input_data]


class TextTransformer:
    def __init__(self, text: str, replacement: str):
        self.text = text
        self.replacement = replacement

    def transform(self, input_data: dict, *, ctx: TransformContext) -> dict:
        def replace_val(s):
            return s.replace(self.text, self.replacement)

        ctx.register_serialized_replacement(replace_val)
        SNAPSHOT_LOGGER.debug(
            f"Registering text pattern '{self.text}' in snapshot with '{self.replacement}'"
        )
        return input_data


class JsonStringTransformer:
    """
    Parses JSON string at the specified key.
    Additionally, attempts to parse any JSON strings inside the parsed JSON

    This transformer complements the default parsing of JSON strings in
    localemu.testing.snapshots.prototype.SnapshotSession._transform_dict_to_parseable_values

    Shortcomings of the default parser that this transformer addresses:
    - parsing of nested JSON strings '{"a": "{\\"b\\":42}"}'
    - parsing of JSON arrays at the specified key, e.g. '["a", "b"]'

    Such parsing allows applying transformations further to the elements of the parsed JSON - timestamps, ARNs, etc.

    Such parsing is not done by default because it's not a common use case.
    Whether to parse a JSON string or not should be decided by the user on a case by case basis.
    Limited general parsing that we already have is preserved for backwards compatibility.
    """

    key: str

    def __init__(self, key: str):
        self.key = key

    def transform(self, input_data: dict, *, ctx: TransformContext = None) -> dict:
        return self._transform_dict(input_data, ctx=ctx)

    def _transform(self, input_data: Any, ctx: TransformContext = None) -> Any:
        if isinstance(input_data, dict):
            return self._transform_dict(input_data, ctx=ctx)
        elif isinstance(input_data, list):
            return self._transform_list(input_data, ctx=ctx)
        return input_data

    def _transform_dict(self, input_data: dict, ctx: TransformContext = None) -> dict:
        for k, v in input_data.items():
            if k == self.key and isinstance(v, str) and v.strip().startswith(("{", "[")):
                try:
                    SNAPSHOT_LOGGER.debug(f"Replacing string value of {k} with parsed JSON")
                    json_value = json.loads(v)
                    input_data[k] = self._transform_nested(json_value)
                except JSONDecodeError:
                    SNAPSHOT_LOGGER.exception(
                        f'Value mapped to "{k}" key is not a valid JSON string and won\'t be transformed. Value: {v}'
                    )
            else:
                input_data[k] = self._transform(v, ctx=ctx)
        return input_data

    def _transform_list(self, input_data: list, ctx: TransformContext = None) -> list:
        return [self._transform(item, ctx=ctx) for item in input_data]

    def _transform_nested(self, input_data: Any) -> Any:
        """
        Separate method from the main `_transform_dict` one because
        it checks every string while the main one attempts to load at specified key only.
        This one is implicit, best-effort attempt,
        while the main one is explicit about at which key transform should happen
        """
        if isinstance(input_data, list):
            input_data = [self._transform_nested(item) for item in input_data]
        if isinstance(input_data, dict):
            for k, v in input_data.items():
                input_data[k] = self._transform_nested(v)
        if isinstance(input_data, str) and input_data.strip().startswith(("{", "[")):
            try:
                json_value = json.loads(input_data)
                input_data = self._transform_nested(json_value)
            except JSONDecodeError:
                SNAPSHOT_LOGGER.debug(
                    f"The value is not a valid JSON string and won't be transformed. The value: {input_data}"
                )
        return input_data
