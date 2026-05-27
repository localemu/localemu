"""CloudFormation intrinsic function helpers and YAML representers.

This module centralises the fiddly parts of emitting CloudFormation YAML:

* lightweight :class:`CfnIntrinsic` wrappers for ``!Ref``, ``!GetAtt`` and
  ``!Sub``; writers construct these instead of raw strings so the YAML
  dumper can emit the correct ``!Tag`` syntax;
* a :class:`CfnSafeDumper` subclass of :class:`yaml.SafeDumper` that knows
  how to serialise the wrapper objects using CloudFormation's short-form
  intrinsic syntax — so ``!Ref MyBucket`` comes out unquoted and valid,
  rather than as the literal string ``"!Ref MyBucket"``;
* tiny factory helpers (:func:`cfn_ref`, :func:`cfn_getatt`, :func:`cfn_sub`)
  that the writer uses everywhere it needs an intrinsic.

The output of :func:`yaml.dump(..., Dumper=CfnSafeDumper)` parses cleanly
with :func:`yaml.safe_load` (which treats unknown ``!`` tags as strings)
and, more importantly, with :mod:`cfn-lint` / the AWS CloudFormation
service itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import yaml


@dataclass(frozen=True)
class CfnIntrinsic:
    """Opaque wrapper around a CloudFormation intrinsic function call.

    ``tag`` is the short-form tag name (``"Ref"``, ``"GetAtt"``, ``"Sub"``
    …) *without* the leading ``!``. ``value`` is whatever the tag expects
    as its argument: a scalar for ``!Ref``, a two-element list for
    ``!GetAtt`` (``[LogicalId, Attribute]``), or a string / ``[string,
    dict]`` for ``!Sub``.
    """

    tag: str
    value: Any


def cfn_ref(logical_id: str) -> CfnIntrinsic:
    """Return ``!Ref <logical_id>``.

    Use for properties that CloudFormation resolves to a resource's primary
    identifier (bucket name, function name, role name, queue URL, …).
    """
    if not logical_id:
        raise ValueError("cfn_ref requires a non-empty logical_id")
    return CfnIntrinsic(tag="Ref", value=logical_id)


def cfn_getatt(logical_id: str, attribute: str) -> CfnIntrinsic:
    """Return ``!GetAtt <logical_id>.<attribute>``.

    Emitted in YAML as the short-form dotted-string variant, which is
    the idiomatic CloudFormation spelling.
    """
    if not logical_id or not attribute:
        raise ValueError("cfn_getatt requires logical_id and attribute")
    return CfnIntrinsic(tag="GetAtt", value=f"{logical_id}.{attribute}")


def cfn_sub(template: str, variables: dict[str, Any] | None = None) -> CfnIntrinsic:
    """Return ``!Sub`` with either the string form or the ``[str, map]`` form.

    Passing ``variables`` produces the two-element list form understood by
    CloudFormation for template-local substitutions.
    """
    if variables:
        return CfnIntrinsic(tag="Sub", value=[template, dict(variables)])
    return CfnIntrinsic(tag="Sub", value=template)


class CfnSafeDumper(yaml.SafeDumper):
    """YAML safe-dumper that knows how to render :class:`CfnIntrinsic`.

    We subclass :class:`yaml.SafeDumper` (not :class:`yaml.Dumper`) so the
    emitter refuses arbitrary Python objects — any unrepresentable value
    surfaces immediately as a dumper error rather than being smuggled into
    the template as a ``!!python/object`` tag.
    """

    pass


def _represent_intrinsic(dumper: yaml.SafeDumper, data: CfnIntrinsic) -> yaml.Node:
    """Render a :class:`CfnIntrinsic` using CFN short-form tag syntax.

    * ``!Ref`` / ``!GetAtt`` always emit a scalar (string) value.
    * ``!Sub`` emits a scalar when ``value`` is a string, a sequence when
      it is the two-element variable-map form.
    * All other tags fall back to whatever structural form ``value`` has
      (scalar / sequence / mapping) — extension room without special-casing.
    """
    tag = f"!{data.tag}"
    value = data.value
    if data.tag in ("Ref", "GetAtt"):
        return dumper.represent_scalar(tag, str(value), style="")
    if data.tag == "Sub":
        if isinstance(value, str):
            return dumper.represent_scalar(tag, value, style="")
        return dumper.represent_sequence(tag, value)
    if isinstance(value, str):
        return dumper.represent_scalar(tag, value)
    if isinstance(value, list):
        return dumper.represent_sequence(tag, value)
    if isinstance(value, dict):
        return dumper.represent_mapping(tag, value)
    return dumper.represent_scalar(tag, str(value))


CfnSafeDumper.add_representer(CfnIntrinsic, _represent_intrinsic)


class CfnSafeLoader(yaml.SafeLoader):
    """YAML safe-loader that round-trips CFN short-form tags into :class:`CfnIntrinsic`.

    The base ``SafeLoader`` rejects unknown tags like ``!Ref`` / ``!GetAtt``
    with a ``ConstructorError``. The export code re-reads its own template
    output to splice in ``Parameters`` / ``Rules`` sections; without this
    loader the re-read fails the moment a single intrinsic appears.
    """

    pass


def _construct_intrinsic(loader: yaml.SafeLoader, node: yaml.Node) -> CfnIntrinsic:
    tag = node.tag.lstrip("!")
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node, deep=True)
    else:  # pragma: no cover - defensive
        value = None
    return CfnIntrinsic(tag=tag, value=value)


# Register every short-form intrinsic CFN supports. yaml's tag dispatch is
# exact-match on the leading tag, so we list each explicitly.
for _tag in (
    "Ref", "GetAtt", "Sub", "Join", "Select", "Split", "Base64",
    "Cidr", "FindInMap", "GetAZs", "ImportValue", "Transform",
    "If", "And", "Or", "Not", "Equals", "Condition",
    "ToJsonString", "Length",
):
    CfnSafeLoader.add_constructor(f"!{_tag}", _construct_intrinsic)


__all__ = [
    "CfnIntrinsic",
    "CfnSafeDumper",
    "CfnSafeLoader",
    "cfn_getatt",
    "cfn_ref",
    "cfn_sub",
]
