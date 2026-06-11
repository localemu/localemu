"""End-to-end tests for Lambda layer mounting (PR-004 Phase 1).

Each test:
  1. Builds a layer ZIP in-memory.
  2. Calls ``lambda.publish_layer_version`` with that ZIP.
  3. Creates a Lambda function whose handler depends on the layer.
  4. Attaches the layer via ``UpdateFunctionConfiguration --layers ...``.
  5. Invokes the function and asserts the layer's code ran.

These tests require Docker (the Lambda runtime container) plus a live
LocalEmu instance, so they skip cleanly on hosts without Docker.

Coverage:

* python: ``/opt/python/<name>.py`` is on ``PYTHONPATH``.
* python: a layer can override built-in import order (two layers with
  the same top-level module — later one wins, real-AWS semantics).
* python: ``/opt/python/lib/python3.12/site-packages/<name>.py`` is also
  on ``PYTHONPATH`` (the runtime-versioned site-packages path).
"""
from __future__ import annotations

import io
import json
import shutil
import time
import uuid
import zipfile

import pytest


pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="Docker CLI not available on host; Lambda E2E cannot run",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _zip_from_tree(files: dict[str, bytes | str]) -> bytes:
    """Return a ZIP-file bytes object containing ``files``.

    ``files`` is a {relative-path: content} map. Strings are encoded as
    UTF-8; bytes are written verbatim.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel, body in files.items():
            if isinstance(body, str):
                body = body.encode("utf-8")
            zf.writestr(rel, body)
    return buf.getvalue()


def _publish_layer(lambda_client, *, name: str, content: bytes,
                   compatible_runtimes: list[str]) -> str:
    """Publish a layer version and return its full ARN."""
    resp = lambda_client.publish_layer_version(
        LayerName=name,
        Content={"ZipFile": content},
        CompatibleRuntimes=compatible_runtimes,
    )
    return resp["LayerVersionArn"]


def _create_function(lambda_client, lambda_role, *, name: str, handler_code: str,
                     runtime: str, layers: list[str]):
    """Create a Lambda function from inline code and attach ``layers``."""
    zip_bytes = _zip_from_tree({"lambda_function.py": handler_code})
    resp = lambda_client.create_function(
        FunctionName=name,
        Runtime=runtime,
        Role=lambda_role,
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": zip_bytes},
        Layers=layers,
    )
    # Wait for the function to be Active so Invoke doesn't hit a cold-start
    # InvalidParameterValueException.
    _wait_function_active(lambda_client, name)
    return resp


def _wait_function_active(lambda_client, name: str, timeout: float = 90.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = lambda_client.get_function(FunctionName=name)
        state = resp["Configuration"].get("State", "Active")
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(
                f"function {name} entered Failed state: "
                f"{resp['Configuration'].get('StateReason', '')}"
            )
        time.sleep(1.0)
    raise AssertionError(f"function {name} did not become Active within {timeout}s")


def _invoke(lambda_client, name: str) -> dict:
    resp = lambda_client.invoke(FunctionName=name, Payload=b"{}")
    payload = resp["Payload"].read()
    return json.loads(payload.decode("utf-8") or "null")


def _delete_function(lambda_client, name: str) -> None:
    try:
        lambda_client.delete_function(FunctionName=name)
    except Exception:
        pass


def _delete_layer(lambda_client, layer_arn: str) -> None:
    """Delete a layer-version given its full ARN."""
    try:
        # ARN shape: arn:aws:lambda:<region>:<acct>:layer:<name>:<version>
        head, _, version = layer_arn.rpartition(":")
        _, _, name = head.rpartition(":")
        lambda_client.delete_layer_version(LayerName=name, VersionNumber=int(version))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Test 1: single python layer, top-level import path
# ---------------------------------------------------------------------------


def test_python_layer_top_level_import(lambda_client, lambda_role):
    layer_zip = _zip_from_tree({
        "python/layermod.py": (
            "MARK = 'LAYER-CODE-RAN'\n"
            "def hello():\n"
            "    return MARK\n"
        ),
    })
    layer_arn = _publish_layer(
        lambda_client, name=f"pwn-layer-{uuid.uuid4().hex[:8]}",
        content=layer_zip, compatible_runtimes=["python3.12"],
    )

    handler = (
        "def lambda_handler(event, context):\n"
        "    try:\n"
        "        import layermod\n"
        "        return {'msg': layermod.hello()}\n"
        "    except ModuleNotFoundError as e:\n"
        "        return {'msg': f'no-layer:{type(e).__name__}'}\n"
    )
    fn_name = f"ltest-{uuid.uuid4().hex[:8]}"
    try:
        _create_function(
            lambda_client, lambda_role,
            name=fn_name, handler_code=handler,
            runtime="python3.12", layers=[layer_arn],
        )
        result = _invoke(lambda_client, fn_name)
        assert result == {"msg": "LAYER-CODE-RAN"}, (
            f"expected the layer's code to run, got {result!r}. "
            "If 'no-layer:ModuleNotFoundError' is returned the layer "
            "was published but not mounted under /opt/python."
        )
    finally:
        _delete_function(lambda_client, fn_name)
        _delete_layer(lambda_client, layer_arn)


# ---------------------------------------------------------------------------
# Test 2: ordering — later layer overwrites earlier
# ---------------------------------------------------------------------------


def test_two_layers_later_overrides_earlier(lambda_client, lambda_role):
    """Same top-level module name in both layers, later listed wins.

    Real AWS docs: "If your function has multiple layers that contain a
    file at the same path, the layer that is added last takes precedence."
    """
    suffix = uuid.uuid4().hex[:6]
    layer_a = _publish_layer(
        lambda_client, name=f"layer-a-{suffix}",
        content=_zip_from_tree({"python/winner.py": "VAL = 'from-A'\n"}),
        compatible_runtimes=["python3.12"],
    )
    layer_b = _publish_layer(
        lambda_client, name=f"layer-b-{suffix}",
        content=_zip_from_tree({"python/winner.py": "VAL = 'from-B'\n"}),
        compatible_runtimes=["python3.12"],
    )
    handler = (
        "def lambda_handler(event, context):\n"
        "    import winner\n"
        "    return {'val': winner.VAL}\n"
    )
    fn_name = f"ltest-{suffix}"
    try:
        _create_function(
            lambda_client, lambda_role,
            name=fn_name, handler_code=handler,
            runtime="python3.12", layers=[layer_a, layer_b],
        )
        # Order [A, B] -> B wins
        assert _invoke(lambda_client, fn_name) == {"val": "from-B"}

        # Swap the order: [B, A] -> A now wins.
        lambda_client.update_function_configuration(
            FunctionName=fn_name, Layers=[layer_b, layer_a],
        )
        _wait_function_active(lambda_client, fn_name)
        assert _invoke(lambda_client, fn_name) == {"val": "from-A"}
    finally:
        _delete_function(lambda_client, fn_name)
        _delete_layer(lambda_client, layer_a)
        _delete_layer(lambda_client, layer_b)


# ---------------------------------------------------------------------------
# Test 3: runtime-versioned site-packages path
# ---------------------------------------------------------------------------


def test_python_layer_runtime_versioned_site_packages_path(lambda_client, lambda_role):
    """AWS adds `/opt/python/lib/python<ver>/site-packages` to ``PYTHONPATH``
    in addition to the top-level ``/opt/python``."""
    layer_zip = _zip_from_tree({
        "python/lib/python3.12/site-packages/sitepkg_layer/__init__.py":
            "MARK = 'SITE-PACKAGES-LAYER-RAN'\n",
    })
    layer_arn = _publish_layer(
        lambda_client, name=f"sitepkg-layer-{uuid.uuid4().hex[:8]}",
        content=layer_zip, compatible_runtimes=["python3.12"],
    )
    handler = (
        "def lambda_handler(event, context):\n"
        "    try:\n"
        "        from sitepkg_layer import MARK\n"
        "        return {'msg': MARK}\n"
        "    except ModuleNotFoundError as e:\n"
        "        return {'msg': f'no-layer:{type(e).__name__}'}\n"
    )
    fn_name = f"ltest-sp-{uuid.uuid4().hex[:8]}"
    try:
        _create_function(
            lambda_client, lambda_role,
            name=fn_name, handler_code=handler,
            runtime="python3.12", layers=[layer_arn],
        )
        result = _invoke(lambda_client, fn_name)
        assert result == {"msg": "SITE-PACKAGES-LAYER-RAN"}, result
    finally:
        _delete_function(lambda_client, fn_name)
        _delete_layer(lambda_client, layer_arn)


# ---------------------------------------------------------------------------
# Test 4: no-layer baseline — no /opt mount when no layers attached
# ---------------------------------------------------------------------------


def test_function_without_layers_runs_unchanged(lambda_client, lambda_role):
    handler = (
        "def lambda_handler(event, context):\n"
        "    return {'msg': 'no-layers'}\n"
    )
    fn_name = f"nolayers-{uuid.uuid4().hex[:8]}"
    try:
        _create_function(
            lambda_client, lambda_role,
            name=fn_name, handler_code=handler,
            runtime="python3.12", layers=[],
        )
        assert _invoke(lambda_client, fn_name) == {"msg": "no-layers"}
    finally:
        _delete_function(lambda_client, fn_name)
