from localemu import config
from localemu.http import Request
from localemu.services.internal import DiagnoseResource


def test_diagnose_resource():
    # simple smoke test diagnose resource
    resource = DiagnoseResource()
    result = resource.on_get(Request(path="/_localemu/diagnose"))

    assert "/tmp" in result["file-tree"]
    assert "/var/lib/localemu" in result["file-tree"]
    assert result["config"]["DATA_DIR"] == config.DATA_DIR
    assert result["config"]["GATEWAY_LISTEN"] == [config.HostAndPort("0.0.0.0", 4566)]
    assert result["important-endpoints"]["localhost"].startswith("127.0.")
    assert result["logs"]["docker"]
