"""``StartSession`` DocumentName / Parameters → session_type resolver.

The real ``aws ssm start-session --document-name
AWS-StartPortForwardingSession --parameters
portNumber=8000,localPortNumber=18000`` sends the document + params over
the wire ; the LocalEmu ``start_session`` handler must map that into
the ``(session_type, session_properties)`` pair the handshake frame
consumes.
"""
from __future__ import annotations

from localemu.services.ssm.provider import _resolve_session_type
from localemu.services.ssm.session_manager import handshake_request_frame


def test_no_document_defaults_to_standard_stream_shell():
    assert _resolve_session_type("", None) == ("Standard_Stream", None)


def test_run_shell_document_resolves_to_standard_stream():
    assert _resolve_session_type(
        "SSM-SessionManagerRunShell", None,
    ) == ("Standard_Stream", None)


def test_port_forwarding_document_with_dict_list_params():
    """AWS wire encoding delivers Parameters as ``{"portNumber": ["8000"]}``
    (list-valued). The resolver flattens the first value.
    """
    st, props = _resolve_session_type(
        "AWS-StartPortForwardingSession",
        {"portNumber": ["8000"]},
    )
    assert st == "Port"
    assert props == {"portNumber": "8000", "type": "LocalPortForwarding"}


def test_port_forwarding_document_with_dict_flat_params():
    """The Python SDK may pre-flatten the values ; also supported."""
    st, props = _resolve_session_type(
        "AWS-StartPortForwardingSession",
        {"portNumber": "8000", "localPortNumber": "18000"},
    )
    assert st == "Port"
    assert props == {
        "portNumber": "8000",
        "type": "LocalPortForwarding",
        "localPortNumber": "18000",
    }


def test_port_forwarding_document_with_list_of_kv_params():
    """CFN and some AWS CLI encodings deliver Parameters as
    ``[{"Name": "portNumber", "Values": ["8000"]}, ...]`` - supported.
    """
    st, props = _resolve_session_type(
        "AWS-StartPortForwardingSession",
        [
            {"Name": "portNumber", "Values": ["9000"]},
            {"Name": "localPortNumber", "Values": ["19000"]},
        ],
    )
    assert st == "Port"
    assert props["portNumber"] == "9000"
    assert props["localPortNumber"] == "19000"


def test_port_forwarding_document_with_empty_params_returns_empty_port():
    """Missing portNumber is legal at resolver level ; the handler
    rejects it with ``InvalidParameters`` before creating the session.
    """
    st, props = _resolve_session_type(
        "AWS-StartPortForwardingSession", None,
    )
    assert st == "Port"
    assert props == {"portNumber": "", "type": "LocalPortForwarding"}


def test_handshake_request_frame_carries_port_session_type():
    """The plugin's ``ProcessSessionTypeHandshakeAction`` accepts
    ``"Port"`` only when the frame explicitly declares it. Verify
    that the frame we build carries the right session type
    AND the ``Properties`` object with portNumber.
    """
    import json

    frame = handshake_request_frame(
        0,
        session_type="Port",
        properties={"portNumber": "8000", "type": "LocalPortForwarding"},
    )
    parsed = json.loads(frame.payload)
    action = parsed["RequestedClientActions"][0]
    assert action["ActionType"] == "SessionType"
    assert (
        action["ActionParameters"]["SessionType"] == "Port"
    )
    props = action["ActionParameters"]["Properties"]
    assert props["portNumber"] == "8000"
    assert props["type"] == "LocalPortForwarding"


def test_handshake_request_frame_default_stays_standard_stream():
    """The default shell path must not regress the default shell session's shape."""
    import json

    frame = handshake_request_frame(0)
    parsed = json.loads(frame.payload)
    action = parsed["RequestedClientActions"][0]
    assert action["ActionParameters"]["SessionType"] == "Standard_Stream"
    assert action["ActionParameters"]["Properties"] is None
