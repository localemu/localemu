"""EIP data plane: makes ``aws ec2 associate-address`` route real
traffic to ANY TCP port the EC2 container is listening on, with SG
rules enforced against the real source IP and flow logs that carry
the real source IP.

A host-side asyncio TCP proxy bound on ``127.0.0.1:<host_port>``
accepts the incoming connection (so the socket peer is the real Mac
/ Linux caller), evaluates SG, emits a flow log entry, and tunnels
the bytes via ``docker exec -i <ec2> socat - TCP:127.0.0.1:<port>``
into the container's netns. No Docker NAT in the path, no source-IP
rewrite, no sidecar.
"""
from localemu.services.ec2.eip.data_plane import (
    EipDataPlane,
    cleanup_v1_sidecars,
    get_eip_data_plane,
    reset_for_tests,
)
from localemu.services.ec2.eip.store import (
    EipAssociation,
    EipStore,
    get_eip_store,
)

__all__ = [
    "EipAssociation",
    "EipDataPlane",
    "EipStore",
    "cleanup_v1_sidecars",
    "get_eip_data_plane",
    "get_eip_store",
    "reset_for_tests",
]
