"""Unit tests for per-instance IMDS port identification .

On macOS Docker Desktop all containers reach ``host.docker.internal``
through a single Docker-VM gateway, so ``resolve_instance(client_ip)``
sees the same source IP for every container. With two or more EC2
instances, IMDS returned 404 for all but (optionally) one.

The fix: each EC2 instance is given a dedicated per-instance proxy
port. The container's ``AWS_EC2_METADATA_SERVICE_ENDPOINT`` points to
that port, and the proxy stamps an ``X-Localemu-Instance-Id`` header
on every forwarded request. The IMDS handler prefers the header over
source-IP lookup.
"""
from __future__ import annotations

import http.client
import socket
import threading
import time
from unittest import mock

import pytest

from localemu.services.ec2.docker.imds import (
    ImdsServer,
    PerInstanceImdsPortProxy,
    STAMP_HEADER,
)


@pytest.fixture
def imds_server():
    s = ImdsServer(port=0)
    s.start()
    yield s
    s.stop()


class TestStampHeader:
    def test_header_takes_precedence_over_source_ip(self, imds_server):
        """A request with the stamp header identifies the instance even
        when the source IP matches a DIFFERENT instance."""
        # Register two instances at two different IPs
        imds_server.register_instance(
            "i-aaa", "10.0.0.1",
            {"instance_id": "i-aaa", "instance_type": "t2.micro",
             "ami_id": "ami-1", "region": "us-east-1", "az": "us-east-1a",
             "private_ip": "10.0.0.1", "hostname": "host-a"},
        )
        imds_server.register_instance(
            "i-bbb", "10.0.0.2",
            {"instance_id": "i-bbb", "instance_type": "t3.small",
             "ami_id": "ami-2", "region": "us-east-1", "az": "us-east-1a",
             "private_ip": "10.0.0.2", "hostname": "host-b"},
        )

        conn = http.client.HTTPConnection("127.0.0.1", imds_server.port, timeout=5)
        # Source IP on loopback is 127.0.0.1 — matches neither instance —
        # but the stamp header explicitly picks i-bbb.
        conn.request(
            "GET", "/latest/meta-data/instance-id",
            headers={STAMP_HEADER: "i-bbb"},
        )
        resp = conn.getresponse()
        body = resp.read().decode()
        assert resp.status == 200
        assert body == "i-bbb"
        conn.close()

    def test_without_stamp_header_falls_back_to_source_ip(self, imds_server):
        imds_server.register_instance(
            "i-ccc", "127.0.0.1",
            {"instance_id": "i-ccc", "instance_type": "t2.micro",
             "ami_id": "ami-3", "region": "us-east-1", "az": "us-east-1a",
             "private_ip": "127.0.0.1", "hostname": "host-c"},
        )
        conn = http.client.HTTPConnection("127.0.0.1", imds_server.port, timeout=5)
        conn.request("GET", "/latest/meta-data/instance-id")
        resp = conn.getresponse()
        body = resp.read().decode()
        assert resp.status == 200
        assert body == "i-ccc"
        conn.close()

    def test_stamp_for_unknown_instance_returns_404(self, imds_server):
        conn = http.client.HTTPConnection("127.0.0.1", imds_server.port, timeout=5)
        conn.request(
            "GET", "/latest/meta-data/instance-id",
            headers={STAMP_HEADER: "i-unknown"},
        )
        resp = conn.getresponse()
        assert resp.status == 404
        conn.close()


class TestPerInstanceProxy:
    """The proxy listens on its own port and stamps X-Localemu-Instance-Id
    before forwarding to the real IMDS server."""

    def test_proxy_adds_stamp_header(self, imds_server):
        imds_server.register_instance(
            "i-proxy", "10.0.0.99",
            {"instance_id": "i-proxy", "instance_type": "t2.micro",
             "ami_id": "ami-p", "region": "us-east-1", "az": "us-east-1a",
             "private_ip": "10.0.0.99", "hostname": "host-p"},
        )
        proxy = PerInstanceImdsPortProxy(
            instance_id="i-proxy", upstream_port=imds_server.port,
        )
        proxy.start()
        try:
            # Connect to the proxy's own port — we supply NO stamp header
            # ourselves; the proxy should add it before forwarding.
            conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
            conn.request("GET", "/latest/meta-data/instance-id")
            resp = conn.getresponse()
            body = resp.read().decode()
            assert resp.status == 200
            assert body == "i-proxy"
            conn.close()
        finally:
            proxy.stop()

    def test_proxy_forwards_put_for_imdsv2_token(self, imds_server):
        imds_server.register_instance(
            "i-tok", "10.0.0.7",
            {"instance_id": "i-tok", "instance_type": "t2.micro",
             "ami_id": "ami-t", "region": "us-east-1", "az": "us-east-1a",
             "private_ip": "10.0.0.7", "hostname": "host-t"},
        )
        proxy = PerInstanceImdsPortProxy(
            instance_id="i-tok", upstream_port=imds_server.port,
        )
        proxy.start()
        try:
            # PUT /latest/api/token
            conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
            conn.request(
                "PUT", "/latest/api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
            )
            resp = conn.getresponse()
            assert resp.status == 200
            token = resp.read().decode()
            assert token  # non-empty
            conn.close()
        finally:
            proxy.stop()


class TestImdsServerAllocateReleasePort:
    def test_allocate_returns_live_port(self, imds_server):
        imds_server.register_instance(
            "i-alloc", "10.0.0.50",
            {"instance_id": "i-alloc", "instance_type": "t2.micro",
             "ami_id": "ami-a", "region": "us-east-1", "az": "us-east-1a",
             "private_ip": "10.0.0.50", "hostname": "host-a"},
        )
        port = imds_server.allocate_port_for_instance("i-alloc")
        assert isinstance(port, int) and port > 0
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/latest/meta-data/instance-id")
            resp = conn.getresponse()
            assert resp.status == 200
            assert resp.read().decode() == "i-alloc"
            conn.close()
        finally:
            imds_server.release_port_for_instance("i-alloc")

    def test_release_closes_port(self, imds_server):
        imds_server.register_instance(
            "i-rel", "10.0.0.60",
            {"instance_id": "i-rel", "instance_type": "t2.micro",
             "ami_id": "ami-r", "region": "us-east-1", "az": "us-east-1a",
             "private_ip": "10.0.0.60", "hostname": "host-r"},
        )
        port = imds_server.allocate_port_for_instance("i-rel")
        imds_server.release_port_for_instance("i-rel")
        # Port should now refuse connections (server closed). HTTPConnection
        # raises ConnectionRefusedError — catch with a broad Exception since
        # exact type varies by platform.
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        with pytest.raises(Exception):
            conn.request("GET", "/latest/meta-data/instance-id")
            resp = conn.getresponse()
            resp.read()

    def test_allocate_idempotent_returns_same_port(self, imds_server):
        imds_server.register_instance(
            "i-idem", "10.0.0.70",
            {"instance_id": "i-idem", "instance_type": "t2.micro",
             "ami_id": "ami-i", "region": "us-east-1", "az": "us-east-1a",
             "private_ip": "10.0.0.70", "hostname": "host-i"},
        )
        try:
            p1 = imds_server.allocate_port_for_instance("i-idem")
            p2 = imds_server.allocate_port_for_instance("i-idem")
            assert p1 == p2
        finally:
            imds_server.release_port_for_instance("i-idem")

    def test_allocate_with_requested_port_honors_request(self, imds_server):
        """Persistence path: on restore we inspect the container's
        baked-in AWS_EC2_METADATA_SERVICE_ENDPOINT env var to find the
        old port, then re-bind the proxy to exactly that port."""
        from localemu.utils.net import get_free_tcp_port

        imds_server.register_instance(
            "i-req", "10.0.0.80",
            {"instance_id": "i-req", "instance_type": "t2.micro",
             "ami_id": "ami-q", "region": "us-east-1", "az": "us-east-1a",
             "private_ip": "10.0.0.80", "hostname": "host-q"},
        )
        wanted = get_free_tcp_port()
        try:
            got = imds_server.allocate_port_for_instance(
                "i-req", requested_port=wanted,
            )
            assert got == wanted
        finally:
            imds_server.release_port_for_instance("i-req")

    def test_allocate_requested_port_in_use_falls_back(self, imds_server):
        """If the requested port is already bound by some other process,
        fall back to a random port and log a warning — do NOT raise."""
        imds_server.register_instance(
            "i-busy", "10.0.0.90",
            {"instance_id": "i-busy", "instance_type": "t2.micro",
             "ami_id": "ami-b", "region": "us-east-1", "az": "us-east-1a",
             "private_ip": "10.0.0.90", "hostname": "host-b"},
        )
        # Bind something else to a port, then try to allocate there.
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        blocked_port = blocker.getsockname()[1]
        try:
            got = imds_server.allocate_port_for_instance(
                "i-busy", requested_port=blocked_port,
            )
            # Must be non-zero (fallback succeeded) and different from the blocker.
            assert got and got != blocked_port
        finally:
            blocker.close()
            imds_server.release_port_for_instance("i-busy")
