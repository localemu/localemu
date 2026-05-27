"""VPC Endpoint proxy must not depend on runtime ``apk add``.

The proxy container's job is to bridge a ``--internal=true`` VPC network
(which by definition has no internet access) to the LocalEmu host. The
old code ran ``apk add --no-cache socat`` as the first thing in the
container's entrypoint — when the host had no Alpine mirror access (most
corporate networks, air-gapped CI), the install silently failed and the
proxy never started forwarding traffic.

The fix bakes socat into ``localemu/vpc-endpoint:latest`` at LocalEmu
host time (where mirrors do reach), then uses that image at runtime. We
keep a fallback to ``alpine:3.19 + apk add`` for deployments where the
image build itself fails, but never as the primary path.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from localemu.services.ec2.docker import vpc_endpoint


class TestProxyImage:
    def test_image_available_short_circuit(self):
        with patch.object(vpc_endpoint, "DOCKER_CLIENT") as mock_docker:
            mock_docker.inspect_image.return_value = {"Id": "sha:deadbeef"}
            assert vpc_endpoint._ensure_proxy_image() is True
            mock_docker.build_image.assert_not_called()

    def test_build_when_missing(self):
        # The function double-checks inspect_image inside the lock, so the
        # side-effect list needs three entries: outer miss, inner miss (so
        # the build actually runs), then the post-build hit isn't asked
        # because _ensure_proxy_image returns True straight after build.
        with patch.object(vpc_endpoint, "DOCKER_CLIENT") as mock_docker:
            mock_docker.inspect_image.side_effect = [
                Exception("not found"),
                Exception("not found"),
            ]
            mock_docker.build_image.return_value = None
            assert vpc_endpoint._ensure_proxy_image() is True
            mock_docker.build_image.assert_called_once()
            kwargs = mock_docker.build_image.call_args.kwargs
            assert kwargs["image_name"] == vpc_endpoint._PROXY_IMAGE

    def test_dockerfile_installs_socat(self):
        # The Dockerfile body must actually include the socat install, else
        # the baked image would be just as broken as the old runtime path.
        assert "apk add" in vpc_endpoint._PROXY_DOCKERFILE
        assert "socat" in vpc_endpoint._PROXY_DOCKERFILE

    def test_build_failure_falls_back_to_apk_path(self):
        # If the build fails we MUST NOT prevent the endpoint from being
        # created — the alpine + apk add path is the legacy fallback.
        with patch.object(vpc_endpoint, "DOCKER_CLIENT") as mock_docker:
            mock_docker.inspect_image.side_effect = Exception("missing")
            mock_docker.build_image.side_effect = RuntimeError("registry down")
            assert vpc_endpoint._ensure_proxy_image() is False
