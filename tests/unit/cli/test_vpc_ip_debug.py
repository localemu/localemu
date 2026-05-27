"""Tests for the `localemu vpc-ip` debug command."""
from __future__ import annotations

import json
from unittest import mock

import pytest
from click.testing import CliRunner

from localemu.cli.vpc_ip import vpc_ip
from localemu.services.ec2.docker.address_index import (
    get_address_index,
    reset_address_index_for_tests,
)
from localemu.services.ec2.docker.subnet_allocator import (
    get_subnet_allocator,
    reset_subnet_allocator_for_tests,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()
    yield
    reset_subnet_allocator_for_tests()
    reset_address_index_for_tests()


def _populate():
    alloc = get_subnet_allocator()
    alloc.register_subnet(
        "vpc-1", "sub-a", "10.0.1.0/24", "10.0.0.0/16", "us-east-1a",
    )
    ip = alloc.reserve("vpc-1", "sub-a", "eni-abc")
    idx = get_address_index()
    idx.register_eni(
        "eni-abc", "vpc-1", "sub-a", ip,
        sg_ids=["sg-web"], instance_id="i-abc",
    )
    return ip


class TestEmptyState:
    def test_empty_index(self):
        runner = CliRunner()
        result = runner.invoke(vpc_ip, ["--all"])
        assert result.exit_code == 0
        assert "No matching" in result.output


class TestTableOutput:
    def test_show_all_renders_table(self):
        _populate()
        runner = CliRunner()
        with mock.patch(
            "localemu.cli.vpc_ip._probe_docker_ip", return_value="10.0.0.2",
        ):
            result = runner.invoke(vpc_ip, ["--all"])
        assert result.exit_code == 0
        assert "eni-abc" in result.output
        assert "vpc-1" in result.output
        assert "sub-a" in result.output
        assert "10.0.0.2" in result.output

    def test_filter_by_eni_id(self):
        _populate()
        runner = CliRunner()
        with mock.patch(
            "localemu.cli.vpc_ip._probe_docker_ip", return_value="10.0.0.2",
        ):
            result = runner.invoke(vpc_ip, ["eni-abc"])
        assert result.exit_code == 0
        assert "eni-abc" in result.output

    def test_filter_by_instance_id(self):
        _populate()
        runner = CliRunner()
        with mock.patch(
            "localemu.cli.vpc_ip._probe_docker_ip", return_value="10.0.0.2",
        ):
            result = runner.invoke(vpc_ip, ["i-abc"])
        assert result.exit_code == 0
        assert "eni-abc" in result.output

    def test_filter_by_container_name(self):
        _populate()
        runner = CliRunner()
        with mock.patch(
            "localemu.cli.vpc_ip._probe_docker_ip", return_value="10.0.0.2",
        ):
            result = runner.invoke(vpc_ip, ["localemu-ec2-i-abc"])
        assert result.exit_code == 0
        assert "eni-abc" in result.output


class TestJsonOutput:
    def test_json_parses(self):
        _populate()
        runner = CliRunner()
        with mock.patch(
            "localemu.cli.vpc_ip._probe_docker_ip", return_value="10.0.0.2",
        ):
            result = runner.invoke(vpc_ip, ["--all", "--output", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["eni"] == "eni-abc"
        assert data[0]["vpc"] == "vpc-1"
        assert data[0]["subnet"] == "sub-a"
        assert data[0]["index_ip"] == "10.0.0.2"
        assert data[0]["docker_ip"] == "10.0.0.2"


class TestDockerIpProbeFailure:
    def test_docker_unreachable_shows_dash(self):
        _populate()
        runner = CliRunner()
        with mock.patch(
            "localemu.cli.vpc_ip._probe_docker_ip", return_value=None,
        ):
            result = runner.invoke(vpc_ip, ["--all"])
        assert result.exit_code == 0
        # Docker IP column shows the no-data placeholder
        assert " — " in result.output or "—" in result.output
