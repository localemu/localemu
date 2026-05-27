#!/usr/bin/env python3
"""Deep ECS Docker-backend E2E suite for LocalEmu.

Exercises the ECS Docker backend beyond the basic awsvpc attach test in
``run_e2e.py`` step 28. Each scenario is an isolated step printing
PASS/FAIL with a duration; cleanup always runs, even on failure.

Scenarios covered:
  1.  CreateCluster
  2.  RegisterTaskDefinition (FARGATE, awsvpc, cpu=256, memory=512,
      nginx:alpine + portMappings 80:80)
  3.  RunTask with explicit subnets + SG — container RUNNING
  4.  From the host, ``curl http://<task-host-port>`` → nginx welcome
  5.  Multi-container task (web + sidecar) with shared volume
  6.  CreateService desiredCount=2 → 2 containers in awsvpc/correct VPC
  7.  UpdateService desiredCount=3 → scale up
  8.  UpdateService desiredCount=1 → scale down (extras stop+remove)
  9.  DescribeTasks returns lastStatus=RUNNING + networkBindings
  10. StopTask → container STOPPED + exitCode set
  11. Container env has ECS_CONTAINER_METADATA_URI_V4 +
      AWS_CONTAINER_CREDENTIALS_RELATIVE_URI (real ECS contract)
  12. Task in bridge networkMode → default bridge, ports mapped
  13. Task with containerDefinition.healthCheck → Docker has HEALTHCHECK
  14. DeleteCluster cleans up all task containers

Usage::

    # LocalEmu already running on :4566 with ECS_DOCKER_BACKEND=1
    python tests/e2e/docker_emulation/test_ecs.py

Exit code is non-zero iff any scenario failed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid

import boto3
from botocore.client import Config

ENDPOINT = os.environ.get("LOCALEMU_ENDPOINT", "http://localhost:4566")
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
TAG = uuid.uuid4().hex[:8]

CFG = Config(retries={"max_attempts": 3}, connect_timeout=5, read_timeout=60)
KW = dict(
    endpoint_url=ENDPOINT,
    region_name=REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
    config=CFG,
)

ec2 = boto3.client("ec2", **KW)
ecs_c = boto3.client("ecs", **KW)


PASS: list[tuple[str, float]] = []
FAIL: list[tuple[str, str]] = []


def step(name: str):
    """Decorator: turns a function into a tracked test step."""
    def deco(fn):
        def wrap(*a, **k):
            print(f"\n=== {name} ===", flush=True)
            t0 = time.time()
            try:
                fn(*a, **k)
                dt = time.time() - t0
                print(f"  PASS [{dt:.1f}s]", flush=True)
                PASS.append((name, dt))
            except AssertionError as e:
                dt = time.time() - t0
                print(f"  FAIL [{dt:.1f}s] {e}", flush=True)
                FAIL.append((name, str(e)))
            except Exception as e:
                dt = time.time() - t0
                print(f"  ERROR [{dt:.1f}s] {type(e).__name__}: {e}", flush=True)
                FAIL.append((name, f"{type(e).__name__}: {e}"))
        return wrap
    return deco


def docker(*args: str, timeout: int = 15) -> tuple[int, str, str]:
    r = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


def docker_running(name: str) -> bool:
    rc, out, _ = docker("inspect", "--format", "{{.State.Running}}", name, timeout=10)
    return rc == 0 and out.strip() == "true"


def wait_docker(
    predicate, *, timeout: int = 60, interval: float = 2.0, msg: str = "",
) -> bool:
    """Poll ``predicate`` (no-arg callable returning bool) up to ``timeout`` s."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def task_containers(task_arn: str) -> list[str]:
    """Return Docker container names labeled with ``localemu.task-arn=<arn>``."""
    rc, out, _ = docker(
        "ps", "--filter", f"label=localemu.task-arn={task_arn}",
        "--format", "{{.Names}}",
    )
    if rc != 0:
        return []
    return [ln for ln in out.strip().split("\n") if ln]


def service_containers(cluster_arn: str) -> list[str]:
    """Return Docker container names for an ECS cluster (running + stopped)."""
    rc, out, _ = docker(
        "ps", "-a", "--filter", f"label=localemu.cluster={cluster_arn}",
        "--format", "{{.Names}}",
    )
    if rc != 0:
        return []
    return [ln for ln in out.strip().split("\n") if ln]


def wait_task_running(cluster: str, task_arn: str, timeout: int = 60) -> dict:
    """Poll DescribeTasks until the task reports RUNNING or timeout."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        d = ecs_c.describe_tasks(cluster=cluster, tasks=[task_arn])
        if d.get("tasks"):
            last = d["tasks"][0]
            if last.get("lastStatus") == "RUNNING":
                return last
        time.sleep(1.5)
    return last or {}


# ---------------------------------------------------------------------------
# Shared topology
# ---------------------------------------------------------------------------

state: dict = {}


def _bootstrap_topology() -> None:
    """Create VPC + subnets + SG + NACL-open rules used by every scenario.

    Kept out of the scenario list because failure here aborts everything.
    """
    vpc = ec2.create_vpc(CidrBlock="10.70.0.0/16")["Vpc"]["VpcId"]
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})
    state["vpc"] = vpc

    vpc2 = ec2.create_vpc(CidrBlock="10.71.0.0/16")["Vpc"]["VpcId"]
    ec2.modify_vpc_attribute(VpcId=vpc2, EnableDnsHostnames={"Value": True})
    state["vpc2"] = vpc2  # unused VPC — just to prove per-VPC resolution picks subnet's VPC

    state["subnet"] = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.70.1.0/24", AvailabilityZone=f"{REGION}a",
    )["Subnet"]["SubnetId"]
    state["subnet2"] = ec2.create_subnet(
        VpcId=vpc2, CidrBlock="10.71.1.0/24", AvailabilityZone=f"{REGION}a",
    )["Subnet"]["SubnetId"]

    state["sg"] = ec2.create_security_group(
        GroupName=f"ecs-e2e-{TAG}", Description="e2e", VpcId=vpc,
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=state["sg"],
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ],
    )

    # Shared volume directory used by scenario 5
    vol_dir = f"/tmp/le-ecs-vol-{TAG}"
    os.makedirs(vol_dir, exist_ok=True)
    state["vol_dir"] = vol_dir

    print(f"  topology: vpc={vpc} subnet={state['subnet']} sg={state['sg']}"
          f" vol={vol_dir}")


# ---------------------------------------------------------------------------
# 1 — CreateCluster
# ---------------------------------------------------------------------------
@step("01-create-cluster")
def s01_create_cluster():
    name = f"ecs-e2e-{TAG}"
    r = ecs_c.create_cluster(clusterName=name)
    assert r["cluster"]["status"] == "ACTIVE", f"cluster status={r['cluster']['status']}"
    state["cluster"] = name
    state["cluster_arn"] = r["cluster"]["clusterArn"]
    print(f"  cluster={state['cluster_arn']}")


# ---------------------------------------------------------------------------
# 2 — RegisterTaskDefinition (FARGATE, awsvpc, nginx)
# ---------------------------------------------------------------------------
@step("02-register-task-definition")
def s02_register_td():
    td = ecs_c.register_task_definition(
        family=f"nginx-td-{TAG}",
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256", memory="512",
        containerDefinitions=[{
            "name": "web",
            "image": "nginx:alpine",
            "essential": True,
            "cpu": 256, "memory": 512,
            "portMappings": [{
                "containerPort": 80,
                "hostPort": 80,
                "protocol": "tcp",
            }],
        }],
    )["taskDefinition"]
    assert td["networkMode"] == "awsvpc"
    assert td["cpu"] == "256" and td["memory"] == "512"
    state["td_nginx_arn"] = td["taskDefinitionArn"]
    print(f"  td={state['td_nginx_arn']}")


# ---------------------------------------------------------------------------
# 3 — RunTask with explicit subnets + SG, container RUNNING
# ---------------------------------------------------------------------------
@step("03-runtask-awsvpc-running")
def s03_runtask():
    r = ecs_c.run_task(
        cluster=state["cluster"],
        taskDefinition=state["td_nginx_arn"],
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [state["subnet"]],
                "securityGroups": [state["sg"]],
            },
        },
    )
    assert r["tasks"], f"RunTask returned no tasks: failures={r.get('failures')}"
    task_arn = r["tasks"][0]["taskArn"]
    state["task_nginx_arn"] = task_arn
    # Wait for container to become RUNNING via Docker
    names = []
    def _up():
        nonlocal names
        names = task_containers(task_arn)
        return bool(names) and docker_running(names[0])
    assert wait_docker(_up, timeout=90), (
        f"nginx container never RUNNING; names={names}"
    )
    state["task_nginx_container"] = names[0]
    print(f"  container={names[0]}")


# ---------------------------------------------------------------------------
# 4 — host → curl host-port → nginx welcome
# ---------------------------------------------------------------------------
@step("04-host-curl-nginx")
def s04_curl_nginx():
    cname = state["task_nginx_container"]
    # Find the host port mapped to container port 80
    rc, out, _ = docker("port", cname, "80/tcp")
    assert rc == 0 and out.strip(), f"no host port for 80/tcp on {cname}"
    # out may be e.g. "0.0.0.0:49153\n[::]:49153\n"
    host_port = None
    for line in out.strip().split("\n"):
        if ":" in line:
            host_port = line.rsplit(":", 1)[-1].strip()
            if host_port.isdigit():
                break
    assert host_port, f"could not parse host port from: {out!r}"
    state["nginx_host_port"] = host_port

    # Wait for nginx to actually accept connections (pull + start takes time)
    body = ""
    def _probe():
        nonlocal body
        try:
            with urllib.request.urlopen(
                f"http://localhost:{host_port}/", timeout=3,
            ) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            return "nginx" in body.lower()
        except Exception:
            return False
    assert wait_docker(_probe, timeout=45), (
        f"nginx host-port :{host_port} never responded (body={body!r})"
    )
    assert "welcome to nginx" in body.lower(), (
        f"nginx host-port response missing 'welcome to nginx': {body[:200]!r}"
    )
    print(f"  host-port={host_port}  body contains 'Welcome to nginx'")


# ---------------------------------------------------------------------------
# 5 — Multi-container task: web + sidecar, shared bind-mounted volume
# ---------------------------------------------------------------------------
@step("05-multi-container-shared-volume")
def s05_multi_container():
    vol_dir = state["vol_dir"]
    sentinel = "hello-from-sidecar"
    # Pre-create a file so both containers can see it
    with open(os.path.join(vol_dir, "sentinel.txt"), "w") as f:
        f.write(sentinel)

    td = ecs_c.register_task_definition(
        family=f"multi-td-{TAG}",
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="512", memory="1024",
        volumes=[{
            "name": "shared",
            "host": {"sourcePath": vol_dir},
        }],
        containerDefinitions=[
            {
                "name": "web",
                "image": "nginx:alpine",
                "essential": True,
                "cpu": 256, "memory": 512,
                "mountPoints": [{
                    "sourceVolume": "shared",
                    "containerPath": "/shared",
                    "readOnly": False,
                }],
            },
            {
                "name": "sidecar",
                "image": "busybox:1.36",
                "essential": False,
                "cpu": 128, "memory": 256,
                "command": ["sh", "-c", "while true; do sleep 30; done"],
                "mountPoints": [{
                    "sourceVolume": "shared",
                    "containerPath": "/shared",
                    "readOnly": False,
                }],
            },
        ],
    )["taskDefinition"]
    state["td_multi_arn"] = td["taskDefinitionArn"]

    r = ecs_c.run_task(
        cluster=state["cluster"],
        taskDefinition=td["taskDefinitionArn"],
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [state["subnet"]],
                "securityGroups": [state["sg"]],
            },
        },
    )
    assert r["tasks"], f"RunTask returned no tasks: failures={r.get('failures')}"
    task_arn = r["tasks"][0]["taskArn"]
    state["task_multi_arn"] = task_arn

    # Wait for BOTH containers to be RUNNING
    names: list[str] = []
    def _both_up():
        nonlocal names
        names = task_containers(task_arn)
        return len(names) == 2 and all(docker_running(n) for n in names)
    assert wait_docker(_both_up, timeout=90), (
        f"multi-container task: got {len(names)} containers ({names}), expected 2 RUNNING"
    )

    # Check mount in BOTH containers
    for cname in names:
        rc, out, _ = docker("exec", cname, "cat", "/shared/sentinel.txt", timeout=10)
        assert rc == 0, f"{cname}: cat /shared/sentinel.txt failed: {out!r}"
        assert sentinel in out, (
            f"{cname}: shared volume content mismatch: got {out!r}"
        )

    # Verify the mount shows up as a real bind mount via inspect
    for cname in names:
        rc, out, _ = docker(
            "inspect", "--format",
            "{{range .Mounts}}{{.Type}}:{{.Source}}->{{.Destination}}; {{end}}",
            cname,
        )
        assert rc == 0, f"inspect failed for {cname}"
        assert vol_dir in out and "/shared" in out, (
            f"{cname} missing bind mount {vol_dir}->/shared; inspect={out!r}"
        )
    print(f"  web+sidecar both running, shared mount OK ({vol_dir})")


# ---------------------------------------------------------------------------
# 6 — CreateService desiredCount=2 → 2 tasks in awsvpc mode
# ---------------------------------------------------------------------------
@step("06-create-service-desired-2")
def s06_create_service():
    # Use a cheap image so the service scales quickly
    td = ecs_c.register_task_definition(
        family=f"svc-td-{TAG}",
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256", memory="512",
        containerDefinitions=[{
            "name": "worker",
            "image": "busybox:1.36",
            "essential": True,
            "cpu": 256, "memory": 512,
            "command": ["sh", "-c", "while true; do sleep 30; done"],
        }],
    )["taskDefinition"]
    state["td_svc_arn"] = td["taskDefinitionArn"]

    svc_name = f"svc-{TAG}"
    r = ecs_c.create_service(
        cluster=state["cluster"],
        serviceName=svc_name,
        taskDefinition=td["taskDefinitionArn"],
        desiredCount=2,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [state["subnet"]],
                "securityGroups": [state["sg"]],
            },
        },
    )
    assert r["service"]["status"] == "ACTIVE"
    state["service_name"] = svc_name
    state["service_arn"] = r["service"]["serviceArn"]

    # Wait for 2 service containers
    def _two():
        ns = [
            n for n in service_containers(state["cluster_arn"])
            if f"-worker" in n
        ]
        return len(ns) >= 2 and all(docker_running(n) for n in ns[:2])
    assert wait_docker(_two, timeout=90), (
        f"service never spawned 2 containers; have={service_containers(state['cluster_arn'])}"
    )

    # Confirm both are attached to the right VPC network
    vpc_net = f"localemu-vpc-{state['vpc']}"
    names = [
        n for n in service_containers(state["cluster_arn"]) if "-worker" in n
    ]
    for cname in names[:2]:
        rc, out, _ = docker(
            "inspect", "--format",
            "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}",
            cname,
        )
        assert vpc_net in out, (
            f"service container {cname} NOT on VPC network {vpc_net}: {out!r}"
        )
    print(f"  service running: {names[:2]} on {vpc_net}")


# ---------------------------------------------------------------------------
# 7 — UpdateService desiredCount=3 → scale up
# ---------------------------------------------------------------------------
@step("07-update-service-scale-up-3")
def s07_scale_up():
    ecs_c.update_service(
        cluster=state["cluster"], service=state["service_name"], desiredCount=3,
    )

    def _three():
        ns = [
            n for n in service_containers(state["cluster_arn"]) if "-worker" in n
        ]
        running = [n for n in ns if docker_running(n)]
        return len(running) >= 3
    assert wait_docker(_three, timeout=90), (
        f"scale-up failed; running={[n for n in service_containers(state['cluster_arn']) if docker_running(n)]}"
    )
    print("  3 containers running")


# ---------------------------------------------------------------------------
# 8 — UpdateService desiredCount=1 → scale down (extras stopped+removed)
# ---------------------------------------------------------------------------
@step("08-update-service-scale-down-1")
def s08_scale_down():
    ecs_c.update_service(
        cluster=state["cluster"], service=state["service_name"], desiredCount=1,
    )

    def _one():
        ns = [
            n for n in service_containers(state["cluster_arn"]) if "-worker" in n
        ]
        running = [n for n in ns if docker_running(n)]
        return len(running) == 1
    assert wait_docker(_one, timeout=90), (
        f"scale-down failed; "
        f"running={[n for n in service_containers(state['cluster_arn']) if docker_running(n)]}"
    )

    # Verify extras are actually removed (not just stopped)
    all_worker = [
        n for n in service_containers(state["cluster_arn"]) if "-worker" in n
    ]
    # `service_containers` uses `-a`, so stopped-but-present would show up
    # here. After stop_task, the implementation also calls remove_container
    # — so the count must drop to 1.
    assert len(all_worker) == 1, (
        f"scale-down left stale containers (stopped-but-present): {all_worker}"
    )
    print("  1 container running, extras removed")


# ---------------------------------------------------------------------------
# 9 — DescribeTasks: lastStatus=RUNNING + networkBindings populated
# ---------------------------------------------------------------------------
@step("09-describe-tasks-has-network-bindings")
def s09_describe_tasks():
    # nginx task has portMappings 80:80 → bindings should be populated.
    d = ecs_c.describe_tasks(
        cluster=state["cluster"], tasks=[state["task_nginx_arn"]],
    )
    assert d["tasks"], "describe_tasks returned empty"
    t = d["tasks"][0]
    assert t["lastStatus"] == "RUNNING", (
        f"lastStatus={t['lastStatus']!r}, expected RUNNING"
    )
    conts = t.get("containers", [])
    assert conts, "task has no containers"
    bindings = []
    for c in conts:
        bindings.extend(c.get("networkBindings") or [])
    assert bindings, f"no networkBindings on any container: {conts!r}"
    mapped = [b for b in bindings if b.get("containerPort") == 80]
    assert mapped, f"no binding for containerPort=80: {bindings!r}"
    assert mapped[0].get("hostPort"), f"binding missing hostPort: {mapped!r}"
    print(f"  bindings={mapped}")


# ---------------------------------------------------------------------------
# 10 — StopTask → STOPPED + exitCode populated
# ---------------------------------------------------------------------------
@step("10-stop-task")
def s10_stop_task():
    # Register + run a short-lived task we can stop cleanly.
    td = ecs_c.register_task_definition(
        family=f"stop-td-{TAG}",
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256", memory="512",
        containerDefinitions=[{
            "name": "stopme",
            "image": "busybox:1.36",
            "essential": True,
            "cpu": 256, "memory": 512,
            "command": ["sh", "-c", "while true; do sleep 30; done"],
        }],
    )["taskDefinition"]
    r = ecs_c.run_task(
        cluster=state["cluster"],
        taskDefinition=td["taskDefinitionArn"],
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [state["subnet"]],
                "securityGroups": [state["sg"]],
            },
        },
    )
    task_arn = r["tasks"][0]["taskArn"]
    state["task_stop_arn"] = task_arn

    # Let it come up
    names: list[str] = []
    def _up():
        nonlocal names
        names = task_containers(task_arn)
        return bool(names) and docker_running(names[0])
    assert wait_docker(_up, timeout=60), f"stopme task never RUNNING; names={names}"
    cname = names[0]

    ecs_c.stop_task(
        cluster=state["cluster"], task=task_arn, reason="e2e-stop-test",
    )

    def _stopped():
        return not docker_running(cname)
    assert wait_docker(_stopped, timeout=30), f"container {cname} still running after StopTask"

    # DescribeTasks must reflect STOPPED + exitCode
    d = ecs_c.describe_tasks(cluster=state["cluster"], tasks=[task_arn])
    t = d["tasks"][0]
    assert t["lastStatus"] == "STOPPED", f"lastStatus={t['lastStatus']!r}"
    # stop_task removes container from manager BEFORE exit_code is inspected,
    # so exitCode comes via Docker inspect before removal. For busybox
    # running `sleep` SIGTERM → 143 (or 137 on SIGKILL). We accept any int.
    cs = t.get("containers", [])
    assert cs, "stopped task has no containers in describe"
    exit_codes = [c.get("exitCode") for c in cs]
    print(f"  exitCodes={exit_codes}")
    assert any(ec is not None for ec in exit_codes), (
        f"no exitCode populated on any container: {cs!r}"
    )


# ---------------------------------------------------------------------------
# 11 — ECS standard env vars are present in container
# ---------------------------------------------------------------------------
@step("11-ecs-standard-env-vars")
def s11_env_vars():
    cname = state["task_nginx_container"]
    rc, out, _ = docker(
        "exec", cname, "sh", "-c",
        "env | grep -E '^(ECS_CONTAINER_METADATA_URI_V4|AWS_CONTAINER_CREDENTIALS_RELATIVE_URI|AWS_REGION)='",
    )
    assert rc == 0, f"docker exec env failed: rc={rc}, out={out!r}"
    lines = {ln.split("=", 1)[0]: ln.split("=", 1)[1] for ln in out.strip().split("\n") if "=" in ln}
    assert "ECS_CONTAINER_METADATA_URI_V4" in lines, f"missing V4 metadata URI: {lines}"
    assert lines["ECS_CONTAINER_METADATA_URI_V4"].startswith("http://169.254.170.2/v4/"), (
        f"malformed metadata URI: {lines['ECS_CONTAINER_METADATA_URI_V4']!r}"
    )
    assert "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" in lines, (
        f"missing creds relative URI: {lines}"
    )
    assert lines["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"].startswith("/v2/credentials/"), (
        f"malformed creds URI: {lines['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI']!r}"
    )
    print(f"  V4 URI={lines['ECS_CONTAINER_METADATA_URI_V4']}")
    print(f"  creds URI={lines['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI']}")


# ---------------------------------------------------------------------------
# 12 — bridge networkMode → default bridge + ports mapped
# ---------------------------------------------------------------------------
@step("12-bridge-network-mode")
def s12_bridge_mode():
    td = ecs_c.register_task_definition(
        family=f"bridge-td-{TAG}",
        networkMode="bridge",
        containerDefinitions=[{
            "name": "web",
            "image": "nginx:alpine",
            "essential": True,
            "cpu": 128, "memory": 256,
            "portMappings": [{
                "containerPort": 80,
                "hostPort": 0,  # dynamic host port
                "protocol": "tcp",
            }],
        }],
    )["taskDefinition"]

    # Bridge mode uses EC2 launch type. We provide a synthetic cluster that
    # lets the synthetic-instance path create the placeholder — same code
    # path the ``run_e2e.py`` tests hit.
    r = ecs_c.run_task(
        cluster=state["cluster"],
        taskDefinition=td["taskDefinitionArn"],
        launchType="EC2",
    )
    assert r["tasks"], f"RunTask returned no tasks: failures={r.get('failures')}"
    task_arn = r["tasks"][0]["taskArn"]
    state["task_bridge_arn"] = task_arn

    names: list[str] = []
    def _up():
        nonlocal names
        names = task_containers(task_arn)
        return bool(names) and docker_running(names[0])
    assert wait_docker(_up, timeout=60), f"bridge task never RUNNING; names={names}"
    cname = names[0]

    rc, out, _ = docker(
        "inspect", "--format",
        "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}",
        cname,
    )
    nets = set(out.strip().split())
    assert "bridge" in nets, (
        f"bridge-mode task should be on default bridge; got {nets}"
    )
    # Must NOT be on any localemu-vpc-* network
    vpc_nets = [n for n in nets if n.startswith("localemu-vpc-")]
    assert not vpc_nets, (
        f"bridge-mode task incorrectly attached to VPC networks: {vpc_nets}"
    )

    # Host port present and reachable
    rc, out, _ = docker("port", cname, "80/tcp")
    assert rc == 0 and out.strip(), f"no host port on {cname}"
    host_port = None
    for line in out.strip().split("\n"):
        if ":" in line:
            host_port = line.rsplit(":", 1)[-1].strip()
            if host_port.isdigit():
                break
    assert host_port, f"could not parse host port from: {out!r}"
    state["bridge_host_port"] = host_port

    ok = False
    def _probe():
        nonlocal ok
        try:
            with urllib.request.urlopen(
                f"http://localhost:{host_port}/", timeout=3,
            ) as resp:
                ok = "nginx" in resp.read().decode("utf-8", errors="replace").lower()
            return ok
        except Exception:
            return False
    assert wait_docker(_probe, timeout=30), (
        f"bridge-mode nginx :{host_port} never responded"
    )
    print(f"  bridge-mode nginx on {cname}, host-port {host_port}")


# ---------------------------------------------------------------------------
# 13 — containerDefinition.healthCheck → Docker HEALTHCHECK configured
# ---------------------------------------------------------------------------
@step("13-container-healthcheck")
def s13_healthcheck():
    td = ecs_c.register_task_definition(
        family=f"hc-td-{TAG}",
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256", memory="512",
        containerDefinitions=[{
            "name": "hc",
            "image": "busybox:1.36",
            "essential": True,
            "cpu": 256, "memory": 512,
            "command": ["sh", "-c", "while true; do sleep 30; done"],
            "healthCheck": {
                "command": ["CMD", "sh", "-c", "exit 0"],
                "interval": 5,
                "timeout": 3,
                "retries": 2,
                "startPeriod": 1,
            },
        }],
    )["taskDefinition"]
    r = ecs_c.run_task(
        cluster=state["cluster"],
        taskDefinition=td["taskDefinitionArn"],
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [state["subnet"]],
                "securityGroups": [state["sg"]],
            },
        },
    )
    assert r["tasks"], f"RunTask returned no tasks: failures={r.get('failures')}"
    task_arn = r["tasks"][0]["taskArn"]
    state["task_hc_arn"] = task_arn

    names: list[str] = []
    def _up():
        nonlocal names
        names = task_containers(task_arn)
        return bool(names) and docker_running(names[0])
    assert wait_docker(_up, timeout=60), f"hc task never RUNNING; names={names}"
    cname = names[0]

    # Check Docker HEALTHCHECK is configured
    rc, out, _ = docker(
        "inspect", "--format", "{{json .Config.Healthcheck}}", cname,
    )
    assert rc == 0, f"docker inspect failed: {out!r}"
    hc_raw = out.strip()
    # Docker returns `null` if no healthcheck is configured
    assert hc_raw and hc_raw != "null", (
        f"container {cname} has NO HEALTHCHECK configured (got {hc_raw!r}) — "
        "ECS healthCheck → Docker HEALTHCHECK translation is broken"
    )
    hc = json.loads(hc_raw)
    test = hc.get("Test") or []
    assert test, f"HEALTHCHECK.Test is empty: {hc}"
    print(f"  HEALTHCHECK Test={test}")
    # Wait for docker to run the healthcheck at least once
    def _healthy():
        rc2, out2, _ = docker(
            "inspect", "--format", "{{.State.Health.Status}}", cname,
        )
        return rc2 == 0 and out2.strip() in ("healthy", "starting")
    assert wait_docker(_healthy, timeout=20), (
        "container never reported a health status — HEALTHCHECK not actually running"
    )
    rc, out, _ = docker(
        "inspect", "--format", "{{.State.Health.Status}}", cname,
    )
    print(f"  State.Health.Status={out.strip()}")


# ---------------------------------------------------------------------------
# 14 — DeleteCluster removes all remaining task containers
# ---------------------------------------------------------------------------
@step("14-delete-cluster-cleans-containers")
def s14_delete_cluster():
    cluster_arn = state["cluster_arn"]
    # Take a snapshot of everything under this cluster before delete
    pre = service_containers(cluster_arn)
    assert pre, "precondition: cluster should still have containers before delete"
    print(f"  before delete: {len(pre)} containers")

    # Stop the service first so DeleteCluster doesn't 400 on active services
    try:
        ecs_c.update_service(
            cluster=state["cluster"], service=state["service_name"],
            desiredCount=0,
        )
        time.sleep(2)
        ecs_c.delete_service(
            cluster=state["cluster"], service=state["service_name"], force=True,
        )
    except Exception as e:
        print(f"  (delete_service best-effort: {e})")

    ecs_c.delete_cluster(cluster=state["cluster"])
    # Prevent cleanup() from trying to delete the same cluster again
    state.pop("cluster", None)
    state.pop("cluster_arn", None)

    # All containers labeled with this cluster must be gone
    def _gone():
        remaining = service_containers(cluster_arn)
        return not remaining
    assert wait_docker(_gone, timeout=45), (
        f"DeleteCluster did NOT clean up containers: "
        f"remaining={service_containers(cluster_arn)}"
    )
    print("  all containers removed")


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
def cleanup() -> None:
    print("\n=== CLEANUP ===")
    # Stop any known task ARNs first
    for k in ("task_nginx_arn", "task_multi_arn", "task_stop_arn",
              "task_bridge_arn", "task_hc_arn"):
        if k in state and "cluster" in state:
            try:
                ecs_c.stop_task(cluster=state["cluster"], task=state[k])
            except Exception:
                pass
    if "service_name" in state and "cluster" in state:
        try:
            ecs_c.update_service(
                cluster=state["cluster"], service=state["service_name"],
                desiredCount=0,
            )
        except Exception:
            pass
        try:
            ecs_c.delete_service(
                cluster=state["cluster"], service=state["service_name"],
                force=True,
            )
        except Exception:
            pass
    if "cluster" in state:
        try:
            ecs_c.delete_cluster(cluster=state["cluster"])
        except Exception:
            pass

    # Any leftover containers (labels carry the cluster ARN, not name)
    arn = state.get("cluster_arn")
    if arn:
        for cname in service_containers(arn):
            try:
                docker("rm", "-f", cname, timeout=15)
            except Exception:
                pass

    # Topology
    for k in ("sg",):
        if k in state:
            try:
                ec2.delete_security_group(GroupId=state[k])
            except Exception:
                pass
    for k in ("subnet", "subnet2"):
        if k in state:
            try:
                ec2.delete_subnet(SubnetId=state[k])
            except Exception:
                pass
    for k in ("vpc", "vpc2"):
        if k in state:
            try:
                ec2.delete_vpc(VpcId=state[k])
            except Exception:
                pass

    # Shared volume dir
    if state.get("vol_dir"):
        try:
            shutil.rmtree(state["vol_dir"], ignore_errors=True)
        except Exception:
            pass


def main() -> int:
    try:
        _bootstrap_topology()
    except Exception as e:
        print(f"FATAL: topology bootstrap failed: {e}")
        cleanup()
        return 2

    fns = [
        s01_create_cluster,
        s02_register_td,
        s03_runtask,
        s04_curl_nginx,
        s05_multi_container,
        s06_create_service,
        s07_scale_up,
        s08_scale_down,
        s09_describe_tasks,
        s10_stop_task,
        s11_env_vars,
        s12_bridge_mode,
        s13_healthcheck,
        s14_delete_cluster,
    ]
    try:
        for fn in fns:
            fn()
    finally:
        print("\n" + "=" * 60)
        print(f"SUMMARY: PASS={len(PASS)} FAIL={len(FAIL)}")
        print("=" * 60)
        for n, dt in PASS:
            print(f"  PASS  {n}  ({dt:.1f}s)")
        for n, e in FAIL:
            print(f"  FAIL  {n}  -- {e[:200]}")
        cleanup()

    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
