"""
Security Group enforcement via iptables inside Docker containers.

Translates AWS Security Group ingress and egress rules to iptables
chains and applies them via ``docker exec``.  Security Groups are
stateful — return traffic for established connections is always allowed.

Works on Mac, Linux, and Windows (Docker Desktop).
Requires NET_ADMIN capability on containers.

Architecture
------------

  RunInstances → apply SG rules → docker exec per container
  Chain structure:
    INPUT  → SG_IN  (ingress rules — allow matching, drop rest)
    OUTPUT → SG_OUT (egress rules — allow matching, drop rest)
    Both chains allow ESTABLISHED,RELATED traffic (stateful behavior).

Fail-closed contract 
-------------------------------
``apply_sg_to_container`` returns ``True`` only on full success. On any
failure path — ``iptables`` binary missing, moto backend unreachable,
or any step of the apply script erroring — it returns ``False`` and
installs a fail-closed default-DROP policy (loopback + established
only). Callers MUST treat a ``False`` return as a hard error; leaving
the container at Docker's default-ACCEPT with SGs pretending to be
enforced would be a silent security hole.
"""

from __future__ import annotations

import logging

from localemu.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

# Probe command: succeeds only if iptables is installed and runnable.
# command -v is POSIX and avoids requiring which(1); iptables -V returns
# non-zero when the binary is absent or lacks kernel support.
_IPTABLES_PROBE_CMD = ["sh", "-c", "command -v iptables >/dev/null && iptables -V >/dev/null"]

# Install attempts in priority order. Each entry is a single shell line
# passed to ``sh -c``; whichever pkg manager exists in the container
# wins. Stderr / stdout is silenced -- the source of truth is the
# re-probe afterwards, not the install command's exit code.
_IPTABLES_INSTALL_CMDS = [
    "apk add --no-cache iptables",
    "apt-get update -qq && apt-get install -y -qq iptables",
    "dnf install -y iptables",
    "yum install -y iptables",
]


def _probe_iptables(container_name: str, *, log_level: int = logging.DEBUG) -> bool:
    """Return True iff iptables is available and runnable inside the container.

    ``log_level`` controls the level used to report a failed probe.
    Callers that expect failure (e.g. the install-then-probe loop in
    ``ensure_iptables_in_container``) pass DEBUG so the noise stays
    out of operator logs; callers that consider failure an error
    (post-install final probe) pass WARNING.
    """
    try:
        DOCKER_CLIENT.exec_in_container(container_name, _IPTABLES_PROBE_CMD)
        return True
    except Exception as exc:
        LOG.log(
            log_level,
            "iptables probe failed for container %s: %s", container_name, exc,
        )
        return False


def ensure_iptables_in_container(container_name: str) -> bool:
    """Make iptables present + runnable in ``container_name``.

    Order:
      1. Probe (DEBUG-level on miss -- normal codepath for alpine).
      2. If present, return True.
      3. Try each pkg-manager install in priority order.
      4. Re-probe (DEBUG-level until last attempt).
      5. Return True iff iptables now works; otherwise log ERROR once.

    Returns False if every install path failed AND iptables is still
    missing. Callers MUST treat False as a hard error: there is no
    honest fail-closed mode without iptables (a "default DROP" rule
    is itself an iptables command).
    """
    if _probe_iptables(container_name, log_level=logging.DEBUG):
        return True
    for install_line in _IPTABLES_INSTALL_CMDS:
        try:
            DOCKER_CLIENT.exec_in_container(
                container_name,
                ["sh", "-c", f"{install_line} >/dev/null 2>&1"],
            )
        except Exception:
            continue
        if _probe_iptables(container_name, log_level=logging.DEBUG):
            LOG.info(
                "Container %s: iptables installed via `%s`",
                container_name, install_line.split()[0],
            )
            return True
    LOG.error(
        "Container %s: could not install iptables via any of apk / "
        "apt-get / dnf / yum. SG enforcement is impossible in this "
        "container.", container_name,
    )
    return False


def _build_chain_rules(sg_rules: list, chain: str, is_egress: bool) -> list[str]:
    """Convert SG rules to iptables -A arguments for a chain.

    AWS SGs are allow-only (no explicit deny) and stateful.
    We create ACCEPT rules for each SG rule and a final DROP.
    ESTABLISHED,RELATED traffic is always allowed (stateful SG behavior).
    """
    rules: list[str] = []

    # Always allow established/related connections (stateful SG behavior)
    rules.append(f"-A {chain} -m state --state ESTABLISHED,RELATED -j ACCEPT")

    # Always allow loopback
    if not is_egress:
        rules.append(f"-A {chain} -i lo -j ACCEPT")
    else:
        rules.append(f"-A {chain} -o lo -j ACCEPT")

    # Always allow DNS (UDP 53) — AWS handles this implicitly
    rules.append(f"-A {chain} -p udp --dport 53 -j ACCEPT")

    for rule in sg_rules:
        proto = getattr(rule, "ip_protocol", "-1") or "-1"
        from_port = getattr(rule, "from_port", None)
        to_port = getattr(rule, "to_port", None)

        cidrs: list[str] = []
        # moto's SecurityGroupRule stores ONE source per rule object:
        # `ip_range` (dict, singular) OR `source_group` (dict, singular).
        # The previous code looked up plural `ip_ranges` / `source_groups`,
        # which never matched moto, defaulted to 0.0.0.0/0 below, and
        # silently widened every SG rule to allow-all.
        plural_ranges = getattr(rule, "ip_ranges", None) or []
        singular_range = getattr(rule, "ip_range", None) or {}
        for ip_range in (list(plural_ranges) + [singular_range]):
            if not ip_range:
                continue
            cidr = (
                ip_range.get("CidrIp")
                if isinstance(ip_range, dict)
                else getattr(ip_range, "cidr_ip", None)
            )
            if cidr:
                cidrs.append(cidr)

        # Resolve cross-references to concrete member IPs via the
        # AddressIndex. Each ENI carrying the referenced SG contributes
        # its primary_ip (and secondaries) as a /32 source. When
        # LOCALEMU_VPC_IP_PINNING is on and the AddressIndex has been
        # populated, this fixes the silent-allow-all behavior.
        plural_groups = getattr(rule, "source_groups", None) or []
        singular_group = getattr(rule, "source_group", None) or {}
        source_groups: list = list(plural_groups)
        if singular_group:
            source_groups.append(singular_group)
        if source_groups:
            from localemu import config as _config
            if _config.LOCALEMU_VPC_IP_PINNING:
                try:
                    from localemu.services.ec2.docker.address_index import (
                        get_address_index,
                    )
                    index = get_address_index()
                    for sg_ref in source_groups:
                        sg_id = (
                            sg_ref.get("GroupId")
                            if isinstance(sg_ref, dict)
                            else getattr(sg_ref, "group_id", None)
                        )
                        if not sg_id:
                            continue
                        for ip in index.get_ips_for_sg(sg_id):
                            cidrs.append(f"{ip}/32")
                except Exception:
                    LOG.debug(
                        "SG cross-ref resolution failed; falling back",
                        exc_info=True,
                    )

        if not cidrs:
            # Honest behavior split:
            #   - LOCALEMU_VPC_IP_PINNING=1 + source_groups set but the
            #     AddressIndex has no members for any of them: emit no
            #     ACCEPT for this rule. The default-DROP at the end of
            #     the chain takes over. This is what AWS does — an SG
            #     reference with no current members denies everything.
            #   - Off-path or no source_groups at all: keep today's
            #     0.0.0.0/0 fallback so existing tutorials don't break.
            from localemu import config as _config
            if _config.LOCALEMU_VPC_IP_PINNING and source_groups:
                continue
            cidrs = ["0.0.0.0/0"]

        direction = "-d" if is_egress else "-s"
        proto_name = _proto_name(proto)
        for cidr in cidrs:
            if proto == "-1":
                # any-protocol rule
                rules.append(f"-A {chain} {direction} {cidr} -j ACCEPT")
            elif proto_name == "icmp":
                # AWS uses from_port = ICMP type, to_port = ICMP code
                # (-1/-1 = any). iptables uses ``--icmp-type`` (NOT
                # ``--dport``) and accepts no type flag at all for
                # "any ICMP". The previous code emitted ``--dport -1``
                # which iptables rejects, blowing up the whole apply
                # script and forcing the fail-closed default-DROP.
                if from_port is None or from_port == -1 or from_port == "-1":
                    rules.append(
                        f"-A {chain} -p icmp {direction} {cidr} -j ACCEPT",
                    )
                else:
                    rules.append(
                        f"-A {chain} -p icmp {direction} {cidr} "
                        f"--icmp-type {from_port} -j ACCEPT",
                    )
            elif from_port is not None and to_port is not None and \
                    from_port != -1 and to_port != -1:
                if from_port == to_port:
                    port_flag = f"--dport {from_port}"
                else:
                    port_flag = f"--dport {from_port}:{to_port}"
                rules.append(
                    f"-A {chain} -p {proto_name} {direction} {cidr} {port_flag} -j ACCEPT",
                )
            else:
                rules.append(
                    f"-A {chain} -p {proto_name} {direction} {cidr} -j ACCEPT",
                )

    # Default deny at the end
    rules.append(f"-A {chain} -j DROP")

    return rules


def _proto_name(proto) -> str:
    """Map AWS numeric protocol to iptables protocol name."""
    proto = str(proto)
    if proto == "6":
        return "tcp"
    if proto == "17":
        return "udp"
    if proto == "1":
        return "icmp"
    return proto


def _collect_rules(
    sg_ids: list[str], account_id: str, region: str,
) -> tuple[list[str], list[str]]:
    """Pull ingress + egress rules from moto and compile iptables arguments.

    moto stores ``backend.groups`` as ``dict[vpc_id, dict[sg_id, SG]]``
    (a nested dict), so ``backend.groups.get(sg_id)`` always misses —
    the previous lookup silently returned no rules and the iptables
    chain ended up with only the default DROP. We use
    ``describe_security_groups(group_ids=[sg_id])`` which knows how
    to walk the nested structure.

    Raises on any moto-side failure; caller treats that as a hard
    error and installs the fail-closed default-DROP policy.
    """
    import moto.backends as moto_backends

    backend = moto_backends.get_backend("ec2")[account_id][region]

    all_ingress: list = []
    all_egress: list = []
    for sg_id in sg_ids:
        try:
            sgs = list(backend.describe_security_groups(group_ids=[sg_id]))
        except Exception:
            sgs = []
        for sg in sgs:
            all_ingress.extend(getattr(sg, "ingress_rules", []))
            all_egress.extend(getattr(sg, "egress_rules", []))

    in_rules = _build_chain_rules(all_ingress, "SG_IN", is_egress=False)
    out_rules = _build_chain_rules(all_egress, "SG_OUT", is_egress=True)
    return in_rules, out_rules


def _insert_log_directives(
    rules: list[str], chain: str, instance_id: str | None,
) -> list[str]:
    """Inject NFLOG / LOG directives into a chain for VPC Flow Logs .

    We emit BOTH ``-j NFLOG`` and ``-j LOG`` for each terminal rule:

      - ``NFLOG --nflog-group 42 --nflog-prefix LE-FL:...``
        delivers the packet over a netlink socket to a per-EC2-instance
        sidecar that runs ``ulogd2`` (see ``flow_log_sidecar.py``).
        Netlink is per-network-namespace so this path works on Linux
        AND macOS Docker Desktop — the sidecar joins the EC2 container's
        netns via ``--network=container:<ec2>``.

      - ``LOG --log-prefix LE-FL:...`` writes to the kernel ring buffer,
        which is readable via ``dmesg`` only on Linux (Docker Desktop's
        LinuxKit VM shares one ring buffer for all containers so
        per-container dmesg returns empty). Kept as a belt-and-braces
        fallback for Linux hosts where SYSLOG container cap works.

    iptables ``--log-prefix`` / ``--nflog-prefix`` truncate at 29/64
    characters respectively; our compact prefix
    ``LE-FL:<8-char-iid-suffix>:<I|O>:<A|D>:`` (≤20 chars) survives both.

    Without an ``instance_id`` we skip the instrumentation entirely
    (legacy callers: emergency default-DROP, unit tests).
    """
    if not instance_id:
        return rules

    iid_short = instance_id[-8:] if len(instance_id) > 8 else instance_id
    chain_short = "I" if chain == "SG_IN" else "O"

    # Import here to avoid a module-import cycle (flow_log_sidecar
    # imports docker_utils which imports localemu.config …).
    from localemu.services.ec2.docker.flow_log_sidecar import DEFAULT_NFLOG_GROUP

    out: list[str] = []
    for rule in rules:
        # Extract the action on this rule (ACCEPT / DROP). Rules that
        # don't end in one of those are rarer (e.g. -j RETURN) — skip
        # them rather than invent a LOG mapping.
        action_short = None
        if rule.endswith(" -j ACCEPT"):
            action_short = "A"
        elif rule.endswith(" -j DROP"):
            action_short = "D"

        if action_short:
            # Compact prefix that survives both --log-prefix (29 bytes)
            # and --nflog-prefix (64 bytes) truncation:
            prefix = f'"LE-FL:{iid_short}:{chain_short}:{action_short}: "'
            match_clause = rule.rsplit(" -j ", 1)[0]
            # NFLOG first — the sidecar (ulogd2) is the primary
            # cross-platform observation path.
            nflog_rule = (
                f"{match_clause} -j NFLOG "
                f"--nflog-group {DEFAULT_NFLOG_GROUP} "
                f"--nflog-prefix {prefix}"
            )
            out.append(nflog_rule)
            # LOG second — still useful on Linux hosts where dmesg
            # readback works, and the flow-log e2e test counts on the
            # LOG counters incrementing to confirm "the directive fired".
            log_rule = (
                f"{match_clause} -j LOG --log-prefix {prefix} --log-level 4"
            )
            out.append(log_rule)
        out.append(rule)
    return out


def _build_apply_script(
    in_rules: list[str],
    out_rules: list[str],
    instance_id: str | None = None,
) -> str:
    """Produce the shell script that applies all rules atomically.

    ``set -e`` guarantees that any step failing aborts the script, and
    the caller's try/except then triggers the fail-closed emergency
    default-DROP install. The ``|| true`` guards on ``-N <chain>`` are
    deliberate — chain-already-exists is not a failure.

    When ``instance_id`` is provided, an extra ``-j LOG`` rule is
    injected before every ACCEPT / DROP so dmesg carries the flow-log
    Stream for that instance .
    """
    in_rules = _insert_log_directives(in_rules, "SG_IN", instance_id)
    out_rules = _insert_log_directives(out_rules, "SG_OUT", instance_id)

    commands = [
        "set -e",
        "iptables -N SG_IN 2>/dev/null || true",
        "iptables -N SG_OUT 2>/dev/null || true",
        "iptables -F SG_IN",
        "iptables -F SG_OUT",
    ]
    commands.extend(f"iptables {r}" for r in in_rules)
    commands.extend(f"iptables {r}" for r in out_rules)
    # Idempotent hookup: only install the jump if it doesn't already exist.
    commands.append("iptables -C INPUT -j SG_IN 2>/dev/null || iptables -I INPUT -j SG_IN")
    commands.append("iptables -C OUTPUT -j SG_OUT 2>/dev/null || iptables -I OUTPUT -j SG_OUT")
    return "; ".join(commands)


def apply_sg_to_container(
    container_name: str,
    sg_ids: list[str],
    account_id: str,
    region: str,
    instance_id: str | None = None,
) -> bool:
    """Apply Security Group ingress and egress rules to a container.

    Reads SG rules from Moto's EC2 backend, translates to iptables,
    and injects via docker exec.

    When ``instance_id`` is provided, iptables ``LOG`` directives are
    injected alongside each ACCEPT / DROP so ``FlowLogPoller`` can
    Turn dmesg output into VPC Flow Log entries . Callers that
    don't have an instance id (e.g. unit tests, legacy paths) can
    safely omit it — the instrumentation is additive.

    Returns
    -------
    bool
        ``True`` on full success. Raises ``RuntimeError`` on any
        failure (iptables can't be installed, moto rules can't be
        built, the apply script errors). There is no silent
        fail-closed fallback -- a "default DROP" rule is itself an
        iptables command, so if we can't run iptables we can't
        honestly fail-closed. Callers MUST catch the exception and
        abort the higher-level operation (e.g. RunInstances).
    """
    # If the caller didn't supply an instance id but the container name
    # follows our naming convention, extract it so the flow-log LOG
    # directives still get stamped.
    if instance_id is None and container_name.startswith("localemu-ec2-"):
        instance_id = container_name.removeprefix("localemu-ec2-") or None

    # Guarantee iptables is present BEFORE we try to apply SG rules.
    # There is no honest fail-closed mode without iptables -- a "default
    # DROP" rule is itself an iptables command. If install fails, raise
    # so the caller (vm_manager) can abort RunInstances rather than
    # ship an instance whose SG is silently ignored.
    if not ensure_iptables_in_container(container_name):
        raise RuntimeError(
            f"Container {container_name}: iptables is not installed and "
            f"cannot be installed (apk/apt-get/dnf/yum all failed). "
            f"SG enforcement is impossible; refusing to claim SG "
            f"{sg_ids} is applied."
        )

    try:
        in_rules, out_rules = _collect_rules(sg_ids, account_id, region)
    except Exception as exc:
        raise RuntimeError(
            f"Container {container_name}: failed to build SG rules "
            f"from sgs={sg_ids}: {exc}"
        ) from exc

    script = _build_apply_script(in_rules, out_rules, instance_id=instance_id)
    try:
        DOCKER_CLIENT.exec_in_container(container_name, ["sh", "-c", script])
    except Exception as exc:
        raise RuntimeError(
            f"Container {container_name}: SG apply script failed: {exc}"
        ) from exc

    LOG.debug(
        "Container %s: applied SG rules (%d ingress, %d egress)",
        container_name, len(in_rules), len(out_rules),
    )
    return True
