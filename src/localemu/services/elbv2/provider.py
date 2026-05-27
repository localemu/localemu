"""Custom ELBv2 provider for LocalEmu.

Goes beyond Moto's state-only stub by running real HTTP listeners that
reverse-proxy to registered targets, plus active TCP health checking.

Operations intercepted:
  - CreateLoadBalancer        : normalize DNS name, track LB in router
  - CreateTargetGroup         : register TG in router
  - RegisterTargets           : add targets to router
  - DeregisterTargets         : remove targets from router
  - CreateListener            : start an actual HTTP listener (for HTTP ALBs)
  - DeleteListener            : stop the HTTP listener
  - DescribeLoadBalancers     : ensure DNS names match what we emit
  - DescribeTargetHealth      : return real TCP-probe-derived health

All other operations (rules, tags, SSL policies, attributes, NLB details,
etc.) fall through to Moto via `_proxy_moto`.
"""

from __future__ import annotations

import hashlib
import logging

from localemu.aws.api import RequestContext, ServiceRequest, ServiceResponse
from localemu.aws.skeleton import DispatchTable, Skeleton
from localemu.services.elbv2.listener_router import TargetGroup, get_router
from localemu.services.moto import _proxy_moto, call_moto
from localemu.services.plugins import Service

LOG = logging.getLogger(__name__)


def _lb_dns_name(name: str, region: str) -> str:
    """AWS-style ALB DNS: {name}-{16-hex}.{region}.elb.amazonaws.com."""
    suffix = hashlib.md5(name.encode()).hexdigest()[:16]  # noqa: S324
    return f"{name}-{suffix}.{region}.elb.amazonaws.com"


def _handle_create_load_balancer(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    result = call_moto(context)
    region = context.region or "us-east-1"
    router = get_router()
    for lb in result.get("LoadBalancers", []) or []:
        name = lb.get("LoadBalancerName") or "lb"
        dns = _lb_dns_name(name, region)
        lb["DNSName"] = dns
        router.register_lb(
            arn=lb.get("LoadBalancerArn", ""),
            name=name,
            dns_name=dns,
            scheme=lb.get("Scheme", "internet-facing"),
            lb_type=lb.get("Type", "application"),
        )
        LOG.info("ELBv2 LB created: %s (%s)", name, dns)
    return result


def _handle_describe_load_balancers(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    result = call_moto(context)
    region = context.region or "us-east-1"
    for lb in result.get("LoadBalancers", []) or []:
        name = lb.get("LoadBalancerName")
        if name:
            lb["DNSName"] = _lb_dns_name(name, region)
    return result


def _handle_create_target_group(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    result = call_moto(context)
    router = get_router()
    for tg in result.get("TargetGroups", []) or []:
        arn = tg.get("TargetGroupArn", "")
        if not arn:
            continue
        hc_port = tg.get("HealthCheckPort")
        try:
            hc_port_int = int(hc_port) if hc_port and str(hc_port).isdigit() else None
        except (ValueError, TypeError):
            hc_port_int = None
        router.register_target_group(TargetGroup(
            arn=arn,
            name=tg.get("TargetGroupName", ""),
            protocol=tg.get("Protocol", "HTTP"),
            port=int(tg.get("Port") or 80),
            health_check_port=hc_port_int,
        ))
    return result


def _handle_register_targets(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    result = call_moto(context)
    tg_arn = request.get("TargetGroupArn")
    targets = request.get("Targets") or []
    if tg_arn and targets:
        get_router().add_targets(tg_arn, targets)
    return result


def _handle_deregister_targets(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    result = call_moto(context)
    tg_arn = request.get("TargetGroupArn")
    targets = request.get("Targets") or []
    if tg_arn and targets:
        get_router().remove_targets(tg_arn, targets)
    return result


def _handle_create_listener(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    result = call_moto(context)
    router = get_router()
    for listener in result.get("Listeners", []) or []:
        protocol = listener.get("Protocol", "HTTP")
        # Start a real listener only for HTTP-family protocols (MVP).
        if protocol.upper() not in ("HTTP", "HTTPS"):
            continue

        lb_arn = listener.get("LoadBalancerArn", "")
        listener_arn = listener.get("ListenerArn", "")
        requested_port = int(listener.get("Port") or 80)

        # Pick the default target group from DefaultActions.
        target_group_arn = ""
        for action in listener.get("DefaultActions", []) or []:
            if action.get("Type") == "forward":
                target_group_arn = action.get("TargetGroupArn", "")
                if not target_group_arn:
                    fw = action.get("ForwardConfig") or {}
                    tgs = fw.get("TargetGroups") or []
                    if tgs:
                        target_group_arn = tgs[0].get("TargetGroupArn", "")
                if target_group_arn:
                    break

        if not target_group_arn:
            LOG.debug("Listener %s has no forward action; skipping HTTP proxy", listener_arn)
            continue

        actual_port = router.start_listener(
            lb_arn=lb_arn,
            listener_arn=listener_arn,
            protocol=protocol,
            requested_port=requested_port,
            target_group_arn=target_group_arn,
        )
        # Surface the real bound port via a non-AWS field so clients that care
        # (tests, dashboard) can discover it; advertised Port stays as requested.
        if actual_port:
            listener["LocalEmuBoundPort"] = actual_port
    return result


def _handle_delete_listener(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    listener_arn = request.get("ListenerArn") or ""
    result = call_moto(context)
    if listener_arn:
        get_router().stop_listener(listener_arn)
    return result


def _record_rule(rule: dict) -> None:
    """Mirror a moto-returned Rule into the proxy router so request
    routing actually honours its conditions/actions on the next hit."""
    rule_arn = rule.get("RuleArn") or ""
    if not rule_arn:
        return
    # moto returns ListenerArn on the rule object since elbv2 v3; older
    # versions omit it and the caller had to know it. Fall back to a scan
    # over our own listener map keyed by load-balancer ownership.
    listener_arn = rule.get("ListenerArn", "")
    if not listener_arn:
        # Worst case: pick the listener whose default TG matches one of
        # the rule's forward actions; if that fails too, drop silently.
        router_inst = get_router()
        for la, listener in router_inst.listeners.items():
            if any(
                (a.get("TargetGroupArn") or "") == listener.target_group_arn
                for a in (rule.get("Actions") or [])
            ):
                listener_arn = la
                break
    if not listener_arn:
        LOG.debug("CreateRule: no listener arn resolvable for %s; not recording", rule_arn)
        return
    get_router().register_rule(
        rule_arn=rule_arn,
        listener_arn=listener_arn,
        priority=str(rule.get("Priority") or "default"),
        conditions=rule.get("Conditions") or [],
        actions=rule.get("Actions") or [],
    )


def _handle_create_rule(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    result = call_moto(context)
    # moto returns the rule with its ARN populated.
    listener_arn = request.get("ListenerArn") or ""
    for rule in result.get("Rules", []) or []:
        if listener_arn and not rule.get("ListenerArn"):
            rule["ListenerArn"] = listener_arn
        _record_rule(rule)
    return result


def _handle_modify_rule(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    result = call_moto(context)
    for rule in result.get("Rules", []) or []:
        _record_rule(rule)
    return result


def _handle_delete_rule(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    rule_arn = request.get("RuleArn") or ""
    result = call_moto(context)
    if rule_arn:
        get_router().remove_rule(rule_arn)
    return result


def _handle_set_rule_priorities(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    result = call_moto(context)
    mapping = {
        item.get("RuleArn"): str(item.get("Priority"))
        for item in (request.get("RulePriorities") or [])
        if item.get("RuleArn") is not None
    }
    if mapping:
        get_router().set_rule_priorities(mapping)
    return result


def _handle_describe_target_health(
    context: RequestContext, request: ServiceRequest
) -> ServiceResponse:
    tg_arn = request.get("TargetGroupArn")
    if not tg_arn:
        return call_moto(context)

    router = get_router()
    if tg_arn not in router.target_groups:
        # Unknown to our router -> let Moto answer (state-only).
        return call_moto(context)

    descriptions = router.describe_target_health(tg_arn)

    # Allow filtering by requested Targets list, like the real API does.
    wanted = request.get("Targets") or []
    if wanted:
        wanted_keys = {(t.get("Id"), int(t.get("Port") or 0)) for t in wanted}
        descriptions = [
            d for d in descriptions
            if (d["Target"]["Id"], int(d["Target"]["Port"])) in wanted_keys
               or (d["Target"]["Id"], 0) in wanted_keys
        ]

    return {"TargetHealthDescriptions": descriptions}


_INTERCEPTED_OPS = {
    "CreateLoadBalancer": _handle_create_load_balancer,
    "DescribeLoadBalancers": _handle_describe_load_balancers,
    "CreateTargetGroup": _handle_create_target_group,
    "RegisterTargets": _handle_register_targets,
    "DeregisterTargets": _handle_deregister_targets,
    "CreateListener": _handle_create_listener,
    "DeleteListener": _handle_delete_listener,
    "DescribeTargetHealth": _handle_describe_target_health,
    "CreateRule": _handle_create_rule,
    "ModifyRule": _handle_modify_rule,
    "DeleteRule": _handle_delete_rule,
    "SetRulePriorities": _handle_set_rule_priorities,
}


def Elbv2Dispatcher(service_model) -> DispatchTable:
    table = {}
    for op in service_model.operation_names:
        table[op] = _INTERCEPTED_OPS.get(op, _proxy_moto)
    return table


def create_elbv2_service() -> Service:
    from localemu.aws.spec import load_service

    service_model = load_service("elbv2")
    dispatch_table = Elbv2Dispatcher(service_model)
    skeleton = Skeleton(service_model, dispatch_table)
    return Service(name="elbv2", skeleton=skeleton)
