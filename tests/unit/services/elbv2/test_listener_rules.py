"""ELBv2 listener rules — host/path conditions + actions.

Pre-fix: the proxy router ignored every rule on a listener and always
proxied to the listener's default target group. CDK / TF deployments
that wire path-pattern or host-header routing to multiple target groups
silently funneled every request to the default action, breaking any
multi-service ALB.

These tests run the real router end-to-end: spin up two HTTP target
servers, register them as separate target groups, define rules that
route by path / host / fixed-response / redirect, and verify the
correct target answers each request.
"""

from __future__ import annotations

import http.client
import http.server
import socket
import threading
from contextlib import closing


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_target(body: bytes):
    class _T(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_, **__):
            return

        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    port = _free_port()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), _T)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def _http_get(port: int, path: str, *, host_header: str | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {}
    if host_header:
        headers["Host"] = host_header
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp, body


class TestListenerRulesEndToEnd:
    def test_path_pattern_routes_to_rule_target_group(self):
        from localemu.services.elbv2.listener_router import (
            ListenerRouter,
            TargetGroup,
        )

        default_srv, default_port = _make_target(b"default")
        rule_srv, rule_port = _make_target(b"rule-tg")
        try:
            router = ListenerRouter()
            default_tg_arn = "arn:aws:elasticloadbalancing:::targetgroup/default/d"
            rule_tg_arn = "arn:aws:elasticloadbalancing:::targetgroup/rule/r"
            listener_arn = "arn:aws:elasticloadbalancing:::listener/lb/path-test"
            router.register_target_group(
                TargetGroup(arn=default_tg_arn, name="default", protocol="HTTP", port=default_port)
            )
            router.register_target_group(
                TargetGroup(arn=rule_tg_arn, name="rule", protocol="HTTP", port=rule_port)
            )
            router.add_targets(default_tg_arn, [{"Id": "127.0.0.1", "Port": default_port}])
            router.add_targets(rule_tg_arn, [{"Id": "127.0.0.1", "Port": rule_port}])
            lp = router.start_listener(
                lb_arn="arn:aws:elasticloadbalancing:::loadbalancer/lb",
                listener_arn=listener_arn,
                protocol="HTTP",
                requested_port=80,
                target_group_arn=default_tg_arn,
            )
            router.register_rule(
                rule_arn="arn:aws:elasticloadbalancing:::listener-rule/lb/r/api",
                listener_arn=listener_arn,
                priority="10",
                conditions=[
                    {
                        "Field": "path-pattern",
                        "PathPatternConfig": {"Values": ["/api/*"]},
                    }
                ],
                actions=[{"Type": "forward", "TargetGroupArn": rule_tg_arn}],
            )

            resp, body = _http_get(lp, "/")
            assert resp.status == 200 and body == b"default"
            resp, body = _http_get(lp, "/api/users")
            assert resp.status == 200 and body == b"rule-tg"
            resp, body = _http_get(lp, "/api/")
            assert resp.status == 200 and body == b"rule-tg"
            resp, body = _http_get(lp, "/static/css")
            assert resp.status == 200 and body == b"default"
        finally:
            router.stop_listener(listener_arn)
            default_srv.shutdown()
            default_srv.server_close()
            rule_srv.shutdown()
            rule_srv.server_close()

    def test_host_header_routes_independently_of_path(self):
        from localemu.services.elbv2.listener_router import (
            ListenerRouter,
            TargetGroup,
        )

        default_srv, default_port = _make_target(b"default")
        api_srv, api_port = _make_target(b"api-host")
        try:
            router = ListenerRouter()
            d_arn = "arn:aws:elasticloadbalancing:::targetgroup/d/d"
            a_arn = "arn:aws:elasticloadbalancing:::targetgroup/a/a"
            listener_arn = "arn:aws:elasticloadbalancing:::listener/lb/host-test"
            router.register_target_group(
                TargetGroup(arn=d_arn, name="d", protocol="HTTP", port=default_port)
            )
            router.register_target_group(
                TargetGroup(arn=a_arn, name="a", protocol="HTTP", port=api_port)
            )
            router.add_targets(d_arn, [{"Id": "127.0.0.1", "Port": default_port}])
            router.add_targets(a_arn, [{"Id": "127.0.0.1", "Port": api_port}])
            lp = router.start_listener(
                lb_arn="arn:aws:elasticloadbalancing:::loadbalancer/lb",
                listener_arn=listener_arn,
                protocol="HTTP",
                requested_port=80,
                target_group_arn=d_arn,
            )
            router.register_rule(
                rule_arn="arn:aws:elasticloadbalancing:::listener-rule/lb/host",
                listener_arn=listener_arn,
                priority="1",
                conditions=[
                    {
                        "Field": "host-header",
                        "HostHeaderConfig": {"Values": ["api.example.com"]},
                    }
                ],
                actions=[{"Type": "forward", "TargetGroupArn": a_arn}],
            )

            resp, body = _http_get(lp, "/", host_header="api.example.com")
            assert body == b"api-host", body
            resp, body = _http_get(lp, "/", host_header="www.example.com")
            assert body == b"default", body
        finally:
            router.stop_listener(listener_arn)
            default_srv.shutdown(); default_srv.server_close()
            api_srv.shutdown(); api_srv.server_close()

    def test_fixed_response_short_circuits(self):
        from localemu.services.elbv2.listener_router import (
            ListenerRouter,
            TargetGroup,
        )

        default_srv, default_port = _make_target(b"default")
        try:
            router = ListenerRouter()
            d_arn = "arn:aws:elasticloadbalancing:::targetgroup/d/d"
            listener_arn = "arn:aws:elasticloadbalancing:::listener/lb/fixed-test"
            router.register_target_group(
                TargetGroup(arn=d_arn, name="d", protocol="HTTP", port=default_port)
            )
            router.add_targets(d_arn, [{"Id": "127.0.0.1", "Port": default_port}])
            lp = router.start_listener(
                lb_arn="arn:aws:elasticloadbalancing:::loadbalancer/lb",
                listener_arn=listener_arn,
                protocol="HTTP",
                requested_port=80,
                target_group_arn=d_arn,
            )
            router.register_rule(
                rule_arn="arn:aws:elasticloadbalancing:::listener-rule/lb/fixed",
                listener_arn=listener_arn,
                priority="1",
                conditions=[
                    {"Field": "path-pattern", "PathPatternConfig": {"Values": ["/health"]}}
                ],
                actions=[
                    {
                        "Type": "fixed-response",
                        "FixedResponseConfig": {
                            "StatusCode": "418",
                            "ContentType": "text/plain",
                            "MessageBody": "I'm a teapot",
                        },
                    }
                ],
            )

            resp, body = _http_get(lp, "/health")
            assert resp.status == 418
            assert body == b"I'm a teapot"
            # Non-matching paths still go to default target.
            resp, body = _http_get(lp, "/")
            assert body == b"default"
        finally:
            router.stop_listener(listener_arn)
            default_srv.shutdown(); default_srv.server_close()

    def test_redirect_action(self):
        from localemu.services.elbv2.listener_router import (
            ListenerRouter,
            TargetGroup,
        )

        default_srv, default_port = _make_target(b"default")
        try:
            router = ListenerRouter()
            d_arn = "arn:aws:elasticloadbalancing:::targetgroup/d/d"
            listener_arn = "arn:aws:elasticloadbalancing:::listener/lb/redir-test"
            router.register_target_group(
                TargetGroup(arn=d_arn, name="d", protocol="HTTP", port=default_port)
            )
            router.add_targets(d_arn, [{"Id": "127.0.0.1", "Port": default_port}])
            lp = router.start_listener(
                lb_arn="arn:aws:elasticloadbalancing:::loadbalancer/lb",
                listener_arn=listener_arn,
                protocol="HTTP",
                requested_port=80,
                target_group_arn=d_arn,
            )
            router.register_rule(
                rule_arn="arn:aws:elasticloadbalancing:::listener-rule/lb/redir",
                listener_arn=listener_arn,
                priority="1",
                conditions=[
                    {"Field": "path-pattern", "PathPatternConfig": {"Values": ["/old/*"]}}
                ],
                actions=[
                    {
                        "Type": "redirect",
                        "RedirectConfig": {
                            "Protocol": "HTTPS",
                            "Host": "new.example.com",
                            "Port": "443",
                            "Path": "/v2/#{path}",
                            "Query": "#{query}",
                            "StatusCode": "HTTP_301",
                        },
                    }
                ],
            )

            resp, _ = _http_get(lp, "/old/foo?x=1")
            assert resp.status == 301
            assert resp.getheader("Location") == "https://new.example.com:443/v2//old/foo?x=1"
        finally:
            router.stop_listener(listener_arn)
            default_srv.shutdown(); default_srv.server_close()

    def test_priority_order_first_match_wins(self):
        from localemu.services.elbv2.listener_router import (
            ListenerRouter,
            TargetGroup,
        )

        d_srv, d_port = _make_target(b"default")
        a_srv, a_port = _make_target(b"alpha")
        b_srv, b_port = _make_target(b"beta")
        try:
            router = ListenerRouter()
            d_arn = "arn:aws:elasticloadbalancing:::targetgroup/d/d"
            a_arn = "arn:aws:elasticloadbalancing:::targetgroup/a/a"
            b_arn = "arn:aws:elasticloadbalancing:::targetgroup/b/b"
            listener_arn = "arn:aws:elasticloadbalancing:::listener/lb/prio-test"
            for arn, port, name in [
                (d_arn, d_port, "d"),
                (a_arn, a_port, "a"),
                (b_arn, b_port, "b"),
            ]:
                router.register_target_group(
                    TargetGroup(arn=arn, name=name, protocol="HTTP", port=port)
                )
                router.add_targets(arn, [{"Id": "127.0.0.1", "Port": port}])

            lp = router.start_listener(
                lb_arn="arn:aws:elasticloadbalancing:::loadbalancer/lb",
                listener_arn=listener_arn,
                protocol="HTTP",
                requested_port=80,
                target_group_arn=d_arn,
            )
            # Same condition, two rules — priority 5 (alpha) beats priority 10 (beta).
            router.register_rule(
                rule_arn="arn:aws:elasticloadbalancing:::listener-rule/lb/beta",
                listener_arn=listener_arn,
                priority="10",
                conditions=[
                    {"Field": "path-pattern", "PathPatternConfig": {"Values": ["/x/*"]}}
                ],
                actions=[{"Type": "forward", "TargetGroupArn": b_arn}],
            )
            router.register_rule(
                rule_arn="arn:aws:elasticloadbalancing:::listener-rule/lb/alpha",
                listener_arn=listener_arn,
                priority="5",
                conditions=[
                    {"Field": "path-pattern", "PathPatternConfig": {"Values": ["/x/*"]}}
                ],
                actions=[{"Type": "forward", "TargetGroupArn": a_arn}],
            )

            _resp, body = _http_get(lp, "/x/anything")
            assert body == b"alpha"
        finally:
            router.stop_listener(listener_arn)
            d_srv.shutdown(); d_srv.server_close()
            a_srv.shutdown(); a_srv.server_close()
            b_srv.shutdown(); b_srv.server_close()
