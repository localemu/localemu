"""Real-time WAFv2 rule enforcement.

Moto's WAFv2 backend (``moto.wafv2.models``) is CRUD-only: it stores Web
ACLs, rules, IP sets, rule groups and regex pattern sets, and the
association between a Web ACL and a resource, but never evaluates a rule
against a request. ``evaluator.py`` is the actual request-time engine;
``alb_hook.py`` wires it into the ALB listener proxy
(``services.elbv2.listener_router``); ``patches.py`` fixes a moto gap
(multiple Web ACLs can end up "associated" with the same resource) that
the evaluator's resolution logic depends on being impossible.

Scope: ALB only. CloudFront and API Gateway integration were found, on
review, to need their own separate work (CloudFront's real traffic path
bypasses the handler-chain entirely; API Gateway has its own distinct
handler chain) and are not covered here.
"""
