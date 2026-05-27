"""Route-deduplication contract for ``LocalemuResources``.

``rolo.Router.add`` is silently additive — registering the same path
twice appends a second rule, and werkzeug's Map dispatches the FIRST
match. So any handler added on a hot-reload or by a re-fired
on_infra_start hook is dead, the old handler keeps serving, and the
dashboard quietly stops reflecting code changes.

The :class:`LocalemuResources` subclass overrides ``add`` to make the
mounting idempotent. These tests pin the contract.
"""

from __future__ import annotations

from localemu.http import Resource
from localemu.services.internal import LocalemuResources


class _Handler:
    def __init__(self, tag: str):
        self.tag = tag

    def on_get(self, request):
        return self.tag


class TestRouterDedup:
    def test_duplicate_path_is_a_noop(self):
        router = LocalemuResources()
        before = len(router._registered_paths)
        router.add(Resource("/_localemu/x", _Handler("first")))
        assert "/_localemu/x" in router._registered_paths
        # Second add at the same path must not increase the count.
        result = router.add(Resource("/_localemu/x", _Handler("second")))
        assert result is None
        assert len(router._registered_paths) == before + 1

    def test_first_handler_wins_after_duplicate_add(self):
        """The first-mounted handler must stay live — confirm by checking
        the underlying werkzeug url_map only has the FIRST rule for the
        contested path. (We don't double-mount, so the count must be 1.)"""
        router = LocalemuResources()
        router.add(Resource("/_localemu/wins", _Handler("first")))
        router.add(Resource("/_localemu/wins", _Handler("second")))
        matching = [
            rule for rule in router.url_map.iter_rules()
            if rule.rule == "/_localemu/wins"
        ]
        assert len(matching) == 1, [r.rule for r in matching]

    def test_default_routes_register_only_once_across_reinit(self):
        """If ``add_default_routes`` is invoked a second time (e.g. via a
        plugin that does so explicitly) the per-instance ``_registered_paths``
        guard keeps the route table flat."""
        router = LocalemuResources()
        snapshot = set(router._registered_paths)
        router.add_default_routes()
        assert router._registered_paths == snapshot

    def test_distinct_paths_still_register(self):
        router = LocalemuResources()
        router.add(Resource("/_localemu/a", _Handler("a")))
        router.add(Resource("/_localemu/b", _Handler("b")))
        assert "/_localemu/a" in router._registered_paths
        assert "/_localemu/b" in router._registered_paths
