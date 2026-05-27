"""HTTP API route matching for API Gateway V2.

Matches incoming HTTP requests to routes using the flat route key model:
  "GET /users/{id}"     - standard path parameter
  "ANY /admin/{proxy+}" - greedy path parameter
  "$default"            - catch-all fallback

Priority: exact > parameterized > greedy > $default
"""

import re
from dataclasses import dataclass, field

__all__ = ["RouteMatcher", "RouteMatch"]


@dataclass
class RouteMatch:
    """Result of matching an HTTP request against API Gateway V2 routes."""

    route_key: str
    route_id: str
    integration_id: str
    path_parameters: dict[str, str] = field(default_factory=dict)
    authorizer_id: str | None = None
    operation_name: str | None = None


@dataclass
class _CompiledRoute:
    route_key: str
    method: str  # GET, POST, ANY, etc.
    pattern: re.Pattern | None  # None for $default
    route_id: str
    integration_id: str
    authorizer_id: str | None
    priority: tuple[int, int]
    operation_name: str | None = None


class RouteMatcher:
    """Matches incoming HTTP requests to API Gateway V2 routes.

    Routes are compiled into regex patterns on creation. Matching follows
    AWS priority: exact paths > parameterized > greedy > $default.
    """

    def __init__(self):
        self._routes: list[_CompiledRoute] = []

    def compile_routes(self, routes: list[dict]) -> None:
        """Compile route definitions into matchers.

        Args:
            routes: List of route dicts from moto (GetRoutes response format).
                    Each must have RouteKey, RouteId, and optionally Target, AuthorizerId.
        """
        self._routes = []

        for route in routes:
            route_key = route.get("RouteKey", "")
            route_id = route.get("RouteId", "")
            target = route.get("Target", "")
            authorizer_id = route.get("AuthorizerId")
            operation_name = route.get("OperationName")

            # Extract integration ID from target (format: "integrations/<id>")
            integration_id = ""
            if target and "/" in target:
                integration_id = target.split("/", 1)[1]

            if route_key == "$default":
                self._routes.append(
                    _CompiledRoute(
                        route_key=route_key,
                        method="ANY",
                        pattern=None,
                        route_id=route_id,
                        integration_id=integration_id,
                        authorizer_id=authorizer_id,
                        priority=(3, 0),
                        operation_name=operation_name,
                    )
                )
                continue

            # Parse "METHOD /path" format
            parts = route_key.split(" ", 1)
            if len(parts) == 2:
                method, path_pattern = parts
            else:
                method = "ANY"
                path_pattern = parts[0]

            regex = _path_to_regex(path_pattern)
            priority = _route_priority(route_key, path_pattern)

            self._routes.append(
                _CompiledRoute(
                    route_key=route_key,
                    method=method.upper(),
                    pattern=re.compile(f"^{regex}$"),
                    route_id=route_id,
                    integration_id=integration_id,
                    authorizer_id=authorizer_id,
                    priority=priority,
                    operation_name=operation_name,
                )
            )

        # Sort by priority (lower tuple = higher priority)
        self._routes.sort(key=lambda r: r.priority)

    def match(self, method: str, path: str) -> RouteMatch | None:
        """Match an HTTP method and path against compiled routes.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path (e.g., /users/123)

        Returns:
            RouteMatch if a route matches, None otherwise.
        """
        method = method.upper()

        for route in self._routes:
            # $default catches everything
            if route.route_key == "$default":
                return RouteMatch(
                    route_key=route.route_key,
                    route_id=route.route_id,
                    integration_id=route.integration_id,
                    path_parameters={},
                    authorizer_id=route.authorizer_id,
                    operation_name=route.operation_name,
                )

            # Check method match
            if route.method != "ANY" and route.method != method:
                continue

            # Check path match
            m = route.pattern.match(path)
            if m:
                return RouteMatch(
                    route_key=route.route_key,
                    route_id=route.route_id,
                    integration_id=route.integration_id,
                    path_parameters=m.groupdict(),
                    authorizer_id=route.authorizer_id,
                    operation_name=route.operation_name,
                )

        return None


def _path_to_regex(path_pattern: str) -> str:
    """Convert API Gateway V2 path pattern to regex.

    /users/{id}       -> /users/(?P<id>[^/]+)
    /admin/{proxy+}   -> /admin/(?P<proxy>.+)
    /health           -> /health

    Literal path segments are escaped to prevent dots/special chars from
    matching unintended characters (audit fix: regex injection prevention).
    """
    # Split on parameter placeholders, escape literal segments
    parts = re.split(r"(\{[\w+]+\})", path_pattern)
    result = ""
    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            # Parameter placeholder — convert to regex capture group
            inner = part[1:-1]
            if inner.endswith("+"):
                name = inner[:-1]
                result += f"(?P<{name}>.+)"
            else:
                result += f"(?P<{inner}>[^/]+)"
        else:
            # Literal segment — escape special regex characters
            result += re.escape(part)
    return result


def _route_priority(route_key: str, path: str) -> tuple[int, int]:
    """Compute sort priority. Lower tuple = higher priority.

    exact paths > parameterized > greedy > $default
    Within same type, longer paths take precedence.
    """
    if route_key == "$default":
        return (3, 0)
    if "{" not in path:
        return (0, -len(path))  # exact, longer paths first
    if "+" in path:
        return (2, -len(path))  # greedy
    return (1, -len(path))  # parameterized
