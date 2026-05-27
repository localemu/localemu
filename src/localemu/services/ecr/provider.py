"""Pure Moto provider for ecr."""

from localemu.services.moto import call_moto, dispatch_to_moto
from localemu.http import Request, Response


def ecr_dispatch(request: Request, service_name: str, path_params: dict) -> Response:
    """Forward all ecr requests to Moto."""
    return dispatch_to_moto(request.context) if hasattr(request, "context") else Response("", status=501)
