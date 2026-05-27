import werkzeug
import yaml
from rolo.routing import RuleAdapter

from localemu.http.resources.swagger.endpoints import SwaggerUIApi
from localemu.runtime import hooks
from localemu.services.edge import ROUTER
from localemu.services.internal import get_internal_apis
from localemu.utils.openapi import get_localemu_openapi_spec


@hooks.on_infra_start()
def register_swagger_endpoints():
    get_internal_apis().add(SwaggerUIApi())

    def _serve_openapi_spec(_request):
        spec = get_localemu_openapi_spec()
        response_body = yaml.dump(spec)
        return werkzeug.Response(
            response_body, content_type="application/yaml", direct_passthrough=True
        )

    ROUTER.add(RuleAdapter("/openapi.yaml", _serve_openapi_spec))
