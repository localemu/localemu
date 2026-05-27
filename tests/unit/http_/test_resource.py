import pytest
from werkzeug.exceptions import MethodNotAllowed

from localemu.http import Request, Resource, Response, Router, resource
from localemu.http.dispatcher import handler_dispatcher


class TestResource:
    def test_resource_decorator_dispatches_correctly(self):
        router = Router(dispatcher=handler_dispatcher())

        requests = []

        @resource("/_localemu/health")
        class TestResource:
            def on_get(self, req):
                requests.append(req)
                return "GET/OK"

            def on_post(self, req):
                requests.append(req)
                return {"ok": "POST"}

            def on_head(self, req):
                # this is ignored
                requests.append(req)
                return "HEAD/OK"

        router.add(TestResource())

        request1 = Request("GET", "/_localemu/health")
        request2 = Request("POST", "/_localemu/health")
        request3 = Request("HEAD", "/_localemu/health")
        assert router.dispatch(request1).get_data(True) == "GET/OK"
        assert router.dispatch(request1).get_data(True) == "GET/OK"
        assert router.dispatch(request2).json == {"ok": "POST"}
        assert router.dispatch(request3).get_data(True) == "HEAD/OK"
        assert len(requests) == 4
        assert requests[0] is request1
        assert requests[1] is request1
        assert requests[2] is request2
        assert requests[3] is request3

    def test_resource_dispatches_correctly(self):
        router = Router(dispatcher=handler_dispatcher())

        class TestResource:
            def on_get(self, req):
                return "GET/OK"

            def on_post(self, req):
                return "POST/OK"

            def on_head(self, req):
                return "HEAD/OK"

        router.add(Resource("/_localemu/health", TestResource()))

        request1 = Request("GET", "/_localemu/health")
        request2 = Request("POST", "/_localemu/health")
        request3 = Request("HEAD", "/_localemu/health")
        assert router.dispatch(request1).get_data(True) == "GET/OK"
        assert router.dispatch(request2).get_data(True) == "POST/OK"
        assert router.dispatch(request3).get_data(True) == "HEAD/OK"

    def test_dispatch_to_non_existing_method_raises_exception(self):
        router = Router(dispatcher=handler_dispatcher())

        @resource("/_localemu/health")
        class TestResource:
            def on_post(self, request):
                return "POST/OK"

        router.add(TestResource())

        with pytest.raises(MethodNotAllowed):
            assert router.dispatch(Request("GET", "/_localemu/health"))
        assert router.dispatch(Request("POST", "/_localemu/health")).get_data(True) == "POST/OK"

    def test_resource_with_default_dispatcher(self):
        router = Router()

        @resource("/_localemu/<path>")
        class TestResource:
            def on_get(self, req, args):
                return Response.for_json({"message": "GET/OK", "path": args["path"]})

            def on_post(self, req, args):
                return Response.for_json({"message": "POST/OK", "path": args["path"]})

        router.add(TestResource())
        assert router.dispatch(Request("GET", "/_localemu/health")).json == {
            "message": "GET/OK",
            "path": "health",
        }
        assert router.dispatch(Request("POST", "/_localemu/foobar")).json == {
            "message": "POST/OK",
            "path": "foobar",
        }

    def test_resource_overwrite_with_resource_wrapper(self):
        router = Router(dispatcher=handler_dispatcher())

        @resource("/_localemu/health")
        class TestResourceHealth:
            def on_get(self, req):
                return Response.for_json({"message": "GET/OK", "path": req.path})

            def on_post(self, req):
                return Response.for_json({"message": "POST/OK", "path": req.path})

        endpoints = TestResourceHealth()
        router.add(endpoints)
        router.add(Resource("/health", endpoints))

        assert router.dispatch(Request("GET", "/_localemu/health")).json == {
            "message": "GET/OK",
            "path": "/_localemu/health",
        }
        assert router.dispatch(Request("POST", "/_localemu/health")).json == {
            "message": "POST/OK",
            "path": "/_localemu/health",
        }

        assert router.dispatch(Request("GET", "/health")).json == {
            "message": "GET/OK",
            "path": "/health",
        }
        assert router.dispatch(Request("POST", "/health")).json == {
            "message": "POST/OK",
            "path": "/health",
        }
