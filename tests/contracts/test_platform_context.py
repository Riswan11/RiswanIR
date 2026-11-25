import io
import json
import tomllib
from dataclasses import replace
from pathlib import Path
from uuid import UUID, uuid4
from wsgiref.util import setup_testing_defaults

import pytest

from riswan_app.composition import compose_local, open_local_job_store
from riswan_app.local import LOCAL_TENANT, local_context
from riswan_ir.api.http import Application
from riswan_ir.product import IRProduct
from riswan_platform.core.context import PlatformContext, bind_context, require_context
from riswan_platform.core.exceptions import ContextRequiredError
from riswan_platform.events import EventDispatcher


def invoke(app, path, data=None, **headers):
    payload = json.dumps(data).encode() if data is not None else b""
    env = {}
    setup_testing_defaults(env)
    env.update(
        REQUEST_METHOD="POST" if data is not None else "GET",
        PATH_INFO=path,
        HTTP_HOST="localhost:8000",
        CONTENT_TYPE="application/json",
        CONTENT_LENGTH=str(len(payload)),
        **headers,
    )
    env["wsgi.input"] = io.BytesIO(payload)
    response = []
    body = b"".join(app(env, lambda status, headers: response.append(status)))
    return int(response[0].split()[0]), json.loads(body)


def test_local_composition_refuses_missing_or_production_context(tmp_path):
    path = tmp_path / "new.sqlite3"
    for mode in (None, "production"):
        with pytest.raises(ContextRequiredError):
            compose_local(path, mode)
    assert not path.exists()
    with pytest.raises(ContextRequiredError):
        open_local_job_store(path)
    assert not path.exists()


def test_request_context_cannot_be_supplied_by_headers_or_body(store, request_payload):
    local = local_context("local", "ir")
    foreign = replace(local, tenant_id=uuid4())
    for resolver in (None, lambda: foreign, lambda: replace(local, product_id="other")):
        app = Application(
            store, context_provider=resolver, tenant_id=LOCAL_TENANT, product=IRProduct()
        )
        assert (
            invoke(
                app,
                "/v1/investigations",
                {**request_payload, "tenant_id": str(LOCAL_TENANT)},
                HTTP_X_TENANT_ID=str(LOCAL_TENANT),
                HTTP_X_ACTOR_ID="spoofed",
            )[0]
            == 403
        )
    assert store.list() == []
    with pytest.raises(ContextRequiredError):
        require_context()


def test_composition_binds_context_and_emits_after_persistence(tmp_path, request_payload):
    observed = []

    def handler(event):
        request = require_context()
        stored = runtime.http.store.get(event.payload["investigation_id"])
        observed.append((event, request, stored.id))

    runtime = compose_local(
        tmp_path / "case.sqlite3",
        "local",
        dispatcher=EventDispatcher({"ir.investigation.created": (handler,)}),
    )
    version = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    assert runtime.product.product_id == "ir"
    assert runtime.product.version == version
    assert "historical_investigation_memory" in runtime.product.capabilities()
    assert invoke(runtime.http, "/v1/investigations", {"records": []})[0] == 400
    assert observed == []
    status, report = invoke(
        runtime.http,
        "/v1/investigations",
        request_payload,
        HTTP_X_TENANT_ID=str(uuid4()),
        HTTP_X_ACTOR_ID="forged",
        HTTP_X_REQUEST_ID="forged",
        HTTP_X_CORRELATION_ID="forged",
    )
    assert status == 201
    event, context, saved_id = observed.pop()
    assert saved_id == report["id"]
    assert context.tenant_id == event.tenant_id == LOCAL_TENANT
    assert context.actor_id == "local-operator"
    assert event.correlation_id == context.correlation_id != "forged"
    with pytest.raises(ContextRequiredError):
        require_context()
    with pytest.raises(ContextRequiredError):
        runtime.evidence.canonical_events(context, saved_id)
    with bind_context(context):
        assert len(runtime.evidence.canonical_events(context, saved_id)) == len(report["evidence"])


def test_invalid_and_nested_contexts_fail_closed(tmp_path):
    context = local_context("local", "ir")
    with pytest.raises(ValueError):
        replace(context, tenant_id=UUID(int=0))
    with pytest.raises(ValueError):
        PlatformContext(uuid4(), "actor with spaces", "human", "ir", "req-1", "corr-1")
    with bind_context(context):
        with pytest.raises(ContextRequiredError), bind_context(replace(context, actor_id="other")):
            pytest.fail("Cross-scope rebinding succeeded.")
        with pytest.raises(ContextRequiredError):
            open_local_job_store(tmp_path / "human.sqlite3")
        assert require_context() is context
    service = local_context("local", "ir", actor_type="service")
    with bind_context(service):
        assert open_local_job_store(tmp_path / "service.sqlite3").list() == []
