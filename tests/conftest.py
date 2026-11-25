import io
import json
import uuid
from pathlib import Path
from wsgiref.util import setup_testing_defaults
from wsgiref.validate import validator

import pytest

from sentinelforge.api.http import Application
from sentinelforge.models import InvestigationRequest
from sentinelforge.storage.sqlite import Store


@pytest.fixture(autouse=True)
def deterministic_metadata(monkeypatch):
    when = "2025-01-01T04:00:00+00:00"
    ids = iter(range(1, 1000))
    monkeypatch.setattr("sentinelforge.storage.sqlite.uuid4", lambda: uuid.UUID(int=next(ids)))
    monkeypatch.setattr("sentinelforge.storage.sqlite.now", lambda: when)
    monkeypatch.setattr("sentinelforge.api.http.now", lambda: when)


@pytest.fixture
def cloudtrail():
    path = Path(__file__).parent / "fixtures" / "cloudtrail" / "credential-chain.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def request_payload(cloudtrail):
    return {"title": "Review build service activity", "principal": cloudtrail["Records"][0]["userIdentity"]["arn"],
            "records": cloudtrail}


@pytest.fixture
def investigation_request(request_payload):
    return InvestigationRequest.model_validate(request_payload)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "test.sqlite3")


@pytest.fixture
def client(store):
    application = validator(Application(store))

    def request(method, path, payload=None, *, raw=None, headers=None, length=None):
        body = raw if raw is not None else json.dumps(payload).encode() if payload is not None else b""
        env = {}
        setup_testing_defaults(env)
        env.update(REQUEST_METHOD=method, PATH_INFO=path, QUERY_STRING="", SERVER_PROTOCOL="HTTP/1.1",
                   HTTP_HOST="localhost:8000", CONTENT_TYPE="application/json",
                   CONTENT_LENGTH=str(len(body)) if length is None else str(length))
        env.update(headers or {})
        env["wsgi.input"] = io.BytesIO(body)
        captured = {}

        def start_response(status, response_headers, exc_info=None):
            captured.update(status=int(status.split()[0]), headers=dict(response_headers))

        result = application(env, start_response)
        try:
            response = b"".join(result)
        finally:
            result.close()
        if captured["headers"]["Content-Type"] == "application/json":
            response = json.loads(response)
        return captured["status"], response, captured["headers"]

    return request
