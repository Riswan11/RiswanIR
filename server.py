"""Local single-analyst HTTP interface for SentinelForge."""

import json
import logging
import os
import re
from http import HTTPStatus
from pathlib import Path
from wsgiref.simple_server import make_server

from forge import NotFoundError, Store


LOGGER = logging.getLogger(__name__)
LOCAL_HOST = re.compile(r"(?:localhost|127\.0\.0\.1)(?::[0-9]{1,5})?", re.IGNORECASE | re.ASCII)


class Application:
    def __init__(self, store):
        self.store = store

    def __call__(self, env, start_response):
        content_type = "application/json"
        try:
            if not LOCAL_HOST.fullmatch(env.get("HTTP_HOST", "")):
                status, result = 400, {"error": "Use localhost or 127.0.0.1 to access SentinelForge."}
            elif env["PATH_INFO"] == "/" and env["REQUEST_METHOD"] == "GET":
                result = Path(__file__).with_name("index.html").read_bytes()
                status, content_type = 200, "text/html; charset=utf-8"
            else:
                status, result = self.route(env)
            body = result if isinstance(result, bytes) else json.dumps(result).encode()
        except (ValueError, RecursionError) as exc:
            status, body = 400, json.dumps({"error": str(exc)}).encode()
        except FileExistsError as exc:
            status, body = 409, json.dumps({"error": str(exc)}).encode()
        except NotFoundError as exc:
            status, body = 404, json.dumps({"error": str(exc)}).encode()
        except Exception:
            LOGGER.exception("Unexpected error handling local request")
            status, content_type, body = 500, "application/json", b'{"error":"Internal server error."}'
        start_response(f"{status} {HTTPStatus(status).phrase}", [
            ("Content-Type", content_type), ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
        ])
        return [body]

    @staticmethod
    def body(env):
        if env.get("CONTENT_TYPE", "").split(";")[0].strip().lower() != "application/json":
            raise ValueError("Use application/json.")
        length = int(env.get("CONTENT_LENGTH") or 0)
        if not 0 < length <= 8_000_000:
            raise ValueError("JSON body must be between 1 byte and 8 MB.")
        raw = env["wsgi.input"].read(length)
        if len(raw) != length:
            raise ValueError("Incomplete JSON body.")
        try:
            data = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Malformed JSON body.") from exc
        if not isinstance(data, dict):
            raise ValueError("Provide a JSON object.")
        return data

    def route(self, env):
        method, path = env["REQUEST_METHOD"], env["PATH_INFO"]
        if path == "/v1/investigations":
            if method == "GET":
                return 200, self.store.list()
            if method == "POST":
                return 201, self.store.create(self.body(env))
        match = re.fullmatch(r"/v1/investigations/([a-f0-9]{32})(.*)", path)
        if match:
            investigation_id, suffix = match.groups()
            if method == "GET" and suffix in {"", "/evidence", "/graph"}:
                report = self.store.get(investigation_id)
                return 200, report[suffix[1:]] if suffix else report
            if method == "POST" and suffix == "/feedback":
                return 201, self.store.feedback(investigation_id, self.body(env))
            action = re.fullmatch(r"/actions/([a-z-]+)/(approve|reject)", suffix)
            if method == "POST" and action:
                action_id, decision = action.groups()
                return 201, self.store.decide(investigation_id, action_id, decision, self.body(env))
        raise NotFoundError("Route not found.")


if __name__ == "__main__":
    port = int(os.environ.get("SENTINELFORGE_PORT", "8000"))
    store = Store(os.environ.get("SENTINELFORGE_DB", "sentinelforge.sqlite3"))
    with make_server("127.0.0.1", port, Application(store)) as server:
        print(f"SentinelForge is listening at http://127.0.0.1:{port}", flush=True)
        server.serve_forever()
