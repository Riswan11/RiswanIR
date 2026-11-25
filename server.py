"""Local single-analyst HTTP interface for SentinelForge."""

import json
import os
import re
from http import HTTPStatus
from pathlib import Path
from wsgiref.simple_server import make_server

from forge import Store


class Application:
    def __init__(self, store):
        self.store = store

    def __call__(self, env, start_response):
        content_type = "application/json"
        try:
            if env["PATH_INFO"] == "/" and env["REQUEST_METHOD"] == "GET":
                result = Path(__file__).with_name("index.html").read_bytes()
                status, content_type = 200, "text/html; charset=utf-8"
            else:
                status, result = self.route(env)
        except (ValueError, RecursionError) as exc:
            status, result = 400, {"error": str(exc)}
        except FileExistsError as exc:
            status, result = 409, {"error": str(exc)}
        except LookupError as exc:
            status, result = 404, {"error": str(exc)}
        body = result if isinstance(result, bytes) else json.dumps(result).encode()
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
        data = json.loads(env["wsgi.input"].read(length))
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
        raise LookupError("Route not found.")


if __name__ == "__main__":
    port = int(os.environ.get("SENTINELFORGE_PORT", "8000"))
    store = Store(os.environ.get("SENTINELFORGE_DB", "sentinelforge.sqlite3"))
    with make_server("127.0.0.1", port, Application(store)) as server:
        print(f"SentinelForge is listening at http://127.0.0.1:{port}", flush=True)
        server.serve_forever()
