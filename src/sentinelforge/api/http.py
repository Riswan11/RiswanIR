"""Serve the browser workspace and investigation API over WSGI."""

import json
import logging
import re
from http import HTTPStatus
from importlib.resources import files

from .. import frontend
from ..core.errors import NotFoundError
from ..core.fields import now
from ..correlation.temporal.service import serve as serve_temporal
from ..knowledge_graph.service import serve_graph
from ..models import (
    ActionDecision,
    AnalystFeedback,
    ApprovalDecision,
    EvidenceSubmission,
    InvestigationRequest,
)
from ..risk.models import Reassessment
from ..risk.service import serve as serve_risk
from ..schema.projection import export_events
from ..security.host import is_local_host

LOGGER = logging.getLogger(__name__)


class Application:
    def __init__(self, store):
        self.store = store

    def __call__(self, env, start_response):
        content_type = "application/json"
        result: object
        try:
            if not is_local_host(env.get("HTTP_HOST", "")):
                status, result = (
                    400,
                    {"error": "Use localhost or 127.0.0.1 to access SentinelForge."},
                )
            elif env["PATH_INFO"] == "/" and env["REQUEST_METHOD"] == "GET":
                result = files(frontend).joinpath("index.html").read_bytes()
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
        except Exception as exc:
            LOGGER.error("Unexpected error handling local request (%s)", type(exc).__name__)
            status, content_type, body = (
                500,
                "application/json",
                b'{"error":"Internal server error."}',
            )
        start_response(
            f"{status} {HTTPStatus(status).phrase}",
            [
                ("Content-Type", content_type),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
            ],
        )
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
                return 200, [summary.payload() for summary in self.store.list()]
            if method == "POST":
                request = InvestigationRequest.model_validate(self.body(env))
                return 201, self.store.create(request).payload()
        match = re.fullmatch(r"/v1/investigations/([a-f0-9]{32})(.*)", path)
        if match:
            investigation_id, suffix = match.groups()
            if method == "GET" and (suffix == "/risk" or suffix.startswith("/risk/")):
                return 200, serve_risk(
                    self.store, investigation_id, suffix, env.get("QUERY_STRING", "")
                )
            if method == "POST" and suffix == "/risk/reassess":
                reassessment = Reassessment.model_validate(self.body(env))
                return 200, self.store.reassess_risk(investigation_id, reassessment).payload()

            if method == "GET" and (
                suffix in {"/temporal-correlation", "/temporal-correlation/replay", "/incidents"}
                or suffix.startswith("/incidents/")
            ):
                return 200, serve_temporal(
                    self.store,
                    investigation_id,
                    suffix,
                    env.get("QUERY_STRING", ""),
                )
            if method == "GET" and (
                suffix == "/knowledge-graph" or suffix.startswith("/knowledge-graph/")
            ):
                return 200, serve_graph(
                    self.store,
                    investigation_id,
                    suffix.removeprefix("/knowledge-graph"),
                    env.get("QUERY_STRING", ""),
                )
            if method == "GET" and suffix in {"", "/evidence", "/graph"}:
                report = self.store.get(investigation_id).payload()
                return 200, report[suffix[1:]] if suffix else report
            if method == "GET" and suffix == "/correlation":
                return 200, self.store.get(investigation_id).payload().get("correlation")
            if method == "GET" and suffix == "/events":
                return 200, export_events(self.store.get(investigation_id))
            if method == "POST" and suffix == "/revisions":
                supplement = EvidenceSubmission.model_validate(self.body(env))
                return 201, self.store.revise(investigation_id, supplement).payload()
            if method == "POST" and suffix == "/feedback":
                feedback = AnalystFeedback.model_validate(self.body(env))
                return 201, self.store.feedback(investigation_id, feedback).payload()
            action = re.fullmatch(r"/actions/([a-z-]+)/(approve|reject)", suffix)
            if method == "POST" and action:
                action_id, decision = action.groups()
                body = self.body(env)
                approval = ActionDecision(
                    reviewer=body.get("reviewer"),
                    decision=ApprovalDecision(decision),
                    created_at=now(),
                )
                return 201, self.store.decide(investigation_id, action_id, approval).payload()
        raise NotFoundError("Route not found.")
