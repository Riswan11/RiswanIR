"""Serve the browser workspace and investigation API over WSGI."""

import json
import logging
import re
from http import HTTPStatus
from importlib.resources import files
from urllib.parse import parse_qs
from uuid import UUID

from riswan_platform.authorization import Permission, ScopeType
from riswan_platform.authorization.enforcement import AccessDenied, Enforcement
from riswan_platform.core.context import bind_context, require_context
from riswan_platform.core.contracts import ContextProvider, ProductModule
from riswan_platform.core.exceptions import ContextRequiredError
from riswan_platform.events import DomainEvent, EventDispatcher
from riswan_security_data.time import utc_timestamp

from .. import frontend
from ..core.errors import NotFoundError
from ..core.fields import now
from ..correlation.temporal.service import serve as serve_temporal
from ..investigation.ports import CaseRepository
from ..knowledge_graph.service import serve_graph
from ..memory.models import Feedback as MemoryFeedback
from ..models import (
    ActionDecision,
    AnalystFeedback,
    ApprovalDecision,
    EvidenceSubmission,
    InvestigationReport,
    InvestigationRequest,
)
from ..risk.models import Reassessment
from ..risk.service import serve as serve_risk
from ..schema.projection import export_events
from ..security.host import is_local_host

LOGGER = logging.getLogger(__name__)


class Application:
    def __init__(
        self,
        store: CaseRepository,
        *,
        context_provider: ContextProvider | None = None,
        tenant_id: UUID | None = None,
        product: ProductModule | None = None,
        dispatcher: EventDispatcher | None = None,
        enforcement: Enforcement | None = None,
    ):
        self.store = store
        self._context_provider = context_provider
        self._tenant_id = tenant_id
        self._product = product
        self._dispatcher = dispatcher
        self._enforcement = enforcement

    def __call__(self, env, start_response):
        content_type = "application/json"
        result: object
        try:
            if not is_local_host(env.get("HTTP_HOST", "")):
                status, result = (
                    400,
                    {"error": "Use localhost or 127.0.0.1 to access Riswan IR."},
                )
            elif env["PATH_INFO"] == "/" and env["REQUEST_METHOD"] == "GET":
                result = files(frontend).joinpath("index.html").read_bytes()
                status, content_type = 200, "text/html; charset=utf-8"
            elif env["REQUEST_METHOD"] == "GET" and re.fullmatch(
                r"/assets/ir-(?:logo|favicon)-(?:dark|light)\.svg", env["PATH_INFO"]
            ):
                result = files(frontend).joinpath(env["PATH_INFO"].rsplit("/", 1)[-1]).read_bytes()
                status, content_type = 200, "image/svg+xml"
            else:
                if self._context_provider is None or self._product is None:
                    raise ContextRequiredError("Trusted execution context is required.")
                context = self._context_provider()
                with bind_context(context):
                    if (context.tenant_id, context.product_id) != (
                        self._tenant_id,
                        self._product.product_id,
                    ):
                        raise ContextRequiredError("Invalid application scope.")
                    status, result = self.route(env)
            body = result if isinstance(result, bytes) else json.dumps(result).encode()
        except AccessDenied:
            status, body = 404, b'{"error":"Route not found."}'
        except ContextRequiredError:
            status, body = 403, b'{"error":"Trusted execution context is required."}'
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

    def _created(self, report: InvestigationReport) -> dict[str, object]:
        if self._dispatcher:
            context = require_context()
            self._dispatcher.publish(
                DomainEvent.from_context(
                    context,
                    "ir.investigation.created",
                    utc_timestamp(report.created_at),
                    report.id,
                )
            )
        return report.payload()

    def route(self, env):
        context = require_context()
        if self._product is None or (context.tenant_id, context.product_id) != (
            self._tenant_id,
            self._product.product_id,
        ):
            raise ContextRequiredError("Invalid application scope.")
        method, path = env["REQUEST_METHOD"], env["PATH_INFO"]
        if self._enforcement is not None:
            return self._authorized_route(method, path)
        if path == "/v1/memory/expire" and method == "POST":
            return 200, {"expired": self.store.memory_expire()}
        if path == "/v1/investigations":
            if method == "GET":
                return 200, [summary.payload() for summary in self.store.list()]
            if method == "POST":
                request = InvestigationRequest.model_validate(self.body(env))
                return 201, self._created(self.store.create(request))
        match = re.fullmatch(r"/v1/investigations/([a-f0-9]{32})(.*)", path)
        if match:
            investigation_id, suffix = match.groups()
            if method == "GET" and suffix == "/memory":
                query = env.get("QUERY_STRING", "")
                if len(query) > 512:
                    raise ValueError("Memory query is too large.")
                params = parse_qs(
                    query, strict_parsing=True, keep_blank_values=True, max_num_fields=2
                )
                if set(params) - {"as_of"} or len(params.get("as_of", [])) > 1:
                    raise ValueError("Provide at most one as_of timestamp.")
                return 200, self.store.memory_intelligence(
                    investigation_id, params.get("as_of", [None])[0]
                ).payload()
            if method == "POST" and suffix == "/memory/index":
                return 200, {"indexed": self.store.memory_index(investigation_id)}
            if method == "POST" and suffix == "/memory/feedback":
                self.store.memory_feedback(
                    investigation_id, MemoryFeedback.model_validate(self.body(env))
                )
                return 201, {"recorded": True}
            if method == "DELETE" and suffix == "/memory":
                self.store.memory_remove(investigation_id)
                return 200, {"deleted": True}
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
                return 201, self._created(self.store.revise(investigation_id, supplement))
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

    def _authorized_route(self, method: str, path: str):
        enforcement = self._enforcement
        if enforcement is None:
            raise AccessDenied
        if path == "/v1/investigations" and method == "GET":
            ids = enforcement.investigation_ids()
            return 200, [summary.payload() for summary in self.store.list_scoped(ids)]
        match = re.fullmatch(r"/v1/investigations/([a-f0-9]{32})(.*)", path)
        if method != "GET" or match is None:
            raise AccessDenied
        case_id, suffix = match.groups()
        enforcement.require(Permission.READ, ScopeType.INVESTIGATION, case_id)
        if not suffix:
            # The legacy full report embeds separately protected evidence and memory.
            return 200, self.store.get_summary(case_id).payload()
        raise AccessDenied
