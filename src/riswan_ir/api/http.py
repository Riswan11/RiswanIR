"""Serve the browser workspace and investigation API over WSGI."""

import json
import logging
import re
from http import HTTPStatus
from importlib.resources import files
from urllib.parse import parse_qs
from uuid import UUID

from riswan_platform.authorization import Permission, Scope, ScopeType
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
            try:
                with self._enforcement.operation(mutation=method != "GET"):
                    return self._authorized_route(method, path, env)
            except NotFoundError as exc:
                raise AccessDenied from exc
        return self._route(method, path, env)

    def _route(self, method, path, env, *, related_ids=None):
        context = require_context()
        scoped = related_ids is not None
        if path == "/v1/memory/expire" and method == "POST":
            return 200, {"expired": self.store.memory_expire()}
        if path == "/v1/investigations":
            if method == "GET":
                return 200, [summary.payload() for summary in self.store.list()]
            if method == "POST":
                request = InvestigationRequest.model_validate(self.body(env))
                return 201, self._mutation_result(self.store.create(request), scoped, created=True)
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
                    investigation_id, params.get("as_of", [None])[0], case_ids=related_ids
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
                    self.store, investigation_id, suffix, env.get("QUERY_STRING", ""), scoped=scoped
                )
            if method == "POST" and suffix == "/risk/reassess":
                reassessment = Reassessment.model_validate(self.body(env))
                result = self.store.reassess_risk(investigation_id, reassessment)
                return 200, {"recorded": True} if scoped else result.payload()

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
                report = self.store.get(investigation_id, related_ids=related_ids).payload()
                if not suffix and scoped:
                    return 200, self._scoped_report(investigation_id, report)
                return 200, report[suffix[1:]] if suffix else report
            if method == "GET" and suffix == "/correlation":
                return 200, self.store.get(investigation_id, related_ids=related_ids).payload().get(
                    "correlation"
                )
            if method == "GET" and suffix == "/events":
                return 200, export_events(self.store.get(investigation_id, related_ids=()))
            if method == "POST" and suffix == "/revisions":
                supplement = EvidenceSubmission.model_validate(self.body(env))
                return 201, self._mutation_result(
                    self.store.revise(investigation_id, supplement), scoped, created=True
                )
            if method == "POST" and suffix == "/feedback":
                data = self.body(env)
                if scoped:
                    data["reviewer"] = context.actor_id
                feedback = AnalystFeedback.model_validate(data)
                return 201, self._mutation_result(
                    self.store.feedback(investigation_id, feedback), scoped
                )
            action = re.fullmatch(r"/actions/([a-z-]+)/(approve|reject)", suffix)
            if method == "POST" and action:
                action_id, decision = action.groups()
                body = self.body(env)
                approval = ActionDecision(
                    reviewer=context.actor_id if scoped else body.get("reviewer"),
                    decision=ApprovalDecision(decision),
                    created_at=now(),
                )
                return 201, self._mutation_result(
                    self.store.decide(investigation_id, action_id, approval), scoped
                )
        raise NotFoundError("Route not found.")

    def _mutation_result(self, report: InvestigationReport, scoped: bool, *, created=False):
        payload = self._created(report) if created else report.payload()
        if scoped:
            return {key: payload[key] for key in ("id", "created_at")}
        return payload

    def _evidence_scope(self, case_id: str, action: Permission, *, raw: bool = False) -> None:
        enforcement = self._enforcement
        if enforcement is None:
            raise AccessDenied
        parent = Scope(ScopeType.INVESTIGATION, case_id)
        enforcement.require(action, parent.kind, parent.id)
        for evidence_id in self.store.evidence_ids(case_id, raw=raw):
            key = evidence_id if raw else f"normalized/{evidence_id}"
            enforcement.require(action, ScopeType.EVIDENCE, f"{case_id}/{key}", parent=parent)

    def _scoped_report(self, case_id: str, report: dict[str, object]) -> dict[str, object]:
        enforcement = self._enforcement
        if enforcement is None:
            raise AccessDenied
        for action, fields in (
            (Permission.GRAPH, ("graph",)),
            (Permission.CORRELATE, ("correlation",)),
            (Permission.MEMORY, ("similar_investigations",)),
            (Permission.EXPORT, ("canonical_events",)),
            (Permission.DETECTION_READ, ("detection",)),
        ):
            try:
                if action == Permission.EXPORT:
                    self._evidence_scope(case_id, action)
                else:
                    enforcement.require(action, ScopeType.INVESTIGATION, case_id)
            except AccessDenied:
                for field in fields:
                    report.pop(field, None)
        # The parent may fall outside the viewer's authorized scope.
        previous = report.get("previous_investigation_id")
        if isinstance(previous, str):
            try:
                enforcement.require(Permission.READ, ScopeType.INVESTIGATION, previous)
            except AccessDenied:
                report.pop("previous_investigation_id", None)
        return report

    def _related_scope(self) -> tuple[str, ...]:
        enforcement = self._enforcement
        if enforcement is None:
            raise AccessDenied
        readable = set(enforcement.investigation_ids())
        related = []
        for case_id in enforcement.investigation_ids(Permission.MEMORY):
            if case_id in readable:
                try:
                    self._evidence_scope(case_id, Permission.EVIDENCE)
                except (AccessDenied, NotFoundError):
                    continue
                related.append(case_id)
        return tuple(related)

    def _authorized_route(self, method: str, path: str, env):
        enforcement = self._enforcement
        if enforcement is None:
            raise AccessDenied
        p = Permission
        if path == "/v1/investigations":
            if method == "GET":
                ids = enforcement.investigation_ids()
                return 200, [summary.payload() for summary in self.store.list_scoped(ids)]
            if method == "POST":
                enforcement.require(p.CREATE, ScopeType.PRODUCT, "ir")
                return self._route(method, path, env, related_ids=())
        match = re.fullmatch(r"/v1/investigations/([a-f0-9]{32})(.*)", path)
        if match is None:
            raise AccessDenied
        case_id, suffix = match.groups()
        parent = Scope(ScopeType.INVESTIGATION, case_id)
        enforcement.require(p.READ, parent.kind, parent.id)
        action = re.fullmatch(r"/actions/([a-z-]+)/(approve|reject)", suffix)
        if method == "POST" and action:
            enforcement.require(
                p.APPROVE, ScopeType.RESPONSE, f"{case_id}/{action[1]}", parent=parent
            )
            return self._route(method, path, env, related_ids=())
        evidence = re.fullmatch(r"/evidence/([^/]+)", suffix)
        if method == "GET" and evidence and evidence[1] != "export":
            enforcement.require(
                p.EVIDENCE, ScopeType.EVIDENCE, f"{case_id}/normalized/{evidence[1]}", parent=parent
            )
            report = self.store.get(case_id, related_ids=())
            for item in report.evidence:
                if item.id == evidence[1]:
                    return 200, item.payload()
            raise AccessDenied
        if method == "POST" and suffix == "/evidence/export":
            self._evidence_scope(case_id, p.EVIDENCE)
            self._evidence_scope(case_id, p.EXPORT)
            self._evidence_scope(case_id, p.EVIDENCE, raw=True)
            self._evidence_scope(case_id, p.EXPORT, raw=True)
            return 200, self.store.export_evidence(case_id)
        permissions = {
            ("GET", ""): p.READ,
            ("GET", "/evidence"): p.EVIDENCE,
            ("GET", "/events"): p.EXPORT,
            ("GET", "/graph"): p.GRAPH,
            ("GET", "/correlation"): p.CORRELATE,
            ("GET", "/memory"): p.MEMORY,
            ("POST", "/revisions"): p.UPDATE,
            ("POST", "/feedback"): p.FEEDBACK,
            ("POST", "/memory/index"): p.MEMORY_MANAGE,
            ("POST", "/memory/feedback"): p.FEEDBACK,
            ("DELETE", "/memory"): p.MEMORY_MANAGE,
            ("POST", "/risk/reassess"): p.RISK,
        }
        permission = permissions.get((method, suffix))
        if method == "GET" and suffix.startswith(("/risk/", "/incidents/", "/knowledge-graph/")):
            permission = {"risk": p.RISK, "incidents": p.CORRELATE, "knowledge-graph": p.GRAPH}[
                suffix.split("/")[1]
            ]
        elif method == "GET":
            permission = {
                "/risk": p.RISK,
                "/incidents": p.CORRELATE,
                "/knowledge-graph": p.GRAPH,
                "/temporal-correlation": p.CORRELATE,
                "/temporal-correlation/replay": p.CORRELATE,
            }.get(suffix, permission)
        if permission is None:
            raise AccessDenied
        enforcement.require(permission, parent.kind, parent.id)
        try:
            self._evidence_scope(case_id, p.EVIDENCE)
        except AccessDenied:
            if suffix == "":
                return 200, self.store.get_summary(case_id).payload()
            raise
        if permission in {p.GRAPH, p.RISK} or suffix == "/revisions":
            self._evidence_scope(case_id, p.EVIDENCE, raw=True)
        if permission == p.EXPORT:
            self._evidence_scope(case_id, p.EXPORT)
        related: tuple[str, ...] = ()
        if suffix == "/memory":
            related = self._related_scope()
        elif not suffix:
            try:
                enforcement.require(p.MEMORY, parent.kind, parent.id)
            except AccessDenied:
                pass
            else:
                related = self._related_scope()
        return self._route(method, path, env, related_ids=related)
