"""Product ownership directory and authenticated route composition."""

import json
import re
from dataclasses import replace
from urllib.parse import parse_qsl
from uuid import UUID

from riswan_ir.api.http import Application
from riswan_ir.correlation.temporal.service import serve as serve_temporal
from riswan_ir.knowledge_graph.service import serve_graph
from riswan_ir.models import EvidenceSubmission, InvestigationRequest, InvestigationSummary
from riswan_ir.product import IRProduct
from riswan_ir.risk.models import Reassessment
from riswan_ir.risk.service import serve as serve_risk
from riswan_ir.storage.sqlite import Store
from riswan_platform.authorization import (
    AuthorizationRequest,
    Permission,
    Resource,
    Scope,
    ScopeType,
)
from riswan_platform.authorization.enforcement import AccessDenied, Enforcement
from riswan_platform.core.context import bind_context, require_context
from riswan_platform.core.exceptions import NotFoundError
from riswan_platform.data_protection import HoldReason
from riswan_platform.identity.models import VerifiedPrincipal

from .postgres_cases import CaseUpdate, PostgresCases
from .postgres_events import TimelineQuery
from .tenancy import Tenancy


class IRResources:
    def __init__(self, store: Store | PostgresCases, tenant_id: UUID):
        self.store = store
        self.tenant_id = tenant_id
        self._cases = store.owned_investigations(tenant_id)
        self._evidence: dict[str, set[str]] = {}

    def _case(self, case_id: str) -> Resource:
        return Resource(
            self.tenant_id,
            "ir",
            Scope(ScopeType.INVESTIGATION, case_id),
            (Scope(ScopeType.PRODUCT, "ir"), Scope(ScopeType.ORGANIZATION, str(self.tenant_id))),
            tenant_shared=True,
        )

    def investigations(self):
        return (self._case(case_id) for case_id in self._cases)

    def resolve(self, kind: ScopeType, key: str) -> Resource | None:
        if (kind, key) == (ScopeType.PRODUCT, "ir"):
            return Resource(
                self.tenant_id,
                "ir",
                Scope(kind, key),
                (Scope(ScopeType.ORGANIZATION, str(self.tenant_id)),),
            )
        case_id, _, child = key.partition("/")
        if case_id not in self._cases:
            return None
        case = self._case(case_id)
        if kind == ScopeType.INVESTIGATION and not child:
            return case
        if kind == ScopeType.EVIDENCE:
            if case_id not in self._evidence:
                self._evidence[case_id] = {
                    *(f"normalized/{item}" for item in self.store.evidence_ids(case_id)),
                    *self.store.evidence_ids(case_id, raw=True),
                }
            if child in self._evidence[case_id]:
                return Resource(
                    self.tenant_id,
                    "ir",
                    Scope(kind, key),
                    (case.scope, *case.parents),
                    tenant_shared=True,
                )
        if kind == ScopeType.RESPONSE and not isinstance(self.store, PostgresCases):
            action = self.store.get(case_id, related_ids=()).action
            if action is not None and action.id == child:
                return Resource(
                    self.tenant_id,
                    "ir",
                    Scope(kind, key),
                    (case.scope, *case.parents),
                    proposer_id=self._cases[case_id],
                    tenant_shared=True,
                )
        return None


class HostedProduct:
    def __init__(self, tenancy: Tenancy, store: Store):
        self.tenancy = tenancy
        self.store = store

    def route(self, env, principal: VerifiedPrincipal, tenant_id: UUID, request_id: str):
        with self.tenancy.authorization.transaction():
            context = self.tenancy.context_for(principal, tenant_id, "ir", request_id)
            if context is None:
                raise AccessDenied
            with bind_context(context):
                if "/legal-holds" in env["PATH_INFO"]:
                    return self._legal_hold(env, principal)
                resources = IRResources(self.store, tenant_id)
                guard = Enforcement(
                    self.tenancy.evaluator, resources, self.tenancy.authorization.transaction
                )
                app = Application(
                    self.store, product=IRProduct(), tenant_id=tenant_id, enforcement=guard
                )
                return app.route(env)

    def _legal_hold(self, env, principal: VerifiedPrincipal):
        match = re.fullmatch(
            r"/v1/investigations/([a-f0-9]{32})/legal-holds(?:/([a-f0-9-]{36})/release)?",
            env["PATH_INFO"],
        )
        if match is None or env["REQUEST_METHOD"] != "POST":
            raise AccessDenied
        context = require_context()
        resource = Resource(
            context.tenant_id, "platform", Scope(ScopeType.ORGANIZATION, str(context.tenant_id))
        )
        request = AuthorizationRequest(
            principal, replace(context, product_id="platform"), Permission.LEGAL_HOLD, resource
        )
        if not self.tenancy.evaluator.evaluate(request).allowed:
            raise AccessDenied
        reason = HoldReason.model_validate(Application.body(env)).reason
        try:
            release = UUID(match[2]) if match[2] else None
            hold = self.store.change_legal_hold(match[1], reason, release=release)
        except NotFoundError as exc:
            raise AccessDenied from exc
        return (200 if release else 201), hold.model_dump(mode="json")


class HostedPostgresCases:
    """Explicit composition-only preview of supported case operations."""

    def __init__(self, tenancy: Tenancy, store: PostgresCases):
        self.tenancy = tenancy
        self.store = store

    def route(self, env, principal: VerifiedPrincipal, tenant_id: UUID, request_id: str):
        from psycopg import Error
        from psycopg_pool import PoolClosed, PoolTimeout

        with self.tenancy.authorization.transaction():
            context = self.tenancy.context_for(principal, tenant_id, "ir", request_id)
            if context is None:
                raise AccessDenied
            try:
                with bind_context(context):
                    return self._case_route(env, tenant_id)
            except NotFoundError as exc:
                raise AccessDenied from exc
            except (Error, PoolClosed, PoolTimeout):
                return 503, {"error": "PostgreSQL case storage unavailable."}

    def _case_route(self, env, tenant_id: UUID):
        method, path = env["REQUEST_METHOD"], env["PATH_INFO"]
        guard = Enforcement(self.tenancy.evaluator, IRResources(self.store, tenant_id))
        if path == "/v1/investigations":
            if method == "POST":
                guard.require(Permission.CREATE, ScopeType.PRODUCT, "ir")
                report = self.store.create(
                    InvestigationRequest.model_validate(Application.body(env))
                )
                return 201, {"id": report.id, "created_at": report.created_at}
            if method == "GET":
                return 200, [
                    item.payload() for item in self.store.list_scoped(guard.investigation_ids())
                ]
        match = re.fullmatch(r"/v1/investigations/([a-f0-9]{32})(.*)", path)
        if match is None:
            return 501, {"error": "Operation unavailable in the PostgreSQL case preview."}
        case_id, suffix = match.groups()
        scope = Scope(ScopeType.INVESTIGATION, case_id)
        guard.require(Permission.READ, scope.kind, scope.id)
        if method == "PATCH" and not suffix:
            guard.require(Permission.UPDATE, scope.kind, scope.id)
            return 200, self.store.update(
                case_id, CaseUpdate.model_validate(Application.body(env))
            ).payload()
        if method == "POST" and suffix.startswith("/legal-holds"):
            return self._hold(env, case_id, suffix)
        if method == "DELETE" and suffix == "/memory":
            guard.require(Permission.MEMORY_MANAGE, scope.kind, scope.id)
            self._evidence(guard, scope)
            self.store.memory_remove(case_id)
            return 204, None
        if method == "POST" and suffix == "/revisions":
            guard.require(Permission.UPDATE, scope.kind, scope.id)
            self._evidence(guard, scope, raw=True)
            self._evidence(guard, scope)
            report = self.store.revise(
                case_id, EvidenceSubmission.model_validate(Application.body(env))
            )
            return 201, {"id": report.id, "created_at": report.created_at}
        if method == "POST" and suffix == "/risk/reassess":
            guard.require(Permission.RISK, scope.kind, scope.id)
            self._evidence(guard, scope)
            self._evidence(guard, scope, raw=True)
            request = Reassessment.model_validate(Application.body(env))
            return 200, self.store.reassess(case_id, request).payload()
        graph_route = suffix == "/knowledge-graph" or suffix.startswith("/knowledge-graph/")
        temporal_route = suffix in {
            "/temporal-correlation",
            "/temporal-correlation/replay",
            "/incidents",
        } or suffix.startswith("/incidents/")
        risk_route = suffix == "/risk" or suffix.startswith("/risk/")

        if method != "GET" or (
            not (graph_route or temporal_route or risk_route)
            and suffix
            not in {
                "",
                "/evidence",
                "/events",
                "/evidence/provenance",
                "/evidence/custody",
                "/evidence/verify",
                "/findings",
                "/knowledge-graph",
                "/temporal-correlation",
                "/risk",
            }
        ):
            return 501, {"error": "Operation unavailable in the PostgreSQL case preview."}
        report = self.store.get(case_id)
        try:
            self._evidence(guard, scope)
        except AccessDenied:
            if suffix:
                raise
            return 200, InvestigationSummary(
                id=report.id, title=report.title, created_at=report.created_at
            ).payload()
        if suffix == "/evidence":
            return 200, [item.payload() for item in report.evidence]
        if suffix == "/events":
            guard.require(Permission.EXPORT, scope.kind, scope.id)
            for event_id in self.store.evidence_ids(case_id):
                guard.require(
                    Permission.EXPORT,
                    ScopeType.EVIDENCE,
                    f"{case_id}/normalized/{event_id}",
                    parent=scope,
                )
            raw_query = env.get("QUERY_STRING", "")
            if not raw_query:
                return 200, self.store.events(case_id)
            if len(raw_query) > 2048:
                raise ValueError("Invalid timeline query.")
            pairs = parse_qsl(
                raw_query, keep_blank_values=True, strict_parsing=True, max_num_fields=7
            )
            query = dict(pairs)
            if len(pairs) != len(query):
                raise ValueError("Duplicate timeline filter.")
            return 200, self.store.timeline(case_id, TimelineQuery.model_validate(query))
        if suffix == "/findings":
            guard.require(Permission.DETECTION_READ, scope.kind, scope.id)
            return 200, self.store.findings(case_id)
        if suffix in {"/evidence/provenance", "/evidence/custody", "/evidence/verify"}:
            self._evidence(guard, scope, raw=True)
            if suffix == "/evidence/verify":
                verification = self.store.verify(case_id)
                return 200, {**verification.payload(), "valid": verification.valid}
            if suffix == "/evidence/provenance":
                return 200, [
                    json.loads(row["provenance"])
                    for row in self.store.artifact(case_id, "evidence_receipts")
                ]
            return 200, [
                json.loads(row["entry"]) for row in self.store.artifact(case_id, "evidence_custody")
            ]
        if graph_route:
            guard.require(Permission.GRAPH, scope.kind, scope.id)
            self._evidence(guard, scope, raw=True)
            return 200, serve_graph(
                self.store,
                case_id,
                suffix.removeprefix("/knowledge-graph"),
                env.get("QUERY_STRING", ""),
            )
        if temporal_route:
            guard.require(Permission.CORRELATE, scope.kind, scope.id)
            if report.previous_investigation_id:
                guard.require(Permission.READ, scope.kind, report.previous_investigation_id)
            return 200, serve_temporal(self.store, case_id, suffix, env.get("QUERY_STRING", ""))
        if risk_route:
            guard.require(Permission.RISK, scope.kind, scope.id)
            self._evidence(guard, scope, raw=True)
            if report.previous_investigation_id:
                guard.require(Permission.READ, scope.kind, report.previous_investigation_id)
            return 200, serve_risk(
                self.store, case_id, suffix, env.get("QUERY_STRING", ""), scoped=True
            )
        result = report.payload()
        for action, field in (
            (Permission.GRAPH, "graph"),
            (Permission.CORRELATE, "correlation"),
            (Permission.EXPORT, "canonical_events"),
            (Permission.DETECTION_READ, "detection"),
        ):
            try:
                guard.require(action, scope.kind, scope.id)
            except AccessDenied:
                result.pop(field, None)
        if report.previous_investigation_id:
            try:
                guard.require(Permission.READ, scope.kind, report.previous_investigation_id)
            except AccessDenied:
                result.pop("previous_investigation_id", None)
        return 200, result

    def _evidence(self, guard: Enforcement, scope: Scope, *, raw: bool = False) -> None:
        guard.require(Permission.EVIDENCE, scope.kind, scope.id)
        for item in self.store.evidence_ids(scope.id, raw=raw):
            key = item if raw else f"normalized/{item}"
            guard.require(
                Permission.EVIDENCE, ScopeType.EVIDENCE, f"{scope.id}/{key}", parent=scope
            )

    def _hold(self, env, case: str, suffix: str):
        from riswan_platform.identity.principal import require_principal

        match = re.fullmatch(r"/legal-holds(?:/([a-f0-9-]{36})/release)?", suffix)
        if match is None:
            raise AccessDenied
        context = require_context()
        resource = Resource(
            context.tenant_id, "platform", Scope(ScopeType.ORGANIZATION, str(context.tenant_id))
        )
        auth = AuthorizationRequest(
            require_principal(),
            replace(context, product_id="platform"),
            Permission.LEGAL_HOLD,
            resource,
        )
        if not self.tenancy.evaluator.evaluate(auth).allowed:
            raise AccessDenied
        reason = HoldReason.model_validate(Application.body(env)).reason
        release = UUID(match[1]) if match[1] else None
        return (200 if release else 201), self.store.change_legal_hold(
            case, reason, release=release
        ).model_dump(mode="json")
