"""Product ownership directory and authenticated route composition."""

import re
from dataclasses import replace
from uuid import UUID

from riswan_ir.api.http import Application
from riswan_ir.models import InvestigationRequest, InvestigationSummary
from riswan_ir.product import IRProduct
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
        if isinstance(self.store, PostgresCases):
            return None
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
        if kind == ScopeType.RESPONSE:
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
        match = re.fullmatch(r"/v1/investigations/([a-f0-9]{32})", path)
        if match is None or method not in {"GET", "PATCH"}:
            return 501, {"error": "Operation unavailable in the PostgreSQL case preview."}
        case_id = match[1]
        guard.require(Permission.READ, ScopeType.INVESTIGATION, case_id)
        if method == "PATCH":
            guard.require(Permission.UPDATE, ScopeType.INVESTIGATION, case_id)
            return 200, self.store.update(
                case_id, CaseUpdate.model_validate(Application.body(env))
            ).payload()
        report = self.store.get(case_id)
        return 200, InvestigationSummary(
            id=report.id, title=report.title, created_at=report.created_at
        ).payload()
