"""Product ownership directory and authenticated route composition."""

from uuid import UUID

from riswan_ir.api.http import Application
from riswan_ir.product import IRProduct
from riswan_ir.storage.sqlite import Store
from riswan_platform.authorization import Resource, Scope, ScopeType
from riswan_platform.authorization.enforcement import AccessDenied, Enforcement
from riswan_platform.core.context import bind_context
from riswan_platform.identity.models import VerifiedPrincipal

from .tenancy import Tenancy


class IRResources:
    def __init__(self, store: Store, tenant_id: UUID):
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
                resources = IRResources(self.store, tenant_id)
                guard = Enforcement(
                    self.tenancy.evaluator, resources, self.tenancy.authorization.transaction
                )
                app = Application(
                    self.store, product=IRProduct(), tenant_id=tenant_id, enforcement=guard
                )
                return app.route(env)
