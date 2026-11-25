"""Assemble the installed local application from explicit product and storage dependencies."""

from dataclasses import dataclass
from pathlib import Path

from riswan_ir.api.http import Application
from riswan_ir.investigation.ports import CaseReader
from riswan_ir.normalization.aws.ocsf_mapper import map_event
from riswan_ir.product import IRProduct
from riswan_ir.storage.sqlite import Store
from riswan_platform.core.context import PlatformContext, require_context
from riswan_platform.core.contracts import ProductModule
from riswan_platform.core.exceptions import ContextRequiredError
from riswan_platform.events import EventDispatcher
from riswan_security_data.canonical_event import SecurityEvent
from riswan_security_data.contracts import EvidenceReader

from .local import LOCAL_TENANT, local_context


class LocalEvidenceReader:
    def __init__(self, cases: CaseReader, product: ProductModule):
        self._cases = cases
        self._product = product

    def canonical_events(
        self, context: PlatformContext, investigation_id: str
    ) -> tuple[SecurityEvent, ...]:
        if require_context() != context or (context.tenant_id, context.product_id) != (
            LOCAL_TENANT,
            self._product.product_id,
        ):
            raise ContextRequiredError("Evidence scope does not match the local deployment.")
        report = self._cases.get(investigation_id)
        if report.canonical_events is not None:
            return tuple(report.canonical_events)
        return tuple(
            map_event(item, evidence=item.reference, parent=item.linked_from_evidence_id)
            for item in report.evidence
        )


@dataclass(frozen=True, slots=True)
class LocalRuntime:
    product: ProductModule
    http: Application
    evidence: EvidenceReader


def open_local_job_store(path: Path | str) -> Store:
    context = require_context()
    if (context.tenant_id, context.product_id, context.actor_type) != (
        LOCAL_TENANT,
        IRProduct().product_id,
        "service",
    ):
        raise ContextRequiredError("A trusted workstation service context is required.")
    return Store(path)


def compose_local(
    path: Path | str,
    mode: str | None,
    *,
    dispatcher: EventDispatcher | None = None,
) -> LocalRuntime:
    product = IRProduct()
    local_context(mode, product.product_id)  # Fail before opening or creating the database.
    store = Store(path)
    return LocalRuntime(
        product=product,
        http=Application(
            store,
            context_provider=lambda: local_context(mode, product.product_id),
            tenant_id=LOCAL_TENANT,
            product=product,
            dispatcher=dispatcher or EventDispatcher(),
        ),
        evidence=LocalEvidenceReader(store, product),
    )
