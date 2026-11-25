from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from riswan_app.local import local_context
from riswan_platform.core.context import bind_context
from riswan_platform.core.exceptions import ContextRequiredError
from riswan_platform.events import DomainEvent, EventDispatcher
from riswan_security_data.contracts import SecurityFinding
from riswan_security_data.provenance import EvidenceReference

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_event_validity_idempotency_and_scope(caplog):
    context = local_context("local", "ir")
    retained = []

    def failing(event):
        raise RuntimeError("internal detail")

    dispatcher = EventDispatcher({"ir.investigation.created": (failing, retained.append)})
    item = DomainEvent.from_context(context, "ir.investigation.created", NOW, "case-001")
    assert item.payload == {"investigation_id": "case-001"}
    assert DomainEvent.model_validate_json(item.model_dump_json()) == item
    for key, value in (
        ("schema_version", "2.0"),
        ("source", "foreign"),
        ("occurred_at", NOW.replace(tzinfo=None)),
    ):
        with pytest.raises(ValueError):
            DomainEvent.model_validate({**item.model_dump(), key: value})
    with pytest.raises(ContextRequiredError):
        dispatcher.publish(item)
    for foreign in (replace(context, tenant_id=uuid4()), replace(context, correlation_id="other")):
        with bind_context(foreign), pytest.raises(ContextRequiredError):
            dispatcher.publish(item)
    with bind_context(context):
        assert dispatcher.publish(item) == 1
        assert dispatcher.publish(item) == 0
    assert retained == [item]
    assert "handler failed" in caplog.text and "internal detail" not in caplog.text


def test_cross_product_finding_has_version_scope_and_evidence():
    context = local_context("local", "ir")
    reference = EvidenceReference(
        evidence_id="normalized-1", parent_evidence_id="raw-1", source_event_id="event-1"
    )
    data = dict(
        id="finding-1",
        tenant_id=context.tenant_id,
        product_id="cloud",
        title="Unexpected policy",
        evidence=[reference],
    )
    finding = SecurityFinding.model_validate(data)
    assert finding.schema_version == "1.0" and finding.evidence == (reference,)
    for change in (
        {"evidence": []},
        {"evidence": [reference, reference]},
        {"tenant_id": "00000000-0000-0000-0000-000000000000"},
    ):
        with pytest.raises(ValueError):
            SecurityFinding.model_validate({**data, **change})
