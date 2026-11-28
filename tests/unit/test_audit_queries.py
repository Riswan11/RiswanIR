"""Ensure invalid audit filters and workstation paths fail before database access."""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from riswan_app.postgres_audit import (
    CredentialAuditQuery,
    TenantAuditQuery,
    credential_timeline,
    tenant_timeline,
)
from riswan_platform.authorization.enforcement import AccessDenied


@pytest.mark.parametrize(
    "query",
    ["resource=" + "x" * 1024, "start=2026-02-01T00:00:00Z&end=2026-01-01T00:00:00Z"],
)
def test_tenant_audit_rejects_oversized_or_inverted_filters(query):
    with pytest.raises(ValueError):
        TenantAuditQuery.parse(query)


@pytest.mark.parametrize(
    "query",
    [
        CredentialAuditQuery(limit=101),
        CredentialAuditQuery(start=datetime(2026, 1, 1)),
        CredentialAuditQuery(
            start=datetime(2026, 2, 1, tzinfo=UTC), end=datetime(2026, 1, 1, tzinfo=UTC)
        ),
    ],
)
def test_credential_audit_rejects_invalid_filters_before_database_access(query):
    service = SimpleNamespace(repository=SimpleNamespace(initializes_sqlite_schema=False))
    with pytest.raises(ValueError):
        credential_timeline(service, uuid4(), query)


def test_postgres_audit_services_reject_workstation_storage():
    repository = SimpleNamespace(initializes_sqlite_schema=True)
    with pytest.raises(AccessDenied):
        credential_timeline(SimpleNamespace(repository=repository), uuid4(), CredentialAuditQuery())
    with pytest.raises(AccessDenied):
        tenant_timeline(
            SimpleNamespace(authorization=repository), None, uuid4(), "audit", TenantAuditQuery()
        )
