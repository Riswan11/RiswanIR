"""PostgreSQL-backed case bundle persistence for the hosted cutover preview."""

import json
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from riswan_ir.core.fields import utc_timestamp
from riswan_ir.investigation.ports import CaseReader
from riswan_ir.models import InvestigationReport, InvestigationRequest, InvestigationSummary
from riswan_ir.models.base import Text
from riswan_ir.storage import evidence_store
from riswan_ir.storage.sqlite import Store
from riswan_platform.core.exceptions import NotFoundError

from .postgres_case_ownership import PostgresCaseOwnership
from .postgres_scope import ScopedPostgres

ARTIFACT_QUERIES = {
    "raw_evidence": "SELECT * FROM raw_evidence",
    "tenant_raw_evidence_payloads": "SELECT * FROM tenant_raw_evidence_payloads",
    "evidence_receipts": "SELECT * FROM evidence_receipts",
    "evidence_transformations": "SELECT * FROM evidence_transformations",
    "evidence_custody": "SELECT * FROM evidence_custody",
    "detection_configuration": "SELECT * FROM detection_configuration",
    "security_graphs": "SELECT * FROM security_graphs",
    "temporal_correlations": "SELECT * FROM temporal_correlations",
    "risk_assessments": "SELECT * FROM risk_assessments",
    "memory_cases": "SELECT * FROM memory_cases",
    "memory_accounts": "SELECT * FROM memory_accounts",
    "memory_records": "SELECT * FROM memory_records",
}


class CaseUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: Text


class PostgresCases(CaseReader):
    def __init__(self, pool: Any):
        self._scope = ScopedPostgres(pool, ("investigation_ownership", "investigations"))
        self._directory = PostgresCaseOwnership(pool)
        self._compiler = Store(":memory:", hosted=True, transient=True)

    def owned_investigations(self, tenant_id: UUID) -> dict[str, UUID]:
        return self._directory.owned_investigations(tenant_id)

    def create(self, request: InvestigationRequest) -> InvestigationReport:
        with self._scope.transaction() as (db, context):
            # The workspace is one case, one connection, RAM-only. Nothing is committed on disk
            # outside the PostgreSQL transaction. Reuse the existing analysis and custody pipeline.
            with self._compiler.connect() as staging:
                case = self._compiler.create_in_transaction(staging, request)
                report = self._compiler._stored_case(staging, case)
                verification = evidence_store.verify(staging, case, report)
                if not verification.valid:
                    raise ValueError("New evidence could not be verified.")
                artifacts = {
                    table: [dict(row) for row in staging.execute(query)]
                    for table, query in ARTIFACT_QUERIES.items()
                }
            self._directory.insert(db, context, case, utc_timestamp(report.created_at))
            db.execute(
                """INSERT INTO riswan_data.investigations
                   (tenant_id, product_id, investigation_id, report, artifacts)
                   VALUES (%s, %s, %s, %s::jsonb, %s::jsonb)""",
                (
                    context.tenant_id,
                    context.product_id,
                    case,
                    report.model_dump_json(by_alias=True),
                    json.dumps(artifacts),
                ),
            )
            return report

    def get(
        self, investigation_id: str, *, related_ids: tuple[str, ...] | None = None
    ) -> InvestigationReport:
        with self._scope.transaction() as (db, _):
            row = db.execute(
                "SELECT report FROM riswan_data.investigations WHERE investigation_id = %s",
                (investigation_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("Investigation not found.")
            return InvestigationReport.model_validate_json(json.dumps(row[0]))

    def list_scoped(self, ids: tuple[str, ...]) -> list[InvestigationSummary]:
        with self._scope.transaction() as (db, _):
            rows = db.execute(
                """SELECT i.report FROM riswan_data.investigations i
                   JOIN riswan_data.investigation_ownership o
                   USING (tenant_id, product_id, investigation_id)
                   WHERE i.investigation_id = ANY(%s)
                   ORDER BY o.created_at DESC, o.investigation_id DESC LIMIT 50""",
                (list(ids),),
            )
            return [InvestigationSummary.model_validate(row[0]) for row in rows]

    def update(self, case: str, request: CaseUpdate) -> InvestigationSummary:
        with self._scope.transaction() as (db, _):
            row = db.execute(
                """UPDATE riswan_data.investigations
                   SET report = jsonb_set(report, '{title}', to_jsonb(%s::text))
                   WHERE investigation_id = %s RETURNING report""",
                (request.title, case),
            ).fetchone()
            if row is None:
                raise NotFoundError("Investigation not found.")
            return InvestigationSummary.model_validate(row[0])
