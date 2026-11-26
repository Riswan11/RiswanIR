"""PostgreSQL-backed case bundle persistence for the hosted cutover preview."""

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from riswan_ir.core.fields import utc_timestamp
from riswan_ir.investigation.ports import CaseReader
from riswan_ir.models import (
    EvidenceSubmission,
    InvestigationReport,
    InvestigationRequest,
    InvestigationSummary,
)
from riswan_ir.models.base import Text
from riswan_ir.storage import evidence_store
from riswan_ir.storage.sqlite import Store
from riswan_platform.core.exceptions import NotFoundError
from riswan_platform.data_protection import LegalHold, Ownership, ProtectionDenied
from riswan_security_data.provenance import EvidenceProvenance

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
ARTIFACT_INSERTS = {
    "raw_evidence": "INSERT INTO main.raw_evidence VALUES (?, ?)",
    "tenant_raw_evidence_payloads": "INSERT INTO main.tenant_raw_evidence_payloads VALUES (?, ?, ?)",
    "evidence_receipts": "INSERT INTO main.evidence_receipts VALUES (?, ?, ?, ?, ?)",
    "evidence_transformations": "INSERT INTO main.evidence_transformations VALUES (?, ?, ?, ?)",
    "evidence_custody": "INSERT INTO main.evidence_custody VALUES (?, ?, ?)",
    "detection_configuration": "INSERT INTO main.detection_configuration VALUES (?, ?, ?)",
    "security_graphs": "INSERT INTO main.security_graphs VALUES (?, ?)",
    "temporal_correlations": "INSERT INTO main.temporal_correlations VALUES (?, ?)",
    "risk_assessments": "INSERT INTO main.risk_assessments VALUES (?, ?, ?, ?, ?, ?)",
    "memory_cases": "INSERT INTO main.memory_cases VALUES (?, ?, ?, ?)",
    "memory_accounts": "INSERT INTO main.memory_accounts VALUES (?, ?)",
    "memory_records": "INSERT INTO main.memory_records VALUES (?, ?, ?, ?, ?)",
}


class CaseUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: Text


class PostgresCases(CaseReader):
    def __init__(self, pool: Any):
        self._scope = ScopedPostgres(
            pool,
            (
                "investigation_ownership",
                "investigations",
                "investigation_legal_holds",
                "investigation_hold_audit",
                "investigation_memory_removals",
            ),
        )
        self._directory = PostgresCaseOwnership(pool)
        self._compiler = Store(":memory:", hosted=True, transient=True)

    def owned_investigations(self, tenant_id: UUID) -> dict[str, UUID]:
        return self._directory.owned_investigations(tenant_id)

    def create(self, request: InvestigationRequest) -> InvestigationReport:
        with self._scope.transaction() as (db, context):
            return self._compile(db, context, request)

    def revise(self, parent_id: str, submission: EvidenceSubmission) -> InvestigationReport:
        with self._scope.transaction() as (db, context):
            parent, artifacts = self._bundle(db, parent_id)
            receipts = sorted(artifacts["evidence_receipts"], key=lambda row: row["ordinal"])
            payloads = {
                row["raw_id"]: row["payload"] for row in artifacts["tenant_raw_evidence_payloads"]
            }
            if not submission.records:
                raise ValueError("A revision requires supplemental evidence.")
            records = [json.loads(payloads[row["raw_id"]]) for row in receipts]
            request = InvestigationRequest(
                title=parent.title,
                principal=parent.principal,
                records=records + submission.records,
                provenance=submission.provenance,
            )
            origins = tuple(
                EvidenceProvenance.model_validate_json(row["provenance"]) for row in receipts
            )
            return self._compile(
                db, context, request, parent=parent, artifacts=artifacts, inherited=origins
            )

    def _compile(self, db, context, request, *, parent=None, artifacts=None, inherited=()):
        with self._compiler.connect() as staging:
            if parent is not None:
                self._compiler.seed_transient_parent(staging, parent)
                self._restore(staging, artifacts)
                if not evidence_store.verify(staging, parent.id, parent).valid:
                    raise ValueError("Parent evidence could not be verified.")
            case = self._compiler.create_in_transaction(
                staging, request, previous=parent.id if parent else None, inherited=inherited
            )
            report = self._compiler._stored_case(staging, case)
            if not evidence_store.verify(staging, case, report).valid:
                raise ValueError("New evidence could not be verified.")
            captured = {
                table: [
                    dict(row)
                    for row in staging.execute(query)
                    if ("investigation_id" not in row.keys() or row["investigation_id"] == case)
                    and ("case_id" not in row.keys() or row["case_id"] == case)
                ]
                for table, query in ARTIFACT_QUERIES.items()
            }
        self._directory.insert(db, context, case, utc_timestamp(report.created_at))
        db.execute(
            """INSERT INTO riswan_data.investigations
               (tenant_id, product_id, investigation_id, report, artifacts, parent_id)
               VALUES (%s, %s, %s, %s::jsonb, %s::jsonb, %s)""",
            (
                context.tenant_id,
                context.product_id,
                case,
                report.model_dump_json(by_alias=True),
                json.dumps(captured),
                parent.id if parent else None,
            ),
        )
        return report

    @staticmethod
    def _restore(staging, artifacts):
        for table, query in ARTIFACT_QUERIES.items():
            # Both identifiers and column order come from the static compiler schema, never JSON.
            columns = tuple(item[0] for item in staging.execute(query).description)
            staging.executemany(
                ARTIFACT_INSERTS[table],
                [tuple(row[key] for key in columns) for row in artifacts[table]],
            )

    @staticmethod
    def _bundle(db, case: str):
        row = db.execute(
            "SELECT report, artifacts FROM riswan_data.investigations WHERE investigation_id = %s",
            (case,),
        ).fetchone()
        if row is None:
            raise NotFoundError("Investigation not found.")
        return InvestigationReport.model_validate_json(json.dumps(row[0])), row[1]

    def artifact(self, case: str, name: str):
        with self._scope.transaction() as (db, _):
            _, artifacts = self._bundle(db, case)
            if (
                name.startswith("memory_")
                and db.execute(
                    "SELECT 1 FROM riswan_data.investigation_memory_removals WHERE investigation_id = %s",
                    (case,),
                ).fetchone()
            ):
                raise NotFoundError("Investigation memory unavailable.")
            return artifacts[name]

    def evidence_ids(self, case: str, *, raw: bool = False) -> tuple[str, ...]:
        with self._scope.transaction() as (db, _):
            report, bundle = self._bundle(db, case)
            if raw:
                return tuple(f"raw/{item['raw_id']}" for item in bundle["evidence_receipts"])
            return tuple(item.id for item in report.evidence)

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

    @staticmethod
    def _lock_case(db, case: str) -> None:
        # UPDATE privilege on report allows this row lock without mutating immutable artifacts.
        if (
            db.execute(
                "SELECT 1 FROM riswan_data.investigations WHERE investigation_id = %s FOR UPDATE",
                (case,),
            ).fetchone()
            is None
        ):
            raise NotFoundError("Investigation not found.")

    def change_legal_hold(
        self, case: str, reason: str, *, release: UUID | None = None
    ) -> LegalHold:
        with self._scope.transaction() as (db, context):
            self._lock_case(db, case)
            now = datetime.now(UTC)
            hold = release or uuid4()
            keys = (context.tenant_id, context.product_id, case, hold)
            if release is None:
                row = db.execute(
                    """INSERT INTO riswan_data.investigation_legal_holds
                       VALUES (%s, %s, %s, %s, %s, NULL) RETURNING created_at, released_at""",
                    (*keys, now),
                ).fetchone()
            else:
                row = db.execute(
                    """UPDATE riswan_data.investigation_legal_holds SET released_at = %s
                       WHERE investigation_id = %s AND id = %s AND released_at IS NULL
                       RETURNING created_at, released_at""",
                    (now, case, hold),
                ).fetchone()
            if row is None:
                raise NotFoundError("Legal hold unavailable.")
            db.execute(
                """INSERT INTO riswan_data.investigation_hold_audit
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    *keys,
                    "released" if release else "created",
                    UUID(context.actor_id),
                    now,
                    context.request_id,
                    reason,
                ),
            )
            return LegalHold(
                id=hold,
                owner=Ownership(tenant_id=context.tenant_id, product_id=context.product_id),
                investigation_id=case,
                created_at=row[0],
                released_at=row[1],
            )

    def memory_remove(self, case: str) -> None:
        with self._scope.transaction() as (db, context):
            self._lock_case(db, case)
            if db.execute(
                "SELECT 1 FROM riswan_data.investigation_legal_holds WHERE investigation_id = %s AND released_at IS NULL",
                (case,),
            ).fetchone():
                raise ProtectionDenied("Investigation is under legal hold.")
            db.execute(
                """INSERT INTO riswan_data.investigation_memory_removals VALUES (%s, %s, %s)
                   ON CONFLICT DO NOTHING""",
                (context.tenant_id, context.product_id, case),
            )
