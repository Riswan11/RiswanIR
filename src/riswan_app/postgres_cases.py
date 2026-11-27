"""PostgreSQL-backed case bundle persistence for the hosted cutover preview."""

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from riswan_ir.core.fields import utc_timestamp
from riswan_ir.correlation.temporal.engine import run as correlate_temporal
from riswan_ir.correlation.temporal.registry import select_rules
from riswan_ir.investigation.ports import CaseReader
from riswan_ir.knowledge_graph.builder import build_security_graph
from riswan_ir.memory import repository as memory_repository
from riswan_ir.memory.ingestion import capture_review, promote
from riswan_ir.memory.intelligence import retrieve
from riswan_ir.memory.models import Feedback
from riswan_ir.memory.policy import allowed
from riswan_ir.memory.policy import policy as memory_policy
from riswan_ir.models import (
    AnalystFeedback,
    AnalystReview,
    EvidenceSubmission,
    InvestigationReport,
    InvestigationRequest,
    InvestigationSummary,
)
from riswan_ir.models.base import Text
from riswan_ir.risk.engine import calculate as calculate_risk
from riswan_ir.risk.models import Assessment, Reassessment
from riswan_ir.schema.projection import export_events
from riswan_ir.storage import evidence_store
from riswan_ir.storage.sqlite import Store
from riswan_platform.core.exceptions import NotFoundError
from riswan_platform.data_protection import LegalHold, Ownership, ProtectionDenied
from riswan_security_data.integrity import canonical_json, sha256
from riswan_security_data.provenance import EvidenceProvenance

from . import (
    postgres_events,
    postgres_graphs,
    postgres_intelligence,
    postgres_memory,
    postgres_security_data,
)
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
                "investigation_events",
                "case_graph_snapshots",
                "case_graph_nodes",
                "case_graph_edges",
                "case_temporal_snapshots",
                "case_risk_assessments",
                "case_memory_snapshots",
                "case_memory_history",
                *postgres_security_data.TABLES,
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
            inherited_bytes = [payloads[row["raw_id"]] for row in receipts]
            if (
                sum(len(value.encode()) for value in inherited_bytes)
                + len(submission.model_dump_json().encode())
                > 8_000_000
            ):
                raise ValueError("Revision exceeds the supported evidence size.")
            records = [json.loads(value) for value in inherited_bytes]
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
            index_audit = [
                list(row)
                for row in staging.execute("SELECT * FROM memory_audit WHERE case_id = ?", (case,))
            ]
        security_data = {name: captured.pop(name) for name in postgres_security_data.ARTIFACTS}
        graph = captured.pop("security_graphs")[0]["snapshot"]
        temporal = captured.pop("temporal_correlations")[0]["snapshot"]
        risk = captured.pop("risk_assessments")
        memory = {name: captured.pop(name) for name in postgres_intelligence.MEMORY_ARTIFACTS}
        bundle = {
            **captured,
            "security_data_digest": postgres_security_data.digest(security_data),
            "graph_digest": sha256(graph),
            "graph_relational": True,
            "temporal_digest": sha256(temporal),
            "risk_digest": postgres_intelligence.risk_digest(risk),
            "initial_risk_count": len(risk),
            "memory_digest": sha256(canonical_json(memory)),
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
                report.model_dump_json(by_alias=True, exclude_unset=True),
                json.dumps(bundle),
                parent.id if parent else None,
            ),
        )
        postgres_events.append(db, context, case, report.canonical_events or [])
        postgres_security_data.append(db, context, report, security_data)
        postgres_graphs.append(db, context, case, graph)
        postgres_intelligence.append(db, context, case, temporal, risk)
        postgres_intelligence.save_memory(db, context, case, memory)
        for entry in index_audit:
            postgres_memory.insert_entry(db, context, case, "audit", entry, entry[3])
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
        report = InvestigationReport.model_validate_json(json.dumps(row[0]))
        artifacts = row[1]
        if "security_data_digest" in artifacts:
            artifacts.update(
                postgres_security_data.read(db, case, artifacts["security_data_digest"])
            )
        if "graph_digest" in artifacts:
            snapshot = postgres_graphs.read(db, case, artifacts["graph_digest"])
            artifacts["security_graphs"] = [{"investigation_id": case, "snapshot": snapshot}]
        if "temporal_digest" in artifacts:
            snapshot = postgres_intelligence.temporal_snapshot(
                db, case, artifacts["temporal_digest"]
            )
            artifacts["temporal_correlations"] = [{"investigation_id": case, "snapshot": snapshot}]
        if "risk_digest" in artifacts:
            artifacts["risk_assessments"] = postgres_intelligence.risk_rows(
                db, case, artifacts["risk_digest"], artifacts.get("initial_risk_count")
            )
        if "memory_digest" in artifacts:
            artifacts.update(
                postgres_intelligence.read_memory(db, case, artifacts["memory_digest"])
            )
        return report, artifacts

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

    def security_graph(self, investigation_id: str):
        with self._scope.transaction() as (db, _):
            _, artifacts = self._bundle(db, investigation_id)
            snapshot = artifacts["security_graphs"][0]["snapshot"]
            if artifacts.get("graph_relational"):
                return postgres_graphs.graph_from_rows(db, investigation_id, snapshot)
            return postgres_graphs.validate(investigation_id, snapshot)

    def temporal_result(self, case_id: str):
        rows = self.artifact(case_id, "temporal_correlations")
        return postgres_intelligence.parse_temporal(case_id, rows[0]["snapshot"]).result

    def replay_temporal(self, case_id: str, versions: dict[str, str] | None = None):
        with self._scope.transaction() as (db, _):
            report, artifacts = self._bundle(db, case_id)
            snapshot = postgres_intelligence.parse_temporal(
                case_id, artifacts["temporal_correlations"][0]["snapshot"]
            )
            with self._compiler.connect() as staging:
                self._compiler.seed_transient_parent(staging, report)
                self._restore(staging, artifacts)
                if not evidence_store.verify(staging, case_id, report).valid:
                    raise ValueError("Temporal replay requires verified investigation evidence.")
                received = self._compiler._received_times(staging, case_id)
            graph = build_security_graph(report)
            baseline = correlate_temporal(
                report,
                graph,
                select_rules(
                    snapshot.rules, {item.id: item.version for item in snapshot.result.rules}
                ),
                snapshot.policy,
                received,
                snapshot.result.lineage_id,
            )
            if baseline != snapshot.result:
                raise ValueError("Archived temporal correlation cannot be reproduced.")
            if versions is None:
                return baseline
            return correlate_temporal(
                report,
                graph,
                select_rules(snapshot.rules, versions),
                snapshot.policy,
                received,
                snapshot.result.lineage_id,
            )

    def risk_page(
        self,
        case_id: str,
        limit: int,
        offset: int,
        subject: tuple[str, str] | None,
        *,
        scoped: bool = False,
    ) -> list[Assessment]:
        archives = postgres_intelligence.parse_risk(
            case_id, self.artifact(case_id, "risk_assessments")
        )
        assessments = [item.assessment for item in reversed(archives)]
        if subject:
            assessments = [
                item for item in assessments if (item.subject_kind, item.subject_id) == subject
            ]
        else:
            latest: dict[tuple[str, str], Assessment] = {}
            for item in assessments:
                latest.setdefault((item.subject_kind, item.subject_id), item)
            assessments = list(latest.values())
        return assessments[offset : offset + limit]

    def risk_parent(self, case: str) -> str | None:
        with self._scope.transaction() as (db, _):
            row = db.execute(
                "SELECT parent_id FROM riswan_data.investigations WHERE investigation_id = %s",
                (case,),
            ).fetchone()
            if row is None:
                raise NotFoundError("Investigation not found.")
            return row[0]

    def reassess(self, case: str, request: Reassessment, *, parent: str | None) -> Assessment:
        with self._scope.transaction() as (db, context):
            self._lock_case(db, case)
            owner = db.execute(
                "SELECT parent_id FROM riswan_data.investigations WHERE investigation_id = %s",
                (case,),
            ).fetchone()
            if owner is None or owner[0] != parent:
                raise NotFoundError("Reassessment unavailable for this case.")
            report, artifacts = self._bundle(db, case)
            if "risk_digest" not in artifacts or report.previous_investigation_id != parent:
                raise NotFoundError("Reassessment unavailable for this case.")
            old_ids = {row["id"] for row in artifacts["risk_assessments"]}
            with self._compiler.connect() as staging:
                self._compiler.seed_transient_parent(staging, report)
                self._restore(staging, artifacts)
                if not evidence_store.verify(staging, case, report).valid:
                    raise ValueError("Risk reassessment requires verified investigation evidence.")
                self._stage_parent_risk(db, staging, parent)
                postgres_memory.restore_history(db, staging, case, for_write=True)
                assessed = self._compiler._score_existing_risk(
                    staging, case, datetime.now(UTC).isoformat(), "reassessment", request
                )
                if assessed is None:
                    raise NotFoundError("Risk subject not found.")
                added = [
                    dict(row)
                    for row in staging.execute(ARTIFACT_QUERIES["risk_assessments"])
                    if row["investigation_id"] == case and row["id"] not in old_ids
                ]
            postgres_intelligence.append_risk(db, context, case, added)
            return assessed

    def _stage_parent_risk(self, db, staging, parent):
        if parent is None:
            return
        report, artifacts = self._bundle(db, parent)
        self._compiler.seed_transient_parent(staging, report)
        archives = artifacts["risk_assessments"]
        postgres_intelligence.parse_risk(parent, archives)
        staging.executemany(
            ARTIFACT_INSERTS["risk_assessments"],
            [
                (None, row["id"], parent, row["kind"], row["subject_id"], row["archive"])
                for row in archives
            ],
        )

    def risk_assessment(
        self, case_id: str, assessment_id: str, *, replay: bool, scoped: bool = False
    ) -> Assessment:
        entries = postgres_intelligence.parse_risk(
            case_id, self.artifact(case_id, "risk_assessments")
        )
        by_id = {item.assessment.id: item for item in entries}
        archive = by_id.get(assessment_id)
        if archive is None:
            raise NotFoundError("Risk assessment not found.")
        stored = archive.assessment
        if not replay:
            return stored
        origin = by_id.get(stored.original_assessment_id)
        if origin is None:
            # The hosted route authorizes each linked case and its evidence before dispatch.
            parent = self.risk_parent(case_id)
            seen = {case_id}
            while origin is None and parent is not None:
                if parent in seen or len(seen) >= 100:
                    raise NotFoundError("Original assessment unavailable for this case.")
                seen.add(parent)
                origin = next(
                    (
                        item
                        for item in postgres_intelligence.parse_risk(
                            parent, self.artifact(parent, "risk_assessments")
                        )
                        if item.assessment.id == stored.original_assessment_id
                    ),
                    None,
                )
                parent = self.risk_parent(parent)
        if origin is None:
            raise NotFoundError("Original assessment unavailable for this case.")
        reproduced = calculate_risk(
            case_id,
            archive.inputs,
            archive.policy,
            stored.created_at,
            stored.trigger,
            original=origin.assessment if origin is not archive else None,
            predecessor_id=stored.previous_assessment_id,
        ).assessment
        if reproduced != stored:
            raise ValueError("Archived assessment could not be reproduced.")
        return reproduced

    def events(self, case: str) -> dict[str, object]:
        with self._scope.transaction() as (db, _):
            report, _ = self._bundle(db, case)
            stored = postgres_events.read(db, case)
            if stored or self._native_security_data(db, case):
                if stored != (report.canonical_events or []):
                    raise NotFoundError("Canonical event archive unavailable.")
                report = report.model_copy(update={"canonical_events": stored})
            return export_events(report)

    @staticmethod
    def _native_security_data(db, case: str) -> bool:
        return bool(
            db.execute(
                """SELECT artifacts ? 'security_data_digest' FROM riswan_data.investigations
               WHERE investigation_id = %s""",
                (case,),
            ).fetchone()[0]
        )

    def findings(self, case: str):
        with self._scope.transaction() as (db, _):
            report, _ = self._bundle(db, case)
            if self._native_security_data(db, case):
                return postgres_security_data.findings(db, report)
            return postgres_security_data.expected_findings(report)

    def verify(self, case: str):
        with self._scope.transaction() as (db, _):
            report, artifacts = self._bundle(db, case)
            with self._compiler.connect() as staging:
                self._compiler.seed_transient_parent(staging, report)
                self._restore(staging, artifacts)
                return evidence_store.verify(staging, case, report)

    def timeline(self, case: str, query):
        with self._scope.transaction() as (db, context):
            report, _ = self._bundle(db, case)
            selected = postgres_events.timeline(db, context, case, query)
            reference = {item.id: item for item in report.canonical_events or []}
            if any(reference.get(item.id) != item for item in selected):
                raise NotFoundError("Canonical event archive unavailable.")
            count = query.limit
            archived = report.model_copy(update={"canonical_events": selected[:count]})
            result = export_events(archived)
            if not selected and report.canonical_events:
                result["schema_version"] = report.canonical_events[0].metadata.schema_version
            result["next_offset"] = query.offset + count if len(selected) > count else None
            return result

    def evidence_ids(self, case: str, *, raw: bool = False) -> tuple[str, ...]:
        with self._scope.transaction() as (db, _):
            row = db.execute(
                """SELECT report->'evidence', artifacts->'evidence_receipts',
                          artifacts ? 'security_data_digest'
                FROM riswan_data.investigations WHERE investigation_id = %s""",
                (case,),
            ).fetchone()
            if row is None:
                raise NotFoundError("Investigation not found.")
            if not raw:
                return tuple(item["id"] for item in row[0] or ())
            if not row[2]:
                return tuple(f"raw/{item['raw_id']}" for item in row[1])
            return tuple(
                f"raw/{entry[0]}"
                for entry in db.execute(
                    "SELECT raw_id FROM riswan_data.case_evidence_receipts WHERE investigation_id = %s",
                    (case,),
                )
            )

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

    def reviews(self, case: str) -> list[AnalystReview]:
        with self._scope.transaction() as (db, _):
            return [
                AnalystReview(reviewer=actor, disposition=entry[3], notes=entry[4], created_at=when)
                for actor, when, entry in db.execute(
                    """SELECT actor_id, recorded_at, entry FROM riswan_data.case_memory_history
                    WHERE investigation_id = %s AND kind = 'review' ORDER BY ordinal""",
                    (case,),
                )
            ]

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

    @staticmethod
    def _stage_memory(staging, case, archive):
        for table in postgres_intelligence.MEMORY_ARTIFACTS:
            columns = tuple(
                item[0] for item in staging.execute(ARTIFACT_QUERIES[table]).description
            )
            staging.executemany(
                ARTIFACT_INSERTS[table],
                [tuple(row[key] for key in columns) for row in archive[table]],
            )

    def memory_intelligence(self, case, as_of=None, *, case_ids):
        with self._scope.transaction() as (db, context), self._compiler.connect() as staging:
            self._lock_case(db, case)
            timestamp = datetime.now(UTC).isoformat()
            cutoff = utc_timestamp(as_of or timestamp)
            archive = postgres_memory.snapshot(db, case)
            self._seed_memory_profile(staging, case, archive, timestamp)
            live = memory_policy()
            config = memory_repository.archived_policy(staging, case)
            profile = memory_repository.read(staging, case, live, timestamp)
            if config is None or profile is None:
                raise NotFoundError("Indexed historical profile not found.")
            ids = postgres_memory.candidates(
                db,
                context,
                case_ids,
                allowed(profile.scope, live) & allowed(profile.scope, config),
                cutoff.isoformat(),
                (cutoff - timedelta(days=config.observation_days)).isoformat(),
                timestamp,
            )
            for candidate in ids:
                if candidate != case:
                    previous = postgres_memory.snapshot(db, candidate)
                    self._seed_memory_profile(staging, candidate, previous, timestamp)
                    postgres_memory.restore_history(
                        db,
                        staging,
                        candidate,
                        cutoff=memory_repository.time_key(cutoff.isoformat()),
                    )
            result = retrieve(
                staging,
                profile,
                config,
                cutoff.isoformat(),
                timestamp,
                authorization=live,
                case_ids=ids,
            )
            postgres_memory.append_history(db, context, staging, case, {"audit": 0})
            return result

    @staticmethod
    def _seed_memory_profile(staging, case, archive, timestamp):
        # The evaluator only needs the indexed records. Never copy candidate raw evidence.
        staging.execute("INSERT INTO main.investigations VALUES (?, ?, '{}')", (case, timestamp))
        PostgresCases._stage_memory(staging, case, archive)

    def memory_feedback(
        self, case: str, feedback: Feedback | AnalystFeedback, *, parent: str | None = None
    ) -> None:
        with self._scope.transaction() as (db, context), self._compiler.connect() as staging:
            self._lock_case(db, case)
            if not isinstance(feedback, AnalystFeedback):
                postgres_memory.snapshot(db, case)
            removed = (
                db.execute(
                    "SELECT 1 FROM riswan_data.investigation_memory_removals WHERE investigation_id = %s",
                    (case,),
                ).fetchone()
                is not None
            )
            report, artifacts = self._bundle(db, case)
            self._compiler.seed_transient_parent(staging, report)
            self._restore(staging, artifacts)
            postgres_memory.restore_history(db, staging, case, for_write=True)
            before = {
                kind: max((row[0] for row in staging.execute(query)), default=0)
                for kind, (query, _) in postgres_memory.HISTORY_QUERIES.items()
            }
            config = memory_policy()
            current = datetime.now(UTC).isoformat()
            if isinstance(feedback, AnalystFeedback):
                if report.previous_investigation_id != parent:
                    raise NotFoundError("Review lineage unavailable.")
                self._stage_parent_risk(db, staging, parent)
                previous = {row["id"] for row in artifacts["risk_assessments"]}
                staging.execute(
                    """INSERT INTO main.reviews(investigation_id, reviewer, disposition, notes, created_at)
                    VALUES (?, ?, ?, ?, ?)""",
                    (case, context.actor_id, feedback.disposition, feedback.notes, current),
                )
                verification = evidence_store.verify(staging, case, report)
                if (
                    not removed
                    and verification.valid
                    and verification.custody_checked
                    and not verification.expired_raw
                ):
                    capture_review(staging, case, feedback.disposition, config, current)
                self._compiler._score_existing_risk(staging, case, current, "analyst_review")
                postgres_intelligence.append_risk(
                    db,
                    context,
                    case,
                    [
                        dict(row)
                        for row in staging.execute(ARTIFACT_QUERIES["risk_assessments"])
                        if row["investigation_id"] == case and row["id"] not in previous
                    ],
                )
            else:
                promote(staging, report, feedback, config, current)
            postgres_memory.append_history(db, context, staging, case, before)

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
