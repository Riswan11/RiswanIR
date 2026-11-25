"""Persist investigations, analyst feedback, and action decisions in SQLite."""

import json
import logging
import os
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import TypeAdapter, ValidationError

from riswan_platform.core.context import require_context
from riswan_platform.core.exceptions import ContextRequiredError
from riswan_platform.data_protection import LegalHold, Ownership
from riswan_security_data.provenance import EvidenceProvenance

from ..core.config import setting
from ..core.errors import NotFoundError
from ..core.fields import now, utc_timestamp
from ..correlation.aws import arn_account, partition
from ..correlation.temporal import repository as temporal_repository
from ..correlation.temporal.engine import run as correlate_temporal
from ..correlation.temporal.models import TemporalPolicy, TemporalResult, TemporalSnapshot
from ..correlation.temporal.registry import default_rules, read_rules, select_rules
from ..detection.engine import evaluate
from ..detection.registry import RuleRegistry, default_registry
from ..evidence.redaction import redact_record
from ..investigation.analysis import analyze
from ..knowledge_graph.builder import build_security_graph
from ..knowledge_graph.models import SecurityGraph
from ..knowledge_graph.ontology import Entity
from ..knowledge_graph.repository import SCHEMA as GRAPH_SCHEMA
from ..knowledge_graph.repository import SQLiteGraphRepository
from ..memory import repository as memory_repository
from ..memory.features import scope as memory_scope
from ..memory.ingestion import capture_review, promote
from ..memory.ingestion import index as index_memory
from ..memory.intelligence import retrieve as retrieve_memory
from ..memory.models import Feedback as MemoryFeedback
from ..memory.models import Intelligence, MemoryPolicy
from ..memory.policy import allowed as allowed_accounts
from ..memory.policy import policy as memory_policy
from ..memory.similarity import similar_investigations
from ..models import (
    ActionDecision,
    AnalystFeedback,
    AnalystReview,
    Disposition,
    EvidenceSubmission,
    InvestigationReport,
    InvestigationRequest,
    InvestigationSummary,
)
from ..models.chain_of_custody import EvidenceIntegrity, EvidenceRetentionPolicy
from ..models.detection import DetectionContext, DetectionReplayResult, DetectionRule
from ..normalization.aws.ocsf_mapper import map_event
from ..risk import repository as risk_repository
from ..risk.engine import calculate as calculate_risk
from ..risk.models import Assessment, Reassessment, Trigger
from ..risk.reassessment import score_case
from . import checkpoint_store, evidence_store, legal_holds
from .review_store import latest_disposition

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, report TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS investigation_ownership (
    investigation_id TEXT PRIMARY KEY REFERENCES investigations(id),
    tenant_id TEXT NOT NULL,
    creator_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS investigation_ownership_tenant
ON investigation_ownership(tenant_id, investigation_id);
CREATE TABLE IF NOT EXISTS detection_configuration (
    investigation_id TEXT PRIMARY KEY REFERENCES investigations(id),
    context TEXT NOT NULL, rules TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY, investigation_id TEXT NOT NULL REFERENCES investigations(id),
    reviewer TEXT NOT NULL, disposition TEXT NOT NULL, notes TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
    investigation_id TEXT PRIMARY KEY REFERENCES investigations(id),
    reviewer TEXT NOT NULL, decision TEXT NOT NULL, created_at TEXT NOT NULL
);
"""


def deserialize_report(payload: str) -> InvestigationReport:
    try:
        return InvestigationReport.model_validate_json(payload)
    except ValidationError as exc:
        raise RuntimeError("Invalid stored investigation report.") from exc


RULE_LIST = TypeAdapter(list[DetectionRule])
LOGGER = logging.getLogger(__name__)


class Store:
    def __init__(
        self,
        path,
        *,
        detection_context: DetectionContext | None = None,
        detection_registry: RuleRegistry | None = None,
        hosted: bool = False,
    ):
        self.path = path
        self.hosted = hosted
        policy = setting("DETECTION_CONTEXT")
        registry = setting("DETECTION_RULES")
        if detection_context is None and policy:
            with Path(policy).open("rb") as source:
                data = source.read(1_000_001)
            if len(data) > 1_000_000:
                raise ValueError("Detection context file is too large.")
            detection_context = DetectionContext.model_validate_json(data)
        self.detection_context = detection_context or DetectionContext()
        self.detection_registry = detection_registry or (
            RuleRegistry.from_file(Path(registry)) if registry else default_registry()
        )
        # Existing databases keep their operating-system permissions.
        if os.name == "posix":
            try:
                os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            except FileExistsError:
                pass
        with self.connect() as db:
            db.executescript(
                SCHEMA
                + evidence_store.EVIDENCE_SCHEMA
                + checkpoint_store.SCHEMA
                + GRAPH_SCHEMA
                + temporal_repository.SCHEMA
                + risk_repository.SCHEMA
                + memory_repository.SCHEMA
                + legal_holds.SCHEMA
            )
            db.execute("BEGIN IMMEDIATE")
            evidence_store.split_owned_payloads(db)

    @contextmanager
    def connect(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            yield db

    def _tenant(self) -> UUID:
        context = require_context()
        if context.product_id != "ir":
            raise ContextRequiredError("Invalid product scope.")
        return context.tenant_id

    def _require_case(self, db: sqlite3.Connection, case_id: str) -> None:
        expected = str(self._tenant()) if self.hosted else None
        row = db.execute(
            "SELECT tenant_id FROM investigation_ownership WHERE investigation_id = ?",
            (case_id,),
        ).fetchone()
        if (row[0] if row else None) != expected:
            raise NotFoundError("Investigation not found.")

    def _related(
        self, db: sqlite3.Connection, ids: tuple[str, ...] | None
    ) -> tuple[str, ...] | None:
        if not self.hosted:
            if ids is None:
                return None
            return tuple(
                row[0]
                for row in db.execute(
                    """SELECT i.id FROM investigations i LEFT JOIN investigation_ownership o
                ON o.investigation_id = i.id
                WHERE o.tenant_id IS NULL AND i.id IN (SELECT value FROM json_each(?))""",
                    (json.dumps(ids),),
                )
            )
        return tuple(
            row[0]
            for row in db.execute(
                """SELECT investigation_id FROM investigation_ownership
                WHERE tenant_id = ? AND investigation_id IN (SELECT value FROM json_each(?))""",
                (str(self._tenant()), json.dumps(ids or ())),
            )
        )

    def create(self, request: InvestigationRequest) -> InvestigationReport:
        with self.connect() as db:
            case_id = self.create_in_transaction(db, request)
        return self.get(case_id, related_ids=() if self.hosted else None)

    def create_in_transaction(
        self,
        db: sqlite3.Connection,
        request: InvestigationRequest,
        *,
        previous: str | None = None,
        inherited: tuple[EvidenceProvenance, ...] = (),
    ) -> str:
        if self.hosted:
            self._tenant()
            if previous:
                self._require_case(db, previous)
        request = request.model_copy(
            update={"records": [redact_record(record) for record in request.records]}
        )
        case_id, timestamp = uuid4().hex, now()
        db.execute("INSERT INTO investigations VALUES (?, ?, ?)", (case_id, timestamp, "{}"))
        if self.hosted:
            context = require_context()
            db.execute(
                "INSERT INTO investigation_ownership VALUES (?, ?, ?)",
                (case_id, str(context.tenant_id), str(UUID(context.actor_id))),
            )
        origins = evidence_store.ingest(db, case_id, request, timestamp, inherited)
        rules = self.detection_registry.select()
        result = analyze(request, rules=rules, context=self.detection_context)
        db.execute(
            "INSERT INTO detection_configuration VALUES (?, ?, ?)",
            (
                case_id,
                self.detection_context.model_dump_json(),
                RULE_LIST.dump_json(rules).decode(),
            ),
        )
        evidence_store.record_transformations(db, case_id, request, timestamp, result, origins)
        report = InvestigationReport(id=case_id, created_at=timestamp, **dict(result))
        if previous:
            report.previous_investigation_id = previous
            evidence_store.append_custody(
                db, case_id, "revised", timestamp, {"previous_investigation_id": previous}
            )
        db.execute(
            "UPDATE investigations SET report = ? WHERE id = ?",
            (report.model_dump_json(by_alias=True, exclude_unset=True), case_id),
        )
        graph = build_security_graph(report)
        SQLiteGraphRepository(db).save(graph)
        prior = temporal_repository.load(db, previous) if previous else None
        lineage = prior.result.lineage_id if prior else previous or case_id
        rules_path = setting("TEMPORAL_RULES")
        temporal_rules = read_rules(Path(rules_path)) if rules_path else default_rules()
        policy_path = setting("TEMPORAL_POLICY")
        policy = TemporalPolicy(enrichment=self.detection_context)
        if policy_path:
            with Path(policy_path).open("rb") as source:
                data = source.read(1_000_001)
            if len(data) > 1_000_000:
                raise ValueError("Temporal policy file is too large.")
            policy = TemporalPolicy.model_validate_json(data)
            if "enrichment" not in policy.model_fields_set:
                policy.enrichment = self.detection_context
        result_ = correlate_temporal(
            report,
            graph,
            select_rules(temporal_rules),
            policy,
            self._received_times(db, case_id),
            lineage,
        )
        LOGGER.info("Temporal correlation metrics %s", result_.metrics.model_dump_json())
        temporal_repository.save(
            db, TemporalSnapshot(result=result_, rules=temporal_rules, policy=policy)
        )
        config = memory_policy()
        profile = index_memory(
            db, report, graph, result_, self.detection_context, config, timestamp
        )
        historical = (
            None
            if self.hosted
            else retrieve_memory(db, profile, config, timestamp, timestamp, log=False)
        )
        score_case(
            db,
            report,
            graph,
            result_,
            self.detection_context,
            timestamp,
            "revision" if previous else "initial",
            historical=historical,
        )
        return case_id

    @staticmethod
    def _stored_case(db: sqlite3.Connection, case_id: str) -> InvestigationReport:
        row = db.execute("SELECT report FROM investigations WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise NotFoundError("Investigation not found.")
        return deserialize_report(row["report"])

    def _index_memory_case(
        self,
        db: sqlite3.Connection,
        case_id: str,
        config: MemoryPolicy,
        timestamp: str,
    ) -> bool:
        report = self._stored_case(db, case_id)
        snapshot = temporal_repository.load(db, case_id)
        index_memory(
            db,
            report,
            build_security_graph(report),
            snapshot.result if snapshot else None,
            self.detection_context,
            config,
            timestamp,
        )
        return memory_repository.read(db, case_id, config, timestamp) is not None

    def memory_index(self, case_id: str) -> bool:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_case(db, case_id)
            return self._index_memory_case(db, case_id, memory_policy(), now())

    def memory_intelligence(
        self, case_id: str, as_of: str | None = None, *, case_ids: tuple[str, ...] | None = None
    ) -> Intelligence:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_case(db, case_id)
            self._stored_case(db, case_id)
            timestamp = now()
            live = memory_policy()
            config = memory_repository.archived_policy(db, case_id)
            profile = memory_repository.read(db, case_id, live, timestamp)
            if profile is None or config is None:
                raise NotFoundError("Indexed historical profile not found.")
            return retrieve_memory(
                db,
                profile,
                config,
                as_of or timestamp,
                timestamp,
                authorization=live,
                case_ids=self._related(db, case_ids),
            )

    def memory_feedback(self, case_id: str, feedback: MemoryFeedback) -> None:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_case(db, case_id)
            promote(db, self._stored_case(db, case_id), feedback, memory_policy(), now())

    def change_legal_hold(
        self, case_id: str, reason: str, *, release: UUID | None = None
    ) -> LegalHold:
        if not self.hosted:
            raise ContextRequiredError("Legal holds require hosted ownership.")
        tenant = self._tenant()
        context = require_context()
        identifier = release or uuid4()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_case(db, case_id)
            row = legal_holds.change(
                db,
                case_id,
                str(identifier),
                context.actor_id,
                now(),
                reason,
                context.request_id,
                release=release is not None,
            )
            if row is None:
                raise NotFoundError("Legal hold unavailable.")
            return LegalHold(
                id=identifier,
                owner=Ownership(tenant_id=tenant, product_id=context.product_id),
                investigation_id=case_id,
                created_at=utc_timestamp(row[0]),
                released_at=utc_timestamp(row[1]) if row[1] else None,
            )

    def memory_remove(self, case_id: str) -> None:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_case(db, case_id)
            legal_holds.require_unheld(db, case_id)
            self._stored_case(db, case_id)
            memory_repository.remove(db, case_id, memory_policy(), now())

    def memory_expire(self) -> int:
        if self.hosted:
            raise ContextRequiredError("Hosted storage requires a scoped operation.")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            return memory_repository.expire(db, memory_policy(), now())

    def _score_existing_risk(
        self,
        db: sqlite3.Connection,
        case_id: str,
        timestamp: str,
        trigger: Trigger,
        request: Reassessment | None = None,
    ) -> Assessment | None:
        row = db.execute("SELECT report FROM investigations WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise NotFoundError("Investigation not found.")
        report = deserialize_report(row["report"])
        snapshot = temporal_repository.load(db, case_id)
        live = memory_policy()
        profile = memory_repository.read(db, case_id, live, timestamp)
        config = memory_repository.archived_policy(db, case_id)
        historical = (
            retrieve_memory(
                db,
                profile,
                config,
                timestamp,
                timestamp,
                log=False,
                authorization=live,
            )
            if profile and config and not self.hosted
            else None
        )
        return score_case(
            db,
            report,
            build_security_graph(report),
            snapshot.result if snapshot else None,
            self.detection_context,
            timestamp,
            trigger,
            disposition=latest_disposition(db, case_id),
            request=request,
            historical=historical,
        )

    def reassess_risk(self, case_id: str, request: Reassessment) -> Assessment:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_case(db, case_id)
            result = self._score_existing_risk(db, case_id, now(), "reassessment", request)
            if result is None:
                raise NotFoundError("Risk subject not found.")
            return result

    def risk_page(
        self,
        case_id: str,
        limit: int,
        offset: int,
        subject: tuple[str, str] | None,
        *,
        scoped: bool = False,
    ) -> list[Assessment]:
        with self.connect() as db:
            self._require_case(db, case_id)
            case = db.execute("SELECT 1 FROM investigations WHERE id = ?", (case_id,)).fetchone()
            if case is None:
                raise NotFoundError("Investigation not found.")
            page = risk_repository.scoped_page if scoped else risk_repository.page
            return [entry.assessment for entry in page(db, case_id, limit, offset, subject)]

    def risk_assessment(
        self, case_id: str, assessment_id: str, *, replay: bool = False, scoped: bool = False
    ) -> Assessment:
        with self.connect() as db:
            self._require_case(db, case_id)
            get = risk_repository.scoped_get if scoped else risk_repository.get
            archive = get(db, case_id, assessment_id)
            if archive is None:
                raise NotFoundError("Risk assessment not found.")
            item = archive.assessment
            if not replay:
                return item
            original = None
            if item.original_assessment_id != item.id:
                row = db.execute(
                    "SELECT investigation_id FROM risk_assessments WHERE id = ? AND kind = ? AND subject_id = ?",
                    (item.original_assessment_id, item.subject_kind, item.subject_id),
                ).fetchone()
                if row is not None:
                    self._require_case(db, row["investigation_id"])
                origin = (
                    risk_repository.get(db, row["investigation_id"], item.original_assessment_id)
                    if row
                    else None
                )
                if origin is None:
                    raise ValueError("Original assessment is unavailable.")
                original = origin.assessment
        reproduced = calculate_risk(
            case_id,
            archive.inputs,
            archive.policy,
            item.created_at,
            item.trigger,
            original=original,
            predecessor_id=item.previous_assessment_id,
        ).assessment
        if reproduced != item:
            raise ValueError("Archived assessment could not be reproduced.")
        return reproduced

    @staticmethod
    def _received_times(db: sqlite3.Connection, case_id: str) -> dict[str, str]:
        times: dict[str, str] = {}
        for origin in evidence_store.receipts(db, case_id):
            event_id = origin.source_event_id.strip()
            observed = utc_timestamp(origin.ingested_at).isoformat()
            times[event_id] = min(times.get(event_id, observed), observed)
        return times

    def temporal_result(self, case_id: str) -> TemporalResult:
        with self.connect() as db:
            self._require_case(db, case_id)
            snapshot = temporal_repository.load(db, case_id)
        return snapshot.result if snapshot else self.replay_temporal(case_id)

    def replay_temporal(
        self, case_id: str, versions: dict[str, str] | None = None
    ) -> TemporalResult:
        with self.connect() as db:
            db.execute("BEGIN")
            self._require_case(db, case_id)
            row = db.execute(
                "SELECT report FROM investigations WHERE id = ?", (case_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("Investigation not found.")
            report = deserialize_report(row["report"])
            if not evidence_store.verify(db, case_id, report).valid:
                raise ValueError("Temporal replay requires verified investigation evidence.")
            snapshot = temporal_repository.load(db, case_id)
            received = self._received_times(db, case_id)
        graph = build_security_graph(report)
        policy = snapshot.policy if snapshot else TemporalPolicy()
        catalog = snapshot.rules if snapshot else default_rules()
        lineage = snapshot.result.lineage_id if snapshot else case_id
        baseline_versions = (
            {item.id: item.version for item in snapshot.result.rules} if snapshot else None
        )
        baseline = correlate_temporal(
            report, graph, select_rules(catalog, baseline_versions), policy, received, lineage
        )
        if snapshot and baseline != snapshot.result:
            raise ValueError("Archived temporal correlation cannot be reproduced.")
        if versions is None:
            return baseline
        return correlate_temporal(
            report, graph, select_rules(catalog, versions), policy, received, lineage
        )

    def security_graph(self, investigation_id: str) -> SecurityGraph:
        with self.connect() as db:
            self._require_case(db, investigation_id)
            graph = SQLiteGraphRepository(db).get(investigation_id)
        return graph if graph is not None else build_security_graph(self.get(investigation_id))

    def replay_detection(
        self,
        case_id: str,
        *,
        versions: dict[str, str] | None = None,
        registry: RuleRegistry | None = None,
    ) -> DetectionReplayResult:
        with self.connect() as db:
            db.execute("BEGIN")
            self._require_case(db, case_id)
            row = db.execute(
                "SELECT report FROM investigations WHERE id = ?", (case_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("Investigation not found.")
            report = deserialize_report(row["report"])
            if not evidence_store.verify(db, case_id, report).valid:
                raise ValueError("Detection replay requires verified investigation evidence.")
            archived = db.execute(
                "SELECT context, rules FROM detection_configuration WHERE investigation_id = ?",
                (case_id,),
            ).fetchone()
        if archived:
            context = DetectionContext.model_validate_json(archived["context"])
            rules = RULE_LIST.validate_json(archived["rules"])
        elif report.detection:
            raise ValueError("Archived detection configuration is missing.")
        else:
            context, rules = DetectionContext(), self.detection_registry.select()
        events = report.canonical_events
        if events is None:
            events = [
                map_event(item, evidence=item.reference, parent=item.linked_from_evidence_id)
                for item in report.evidence
            ]
        if report.detection:
            baseline = evaluate(events, rules, context).result
            if (
                baseline.execution.configuration_digest
                != report.detection.execution.configuration_digest
            ):
                raise ValueError("Archived detection configuration failed integrity verification.")
            if versions is None and registry is None:
                if baseline != report.detection:
                    raise ValueError("Archived detection cannot be reproduced with this engine.")
                return baseline
        if registry is not None:
            rules = registry.select(versions)
        elif versions is not None:
            archive = RuleRegistry(rules)
            historical = {
                key: version for key, version in versions.items() if archive.contains(key, version)
            }
            current = {key: version for key, version in versions.items() if key not in historical}
            rules = archive.select(historical) + self.detection_registry.select(current)
        return evaluate(events, rules, context).result

    def revise(self, case_id: str, supplement: EvidenceSubmission) -> InvestigationReport:
        if not supplement.records:
            raise ValueError("A revision requires supplemental records.")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_case(db, case_id)
            row = db.execute(
                "SELECT report FROM investigations WHERE id = ?", (case_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("Investigation not found.")
            previous = deserialize_report(row["report"])
            status = evidence_store.verify(db, case_id, previous)
            if not status.valid or status.expired_raw:
                raise ValueError("A revision requires intact original raw evidence and custody.")
            records = evidence_store.original_records(db, case_id)
            origins = tuple(evidence_store.receipts(db, case_id))
            request = InvestigationRequest(
                title=previous.title,
                principal=previous.principal,
                records=[*records, *supplement.records],
                provenance=supplement.provenance,
            )
            revised = self.create_in_transaction(db, request, previous=case_id, inherited=origins)
        return self.get(revised, related_ids=() if self.hosted else None)

    def verify_evidence(self, case_id: str) -> EvidenceIntegrity:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_case(db, case_id)
            return self._verify_evidence(db, case_id)

    def _verify_evidence(self, db: sqlite3.Connection, case_id: str) -> EvidenceIntegrity:
        row = db.execute("SELECT report FROM investigations WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise NotFoundError("Investigation not found.")
        try:
            report = InvestigationReport.model_validate_json(row["report"])
            result = evidence_store.verify(db, case_id, report)
        except (ValueError, TypeError):
            return EvidenceIntegrity(
                raw_checked=0,
                normalized_checked=0,
                expired_raw=0,
                custody_checked=0,
                problems=["Stored evidence or custody metadata is invalid."],
            )
        if result.custody_checked:
            evidence_store.append_custody(db, case_id, "verified", now(), {"valid": result.valid})
        return result

    def export_evidence(self, case_id: str) -> dict[str, object]:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._require_case(db, case_id)
            verification = self._verify_evidence(db, case_id)
            if verification.valid:
                evidence_store.append_custody(
                    db, case_id, "export_prepared", now(), {"format": "json-v1"}
                )
                report = db.execute(
                    "SELECT report FROM investigations WHERE id = ?", (case_id,)
                ).fetchone()
                return {
                    "format": "sentinelforge-evidence-v1",
                    "report": deserialize_report(report["report"]).payload(),
                    "raw_evidence": [
                        item.payload() for item in evidence_store.raw_records(db, case_id)
                    ],
                    "provenance": [
                        item.model_dump(mode="json")
                        for item in evidence_store.receipts(db, case_id)
                    ],
                    "transformations": [
                        item.payload() for item in evidence_store.transformations(db, case_id)
                    ],
                    "custody": [item.payload() for item in evidence_store.custody(db, case_id)],
                    "verification": verification.payload(),
                }
        raise ValueError("Export requires valid evidence custody and integrity.")

    def expire_evidence(
        self, policy: EvidenceRetentionPolicy, timestamp: datetime | None = None
    ) -> int:
        if self.hosted:
            raise ContextRequiredError("Hosted storage requires a scoped operation.")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            return evidence_store.expire(db, policy, timestamp or utc_timestamp(now()))

    def get(
        self, investigation_id: str, *, related_ids: tuple[str, ...] | None = None
    ) -> InvestigationReport:
        with self.connect() as db:
            self._require_case(db, investigation_id)
            row = db.execute(
                "SELECT report FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("Investigation not found.")
            report = deserialize_report(row["report"])
            report.reviews = [
                AnalystReview.model_validate(dict(item))
                for item in db.execute(
                    "SELECT reviewer, disposition, notes, created_at FROM reviews WHERE investigation_id = ? ORDER BY id",
                    (investigation_id,),
                )
            ]
            decision = db.execute(
                "SELECT reviewer, decision, created_at FROM decisions WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()
            report.decision = ActionDecision.model_validate(dict(decision)) if decision else None
            moment = memory_repository.time_key(now())
            related_ids = self._related(db, related_ids)
            authorized = json.dumps(related_ids) if related_ids is not None else None
            history = db.execute(
                """
                SELECT i.report, r.disposition FROM investigations i JOIN reviews r
                    ON r.id = (SELECT max(id) FROM reviews WHERE investigation_id = i.id)
                WHERE i.id <> ?
                AND (? IS NOT NULL OR NOT EXISTS
                     (SELECT 1 FROM investigation_ownership o WHERE o.investigation_id = i.id))
                AND (? IS NULL OR i.id IN (SELECT value FROM json_each(?)))
                AND NOT EXISTS (SELECT 1 FROM memory_tombstones t WHERE t.case_id = i.id)
                AND NOT EXISTS (
                    SELECT 1 FROM case_evidence_payloads e
                    WHERE e.investigation_id = i.id AND e.payload IS NULL
                )
                AND (
                    NOT EXISTS (SELECT 1 FROM memory_cases m WHERE m.case_id = i.id)
                    OR (
                        (SELECT COUNT(*) FROM memory_records m WHERE m.case_id = i.id
                         AND m.category IN ('episodic', 'semantic') AND m.expires_at > ?) = 2
                        AND EXISTS (SELECT 1 FROM memory_feedback f
                                    WHERE f.case_id = i.id AND f.expires_at > ?)
                    )
                )
                ORDER BY r.id DESC LIMIT 100
            """,
                (investigation_id, authorized, authorized, authorized, moment, moment),
            )
            config = memory_policy()
            current_scope = self._legacy_memory_scope(report)
            available = allowed_accounts(current_scope, config)
            required = {"episodic", "semantic", "feedback"}
            legacy_shared = required <= config.cross_account_categories
            report.similar_investigations = similar_investigations(
                report,
                (
                    (prior, Disposition(item["disposition"]))
                    for item in history
                    if available
                    and required <= config.enabled_categories
                    and (
                        prior_scope := self._legacy_memory_scope(
                            prior := deserialize_report(item["report"])
                        )
                    )
                    and set(prior_scope) <= available
                    and (prior_scope == current_scope or legacy_shared)
                ),
            )
        return report

    @staticmethod
    def _legacy_memory_scope(report: InvestigationReport) -> list[str]:
        accounts: set[str] = set()
        for event in report.evidence:
            key = arn_account(event.principal)
            partition_id = partition(event.principal, event.region)
            actor = memory_scope(key or event.account_id, partition_id)
            owner = memory_scope(
                event.recipient_account_id or event.account_id or key, partition_id
            )
            if not actor or not owner or (key and event.account_id and key != event.account_id):
                return []
            accounts.update((actor, owner))
        return sorted(accounts)

    def owned_investigations(self, tenant_id: UUID) -> dict[str, UUID]:
        if not self.hosted or self._tenant() != tenant_id:
            raise ContextRequiredError("Invalid hosted tenant scope.")
        with self.connect() as db:
            return {
                row[0]: UUID(row[1])
                for row in db.execute(
                    "SELECT investigation_id, creator_id FROM investigation_ownership WHERE tenant_id = ?",
                    (str(tenant_id),),
                )
            }

    def list_scoped(self, ids: tuple[str, ...]) -> list[InvestigationSummary]:
        with self.connect() as db:
            ids = self._related(db, ids) or ()
            rows = db.execute(
                "SELECT report FROM investigations WHERE id IN (SELECT value FROM json_each(?)) "
                "ORDER BY created_at DESC, id DESC LIMIT 50",
                (json.dumps(ids),),
            )
            return [InvestigationSummary.model_validate_json(row["report"]) for row in rows]

    def list(self) -> list[InvestigationSummary]:
        if self.hosted:
            raise ContextRequiredError("Hosted storage requires a scoped operation.")
        with self.connect() as db:
            return [
                InvestigationSummary.model_validate_json(row["report"])
                for row in db.execute(
                    """SELECT report FROM investigations
                    WHERE NOT EXISTS (SELECT 1 FROM investigation_ownership o WHERE o.investigation_id = investigations.id)
                    ORDER BY created_at DESC LIMIT 50"""
                )
            ]

    def evidence_ids(self, case_id: str, *, raw: bool = False) -> tuple[str, ...]:
        with self.connect() as db:
            self._require_case(db, case_id)
            if raw:
                return tuple(
                    f"raw/{row.evidence_id}" for row in evidence_store.receipts(db, case_id)
                )
            return tuple(item.id for item in self._stored_case(db, case_id).evidence)

    def get_summary(self, investigation_id: str) -> InvestigationSummary:
        with self.connect() as db:
            self._require_case(db, investigation_id)
            row = db.execute(
                "SELECT report FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("Route not found.")
        return InvestigationSummary.model_validate_json(row["report"])

    def feedback(self, investigation_id: str, feedback: AnalystFeedback) -> InvestigationReport:
        self.get_summary(investigation_id)
        review = AnalystReview(**dict(feedback), created_at=now())
        with self.connect() as db:
            self._require_case(db, investigation_id)
            db.execute(
                "INSERT INTO reviews (investigation_id, reviewer, disposition, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    investigation_id,
                    review.reviewer,
                    review.disposition,
                    review.notes,
                    review.created_at,
                ),
            )
            config = memory_policy()
            prior = memory_repository.read(db, investigation_id, config, review.created_at)
            if prior is None:
                self._index_memory_case(db, investigation_id, config, review.created_at)
            else:
                stored = self._stored_case(db, investigation_id)
                verification = evidence_store.verify(db, investigation_id, stored)
                if verification.valid and not verification.expired_raw:
                    capture_review(
                        db, investigation_id, review.disposition, config, review.created_at
                    )
            self._score_existing_risk(db, investigation_id, review.created_at, "analyst_review")
        return self.get(investigation_id, related_ids=() if self.hosted else None)

    def decide(
        self, investigation_id: str, action_id: str, decision: ActionDecision
    ) -> InvestigationReport:
        action = self.get(investigation_id, related_ids=()).action
        if action is None or action.id != action_id:
            raise NotFoundError("Action not found.")
        with self.connect() as db:
            self._require_case(db, investigation_id)
            result = db.execute(
                "INSERT INTO decisions VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                (investigation_id, decision.reviewer, decision.decision, decision.created_at),
            )
            if result.rowcount != 1:
                raise FileExistsError("This action already has a decision.")
            repository = SQLiteGraphRepository(db)
            graph = repository.get(investigation_id)
            if graph is not None:
                for node in graph.nodes:
                    if node.kind == Entity.ACTION and node.key == action_id:
                        node.metadata["status"] = decision.decision.value
                        node.metadata["decision_at"] = decision.created_at
                repository.save(graph)
        return self.get(investigation_id, related_ids=() if self.hosted else None)
