"""SQLite evidence repository. Callers own the transaction and local authorization."""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import NAMESPACE_URL, uuid5

from ..core.fields import mapping, text_field
from ..evidence.integrity import attach_reference, canonical_json, sha256
from ..models import InvestigationReport, InvestigationRequest, InvestigationResult
from ..models.canonical_event import SecurityEvent
from ..models.chain_of_custody import (
    ChainOfCustodyEntry,
    EvidenceIntegrity,
    EvidenceRetentionPolicy,
)
from ..models.evidence import RawEvidence
from ..models.provenance import EvidenceProvenance, EvidenceReference, EvidenceTransformation

NORMALIZATION_VERSION = "cloudtrail-2"
SCHEMA_VERSION = "1"

# Additive, idempotent migration. Case overlays and legacy report JSON remain intact.
EVIDENCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_evidence (
    id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS raw_evidence_payloads (
    raw_id TEXT PRIMARY KEY REFERENCES raw_evidence(id), payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_receipts (
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    ordinal INTEGER NOT NULL, raw_id TEXT NOT NULL REFERENCES raw_evidence(id),
    ingested_at TEXT NOT NULL, provenance TEXT NOT NULL,
    PRIMARY KEY (investigation_id, ordinal)
);
CREATE INDEX IF NOT EXISTS evidence_receipts_raw ON evidence_receipts(raw_id, ingested_at);
CREATE TABLE IF NOT EXISTS evidence_transformations (
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    event_id TEXT NOT NULL, normalized_id TEXT NOT NULL UNIQUE,
    metadata TEXT NOT NULL, PRIMARY KEY (investigation_id, event_id)
);
CREATE TABLE IF NOT EXISTS evidence_custody (
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    sequence INTEGER NOT NULL, entry TEXT NOT NULL, PRIMARY KEY (investigation_id, sequence)
);
"""


def ingest(
    db: sqlite3.Connection,
    case_id: str,
    request: InvestigationRequest,
    timestamp: str,
    inherited: tuple[EvidenceProvenance, ...] = (),
) -> dict[str, EvidenceProvenance]:
    by_event: dict[str, EvidenceProvenance] = {}
    receipts = []
    for index, record in enumerate(request.records):
        try:
            payload = canonical_json(record)
        except (ValueError, RecursionError) as exc:
            raise ValueError("CloudTrail records must contain valid JSON values.") from exc
        digest = sha256(payload)
        raw_id = "raw_" + digest.removeprefix("sha256:")
        event_id = record.get("eventID")
        event_id = event_id if isinstance(event_id, str) else ""
        origin = EvidenceProvenance(
            **dict(request.provenance),
            evidence_id=raw_id,
            source_event_id=event_id,
            source_account_id=request.provenance.collection_account_id
            or text_field(record, "recipientAccountId")
            or text_field(record, "recipientAccountID")
            or text_field(mapping(record, "userIdentity"), "accountId"),
            source_region=request.provenance.collection_region or text_field(record, "awsRegion"),
            observed_at=text_field(record, "eventTime"),
            ingested_at=timestamp,
            raw_integrity_hash=digest,
        )
        if index < len(inherited):
            origin = inherited[index].model_copy(
                update={"evidence_id": raw_id, "raw_integrity_hash": digest}
            )
        db.execute("INSERT OR IGNORE INTO raw_evidence VALUES (?, ?)", (raw_id, digest))
        db.execute("INSERT OR IGNORE INTO raw_evidence_payloads VALUES (?, ?)", (raw_id, payload))
        stored = db.execute(
            """SELECT r.digest, p.payload FROM raw_evidence r JOIN raw_evidence_payloads p
               ON p.raw_id = r.id WHERE r.id = ?""",
            (raw_id,),
        ).fetchone()
        if stored["digest"] != digest or stored["payload"] != payload:
            raise RuntimeError("Stored raw evidence does not match its address.")
        db.execute(
            "INSERT INTO evidence_receipts VALUES (?, ?, ?, ?, ?)",
            (case_id, index, raw_id, origin.ingested_at, origin.model_dump_json()),
        )
        receipts.append(origin.model_dump(mode="json"))
        by_event[event_id.strip()] = origin
    append_custody(
        db, case_id, "ingested", timestamp, {"receipts_digest": sha256(canonical_json(receipts))}
    )
    return by_event


def record_transformations(
    db: sqlite3.Connection,
    case_id: str,
    request: InvestigationRequest,
    timestamp: str,
    result: InvestigationResult,
    origins: dict[str, EvidenceProvenance],
) -> None:
    results = []
    transformations = []
    for item in result.evidence:
        origin = origins[item.id]
        reference = EvidenceReference(
            evidence_id=uuid5(NAMESPACE_URL, f"sentinelforge:{case_id}:{item.id}").hex,
            parent_evidence_id=origin.evidence_id,
            source_event_id=item.id,
        )
        linked = attach_reference(item, reference)
        transformation = EvidenceTransformation(
            **dict(reference),
            raw_integrity_hash=origin.raw_integrity_hash,
            normalized_integrity_hash=linked.integrity_hash,
            normalization_version=NORMALIZATION_VERSION,
            schema_version=SCHEMA_VERSION,
            configuration={
                "principal": request.principal,
                "encoding": "canonical-json-v1",
                "redaction": "credential-fields-v1",
            },
        )
        db.execute(
            "INSERT INTO evidence_transformations VALUES (?, ?, ?, ?)",
            (case_id, item.id, reference.evidence_id, transformation.model_dump_json()),
        )
        transformations.append(transformation.model_dump(mode="json"))
        results.append(linked)
    transformations.sort(key=lambda entry: entry["source_event_id"])
    result.evidence = results
    if result.canonical_events is not None:
        references = {item.id: item.reference for item in results}
        result.canonical_events = [
            event.model_copy(update={"evidence": references[event.id]})
            for event in result.canonical_events
        ]
    append_custody(
        db,
        case_id,
        "normalized",
        timestamp,
        {
            "transformations_digest": sha256(canonical_json(transformations)),
            "correlation_digest": sha256(canonical_json(result.correlation.payload()))
            if result.correlation
            else None,
            "canonical_digest": canonical_digest(result.canonical_events),
            "detection_digest": sha256(canonical_json(result.detection.payload()))
            if result.detection
            else None,
        },
    )


def canonical_digest(events: list[SecurityEvent] | None) -> str | None:
    return (
        sha256(canonical_json([event.payload() for event in events]))
        if events is not None
        else None
    )


def custody(db: sqlite3.Connection, case_id: str) -> list[ChainOfCustodyEntry]:
    return [
        ChainOfCustodyEntry.model_validate_json(row["entry"])
        for row in db.execute(
            "SELECT entry FROM evidence_custody WHERE investigation_id = ? ORDER BY sequence",
            (case_id,),
        )
    ]


def append_custody(
    db: sqlite3.Connection, case_id: str, action: str, timestamp: str, details: dict[str, object]
) -> None:
    previous = db.execute(
        "SELECT entry FROM evidence_custody WHERE investigation_id = ? ORDER BY sequence DESC LIMIT 1",
        (case_id,),
    ).fetchone()
    last = ChainOfCustodyEntry.model_validate_json(previous["entry"]) if previous else None
    fields = {
        "investigation_id": case_id,
        "sequence": last.sequence + 1 if last else 1,
        "action": action,
        "actor": "local_application" if action in ("ingested", "normalized") else "local_operator",
        "recorded_at": timestamp,
        "previous_hash": last.integrity_hash if last else None,
        "details": details,
    }
    entry = ChainOfCustodyEntry.model_validate(
        {**fields, "integrity_hash": sha256(canonical_json(fields))}
    )
    db.execute(
        "INSERT INTO evidence_custody VALUES (?, ?, ?)",
        (case_id, entry.sequence, entry.model_dump_json()),
    )


def receipts(db: sqlite3.Connection, case_id: str) -> list[EvidenceProvenance]:
    return [
        EvidenceProvenance.model_validate_json(row["provenance"])
        for row in db.execute(
            "SELECT provenance FROM evidence_receipts WHERE investigation_id = ? ORDER BY ordinal",
            (case_id,),
        )
    ]


def transformations(db: sqlite3.Connection, case_id: str) -> list[EvidenceTransformation]:
    return [
        EvidenceTransformation.model_validate_json(row["metadata"])
        for row in db.execute(
            "SELECT metadata FROM evidence_transformations WHERE investigation_id = ? ORDER BY event_id",
            (case_id,),
        )
    ]


def raw_rows(db: sqlite3.Connection, case_id: str) -> list[sqlite3.Row]:
    return db.execute(
        """SELECT DISTINCT r.id, r.digest, p.payload FROM evidence_receipts x
           JOIN raw_evidence r ON r.id = x.raw_id LEFT JOIN raw_evidence_payloads p ON p.raw_id = r.id
           WHERE x.investigation_id = ? ORDER BY r.id""",
        (case_id,),
    ).fetchall()


def raw_records(db: sqlite3.Connection, case_id: str) -> list[RawEvidence]:
    return [
        RawEvidence(
            evidence_id=row["id"],
            integrity_hash=row["digest"],
            record=json.loads(row["payload"]) if row["payload"] is not None else None,
        )
        for row in raw_rows(db, case_id)
    ]


def original_records(db: sqlite3.Connection, case_id: str) -> list[dict[str, object]]:
    rows = db.execute(
        """SELECT p.payload FROM evidence_receipts r LEFT JOIN raw_evidence_payloads p
           ON p.raw_id = r.raw_id WHERE r.investigation_id = ? ORDER BY r.ordinal""",
        (case_id,),
    )
    return [json.loads(row["payload"]) for row in rows]


def verify(
    db: sqlite3.Connection,
    case_id: str,
    report: InvestigationReport,
) -> EvidenceIntegrity:
    evidence, correlation = report.evidence, report.correlation
    problems = []
    history = custody(db, case_id)
    origins = receipts(db, case_id)
    versions = transformations(db, case_id)
    previous = None
    expired = set()
    for index, entry in enumerate(history, 1):
        fields = entry.payload()
        fields.pop("integrity_hash")
        if (
            entry.sequence != index
            or entry.previous_hash != previous
            or entry.investigation_id != case_id
            or sha256(canonical_json(fields)) != entry.integrity_hash
        ):
            problems.append(f"Custody verification failed at entry {index}.")
        previous = entry.integrity_hash
        if entry.action == "raw_expired":
            identifier = entry.details.get("raw_id")
            if isinstance(identifier, str):
                expired.add(identifier)
    if len(history) < 2 or [item.action for item in history[:2]] != ["ingested", "normalized"]:
        problems.append("Evidence custody anchors unavailable.")
    else:
        expected = sha256(canonical_json(correlation.payload())) if correlation else None
        if history[1].details.get("correlation_digest") != expected:
            problems.append("Correlation snapshot verification failed.")
        if history[1].details.get("canonical_digest") != canonical_digest(report.canonical_events):
            problems.append("Canonical event snapshot verification failed.")
        detection = sha256(canonical_json(report.detection.payload())) if report.detection else None
        if history[1].details.get("detection_digest") != detection:
            problems.append("Detection snapshot verification failed.")
        for anchor, name, items in (
            (history[0], "receipts_digest", origins),
            (history[1], "transformations_digest", versions),
        ):
            digest = sha256(canonical_json([item.payload() for item in items]))
            if anchor.details.get(name) != digest:
                problems.append(f"Evidence metadata verification failed for {name}.")
    seen_raw = set()
    raw_checked = 0
    expired_count = 0
    for row in raw_rows(db, case_id):
        seen_raw.add((row["id"], row["digest"]))
        if row["payload"] is None:
            if row["id"] in expired:
                expired_count += 1
            else:
                problems.append("A raw payload is missing without a retention entry.")
        else:
            raw_checked += 1
            if sha256(row["payload"]) != row["digest"]:
                problems.append("Raw evidence digest mismatch.")
    if any((origin.evidence_id, origin.raw_integrity_hash) not in seen_raw for origin in origins):
        problems.append("A raw receipt does not match its stored evidence.")
    by_event = {version.source_event_id: version for version in versions}
    for item in evidence:
        fields = item.payload()
        normalized_digest = fields.pop("integrity_hash")
        version = by_event.pop(item.id, None)
        if (
            version is None
            or item.reference is None
            or version.evidence_id != item.reference.evidence_id
            or item.reference.source_event_id != item.id
            or version.parent_evidence_id != item.reference.parent_evidence_id
            or (version.parent_evidence_id, version.raw_integrity_hash) not in seen_raw
            or version.normalized_integrity_hash != normalized_digest
            or sha256(canonical_json(fields)) != normalized_digest
        ):
            problems.append("Normalized evidence verification failed.")
    if by_event:
        problems.append("Normalized evidence referenced by a transformation is missing.")
    return EvidenceIntegrity(
        raw_checked=raw_checked,
        normalized_checked=len(evidence),
        expired_raw=expired_count,
        custody_checked=len(history),
        problems=problems,
    )


def expire(db: sqlite3.Connection, policy: EvidenceRetentionPolicy, now: datetime) -> int:
    cutoff = (now - timedelta(days=policy.days)).astimezone(timezone.utc).isoformat()
    candidates = db.execute(
        """SELECT p.raw_id FROM raw_evidence_payloads p JOIN evidence_receipts r ON r.raw_id = p.raw_id
           GROUP BY p.raw_id HAVING max(julianday(r.ingested_at)) <= julianday(?) ORDER BY p.raw_id""",
        (cutoff,),
    ).fetchall()
    for candidate in candidates:
        raw_id = candidate["raw_id"]
        cases = db.execute(
            "SELECT DISTINCT investigation_id FROM evidence_receipts WHERE raw_id = ?", (raw_id,)
        )
        for case in cases:
            append_custody(
                db,
                case["investigation_id"],
                "raw_expired",
                now.isoformat(),
                {"raw_id": raw_id, "retention_days": policy.days},
            )
        db.execute("DELETE FROM raw_evidence_payloads WHERE raw_id = ?", (raw_id,))
    return len(candidates)
