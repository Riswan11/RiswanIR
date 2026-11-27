"""Authoritative PostgreSQL evidence and finding snapshots."""

import json

from riswan_platform.core.exceptions import NotFoundError
from riswan_security_data.integrity import canonical_json, sha256

TABLES = (
    "case_raw_evidence",
    "case_evidence_receipts",
    "case_evidence_transformations",
    "case_custody",
    "case_findings",
)
ARTIFACTS = (
    "raw_evidence",
    "tenant_raw_evidence_payloads",
    "evidence_receipts",
    "evidence_transformations",
    "evidence_custody",
)


def digest(evidence) -> str:
    return sha256(
        canonical_json({name: sorted(map(canonical_json, evidence[name])) for name in ARTIFACTS})
    )


def append(db, context, report, evidence) -> None:
    scope = (context.tenant_id, context.product_id, report.id)
    digests = {row["id"]: row["digest"] for row in evidence["raw_evidence"]}
    with db.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO riswan_data.case_raw_evidence VALUES (%s, %s, %s, %s, %s, %s)",
            [
                (*scope, row["raw_id"], digests[row["raw_id"]], row["payload"])
                for row in evidence["tenant_raw_evidence_payloads"]
            ],
        )
        cursor.executemany(
            "INSERT INTO riswan_data.case_evidence_receipts VALUES (%s, %s, %s, %s, %s, %s, %s)",
            [
                (*scope, row["ordinal"], row["raw_id"], row["ingested_at"], row["provenance"])
                for row in evidence["evidence_receipts"]
            ],
        )
        cursor.executemany(
            "INSERT INTO riswan_data.case_evidence_transformations VALUES (%s, %s, %s, %s, %s, %s)",
            [
                (*scope, row["event_id"], row["normalized_id"], row["metadata"])
                for row in evidence["evidence_transformations"]
            ],
        )
        cursor.executemany(
            "INSERT INTO riswan_data.case_custody VALUES (%s, %s, %s, %s, %s)",
            [(*scope, row["sequence"], row["entry"]) for row in evidence["evidence_custody"]],
        )
        for family, items in expected_findings(report).items():
            cursor.executemany(
                "INSERT INTO riswan_data.case_findings VALUES (%s, %s, %s, %s, %s, %s::jsonb)",
                [(*scope, family, index, json.dumps(item)) for index, item in enumerate(items)],
            )


def expected_findings(report):
    return {
        "assessment": [claim.payload() for claim in report.assessment.claims],
        "detection": [finding.payload() for finding in report.detection.findings]
        if report.detection
        else [],
    }


def findings(db, report):
    result: dict[str, list[dict[str, object]]] = {"assessment": [], "detection": []}
    for family, item in db.execute(
        """SELECT family, finding FROM riswan_data.case_findings
           WHERE investigation_id = %s ORDER BY family, ordinal""",
        (report.id,),
    ):
        result[family].append(item)
    if result != expected_findings(report):
        raise NotFoundError("Finding archive unavailable.")
    return result


def read(db, case: str, expected: str):
    raw = db.execute(
        "SELECT tenant_id, raw_id, digest, payload FROM riswan_data.case_raw_evidence WHERE investigation_id = %s",
        (case,),
    ).fetchall()
    output = {
        "raw_evidence": [{"id": raw_id, "digest": value} for _, raw_id, value, _ in raw],
        "tenant_raw_evidence_payloads": [
            {"tenant_id": str(tenant), "raw_id": raw_id, "payload": value}
            for tenant, raw_id, _, value in raw
        ],
        "evidence_receipts": [
            {
                "investigation_id": case,
                "ordinal": ordinal,
                "raw_id": raw_id,
                "ingested_at": ingested,
                "provenance": provenance,
            }
            for ordinal, raw_id, ingested, provenance in db.execute(
                """SELECT ordinal, raw_id, ingested_at, provenance FROM riswan_data.case_evidence_receipts
                   WHERE investigation_id = %s ORDER BY ordinal""",
                (case,),
            )
        ],
        "evidence_transformations": [
            {
                "investigation_id": case,
                "event_id": event,
                "normalized_id": normalized,
                "metadata": metadata,
            }
            for event, normalized, metadata in db.execute(
                """SELECT event_id, normalized_id, metadata FROM riswan_data.case_evidence_transformations
                   WHERE investigation_id = %s ORDER BY event_id""",
                (case,),
            )
        ],
        "evidence_custody": [
            {"investigation_id": case, "sequence": sequence, "entry": entry}
            for sequence, entry in db.execute(
                """SELECT sequence, entry FROM riswan_data.case_custody
                   WHERE investigation_id = %s ORDER BY sequence""",
                (case,),
            )
        ],
    }
    if digest(output) != expected:
        raise NotFoundError("Evidence archive unavailable.")
    return output
