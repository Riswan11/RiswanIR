import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from src.sentinelforge.investigation.analysis import analyze
from src.sentinelforge.models import (
    ActionDecision, AnalystFeedback, Evidence, GraphEdge, InvestigationReport, InvestigationRequest, RiskAssessment,
)
from src.sentinelforge.storage.sqlite import Store


WHEN = "2025-01-01T00:00:00+00:00"
PRINCIPAL = "arn:aws:iam::123456789012:user/test"
EVENT = {"eventID": "key-created", "eventTime": WHEN, "eventName": "CreateAccessKey",
         "userIdentity": {"arn": PRINCIPAL}}


def request(records):
    return InvestigationRequest(title="Review activity", principal=PRINCIPAL, records=records)


class ModelTests(unittest.TestCase):
    def test_request_formats_and_constraints(self):
        for records in ([EVENT], {"Records": [EVENT]}, {"Events": [{"CloudTrailEvent": json.dumps(EVENT)}]}):
            self.assertEqual(request(records).records, [EVENT])
        for records in (None, [None], [EVENT] * 2001, {"Events": [{"CloudTrailEvent": "{"}]}):
            with self.subTest(kind=type(records)), self.assertRaises(ValidationError):
                request(records)
        with self.assertRaises(ValidationError):
            InvestigationRequest(title=" ", principal=PRINCIPAL, records=[])

    def test_invalid_domain_values(self):
        evidence = analyze(request([EVENT])).evidence[0].payload()
        with self.assertRaises(ValidationError):
            Evidence.model_validate({**evidence, "integrity_hash": "invalid"})
        with self.assertRaises(ValidationError):
            Evidence.model_validate({**evidence, "observed_at": "2025-01-01"})
        with self.assertRaises(ValidationError):
            RiskAssessment(severity="low", score=71, score_max=70, claims=[], open_questions=[], observed_targets=[])
        with self.assertRaises(ValidationError):
            RiskAssessment(severity="unknown", score=0, score_max=70, claims=[], open_questions=[], observed_targets=[])
        with self.assertRaises(ValidationError):
            AnalystFeedback(reviewer="Analyst", disposition="unknown")
        with self.assertRaises(ValidationError):
            ActionDecision(reviewer="Analyst", decision="unknown", created_at=WHEN)
        with self.assertRaises(ValidationError):
            GraphEdge(source=PRINCIPAL, relationship="INVALID", target=EVENT["eventID"])

    def test_references_and_json_round_trip(self):
        result = analyze(request([EVENT]))
        model = InvestigationReport(id="case", created_at=WHEN, **dict(result))
        serialized = model.model_dump_json(by_alias=True, exclude_unset=True)
        payload = json.loads(serialized)
        self.assertEqual(InvestigationReport.model_validate_json(serialized), model)
        self.assertEqual(payload["graph"][0], {"from": PRINCIPAL, "relationship": "CALLED", "to": "key-created"})
        evidence = payload["evidence"][0].copy()
        expected_hash = evidence.pop("integrity_hash")
        canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
        self.assertEqual(expected_hash, "sha256:" + hashlib.sha256(canonical.encode()).hexdigest())
        for ref in (payload["assessment"]["claims"][0], payload["action"]):
            original = ref["evidence_ids"]
            ref["evidence_ids"] = ["different-event"]
            with self.assertRaises(ValidationError):
                InvestigationReport.model_validate(payload)
            ref["evidence_ids"] = original
        payload["evidence"].append(payload["evidence"][0])
        with self.assertRaises(ValidationError):
            InvestigationReport.model_validate(payload)

    def test_reads_legacy_sqlite_payload_without_adding_fields(self):
        legacy = {
            "id": "legacy", "created_at": WHEN, "title": "Legacy investigation", "principal": PRINCIPAL,
            "plan": [], "graph": [], "action": None,
            "evidence": [{"id": "old", "source": "aws.cloudtrail", "observed_at": WHEN, "event": "AssumeRole",
                          "principal": PRINCIPAL, "target": None, "query": "Exact principal ARN match",
                          "integrity_hash": "sha256:" + "a" * 64}],
            "assessment": {"severity": "low", "score": 20, "score_max": 70, "observed_targets": [],
                           "open_questions": [], "claims": [{"summary": "Role assumption observed",
                                                             "evidence_ids": ["old"], "possible_attack_technique": "T1078"}]},
        }
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "test.sqlite3")
            with store.connect() as db:
                db.execute("INSERT INTO investigations VALUES (?, ?, ?)", ("legacy", WHEN, json.dumps(legacy)))
                db.execute("INSERT INTO reviews VALUES (?, ?, ?, ?, ?, ?)",
                           (1, "legacy", "Analyst", "benign", "", WHEN))
            payload = store.get("legacy").payload()
            self.assertEqual(payload["evidence"], legacy["evidence"])
            self.assertEqual(payload["assessment"], legacy["assessment"])
            self.assertEqual(payload["reviews"][0]["disposition"], "benign")
            self.assertEqual(store.list()[0].title, legacy["title"])
