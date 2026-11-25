import unittest

import pytest

from tests.fixtures.cloudtrail import assumption, record, report, SESSION, KEY


class DetectionTests(unittest.TestCase):
    def test_each_scoring_rule(self):
        cases = [
            ("role-assumption", [assumption("event", 10)], 20, ["event"]),
            ("object-read", [record("event", 10, "GetObject")], 20, ["event"]),
            ("key-creation", [record("event", 10, "CreateAccessKey")], 15, ["event"]),
            ("policy-attachment", [record("event", 10, "AttachUserPolicy")], 15, ["event"]),
            ("repeated-key-creation", [record("first", 10, "CreateAccessKey"),
                                       record("second", 11, "CreateAccessKey")], 25, ["first", "second"]),
            ("role-then-key", [assumption("first", 10),
                              record("second", 11, "CreateAccessKey", SESSION, KEY)], 55, ["first", "second"]),
        ]
        for rule_id, records, score, evidence_ids in cases:
            with self.subTest(rule_id=rule_id):
                assessment = report(records)["assessment"]
                self.assertEqual(assessment["score"], score)
                claim = next(claim for claim in assessment["claims"] if claim["rule_id"] == rule_id)
                self.assertEqual(claim["evidence_ids"], evidence_ids)

    def test_counts_deduplicate_and_sequence_requires_credential_link(self):
        create = record("create", 12, "CreateAccessKey")
        assessment = report([create, create, assumption("role", 10)])["assessment"]
        self.assertEqual({item["rule_id"] for item in assessment["claims"]}, {"role-assumption", "key-creation"})


@pytest.mark.parametrize(("operations", "score", "severity"), [
    ([], 0, "unrated"),
    (["CreateAccessKey"], 15, "low"),
    (["CreateAccessKey", "CreateAccessKey"], 25, "medium"),
    (["GetObject", "CreateAccessKey", "CreateAccessKey"], 45, "medium"),
    (["AssumeRole", "CreateAccessKey", "AttachUserPolicy"], 50, "high"),
])
def test_severity_thresholds(operations, score, severity):
    assessment = report([record(str(index), index, event) for index, event in enumerate(operations)])["assessment"]
    assert (assessment["score"], assessment["severity"]) == (score, severity)
