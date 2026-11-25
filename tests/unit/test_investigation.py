import json
import unittest

from tests.fixtures.cloudtrail import (
    KEY,
    LONG_TERM_KEY,
    NEXT,
    NEXT_KEY,
    SESSION,
    assumption,
    record,
    report,
)


class CorrelationTests(unittest.TestCase):
    def test_chains_cross_account_role_sessions_and_created_key(self):
        assume = assumption("assume", 10, recipientAccountId="111122223333")
        chain = assumption("chain", 11, SESSION, KEY, NEXT, NEXT_KEY)
        create = record(
            "create",
            12,
            "CreateAccessKey",
            NEXT,
            NEXT_KEY,
            eventSource="iam.amazonaws.com",
            responseElements={
                "accessKey": {"accessKeyId": LONG_TERM_KEY, "secretAccessKey": "omit-me"}
            },
        )
        created_user = "arn:aws:iam::111122223333:user/target"
        used = record(
            "used",
            13,
            "GetObject",
            created_user,
            LONG_TERM_KEY,
            sourceIPAddress="203.0.113.64",
            userAgent="aws-cli/2.0",
            awsRegion="us-east-1",
            recipientAccountId="111122223333",
        )
        other = record("other", 14, "AttachUserPolicy", SESSION, "ASIAUNRELATED")
        result = report({"Records": [used, other, create, chain, assume]})
        self.assertEqual(
            [(row["id"], row["linked_from_evidence_id"]) for row in result["evidence"]],
            [("assume", None), ("chain", "assume"), ("create", "chain"), ("used", "create")],
        )
        self.assertEqual(result["evidence"][0]["account_id"], "777788889999")
        self.assertEqual(result["evidence"][0]["recipient_account_id"], "111122223333")
        self.assertEqual(result["evidence"][-1]["source_ip"], "203.0.113.64")
        self.assertEqual(result["evidence"][-1]["user_agent"], "aws-cli/2.0")
        self.assertEqual(result["evidence"][-1]["region"], "us-east-1")
        self.assertNotIn("omit-me", json.dumps(result))
        self.assertIn(
            {"from": "create", "relationship": "ISSUED_CREDENTIAL_USED_IN", "to": "used"},
            result["graph"],
        )

    def test_does_not_join_before_issuance_after_expiry_or_wrong_session(self):
        result = report(
            [
                assumption("assume", 10),
                record("before", 9, "GetObject", SESSION, KEY),
                record("same-time", 10, "GetObject", SESSION, KEY),
                record("expired", 47, "GetObject", SESSION, KEY),
                record("wrong", 11, "GetObject", NEXT, KEY),
                record("missing", 12, "GetObject", SESSION),
            ]
        )
        self.assertEqual([row["id"] for row in result["evidence"]], ["assume"])

    def test_failed_issuance_does_not_expand_scope(self):
        result = report(
            [
                assumption("denied", 10, errorCode="AccessDenied"),
                record("used", 11, "GetObject", SESSION, KEY),
            ]
        )
        self.assertEqual(result["evidence"], [])

    def test_malformed_exports_and_lookup_wrapper(self):
        valid = record("valid", 10, "AssumeRole")
        self.assertEqual(
            report({"Events": [{"CloudTrailEvent": json.dumps(valid)}]})["evidence"][0]["id"],
            "valid",
        )
        for invalid in (
            {"Records": {}},
            {"Events": [{"CloudTrailEvent": "{"}]},
            [None],
            [{"eventName": "ListBuckets"}],
            [{**valid, "eventTime": "2020-01-01"}],
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                report(invalid)
