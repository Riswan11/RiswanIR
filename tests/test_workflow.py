import io
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from wsgiref.validate import validator

from forge import Store
from server import Application


class InvestigationWorkflow(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "test.sqlite3"
        self.app = validator(Application(Store(self.path)))
        principal = "arn:aws:iam::123456789012:user/test"
        self.finding = {"title": "Review IAM activity", "principal": principal, "records": [{
            "eventID": "test-1", "eventTime": "2025-01-01T12:00:00Z",
            "eventName": "CreateAccessKey", "userIdentity": {"arn": principal},
            "requestParameters": {"userName": "test", "secret": "omit-me"},
        }]}

    def request(self, method, path, obj=None, *, host="localhost:8000", raw=None):
        data = raw if raw is not None else json.dumps(obj).encode() if obj is not None else b""
        env = {
            "REQUEST_METHOD": method, "SCRIPT_NAME": "", "PATH_INFO": path, "QUERY_STRING": "",
            "SERVER_NAME": "localhost", "SERVER_PORT": "8000", "SERVER_PROTOCOL": "HTTP/1.1",
            "HTTP_HOST": host,
            "CONTENT_LENGTH": str(len(data)), "CONTENT_TYPE": "application/json",
            "wsgi.url_scheme": "http", "wsgi.version": (1, 0),
            "wsgi.input": io.BytesIO(data), "wsgi.errors": io.StringIO(),
            "wsgi.multithread": False, "wsgi.multiprocess": False, "wsgi.run_once": False,
        }
        statuses = []
        response = self.app(env, lambda status, headers: statuses.append(int(status.split()[0])))
        try:
            body = b"".join(response)
        finally:
            response.close()
        return statuses[0], body if path == "/" and statuses[0] == 200 else json.loads(body)

    def test_full_workflow(self):
        self.assertIn(b"CloudTrail investigation workspace", self.request("GET", "/")[1])
        base = "/v1/investigations"
        status, report = self.request("POST", base, self.finding)
        self.assertEqual(status, 201)
        path = f"{base}/{report['id']}"
        evidence = self.request("GET", path + "/evidence")[1]
        self.assertEqual(report["assessment"]["claims"][0]["evidence_ids"], [evidence[0]["id"]])
        self.assertNotIn("omit-me", json.dumps(report))
        self.assertTrue(evidence[0]["integrity_hash"].startswith("sha256:"))
        self.assertEqual(len(self.request("GET", path + "/graph")[1]), 2)
        self.assertEqual(self.request("POST", path + "/feedback",
                                      {"reviewer": "Analyst", "disposition": "confirmed"})[0], 201)
        action = path + "/actions/review-access-key"
        self.assertEqual(self.request("POST", action + "/approve", {"reviewer": "Analyst"})[0], 201)
        self.assertEqual(self.request("POST", action + "/reject", {"reviewer": "Analyst"})[0], 409)
        self.assertEqual(Store(self.path).get(report["id"])["decision"]["decision"], "approve")
        next_report = self.request("POST", base, self.finding)[1]
        self.assertEqual(next_report["similar_investigations"][0]["disposition"], "confirmed")

    def test_evidence_matching_and_validation(self):
        record = self.finding["records"][0]
        self.finding["records"].extend([
            record, {**record, "eventID": "failed", "errorCode": "AccessDenied"},
            {**record, "eventID": "other", "userIdentity": {"arn": "another-principal"}},
        ])
        base = "/v1/investigations"
        self.assertEqual(len(self.request("POST", base, self.finding)[1]["evidence"]), 1)
        self.finding["records"].append({**record, "eventName": "AssumeRole"})
        self.assertEqual(self.request("POST", base, self.finding)[0], 400)
        self.assertEqual(self.request("POST", base, {"title": "Missing records"})[0], 400)

    def test_host_validation(self):
        for host in ("attacker.example", "localhost.attacker.example", "localhost@attacker.example", "", "localhost,localhost"):
            with self.subTest(host=host):
                self.assertEqual(self.request("GET", "/", host=host)[0], 400)
        self.assertEqual(self.request("GET", "/", host="127.0.0.1:8000")[0], 200)

    def test_json_error_paths(self):
        base = "/v1/investigations"
        for raw in (b"{", b"[]", b'{"x":"\xff"}'):
            with self.subTest(raw=raw):
                self.assertEqual(self.request("POST", base, raw=raw)[0], 400)
        self.assertEqual(self.request("GET", base + "/" + "0" * 32)[0], 404)
        with patch.object(Store, "list", side_effect=KeyError("private details")), self.assertLogs("server", level="ERROR"):
            self.assertEqual(self.request("GET", base), (500, {"error": "Internal server error."}))
