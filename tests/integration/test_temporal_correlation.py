from urllib.parse import urlencode

import pytest

from riswan_ir.correlation.temporal.registry import default_rules
from riswan_ir.models import EvidenceSubmission, InvestigationRequest
from riswan_ir.models.detection import DetectionContext
from riswan_ir.storage.sqlite import Store
from tests.fixtures.cloudtrail import (
    KEY,
    LONG_TERM_KEY,
    NEXT_KEY,
    ROOT,
    SESSION,
    assumption,
    record,
)

ACCOUNT = ROOT.split(":")[4]
DESTINATION = SESSION.split(":")[4]
ROLE = f"arn:aws:iam::{ACCOUNT}:role/Admin"
LOCAL_SESSION = f"arn:aws:sts::{ACCOUNT}:assumed-role/Admin/Test"
BUCKET = "sensitive-archive"
POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
PREFIX = "SF-CORR-AWS-"


def context():
    return DetectionContext(
        privileged_roles={ROLE: True},
        resources={BUCKET: "critical"},
        expected_networks={ACCOUNT: ["10.0.0.0/8"]},
        account_environments={ACCOUNT: "production"},
    )


def activity(event_id, minute, service, operation, *, principal=ROOT, key=LONG_TERM_KEY, **extra):
    return record(
        event_id,
        minute,
        operation,
        principal,
        key,
        eventSource=f"{service}.amazonaws.com",
        sourceIPAddress="192.0.2.9",
        **extra,
    )


def local_assumption():
    return assumption(
        "assume",
        1,
        ROOT,
        LONG_TERM_KEY,
        session=LOCAL_SESSION,
        requestParameters={"roleArn": ROLE},
    )


def access(event_id, minute, **extra):
    return activity(
        event_id,
        minute,
        "s3",
        "GetObject",
        recipientAccountId=ACCOUNT,
        requestParameters={"bucketName": BUCKET},
        **extra,
    )


def create_key(*, principal=ROOT, key=LONG_TERM_KEY, issued=NEXT_KEY, minute=2):
    return activity(
        "create",
        minute,
        "iam",
        "CreateAccessKey",
        principal=principal,
        key=key,
        requestParameters={"userName": "John"},
        responseElements={"accessKey": {"accessKeyId": issued}},
    )


def attached_policy():
    return activity(
        "attach",
        1,
        "iam",
        "AttachUserPolicy",
        requestParameters={"userName": "John", "policyArn": POLICY},
    )


def scenario(number):
    match number:
        case 1:
            return [
                local_assumption(),
                create_key(principal=LOCAL_SESSION, key=KEY),
                activity("stop", 3, "cloudtrail", "StopLogging", principal=LOCAL_SESSION, key=KEY),
            ]
        case 2:
            return [
                create_key(issued=NEXT_KEY, minute=0),
                assumption(
                    "assume",
                    1,
                    ROOT,
                    NEXT_KEY,
                    session=LOCAL_SESSION,
                    requestParameters={"roleArn": ROLE},
                ),
            ]
        case 3:
            return [
                assumption(
                    "cross",
                    1,
                    ROOT,
                    LONG_TERM_KEY,
                    requestParameters={
                        "roleArn": f"arn:aws:iam::{DESTINATION}:role/Developer_Role"
                    },
                ),
                activity("inspect", 2, "iam", "ListUsers", principal=SESSION, key=KEY),
            ]
        case 4:
            return [attached_policy(), create_key()]
        case 5:
            return [activity("stop", 1, "cloudtrail", "StopLogging"), access("read", 2)]
        case 6:
            return [access(f"read-{i}", i) for i in range(1, 4)]
        case 7:
            return [
                activity(
                    f"fail-{i}",
                    i,
                    "signin",
                    "ConsoleLogin",
                    responseElements={"ConsoleLogin": "Failure"},
                )
                for i in range(1, 4)
            ] + [
                activity(
                    "success",
                    4,
                    "signin",
                    "ConsoleLogin",
                    responseElements={"ConsoleLogin": "Success"},
                )
            ]
        case 8:
            return [
                local_assumption(),
                assumption(
                    "follow",
                    2,
                    LOCAL_SESSION,
                    KEY,
                    session=f"arn:aws:sts::{ACCOUNT}:assumed-role/Admin/Second",
                    issued=NEXT_KEY,
                    requestParameters={"roleArn": ROLE},
                    sourceIPAddress="192.0.2.8",
                ),
            ]
        case 9:
            return [attached_policy(), activity("run", 2, "ec2", "RunInstances")]
        case _:
            return [
                activity(
                    "policy",
                    1,
                    "s3",
                    "PutBucketPolicy",
                    recipientAccountId=ACCOUNT,
                    requestParameters={
                        "bucketName": BUCKET,
                        "bucketPolicy": {
                            "Statement": {"Effect": "Allow", "Principal": "*"},
                        },
                    },
                ),
                access("read", 2),
            ]


def create(store, records):
    return store.create(
        InvestigationRequest(title="Temporal review", principal=ROOT, records=records)
    )


@pytest.mark.parametrize("number", range(1, 11))
def test_every_rule_matches_only_the_complete_evidenced_pattern(number, tmp_path, monkeypatch):
    policy = tmp_path / "policy.json"
    policy.write_text(
        '{"cross_account":[{"source":"aws:' + ACCOUNT + '","target":"aws:' + DESTINATION + '"}]}',
        encoding="utf-8",
    )
    monkeypatch.setenv("RISWAN_IR_TEMPORAL_POLICY", str(policy))
    store = Store(tmp_path / "test.sqlite3", detection_context=context())
    data = scenario(number)
    report = create(store, list(reversed(data)) + [data[0]])
    result = store.temporal_result(report.id)
    rule_id = f"{PREFIX}{number:03d}"
    assert len(default_rules()) == 10
    (incident,) = [item for item in result.incidents if item.id == rule_id]
    assert [step.event_id for step in incident.timeline] == [item["eventID"] for item in data]
    assert all(step.evidence_id and step.ingested_at for step in incident.timeline)
    assert all(
        step.relationship_ids and step.relationship_evidence_ids for step in incident.timeline[1:]
    )
    assert Store(store.path).replay_temporal(report.id) == result
    assert store.replay_temporal(report.id, {rule_id: "1.0.0"}).incidents == [incident]
    incomplete = create(store, data[:-1])
    assert rule_id not in {item.id for item in store.temporal_result(incomplete.id).incidents}


def test_late_event_preserves_ingestion_times_and_stable_incident_identity(tmp_path, monkeypatch):
    store = Store(tmp_path / "late.sqlite3", detection_context=context())
    data = scenario(5)
    early = create(store, data[:1])
    state = Store(store.path).temporal_result(early.id)
    assert state.partial_matches and state.incidents == []
    monkeypatch.setattr("riswan_ir.storage.sqlite.now", lambda: "2025-02-01T04:00:00+00:00")
    completed = store.revise(early.id, EvidenceSubmission(records=data[1:]))
    (first,) = store.temporal_result(completed.id).incidents
    assert first.timeline[0].ingested_at != first.timeline[1].ingested_at
    retry = store.revise(completed.id, EvidenceSubmission(records=data[1:]))
    (again,) = store.temporal_result(retry.id).incidents
    assert again.incident_id == first.incident_id
    assert [item.ingested_at for item in again.timeline] == [
        item.ingested_at for item in first.timeline
    ]
    assert store.replay_temporal(retry.id) == store.temporal_result(retry.id)


def test_incident_api_and_scope(client, store):
    payload = {"title": "Authentication", "principal": ROOT, "records": scenario(7)}
    status, report, _ = client("POST", "/v1/investigations", payload)
    assert status == 201
    base = f"/v1/investigations/{report['id']}"
    (incident,) = client("GET", base + "/incidents")[1]["incidents"]
    detail = base + f"/incidents/{incident['incident_id']}"
    assert client("GET", detail)[1] == incident
    assert client("GET", detail + "/timeline")[1]["timeline"] == incident["timeline"]
    assert "metrics" in client("GET", base + "/temporal-correlation")[1]
    query = urlencode({"version": f"{PREFIX}007=1.0.0"})
    replay = client("GET", base + "/temporal-correlation/replay", headers={"QUERY_STRING": query})
    assert replay[:2][0] == 200 and replay[1]["incidents"] == [incident]
    assert (
        client(
            "GET",
            base + "/temporal-correlation/replay",
            headers={"QUERY_STRING": "version=not-a-version"},
        )[0]
        == 400
    )
    other = create(store, [])
    assert client("GET", detail.replace(report["id"], other.id))[0] == 404
