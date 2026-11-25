import json

BASE = "/v1/investigations"
ACTOR = "arn:aws:iam::123456789012:user/build"
ROLE = "arn:aws:iam::999988887777:role/Prod"
SESSION = "arn:aws:sts::999988887777:assumed-role/Prod/reused-name"
NEXT_ROLE = "arn:aws:iam::999988887777:role/Second"
NEXT_SESSION = "arn:aws:sts::999988887777:assumed-role/Second/deploy"


def chain():
    first = {
        "eventID": "initial",
        "eventTime": "2025-01-01T00:01:00Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "arn": ACTOR, "principalId": "Person"},
        "requestParameters": {"roleArn": ROLE, "sourceIdentity": "build-id"},
        "responseElements": {
            "credentials": {"accessKeyId": "first-key", "sessionToken": "fixture-only-token"},
            "assumedRoleUser": {"arn": SESSION, "assumedRoleId": "RoleId:reused-name"},
        },
    }
    second = {
        "eventID": "second",
        "eventTime": "2025-01-01T00:02:00Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": "us-west-2",
        "recipientAccountId": "999988887777",
        "userIdentity": {
            "type": "AssumedRole",
            "arn": SESSION,
            "principalId": "RoleId:reused-name",
            "accessKeyId": "first-key",
            "sessionContext": {
                "sourceIdentity": "build-id",
                "sessionIssuer": {"arn": ROLE},
                "attributes": {"creationDate": "2025-01-01T00:01:01Z"},
            },
        },
        "requestParameters": {"roleArn": NEXT_ROLE},
        "responseElements": {
            "credentials": {"accessKeyId": "second-key"},
            "assumedRoleUser": {"arn": NEXT_SESSION, "assumedRoleId": "RoleId2:deploy"},
        },
    }
    last = {
        "eventID": "read",
        "eventTime": "2025-01-01T00:03:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "readOnly": True,
        "awsRegion": "eu-west-1",
        "recipientAccountId": "999988887777",
        "userIdentity": {
            "type": "AssumedRole",
            "arn": NEXT_SESSION,
            "accessKeyId": "second-key",
            "principalId": "RoleId2:deploy",
        },
        "resources": [{"ARN": "arn:aws:s3:::example/object", "type": "AWS::S3::Object"}],
    }
    return first, second, last


def test_cross_account_role_chain_graph_and_chronology(client, store):
    first, second, last = chain()
    status, report, _ = client(
        "POST", BASE, {"title": "Review", "principal": ACTOR, "records": [last, second, first]}
    )
    assert status == 201
    assert [item["id"] for item in report["evidence"]] == ["initial", "second", "read"]
    correlation = report["correlation"]
    assert correlation["context"]["version"] == "identity-correlation-1"
    assert [item["cross_account"] for item in correlation["assumptions"]] == [True, False]
    assert correlation["chains"][0]["event_ids"] == ["initial", "second", "read"]
    assert {edge["relationship"] for edge in report["graph"]} >= {
        "ASSUMED_ROLE",
        "ESTABLISHED_SESSION",
        "ISSUED_CREDENTIAL",
        "AUTHENTICATED_AS",
        "ACCESSED_RESOURCE",
        "CHAINED_TO",
        "PERFORMED_ACTION",
        "BELONGS_TO_ACCOUNT",
        "SUPPORTED_BY",
    }
    assert all(edge["evidence_ids"] for edge in correlation["relationships"])
    assert client("GET", f"{BASE}/{report['id']}/correlation")[1] == correlation
    assert store.verify_evidence(report["id"]).valid
    bundle = store.export_evidence(report["id"])
    assert "fixture-only-token" not in json.dumps(bundle)
    assert "first-key" not in json.dumps(report)


def test_late_records_create_immutable_revision(client, store):
    first, second, last = chain()
    status, base, _ = client(
        "POST",
        BASE,
        {
            "title": "Review",
            "principal": ACTOR,
            "records": [first, last],
            "provenance": {"source_location": "original-export"},
        },
    )
    assert status == 201 and [item["id"] for item in base["evidence"]] == ["initial"]
    status, revised, _ = client(
        "POST",
        f"{BASE}/{base['id']}/revisions",
        {"records": second, "provenance": {"source_location": "late-export"}},
    )
    assert status == 201 and revised["id"] != base["id"]
    assert revised["previous_investigation_id"] == base["id"]
    assert [item["id"] for item in revised["evidence"]] == ["initial", "second", "read"]
    assert client("GET", f"{BASE}/{base['id']}")[1] == base
    bundle = store.export_evidence(revised["id"])
    assert [entry["source_location"] for entry in bundle["provenance"]] == [
        "original-export",
        "original-export",
        "late-export",
    ]
    assert any(entry["action"] == "revised" for entry in bundle["custody"])


def test_revoking_correlation_metadata_breaks_verification(store, investigation_request):
    report = store.create(investigation_request)
    payload = report.payload()
    payload.pop("correlation")
    with store.connect() as db:
        db.execute(
            "UPDATE investigations SET report = ? WHERE id = ?", (json.dumps(payload), report.id)
        )
    assert "Correlation snapshot verification failed." in store.verify_evidence(report.id).problems


def test_shared_events_and_requests_are_evidence_backed_without_expanding_scope(client):
    first, second, last = chain()
    first["sharedEventID"] = "shared"
    peer = {**first, "eventID": "initial-peer", "recipientAccountId": "999988887777"}
    last["requestID"] = "scoped-request"
    duplicate = {
        **last,
        "eventID": "last-copy",
        "eventTime": "2025-01-01T00:03:02Z",
        "readOnly": False,
    }
    status, report, _ = client(
        "POST",
        BASE,
        {"title": "Review", "principal": ACTOR, "records": [first, peer, second, last, duplicate]},
    )
    assert status == 201
    relationships = report["correlation"]["relationships"]
    assert any(
        edge["relationship"] == "SHARED_EVENT"
        and edge["evidence_ids"] == ["initial", "initial-peer"]
        for edge in relationships
    )
    assert any(
        edge["relationship"] == "RELATED_REQUEST" and edge["confidence"] == "high"
        for edge in relationships
    )
    assert any(edge["relationship"] == "MODIFIED_RESOURCE" for edge in relationships)


def test_federated_session_matches_only_issued_key(client):
    first, _, last = chain()
    federated = "arn:aws:sts::123456789012:federated-user/build"
    first["eventName"] = "GetFederationToken"
    first["responseElements"]["federatedUser"] = {"arn": federated}
    last["userIdentity"] = {"type": "FederatedUser", "arn": federated, "accessKeyId": "first-key"}
    status, report, _ = client(
        "POST", BASE, {"title": "Review", "principal": ACTOR, "records": [last, first]}
    )
    assert status == 201 and report["evidence"][-1]["linked_from_evidence_id"] == "initial"
    assert any(
        identity["kind"] == "FederatedUser" for identity in report["correlation"]["identities"]
    )
