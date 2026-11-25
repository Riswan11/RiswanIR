import pytest

from sentinelforge.normalization.aws.cloudtrail import normalize
from sentinelforge.normalization.aws.ocsf_mapper import REGISTRY, map_event
from sentinelforge.schema.export import ocsf_payload


@pytest.mark.parametrize(
    ("operation", "service", "class_uid", "activity"),
    [
        ("ConsoleLogin", "signin", 3002, 1),
        ("AssumeRole", "sts", 6003, 1),
        ("CreateUser", "iam", 3001, 1),
        ("CreateAccessKey", "iam", 6003, 1),
        ("AttachUserPolicy", "iam", 3001, 7),
        ("GetObject", "s3", 6003, 2),
        ("PutObject", "s3", 6003, 0),
        ("RunInstances", "ec2", 6003, 1),
        ("AuthorizeSecurityGroupIngress", "ec2", 6003, 3),
        ("StopLogging", "cloudtrail", 6003, 3),
        ("NewOperation", "future-service", 6003, 0),
    ],
)
def test_cloudtrail_classification(cloudtrail, operation, service, class_uid, activity):
    raw = {
        **cloudtrail["Records"][0],
        "eventSource": f"{service}.amazonaws.com",
        "eventName": operation,
        "eventType": "AwsApiCall",
        "sourceIPAddress": "203.0.113.20",
        "requestParameters": {"userName": "target"},
        "errorCode": "AccessDenied",
    }
    event = map_event(normalize(raw))
    assert REGISTRY.validate(event).valid
    exported = ocsf_payload(event)
    assert exported["class_uid"] == class_uid
    assert exported["type_uid"] == class_uid * 100 + activity
    assert exported["category_uid"] == class_uid // 1000
    assert exported["status_id"] == 2 and exported["severity_id"] == 0
    assert exported["metadata"]["version"] == "1.6.0"
    assert isinstance(exported["time"], int)
    if class_uid == 6003:
        assert exported["api"]["operation"] == operation and exported["actor"]["user"]["uid"]
        assert exported["src_endpoint"]["ip"] == "203.0.113.20"
    else:
        assert (
            exported["user"]["name"] == "target" if class_uid == 3001 else exported["user"]["uid"]
        )


def test_unknown_types_and_missing_endpoints_downgrade_without_fabrication(cloudtrail):
    raw = cloudtrail["Records"][0]
    event = map_event(normalize({**raw, "sourceIPAddress": "AWS Internal"}))
    exported = ocsf_payload(event)
    assert exported["class_uid"] == 0 and "src_endpoint" not in exported
    assert event.extensions["aws.cloudtrail"]["fallback_reason"] == "missing_required_api_context"
    assert event.extensions["aws.cloudtrail"]["reported_source_address"] == "AWS Internal"
    unknown = map_event(
        normalize({**raw, "eventType": "UnknownType", "sourceIPAddress": "2001:db8::1"})
    )
    assert unknown.classification.class_uid == 0
    assert unknown.extensions["aws.cloudtrail"]["record_type"] == "UnknownType"
    assert (
        unknown.extensions["aws.cloudtrail"]["fallback_reason"]
        == "event_type_outside_mapped_subset"
    )


def test_attach_policy_missing_target_uses_api_activity(cloudtrail):
    raw = {
        **cloudtrail["Records"][0],
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "sourceIPAddress": "2001:db8::1",
        "requestParameters": {"policyArn": "arn:aws:iam::123456789012:policy/example"},
    }
    event = map_event(normalize(raw))
    assert event.classification.type_uid == 600303
    assert event.resources[0].uid == raw["requestParameters"]["policyArn"]


def test_session_context_in_api_export(cloudtrail):
    raw = cloudtrail["Records"][1]
    raw["userIdentity"]["sessionContext"] = {
        "attributes": {"creationDate": "2025-01-01T03:10:00Z", "mfaAuthenticated": "true"},
        "sessionIssuer": {"arn": "arn:aws:iam::123456789012:role/Example"},
    }
    event = map_event(normalize(raw))
    payload = ocsf_payload(event)
    assert payload["actor"]["session"] == {"created_time": 1735701000000, "is_mfa": True}
    assert payload["api"]["service"]["name"] == "iam.amazonaws.com"
    assert payload["unmapped"]["sentinelforge"]["extensions"]["aws.cloudtrail"][
        "session_issuer_arn"
    ].endswith("/Example")
