import pytest

from riswan_ir.normalization.cloudtrail import normalize, normalize_batch


@pytest.mark.parametrize(
    ("source", "operation", "family"),
    [
        ("iam", "AttachUserPolicy", "identity"),
        ("sts", "AssumeRole", "identity"),
        ("s3", "GetObject", "storage"),
        ("lambda", "Invoke", "compute"),
        ("ec2", "RunInstances", "compute"),
        ("ec2", "AuthorizeSecurityGroupIngress", "network"),
        ("kms", "Decrypt", "encryption"),
        ("secretsmanager", "GetSecretValue", "encryption"),
        ("guardduty", "ListFindings", "monitoring"),
        ("securityhub", "GetFindings", "monitoring"),
        ("cloudtrail", "LookupEvents", "monitoring"),
        ("eks", "DescribeCluster", "container"),
        ("ecs", "DescribeTasks", "container"),
        ("rds", "DescribeDBInstances", "database"),
        ("dynamodb", "GetItem", "database"),
        ("future-service", "NewOperation", "other"),
    ],
)
def test_service_classification(cloudtrail, source, operation, family):
    source += ".amazonaws.com"
    raw = cloudtrail["Records"][0]
    result = normalize(
        {**raw, "eventSource": source, "eventName": operation, "eventType": "AwsFutureType"}
    )
    assert (result.event_source, result.operation, result.service_family) == (
        source,
        operation,
        family,
    )
    assert result.event_type == "AwsFutureType"


@pytest.mark.parametrize(
    "identity_type",
    [
        "IAMUser",
        "AssumedRole",
        "FederatedUser",
        "SAMLUser",
        "WebIdentityUser",
        "AWSService",
        "Root",
    ],
)
def test_identity_and_session(cloudtrail, identity_type):
    raw = cloudtrail["Records"][0]
    raw["userIdentity"] = {
        "type": identity_type,
        "accountId": "222233334444",
        "principalId": "example-principal",
        "invokedBy": "ec2.amazonaws.com",
        "identityProvider": "example-provider",
        "accessKeyId": "ASIAEXAMPLE",
        "sessionContext": {
            "sessionIssuer": {"type": "Role", "arn": "arn:aws:iam::222233334444:role/workload"},
            "attributes": {
                "creationDate": "2025-01-01T03:00:00+01:00",
                "mfaAuthenticated": "false",
            },
            "sourceIdentity": "example-identity",
        },
    }
    raw["sessionCredentialFromConsole"] = "true"
    raw["recipientAccountId"] = "123456789012"
    entry = normalize_batch(raw).records[0]
    identity = entry.event.identity
    assert identity.type == identity_type and identity.principal_id == "example-principal"
    assert (
        identity.invoked_by == "ec2.amazonaws.com"
        and identity.identity_provider == "example-provider"
    )
    assert identity.session.issuer.type == "Role"
    assert identity.session.created_at == "2025-01-01T02:00:00.000000+00:00"
    assert identity.session.source_identity == "example-identity"
    assert (
        identity.session.mfa_authenticated is False
        and identity.session.credential_from_console is True
    )
    assert (
        entry.event.account_id == "222233334444"
        and entry.event.recipient_account_id == "123456789012"
    )
    assert entry.access_key_id == "ASIAEXAMPLE"
    assert "ASIAEXAMPLE" not in repr(entry) and "ASIAEXAMPLE" not in str(entry.event.payload())


def test_malformed_optional_fields_and_insight(cloudtrail):
    raw = cloudtrail["Records"][0]
    event = normalize(
        {
            **raw,
            "userIdentity": [],
            "resources": [None, {}, {"type": "AWS::EC2::Instance"}],
            "tlsDetails": "bad",
            "readOnly": [],
            "requestParameters": "bad",
        }
    )
    assert (
        event.identity is event.tls_details is event.read_only is event.request_parameters is None
    )
    assert [resource.type for resource in event.resources] == ["AWS::EC2::Instance"]
    insight = normalize(
        {
            "eventID": "insight",
            "eventTime": raw["eventTime"],
            "eventCategory": "Insight",
            "eventType": "AwsCloudTrailInsight",
            "insightDetails": {"eventName": "RunInstances", "eventSource": "ec2.amazonaws.com"},
        }
    )
    assert (insight.event_category, insight.event_source, insight.outcome) == (
        "Insight",
        "ec2.amazonaws.com",
        "unknown",
    )


def test_batch_issues_and_deduplication(cloudtrail):
    first, second, third = cloudtrail["Records"]
    result = normalize_batch(
        {
            "Records": [
                third,
                first,
                dict(reversed(list(third.items()))),
                {**first, "additionalEventData": {"internal": "fixture-secret"}},
                {**second, "eventSource": "fixture-secret"},
                {**second, "eventCategory": "fixture-secret"},
                {**second, "eventTime": "fixture-secret"},
                {**second, "eventVersion": "bad"},
                None,
            ]
        }
    )
    assert [entry.event.id for entry in result.records] == ["key-used"]
    assert [(issue.index, issue.field, issue.code) for issue in result.issues] == [
        (3, "eventID", "conflicting_duplicate"),
        (4, "eventSource", "invalid_aws_service"),
        (5, "eventCategory", "unsupported_category"),
        (6, "eventTime", "invalid_timestamp"),
        (7, "eventVersion", "invalid_version"),
        (8, "record", "expected_object"),
    ]
    assert "fixture-secret" not in repr(result.issues)
    assert normalize_batch({"Records": "bad"}).issues[0].code == "invalid_batch"
    assert (
        normalize_batch({"Events": [{"CloudTrailEvent": "{"}]}).issues[0].code == "invalid_export"
    )


@pytest.mark.parametrize("category", ["Management", "Data", "NetworkActivity"])
@pytest.mark.parametrize("source", ["future-service.amazonaws.com.cn", "future-service.api.aws"])
def test_valid_categories_and_partitions(cloudtrail, source, category):
    event = normalize(
        {**cloudtrail["Records"][0], "eventSource": source, "eventCategory": category}
    )
    assert event.event_source == source and event.event_category == category


def test_optional_dates_and_failed_console_login(cloudtrail):
    raw = cloudtrail["Records"][0]
    raw["userIdentity"]["sessionContext"] = {"attributes": {"creationDate": "invalid"}}
    raw["responseElements"] = {"ConsoleLogin": "Failure"}
    event = normalize(raw)
    assert event.identity.session.created_at is None
    assert event.outcome == "failure"


def test_shared_request_across_accounts_preserves_both_events(cloudtrail):
    original = {**cloudtrail["Records"][0], "sharedEventID": "cross-account"}
    recipient = {
        **original,
        "eventID": "recipient-copy",
        "recipientAccountId": "222233334444",
        "awsRegion": "eu-west-1",
    }
    result = normalize_batch({"Records": [original, recipient, original]})
    assert not result.issues
    assert [entry.event.id for entry in result.records] == ["recipient-copy", "role-issued"]
    assert {entry.event.region for entry in result.records} == {"us-east-1", "eu-west-1"}


def test_malformed_category_and_non_json_value_are_reported(cloudtrail):
    raw = cloudtrail["Records"][0]
    result = normalize_batch(
        [{**raw, "eventCategory": []}, {**raw, "additionalEventData": {"invalid": float("nan")}}]
    )
    assert [issue.code for issue in result.issues] == ["unsupported_category", "invalid_json_value"]
