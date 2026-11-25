from datetime import timedelta
from ipaddress import ip_address

import pytest

from sentinelforge.core.fields import utc_timestamp
from sentinelforge.detection.engine import evaluate, matches
from sentinelforge.detection.registry import RuleRegistry, default_registry
from sentinelforge.models.canonical_event import Status
from sentinelforge.models.detection import DetectionCondition, DetectionContext
from sentinelforge.normalization.aws.cloudtrail import normalize
from sentinelforge.normalization.aws.detection_signals import project
from sentinelforge.normalization.aws.ocsf_mapper import map_event
from tests.fixtures.cloudtrail import ROOT, record

ACCOUNT = "111122223333"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/SecurityAdmin"
RESOURCE = "sensitive-resource"
POLICY = DetectionContext(
    account_environments={ACCOUNT: "production"},
    privileged_roles={ROLE: True},
    resources={RESOURCE: "critical"},
    expected_networks={ACCOUNT: ["10.0.0.0/8"]},
    known_relationships={ROOT: []},
)

CATALOG_CASES = [
    ("IAM-001", "sts", "AssumeRole", {"roleArn": ROLE}, "IAMUser"),
    ("IAM-002", "iam", "CreateAccessKey", {}, "IAMUser"),
    ("IAM-003", "iam", "ListUsers", {}, "Root"),
    ("IAM-004", "iam", "ListUsers", {}, "AssumedRole"),
    (
        "PRIV-001",
        "iam",
        "AttachRolePolicy",
        {
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
        "IAMUser",
    ),
    ("PRIV-002", "iam", "CreatePolicyVersion", {"policyArn": RESOURCE}, "IAMUser"),
    ("PRIV-003", "iam", "UpdateAssumeRolePolicy", {"roleName": RESOURCE}, "IAMUser"),
    ("PRIV-004", "iam", "DeleteRolePermissionsBoundary", {}, "IAMUser"),
    ("DEF-001", "cloudtrail", "StopLogging", {}, "IAMUser"),
    ("DEF-002", "cloudtrail", "DeleteTrail", {}, "IAMUser"),
    ("DEF-003", "guardduty", "DeleteDetector", {}, "IAMUser"),
    ("DEF-004", "cloudtrail", "PutEventSelectors", {}, "IAMUser"),
    ("DATA-001", "s3", "GetObject", {"bucketName": RESOURCE}, "IAMUser"),
    ("DATA-002", "s3", "GetObject", {"bucketName": RESOURCE}, "IAMUser"),
    (
        "DATA-003",
        "s3",
        "PutBucketPolicy",
        {
            "bucketPolicy": '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"}}]}',
        },
        "IAMUser",
    ),
    ("DATA-004", "s3", "DeleteBucketEncryption", {"bucketName": RESOURCE}, "IAMUser"),
    (
        "INFRA-001",
        "ec2",
        "AuthorizeSecurityGroupIngress",
        {
            "ipPermissions": {"items": [{"ipv6Ranges": {"items": [{"cidrIpv6": "::/0"}]}}]},
        },
        "IAMUser",
    ),
    ("INFRA-002", "ec2", "RunInstances", {}, "IAMUser"),
    ("INFRA-003", "ec2", "AuthorizeSecurityGroupEgress", {"groupId": RESOURCE}, "IAMUser"),
    (
        "INFRA-004",
        "ec2",
        "ModifySnapshotAttribute",
        {
            "createVolumePermission": {"add": {"items": [{"userId": "999988887777"}]}},
        },
        "IAMUser",
    ),
]


def canonical(event_id, minute, service, operation, params=None, identity="IAMUser"):
    data = record(
        event_id,
        minute,
        operation,
        eventSource=f"{service}.amazonaws.com",
        eventType="AwsApiCall",
        sourceIPAddress="192.0.2.44",
        recipientAccountId=ACCOUNT,
        requestParameters=params or {},
    )
    if identity:
        data["userIdentity"]["type"] = identity
    if identity == "AssumedRole":
        data["userIdentity"]["sessionContext"] = {
            "sessionIssuer": {"arn": ROLE},
            "attributes": {"mfaAuthenticated": "false"},
        }
    event = normalize(data)
    return map_event(event, detection_signals=project(data, operation, ACCOUNT))


@pytest.mark.parametrize(("suffix", "service", "operation", "params", "identity"), CATALOG_CASES)
def test_every_rule_handles_positive_negative_and_missing_inputs(
    suffix, service, operation, params, identity
):
    rule_id = f"SF-AWS-{suffix}"
    rules = default_registry().select({rule_id: "1.0.0"})
    count = 3 if suffix == "DATA-001" else 1
    events = [canonical(str(i), i, service, operation, params, identity) for i in range(count)]
    findings = evaluate(reversed(events), rules, POLICY).result.findings
    assert len(findings) == 1
    assert findings[0].evidence_ids == [str(i) for i in range(count)]
    assert findings[0].reasons
    failures = [
        event.model_copy(
            update={"outcome": event.outcome.model_copy(update={"status_id": Status.FAILURE})}
        )
        for event in events
    ]
    assert evaluate(failures, rules, POLICY).result.findings == []
    missing = canonical("missing", 0, service, operation, identity=None).model_copy(
        update={"extensions": {}, "network": None, "cloud": None}
    )
    if suffix.startswith("DEF-00") and suffix != "DEF-004":
        missing.activity.service = None
    missing_events = [missing.model_copy(update={"id": str(i)}) for i in range(count)]
    assert evaluate(missing_events, rules, DetectionContext()).result.findings == []


def test_scoped_exception_expiry_threshold_and_suppression():
    rule = default_registry().select({"SF-AWS-DATA-001": "1.0.0"})[0]
    policy = DetectionContext.model_validate(
        {
            **POLICY.model_dump(),
            "exceptions": [
                {
                    "id": "ticket-7",
                    "rule_id": rule.id,
                    "approved_by": "Analyst",
                    "reason": "Temporary access window",
                    "starts_at": "2021-01-22T00:00:00Z",
                    "expires_at": "2021-01-22T00:01:00Z",
                    "match": {"actor.uid": ROOT},
                }
            ],
        }
    )
    events = [canonical(str(i), i, "s3", "GetObject", {"bucketName": RESOURCE}) for i in range(5)]
    result = evaluate(events + [events[0]], [rule], policy).result
    assert result.execution.events == 5
    assert result.findings[0].evidence_ids == ["1", "2", "3"]
    assert [(item.evidence_id, item.disposition) for item in result.decisions] == [
        ("0", "exception"),
        ("4", "suppressed"),
    ]
    assert result.decisions[0].exception_id == "ticket-7"
    old = events[1].model_copy(
        update={
            "observed_at": (
                utc_timestamp(events[1].observed_at) - timedelta(minutes=20)
            ).isoformat()
        }
    )
    assert evaluate([old, *events[2:4]], [rule], POLICY).result.findings == []


def test_version_selection_and_disabled_rules():
    first = default_registry().select()[0]
    second = first.model_copy(update={"version": "1.10.0", "enabled": False})
    registry = RuleRegistry([second, first])
    assert registry.select() == [second]
    assert registry.select({first.id: first.version}) == [first]
    assert evaluate([], registry.select(), POLICY).result.execution.evaluations == 0
    with pytest.raises(ValueError, match="unavailable"):
        registry.select({first.id: "2.0.0"})
    with pytest.raises(ValueError, match="Duplicate"):
        RuleRegistry([first, first])


@pytest.mark.parametrize(
    ("operator", "operand", "actual", "expected"),
    [
        ("exists", None, False, True),
        ("not_equals", True, None, False),
        ("not_equals", True, False, True),
        ("equals", True, 1, False),
        ("gte", 5, 5, True),
        ("gte", 5, True, False),
        ("lte", 5, 6, False),
        ("in", [False, "test"], False, True),
    ],
)
def test_bounded_operators_preserve_missing_and_types(operator, operand, actual, expected):
    condition = DetectionCondition(field="actor.mfa", operator=operator, value=operand)
    assert matches(condition, {"actor.mfa": actual}) is expected


def test_catalog_cases_cover_registry():
    assert {rule.id for rule in default_registry().select()} == {
        f"SF-AWS-{suffix}" for suffix, *_ in CATALOG_CASES
    }


def test_relationship_history_and_approved_network():
    rule = default_registry().select({"SF-AWS-IAM-001": "1.0.0"})[0]
    first, second = [canonical(str(i), i, "sts", "AssumeRole", {"roleArn": ROLE}) for i in range(2)]
    for event in (first, second):
        event.network.source_ip = ip_address("10.1.2.3")
    result = evaluate([second, first], [rule], POLICY).result
    assert [finding.evidence_ids for finding in result.findings] == [["0"]]
    assert [reason.field for reason in result.findings[0].reasons][
        -1
    ] == "context.unseen_relationship"


def test_explicit_failed_outcome_rule_and_actor_isolation():
    rule = default_registry().select({"SF-AWS-DEF-001": "1.0.0"})[0]
    rule = rule.model_copy(update={"outcomes": ("failure",)})
    successful = canonical("stop", 1, "cloudtrail", "StopLogging")
    failed = successful.model_copy(
        update={"outcome": successful.outcome.model_copy(update={"status_id": Status.FAILURE})}
    )
    assert not evaluate([successful], [rule], POLICY).result.findings
    assert evaluate([failed], [rule], POLICY).result.findings[0].evidence_ids == ["stop"]
    with pytest.raises(ValueError, match="Conflicting canonical"):
        evaluate([successful, failed], [rule], POLICY)


@pytest.mark.parametrize(
    ("rule_id", "service", "operation", "params"),
    [
        (
            "DATA-003",
            "s3",
            "PutBucketPolicy",
            {
                "bucketPolicy": {
                    "Statement": {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Condition": {"StringEquals": {"aws:PrincipalAccount": ACCOUNT}},
                    }
                },
            },
        ),
        ("INFRA-001", "ec2", "AuthorizeSecurityGroupIngress", {"cidrIp": "10.0.0.0/8"}),
        ("INFRA-004", "ec2", "ModifySnapshotAttribute", {"userIds": [ACCOUNT]}),
        (
            "PRIV-001",
            "iam",
            "AttachRolePolicy",
            {"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
        ),
    ],
)
def test_targeted_configuration_rules_ignore_legitimate_changes(
    rule_id, service, operation, params
):
    rule = default_registry().select({f"SF-AWS-{rule_id}": "1.0.0"})[0]
    assert not evaluate(
        [canonical("routine", 1, service, operation, params)], [rule], POLICY
    ).result.findings


def test_guardduty_update_requires_explicit_disable_signal():
    rule = default_registry().select({"SF-AWS-DEF-003": "1.0.0"})[0]
    for flag in (None, True, False):
        event = canonical("guard", 5, "guardduty", "UpdateDetector", {"enable": flag})
        assert bool(evaluate([event], [rule], POLICY).result.findings) is (flag is False)
