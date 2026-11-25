import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from botocore.stub import Stubber

from riswan_ir.connectors.aws import authentication as aws
from riswan_ir.connectors.aws.requests import RequestBudget
from riswan_ir.connectors.base import CollectionFailure
from riswan_ir.models.connector import ConnectorConfig


def test_cross_account_assumption_with_restricted_policy(aws_config, fake_aws_session, monkeypatch):
    account = {
        "account_id": "999988887777",
        "region": "us-east-1",
        "role_arn": "arn:aws:iam::999988887777:role/Telemetry",
        "external_id": "test-external-id",
    }
    config = ConnectorConfig.model_validate({**aws_config.model_dump(), "account": account})
    bootstrap = fake_aws_session.client("sts")
    target = fake_aws_session.client("sts")
    client_factory = MagicMock(side_effect=[bootstrap, target])
    monkeypatch.setattr(fake_aws_session, "client", client_factory)
    sdk = MagicMock(side_effect=[fake_aws_session, fake_aws_session])
    monkeypatch.setattr(aws.boto3, "Session", sdk)
    policy = aws.session_policy(config, "aws")
    statements = json.loads(policy)["Statement"]
    assert [statement["Action"] for statement in statements if statement["Effect"] == "Allow"] == [
        "cloudtrail:LookupEvents"
    ]
    assert statements[-1]["NotAction"] == ["cloudtrail:LookupEvents", "sts:GetCallerIdentity"]
    with Stubber(bootstrap) as first, Stubber(target) as second:
        first.add_response(
            "assume_role",
            {
                "Credentials": {
                    "AccessKeyId": "fixture-access-key-id",
                    "SecretAccessKey": "fixture-key",
                    "SessionToken": "temporary",
                    "Expiration": datetime.now(timezone.utc),
                }
            },
            {
                "RoleArn": account["role_arn"],
                "RoleSessionName": "SentinelForgeTelemetry",
                "Policy": policy,
                "DurationSeconds": 900,
                "ExternalId": account["external_id"],
            },
        )
        second.add_response("get_caller_identity", {"Account": account["account_id"]}, {})
        aws.authenticated_session(config, RequestBudget(3, pause=lambda _: None))
        first.assert_no_pending_responses()
        second.assert_no_pending_responses()
    assert sdk.call_args.kwargs["aws_session_token"] == "temporary"
    assert all(
        call.kwargs["verify"] and call.kwargs["use_ssl"] for call in client_factory.call_args_list
    )
    assert "test-external-id" not in repr(config)


def test_rejects_permanent_credentials_before_network(aws_config, monkeypatch):
    session = MagicMock()
    session.get_credentials.return_value.get_frozen_credentials.return_value.token = None
    monkeypatch.setattr(aws.boto3, "Session", lambda **_: session)
    with pytest.raises(CollectionFailure, match="temporary_credentials_required"):
        aws.authenticated_session(aws_config, RequestBudget(3))
    session.client.assert_not_called()


@pytest.mark.parametrize(
    ("outcome", "code"),
    [
        ("account", "account_mismatch"),
        ("ExpiredToken", "credentials_expired"),
        ("AccessDenied", "access_denied"),
    ],
)
def test_auth_failures_are_safe(aws_config, fake_aws_session, monkeypatch, outcome, code):
    sts = fake_aws_session.client("sts")
    monkeypatch.setattr(fake_aws_session, "client", lambda *args, **kwargs: sts)
    monkeypatch.setattr(aws.boto3, "Session", lambda **_: fake_aws_session)
    with Stubber(sts) as stub:
        if outcome == "account":
            stub.add_response("get_caller_identity", {"Account": "999988887777"}, {})
        else:
            stub.add_client_error(
                "get_caller_identity",
                service_error_code=outcome,
                service_message="private material",
            )
        with pytest.raises(CollectionFailure, match=code) as exc:
            aws.authenticated_session(aws_config, RequestBudget(3))
        assert "private material" not in str(exc.value)


def test_scoped_s3_policy_with_kms(s3_config):
    s3_config.s3.kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/example"
    statements = json.loads(aws.session_policy(s3_config, "aws"))["Statement"]
    assert [item["Action"] for item in statements if item["Effect"] == "Allow"] == [
        "s3:ListBucket",
        "s3:GetObject",
        "kms:Decrypt",
    ]
    assert (
        statements[0]["Condition"]["StringLike"]["s3:prefix"]
        == "AWSLogs/123456789012/CloudTrail/us-east-1/*"
    )
    assert statements[1]["Resource"].endswith("/CloudTrail/us-east-1/*.json.gz")
    assert (
        statements[2]["Condition"]["StringEquals"]["kms:ViaService"] == "s3.us-east-1.amazonaws.com"
    )
