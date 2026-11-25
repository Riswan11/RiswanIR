from datetime import timedelta

import pytest
from botocore.exceptions import EndpointConnectionError
from botocore.stub import Stubber
from pydantic import ValidationError

from riswan_ir.connectors.aws.authentication import log_prefix, session_policy
from riswan_ir.connectors.aws.requests import RequestBudget
from riswan_ir.connectors.base import CollectionFailure
from riswan_ir.models.collection import CollectionRequest
from riswan_ir.models.connector import ConnectorConfig


@pytest.mark.parametrize(
    "account_overrides",
    [
        {"access_key_id": "not-accepted"},
        {"external_id": "requires-role"},
        {"role_arn": "arn:aws:iam::999988887777:role/Unrelated"},
        {"region": "https://other.example"},
    ],
)
def test_configuration_rejects_unscoped_or_credential_fields(aws_config, account_overrides):
    data = aws_config.model_dump()
    data["account"].update(account_overrides)
    with pytest.raises(ValidationError):
        ConnectorConfig.model_validate(data)


def test_prefix_cannot_escape_account_and_region(s3_config):
    policy = session_policy(s3_config, "aws")
    assert "PutObject" not in policy and "DeleteObject" not in policy
    assert log_prefix(s3_config) == "AWSLogs/123456789012/CloudTrail/us-east-1/"
    data = s3_config.model_dump()
    data["s3"]["prefix"] = "../AWSLogs"
    with pytest.raises(ValidationError):
        ConnectorConfig.model_validate(data)


def test_request_budget_and_retry_exhaustion(fake_aws_session):
    client = fake_aws_session.client("cloudtrail")
    with Stubber(client) as stub:
        stub.add_client_error("lookup_events", service_error_code="Throttling")
        budget = RequestBudget(1, pause=lambda _: None)
        with pytest.raises(CollectionFailure, match="request_budget_exceeded"):
            budget.call("lookup_events", client.lookup_events)

    def unreachable():
        raise EndpointConnectionError(endpoint_url="https://example.invalid")

    budget = RequestBudget(5, pause=lambda _: None)
    with pytest.raises(CollectionFailure, match="retry_limit_exceeded"):
        budget.call("lookup_events", unreachable)
    assert budget.used == 4


def test_reversed_range_is_rejected(aws_window):
    with pytest.raises(ValidationError):
        CollectionRequest(start=aws_window.end + timedelta(seconds=1), end=aws_window.end)
