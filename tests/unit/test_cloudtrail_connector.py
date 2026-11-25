import json
from datetime import timedelta

import pytest
from botocore.stub import Stubber

from riswan_ir.connectors.aws.cloudtrail import CloudTrailHistory
from riswan_ir.connectors.aws.requests import RequestBudget
from riswan_ir.connectors.base import CollectionFailure
from riswan_ir.models.collection import CollectionRequest


def test_pagination_retry_budget_and_scope(aws_config, aws_window, fake_aws_session, cloudtrail):
    client = fake_aws_session.client("cloudtrail")
    pauses = []
    budget = RequestBudget(6, pause=pauses.append)
    connector = CloudTrailHistory(aws_config, client, budget)
    parameters = {"StartTime": aws_window.start, "EndTime": aws_window.end, "MaxResults": 50}
    event = {"CloudTrailEvent": json.dumps(cloudtrail["Records"][0])}
    with Stubber(client) as stub:
        stub.add_client_error(
            "lookup_events", service_error_code="ThrottlingException", expected_params=parameters
        )
        stub.add_response("lookup_events", {"Events": [event], "NextToken": "page2"}, parameters)
        stub.add_response(
            "lookup_events", {"Events": [event]}, {**parameters, "NextToken": "page2"}
        )
        batches = list(connector.collect(aws_window))
        stub.assert_no_pending_responses()
    assert budget.used == 3 and any(pause >= 0.5 for pause in pauses)
    assert len(batches) == 2 and batches[0].records[0] == cloudtrail["Records"][0]
    assert batches[0].location == batches[1].location


@pytest.mark.parametrize(
    ("response", "code"),
    [
        ({"Events": [{"CloudTrailEvent": "{"}]}, "malformed_event"),
        (
            {"Events": [{"CloudTrailEvent": '{"recipientAccountId":"999988887777"}'}]},
            "record_outside_scope",
        ),
    ],
)
def test_history_rejects_malformed_or_out_of_scope_events(
    aws_config, aws_window, fake_aws_session, response, code
):
    client = fake_aws_session.client("cloudtrail")
    with Stubber(client) as stub, pytest.raises(CollectionFailure, match=code):
        stub.add_response("lookup_events", response)
        list(
            CloudTrailHistory(aws_config, client, RequestBudget(3, pause=lambda _: None)).collect(
                aws_window
            )
        )


def test_expired_history_window_and_pagination_loop(aws_config, aws_window, fake_aws_session):
    client = fake_aws_session.client("cloudtrail")
    connector = CloudTrailHistory(aws_config, client, RequestBudget(4, pause=lambda _: None))
    old = CollectionRequest(start=aws_window.start - timedelta(days=100), end=aws_window.end)
    with pytest.raises(CollectionFailure, match="window_outside"):
        list(connector.collect(old))
    with Stubber(client) as stub, pytest.raises(CollectionFailure, match="pagination_loop"):
        for _ in range(2):
            stub.add_response("lookup_events", {"NextToken": "repeated"})
        list(connector.collect(aws_window))
