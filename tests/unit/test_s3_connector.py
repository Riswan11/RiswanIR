import gzip
import io
import json

import pytest
from botocore.response import StreamingBody
from botocore.stub import Stubber

from trailhound.connectors.aws.requests import RequestBudget
from trailhound.connectors.aws.s3 import S3CloudTrailLogs
from trailhound.connectors.base import CollectionFailure


def test_s3_reads_gzip_with_expected_owner_and_paginates(
    s3_config, aws_window, fake_aws_session, cloudtrail
):
    s3 = fake_aws_session.client("s3")
    connector = S3CloudTrailLogs(s3_config, s3, RequestBudget(5))
    prefix = connector.prefix + aws_window.start.strftime("%Y/%m/%d/")
    key = prefix + "test.json.gz"
    event = {**cloudtrail["Records"][0], "eventTime": aws_window.start.isoformat()}
    body = gzip.compress(json.dumps({"Records": [event, cloudtrail["Records"][1]]}).encode())
    parameters = {
        "Bucket": s3_config.s3.bucket,
        "ExpectedBucketOwner": s3_config.s3.owner_account_id,
    }
    with Stubber(s3) as stub:
        stub.add_response(
            "list_objects_v2",
            {"IsTruncated": True, "NextContinuationToken": "next"},
            {**parameters, "Prefix": prefix},
        )
        stub.add_response(
            "list_objects_v2",
            {"Contents": [{"Key": key, "Size": len(body)}]},
            {**parameters, "Prefix": prefix, "ContinuationToken": "next"},
        )
        stub.add_response(
            "get_object",
            {"Body": StreamingBody(io.BytesIO(body), len(body))},
            {**parameters, "Key": key},
        )
        [batch] = list(connector.collect(aws_window))
        stub.assert_no_pending_responses()
    assert batch.records == [event]
    assert batch.location.endswith(key)


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        (b"broken gzip", "malformed_log"),
        (gzip.compress(b'{"Records":[null]}'), "malformed_log"),
        (gzip.compress(b'{"Records":{}}'), "malformed_log"),
        (gzip.compress(b"x" * 2048), "decompressed_limit_exceeded"),
        (b"x" * 2048, "object_limit_exceeded"),
    ],
)
def test_s3_invalid_or_oversized_objects(s3_config, aws_window, fake_aws_session, payload, error):
    s3_config.max_object_bytes = 1024
    client = fake_aws_session.client("s3")
    connector = S3CloudTrailLogs(s3_config, client, RequestBudget(4))
    with Stubber(client) as stub:
        stub.add_response("get_object", {"Body": StreamingBody(io.BytesIO(payload), len(payload))})
        with pytest.raises(CollectionFailure, match=error):
            list(connector.read(connector.prefix + "object.json.gz", aws_window))


@pytest.mark.parametrize(
    ("reply", "error"),
    [
        ({"Contents": [{"Key": "different-account/log.json.gz"}]}, "object_outside_scope"),
        ({"IsTruncated": True}, "pagination_loop"),
        (
            {"Contents": [{"Key": "allowed/log.json.gz", "Size": 99_000_000}]},
            "object_limit_exceeded",
        ),
    ],
)
def test_s3_list_constraints(s3_config, fake_aws_session, reply, error):
    client = fake_aws_session.client("s3")
    with Stubber(client) as stub:
        stub.add_response("list_objects_v2", reply)
        with pytest.raises(CollectionFailure, match=error):
            list(S3CloudTrailLogs(s3_config, client, RequestBudget(4)).keys("allowed/"))
