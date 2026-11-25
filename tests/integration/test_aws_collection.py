import gzip
import io
import json

import boto3
import pytest
from botocore.response import StreamingBody
from botocore.stub import Stubber

from trailhound.connectors import registry
from trailhound.connectors.aws.authentication import log_prefix
from trailhound.evidence.redaction import redact_record
from trailhound.ingestion.orchestrator import run_collection


def test_moto_s3_collection_reaches_custody(store, s3_config, aws_window, cloudtrail, monkeypatch):
    moto = pytest.importorskip("moto")
    with moto.mock_aws():
        monkeypatch.setenv("AWS_SESSION_TOKEN", "fixture-session")
        s3 = boto3.client("s3", region_name=s3_config.s3.bucket_region)
        s3.create_bucket(Bucket=s3_config.s3.bucket)
        key = log_prefix(s3_config) + aws_window.start.strftime("%Y/%m/%d/") + "cloudtrail.json.gz"
        event = {**cloudtrail["Records"][0], "eventTime": aws_window.start.isoformat()}
        s3.put_object(
            Bucket=s3_config.s3.bucket,
            Key=key,
            Body=gzip.compress(json.dumps({"Records": [event]}).encode()),
        )
        result = run_collection(store, s3_config, aws_window)
    assert result.error is None and result.persisted == 1 and result.requests == 3
    report = store.list()[0]
    exported = store.export_evidence(report.id)
    assert exported["raw_evidence"][0]["record"] == redact_record(event)
    provenance = exported["provenance"][0]
    assert provenance["source_location"] == f"s3://{s3_config.s3.bucket}/{key}"
    assert provenance["collection_method"] == "connector"
    assert provenance["source_account_id"] == s3_config.account.account_id
    assert provenance["source_region"] == s3_config.account.region


def test_both_sources_dispatch_through_registry_and_persist(
    store, aws_config, s3_config, aws_window, fake_aws_session, cloudtrail, monkeypatch
):
    clients = {service: fake_aws_session.client(service) for service in ("s3", "cloudtrail")}
    monkeypatch.setattr(registry, "authenticated_session", lambda *_: fake_aws_session)
    monkeypatch.setattr(
        registry, "service_client", lambda _session, service, _region: clients[service]
    )
    event = {**cloudtrail["Records"][0], "eventTime": aws_window.start.isoformat()}
    prefix = log_prefix(s3_config) + aws_window.start.strftime("%Y/%m/%d/")
    key = prefix + "test.json.gz"
    data = gzip.compress(json.dumps({"Records": [event]}).encode())
    with Stubber(clients["s3"]) as s3, Stubber(clients["cloudtrail"]) as trail:
        s3.add_response("list_objects_v2", {"Contents": [{"Key": key, "Size": len(data)}]})
        s3.add_response("get_object", {"Body": StreamingBody(io.BytesIO(data), len(data))})
        trail.add_response("lookup_events", {"Events": [{"CloudTrailEvent": json.dumps(event)}]})
        assert run_collection(store, s3_config, aws_window).persisted == 1
        assert run_collection(store, aws_config, aws_window).persisted == 1
    assert len(store.list()) == 2
    for summary in store.list():
        bundle = store.export_evidence(summary.id)
        assert bundle["raw_evidence"][0]["record"] == redact_record(event)
        assert bundle["provenance"][0]["collection_method"] == "connector"
