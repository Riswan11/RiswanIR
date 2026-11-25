import pytest

from sentinelforge.investigation.correlation import correlate
from sentinelforge.normalization.cloudtrail import issued_credential, normalize


def test_normalized_fields_and_deduplication(investigation_request):
    records = investigation_request.records
    event = normalize(records[1])
    assert (
        event.source_ip,
        event.user_agent,
        event.region,
        event.account_id,
        event.recipient_account_id,
    ) == ("203.0.113.20", "synthetic-test-client", "us-east-1", "123456789012", "123456789012")
    rows = correlate([*records, records[0]], investigation_request.principal)
    assert [item.id for item in rows] == ["role-issued", "key-created", "key-used"]
    with pytest.raises(ValueError, match="Conflicting"):
        correlate(
            [*records, {**records[0], "awsRegion": "us-west-1"}], investigation_request.principal
        )


@pytest.mark.parametrize("value", [None, {}, {"eventID": "invalid", "eventTime": "bad-date"}])
def test_malformed_records(value):
    with pytest.raises(ValueError):
        normalize(value)


def test_role_alias_and_unparseable_expiry(cloudtrail):
    raw = cloudtrail["Records"][0]
    raw["eventName"] = "AssumeRoleWithSAML"
    raw["responseElements"]["credentials"]["expiration"] = "unknown"
    event = normalize(raw)
    assert (event.event, event.operation) == ("AssumeRole", "AssumeRoleWithSAML")
    key, arn, expiry = issued_credential(raw, event)
    assert key == "ASIAEXAMPLE" and arn.endswith("/Example/build")
    assert expiry is None
    assert issued_credential({**raw, "eventSource": "other.example"}, event) == (None, None, None)
