from datetime import datetime, timedelta, timezone

from riswan_ir.correlation.temporal.engine import run
from riswan_ir.correlation.temporal.models import Stage, TemporalPolicy
from riswan_ir.correlation.temporal.registry import default_rules, select_rules
from riswan_ir.storage.sqlite import Store
from tests.integration.test_temporal_correlation import (
    BUCKET,
    PREFIX,
    access,
    activity,
    context,
    create,
    create_key,
    scenario,
)


def test_sequence_requires_graph_link_and_strict_event_time(tmp_path):
    store = Store(tmp_path / "windows.sqlite3", detection_context=context())
    rule_id = PREFIX + "005"
    for variant in ("late", "same-time", "unrelated"):
        data = scenario(5)
        if variant == "late":
            data[1]["eventTime"] = "2021-01-22T00:32:00Z"
        elif variant == "same-time":
            data[1]["eventTime"] = "2021-01-21T19:01:00-05:00"
        else:
            data[1]["userIdentity"]["accessKeyId"] = "ASIASYNTHETICOTHER"
        report = create(store, data)
        assert rule_id not in {item.id for item in store.temporal_result(report.id).incidents}


def test_optional_stage_and_overlaps_are_deduplicated(tmp_path):
    store = Store(tmp_path / "optional.sqlite3", detection_context=context())
    data = [
        activity("stop-1", 1, "cloudtrail", "StopLogging"),
        activity("stop-2", 2, "cloudtrail", "StopLogging"),
        create_key(minute=3),
        access("read", 4),
    ]
    report = create(store, data)
    rule = select_rules(default_rules(), {PREFIX + "005": "1.0.0"})[0]
    optional = Stage(
        name="optional_credential", service="iam", operations=["CreateAccessKey"], optional=True
    )
    rule = rule.model_copy(update={"stages": [rule.stages[0], optional, rule.stages[-1]]})
    result = run(
        report,
        store.security_graph(report.id),
        [rule],
        TemporalPolicy(enrichment=context()),
        {},
        report.id,
    )
    (incident,) = result.incidents
    assert [item.event_id for item in incident.timeline] == ["stop-1", "create", "read"]
    assert result.metrics.suppressed == 1


def test_exclusion_uses_event_time_and_scoped_selectors(tmp_path):
    inventory = context()
    inventory = type(inventory).model_validate(
        {
            **inventory.model_dump(),
            "exceptions": [
                {
                    "id": "ticket-maintenance",
                    "rule_id": PREFIX + "005",
                    "approved_by": "Operator",
                    "reason": "Scheduled maintenance",
                    "starts_at": "2021-01-22T00:00:00Z",
                    "expires_at": "2021-01-22T00:03:00Z",
                    "match": {"resource.uid": BUCKET},
                }
            ],
        }
    )
    store = Store(tmp_path / "exceptions.sqlite3", detection_context=inventory)
    first = create(store, scenario(5))
    assert store.temporal_result(first.id).metrics.excluded == 1
    assert store.temporal_result(first.id).incidents == []
    data = scenario(5)
    data[-1]["eventTime"] = (
        datetime(2021, 1, 22, tzinfo=timezone.utc) + timedelta(minutes=3)
    ).isoformat()
    next_case = create(store, data)
    assert store.temporal_result(next_case.id).incidents
