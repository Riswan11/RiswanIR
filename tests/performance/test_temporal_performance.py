from datetime import datetime, timedelta, timezone
from time import perf_counter

from riswan_ir.correlation.temporal.engine import MAX_ACTIVE, run
from riswan_ir.correlation.temporal.models import TemporalPolicy
from riswan_ir.correlation.temporal.registry import default_rules, select_rules
from tests.integration.test_temporal_correlation import activity, create


def test_temporal_benchmark_bounds_active_matches(store, record_property):
    start_time = datetime(2021, 1, 22, tzinfo=timezone.utc)
    rows = []
    for index in range(2000):
        row = activity(f"event-{index}", 1, "cloudtrail", "StopLogging")
        row["eventTime"] = (start_time + timedelta(seconds=index)).isoformat()
        rows.append(row)
    report = create(store, rows)
    graph = store.security_graph(report.id)
    start = perf_counter()
    result = run(report, graph, select_rules(default_rules()), TemporalPolicy(), {}, report.id)
    elapsed = perf_counter() - start
    record_property("temporal_elapsed_seconds", round(elapsed, 4))
    record_property("temporal_events_per_second", round(2000 / elapsed))
    assert result.metrics.events == 2000
    assert len(result.partial_matches) == MAX_ACTIVE
    assert result.metrics.truncated_states > 0
    assert elapsed < 10
