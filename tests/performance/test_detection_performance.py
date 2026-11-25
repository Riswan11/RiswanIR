from time import perf_counter

from sentinelforge.detection.engine import MAX_EVENTS, evaluate
from sentinelforge.detection.registry import default_registry
from tests.unit.test_contextual_detection import POLICY, RESOURCE, canonical


def test_maximum_case_detection_throughput(record_property):
    template = canonical("template", 1, "s3", "GetObject", {"bucketName": RESOURCE})
    events = [template.model_copy(update={"id": f"event-{i:04d}"}) for i in range(MAX_EVENTS)]
    rules = default_registry().select()
    start = perf_counter()
    result = evaluate(events, rules, POLICY).result
    elapsed = perf_counter() - start
    record_property("detection_elapsed_seconds", round(elapsed, 4))
    record_property("detection_events_per_second", round(MAX_EVENTS / elapsed))
    assert result.execution.evaluations == MAX_EVENTS * len(rules)
    assert len(result.findings) == 2
    assert elapsed < 10
