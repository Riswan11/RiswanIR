from sentinelforge.memory.baseline import evaluate
from sentinelforge.memory.intelligence import compare
from sentinelforge.memory.models import Feedback, MemoryPolicy, Observation, Profile


def observation(day, index, *, operation="GetObject", network="known", hour=3):
    return Observation(
        reference=f"reference-{day}-{index}",
        raw_reference=f"raw-{day}-{index}",
        observed_at=f"2025-01-{day:02d}T{hour:02d}:{index:02d}:00Z",
        scope="aws:111122223333",
        dimensions={"identity": "scoped-identity"},
        operation=operation,
        service="s3",
        hour=hour,
        weekday=(day + 1) % 7,
        network=network,
        network_range=network,
        privilege_target="routine" if operation == "GetObject" else "new-role",
    )


def test_cold_start_seasonality_frequency_and_drift():
    current = [
        observation(13, index, operation="PutBucketPolicy", network="new", hour=9)
        for index in range(5)
    ]
    prior = [
        observation(day, index)
        for day, count in [(1, 1), (2, 1), (8, 3), (9, 3)]
        for index in range(count)
    ]
    (baseline,) = evaluate(current, prior + [prior[0]], MemoryPolicy())
    assert baseline.samples == 8 and baseline.historical_days == 4
    assert baseline.state == "established" and baseline.expected_daily_count == 2
    assert baseline.seasonal_bucket == "weekday" and baseline.baseline_drift
    assert {
        "unusual_operation",
        "unusual_network",
        "unusual_hour",
        "unusual_network_range",
        "unusual_privilege_target",
    } <= set(baseline.signals)
    (cold,) = evaluate(current, prior[:1], MemoryPolicy())
    assert cold.state == "cold_start" and cold.signals == []


def test_similarity_needs_coverage_and_penalizes_missing_factors():
    common = {"attack_patterns": ["same"], "identity_privilege": ["same"], "mitre": ["same"]}
    base = dict(
        lineage_id="0" * 32,
        created_at="2025-01-01T00:00:00Z",
        scope=["aws:111122223333"],
        complete_scope=True,
        patterns={},
        observations=[],
        evidence_references=["ref"],
        raw_references=["raw"],
    )
    current = Profile(case_id="1" * 32, factors=common, **base)
    prior = Profile(case_id="2" * 32, factors=common, **base)
    feedback = Feedback(classification="confirmed_threat", evidence_references=["ref"])
    match = compare(current, prior, feedback, MemoryPolicy())
    assert match.coverage == 60 and match.similarity_score == 0.6
    assert "resources" in match.missing_factors
    assert compare(current, prior, feedback, MemoryPolicy(minimum_coverage=65)) is None
