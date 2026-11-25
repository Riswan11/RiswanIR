from fractions import Fraction

import pytest

from sentinelforge.risk.engine import calculate, classify, weighted
from sentinelforge.risk.models import AssessmentInputs, Factor, ScoringPolicy, Subject
from sentinelforge.risk.registry import default_policy

NOW = "2026-01-01T00:00:00Z"


def standard_inputs():
    return AssessmentInputs(
        subject=Subject(
            kind="finding",
            id="test",
            rule_id="rule",
            declared_severity="high",
            event_ids=["example"],
        ),
        risk={
            name: Factor(value=value, status="observed", explanation="Synthetic evaluation input.")
            for name, value in zip(
                default_policy().risk, [95, 90, 100, 70, 85, 90, 40], strict=True
            )
        },
        confidence={
            "evidence_integrity": Factor(
                value=45, status="inferred", explanation="Limited evidence."
            )
        },
        evidence_references=["example"],
    )


def test_reference_calculation_and_sensitivity():
    inputs = standard_inputs()
    policy = default_policy()
    baseline = calculate("test", inputs, policy, NOW, "initial").assessment
    assert baseline.risk.score == 87.5
    assert baseline.severity == "high"
    assert baseline.confidence.score == 45
    assert baseline.confidence.assessed_weight == 20
    assert baseline.investigation_priority == "P1"
    for name in policy.risk:
        factors = {**inputs.risk, name: inputs.risk[name].model_copy(update={"value": 0})}
        adjusted = calculate(
            "test", inputs.model_copy(update={"risk": factors}), policy, NOW, "initial"
        ).assessment
        assert adjusted.risk.score == pytest.approx(
            87.5 - policy.risk[name] * inputs.risk[name].value / 100
        )
        assert adjusted.confidence == baseline.confidence


@pytest.mark.parametrize(
    ("exact", "expected"),
    [
        (Fraction(0), "informational"),
        (Fraction(1999, 100), "informational"),
        (Fraction(20), "low"),
        (Fraction(40), "medium"),
        (Fraction(70), "high"),
        (Fraction(8999, 100), "high"),
        (Fraction(90), "critical"),
        (Fraction(100), "critical"),
        (None, None),
    ],
)
def test_unrounded_severity_boundaries(exact, expected):
    assert classify(exact, default_policy()) == expected


def test_missing_and_conflicting_evidence_preserve_urgent_review():
    inputs = standard_inputs()
    inputs.risk = {
        "threat_impact": Factor(
            value=100, status="inferred", explanation="Critical potential harm."
        )
    }
    inputs.confidence = {
        "evidence_integrity": Factor(
            value=0, status="conflicting", explanation="Conflicting receipt."
        )
    }
    snapshot = calculate("case", inputs, default_policy(), NOW, "initial").assessment
    assert snapshot.severity == "critical" and snapshot.risk.assessed_weight == 25
    assert snapshot.investigation_priority == "P1"
    assert snapshot.assessment_status == "provisional"
    assert snapshot.confidence.score == 0
    unknown, exact = weighted({"optional": 100}, {})
    assert exact is None and unknown.score is None and unknown.assessed_weight == 0
    assert unknown.contributions[0].contribution is None


def test_provider_independent_factor_names_and_configurable_thresholds():
    policy = ScoringPolicy(
        id="example",
        version="2.0.0",
        risk={"domain_specific": 100},
        confidence={"observation_quality": 100},
        severity_thresholds=[10, 30, 60, 85],
    )
    inputs = standard_inputs()
    inputs.risk = {
        "domain_specific": Factor(value=87, status="observed", explanation="Domain input.")
    }
    inputs.confidence = {
        "observation_quality": Factor(value=92, status="observed", explanation="Domain proof.")
    }
    result = calculate("case", inputs, policy, NOW, "initial").assessment
    assert (result.risk.score, result.confidence.score) == (87, 92)
    assert result.investigation_priority == "P0"
