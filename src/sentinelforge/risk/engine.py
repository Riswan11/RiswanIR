"""Apply a weighted policy independently to risk and confidence."""

from fractions import Fraction

from ..evidence.integrity import canonical_json, sha256
from ..knowledge_graph.resolver import identifier
from .models import (
    Assessment,
    AssessmentInputs,
    Contribution,
    Dimension,
    Factor,
    RiskArchive,
    ScoringPolicy,
    Severity,
    Trigger,
)


def weighted(
    weights: dict[str, int], factors: dict[str, Factor]
) -> tuple[Dimension, Fraction | None]:
    unknown = Factor(status="unknown", explanation="No supporting context was available.")
    selected = {name: factors.get(name, unknown) for name in weights}
    assessed = sum(weight for name, weight in weights.items() if selected[name].value is not None)
    contributions = []
    total = Fraction()
    for name, weight in sorted(weights.items()):
        factor = selected[name]
        points = None if factor.value is None else Fraction(factor.value * weight, assessed)
        if points is not None:
            total += points
        contributions.append(
            Contribution(
                **dict(factor),
                factor=name,
                weight=weight,
                contribution=float(points) if points is not None else None,
            )
        )
    return Dimension(
        score=float(total) if assessed else None,
        assessed_weight=assessed,
        contributions=contributions,
    ), total if assessed else None


def classify(score: Fraction | None, policy: ScoringPolicy) -> Severity | None:
    if score is None:
        return None
    return list(Severity)[sum(score >= threshold for threshold in policy.severity_thresholds)]


def calculate(
    investigation_id: str,
    inputs: AssessmentInputs,
    policy: ScoringPolicy,
    created_at: str,
    trigger: Trigger,
    original: Assessment | None = None,
    predecessor_id: str | None = None,
) -> RiskArchive:
    risk, risk_exact = weighted(policy.risk, inputs.risk)
    confidence, confidence_exact = weighted(policy.confidence, inputs.confidence)
    residual = None
    priority_score = risk_exact
    if inputs.residual_risk is not None:
        residual, priority_score = weighted(policy.risk, inputs.residual_risk)
    severity = classify(risk_exact, policy)
    priority_severity = classify(priority_score, policy)
    conflicting = any(item.status == "conflicting" for item in confidence.contributions)
    low_confidence = (
        conflicting or confidence_exact is None or confidence_exact < policy.confidence_review_below
    )
    if inputs.disposition == "benign":
        priority, action = (
            "P4",
            "Record the analyst's dismissal and retain the supporting evidence.",
        )
    elif priority_severity == Severity.CRITICAL:
        priority, action = (
            (
                "P1",
                "Validate missing or contradictory evidence promptly and escalate if corroborated.",
            )
            if low_confidence
            else ("P0", "Investigate immediately.")
        )
    elif priority_severity == Severity.HIGH:
        priority, action = "P1", "Expedite evidence validation and investigation."
    elif priority_severity == Severity.MEDIUM or priority_severity is None:
        priority, action = "P2", "Schedule investigation and resolve missing context."
    elif priority_severity == Severity.LOW:
        priority, action = "P3", "Monitor and review."
    else:
        priority, action = "P4", "Record for context."
    status = (
        "dismissed"
        if inputs.disposition == "benign"
        else "analyst_validated"
        if inputs.disposition == "confirmed"
        else "provisional"
        if low_confidence
        or risk.assessed_weight < 100
        or confidence.assessed_weight < 100
        or any(item.status == "conflicting" for item in confidence.contributions)
        else "assessed"
    )
    digest = sha256(canonical_json(policy.model_dump(mode="json")))
    inputs_digest = sha256(canonical_json(inputs.model_dump(mode="json")))
    assessment_id = identifier(
        investigation_id,
        inputs.subject.kind,
        inputs.subject.id,
        digest,
        inputs_digest,
        trigger,
        predecessor_id,
    )
    assessment = Assessment(
        id=assessment_id,
        investigation_id=investigation_id,
        subject_kind=inputs.subject.kind,
        subject_id=inputs.subject.id,
        previous_assessment_id=predecessor_id,
        original_assessment_id=original.original_assessment_id if original else assessment_id,
        original_risk_score=original.original_risk_score if original else risk.score,
        policy_id=policy.id,
        policy_version=policy.version,
        policy_digest=digest,
        created_at=created_at,
        trigger=trigger,
        risk=risk,
        confidence=confidence,
        residual_risk=residual,
        severity=severity,
        investigation_priority=priority,
        recommended_action=action,
        assessment_status=status,
        missing_context=sorted(
            {
                f"{dimension}.{item.factor}"
                for dimension, scores in (("risk", risk), ("confidence", confidence))
                for item in scores.contributions
                if item.status == "unknown"
            }
        ),
        evidence_references=inputs.evidence_references,
        containment_reference=inputs.containment_reference,
    )
    return RiskArchive(assessment=assessment, inputs=inputs, policy=policy)
