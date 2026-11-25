"""Evaluate scoring rules against normalized investigation evidence."""

from ..models import Finding, RiskAssessment, Severity
from ..models.canonical_event import SecurityEvent

RULES = (
    ("role-assumption", 20, "Role assumption observed", "T1078", ("AssumeRole",), 1),
    ("object-read", 20, "Successful object read recorded", None, ("GetObject",), 1),
    ("key-creation", 15, "Access key creation recorded", "T1098.001", ("CreateAccessKey",), 1),
    ("policy-attachment", 15, "User policy attachment recorded", "T1098", ("AttachUserPolicy",), 1),
    (
        "repeated-key-creation",
        10,
        "Multiple access key creations recorded",
        "T1098.001",
        ("CreateAccessKey",),
        2,
    ),
    (
        "role-then-key",
        20,
        "Access key created downstream of a role assumption",
        "T1098.001",
        ("AssumeRole", "CreateAccessKey"),
        1,
    ),
)


def rule_evidence(
    evidence: list[SecurityEvent], events: tuple[str, ...], minimum: int
) -> list[str]:
    if len(events) == 1:
        ids = [item.id for item in evidence if item.activity.name == events[0]]
        return ids if len(ids) >= minimum else []
    by_id = {item.id: item for item in evidence}
    for item in evidence:
        if item.activity.name != events[-1]:
            continue
        matched = [item.id]
        ancestor = item.linked_from_evidence_id
        for event in reversed(events[:-1]):
            while ancestor and by_id[ancestor].activity.name != event:
                ancestor = by_id[ancestor].linked_from_evidence_id
            if not ancestor:
                break
            matched.append(ancestor)
            ancestor = by_id[ancestor].linked_from_evidence_id
        if len(matched) == len(events):
            return list(reversed(matched))
    return []


def assess(evidence: list[SecurityEvent]) -> RiskAssessment:
    claims = []
    score = 0
    for rule_id, weight, summary, technique, events, minimum in RULES:
        event_ids = rule_evidence(evidence, events, minimum)
        if event_ids:
            score += weight
            claims.append(
                Finding(
                    rule_id=rule_id,
                    summary=summary,
                    evidence_ids=event_ids,
                    possible_attack_technique=technique,
                )
            )
    severity = (
        Severity.HIGH
        if score >= 50
        else Severity.MEDIUM
        if score >= 25
        else Severity.LOW
        if score
        else Severity.UNRATED
    )
    targets = sorted({item.activity.target for item in evidence if item.activity.target})
    return RiskAssessment(
        severity=severity,
        score=score,
        score_max=sum(rule[1] for rule in RULES),
        claims=claims,
        open_questions=[
            "Was the activity authorized?",
            "What happened outside the supplied records?",
            "Were any credential identifiers or issuance events missing from the export?",
        ],
        observed_targets=targets,
    )
