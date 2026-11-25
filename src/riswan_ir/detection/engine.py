"""Deterministic evaluation of canonical events against bounded declarative rules."""

import logging
from collections import defaultdict, deque
from collections.abc import Iterable
from datetime import datetime, timedelta
from itertools import islice

from ..core.fields import utc_timestamp
from ..evidence.integrity import canonical_json, sha256
from ..models.canonical_event import SecurityEvent, Status
from ..models.detection import (
    DetectionCondition,
    DetectionContext,
    DetectionExecution,
    DetectionReplayResult,
    DetectionResult,
    DetectionRule,
    DetectionRuleVersion,
    DetectionSnapshot,
    FieldPath,
    Scalar,
    SecurityFinding,
)
from .enrichment import Attributes, enrich
from .registry import MAX_RULES

ENGINE_VERSION = "1.0.0"
MAX_EVENTS = 2000
MAX_OUTCOMES = 4000
LOGGER = logging.getLogger(__name__)
Group = tuple[Scalar | None, ...]


def equals(actual: Scalar, expected: Scalar) -> bool:
    if isinstance(actual, str) and isinstance(expected, str):
        return actual == expected
    return type(actual) is type(expected) and actual == expected


def matches(condition: DetectionCondition, attributes: Attributes) -> bool:
    actual = attributes.get(condition.field)
    if actual is None:
        return False
    operand = condition.value
    match condition.operator:
        case "exists":
            return True
        case "in":
            return isinstance(operand, list) and any(equals(actual, item) for item in operand)
        case "gte" | "lte":
            if type(actual) is not int or type(operand) is not int:
                return False
            return actual >= operand if condition.operator == "gte" else actual <= operand
        case _:
            if operand is None or isinstance(operand, list):
                return False
            if type(actual) is not type(operand) and not (
                isinstance(actual, str) and isinstance(operand, str)
            ):
                return False
            equal = equals(actual, operand)
            return equal if condition.operator == "equals" else not equal


def group(attributes: Attributes, fields: list[FieldPath]) -> Group | None:
    values = tuple(attributes.get(field) for field in fields)
    return values if None not in values else None


def evaluate(
    events: Iterable[SecurityEvent], rules: list[DetectionRule], context: DetectionContext
) -> DetectionSnapshot:
    incoming = list(islice(events, MAX_EVENTS + 1))
    if len(incoming) > MAX_EVENTS or len(rules) > MAX_RULES:
        raise ValueError("Detection evaluation size exceeded.")
    by_id: dict[str, SecurityEvent] = {}
    for event in incoming:
        old = by_id.setdefault(event.id, event)
        if old != event:
            raise ValueError("Conflicting canonical event IDs.")
    ordered = sorted((utc_timestamp(event.observed_at), event.id) for event in by_id.values())
    rules = sorted(rules, key=lambda rule: (rule.id, rule.version))
    if len({rule.id for rule in rules}) != len(rules):
        raise ValueError("Detection requires one selected version per rule.")
    versions = [DetectionRuleVersion(id=rule.id, version=rule.version) for rule in rules]
    configuration = sha256(
        canonical_json(
            {
                "context": context.model_dump(mode="json"),
                "rules": [rule.model_dump(mode="json") for rule in rules],
            }
        )
    )
    exceptions = defaultdict(list)
    for entry in context.exceptions:
        exceptions[entry.rule_id].append(
            (utc_timestamp(entry.starts_at), utc_timestamp(entry.expires_at), entry)
        )
    active = [rule for rule in rules if rule.enabled]
    findings: list[SecurityFinding] = []
    decisions: list[DetectionResult] = []
    seen: set[tuple[str, str]] = set()
    counts: dict[tuple[str, Group], deque[tuple[datetime, str]]] = {}
    last: dict[tuple[str, Group], datetime] = {}
    evaluations = suppressed = excepted = 0

    for timestamp, event_id in ordered:
        event = by_id[event_id]
        attributes = enrich(event, context, seen)
        source = event.metadata.provider.casefold()
        outcome = event.outcome.status_id.name.lower()
        for rule in active:
            if (
                outcome not in rule.outcomes
                or rule.provider.casefold() != source
                or (rule.class_uid is not None and rule.class_uid != event.classification.class_uid)
            ):
                continue
            evaluations += 1
            if not all(matches(condition, attributes) for condition in rule.conditions):
                continue
            alternatives = [item for item in rule.any_conditions if matches(item, attributes)]
            if rule.any_conditions and not alternatives:
                continue
            if len(findings) + len(decisions) >= MAX_OUTCOMES:
                raise ValueError("Detection outcome limit exceeded.")
            excluded = next(
                (
                    entry
                    for start, end, entry in exceptions[rule.id]
                    if start <= timestamp < end
                    and all(
                        (observed := attributes.get(field)) is not None and equals(observed, value)
                        for field, value in entry.match.items()
                    )
                ),
                None,
            )
            if excluded:
                excepted += 1
                decisions.append(
                    DetectionResult(
                        id=rule.id,
                        version=rule.version,
                        evidence_id=event_id,
                        disposition="exception",
                        exception_id=excluded.id,
                    )
                )
                continue

            evidence_ids = [event_id]
            if rule.threshold:
                resolved = group(attributes, rule.threshold.fields)
                if resolved is None:
                    continue
                history = counts.setdefault(
                    (rule.id, resolved), deque(maxlen=rule.threshold.minimum)
                )
                cutoff = timestamp - timedelta(minutes=rule.threshold.window_minutes)
                while history and history[0][0] < cutoff:
                    history.popleft()
                history.append((timestamp, event_id))
                if len(history) < rule.threshold.minimum:
                    continue
                evidence_ids = [item_id for _, item_id in history]

            if rule.suppression:
                resolved = group(attributes, rule.suppression.fields)
                if resolved is not None:
                    key = (rule.id, resolved)
                    prior = last.get(key)
                    if prior and timestamp < prior + timedelta(
                        minutes=rule.suppression.window_minutes
                    ):
                        suppressed += 1
                        decisions.append(
                            DetectionResult(
                                id=rule.id,
                                version=rule.version,
                                evidence_id=event_id,
                                disposition="suppressed",
                            )
                        )
                        continue
                    last[key] = timestamp

            finding_key = sha256(canonical_json([rule.id, rule.version, evidence_ids]))
            findings.append(
                SecurityFinding(
                    id=rule.id,
                    version=rule.version,
                    idempotency_key=finding_key,
                    severity=rule.severity,
                    summary=rule.description,
                    evidence_ids=evidence_ids,
                    reasons=[*rule.conditions, *alternatives],
                    threshold=rule.threshold,
                    recommendation=rule.recommendation,
                    mitre=rule.mitre,
                )
            )
        actor, resource = attributes["actor.uid"], attributes["resource.uid"]
        if (
            event.outcome.status_id == Status.SUCCESS
            and attributes["activity.authentication"] is True
            and isinstance(actor, str)
            and isinstance(resource, str)
        ):
            seen.add((actor, resource))

    execution = DetectionExecution(
        engine_version=ENGINE_VERSION,
        configuration_digest=configuration,
        context_version=context.version,
        rules=versions,
        events=len(ordered),
        evaluations=evaluations,
        findings=len(findings),
        suppressed=suppressed,
        excepted=excepted,
    )
    LOGGER.info("Detection execution %s", execution.model_dump_json())
    return DetectionSnapshot(
        result=DetectionReplayResult(findings=findings, decisions=decisions, execution=execution),
        rules=rules,
        context=context,
    )
