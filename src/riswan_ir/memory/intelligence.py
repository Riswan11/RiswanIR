"""Retrieve scoped historical context, pattern recurrence, and baselines."""

import sqlite3
from datetime import timedelta
from fractions import Fraction

from riswan_security_data.integrity import canonical_json, sha256

from ..core.fields import utc_timestamp
from . import repository
from .baseline import evaluate
from .models import WEIGHTS, Feedback, HistoricalMatch, Intelligence, MemoryPolicy, Pattern, Profile
from .policy import allowed


def compare(
    current: Profile,
    historical: Profile,
    feedback: Feedback,
    config: MemoryPolicy,
) -> HistoricalMatch | None:
    scores = {}
    missing = []
    coverage = 0
    total = Fraction()
    for name, weight in WEIGHTS.items():
        left = set(current.factors.get(name, []))
        right = set(historical.factors.get(name, []))
        if not left or not right:
            missing.append(name)
            continue
        coverage += weight
        similarity = Fraction(len(left & right), len(left | right))
        scores[name] = float(similarity)
        total += similarity * Fraction(weight, 100)
    if coverage < config.minimum_coverage or total < Fraction(3, 10):
        return None
    return HistoricalMatch(
        investigation_id=historical.case_id,
        similarity_score=float(total),
        coverage=coverage,
        factor_scores=scores,
        missing_factors=missing,
        classification=feedback.classification,
        evidence_references=sorted(feedback.evidence_references)[:30],
    )


def retrieve(
    db: sqlite3.Connection,
    profile: Profile,
    config: MemoryPolicy,
    as_of: str,
    current: str,
    *,
    log: bool = True,
    authorization: MemoryPolicy | None = None,
    case_ids: tuple[str, ...] | None = None,
) -> Intelligence:
    cutoff = utc_timestamp(as_of)
    if cutoff > utc_timestamp(current) or cutoff < utc_timestamp(profile.created_at):
        raise ValueError("Historical cutoff must fall between case creation and the present.")
    security = authorization or config
    scopes = allowed(profile.scope, config) & allowed(profile.scope, security)
    config = config.model_copy(
        update={
            "enabled_categories": config.enabled_categories & security.enabled_categories,
        }
    )
    cross_categories = (
        config.cross_account_categories
        & security.cross_account_categories
        & config.enabled_categories
    )
    foreign_config = config.model_copy(update={"enabled_categories": cross_categories})
    after = (cutoff - timedelta(days=config.observation_days)).isoformat()
    ids = repository.candidates(db, scopes, as_of, after, case_ids)
    prior = []
    used = set(profile.raw_references)
    lineages = {profile.lineage_id}
    limitations = []
    if not scopes:
        limitations.append("Account scope could not be authorized for historical retrieval.")
    if len(ids) > 100:
        limitations.append("Historical retrieval was limited to 100 candidate cases.")
    for case_id in ids[:100]:
        if case_id == profile.case_id or "feedback" not in config.enabled_categories:
            continue
        history = repository.read(db, case_id, config, current)
        feedback = repository.classification(db, case_id, as_of, current)
        if history is None or feedback is None or not set(history.scope) <= scopes:
            continue
        if set(history.scope) != set(profile.scope):
            if "feedback" not in cross_categories:
                continue
            history = repository.read(db, case_id, foreign_config, current)
            if history is None:
                continue
        if not set(feedback.evidence_references) <= set(history.evidence_references):
            continue
        if history.lineage_id in lineages or used.intersection(history.raw_references):
            continue
        lineages.add(history.lineage_id)
        used.update(history.raw_references)
        prior.append((history, feedback))
    matches = [
        match
        for history, feedback in prior
        if (match := compare(profile, history, feedback, config)) is not None
    ]
    matches.sort(key=lambda item: (-item.similarity_score, item.investigation_id))
    patterns = []
    recurrence = {}
    for name in sorted(profile.patterns):
        previous = [(history, feedback) for history, feedback in prior if name in history.patterns]
        confirmed = sum(
            feedback.classification == "confirmed_threat"
            and bool(set(feedback.evidence_references) & set(history.patterns[name]))
            for history, feedback in previous
        )
        false_positive = sum(
            feedback.classification == "false_positive" for _, feedback in previous
        )
        if len(previous) >= 2:
            patterns.append(
                Pattern(
                    pattern=name,
                    cases=len(previous),
                    confirmed_cases=confirmed,
                    false_positive_cases=false_positive,
                    evidence_references=sorted(
                        {ref for history, _ in previous for ref in history.patterns[name]}
                    )[:30],
                )
            )
        if confirmed >= 2 and name.startswith("SF-"):
            recurrence[name] = min(100, confirmed * 25)
    patterns.sort(key=lambda item: (-item.confirmed_cases, -item.cases, item.pattern))
    behavioral = []
    if "behavioral" in config.enabled_categories:
        eligible = (
            event
            for history, feedback in prior
            if feedback.classification == "authorized_activity"
            for event in history.observations
            if event.reference in set(feedback.evidence_references)
            if utc_timestamp(event.observed_at) >= cutoff - timedelta(days=config.observation_days)
        )
        behavioral = evaluate(profile.observations, eligible, config)
    if not prior:
        limitations.append("No eligible reviewed history was available in the observation window.")
    if any(item.state == "cold_start" for item in behavioral):
        limitations.append("Some activity groups have insufficient approved baseline observations.")
    result = Intelligence(
        investigation_id=profile.case_id,
        as_of=repository.time_key(as_of),
        memory_policy_version=config.version,
        policy_digest=sha256(
            canonical_json(
                {
                    "evaluation": repository.policy_digest(config),
                    "authorization": repository.policy_digest(security),
                }
            )
        ),
        similar_investigations=matches[:10],
        behavioral_baselines=behavioral,
        recurring_patterns=patterns[:25],
        historical_recurrence=recurrence,
        procedural_guidance=[
            config.playbooks[name]
            for name in sorted(config.playbooks)
            if name in profile.patterns and "procedural" in config.enabled_categories
        ],
        response_history={
            history.case_id: refs
            for history, _ in prior
            if "response" in config.enabled_categories
            and (set(history.scope) == set(profile.scope) or "response" in cross_categories)
            and (refs := repository.response(db, history.case_id, current, as_of))
            and set(refs) <= set(history.evidence_references)
        },
        recommendations=["Review the supporting events and validate the business explanation."]
        if matches or behavioral
        else [],
        limitations=limitations,
    )
    if log:
        repository.audit(
            db,
            profile.case_id,
            "retrieve",
            current,
            config,
            sha256(canonical_json(result.model_dump(mode="json"))),
        )
    return result
