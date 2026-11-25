"""Evaluate authorized historical activity against current observation groups."""

from collections import Counter, defaultdict
from collections.abc import Iterable
from statistics import median

from ..core.fields import utc_timestamp
from .models import Baseline, MemoryPolicy, Observation

MAX_BASELINES = 24


def evaluate(
    current: list[Observation],
    history: Iterable[Observation],
    config: MemoryPolicy,
) -> list[Baseline]:
    observed: dict[tuple[str, str], list[Observation]] = defaultdict(list)
    prior: dict[tuple[str, str], list[Observation]] = defaultdict(list)
    for event in current:
        for kind, key in event.dimensions.items():
            observed[(kind, key)].append(event)
    first = min((utc_timestamp(item.observed_at) for item in current), default=None)
    seen = set()
    for event in history:
        if (
            event.raw_reference in seen
            or first is None
            or utc_timestamp(event.observed_at) >= first
        ):
            continue
        seen.add(event.raw_reference)
        for kind, key in event.dimensions.items():
            if (kind, key) in observed:
                prior[(kind, key)].append(event)
    result = []
    for (kind, key), entries in sorted(observed.items())[:MAX_BASELINES]:
        source = sorted(prior[(kind, key)], key=lambda item: (item.observed_at, item.raw_reference))
        weekend = entries[0].weekday >= 5
        seasonal = [item for item in source if (item.weekday >= 5) == weekend]
        bucket = "all"
        if (
            all((item.weekday >= 5) == weekend for item in entries)
            and len(seasonal) >= config.minimum_samples
        ):
            source = seasonal
            bucket = "weekend" if weekend else "weekday"
        daily = Counter(item.observed_at[:10] for item in source)
        current_count = max(Counter(item.observed_at[:10] for item in entries).values())
        established = len(source) >= config.minimum_samples and len(daily) >= 2
        expected = sum(daily.values()) / len(daily) if established else None
        signals = []
        drift = False
        if established:
            for name, getter in (
                ("unusual_operation", lambda event: event.operation),
                ("unusual_network", lambda event: event.network),
                ("unusual_authentication", lambda event: event.authentication),
                ("unusual_hour", lambda event: event.hour),
                ("unusual_resource", lambda event: event.dimensions.get("resource")),
            ):
                known = {value for item in source if (value := getter(item)) is not None}
                if known and any(
                    (value := getter(item)) is not None and value not in known for item in entries
                ):
                    signals.append(name)
            if expected is not None and current_count >= max(3, expected * 3):
                signals.append("unusual_daily_frequency")
            if len(daily) >= 4:
                counts = [daily[day] for day in sorted(daily)]
                split = len(counts) // 2
                drift = median(counts[split:]) >= median(counts[:split]) * 2
        result.append(
            Baseline(
                subject_type=kind,
                subject_key=key,
                state="established" if established else "cold_start",
                samples=len(source),
                historical_days=len(daily),
                seasonal_bucket=bucket,
                observed_count=current_count,
                expected_daily_count=expected,
                baseline_drift=drift,
                signals=signals,
                evidence_references=sorted({item.reference for item in source})[:30],
            )
        )
    return result
