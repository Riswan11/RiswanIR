"""Load versioned correlation rules using the common safe YAML reader."""

from collections.abc import Mapping
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

from ...detection.registry import MAX_BYTES, load_rule_rows, version_key
from .models import TemporalRule


def select_rules(
    rules: list[TemporalRule], versions: Mapping[str, str] | None = None
) -> list[TemporalRule]:
    by_version = {(rule.id, rule.version): rule for rule in rules}
    if len(by_version) != len(rules):
        raise ValueError("Duplicate correlation rule version.")
    if versions is not None:
        try:
            return [by_version[key] for key in sorted(versions.items())]
        except KeyError:
            raise ValueError("Selected correlation rule version is unavailable.") from None
    latest = {}
    for key in sorted(by_version, key=lambda pair: (pair[0], version_key(pair[1]))):
        latest[key[0]] = by_version[key]
    return list(latest.values())


def load_rules(data: bytes) -> list[TemporalRule]:
    rules = [TemporalRule.model_validate(row) for row in load_rule_rows(data)]
    select_rules(rules)
    return rules


def read_rules(path: Path) -> list[TemporalRule]:
    with path.open("rb") as source:
        return load_rules(source.read(MAX_BYTES + 1))


@lru_cache(maxsize=1)
def default_rules() -> list[TemporalRule]:
    return load_rules(files(__package__).joinpath("aws-rules.yml").read_bytes())
