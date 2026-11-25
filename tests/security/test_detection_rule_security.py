import pytest

from sentinelforge.detection.registry import MAX_BYTES, load_rules
from sentinelforge.models.detection import DetectionCondition


@pytest.mark.parametrize(
    "document",
    [
        b"- !!python/object/apply:os.system ['unused']",
        b"- &entry {id: sample}\n- *entry",
        b"- {id: one, id: two}",
        b"- [",
        b"{}",
        b" " * (MAX_BYTES + 1),
    ],
)
def test_rule_loader_rejects_unsafe_ambiguous_or_unbounded_input(document):
    with pytest.raises(ValueError):
        load_rules(document)


@pytest.mark.parametrize(
    "condition",
    [
        {"field": "__class__", "operator": "exists"},
        {"field": "actor.uid", "operator": "regex", "value": ".*"},
        {"field": "actor.uid", "operator": "in", "value": "abc"},
        {"field": "actor.mfa", "operator": "gte", "value": True},
        {"field": "actor.uid", "operator": "exists", "value": "abc"},
    ],
)
def test_condition_schema_rejects_unknown_or_incompatible_constructs(condition):
    with pytest.raises(ValueError):
        DetectionCondition.model_validate(condition)
