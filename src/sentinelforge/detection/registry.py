"""Load bounded, strictly validated detection rule files."""

from collections.abc import Iterable, Mapping
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import cast

import yaml

from ..models.detection import DetectionRule

MAX_RULES = 100
MAX_BYTES = 256_000


class RuleLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[str, object]:
        keys = [key.value for key, _ in node.value if isinstance(key, yaml.ScalarNode)]
        if len(keys) != len(node.value) or len(set(keys)) != len(keys):
            raise ValueError("Rule mappings require unique scalar keys.")
        return cast(dict[str, object], super().construct_mapping(node, deep))


def load_rules(data: bytes) -> list[DetectionRule]:
    if len(data) > MAX_BYTES:
        raise ValueError("Rule file is too large.")
    try:
        for token in yaml.scan(data, Loader=yaml.SafeLoader):
            if isinstance(token, (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)):
                raise ValueError("Rule YAML cannot use aliases, anchors or explicit tags.")
        # RuleLoader derives from SafeLoader and rejects ambiguous mappings.
        rows = yaml.load(data, Loader=RuleLoader)  # nosec B506
    except (yaml.YAMLError, RecursionError):
        raise ValueError("Invalid detection rule YAML.") from None
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_RULES:
        raise ValueError("Rule YAML must contain a bounded nonempty list.")
    return [DetectionRule.model_validate(row) for row in rows]


def version_key(version: str) -> tuple[int, ...]:
    return tuple(map(int, version.split(".")))


class RuleRegistry:
    def __init__(self, rules: Iterable[DetectionRule]) -> None:
        self._versions: dict[tuple[str, str], DetectionRule] = {}
        for rule in rules:
            key = (rule.id, rule.version)
            if key in self._versions or len(self._versions) >= MAX_RULES:
                raise ValueError("Duplicate rule version or registry size exceeded.")
            self._versions[key] = rule

    @classmethod
    def from_file(cls, path: Path) -> "RuleRegistry":
        with path.open("rb") as source:
            return cls(load_rules(source.read(MAX_BYTES + 1)))

    def contains(self, rule_id: str, version: str) -> bool:
        return (rule_id, version) in self._versions

    def select(self, versions: Mapping[str, str] | None = None) -> list[DetectionRule]:
        if versions is not None:
            try:
                return [self._versions[key] for key in sorted(versions.items())]
            except KeyError:
                raise ValueError("Selected detection rule version is unavailable.") from None
        newest: dict[str, DetectionRule] = {}
        for key in sorted(self._versions, key=lambda pair: (pair[0], version_key(pair[1]))):
            newest[key[0]] = self._versions[key]
        return list(newest.values())


@lru_cache(maxsize=1)
def default_registry() -> RuleRegistry:
    data = files(__package__).joinpath("aws-rules.yml").read_bytes()
    return RuleRegistry(load_rules(data))
