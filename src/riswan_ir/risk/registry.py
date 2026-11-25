"""Load validated policies and local scoring inventory."""

from functools import lru_cache
from importlib.resources import files
from pathlib import Path

from ..core.config import setting
from ..detection.registry import MAX_BYTES, load_rule_rows
from .models import RiskInventory, ScoringPolicy


def load_policies(data: bytes) -> list[ScoringPolicy]:
    policies = [ScoringPolicy.model_validate(row) for row in load_rule_rows(data)]
    if len({(item.id, item.version) for item in policies}) != len(policies):
        raise ValueError("Duplicate scoring policy version.")
    return policies


@lru_cache(maxsize=1)
def default_policy() -> ScoringPolicy:
    return load_policies(files(__package__).joinpath("default.yml").read_bytes())[0]


def active_policy() -> ScoringPolicy:
    path = setting("RISK_POLICY")
    if not path:
        return default_policy()
    with Path(path).open("rb") as source:
        policies = load_policies(source.read(MAX_BYTES + 1))
    product = [policy for policy in policies if policy.id == "security-intelligence"]
    if not product:
        raise ValueError("No Security Intelligence scoring policy was provided.")
    return max(product, key=lambda item: tuple(map(int, item.version.split("."))))


def inventory() -> RiskInventory:
    path = setting("RISK_INVENTORY")
    if not path:
        return RiskInventory()
    with Path(path).open("rb") as source:
        data = source.read(1_000_001)
    if len(data) > 1_000_000:
        raise ValueError("Risk inventory file is too large.")
    return RiskInventory.model_validate_json(data)
