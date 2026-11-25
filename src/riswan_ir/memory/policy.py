"""Load local memory settings and apply complete account-set authorization."""

from pathlib import Path

from ..core.config import setting
from .models import MemoryPolicy


def policy() -> MemoryPolicy:
    path = setting("MEMORY_POLICY")
    if not path:
        return MemoryPolicy()
    with Path(path).open("rb") as stream:
        data = stream.read(256_001)
    if len(data) > 256_000:
        raise ValueError("Memory policy is too large.")
    return MemoryPolicy.model_validate_json(data)


def allowed(scopes: list[str], config: MemoryPolicy) -> set[str]:
    current = set(scopes)
    if not current:
        return set()
    for group in config.organization_accounts:
        if current <= set(group):
            return set(group)
    return current if len(current) == 1 else set()
