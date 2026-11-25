"""Resolve stable node and relationship identifiers without crossing scopes."""

from riswan_security_data.integrity import canonical_json, sha256


def identifier(*parts: str | None) -> str:
    return sha256(canonical_json(parts)).removeprefix("sha256:")
