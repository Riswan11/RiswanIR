"""Validate identifiers used at platform boundaries."""

import re


def require_label(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
        raise ValueError("Invalid platform identifier.")
    return value
