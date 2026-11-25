"""Resolve TrailHound settings with compatibility for existing installations."""

import os
from pathlib import Path


def database_path() -> Path:
    configured = os.getenv("TRAILHOUND_DB", os.getenv("SENTINELFORGE_DB"))
    if configured is not None:
        return Path(configured)
    legacy = Path("sentinelforge.sqlite3")
    if legacy.is_file():
        return legacy
    return Path("trailhound.sqlite3")


def server_port() -> int:
    return int(os.getenv("TRAILHOUND_PORT", os.getenv("SENTINELFORGE_PORT", "8000")))
