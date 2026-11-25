"""Resolve branded settings and retain existing local database paths."""

import os
from pathlib import Path


def setting(name: str, default: str | None = None) -> str | None:
    return os.getenv(f"RISWAN_IR_{name}", os.getenv(f"SENTINELFORGE_{name}", default))


def database_path() -> str:
    explicit = setting("DB")
    if explicit is not None:
        return explicit
    legacy = Path("sentinelforge.sqlite3")
    return str(legacy) if legacy.is_file() else "riswan-ir.sqlite3"
