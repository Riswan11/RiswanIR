"""Replay verified investigation events against archived or selected detection rules."""

import argparse
import os
import sys
from pathlib import Path

from ..core.errors import NotFoundError
from ..storage.sqlite import Store
from .registry import RuleRegistry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("investigation_id")
    parser.add_argument(
        "--db", type=Path, default=Path(os.getenv("SENTINELFORGE_DB", "sentinelforge.sqlite3"))
    )
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--version", action="append", default=[], metavar="RULE_ID=VERSION")
    args = parser.parse_args()
    try:
        if not args.db.is_file():
            raise ValueError("Investigation database was not found.")
        versions: dict[str, str] = {}
        for spec in args.version:
            rule, separator, version = spec.partition("=")
            if not separator or not rule or not version or rule in versions:
                raise ValueError("Specify one version per rule as RULE_ID=VERSION.")
            versions[rule] = version
        registry = RuleRegistry.from_file(args.rules) if args.rules else None
        result = Store(args.db).replay_detection(
            args.investigation_id, versions=versions or None, registry=registry
        )
    except (OSError, ValueError, NotFoundError, RuntimeError):
        print(
            "Detection replay failed. Check the case, database, and selected rules.",
            file=sys.stderr,
        )
        return 1
    print(result.model_dump_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
