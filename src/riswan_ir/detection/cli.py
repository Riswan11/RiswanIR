"""Replay verified investigation events against archived or selected detection rules."""

import argparse
import sys
from pathlib import Path

from riswan_app.composition import open_local_job_store
from riswan_app.local import local_context
from riswan_platform.core.context import bind_context
from riswan_platform.core.exceptions import ContextRequiredError

from ..core.config import database_path, setting
from ..core.errors import NotFoundError
from ..product import IRProduct
from .registry import RuleRegistry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("investigation_id")
    parser.add_argument("--db", type=Path, default=Path(database_path()))
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--version", action="append", default=[], metavar="RULE_ID=VERSION")
    args = parser.parse_args()
    try:
        with bind_context(
            local_context(setting("MODE"), IRProduct().product_id, actor_type="service")
        ):
            if not args.db.is_file():
                raise ValueError("Investigation database was not found.")
            versions: dict[str, str] = {}
            for spec in args.version:
                rule, separator, version = spec.partition("=")
                if not separator or not rule or not version or rule in versions:
                    raise ValueError("Specify one version per rule as RULE_ID=VERSION.")
                versions[rule] = version
            registry = RuleRegistry.from_file(args.rules) if args.rules else None
            result = open_local_job_store(args.db).replay_detection(
                args.investigation_id, versions=versions or None, registry=registry
            )
    except ContextRequiredError as exc:
        print(str(exc), file=sys.stderr)
        return 1
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
