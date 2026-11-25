"""Local forensic operations using the workstation account's file permissions."""

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

from riswan_app.composition import open_local_job_store
from riswan_app.local import local_context
from riswan_platform.core.context import bind_context
from riswan_platform.core.exceptions import ContextRequiredError

from ..core.config import database_path, setting
from ..core.errors import NotFoundError
from ..models.chain_of_custody import EvidenceRetentionPolicy
from ..product import IRProduct


def write_export(path: Path, payload: dict[str, object]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, indent=2)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path(database_path()))
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("investigation_id")
    export = commands.add_parser("export")
    export.add_argument("investigation_id")
    export.add_argument("output", type=Path)
    expire = commands.add_parser("expire")
    expire.add_argument("--days", type=int, required=True)
    expire.add_argument("--confirm", action="store_true", required=True)
    args = parser.parse_args()
    if not args.db.is_file():
        print("Evidence database was not found.", file=sys.stderr)
        return 1
    try:
        with bind_context(
            local_context(setting("MODE"), IRProduct().product_id, actor_type="service")
        ):
            store = open_local_job_store(args.db)
            if args.command == "verify":
                result = store.verify_evidence(args.investigation_id)
                print(json.dumps({"valid": result.valid, **result.payload()}))
                return 0 if result.valid else 1
            if args.command == "export":
                write_export(args.output, store.export_evidence(args.investigation_id))
                print("Forensic export saved.")
                return 0
            count = store.expire_evidence(EvidenceRetentionPolicy(days=args.days))
            print(f"Expired {count} retained raw payloads.")
            return 0
    except ContextRequiredError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (ValueError, OSError, NotFoundError, sqlite3.Error):
        print(
            "Evidence operation failed. Check the case, integrity, policy, and output path.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
