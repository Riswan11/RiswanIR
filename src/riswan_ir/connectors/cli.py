"""Run or inspect authorized, read-only telemetry collection from the workstation."""

import argparse
import json
import logging
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import TypeAdapter

from riswan_app.composition import open_local_job_store
from riswan_app.local import local_context
from riswan_platform.core.context import bind_context
from riswan_platform.core.exceptions import ContextRequiredError

from ..core.config import database_path, setting
from ..ingestion.orchestrator import next_window, run_collection
from ..ingestion.ports import CollectionRepository
from ..models.collection import CollectionRequest
from ..models.connector import ConnectorConfig
from ..product import IRProduct
from ..storage import checkpoint_store


def run_due(
    store: CollectionRepository,
    configs: list[ConnectorConfig],
    due: dict[str, float],
    backfill: CollectionRequest | None,
) -> bool:
    failed = False
    for config in configs:
        if time.monotonic() < due.get(config.scope, 0):
            continue
        window = backfill or next_window(store, config, datetime.now(timezone.utc))
        if window and run_collection(store, config, window).error:
            failed = True
        due[config.scope] = time.monotonic() + config.interval_seconds
    return failed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--db", type=Path, default=Path(database_path()))
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--watch", action="store_true")
    run.add_argument("--start")
    run.add_argument("--end")
    commands.add_parser("status")
    args = parser.parse_args()
    try:
        with bind_context(
            local_context(setting("MODE"), IRProduct().product_id, actor_type="service")
        ):
            configs = TypeAdapter(list[ConnectorConfig]).validate_json(args.config.read_bytes())
            if not configs or len({config.scope for config in configs}) != len(configs):
                raise ValueError
            store = open_local_job_store(args.db)
            if args.command == "status":
                with store.connect() as db:
                    for config in configs:
                        health = checkpoint_store.load_status(db, config.scope)
                        progress = checkpoint_store.checkpoint(db, config.scope)
                        print(
                            json.dumps(
                                {
                                    "scope": config.scope,
                                    "kind": config.kind,
                                    "health": health.payload() if health else None,
                                    "checkpoint": progress.payload() if progress else None,
                                }
                            )
                        )
                return 0
            backfill = None
            if args.start or args.end:
                if not args.start or not args.end or args.watch:
                    raise ValueError
                backfill = CollectionRequest.model_validate(
                    {"start": args.start, "end": args.end, "incremental": False}
                )
                if backfill.end > datetime.now(timezone.utc) or any(
                    backfill.end - backfill.start > timedelta(minutes=config.window_minutes)
                    for config in configs
                ):
                    raise ValueError
            logging.basicConfig(level=logging.INFO, format="%(message)s")
            due: dict[str, float] = {}
            while True:
                failed = run_due(store, configs, due, backfill)
                if not args.watch:
                    return int(failed)
                time.sleep(max(0.1, min(due.values()) - time.monotonic()))
    except ContextRequiredError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except (ValueError, OSError, sqlite3.Error):
        print(
            "Collection setup failed. Check configuration, time range, and database access.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
