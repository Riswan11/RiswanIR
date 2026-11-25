"""Collect and persist source batches before advancing the incremental watermark."""

import logging
import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from ..connectors.aws.requests import RequestBudget
from ..connectors.base import CollectionFailure, TelemetryConnector
from ..connectors.registry import create_connector
from ..models.collection import CollectionRequest, CollectionResult
from ..models.connector import (
    CollectionCheckpoint,
    CollectionError,
    ConnectorConfig,
    ConnectorStatus,
)
from ..storage import checkpoint_store
from ..storage.sqlite import Store
from .pipeline import persist

LOGGER = logging.getLogger("trailhound.ingestion.orchestrator")


def next_window(store: Store, config: ConnectorConfig, now: datetime) -> CollectionRequest | None:
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        interrupted = checkpoint_store.pending(db, config.scope)
        if interrupted:
            return interrupted
        checkpoint = checkpoint_store.checkpoint(db, config.scope)
        step = timedelta(minutes=config.window_minutes)
        if checkpoint is None:
            window = CollectionRequest(start=now - step, end=now)
        elif checkpoint.through >= now:
            return None
        else:
            start = checkpoint.through - timedelta(minutes=config.overlap_minutes)
            window = CollectionRequest(start=start, end=min(checkpoint.through + step, now))
        checkpoint_store.reserve(db, config.scope, window)
        return window


def run_collection(
    store: Store,
    config: ConnectorConfig,
    window: CollectionRequest,
    factory: Callable[[ConnectorConfig, RequestBudget], TelemetryConnector] = create_connector,
) -> CollectionResult:
    started = datetime.now(timezone.utc)
    budget = RequestBudget(config.max_requests)
    received = persisted = 0
    error = None
    try:
        connector = factory(config, budget)
        for batch in connector.collect(window):
            received += len(batch.records)
            if received > config.max_events:
                raise CollectionFailure("collect", "event_budget_exceeded")
            persisted += persist(store, config, batch, datetime.now(timezone.utc))
    except CollectionFailure as exc:
        error = exc.error
    except (sqlite3.Error, RuntimeError):
        error = CollectionError(operation="persist", code="storage_error")
    status = ConnectorStatus(
        scope=config.scope, attempted_at=started, healthy=error is None, error=error
    )
    with store.connect() as db:
        if error is None and window.incremental:
            checkpoint_store.save_checkpoint(
                db, CollectionCheckpoint(scope=config.scope, through=window.end)
            )
            checkpoint_store.release(db, config.scope, window)
        checkpoint_store.save_status(db, status)
    result = CollectionResult(
        scope=config.scope,
        window=window,
        received=received,
        persisted=persisted,
        requests=budget.used,
        error=error,
    )
    LOGGER.log(logging.WARNING if error else logging.INFO, "%s", result.model_dump_json())
    return result
