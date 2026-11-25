"""Persist collection receipts and provenance atomically with investigation evidence."""

from datetime import datetime

from riswan_security_data.integrity import canonical_json, sha256
from riswan_security_data.provenance import CollectionContext, CollectionMethod

from ..connectors.base import CollectedBatch, CollectionFailure
from ..core.fields import required
from ..models import CloudTrailRecord, InvestigationRequest
from ..models.connector import ConnectorConfig
from ..storage.checkpoint_store import accept_receipt
from .ports import CollectionRepository


def persist(
    store: CollectionRepository,
    config: ConnectorConfig,
    batch: CollectedBatch,
    collected_at: datetime,
) -> int:
    scope = config.scope
    fresh: list[CloudTrailRecord] = []
    try:
        with store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for record in batch.records:
                event_id = required(record, "eventID")
                digest = sha256(canonical_json(record))
                try:
                    accepted = accept_receipt(db, scope, batch.location, event_id, digest)
                except FileExistsError:
                    raise CollectionFailure("persist", "conflicting_event") from None
                if accepted:
                    fresh.append(record)
            if fresh:
                request = InvestigationRequest(
                    title=f"AWS {config.kind.value} collection",
                    principal=config.principal,
                    records=fresh,
                    provenance=CollectionContext(
                        source_location=batch.location,
                        collection_method=CollectionMethod.CONNECTOR,
                        collected_at=collected_at.isoformat(),
                        collector_id=scope,
                        collection_account_id=config.account.account_id,
                        collection_region=config.account.region,
                    ),
                )
                store.create_in_transaction(db, request)
    except (ValueError, RecursionError):
        raise CollectionFailure("persist", "invalid_event") from None
    return len(fresh)
