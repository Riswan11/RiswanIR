"""Atomic collection storage on the scoped PostgreSQL case transaction."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager, contextmanager, nullcontext
from datetime import UTC, datetime, timedelta
from time import monotonic
from uuid import UUID, uuid4

from riswan_ir.connectors.base import CollectedBatch, CollectionFailure, TelemetryConnector
from riswan_ir.core.fields import required
from riswan_ir.models import CloudTrailRecord, InvestigationRequest
from riswan_ir.models.collection import CollectionRequest
from riswan_security_data.integrity import canonical_json, sha256
from riswan_security_data.provenance import CollectionContext

from .collection_registration import CollectionRegistration
from .postgres_cases import PostgresCases
from .postgres_scope import ScopedPostgres

TABLES = (
    "collection_integrations",
    "collection_progress",
    "collection_observations",
    "collection_runs",
)


class PostgresCollections:
    def __init__(self, cases: PostgresCases, pool):
        self._cases = cases
        self._scope = ScopedPostgres(pool, TABLES)

    @contextmanager
    def _transaction(self, entry: CollectionRegistration):
        with self._scope.transaction() as (db, context):
            if (
                context.tenant_id != entry.tenant_id
                or context.product_id != "ir"
                or context.actor_id != str(entry.workload_id)
                or context.actor_type not in {"service", "integration"}
            ):
                raise CollectionFailure("collect", "scope_denied")
            db.execute(
                """SELECT set_config('riswan.collection_integration', %s, true),
                          set_config('riswan.collection_workload', %s, true)""",
                (str(entry.integration_id), context.actor_id),
            )
            scope = (
                context.tenant_id,
                context.product_id,
                entry.integration_id,
                entry.connector.scope,
            )
            yield db, context, scope

    def register(self, entry: CollectionRegistration) -> datetime | None:
        with self._transaction(entry) as (db, _, scope):
            config = self._configuration(entry)
            db.execute(
                """INSERT INTO riswan_data.collection_integrations
                (tenant_id, product_id, integration_id, source_scope, workload_id, provider_instance_id,
                 connector, membership_joined, namespace)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (
                    *scope,
                    entry.workload_id,
                    entry.instance_id,
                    config,
                    entry.membership_joined,
                    entry.namespace.model_dump_json(),
                ),
            )
            self._verify_registration(db, scope, entry)
            db.execute(
                """INSERT INTO riswan_data.collection_progress
                (tenant_id,product_id,integration_id,source_scope) VALUES (%s,%s,%s,%s)
                ON CONFLICT DO NOTHING""",
                scope,
            )
            return self._watermark(db, scope, lock=False)

    def reserve_window(
        self, entry: CollectionRegistration, now: datetime
    ) -> tuple[datetime | None, CollectionRequest | None]:
        with self._transaction(entry) as (db, _, scope):
            self._verify_registration(db, scope, entry)
            checkpoint = self._watermark(db, scope, lock=True)
            pending = self._pending_window(db, scope)
            if pending is not None:
                return checkpoint, pending
            if checkpoint is not None and checkpoint >= now:
                return checkpoint, None
            step = timedelta(minutes=entry.connector.window_minutes)
            start = (
                now - step
                if checkpoint is None
                else checkpoint - timedelta(minutes=entry.connector.overlap_minutes)
            )
            end = now if checkpoint is None else min(now, checkpoint + step)
            window = CollectionRequest(start=start, end=end)
            db.execute(
                """UPDATE riswan_data.collection_progress SET pending_start=%s, pending_end=%s
                WHERE (tenant_id,product_id,integration_id,source_scope)=(%s,%s,%s,%s)""",
                (start, end, *scope),
            )
            return checkpoint, window

    @staticmethod
    def _pending_window(db, scope) -> CollectionRequest | None:
        row = db.execute(
            """SELECT pending_start, pending_end FROM riswan_data.collection_progress
            WHERE (tenant_id,product_id,integration_id,source_scope)=(%s,%s,%s,%s)""",
            scope,
        ).fetchone()
        if row is None or row[0] is None:
            return None
        return CollectionRequest(start=row[0], end=row[1])

    def confirm_registration(self, entry: CollectionRegistration) -> None:
        with self._transaction(entry) as (db, _, scope):
            self._verify_registration(db, scope, entry)

    @staticmethod
    def _configuration(entry: CollectionRegistration) -> str:
        return entry.connector.model_dump_json(exclude={"account": {"external_id"}})

    def _verify_registration(self, db, scope, entry):
        row = db.execute(
            """SELECT workload_id, provider_instance_id, connector, membership_joined, namespace, enabled
            FROM riswan_data.collection_integrations
            WHERE (tenant_id,product_id,integration_id,source_scope)=(%s,%s,%s,%s)""",
            scope,
        ).fetchone()
        if row != (
            entry.workload_id,
            entry.instance_id,
            self._configuration(entry),
            entry.membership_joined,
            entry.namespace.model_dump_json(),
            True,
        ):
            raise CollectionFailure("collect", "registration_conflict")

    @staticmethod
    def _watermark(db, scope, *, lock):
        query = (
            """SELECT watermark FROM riswan_data.collection_progress
            WHERE (tenant_id,product_id,integration_id,source_scope)=(%s,%s,%s,%s) FOR UPDATE"""
            if lock
            else """SELECT watermark FROM riswan_data.collection_progress
            WHERE (tenant_id,product_id,integration_id,source_scope)=(%s,%s,%s,%s)"""
        )
        row = db.execute(query, scope).fetchone()
        if row is None:
            raise CollectionFailure("persist", "registration_missing")
        return row[0]

    def collect_and_publish(
        self,
        entry: CollectionRegistration,
        window: CollectionRequest,
        expected: datetime | None,
        source: TelemetryConnector,
        *,
        authorize: Callable[[], AbstractContextManager[None]] = nullcontext,
        expires_at: datetime | None = None,
    ) -> tuple[UUID, int]:
        """Read the complete window before taking any product database lock."""
        with self._transaction(entry) as (db, _, scope):
            self._verify_registration(db, scope, entry)
        batches = []
        count = retained_bytes = 0
        deadline = monotonic() + 120
        try:
            for batch in source.collect(window):
                self._require_live(deadline, expires_at)
                count += len(batch.records)
                if count > min(entry.connector.max_events, 2000):
                    raise CollectionFailure("collect", "event_budget_exceeded")
                for record in batch.records:
                    retained_bytes += len(canonical_json(record).encode())
                    if retained_bytes > 8_000_000:
                        raise CollectionFailure("collect", "byte_budget_exceeded")
                if batch.records:
                    batches.append(batch)
        except (CollectionFailure, ValueError, RuntimeError, TimeoutError):
            with authorize():
                self.record_failure(entry, window, expected, provider_failed=True)
            raise CollectionFailure("collect", "provider_failure") from None
        with authorize():
            self._require_live(deadline, expires_at)
            return self._publish(entry, window, expected, batches)

    @staticmethod
    def _require_live(deadline: float, expires_at: datetime | None) -> None:
        if monotonic() >= deadline or (expires_at is not None and datetime.now(UTC) >= expires_at):
            raise CollectionFailure("collect", "collection_deadline")

    def _publish(
        self,
        entry: CollectionRegistration,
        window: CollectionRequest,
        expected: datetime | None,
        batches: list[CollectedBatch],
    ) -> tuple[UUID, int]:
        with self._transaction(entry) as (db, context, scope):
            db.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 796016))",
                (str(entry.integration_id),),
            )
            self._verify_registration(db, scope, entry)
            current = self._watermark(db, scope, lock=True)
            if current != expected or (current is not None and window.end <= current):
                raise CollectionFailure("persist", "stale_checkpoint")
            pending = self._pending_window(db, scope)
            if (
                not window.incremental
                or (current is not None and window.start > current)
                or (pending is not None and pending != window)
            ):
                raise CollectionFailure("persist", "invalid_checkpoint_window")
            received = sum(len(batch.records) for batch in batches)
            if received > entry.connector.max_events:
                raise CollectionFailure("persist", "event_budget_exceeded")
            count = 0
            for batch in batches:
                count += self._publish_batch(db, context, scope, entry, batch)
            run = uuid4()
            db.execute(
                """INSERT INTO riswan_data.collection_runs
                (tenant_id,product_id,integration_id,source_scope,run_id,actor_id,start_at,end_at,received,persisted)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (*scope, run, entry.workload_id, window.start, window.end, received, count),
            )
            self._advance(db, scope, window.end)
            return run, count

    def record_failure(
        self,
        entry: CollectionRegistration,
        window: CollectionRequest,
        expected: datetime | None,
        *,
        provider_failed: bool,
    ) -> bool:
        code = "provider_failure" if provider_failed else "storage_failure"
        with self._transaction(entry) as (db, _, scope):
            self._verify_registration(db, scope, entry)
            if self._watermark(db, scope, lock=True) != expected:
                return False
            db.execute(
                """INSERT INTO riswan_data.collection_runs
                (tenant_id,product_id,integration_id,source_scope,run_id,actor_id,start_at,end_at,
                 received,persisted,failure_code)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,0,0,%s)""",
                (*scope, uuid4(), entry.workload_id, window.start, window.end, code),
            )
            db.execute(
                """UPDATE riswan_data.collection_progress SET healthy=false, attempted_at=now(), failure_code=%s
                WHERE (tenant_id,product_id,integration_id,source_scope)=(%s,%s,%s,%s)""",
                (code, *scope),
            )
            return True

    @staticmethod
    def _advance(db, scope, through):
        db.execute(
            """UPDATE riswan_data.collection_progress SET watermark=%s, healthy=true, attempted_at=now(),
            failure_code=NULL, pending_start=NULL, pending_end=NULL
            WHERE (tenant_id,product_id,integration_id,source_scope)=(%s,%s,%s,%s)""",
            (through, *scope),
        )

    def _publish_batch(self, db, context, scope, entry, batch):
        fresh: dict[str, tuple[CloudTrailRecord, str]] = {}
        for event in batch.records:
            event_id = required(event, "eventID")
            digest = sha256(canonical_json(event))
            prior = db.execute(
                """SELECT location,digest FROM riswan_data.collection_observations
                WHERE (tenant_id,product_id,integration_id,source_scope,event_id)=(%s,%s,%s,%s,%s)""",
                (*scope, event_id),
            ).fetchall()
            if any(saved != digest for _, saved in prior) or (
                event_id in fresh and fresh[event_id][1] != digest
            ):
                raise CollectionFailure("persist", "conflicting_event")
            if (batch.location, digest) not in prior:
                fresh[event_id] = (event, digest)
        if not fresh:
            return 0
        config = entry.connector
        report = self._cases._compile(
            db,
            context,
            InvestigationRequest(
                title=f"AWS {config.kind.value} collection",
                principal=config.principal,
                records=[event for event, _ in fresh.values()],
                provenance=CollectionContext(
                    source_location=batch.location,
                    collection_method="connector",
                    collected_at=datetime.now(UTC).isoformat(),
                    collector_id=scope[3],
                    collection_account_id=config.account.account_id,
                    collection_region=config.account.region,
                ),
            ),
        )
        db.cursor().executemany(
            """INSERT INTO riswan_data.collection_observations
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            [
                (*scope, key, batch.location, digest, report.id)
                for key, (_, digest) in fresh.items()
            ],
        )
        return len(fresh)
