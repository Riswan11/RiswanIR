from datetime import timedelta

from trailhound.connectors.base import CollectedBatch, CollectionFailure
from trailhound.ingestion.orchestrator import next_window, run_collection
from trailhound.storage import checkpoint_store


class Source:
    def __init__(self, pages, interrupt=False):
        self.pages = pages
        self.interrupt = interrupt

    def collect(self, _window):
        yield from self.pages
        if self.interrupt:
            raise CollectionFailure("lookup_events", "retry_limit_exceeded")


def test_interruption_resume_and_idempotent_receipts(store, aws_config, aws_window, cloudtrail):
    first, second, *_ = cloudtrail["Records"]
    source = "cloudtrail://123456789012/us-east-1/event-history"
    page1 = CollectedBatch(source, [first])
    page2 = CollectedBatch(source, [first, second])
    assert next_window(store, aws_config, aws_window.end) == aws_window
    failed = run_collection(
        store, aws_config, aws_window, lambda *_: Source([page1], interrupt=True)
    )
    assert failed.error.code == "retry_limit_exceeded" and failed.persisted == 1
    assert next_window(store, aws_config, aws_window.end + timedelta(hours=1)) == aws_window
    with store.connect() as db:
        assert checkpoint_store.checkpoint(db, aws_config.scope) is None
        assert not checkpoint_store.load_status(db, aws_config.scope).healthy
    completed = run_collection(store, aws_config, aws_window, lambda *_: Source([page1, page2]))
    assert completed.error is None and completed.persisted == 1 and len(store.list()) == 2
    repeated = run_collection(store, aws_config, aws_window, lambda *_: Source([page1, page2]))
    assert repeated.persisted == 0 and len(store.list()) == 2
    with store.connect() as db:
        assert checkpoint_store.checkpoint(db, aws_config.scope).through == aws_window.end
        assert checkpoint_store.load_status(db, aws_config.scope).healthy
    assert next_window(store, aws_config, aws_window.end) is None
    window = next_window(store, aws_config, aws_window.end + timedelta(hours=3))
    assert window.start == aws_window.end - timedelta(minutes=aws_config.overlap_minutes)
    assert window.end == aws_window.end + timedelta(minutes=aws_config.window_minutes)


def test_conflicting_duplicate_and_failed_persistence_do_not_advance(
    store, aws_config, aws_window, cloudtrail
):
    record = cloudtrail["Records"][0]
    source = "source"
    backfill = aws_window.model_copy(update={"incremental": False})
    for batch, expected in [
        (CollectedBatch(source, [{**record, "eventTime": "invalid"}]), "invalid_event"),
        (
            CollectedBatch(source, [record, {**record, "eventName": "different"}]),
            "conflicting_event",
        ),
    ]:
        failed = run_collection(store, aws_config, aws_window, lambda *_: Source([batch]))
        assert failed.error.code == expected and not store.list()
    with store.connect() as db:
        assert checkpoint_store.checkpoint(db, aws_config.scope) is None
        assert db.execute("SELECT count(*) FROM collection_receipts").fetchone()[0] == 0
    result = run_collection(
        store, aws_config, backfill, lambda *_: Source([CollectedBatch(source, [record])])
    )
    assert result.persisted == 1
    with store.connect() as db:
        assert checkpoint_store.checkpoint(db, aws_config.scope) is None


def test_same_payload_from_distinct_objects_preserves_both_origins(
    store, s3_config, aws_window, cloudtrail
):
    raw = cloudtrail["Records"][0]
    batches = [
        CollectedBatch("s3://example-telemetry/first", [raw]),
        CollectedBatch("s3://example-telemetry/second", [raw]),
    ]
    result = run_collection(store, s3_config, aws_window, lambda *_: Source(batches))
    assert result.persisted == 2
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM raw_evidence").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM evidence_receipts").fetchone()[0] == 2


def test_budget_measures_all_records_before_persisting_page(
    store, aws_config, aws_window, cloudtrail
):
    aws_config.max_events = 1
    result = run_collection(
        store,
        aws_config,
        aws_window,
        lambda *_: Source([CollectedBatch("source", cloudtrail["Records"])]),
    )
    assert result.error.code == "event_budget_exceeded" and not store.list()
