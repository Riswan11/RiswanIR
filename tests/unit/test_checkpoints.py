from datetime import timedelta

from sentinelforge.models.connector import CollectionCheckpoint
from sentinelforge.storage.checkpoint_store import checkpoint, save_checkpoint


def test_checkpoints_are_monotonic_and_partitioned(store, aws_config, aws_window):
    scope = aws_config.scope
    with store.connect() as db:
        assert checkpoint(db, scope) is None
        save_checkpoint(db, CollectionCheckpoint(scope=scope, through=aws_window.end))
        save_checkpoint(
            db, CollectionCheckpoint(scope=scope, through=aws_window.end - timedelta(hours=1))
        )
        assert checkpoint(db, scope).through == aws_window.end
        assert checkpoint(db, "another-scope") is None
