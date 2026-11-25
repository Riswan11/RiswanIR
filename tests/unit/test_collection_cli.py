import json
import sys
from datetime import timedelta

from trailhound.connectors import cli
from trailhound.models.collection import CollectionResult
from trailhound.models.connector import CollectionError


def test_cli_reports_failures_and_status_without_credential_values(
    aws_config, tmp_path, monkeypatch, capsys
):
    config = tmp_path / "config.json"
    config.write_text(json.dumps([aws_config.model_dump(mode="json")]))
    args = [
        "trailhound-collect",
        "--config",
        str(config),
        "--db",
        str(tmp_path / "test.sqlite3"),
    ]
    monkeypatch.setattr(sys, "argv", [*args, "status"])
    assert cli.main() == 0
    status = json.loads(capsys.readouterr().out)
    assert status["scope"] == aws_config.scope and status["health"] is None

    def denied(_store, target, window):
        return CollectionResult(
            scope=target.scope,
            window=window,
            received=0,
            persisted=0,
            requests=1,
            error=CollectionError(operation="lookup_events", code="access_denied"),
        )

    monkeypatch.setattr(cli, "run_collection", denied)
    monkeypatch.setattr(sys, "argv", [*args, "run"])
    assert cli.main() == 1
    monkeypatch.setattr(sys, "argv", [*args, "run", "--start", "not a date"])
    assert cli.main() == 1
    assert "not a date" not in capsys.readouterr().err


def test_cli_backfill_keeps_incremental_checkpoint_separate(
    aws_config, aws_window, tmp_path, monkeypatch, capsys
):
    config = tmp_path / "config.json"
    config.write_text(json.dumps([aws_config.model_dump(mode="json")]))
    args = [
        "trailhound-collect",
        "--config",
        str(config),
        "--db",
        str(tmp_path / "test.sqlite3"),
        "run",
    ]

    def success(_store, target, window):
        assert not window.incremental
        return CollectionResult(
            scope=target.scope, window=window, received=0, persisted=0, requests=1
        )

    monkeypatch.setattr(cli, "run_collection", success)
    monkeypatch.setattr(
        sys,
        "argv",
        [*args, "--start", aws_window.start.isoformat(), "--end", aws_window.end.isoformat()],
    )
    assert cli.main() == 0
    end = (aws_window.end + timedelta(hours=2)).isoformat()
    monkeypatch.setattr(sys, "argv", [*args, "--start", aws_window.start.isoformat(), "--end", end])
    assert cli.main() == 1
    assert "time range" in capsys.readouterr().err
