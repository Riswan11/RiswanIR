from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from trailhound.core.config import database_path, server_port
from trailhound.storage.sqlite import Store


def test_database_and_port_settings(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for name in ("TRAILHOUND_DB", "SENTINELFORGE_DB", "TRAILHOUND_PORT", "SENTINELFORGE_PORT"):
        monkeypatch.delenv(name, raising=False)
    assert database_path() == Path("trailhound.sqlite3")
    assert server_port() == 8000

    monkeypatch.setenv("SENTINELFORGE_DB", "legacy.sqlite3")
    monkeypatch.setenv("SENTINELFORGE_PORT", "8001")
    assert database_path() == Path("legacy.sqlite3")
    assert server_port() == 8001

    monkeypatch.setenv("TRAILHOUND_DB", "explicit.sqlite3")
    monkeypatch.setenv("TRAILHOUND_PORT", "8002")
    assert database_path() == Path("explicit.sqlite3")
    assert server_port() == 8002


def test_reopens_legacy_database_and_preserves_evidence(
    monkeypatch, tmp_path, investigation_request
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("TRAILHOUND_DB", raising=False)
    monkeypatch.delenv("SENTINELFORGE_DB", raising=False)

    legacy = Path("sentinelforge.sqlite3")
    report = Store(legacy).create(investigation_request)
    assert database_path() == legacy
    reopened = Store(database_path())
    assert reopened.get(report.id) == report
    assert reopened.verify_evidence(report.id).valid
    assert reopened.export_evidence(report.id)["format"] == "sentinelforge-evidence-v1"
    for event in report.evidence:
        assert event.reference is not None
        assert (
            event.reference.evidence_id
            == uuid5(NAMESPACE_URL, f"sentinelforge:{report.id}:{event.id}").hex
        )
    assert not Path("trailhound.sqlite3").exists()
