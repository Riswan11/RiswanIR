from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from riswan_ir.core.config import database_path, setting
from riswan_ir.storage.sqlite import Store


def test_legacy_imports_point_to_the_same_classes():
    from sentinelforge.models import InvestigationRequest as PreviousRequest
    from sentinelforge.storage.sqlite import Store as PreviousStore

    from riswan_ir.models import InvestigationRequest

    assert PreviousStore is Store
    assert PreviousRequest is InvestigationRequest


def test_settings_and_legacy_database_remain_compatible(
    monkeypatch, tmp_path, investigation_request
):
    monkeypatch.chdir(tmp_path)
    for prefix in ("RISWAN_IR", "SENTINELFORGE"):
        for name in ("DB", "PORT"):
            monkeypatch.delenv(f"{prefix}_{name}", raising=False)
    assert database_path() == "riswan-ir.sqlite3"
    legacy = Path("sentinelforge.sqlite3")
    report = Store(legacy).create(investigation_request)
    assert database_path() == str(legacy)
    assert Store(database_path()).get(report.id) == report
    assert Store(database_path()).verify_evidence(report.id).valid
    for event in report.evidence:
        assert (
            event.reference.evidence_id
            == uuid5(NAMESPACE_URL, f"sentinelforge:{report.id}:{event.id}").hex
        )
    assert not Path("riswan-ir.sqlite3").exists()
    monkeypatch.setenv("SENTINELFORGE_PORT", "8002")
    assert setting("PORT") == "8002"
    monkeypatch.setenv("RISWAN_IR_PORT", "8003")
    assert setting("PORT") == "8003"


def test_brand_assets_are_served_locally(client):
    assert b"Riswan IR" in client("GET", "/")[1]
    status, asset, headers = client("GET", "/assets/ir-logo-dark.svg")
    assert status == 200 and b"Riswan IR" in asset
    assert headers["Content-Type"] == "image/svg+xml"
    assert client("GET", "/assets/labs-logo-dark.svg")[0] == 404
