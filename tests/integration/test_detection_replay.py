import json

import pytest

from sentinelforge.detection import cli
from sentinelforge.detection.registry import RuleRegistry, default_registry
from sentinelforge.models import InvestigationRequest
from sentinelforge.storage.sqlite import Store
from tests.fixtures.cloudtrail import ROOT, record

RULE = "SF-AWS-DEF-001"


def stored_detection(store):
    return store.create(
        InvestigationRequest(
            title="Review monitoring change",
            principal=ROOT,
            records=[
                record("trail-stop", 3, "StopLogging", eventSource="cloudtrail.amazonaws.com")
            ],
        )
    )


def test_detection_pipeline_archives_policy_and_replays_selected_version(store):
    report = stored_detection(store)
    assert report.detection is not None
    (finding,) = report.detection.findings
    assert (finding.id, finding.evidence_ids) == (RULE, ["trail-stop"])
    assert store.verify_evidence(report.id).valid
    assert Store(store.path).replay_detection(report.id) == report.detection
    rule = default_registry().select({RULE: "1.0.0"})[0]
    disabled = rule.model_copy(update={"version": "2.0.0", "enabled": False})
    result = store.replay_detection(
        report.id, versions={RULE: "2.0.0"}, registry=RuleRegistry([rule, disabled])
    )
    assert result.findings == []
    assert store.get(report.id).detection == report.detection


def test_replay_refuses_changed_archived_configuration(store):
    report = stored_detection(store)
    with store.connect() as db:
        db.execute(
            "UPDATE detection_configuration SET context = ? WHERE investigation_id = ?",
            ('{"version":"2.0.0"}', report.id),
        )
    with pytest.raises(ValueError, match="configuration failed integrity"):
        store.replay_detection(report.id)


def test_cli_read_only_replay(store, monkeypatch, capsys):
    report = stored_detection(store)
    args = ["sentinelforge-detect", report.id, "--db", str(store.path)]
    monkeypatch.setattr("sys.argv", [*args, "--version", f"{RULE}=1.0.0"])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)["findings"][0]["id"] == RULE
    for invalid in (["--version", "bad"], ["--version", f"{RULE}=2.2.2"]):
        monkeypatch.setattr("sys.argv", [*args, *invalid])
        assert cli.main() == 1
        assert "Detection replay failed." in capsys.readouterr().err


def test_detection_uses_trusted_configuration_files(tmp_path, monkeypatch):
    policy = tmp_path / "context.json"
    policy.write_text('{"version":"1.1.0","account_environments":{"111122223333":"production"}}')
    rules = tmp_path / "rules.yml"
    rule = default_registry().select({RULE: "1.0.0"})[0]
    rules.write_text(json.dumps([rule.model_dump(mode="json")]))
    monkeypatch.setenv("SENTINELFORGE_DETECTION_CONTEXT", str(policy))
    monkeypatch.setenv("SENTINELFORGE_DETECTION_RULES", str(rules))
    store = Store(tmp_path / "cases.sqlite3")
    report = stored_detection(store)
    assert report.detection.execution.context_version == "1.1.0"
    assert [item.id for item in report.detection.execution.rules] == [RULE]


def test_investigation_http_report_exposes_findings_without_policy(client):
    status, report, _ = client(
        "POST",
        "/v1/investigations",
        {
            "title": "Investigate monitoring",
            "principal": ROOT,
            "records": [record("stop", 4, "StopLogging", eventSource="cloudtrail.amazonaws.com")],
        },
    )
    assert status == 201
    assert report["detection"]["findings"][0]["evidence_ids"] == ["stop"]
    assert "account_environments" not in json.dumps(report["detection"])
    assert (
        client("GET", f"/v1/investigations/{report['id']}")[1]["detection"] == report["detection"]
    )
