import json

import pytest

from sentinelforge.correlation.temporal.registry import load_rules
from sentinelforge.storage.sqlite import Store
from tests.integration.test_temporal_correlation import (
    ACCOUNT,
    DESTINATION,
    PREFIX,
    create,
    scenario,
)


@pytest.mark.parametrize(
    "document",
    [
        b"- &alias {id: test}\n- *alias",
        b"- !!python/object/apply:os.system ['unused']",
        b"- {id: one, id: two}",
        b" " * 256_001,
    ],
)
def test_temporal_rules_reject_unsafe_or_unbounded_yaml(document):
    with pytest.raises(ValueError):
        load_rules(document)


@pytest.mark.parametrize("reverse", [False, True])
def test_cross_account_requires_directional_local_opt_in(reverse, tmp_path, monkeypatch):
    if reverse:
        policy = tmp_path / "policy.json"
        policy.write_text(
            json.dumps(
                {
                    "cross_account": [
                        {
                            "source": f"aws:{DESTINATION}",
                            "target": f"aws:{ACCOUNT}",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("SENTINELFORGE_TEMPORAL_POLICY", str(policy))
    store = Store(tmp_path / "case.sqlite3")
    report = create(store, scenario(3))
    assert PREFIX + "003" not in {item.id for item in store.temporal_result(report.id).incidents}


def test_replay_rejects_altered_archive(store):
    report = create(store, scenario(7))
    with store.connect() as db:
        row = db.execute(
            "SELECT snapshot FROM temporal_correlations WHERE investigation_id = ?",
            (report.id,),
        ).fetchone()
        archive = json.loads(row["snapshot"])
        archive["policy"]["enrichment"]["version"] = "2.0.0"
        db.execute(
            "UPDATE temporal_correlations SET snapshot = ? WHERE investigation_id = ?",
            (json.dumps(archive), report.id),
        )
    with pytest.raises(ValueError, match="cannot be reproduced"):
        store.replay_temporal(report.id)
