import pytest

from riswan_ir import __main__

BASE = "/v1/investigations"


def test_html_and_investigation_list_contract(client, request_payload):
    status, page, headers = client("GET", "/")
    assert status == 200 and b"CloudTrail investigation workspace" in page
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"
    assert client("GET", BASE)[:2] == (200, [])
    status, report, headers = client("POST", BASE, request_payload)
    assert status == 201
    assert headers["Content-Type"] == "application/json"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert client("GET", BASE)[:2] == (
        200,
        [{key: report[key] for key in ("id", "title", "created_at")}],
    )
    assert client("GET", f"{BASE}/{report['id']}")[:2] == (200, report)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/missing"),
        ("GET", BASE + "/wrong"),
        ("GET", BASE + "/" + "0" * 32),
        ("DELETE", BASE),
        ("GET", BASE + "/" + "0" * 32 + "/missing"),
    ],
)
def test_missing_resources(client, method, path):
    status, error, _ = client(method, path)
    assert status == 404 and error["error"]


def test_http_rejection_and_unknown_advisory(client, request_payload):
    _, report, _ = client("POST", BASE, request_payload)
    path = f"{BASE}/{report['id']}/actions"
    assert client("POST", path + "/unknown/reject", {"reviewer": "Analyst"})[0] == 404
    status, rejected, _ = client(
        "POST", path + "/review-access-key/reject", {"reviewer": "Analyst"}
    )
    assert status == 201 and rejected["decision"]["decision"] == "reject"


def test_server_error_does_not_disclose_details(client, store, monkeypatch):
    def broken():
        raise KeyError("private details")

    monkeypatch.setattr(store, "list", broken)
    assert client("GET", BASE)[:2] == (500, {"error": "Internal server error."})


def test_cli_uses_loopback_and_configured_database(monkeypatch, tmp_path, capsys):
    from unittest.mock import MagicMock

    db = tmp_path / "cli.sqlite3"
    monkeypatch.setenv("RISWAN_IR_DB", str(db))
    monkeypatch.setenv("RISWAN_IR_PORT", "8456")
    server = MagicMock()
    make_server = MagicMock(return_value=server)
    monkeypatch.setattr(__main__, "make_server", make_server)
    __main__.main()
    host, port, application = make_server.call_args.args
    assert (host, port) == ("127.0.0.1", 8456)
    assert application.store.path == str(db)
    assert db.is_file()
    server.__enter__.return_value.serve_forever.assert_called_once_with()
    assert "http://127.0.0.1:8456" in capsys.readouterr().out
