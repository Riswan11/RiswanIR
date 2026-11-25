import pytest

BASE = "/v1/investigations"


@pytest.mark.parametrize(
    "host",
    [
        "",
        "untrusted.example",
        "localhost.untrusted.example",
        "localhost@untrusted.example",
        "localhost,localhost",
    ],
)
def test_rejects_nonlocal_host_headers(client, host):
    assert client("GET", "/", headers={"HTTP_HOST": host})[0] == 400


def test_accepts_loopback_host(client):
    assert client("GET", "/", headers={"HTTP_HOST": "127.0.0.1:8000"})[0] == 200


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"raw": b"{"}, "Malformed JSON"),
        ({"raw": b'{"x":"\xff"}'}, "Malformed JSON"),
        ({"raw": b"[]"}, "Provide a JSON object"),
        ({"raw": b"", "length": 8_000_001}, "8 MB"),
        ({"raw": b"", "length": 0}, "8 MB"),
        ({"raw": b"{}", "length": 3}, "Incomplete JSON"),
        ({"raw": b"{}", "headers": {"CONTENT_TYPE": "text/plain"}}, "application/json"),
    ],
)
def test_bad_bodies_are_rejected_without_creating_a_case(client, kwargs, message):
    status, error, _ = client("POST", BASE, **kwargs)
    assert status == 400 and message in error["error"]
    assert client("GET", BASE)[:2] == (200, [])


def test_validation_does_not_echo_untrusted_input(client, request_payload):
    request_payload["title"] = {"private": "fixture-secret"}
    status, error, _ = client("POST", BASE, request_payload)
    assert status == 400 and "fixture-secret" not in error["error"]
