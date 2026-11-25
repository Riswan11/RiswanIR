import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import UUID
from wsgiref.util import setup_testing_defaults

import pytest

from riswan_app.identity_repository import SQLiteIdentityRepository
from riswan_app.local import local_context
from riswan_platform.core.context import require_context
from riswan_platform.core.exceptions import ContextRequiredError
from riswan_platform.identity.application import LOGIN, SESSION, IdentityApplication, RequestBudget
from riswan_platform.identity.configuration import OIDCSettings
from riswan_platform.identity.models import (
    AuthenticationError,
    ExternalIdentity,
    IdentityStatus,
    IdentityType,
    ProviderUnavailable,
)
from riswan_platform.identity.principal import require_principal
from riswan_platform.identity.service import IdentityService, pkce


@pytest.fixture
def settings():
    return OIDCSettings(
        issuer="https://issuer.example",
        jwks_url="https://issuer.example/jwks",
        authorization_url="https://login.example/authorize",
        token_url="https://login.example/token",
        redirect_uri="https://app.example/v1/auth/callback",
        client_id="browser-client",
        access_audience="riswan-api",
        invited_subjects={"alice", "bob", "outage"},
        logout_url="https://login.example/signout",
        post_logout_redirect_uri="https://app.example/",
        services={"worker": {"client_id": "worker-client", "required_scopes": ["identity:read"]}},
    )


class FixtureProvider:
    def __init__(self, config):
        self.config = config
        self.challenges = {}

    def authorization_redirect(self, state, nonce, challenge):
        self.challenges[nonce] = challenge
        return "https://login.example/authorize?" + urlencode({"state": state, "nonce": nonce})

    def exchange(self, code, verifier, nonce):
        assert self.challenges[nonce] == pkce(verifier)
        if code == "outage":
            raise ProviderUnavailable("do-not-disclose-credentials")
        return ExternalIdentity(
            self.config.issuer,
            code,
            IdentityType.HUMAN,
            code,
            "same@example.test",
            True,
        )

    def validate_access_token(self, token):
        if token != "test-workload-token":
            raise AuthenticationError("do-not-disclose-credentials")
        return ExternalIdentity(self.config.issuer, "worker", IdentityType.SERVICE, "Worker")

    def logout_redirect(self):
        return self.config.logout_url


def call(app, path, method="GET", query="", cookie="", authorization="", origin=None):
    env = {}
    setup_testing_defaults(env)
    env.update(
        REQUEST_METHOD=method,
        PATH_INFO=path,
        QUERY_STRING=query,
        HTTP_HOST="app.example",
        HTTP_COOKIE=cookie,
        HTTP_AUTHORIZATION=authorization,
    )
    if origin:
        env["HTTP_ORIGIN"] = origin
    result = []
    data = b"".join(
        app(env, lambda status, headers: result.append((int(status.split()[0]), headers)))
    )
    status, headers = result[0]
    return status, headers, json.loads(data) if data else None


def get_cookie(headers, name):
    return next(
        value.split(";", 1)[0]
        for key, value in headers
        if key == "Set-Cookie" and value.startswith(name + "=")
    )


def begin(app):
    status, headers, _ = call(app, "/v1/auth/login")
    assert status == 302
    location = dict(headers)["Location"]
    return parse_qs(urlsplit(location).query)["state"][0], get_cookie(headers, LOGIN)


def login(app, actor, existing=""):
    state, browser = begin(app)
    status, headers, _ = call(
        app,
        "/v1/auth/callback",
        query=urlencode({"code": actor, "state": state}),
        cookie=f"{browser}; {existing}" if existing else browser,
    )
    assert status == 303
    return get_cookie(headers, SESSION), headers


@pytest.fixture
def runtime(tmp_path, settings):
    clock = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    repository = SQLiteIdentityRepository(tmp_path / "identity.sqlite3")
    service = IdentityService(
        FixtureProvider(settings), repository, settings, clock=lambda: clock[0]
    )
    return IdentityApplication(service), repository, clock


def test_browser_binding_rotation_audit_and_logout(runtime, caplog):
    app, repository, _ = runtime
    state, browser = begin(app)
    query = urlencode({"state": state, "code": "alice"})
    assert call(app, "/v1/auth/callback", query=query, cookie=f"{LOGIN}=" + "Z" * 43)[0] == 401
    assert call(app, "/v1/auth/callback", query=query)[0] == 401
    status, headers, _ = call(app, "/v1/auth/callback", query=query, cookie=browser)
    assert status == 303
    first = get_cookie(headers, SESSION)
    for key, value in headers:
        if key == "Set-Cookie":
            assert "Secure; HttpOnly; SameSite=Lax" in value and "Path=/" in value
    assert call(app, "/v1/auth/callback", query=query, cookie=browser)[0] == 401
    previous_actor = call(app, "/v1/identity/me", cookie=first)[2]
    newer, _ = login(app, "alice", first)
    assert first != newer
    actor = call(app, "/v1/identity/me", cookie=newer)[2]
    assert actor == previous_actor
    assert call(app, "/v1/identity/me", cookie=first)[0] == 401
    assert actor["mfa_verified"] is True
    assert call(app, "/v1/investigations", cookie=newer)[0] == 403
    assert (
        call(app, "/v1/auth/logout", "POST", cookie=newer, origin="https://foreign.example")[0]
        == 403
    )
    assert (
        call(app, "/v1/auth/refresh", "POST", cookie=newer, origin="https://app.example")[0] == 409
    )
    status, headers, _ = call(
        app, "/v1/auth/logout", "POST", cookie=newer, origin="https://app.example"
    )
    assert status == 303 and dict(headers)["Location"] == "https://login.example/signout"
    assert call(app, "/v1/identity/me", cookie=newer)[0] == 401
    secret = first.split("=", 1)[1]
    with closing(sqlite3.connect(repository.path)) as db:
        assert db.execute(
            "SELECT 1 FROM identity_sessions WHERE digest = ?",
            (sha256(secret.encode()).hexdigest(),),
        ).fetchone()
        events = {row[0] for row in db.execute("SELECT event_type FROM authentication_events")}
    assert {"platform.identity.login_failed", "platform.identity.logout_completed"} <= events
    assert secret.encode() not in repository.path.read_bytes()
    assert secret not in caplog.text
    with pytest.raises(ContextRequiredError):
        require_context()
    with pytest.raises(AuthenticationError):
        require_principal()


def test_ownership_suspend_revoke_and_idle_expiry(runtime):
    app, repository, clock = runtime
    alice, _ = login(app, "alice")
    bob, _ = login(app, "bob")
    first = call(app, "/v1/identity/me", cookie=alice)[2]
    other = call(app, "/v1/identity/me", cookie=bob)[2]
    assert first["identity_id"] != other["identity_id"]  # Both use the same email.
    session = call(app, "/v1/identity/sessions", cookie=bob)[2]["sessions"][0]["id"]
    path = f"/v1/identity/sessions/{session}"
    assert call(app, path, "DELETE", cookie=alice, origin="https://app.example")[0] == 404
    assert call(app, path, "DELETE", cookie=bob, origin="https://app.example")[0] == 204
    assert call(app, "/v1/identity/me", cookie=bob)[0] == 401
    current = app.service.authenticate("status-test", cookie=alice.split("=", 1)[1])
    app.service.set_status(current.identity, IdentityStatus.SUSPENDED, "status-test")
    assert call(app, "/v1/identity/me", cookie=alice)[0] == 401
    with pytest.raises(AuthenticationError):
        repository.resolve(
            ExternalIdentity(
                app.service.settings.issuer,
                "alice",
                IdentityType.HUMAN,
                "Alice",
            ),
            clock[0],
        )
    bob, _ = login(app, "bob")
    clock[0] += timedelta(minutes=30)
    assert call(app, "/v1/identity/me", cookie=bob)[0] == 401
    with closing(sqlite3.connect(repository.path)) as db:
        assert db.execute("SELECT COUNT(*) FROM identity_status_history").fetchone()[0] == 1


def test_missing_credentials_bearer_failures_and_provider_outage(runtime):
    app, repository, _ = runtime
    assert call(app, "/v1/identity/me")[0] == 401
    assert call(app, "/v1/identity/me", authorization="Basic spoof")[0] == 401
    assert call(app, "/v1/identity/me", authorization="Bearer secret-unauthorized")[0] == 401
    credentials = {"authorization": "Bearer test-workload-token"}
    status, _, actor = call(app, "/v1/identity/me", **credentials)
    assert status == 200 and actor["identity_type"] == "service"
    assert call(app, "/v1/identity/sessions", **credentials)[0] == 403
    assert call(app, "/v1/investigations", **credentials)[0] == 403
    state, browser = begin(app)
    status, _, error = call(
        app,
        "/v1/auth/callback",
        query=urlencode(
            {
                "state": state,
                "code": "outage",
            }
        ),
        cookie=browser,
    )
    assert status == 503 and "do-not-disclose" not in json.dumps(error)
    with closing(sqlite3.connect(repository.path)) as db:
        events = str(db.execute("SELECT * FROM authentication_events").fetchall())
    assert "test-workload-token" not in events and "secret-unauthorized" not in events


def test_development_mode_rejected_with_production_or_oidc(monkeypatch):
    monkeypatch.setenv("RISWAN_IR_ENV", "production")
    with pytest.raises(ContextRequiredError):
        local_context("local", "ir")
    monkeypatch.setenv("RISWAN_IR_ENV", "development")
    monkeypatch.setenv("RISWAN_IR_OIDC_CONFIG", "trusted/config.json")
    with pytest.raises(ContextRequiredError):
        local_context("local", "ir")


def test_rate_budget_is_bounded():
    now = [0.0]
    limiter = RequestBudget(lambda: now[0])
    assert all(limiter.allow("same") for _ in range(120))
    assert not limiter.allow("same")
    now[0] = 60
    assert limiter.allow("same")
    assert all(limiter.allow(str(index)) for index in range(1199))
    assert not limiter.allow("next")


def test_disabling_actor_also_denies_previously_valid_bearer(runtime):
    app, _, _ = runtime
    actor = app.service.authenticate("workload", bearer="test-workload-token")
    assert isinstance(actor.identity.identity_id, UUID)
    app.service.set_status(actor.identity, IdentityStatus.DISABLED, "workload")
    with pytest.raises(AuthenticationError):
        app.service.authenticate("workload", bearer="test-workload-token")
