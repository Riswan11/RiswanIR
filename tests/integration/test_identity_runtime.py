import io
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import UUID
from wsgiref.util import setup_testing_defaults

import pytest

from riswan_app.authorization_repository import AuthorizationRepository
from riswan_app.hosted_product import HostedProduct
from riswan_app.identity_repository import SQLiteIdentityRepository
from riswan_app.local import local_context
from riswan_app.tenancy import Tenancy
from riswan_app.tenant_api import TenantAPI
from riswan_ir.storage.sqlite import Store
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


def call(
    app,
    path,
    method="GET",
    query="",
    cookie="",
    authorization="",
    origin=None,
    *,
    payload=None,
    tenant=None,
):
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
    if payload is not None:
        raw = json.dumps(payload).encode()
        env["wsgi.input"] = io.BytesIO(raw)
        env["CONTENT_LENGTH"] = str(len(raw))
        env["CONTENT_TYPE"] = "application/json"
    if tenant is not None:
        env["HTTP_X_RISWAN_TENANT"] = tenant
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


@pytest.fixture
def hosted_runtime(tmp_path, runtime, settings):
    identity_app, identities, _ = runtime
    control = AuthorizationRepository(tmp_path / "control.sqlite3")
    tenancy = Tenancy(control, identities.is_active_human)
    storage = Store(tmp_path / "hosted.sqlite3", hosted=True)
    app = IdentityApplication(
        identity_app.service,
        authenticated_routes=TenantAPI(tenancy, HostedProduct(tenancy, storage), settings.origin),
    )
    alice, _ = login(app, "alice")
    bob, _ = login(app, "bob")

    def request(
        path, method="GET", *, cookie=alice, payload=None, tenant=None, origin=settings.origin
    ):
        status, _, response = call(
            app, path, method, cookie=cookie, origin=origin, payload=payload, tenant=tenant
        )
        return status, response

    bob_id = request("/v1/identity/me", cookie=bob)[1]["identity_id"]
    return request, bob, bob_id, control, storage


def test_tenant_routing_enforces_membership_and_case_ownership(hosted_runtime, request_payload):
    request, bob, bob_id, control, storage = hosted_runtime
    assert request("/v1/organizations", cookie="")[0] == 401
    assert (
        request("/v1/organizations", "POST", payload={"name": "A"}, origin="https://other.example")[
            0
        ]
        == 403
    )
    code, alpha = request("/v1/organizations", "POST", payload={"name": "Alpha"})
    assert code == 201 and alpha["id"] != alpha["tenant_id"]
    code, beta = request("/v1/organizations", "POST", cookie=bob, payload={"name": "Beta"})
    assert code == 201
    first, second = alpha["tenant_id"], beta["tenant_id"]
    org = "/v1/organizations/" + alpha["id"]
    cases = "/v1/investigations"
    assert request(org, cookie=bob) == request(org[:-36] + beta["id"])
    assert request(cases, cookie=bob, tenant=first)[0] == 404
    assert request(cases)[0] == 404
    assert request(org + "/activate", "POST")[1] == {"tenant_id": first}
    code, result = request(cases, "POST", tenant=first, payload=request_payload)
    assert code == 201
    case = cases + "/" + result["id"]
    assert request(case, tenant=first)[1]["evidence"]
    assert request(case, tenant=second, cookie=bob) == request(
        cases + "/" + "0" * 32, tenant=second, cookie=bob
    )
    assert request(cases, tenant=second, cookie=bob) == (200, [])
    assert request(cases, tenant=first)[1][0]["id"] == result["id"]
    assert (
        request(org + "/invitations", "POST", payload={"identity_id": bob_id, "role": "owner"})[0]
        == 404
    )
    code, invite = request(
        org + "/invitations", "POST", payload={"identity_id": bob_id, "role": "viewer"}
    )
    assert code == 201
    token = {"token": invite["token"]}
    accept = "/v1/organizations/invitations/accept"
    assert request(accept, "POST", payload=token)[0] == 404
    assert request(accept, "POST", cookie=bob, payload=token) == (200, {"tenant_id": first})
    assert request(accept, "POST", cookie=bob, payload=token)[0] == 404
    assert invite["token"].encode() not in control.path.read_bytes()
    assert len(request("/v1/organizations", cookie=bob)[1]) == 2
    assert request(org + "/activate", "POST", cookie=bob)[1] == {"tenant_id": first}
    assert request(case, tenant=first, cookie=bob)[0] == 200
    assert request(cases, "POST", tenant=first, cookie=bob, payload=request_payload)[0] == 404
    assert request(case + "/evidence/export", "POST", tenant=first, cookie=bob)[0] == 404
    assert request(org + "/members", cookie=bob)[0] == 404
    assert (
        request(org + "/members/role", "PUT", payload={"identity_id": bob_id, "role": "analyst"})[0]
        == 204
    )
    assert request(cases, "POST", tenant=first, cookie=bob, payload=request_payload)[0] == 201
    assert request(org + "/members/" + bob_id, "DELETE")[0] == 204
    assert request(case, tenant=first, cookie=bob)[0] == 404
    assert request(cases, tenant=second, cookie=bob) == (200, [])
    assert storage.owned_investigations(UUID(first)).keys() >= {result["id"]}
    assert request(org + "/lifecycle", "POST", payload={"status": "suspended"})[0] == 200
    assert request(case, tenant=first)[0] == 404
    assert request(org + "/activate", "POST")[0] == 404
    assert request(org + "/lifecycle", "POST", payload={"status": "active"})[0] == 200
    assert request(case, tenant=first)[0] == 200


def test_invitation_lifecycle_and_owner_transfer(hosted_runtime):
    request, bob, bob_id, control, _ = hosted_runtime
    _, org = request("/v1/organizations", "POST", payload={"name": "Original"})
    path = "/v1/organizations/" + org["id"]
    assert (
        request(path, "PUT", payload={"name": "Updated", "settings": {"description": "Team"}})[1][
            "name"
        ]
        == "Updated"
    )
    assert request(path)[1]["settings"] == {"description": "Team"}
    invitee = {"identity_id": bob_id, "role": "analyst"}
    accept = "/v1/organizations/invitations/accept"

    def invite():
        status, result = request(path + "/invitations", "POST", payload=invitee)
        assert status == 201
        return result

    revoked = invite()
    assert request(path + "/invitations/" + revoked["id"], "DELETE")[0] == 204
    assert request(accept, "POST", cookie=bob, payload={"token": revoked["token"]})[0] == 404

    expired = invite()
    with control.atomic() as db:
        db.execute(
            "UPDATE organization_invitations SET expires_at = ? WHERE id = ?",
            ("2000-01-01", expired["id"]),
        )
    assert request(accept, "POST", cookie=bob, payload={"token": expired["token"]})[0] == 404

    invited = invite()
    assert request(accept, "POST", cookie=bob, payload={"token": invited["token"]})[0] == 200
    actor = request("/v1/identity/me")[1]["identity_id"]
    assert request(path + "/members/" + actor, "DELETE")[0] == 404
    assert (
        request(path + "/ownership", "POST", cookie=bob, payload={"identity_id": actor})[0] == 404
    )
    assert request(path + "/ownership", "POST", payload={"identity_id": bob_id})[0] == 204
    assert request(path + "/members", cookie=bob)[1][1]["role"] == "owner"
    assert request(path + "/members")[0] == 404
    assert (
        request(path + "/lifecycle", "POST", cookie=bob, payload={"status": "archived"})[0] == 200
    )
    assert request(path + "/lifecycle", "POST", cookie=bob, payload={"status": "active"})[0] == 404
    with control.atomic() as db:
        audit = {row[0] for row in db.execute("SELECT event FROM organization_audit_events")}
    assert {
        "platform.tenancy.ownership_transferred",
        "platform.tenancy.tenant_archived",
        "platform.tenancy.invitation_revoked",
        "platform.tenancy.request_denied",
    } <= audit


def test_invitation_consumption_is_atomic(hosted_runtime):
    from concurrent.futures import ThreadPoolExecutor

    request, bob, bob_id, _, _ = hosted_runtime
    _, org = request("/v1/organizations", "POST", payload={"name": "Concurrent"})
    _, invite = request(
        f"/v1/organizations/{org['id']}/invitations",
        "POST",
        payload={"identity_id": bob_id, "role": "viewer"},
    )

    def accept():
        return request(
            "/v1/organizations/invitations/accept",
            "POST",
            cookie=bob,
            payload={"token": invite["token"]},
        )[0]

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = sorted(executor.map(lambda _: accept(), range(2)))
    assert outcomes == [200, 404]


def test_ownership_migration_preserves_legacy_records(hosted_runtime, investigation_request):
    request, _, _, _, hosted = hosted_runtime
    legacy = Store(hosted.path)
    report = legacy.create(investigation_request)
    original_hashes = [event.integrity_hash for event in report.evidence]
    assert original_hashes
    _, org = request("/v1/organizations", "POST", payload={"name": "New tenant"})
    tenant_id = org["tenant_id"]
    assert request("/v1/investigations", tenant=tenant_id) == (200, [])
    assert request(f"/v1/investigations/{report.id}", tenant=tenant_id)[0] == 404
    restarted = Store(hosted.path)
    assert [event.integrity_hash for event in restarted.get(report.id).evidence] == original_hashes
    assert restarted.verify_evidence(report.id).valid


def test_invalid_tenant_controls_return_generic_errors(hosted_runtime):
    request, _, _, _, _ = hosted_runtime
    assert request("/v1/organizations", "POST", payload={"name": " ", "tenant_id": "fake"}) == (
        400,
        {"error": "Invalid request."},
    )
    assert (
        request("/v1/organizations/invitations/accept", "POST", payload={"token": "short"})[0]
        == 400
    )
    assert request("/v1/investigations", tenant="-" * 36) == (404, {"error": "Resource not found."})


def test_hosted_composition_separates_databases(tmp_path, monkeypatch, settings):
    from riswan_app import identity_runtime

    monkeypatch.setattr(identity_runtime, "has_crypto", True)
    config = tmp_path / "oidc.json"
    config.write_text(settings.model_dump_json(), encoding="utf-8")
    identity = tmp_path / "identity.sqlite3"
    local = tmp_path / "local.sqlite3"
    hosted = tmp_path / "hosted.sqlite3"
    control = tmp_path / "control.sqlite3"
    with pytest.raises(ValueError, match="Configure both"):
        identity_runtime.compose_identity(config, identity, local, control_db=control)
    with pytest.raises(ValueError, match="must be separate"):
        identity_runtime.compose_identity(
            config, identity, local, control_db=control, hosted_db=local
        )
    standard = identity_runtime.compose_identity(config, identity, local)
    assert standard._authenticated_routes is None
    configured = identity_runtime.compose_identity(
        config,
        identity,
        local,
        control_db=control,
        hosted_db=hosted,
    )
    assert isinstance(configured._authenticated_routes, TenantAPI)
    assert identity.exists() and control.exists() and hosted.exists()
    assert not local.exists()


def test_secret_api_separates_tenants_and_never_returns_material(tmp_path, runtime, settings):
    from riswan_app.secret_api import SecretAPI
    from riswan_app.secret_providers import MemoryProvider
    from riswan_app.secrets import Secrets

    original, identities, _ = runtime
    control = AuthorizationRepository(tmp_path / "secrets-control.sqlite3")
    tenancy = Tenancy(control, identities.is_active_human, identities.is_active_workload)
    storage = Store(tmp_path / "product.sqlite3", hosted=True)
    app = IdentityApplication(
        original.service,
        authenticated_routes=TenantAPI(
            tenancy,
            HostedProduct(tenancy, storage),
            settings.origin,
            SecretAPI(Secrets(tenancy, MemoryProvider(), environment="test")),
        ),
    )
    alice, _ = login(app, "alice")
    bob, _ = login(app, "bob")
    _, _, organization = call(
        app,
        "/v1/organizations",
        "POST",
        cookie=alice,
        origin=settings.origin,
        payload={"name": "A"},
    )
    _, _, other = call(
        app, "/v1/organizations", "POST", cookie=bob, origin=settings.origin, payload={"name": "B"}
    )
    from uuid import uuid4

    base, identifier = "/v1/secrets", str(uuid4())
    path = f"{base}/{identifier}"
    value = "synthetic-credential-that-must-not-leak"
    expires = "2099-01-01T00:00:00Z"

    def send(route, method="GET", body=None, *, foreign=False):
        cookie, tenant = (bob, other) if foreign else (alice, organization)
        status, _, data = call(
            app,
            route,
            method,
            cookie=cookie,
            origin=settings.origin,
            payload=body,
            tenant=tenant["tenant_id"],
        )
        assert value not in json.dumps(data)
        return status, data

    assert call(app, base)[0] == 401
    assert (
        send(
            base,
            "POST",
            {
                "id": identifier,
                "kind": "api_key",
                "name": "Connector",
                "value": value,
                "expires_at": expires,
            },
        )[0]
        == 201
    )
    assert send(base, foreign=True) == (200, [])
    assert send(path, foreign=True)[0] == 404
    assert send(path, "DELETE", foreign=True)[0] == 404
    assert (
        send(
            path + "/rotate", "POST", {"operation_id": str(uuid4()), "value": value}, foreign=True
        )[0]
        == 404
    )
    assert send(path + "/value")[0] == 404
    updated = send(path, "PATCH", {"name": "Renamed"})[1]
    assert updated["name"] == "Renamed"
    assert updated["expires_at"] == expires
    assert send(path + "/versions")[1][0]["state"] == "active"
    assert send(path + "/audit")[1]
    assert value.encode() not in control.path.read_bytes()
    assert send(path + "/revoke", "POST")[1]["status"] == "revoked"
    assert send(path, "DELETE")[1]["status"] == "pending_deletion"
    assert send(path + "/confirm-deletion", "POST")[1]["status"] == "deleted"


def test_hosted_aws_collection_uses_registered_workload_and_preserves_ownership(
    tmp_path, runtime, settings, monkeypatch
):
    from datetime import UTC
    from unittest.mock import Mock
    from uuid import uuid4

    from riswan_app import hosted_collection
    from riswan_app.credential_broker import AWSSTS
    from riswan_app.secrets import Secrets
    from riswan_platform.secrets import CredentialLease

    previous, identities, _ = runtime
    identity_app = previous
    alice, _ = login(identity_app, "alice")
    bearer = "Bearer test-workload-token"
    worker = call(identity_app, "/v1/identity/me", authorization=bearer)[2]["identity_id"]
    control = AuthorizationRepository(tmp_path / "control.sqlite3")
    tenancy = Tenancy(control, identities.is_active_human, identities.is_active_workload)
    store = Store(tmp_path / "hosted.sqlite3", hosted=True)
    service = Secrets(tenancy, None, environment="production")
    product = HostedProduct(tenancy, store)
    app = IdentityApplication(
        previous.service, authenticated_routes=TenantAPI(tenancy, product, settings.origin)
    )
    _, _, organization = call(
        app,
        "/v1/organizations",
        "POST",
        cookie=alice,
        origin=settings.origin,
        payload={"name": "Hosted"},
    )
    org_path = f"/v1/organizations/{organization['id']}"
    assert (
        call(
            app,
            org_path + "/workloads",
            "POST",
            cookie=alice,
            origin=settings.origin,
            payload={"identity_id": worker},
        )[0]
        == 204
    )
    membership = call(app, org_path + "/members", cookie=alice)[2]
    joined = next(item["joined_at"] for item in membership if item["identity_id"] == worker)
    key, instance = str(uuid4()), str(uuid4())
    config = tmp_path / "integrations.json"
    config.write_text(
        json.dumps(
            [
                {
                    "integration_id": key,
                    "instance_id": instance,
                    "tenant_id": organization["tenant_id"],
                    "workload_id": worker,
                    "membership_joined": joined,
                    "namespace": {
                        "partition": "aws",
                        "account": "123456789012",
                        "region": "us-east-1",
                    },
                    "connector": {
                        "kind": "cloudtrail",
                        "principal": "arn:aws:iam::123456789012:user/user",
                        "account": {
                            "account_id": "123456789012",
                            "region": "us-east-1",
                            "role_arn": "arn:aws:iam::123456789012:role/Collect",
                            "external_id": "synthetic-external",
                        },
                    },
                }
            ]
        ),
        encoding="utf-8",
    )
    sdk = Mock()
    sdk.client.return_value.lookup_events.return_value = {
        "Events": [
            {
                "CloudTrailEvent": json.dumps(
                    {
                        "eventID": "event-1",
                        "eventTime": datetime.now(UTC).isoformat(),
                        "eventSource": "s3.amazonaws.com",
                        "eventName": "GetObject",
                        "awsRegion": "us-east-1",
                        "recipientAccountId": "123456789012",
                        "userIdentity": {"arn": "arn:aws:iam::123456789012:user/user"},
                    }
                )
            }
        ]
    }
    issue = Mock(
        return_value=(
            sdk,
            CredentialLease(id=uuid4(), expires_at=datetime.now(UTC) + timedelta(minutes=15)),
        )
    )
    monkeypatch.setattr(AWSSTS, "session", issue)
    route = hosted_collection.CollectionAPI(
        service, hosted_collection.load_collections(config, service, store)
    )
    app = IdentityApplication(
        previous.service,
        authenticated_routes=TenantAPI(tenancy, product, settings.origin, collections=route),
    )
    endpoint = f"/v1/integrations/{key}/collect"
    tenant = organization["tenant_id"]
    assert (
        call(app, endpoint, "POST", cookie=alice, origin=settings.origin, tenant=tenant)[0] == 404
    )
    assert call(app, endpoint, "POST", authorization=bearer, tenant=str(uuid4()))[0] == 404
    issue.assert_not_called()
    assert call(app, endpoint, "POST", authorization=bearer, tenant=tenant)[0] == 204
    issue.assert_called_once()
    listing = call(app, "/v1/investigations", cookie=alice, tenant=tenant)[2]
    assert len(listing) == 1
    assert store.owned_investigations(UUID(tenant))[listing[0]["id"]] == UUID(worker)
    assert (
        call(app, org_path + "/members/" + worker, "DELETE", cookie=alice, origin=settings.origin)[
            0
        ]
        == 204
    )
    assert call(app, endpoint, "POST", authorization=bearer, tenant=tenant)[0] == 404
