import json
import time
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from jwt import algorithms

from riswan_platform.identity.configuration import OIDCSettings
from riswan_platform.identity.models import AuthenticationError, ProviderUnavailable
from riswan_platform.identity.provider import KeyCache, OIDCProvider

rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")


def config(**changes):
    return OIDCSettings.model_validate(
        {
            "issuer": "https://issuer.example",
            "jwks_url": "https://issuer.example/jwks",
            "authorization_url": "https://login.example/authorize",
            "token_url": "https://login.example/token",
            "redirect_uri": "https://app.example/v1/auth/callback",
            "client_id": "login-client",
            "access_audience": "security-api",
            "invited_subjects": ["analyst"],
            "privileged_subjects": ["analyst"],
            "services": {
                "collector": {"client_id": "service-client", "required_scopes": ["identity:read"]}
            },
            **changes,
        }
    )


@pytest.fixture(scope="module")
def signing():
    return [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2)]


def jwk(key, kid):
    return {
        **json.loads(algorithms.RSAAlgorithm.to_jwk(key.public_key())),
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
    }


def claims(**changes):
    now = int(time.time())
    return {
        "iss": "https://issuer.example",
        "sub": "collector",
        "iat": now - 1,
        "exp": now + 300,
        "aud": "security-api",
        "client_id": "service-client",
        "scope": "identity:read",
        **changes,
    }


def sign(key, payload, kid="one", typ="at+jwt"):
    return jwt.encode(payload, key, algorithm="RS256", headers={"kid": kid, "typ": typ})


def test_valid_token_and_negative_token_matrix(signing):
    first, other = signing
    provider = OIDCProvider(config(), lambda url, form: {"keys": [jwk(first, "one")]})
    assert provider.validate_access_token(sign(first, claims())).subject == "collector"
    valid = claims()
    cases = [
        sign(first, claims(exp=valid["iat"] - 1000, iat=valid["iat"] - 1200)),
        sign(first, claims(iss="https://untrusted.example")),
        sign(first, claims(aud="different")),
        sign(first, claims(nbf=valid["exp"])),
        sign(first, claims(exp=valid["iat"] + 901)),
        sign(first, claims(scope="wrong")),
        sign(first, claims(client_id="another")),
        sign(first, claims(sub="unknown")),
        sign(first, {key: val for key, val in valid.items() if key != "exp"}),
        sign(other, valid),
        sign(first, valid, typ="JWT"),
        jwt.encode(valid, "", algorithm="none", headers={"kid": "one", "typ": "at+jwt"}),
        jwt.encode(
            valid,
            "synthetic-secret-of-at-least-32-characters",
            algorithm="HS256",
            headers={"kid": "one", "typ": "at+jwt"},
        ),
    ]
    for token in cases:
        with pytest.raises(AuthenticationError):
            provider.validate_access_token(token)


def test_bounded_unknown_key_refresh_and_provider_outage(signing):
    first, second = signing
    now = [0.0]
    calls = []
    keys = [jwk(first, "one")]

    def transport(url, form):
        calls.append(url)
        if not keys:
            raise ProviderUnavailable("unavailable")
        return {"keys": keys.copy()}

    settings = config()
    provider = OIDCProvider(
        settings,
        transport,
        keys=KeyCache(settings.jwks_url, transport, clock=lambda: now[0]),
    )
    provider.validate_access_token(sign(first, claims()))
    for _ in range(3):
        with pytest.raises(AuthenticationError):
            provider.validate_access_token(sign(second, claims(), "rotated"))
    assert calls == [settings.jwks_url]
    now[0] = 6
    keys[:] = [jwk(second, "rotated")]
    assert provider.validate_access_token(sign(second, claims(), "rotated")).subject == "collector"
    now[0] = 400
    keys.clear()
    with pytest.raises(ProviderUnavailable):
        provider.validate_access_token(sign(second, claims(), "rotated"))


def test_nonce_pkce_mfa_invitation_and_cognito_binding(signing):
    key = signing[0]

    def identity_token(**changes):
        payload = claims(
            sub="analyst",
            aud="login-client",
            nonce="nonce-ok",
            amr=["mfa"],
            email="analyst@example.test",
            email_verified=True,
            **changes,
        )
        return sign(key, payload, typ="JWT")

    token = [identity_token()]
    settings = config()

    def transport(url, form):
        if form is None:
            assert url == settings.jwks_url
            return {"keys": [jwk(key, "one")]}
        assert url == settings.token_url and form["code_verifier"] == "credential-verifier"
        return {"id_token": token[0], "refresh_token": "never-stored"}

    provider = OIDCProvider(settings, transport)
    params = parse_qs(
        urlsplit(provider.authorization_redirect("state", "nonce-ok", "challenge")).query
    )
    assert params["code_challenge_method"] == ["S256"] and params["response_type"] == ["code"]
    assert provider.exchange("code", "credential-verifier", "nonce-ok").mfa_verified
    with pytest.raises(AuthenticationError):
        provider.exchange("code", "credential-verifier", "bad-nonce")
    base = claims(sub="analyst", aud="login-client", nonce="nonce-ok", amr=["mfa"])
    for changes in (
        {"amr": ["pwd"]},
        {"sub": "uninvited"},
        {"email": "x@example.test", "email_verified": False},
        {"aud": ["login-client", "another"], "azp": "another"},
    ):
        token[0] = sign(key, {**base, **changes}, typ="JWT")
        with pytest.raises(AuthenticationError):
            provider.exchange("code", "credential-verifier", "nonce-ok")

    cognito = config(
        provider="cognito",
        jwks_url="https://issuer.example/.well-known/jwks.json",
        access_audience=None,
    )
    provider = OIDCProvider(cognito, lambda url, form: {"keys": [jwk(key, "one")]})
    assert (
        provider.validate_access_token(sign(key, claims(token_use="access"), typ="JWT")).subject
        == "collector"
    )
    with pytest.raises(AuthenticationError):
        provider.validate_access_token(sign(key, claims(token_use="id"), typ="JWT"))


def test_provider_endpoints_must_be_explicit_https_and_jwks_stays_on_issuer():
    for data in (
        {"jwks_url": "https://foreign.example/jwks"},
        {"authorization_url": "http://login.example/authorize"},
        {"redirect_uri": "https://app.example/v1/auth/callback?next=elsewhere"},
    ):
        with pytest.raises(ValueError):
            config(**data)
