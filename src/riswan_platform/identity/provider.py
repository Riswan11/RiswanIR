"""OIDC code exchange and token validation using pinned endpoints and PyJWT."""

import hmac
import json
import time
from collections.abc import Callable
from threading import Lock
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

import jwt
from jwt.exceptions import PyJWTError

from .configuration import OIDCSettings
from .models import AuthenticationError, ExternalIdentity, IdentityType, ProviderUnavailable

Transport = Callable[[str, dict[str, str] | None], dict[str, object]]


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_json(url: str, form: dict[str, str] | None) -> dict[str, object]:
    request = Request(
        url,
        data=urlencode(form).encode() if form is not None else None,
        headers={
            "Accept": "application/json",
            **({"Content-Type": "application/x-www-form-urlencoded"} if form is not None else {}),
        },
    )
    try:
        with build_opener(NoRedirect()).open(request, timeout=4) as response:
            data = response.read(131_073)
        if len(data) > 131_072:
            raise ValueError("OIDC response too large.")
        parsed = json.loads(data)
        if not isinstance(parsed, dict):
            raise ValueError("Invalid OIDC JSON.")
        return parsed
    except (URLError, OSError, ValueError, RecursionError):
        raise ProviderUnavailable("Identity provider request failed.") from None


class KeyCache:
    def __init__(self, url: str, transport: Transport, clock: Callable[[], float] = time.monotonic):
        self._url = url
        self._transport = transport
        self._clock = clock
        self._lock = Lock()
        self._keys: dict[str, jwt.PyJWK] = {}
        self._expires = float("-inf")
        self._last_attempt = float("-inf")

    def key(self, kid: str) -> jwt.PyJWK:
        with self._lock:
            now = self._clock()
            if now < self._expires and kid in self._keys:
                return self._keys[kid]
            if now - self._last_attempt < 5:
                raise AuthenticationError("Signing key unavailable.")
            self._last_attempt = now
            rows = self._transport(self._url, None).get("keys")
            if not isinstance(rows, list) or not 1 <= len(rows) <= 32:
                raise ProviderUnavailable("Invalid provider signing keys.")
            keys = {}
            try:
                for item in rows:
                    if not isinstance(item, dict):
                        raise ValueError("Invalid signing key.")
                    if (
                        item.get("kty") != "RSA"
                        or item.get("use") not in (None, "sig")
                        or item.get("alg") not in (None, "RS256")
                    ):
                        continue
                    key_id = item.get("kid")
                    if not isinstance(key_id, str) or not 1 <= len(key_id) <= 128 or key_id in keys:
                        raise ValueError("Invalid signing key ID.")
                    key = jwt.PyJWK.from_dict(item, algorithm="RS256")
                    if key.key.key_size < 2048 or key.key.key_size > 4096:
                        raise ValueError("Unsupported RSA key size.")
                    keys[key_id] = key
            except (PyJWTError, ValueError, TypeError, AttributeError, OverflowError):
                raise ProviderUnavailable("Invalid provider signing keys.") from None
            self._keys = keys
            self._expires = now + 300
            if kid not in keys:
                raise AuthenticationError("Signing key unavailable.")
            return keys[kid]


class OIDCProvider:
    def __init__(
        self,
        settings: OIDCSettings,
        transport: Transport = fetch_json,
        *,
        keys: KeyCache | None = None,
    ):
        self.settings = settings
        self.transport = transport
        self.keys = keys or KeyCache(settings.jwks_url, transport)

    def authorization_redirect(self, state: str, nonce: str, challenge: str) -> str:
        return (
            self.settings.authorization_url
            + "?"
            + urlencode(
                {
                    "client_id": self.settings.client_id,
                    "redirect_uri": self.settings.redirect_uri,
                    "response_type": "code",
                    "scope": "openid email profile",
                    "state": state,
                    "nonce": nonce,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            )
        )

    def logout_redirect(self) -> str | None:
        if self.settings.logout_url is None:
            return None
        redirect_key = (
            "logout_uri" if self.settings.provider == "cognito" else "post_logout_redirect_uri"
        )
        return (
            self.settings.logout_url
            + "?"
            + urlencode(
                {
                    "client_id": self.settings.client_id,
                    redirect_key: self.settings.post_logout_redirect_uri,
                }
            )
        )

    def _claims(self, token: str, audience: str | None, *, access: bool) -> dict[str, object]:
        if not 1 <= len(token) <= 16_384 or not token.isascii():
            raise AuthenticationError("Invalid credential.")
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if (
                header.get("alg") != "RS256"
                or not isinstance(kid, str)
                or not 1 <= len(kid) <= 128
                or {"jku", "x5u", "crit"} & header.keys()
            ):
                raise AuthenticationError("Invalid credential.")
            if (
                access
                and self.settings.provider == "oidc"
                and header.get("typ") not in {"at+jwt", "application/at+jwt"}
            ):
                raise AuthenticationError("Invalid access token type.")
            key = self.keys.key(kid)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                issuer=self.settings.issuer,
                audience=audience,
                leeway=self.settings.clock_skew_seconds,
                options={
                    "require": ["iss", "sub", "iat", "exp"],
                    "verify_aud": audience is not None,
                },
            )
            issued, expires = claims["iat"], claims["exp"]
            if (
                type(issued) is not int
                or type(expires) is not int
                or expires <= issued
                or ("nbf" in claims and type(claims["nbf"]) is not int)
                or (access and expires - issued > self.settings.access_lifetime_seconds)
            ):
                raise AuthenticationError("Invalid credential lifetime.")
            if self.settings.provider == "cognito" and claims.get("token_use") != (
                "access" if access else "id"
            ):
                raise AuthenticationError("Invalid Cognito token type.")
            sub = claims["sub"]
            if (
                not isinstance(sub, str)
                or not 1 <= len(sub) <= 256
                or not sub.isascii()
                or not sub.isprintable()
            ):
                raise AuthenticationError("Invalid credential subject.")
            return claims
        except (PyJWTError, ValueError, TypeError, OverflowError, RecursionError):
            raise AuthenticationError("Invalid credential.") from None

    def exchange(self, code: str, verifier: str, nonce: str) -> ExternalIdentity:
        tokens = self.transport(
            self.settings.token_url,
            {
                "grant_type": "authorization_code",
                "client_id": self.settings.client_id,
                "redirect_uri": self.settings.redirect_uri,
                "code": code,
                "code_verifier": verifier,
            },
        )
        token = tokens.get("id_token")
        if not isinstance(token, str):
            raise AuthenticationError("Identity token unavailable.")
        claims = self._claims(token, self.settings.client_id, access=False)
        expected = claims.get("nonce")
        if (
            not isinstance(expected, str)
            or not expected.isascii()
            or not hmac.compare_digest(expected, nonce)
        ):
            raise AuthenticationError("Invalid login nonce.")
        aud = claims.get("aud")
        if (isinstance(aud, list) and len(aud) > 1) or "azp" in claims:
            if claims.get("azp") != self.settings.client_id:
                raise AuthenticationError("Invalid login client.")
        subject = str(claims["sub"])
        if subject not in self.settings.invited_subjects:
            raise AuthenticationError("Identity enrollment is required.")
        indicators = claims.get("amr")
        acr = claims.get("acr")
        mfa = (isinstance(indicators, list) and "mfa" in indicators) or (
            isinstance(acr, str) and acr in self.settings.trusted_mfa_acr
        )
        if not mfa and (
            self.settings.require_human_mfa or subject in self.settings.privileged_subjects
        ):
            raise AuthenticationError("Multi-factor authentication is required.")
        email = claims.get("email")
        if email is not None and (
            not isinstance(email, str)
            or not 1 <= len(email) <= 320
            or "@" not in email
            or not email.isprintable()
            or claims.get("email_verified") is not True
        ):
            raise AuthenticationError("Email verification is required.")
        name = claims.get("name")
        return ExternalIdentity(
            self.settings.issuer,
            subject,
            IdentityType.HUMAN,
            name
            if isinstance(name, str) and 1 <= len(name) <= 160 and name.isprintable()
            else "Riswan Labs user",
            email,
            mfa,
        )

    def validate_access_token(self, token: str) -> ExternalIdentity:
        claims = self._claims(token, self.settings.access_audience, access=True)
        subject = str(claims["sub"])
        registration = self.settings.services.get(subject)
        scopes = claims.get("scope")
        if (
            registration is None
            or claims.get("client_id") != registration.client_id
            or not isinstance(scopes, str)
            or len(scopes) > 2048
            or not registration.required_scopes <= set(scopes.split())
        ):
            raise AuthenticationError("Access token is not authorized for a service identity.")
        return ExternalIdentity(
            self.settings.issuer,
            subject,
            IdentityType(registration.identity_type),
            "Registered workload",
        )
