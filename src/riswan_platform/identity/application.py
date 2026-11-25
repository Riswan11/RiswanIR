"""WSGI authentication and delegation to trusted application routes."""

import json
import re
import time
from collections.abc import Callable
from dataclasses import asdict
from http import HTTPStatus
from threading import Lock
from urllib.parse import parse_qs
from uuid import UUID, uuid4

from .models import AuthenticationError, ProviderUnavailable, VerifiedPrincipal
from .principal import bind_principal
from .service import IdentityService

SESSION = "__Host-riswan_session"
LOGIN = "__Host-riswan_login"
SECRET = re.compile(r"[A-Za-z0-9_-]{43}")


def _cookie(name: str, value: str, age: int) -> tuple[str, str]:
    return "Set-Cookie", f"{name}={value}; Path=/; Max-Age={age}; Secure; HttpOnly; SameSite=Lax"


def _credential_cookie(environ, name: str) -> str | None:
    header = environ.get("HTTP_COOKIE", "")
    if len(header) > 8192:
        raise AuthenticationError("Invalid cookies.")
    found = [
        part.partition("=")[2]
        for item in header.split(";")
        if (part := item.strip()).partition("=")[0] == name
    ]
    if not found:
        return None
    if len(found) != 1 or not SECRET.fullmatch(found[0]):
        raise AuthenticationError("Invalid session cookie.")
    return found[0]


class RequestBudget:
    """Small fixed-window throttle independent of untrusted forwarded-address headers."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._window = -1
        self._counts: dict[str, int] = {}
        self._total = 0
        self._lock = Lock()

    def allow(self, address: str) -> bool:
        with self._lock:
            window = int(self._clock() // 60)
            if window != self._window:
                self._window = window
                self._counts.clear()
                self._total = 0
            count = self._counts.get(address, 0)
            if count >= 120 or self._total >= 1200:
                return False
            self._counts[address] = count + 1
            self._total += 1
            return True


class IdentityApplication:
    def __init__(
        self,
        service: IdentityService,
        budget: RequestBudget | None = None,
        authenticated_routes: Callable[[dict, VerifiedPrincipal, str], tuple[int, object] | None]
        | None = None,
    ):
        self.service = service
        self.budget = budget or RequestBudget()
        self._authenticated_routes = authenticated_routes

    def __call__(self, env, start_response):
        request_id = uuid4().hex
        headers = [
            ("Content-Type", "application/json"),
            ("Cache-Control", "no-store"),
            ("Referrer-Policy", "no-referrer"),
            ("X-Content-Type-Options", "nosniff"),
        ]
        try:
            status, result = self._route(env, headers, request_id)
        except ProviderUnavailable:
            status, result = 503, {"error": "Identity provider unavailable."}
        except AuthenticationError:
            status, result = 401, {"error": "Authentication required or rejected."}
        body = b"" if result is None else json.dumps(result, default=str).encode()
        headers.append(("Content-Length", str(len(body))))
        start_response(f"{status} {HTTPStatus(status).phrase}", headers)
        return [body]

    def _route(self, env, headers: list[tuple[str, str]], request_id: str):
        if (
            env.get("HTTP_HOST", "").lower()
            != self.service.settings.origin.removeprefix("https://").lower()
        ):
            return 400, {"error": "Unexpected application host."}
        if not self.budget.allow(env.get("REMOTE_ADDR", "")[:64]):
            headers.append(("Retry-After", "60"))
            return 429, {"error": "Too many authentication requests."}
        method, path = env["REQUEST_METHOD"], env["PATH_INFO"]
        if (method, path) == ("GET", "/v1/auth/login"):
            location, binding = self.service.start_login()
            headers.extend([("Location", location), _cookie(LOGIN, binding, 300)])
            return 302, None
        if (method, path) == ("GET", "/v1/auth/callback"):
            try:
                query = env.get("QUERY_STRING", "")
                if len(query) > 4096:
                    raise ValueError
                fields = parse_qs(query, strict_parsing=True, max_num_fields=8)
                state, code = fields.get("state", []), fields.get("code", [])
                valid = (
                    len(state) == len(code) == 1
                    and SECRET.fullmatch(state[0])
                    and len(code[0]) <= 2048
                    and code[0].isascii()
                    and code[0].isprintable()
                    and "error" not in fields
                )
                if not valid:
                    raise ValueError
                browser = _credential_cookie(env, LOGIN)
            except (ValueError, AuthenticationError):
                browser = None
            headers.append(_cookie(LOGIN, "", 0))
            if browser is None:
                # A malformed callback follows the same audited generic rejection path.
                self.service.finish_login("", "", "", request_id)
                raise AuthenticationError("Invalid callback.")
            secret = self.service.finish_login(
                code[0],
                state[0],
                browser,
                request_id,
                old_cookie=_credential_cookie(env, SESSION),
            )
            headers.extend(
                [
                    _cookie(SESSION, secret, self.service.settings.session_absolute_seconds),
                    ("Location", "/v1/identity/me"),
                ]
            )
            return 303, None

        authorization = env.get("HTTP_AUTHORIZATION", "")
        prefix, separator, bearer = authorization.partition(" ")
        if authorization and (
            prefix.lower() != "bearer"
            or not separator
            or not bearer
            or len(bearer) > 16384
            or any(char.isspace() for char in bearer)
        ):
            # Reject malformed headers rather than falling back to a browser cookie.
            self.service.authenticate(request_id)
        principal = self.service.authenticate(
            request_id,
            bearer=bearer or None,
            cookie=_credential_cookie(env, SESSION),
        )
        with bind_principal(principal):
            return self._authenticated(env, headers, request_id, principal)

    def _authenticated(
        self,
        env,
        headers: list[tuple[str, str]],
        request_id: str,
        principal: VerifiedPrincipal,
    ):
        method, path = env["REQUEST_METHOD"], env["PATH_INFO"]
        if (method, path) == ("GET", "/v1/identity/me"):
            actor = principal.identity
            return 200, {
                "identity_id": str(actor.identity_id),
                "identity_type": actor.identity_type,
                "display_name": actor.display_name,
                "email": actor.email,
                "authentication_method": principal.method,
                "mfa_verified": principal.mfa_verified,
            }
        if (method, path) == ("GET", "/v1/identity/sessions"):
            if principal.session_id is None:
                return 403, {"error": "A browser session is required."}
            return 200, {"sessions": [asdict(item) for item in self.service.sessions(principal)]}
        if method in {"POST", "DELETE"} and (
            path in {"/v1/auth/logout", "/v1/auth/refresh"}
            or path.startswith("/v1/identity/sessions/")
        ):
            if (
                principal.session_id is None
                or env.get("HTTP_ORIGIN") != self.service.settings.origin
            ):
                return 403, {"error": "Trusted same-origin session required."}
            if (method, path) == ("POST", "/v1/auth/refresh"):
                return 409, {"error": "Start a new sign-in to renew the session."}
            if (method, path) == ("POST", "/v1/auth/logout"):
                self.service.revoke(principal, principal.session_id, request_id, logout=True)
                headers.append(_cookie(SESSION, "", 0))
                location = self.service.provider.logout_redirect()
                if location:
                    headers.append(("Location", location))
                    return 303, None
                return 204, None
            if method == "DELETE" and path.startswith("/v1/identity/sessions/"):
                try:
                    identifier = UUID(path.removeprefix("/v1/identity/sessions/"))
                except ValueError:
                    return 404, {"error": "Session not found."}
                if not self.service.revoke(principal, identifier, request_id):
                    return 404, {"error": "Session not found."}
                if identifier == principal.session_id:
                    headers.append(_cookie(SESSION, "", 0))
                return 204, None
        if self._authenticated_routes is not None:
            result = self._authenticated_routes(env, principal, request_id)
            if result is not None:
                return result
        if path.startswith("/v1/investigations") or path.startswith("/v1/memory"):
            return 403, {"error": "Product access requires authorized tenant membership."}
        return 404, {"error": "Route not found."}
