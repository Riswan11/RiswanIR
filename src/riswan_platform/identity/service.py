"""Authenticate credentials and establish opaque platform sessions."""

import base64
import hashlib
import hmac
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from threading import Lock
from uuid import UUID, uuid4

from .configuration import OIDCSettings
from .contracts import IdentityProvider, IdentityRepository
from .models import (
    AuditEvent,
    AuthenticationError,
    IdentityStatus,
    IdentityType,
    PlatformIdentity,
    ProviderUnavailable,
    Session,
    VerifiedPrincipal,
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def pkce(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


@dataclass(frozen=True, slots=True)
class LoginAttempt:
    browser_digest: str
    verifier: str
    nonce: str
    expires: float


class LoginTransactions:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._lock = Lock()
        self._attempts: dict[str, LoginAttempt] = {}

    def start(self) -> tuple[str, str, LoginAttempt]:
        state, browser = token_urlsafe(32), token_urlsafe(32)
        now = self._clock()
        attempt = LoginAttempt(digest(browser), token_urlsafe(48), token_urlsafe(32), now + 300)
        with self._lock:
            self._attempts = {
                key: value for key, value in self._attempts.items() if now < value.expires
            }
            if len(self._attempts) >= 1024:
                raise AuthenticationError("Login capacity exhausted.")
            self._attempts[digest(state)] = attempt
        return state, browser, attempt

    def consume(self, state: str, browser: str) -> LoginAttempt:
        key = digest(state)
        with self._lock:
            attempt = self._attempts.get(key)
            if (
                attempt is None
                or attempt.expires <= self._clock()
                or not hmac.compare_digest(attempt.browser_digest, digest(browser))
            ):
                raise AuthenticationError("Invalid login state.")
            self._attempts.pop(key)
            return attempt


class IdentityService:
    def __init__(
        self,
        provider: IdentityProvider,
        repository: IdentityRepository,
        settings: OIDCSettings,
        *,
        transactions: LoginTransactions | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self.provider = provider
        self.repository = repository
        self.settings = settings
        self.transactions = transactions or LoginTransactions()
        self.clock = clock

    def start_login(self) -> tuple[str, str]:
        state, browser, attempt = self.transactions.start()
        return self.provider.authorization_redirect(
            state, attempt.nonce, pkce(attempt.verifier)
        ), browser

    def _event(
        self,
        identifier: str,
        request_id: str,
        principal: VerifiedPrincipal | None = None,
        *,
        outcome="success",
        method="oidc",
    ) -> AuditEvent:
        return AuditEvent(
            f"platform.identity.{identifier}",
            principal.identity.identity_id if principal else None,
            principal.identity.identity_type if principal else None,
            principal.method if principal else method,
            principal.mfa_verified if principal else False,
            request_id,
            outcome,
            self.clock(),
        )

    def finish_login(
        self, code: str, state: str, browser: str, request_id: str, *, old_cookie: str | None = None
    ) -> str:
        try:
            attempt = self.transactions.consume(state, browser)
            external = self.provider.exchange(code, attempt.verifier, attempt.nonce)
            if external.identity_type != IdentityType.HUMAN:
                raise AuthenticationError("Interactive login requires a human identity.")
            now = self.clock()
            identity = self.repository.resolve(external, now)
            principal = VerifiedPrincipal(identity, "oidc", external.mfa_verified)
            session = Session(
                uuid4(),
                identity.identity_id,
                now,
                now,
                now + timedelta(seconds=self.settings.session_absolute_seconds),
                external.mfa_verified,
            )
            secret = token_urlsafe(32)
            self.repository.create_session(
                session,
                digest(secret),
                self._event("session_created", request_id, principal),
                digest(old_cookie) if old_cookie else None,
            )
            self.repository.audit(self._event("login_succeeded", request_id, principal))
            return secret
        except ProviderUnavailable:
            self.repository.audit(self._event("provider_error", request_id, outcome="error"))
            raise
        except AuthenticationError:
            self.repository.audit(self._event("login_failed", request_id, outcome="rejected"))
            raise

    def authenticate(
        self,
        request_id: str,
        *,
        bearer: str | None = None,
        cookie: str | None = None,
    ) -> VerifiedPrincipal:
        try:
            if bearer and not cookie:
                external = self.provider.validate_access_token(bearer)
                if external.identity_type not in {IdentityType.SERVICE, IdentityType.INTEGRATION}:
                    raise AuthenticationError("Workload credential is required.")
                identity = self.repository.resolve(external, self.clock())
                principal = VerifiedPrincipal(identity, "bearer", False)
                self.repository.audit(self._event("service_authenticated", request_id, principal))
                return principal
            if cookie and not bearer:
                principal_ = self.repository.authenticate_session(
                    digest(cookie),
                    self.clock(),
                    self.settings.session_idle_seconds,
                    request_id,
                )
                if principal_ is not None:
                    actor = principal_.identity
                    if (
                        actor.issuer == self.settings.issuer
                        and actor.subject in self.settings.invited_subjects
                    ):
                        if principal_.mfa_verified or (
                            not self.settings.require_human_mfa
                            and actor.subject not in self.settings.privileged_subjects
                        ):
                            return principal_
            raise AuthenticationError("Authentication required.")
        except ProviderUnavailable:
            self.repository.audit(
                self._event("provider_error", request_id, outcome="error", method="bearer")
            )
            raise
        except AuthenticationError:
            self.repository.audit(
                self._event(
                    "token_rejected",
                    request_id,
                    outcome="rejected",
                    method="bearer" if bearer else "session",
                )
            )
            raise

    def sessions(self, principal: VerifiedPrincipal) -> list[Session]:
        return self.repository.sessions(
            principal.identity.identity_id, self.clock(), self.settings.session_idle_seconds
        )

    def revoke(
        self,
        principal: VerifiedPrincipal,
        session_id: UUID,
        request_id: str,
        *,
        logout: bool = False,
    ) -> bool:
        name = "logout_completed" if logout else "session_revoked"
        return self.repository.revoke_session(
            principal.identity.identity_id,
            session_id,
            self.clock(),
            self._event(name, request_id, principal),
        )

    def set_status(self, actor: PlatformIdentity, status: IdentityStatus, request_id: str) -> None:
        now = self.clock()
        event = self._event(
            {
                IdentityStatus.SUSPENDED: "account_suspended",
                IdentityStatus.DISABLED: "account_disabled",
                IdentityStatus.ACTIVE: "account_activated",
            }[status],
            request_id,
            VerifiedPrincipal(actor, "session", False),
            method="lifecycle",
        )
        self.repository.set_status(actor.identity_id, status, now, event)
