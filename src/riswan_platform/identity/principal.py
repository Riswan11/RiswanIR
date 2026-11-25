"""Bind an authenticated actor without granting product or tenant access."""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from .models import AuthenticationError, VerifiedPrincipal

_principal: ContextVar[VerifiedPrincipal | None] = ContextVar(
    "authenticated_principal", default=None
)


@contextmanager
def bind_principal(principal: VerifiedPrincipal) -> Iterator[None]:
    current = _principal.get()
    if current is not None and current != principal:
        raise AuthenticationError("Active principal cannot be replaced.")
    token = _principal.set(principal)
    try:
        yield
    finally:
        _principal.reset(token)


def require_principal() -> VerifiedPrincipal:
    principal = _principal.get()
    if principal is None:
        raise AuthenticationError("Authentication required.")
    return principal
