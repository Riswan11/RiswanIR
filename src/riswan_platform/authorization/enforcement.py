"""Enforcement shared by HTTP handlers and trusted execution adapters."""

from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager, nullcontext
from typing import Protocol

from riswan_platform.core.context import require_context
from riswan_platform.identity.principal import require_principal

from . import AuthorizationEngine, AuthorizationRequest, Permission, Resource, Scope, ScopeType


class AccessDenied(PermissionError):
    """Public authorization failure with no resource or policy details."""


class ResourceDirectory(Protocol):
    def resolve(self, kind: ScopeType, key: str) -> Resource | None: ...
    def investigations(self) -> Iterable[Resource]: ...


class Enforcement:
    def __init__(
        self,
        engine: AuthorizationEngine,
        resources: ResourceDirectory,
        transaction: Callable[[], AbstractContextManager[None]] | None = None,
    ):
        self.engine = engine
        self.resources = resources
        self._transaction = transaction

    def operation(self, *, mutation: bool = False) -> AbstractContextManager[None]:
        if self._transaction is not None:
            return self._transaction()
        if mutation:
            raise AccessDenied
        return nullcontext()

    def _allowed(self, action: Permission, resource: Resource) -> bool:
        return self.engine.evaluate(
            AuthorizationRequest(require_principal(), require_context(), action, resource)
        ).allowed

    def require(
        self, action: Permission, kind: ScopeType, key: str, *, parent: Scope | None = None
    ) -> None:
        try:
            resource = self.resources.resolve(kind, key)
            if (
                resource is not None
                and resource.scope == Scope(kind, key)
                and (parent is None or parent in resource.parents)
                and self._allowed(action, resource)
            ):
                return
        except Exception as exc:
            raise AccessDenied from exc
        raise AccessDenied

    def investigation_ids(self, action: Permission = Permission.READ) -> tuple[str, ...]:
        try:
            require_principal()
            require_context()
            return tuple(
                resource.scope.id
                for resource in self.resources.investigations()
                if resource.scope.kind == ScopeType.INVESTIGATION
                and self._allowed(action, resource)
            )
        except Exception as exc:
            raise AccessDenied from exc
