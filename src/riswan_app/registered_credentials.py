"""Resolve temporary credential providers only after workload authorization."""

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from uuid import UUID

from riswan_platform.authorization.enforcement import AccessDenied
from riswan_platform.core.context import PlatformContext, require_context
from riswan_platform.identity.models import IdentityType
from riswan_platform.identity.principal import require_principal
from riswan_platform.secrets import CredentialLease, ProviderUnavailable
from riswan_platform.secrets.providers import (
    Capability,
    CredentialProvider,
    CredentialRequest,
    Registry,
)

from .secrets import Secrets


@dataclass(frozen=True, slots=True)
class CredentialRegistration:
    instance_id: UUID
    tenant_id: UUID
    product_id: str
    membership_joined: str
    request: CredentialRequest


class RegisteredCredentialBroker:
    def __init__(
        self,
        service: Secrets,
        registry: Registry[CredentialProvider],
        registrations: Mapping[UUID, CredentialRegistration],
    ):
        self._service = service
        self._registry = registry
        self._registrations = dict(registrations)

    def execute(
        self, integration_id: UUID, purpose: str, *, preflight: Callable[[], None] | None = None
    ) -> CredentialLease:
        with self._service._operation(integration_id, None, "credential.lease") as context:
            guard = (
                nullcontext(True)
                if self._service.repository.initializes_sqlite_schema
                else self._service.tenancy.workload_guard(require_principal().identity.identity_id)
            )
            with guard as active:
                if not active:
                    raise AccessDenied
                registered, provider = self._authorized(integration_id, purpose, context)
                if not self._service.repository.initializes_sqlite_schema:
                    self._persist_binding(registered, context)
                if preflight is not None:
                    preflight()
                try:
                    lease = provider.execute(registered.request)
                except Exception:
                    raise ProviderUnavailable("Credential issuance failed.") from None
                if lease.expires_at <= self._service.clock():
                    raise AccessDenied
                if not self._service.repository.initializes_sqlite_schema:
                    with self._service.repository._connection() as db:
                        db.execute(
                            "INSERT INTO credential_leases VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (*self._scope(registered), str(lease.id), lease.expires_at),
                        )
                self._service._audit(
                    context,
                    integration_id,
                    "credential.lease.issued",
                    "success",
                    "ISSUED",
                    provider_instance_id=registered.instance_id,
                    integration_id=integration_id,
                    target_cloud=registered.request.resource.namespace.cloud,
                )
                return lease

    def _authorized(
        self, integration_id: UUID, purpose: str, context: PlatformContext
    ) -> tuple[CredentialRegistration, CredentialProvider]:
        registered = self._registrations.get(integration_id)
        if (
            registered is None
            or registered.tenant_id != context.tenant_id
            or registered.product_id != context.product_id
            or registered.request.integration_id != integration_id
            or registered.request.purpose != purpose
            or str(registered.request.workload_id) != context.actor_id
            or context.actor_type not in {IdentityType.SERVICE, IdentityType.INTEGRATION}
        ):
            raise AccessDenied
        with self._service.repository._connection() as db:
            row = db.execute(
                """SELECT 1 FROM organization_memberships WHERE tenant_id = ? AND identity_id = ?
                AND joined_at = ? AND revoked_at IS NULL""",
                (str(context.tenant_id), context.actor_id, registered.membership_joined),
            ).fetchone()
        if row is None:
            raise AccessDenied
        provider = self._registry.resolve(
            registered.instance_id,
            context.tenant_id,
            context.product_id,
            registered.request.resource.namespace,
            Capability.CREDENTIAL_ISSUE,
        )
        return registered, provider

    @contextmanager
    def publication(self, integration_id: UUID, purpose: str) -> Iterator[None]:
        """Reauthorize under the control lock through the product commit, without provider I/O."""
        with self._lock_authorization(integration_id, purpose, enroll=False):
            yield

    @contextmanager
    def enrollment(self, integration_id: UUID, purpose: str) -> Iterator[None]:
        with self._lock_authorization(integration_id, purpose, enroll=True):
            yield

    @contextmanager
    def _lock_authorization(
        self, integration_id: UUID, purpose: str, *, enroll: bool
    ) -> Iterator[None]:
        context = require_context()
        principal = require_principal()
        repository = self._service.repository
        if repository.initializes_sqlite_schema:
            raise AccessDenied
        with repository.transaction():
            trusted = self._service.tenancy.context_for(
                principal, context.tenant_id, context.product_id, context.request_id
            )
            if (
                trusted is None
                or trusted.actor_id != context.actor_id
                or trusted.actor_type != context.actor_type
            ):
                raise AccessDenied
            with self._service.tenancy.workload_guard(principal.identity.identity_id) as active:
                if not active:
                    raise AccessDenied
                repository.bind_secret_product(context.product_id)
                registered, _ = self._authorized(integration_id, purpose, context)
                if enroll:
                    self._persist_binding(registered, context)
                else:
                    self._verify_binding(registered)
                yield

    @staticmethod
    def _scope(registered: CredentialRegistration) -> tuple[str, ...]:
        return (
            str(registered.tenant_id),
            registered.product_id,
            str(registered.request.integration_id),
            str(registered.request.workload_id),
            registered.membership_joined,
        )

    def _persist_binding(
        self, registered: CredentialRegistration, context: PlatformContext
    ) -> None:
        scope = self._scope(registered)
        instance = str(registered.instance_id)
        payload = registered.request.model_dump_json()
        with self._service.repository.atomic() as db:
            self._service._persist_provider(
                db,
                scope[0],
                scope[1],
                registered.instance_id,
                registered.request.resource.namespace.model_dump_json(),
            )
            inserted = db.execute(
                """INSERT INTO credential_bindings
                (tenant_id, product, integration_id, workload_id, membership_joined, instance_id, request)
                VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING""",
                (*scope, instance, payload),
            ).rowcount
            self._verify_binding(registered)
            if inserted:
                self._service._audit(
                    context,
                    registered.request.integration_id,
                    "credential.binding.created",
                    "success",
                    "WORKLOAD_BOUND",
                    provider_instance_id=registered.instance_id,
                    integration_id=registered.request.integration_id,
                    target_cloud=registered.request.resource.namespace.cloud,
                )

    def _verify_binding(self, registered: CredentialRegistration) -> None:
        scope = self._scope(registered)
        instance = str(registered.instance_id)
        payload = registered.request.model_dump_json()
        with self._service.repository._connection() as db:
            binding = db.execute(
                """SELECT binding FROM secret_provider_bindings
                WHERE tenant_id = ? AND product = ? AND instance_id = ?""",
                (scope[0], scope[1], instance),
            ).fetchone()
            if (
                binding is None
                or binding[0] != registered.request.resource.namespace.model_dump_json()
            ):
                raise AccessDenied
            row = db.execute(
                """SELECT instance_id, request FROM credential_bindings
                WHERE tenant_id = ? AND product = ? AND integration_id = ?
                AND workload_id = ? AND membership_joined = ?""",
                scope,
            ).fetchone()
            if row is None or tuple(row) != (instance, payload):
                raise AccessDenied
