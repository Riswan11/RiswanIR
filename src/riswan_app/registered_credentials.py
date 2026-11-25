"""Resolve temporary credential providers only after workload authorization."""

from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from riswan_platform.authorization.enforcement import AccessDenied
from riswan_platform.identity.models import IdentityType
from riswan_platform.secrets import CredentialLease
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

    def execute(self, integration_id: UUID, purpose: str) -> CredentialLease:
        with self._service._operation(integration_id, None, "credential.lease") as context:
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
            lease = provider.execute(registered.request)
            if lease.expires_at <= self._service.clock():
                raise AccessDenied
            self._service._audit(
                context, integration_id, "credential.lease.issued", "success", "ISSUED"
            )
            return lease
