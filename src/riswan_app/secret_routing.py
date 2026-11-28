"""Resolve secret operations from operator-owned tenant/product bindings."""

from dataclasses import dataclass
from uuid import UUID

from riswan_platform.secrets import ProviderUnavailable, SecretMetadata, SecretProvider
from riswan_platform.secrets.providers import Capability, Namespace, Registry


@dataclass(frozen=True, slots=True)
class SecretDestination:
    instance_id: UUID
    namespace: Namespace


class SecretRouting:
    def __init__(
        self,
        registry: Registry[SecretProvider],
        destinations: dict[tuple[UUID, str], SecretDestination],
    ):
        self._registry = registry
        self._destinations = dict(destinations)

    def require_development_only(self) -> None:
        for (tenant, product), destination in self._destinations.items():
            available = self._registry.capabilities(
                destination.instance_id, tenant, product, destination.namespace
            )
            provider = self._registry.resolve(
                destination.instance_id, tenant, product, destination.namespace, min(available)
            )
            if provider.development_only is not True:
                raise ValueError("PostgreSQL preview requires development-only secret adapters.")

    def destination(self, tenant: UUID, product: str) -> SecretDestination | None:
        return self._destinations.get((tenant, product))

    def resolve(
        self, tenant: UUID, product: str, instance: UUID, capability: Capability
    ) -> SecretProvider:
        destination = self.destination(tenant, product)
        if destination is None or destination.instance_id != instance:
            raise ProviderUnavailable("Secret provider binding unavailable.")
        return self._registry.resolve(instance, tenant, product, destination.namespace, capability)

    def provider(self, item: SecretMetadata, capability: Capability) -> SecretProvider:
        if item.provider_instance_id is None:
            raise ProviderUnavailable("Secret provider binding unavailable.")
        provider = self.resolve(
            item.tenant_id, item.product_id, item.provider_instance_id, capability
        )
        if provider.name != item.provider:
            raise ProviderUnavailable("Secret provider binding unavailable.")
        return provider
