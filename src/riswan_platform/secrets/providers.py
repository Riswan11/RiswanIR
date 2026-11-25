"""SDK-independent provider capabilities and tenant-bound external references."""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Generic, Literal, Protocol, TypeAlias, TypeVar
from uuid import UUID

from pydantic import Field, StringConstraints

from . import CredentialLease, Model, ProviderUnavailable

Label = Annotated[
    str, StringConstraints(min_length=1, max_length=256, pattern=r"^[a-zA-Z0-9_.-]+$")
]
Account = Annotated[str, StringConstraints(pattern=r"^[0-9]{12}$")]


class AWSNamespace(Model):
    cloud: Literal["aws"] = "aws"
    partition: Label
    account: Account
    region: Label


class AzureNamespace(Model):
    cloud: Literal["azure"] = "azure"
    directory_id: UUID
    subscription_id: UUID
    vault: Label


class GCPNamespace(Model):
    cloud: Literal["gcp"] = "gcp"
    project: Label
    location: Label


Namespace: TypeAlias = Annotated[
    AWSNamespace | AzureNamespace | GCPNamespace, Field(discriminator="cloud")
]


class ExternalReference(Model):
    namespace: Namespace
    native_id: Annotated[str, StringConstraints(min_length=1, max_length=2048)]
    native_version: Label | None = None


class SecretPayload(Model):
    value: bytes = Field(min_length=1, max_length=65536, exclude=True, repr=False)


class VersionedSecretProvider(Protocol):
    def read(self, resource: ExternalReference) -> SecretPayload: ...
    def write(self, resource: ExternalReference, material: SecretPayload) -> ExternalReference: ...
    def schedule_delete(self, resource: ExternalReference) -> None: ...
    def deleted(self, resource: ExternalReference) -> bool: ...


class Capability(StrEnum):
    SECRET_READ = "secret.read"
    SECRET_WRITE = "secret.write"
    SECRET_DELETE = "secret.delete"
    KEY_ENCRYPT = "key.encrypt"
    KEY_DECRYPT = "key.decrypt"
    CREDENTIAL_ISSUE = "credential.issue"


class Binding(Model):
    instance_id: UUID
    tenant_id: UUID
    product_id: Label
    namespace: Namespace
    capabilities: frozenset[Capability] = Field(min_length=1)
    development_only: bool = False


class KeyAlgorithm(StrEnum):
    MANAGED_SYMMETRIC = "managed_symmetric"
    RSA_OAEP_SHA256 = "rsa_oaep_sha256"


class KeyRequest(Model):
    resource: ExternalReference
    algorithm: KeyAlgorithm
    payload: bytes = Field(min_length=1, max_length=65536, exclude=True, repr=False)


class ManagedKeyProvider(Protocol):
    def encrypt(self, request: KeyRequest) -> bytes: ...
    def decrypt(self, request: KeyRequest) -> bytes: ...


class CredentialRequest(Model):
    integration_id: UUID
    resource: ExternalReference
    audience: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    workload_id: UUID
    purpose: Label


class CredentialProvider(Protocol):
    def execute(self, request: CredentialRequest) -> CredentialLease:
        """Issue and consume a credential inside a configured adapter operation."""
        ...


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Entry(Generic[T]):
    binding: Binding
    provider: T


class Registry(Generic[T]):
    def __init__(
        self,
        entries: Iterable[Entry[T]],
        *,
        environment: Literal["development", "test", "production"],
    ):
        self._entries: dict[UUID, Entry[T]] = {}
        for entry in entries:
            binding = entry.binding
            if binding.instance_id in self._entries:
                raise ValueError("Provider instance IDs must be unique.")
            if environment == "production" and binding.development_only:
                raise ValueError("Development provider rejected in production.")
            self._entries[binding.instance_id] = entry

    def _entry(self, instance: UUID, tenant: UUID, product: str, namespace: Namespace) -> Entry[T]:
        entry = self._entries.get(instance)
        if entry is None or (
            entry.binding.tenant_id,
            entry.binding.product_id,
            entry.binding.namespace,
        ) != (tenant, product, namespace):
            raise ProviderUnavailable("Provider unavailable for this scope.")
        return entry

    def capabilities(
        self, instance: UUID, tenant: UUID, product: str, namespace: Namespace
    ) -> frozenset[Capability]:
        return self._entry(instance, tenant, product, namespace).binding.capabilities

    def resolve(
        self,
        instance: UUID,
        tenant: UUID,
        product: str,
        namespace: Namespace,
        operation: Capability,
    ) -> T:
        entry = self._entry(instance, tenant, product, namespace)
        if operation not in entry.binding.capabilities:
            raise ProviderUnavailable("Provider operation unsupported.")
        return entry.provider
