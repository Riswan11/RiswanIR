"""Immutable, tenant-bound encrypted object storage contract."""

from collections.abc import Callable
from hashlib import sha256
from typing import Protocol
from uuid import UUID

from riswan_platform.core.context import PlatformContext, require_context
from riswan_platform.secrets import Model

from . import DataPolicy, ProtectionDenied
from .envelope import DataIdentity, Envelope, EnvelopeProtector


class ObjectBackend(Protocol):
    def put(self, key: str, payload: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...
    def delete(self, key: str) -> None: ...


class ObjectReference(Model):
    id: UUID


class Destinations(Model):
    storage: str
    processing: str
    key: str
    backup: str

    def regions(self) -> tuple[str, ...]:
        return (self.storage, self.processing, self.key, self.backup)


class ProtectedObjects:
    def __init__(
        self,
        backend: ObjectBackend,
        protector: EnvelopeProtector,
        destinations: Destinations,
        authorize: Callable[[PlatformContext, DataIdentity, str], bool],
    ):
        self._backend = backend
        self._protector = protector
        self._destinations = destinations
        self._authorize = authorize

    def _key(
        self, identity: DataIdentity, reference: ObjectReference, policy: DataPolicy, operation: str
    ) -> str:
        context = require_context()
        identity.owner.require(context)
        if (
            identity.resource_id != str(reference.id)
            or policy.classification != identity.classification
            or not self._authorize(context, identity, operation)
        ):
            raise ProtectionDenied("Protected object unavailable.")
        policy.residency.require(*self._destinations.regions())
        # Do not let any user-controlled resource label become a path segment.
        product = sha256(identity.owner.product_id.encode()).hexdigest()
        return f"{identity.owner.tenant_id.hex}/{product}/{reference.id.hex}"

    def put(
        self, identity: DataIdentity, reference: ObjectReference, policy: DataPolicy, value: bytes
    ) -> None:
        key = self._key(identity, reference, policy, "put")
        envelope = self._protector.seal(identity, value).model_dump_json().encode()
        try:
            self._backend.put(key, envelope)
        except Exception:
            raise ProtectionDenied("Protected object write failed.") from None

    def get(self, identity: DataIdentity, reference: ObjectReference, policy: DataPolicy) -> bytes:
        key = self._key(identity, reference, policy, "get")
        try:
            envelope = Envelope.model_validate_json(self._backend.get(key))
        except Exception:
            raise ProtectionDenied("Protected object unavailable.") from None
        return self._protector.open(identity, envelope)
