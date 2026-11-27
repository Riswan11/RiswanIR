"""Authenticate record ownership and wrap data keys with a registered managed key."""

import base64
import json
import os
from uuid import UUID

from pydantic import Field

from riswan_platform.core.context import require_context
from riswan_platform.secrets import Model
from riswan_platform.secrets.providers import (
    Capability,
    ExternalReference,
    KeyAlgorithm,
    KeyRequest,
    ManagedKeyProvider,
    Registry,
)

from . import Classification, Ownership, ProtectionDenied


class DataIdentity(Model):
    owner: Ownership
    resource_type: str = Field(min_length=1, max_length=80)
    resource_id: str = Field(min_length=1, max_length=256)
    classification: Classification

    def aad(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()


class KeyBinding(Model):
    instance_id: UUID
    resource: ExternalReference
    algorithm: KeyAlgorithm


class Envelope(Model):
    version: int = 1
    key_instance_id: UUID
    nonce: str
    wrapped_key: str
    ciphertext: str


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


class EnvelopeProtector:
    def __init__(
        self,
        registry: Registry[ManagedKeyProvider],
        current_keys: dict[tuple[UUID, str], UUID],
        bindings: dict[UUID, KeyBinding],
    ):
        self._registry = registry
        self._current = dict(current_keys)
        self._bindings = dict(bindings)

    def _key(
        self, identity: DataIdentity, instance: UUID, payload: bytes, capability: Capability
    ) -> bytes:
        identity.owner.require(require_context())
        binding = self._bindings.get(instance)
        if binding is None or binding.instance_id != instance:
            raise ProtectionDenied("Managed key unavailable.")
        provider = self._registry.resolve(
            instance,
            identity.owner.tenant_id,
            identity.owner.product_id,
            binding.resource.namespace,
            capability,
        )
        request = KeyRequest(
            resource=binding.resource, algorithm=binding.algorithm, payload=payload
        )
        return (
            provider.encrypt(request)
            if capability == Capability.KEY_ENCRYPT
            else provider.decrypt(request)
        )

    def seal(self, identity: DataIdentity, plaintext: bytes) -> Envelope:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        identity.owner.require(require_context())
        try:
            instance = self._current[(identity.owner.tenant_id, identity.owner.product_id)]
            dek, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
            wrapped = self._key(identity, instance, dek, Capability.KEY_ENCRYPT)
            return Envelope(
                key_instance_id=instance,
                nonce=_encode(nonce),
                wrapped_key=_encode(wrapped),
                ciphertext=_encode(AESGCM(dek).encrypt(nonce, plaintext, identity.aad())),
            )
        except Exception:
            raise ProtectionDenied("Data encryption unavailable.") from None

    def open(self, identity: DataIdentity, envelope: Envelope) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        identity.owner.require(require_context())
        if envelope.version != 1:
            raise ProtectionDenied("Envelope version unsupported.")
        try:
            dek = self._key(
                identity,
                envelope.key_instance_id,
                _decode(envelope.wrapped_key),
                Capability.KEY_DECRYPT,
            )
            return AESGCM(dek).decrypt(
                _decode(envelope.nonce), _decode(envelope.ciphertext), identity.aad()
            )
        except Exception:
            raise ProtectionDenied("Protected data unavailable.") from None

    def rewrap(self, identity: DataIdentity, envelope: Envelope) -> Envelope:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        identity.owner.require(require_context())
        if envelope.version != 1:
            raise ProtectionDenied("Envelope version unsupported.")
        try:
            dek = self._key(
                identity,
                envelope.key_instance_id,
                _decode(envelope.wrapped_key),
                Capability.KEY_DECRYPT,
            )
            AESGCM(dek).decrypt(
                _decode(envelope.nonce), _decode(envelope.ciphertext), identity.aad()
            )
            instance = self._current[(identity.owner.tenant_id, identity.owner.product_id)]
            wrapped = self._key(identity, instance, dek, Capability.KEY_ENCRYPT)
            return envelope.model_copy(
                update={"key_instance_id": instance, "wrapped_key": _encode(wrapped)}
            )
        except Exception:
            raise ProtectionDenied("Key rewrapping unavailable.") from None
