"""Managed cryptography adapters with exact trusted key bindings."""

from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from riswan_platform.secrets import ProviderUnavailable
from riswan_platform.secrets.providers import (
    AWSNamespace,
    AzureNamespace,
    ExternalReference,
    GCPNamespace,
    KeyAlgorithm,
    KeyRequest,
)


class BoundKey:
    def __init__(
        self,
        resource: ExternalReference,
        algorithm: KeyAlgorithm,
        encrypt: Callable[[bytes], bytes],
        decrypt: Callable[[bytes], bytes],
    ):
        self._resource = resource
        self._algorithm = algorithm
        self._encrypt = encrypt
        self._decrypt = decrypt

    def _perform(self, request: KeyRequest, operation: Callable[[bytes], bytes]) -> bytes:
        if request.resource != self._resource or request.algorithm != self._algorithm:
            raise ProviderUnavailable("Managed key operation unavailable for this binding.")
        try:
            result = operation(request.payload)
            if not isinstance(result, bytes) or not result:
                raise ValueError
            return result
        except Exception:
            raise ProviderUnavailable("Managed key operation failed.") from None

    def encrypt(self, request: KeyRequest) -> bytes:
        return self._perform(request, self._encrypt)

    def decrypt(self, request: KeyRequest) -> bytes:
        return self._perform(request, self._decrypt)


def aws_kms(client: Any, resource: ExternalReference) -> BoundKey:
    namespace = resource.namespace
    if (
        not isinstance(namespace, AWSNamespace)
        or not resource.native_id.startswith(
            f"arn:{namespace.partition}:kms:{namespace.region}:{namespace.account}:key/"
        )
        or resource.native_version is not None
    ):
        raise ValueError("AWS KMS key must belong to the configured account and region.")
    key = resource.native_id
    return BoundKey(
        resource,
        KeyAlgorithm.MANAGED_SYMMETRIC,
        lambda payload: client.encrypt(KeyId=key, Plaintext=payload)["CiphertextBlob"],
        lambda payload: client.decrypt(KeyId=key, CiphertextBlob=payload)["Plaintext"],
    )


def azure_key_vault(client: Any, resource: ExternalReference) -> BoundKey:
    namespace = resource.namespace
    parsed = urlsplit(resource.native_id)
    parts = parsed.path.split("/")
    if (
        not isinstance(namespace, AzureNamespace)
        or parsed.scheme != "https"
        or parsed.netloc
        not in {
            f"{namespace.vault}.vault.azure.net",
            f"{namespace.vault}.managedhsm.azure.net",
        }
        or parsed.query
        or parsed.fragment
        or len(parts) != 4
        or parts[1] != "keys"
        or not parts[2]
        or not resource.native_version
        or parts[3] != resource.native_version
        or client.key_id != resource.native_id
    ):
        raise ValueError("Azure key must match the configured versioned vault key.")
    return BoundKey(
        resource,
        KeyAlgorithm.RSA_OAEP_SHA256,
        lambda payload: client.encrypt("RSA-OAEP-256", payload).ciphertext,
        lambda payload: client.decrypt("RSA-OAEP-256", payload).plaintext,
    )


def gcp_kms(client: Any, resource: ExternalReference) -> BoundKey:
    namespace = resource.namespace
    if not isinstance(namespace, GCPNamespace):
        raise ValueError("Google Cloud key requires a project and location.")
    prefix = f"projects/{namespace.project}/locations/{namespace.location}/keyRings/"
    if not resource.native_id.startswith(prefix) or resource.native_version is not None:
        raise ValueError("Google Cloud key must belong to the configured project and location.")
    ring, marker, name = resource.native_id.removeprefix(prefix).partition("/cryptoKeys/")
    if not marker or not ring or not name or "/" in ring or "/" in name:
        raise ValueError("Google Cloud key resource name is invalid.")
    return BoundKey(
        resource,
        KeyAlgorithm.MANAGED_SYMMETRIC,
        lambda payload: (
            client.encrypt(
                request={"name": resource.native_id, "plaintext": payload}, timeout=10, retry=None
            ).ciphertext
        ),
        lambda payload: (
            client.decrypt(
                request={"name": resource.native_id, "ciphertext": payload}, timeout=10, retry=None
            ).plaintext
        ),
    )
