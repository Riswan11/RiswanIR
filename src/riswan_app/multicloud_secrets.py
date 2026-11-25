"""Native-version Azure Key Vault and Google Secret Manager adapter primitives."""

import base64
import re
from typing import Any

from riswan_platform.secrets import ProviderUnavailable
from riswan_platform.secrets.providers import (
    AzureNamespace,
    ExternalReference,
    GCPNamespace,
    SecretPayload,
)


class AzureSecretVault:
    def __init__(
        self, client: Any, namespace: AzureNamespace, name: str, not_found: type[Exception]
    ):
        if client.vault_url.rstrip("/") != f"https://{namespace.vault}.vault.azure.net":
            raise ValueError("Azure client must match the registered vault.")
        self._client = client
        self._namespace = namespace
        self._not_found = not_found
        self._registered_name = name

    def _name(self, resource: ExternalReference) -> str:
        if (
            resource.namespace != self._namespace
            or resource.native_id != self._registered_name
            or not re.fullmatch(r"[A-Za-z0-9-]{1,127}", resource.native_id)
        ):
            raise ProviderUnavailable("Secret binding unavailable.")
        return resource.native_id

    def read(self, resource: ExternalReference) -> SecretPayload:
        name = self._name(resource)
        if resource.native_version is None:
            raise ProviderUnavailable("An exact secret version is required.")
        try:
            result = self._client.get_secret(name, resource.native_version)
            if result.properties.version != resource.native_version:
                raise ValueError
            return SecretPayload(value=base64.b64decode(result.value, validate=True))
        except Exception:
            raise ProviderUnavailable("Secret read unavailable.") from None

    def write(self, resource: ExternalReference, material: SecretPayload) -> ExternalReference:
        name = self._name(resource)
        if resource.native_version is not None:
            raise ProviderUnavailable("Native versions are immutable.")
        try:
            result = self._client.set_secret(name, base64.b64encode(material.value).decode("ascii"))
            return ExternalReference(
                namespace=self._namespace, native_id=name, native_version=result.properties.version
            )
        except Exception:
            raise ProviderUnavailable("Secret write unavailable.") from None

    def schedule_delete(self, resource: ExternalReference) -> None:
        name = self._name(resource)
        if resource.native_version is not None:
            raise ProviderUnavailable("Key Vault deletes the entire secret.")
        try:
            self._client.begin_delete_secret(name)
        except self._not_found:
            return
        except Exception:
            raise ProviderUnavailable("Secret deletion unavailable.") from None

    def deleted(self, resource: ExternalReference) -> bool:
        name = self._name(resource)
        if resource.native_version is not None:
            raise ProviderUnavailable("Key Vault deletes the entire secret.")
        try:
            self._client.get_secret(name)
        except self._not_found:
            try:
                self._client.get_deleted_secret(name)
            except self._not_found:
                return True
            except Exception:
                raise ProviderUnavailable("Secret deletion state unavailable.") from None
        except Exception:
            raise ProviderUnavailable("Secret deletion state unavailable.") from None
        return False


class GoogleSecretVersions:
    """Operate on explicitly provisioned regional secrets at exact version IDs."""

    def __init__(self, client: Any, namespace: GCPNamespace, name: str, not_found: type[Exception]):
        self._client = client
        self._namespace = namespace
        self._not_found = not_found
        self._registered_name = name

    def _name(self, resource: ExternalReference, *, versioned: bool) -> str:
        prefix = f"projects/{self._namespace.project}/locations/{self._namespace.location}/secrets/"
        if (
            resource.namespace != self._namespace
            or resource.native_id != prefix + self._registered_name
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,255}", resource.native_id.removeprefix(prefix))
        ):
            raise ProviderUnavailable("Secret binding unavailable.")
        if versioned:
            if not resource.native_version or not re.fullmatch(
                r"[1-9][0-9]*", resource.native_version
            ):
                raise ProviderUnavailable("An exact secret version is required.")
            return f"{resource.native_id}/versions/{resource.native_version}"
        if resource.native_version is not None:
            raise ProviderUnavailable("Native versions are immutable.")
        return resource.native_id

    def read(self, resource: ExternalReference) -> SecretPayload:
        name = self._name(resource, versioned=True)
        try:
            result = self._client.access_secret_version(
                request={"name": name}, timeout=10, retry=None
            )
            return SecretPayload(value=result.payload.data)
        except Exception:
            raise ProviderUnavailable("Secret read unavailable.") from None

    def write(self, resource: ExternalReference, material: SecretPayload) -> ExternalReference:
        parent = self._name(resource, versioned=False)
        try:
            reply = self._client.add_secret_version(
                request={"parent": parent, "payload": {"data": material.value}},
                timeout=10,
                retry=None,
            )
            version = reply.name.removeprefix(parent + "/versions/")
            if not re.fullmatch(r"[1-9][0-9]*", version):
                raise ValueError
            return ExternalReference(
                namespace=self._namespace, native_id=parent, native_version=version
            )
        except Exception:
            raise ProviderUnavailable("Secret write unavailable.") from None

    def schedule_delete(self, resource: ExternalReference) -> None:
        name = self._name(resource, versioned=True)
        try:
            self._client.destroy_secret_version(request={"name": name}, timeout=10, retry=None)
        except self._not_found:
            return
        except Exception:
            raise ProviderUnavailable("Secret deletion unavailable.") from None

    def deleted(self, resource: ExternalReference) -> bool:
        name = self._name(resource, versioned=True)
        try:
            reply = self._client.get_secret_version(request={"name": name}, timeout=10, retry=None)
            return getattr(reply.state, "name", "") == "DESTROYED"
        except self._not_found:
            return True
        except Exception:
            raise ProviderUnavailable("Secret deletion state unavailable.") from None
