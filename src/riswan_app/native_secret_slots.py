"""Native cloud storage for deterministic, platform-owned secret version slots."""

import base64
from hashlib import sha256
from typing import Any

from riswan_platform.secrets import ProviderUnavailable, SecretMaterial, checked_material


class AzureSlots:
    name = "azure-key-vault"
    development_only = False

    def __init__(self, client: Any, missing: type[Exception]):
        self._client = client
        self._missing = missing

    @staticmethod
    def key(key: str) -> str:
        return "riswan-" + sha256(key.encode()).hexdigest()

    def put(self, key: str, material: SecretMaterial) -> str:
        name = self.key(key)
        value = base64.b64encode(checked_material(material)).decode("ascii")
        try:
            try:
                record = self._client.get_secret(name)
            except self._missing:
                record = self._client.set_secret(name, value)
            if record.value != value:
                raise ValueError
            return str(record.properties.version)
        except Exception:
            raise ProviderUnavailable("Secret storage unavailable.") from None

    def recover_version(self, key: str) -> str:
        try:
            row = self._client.get_secret(self.key(key))
            return str(row.properties.version)
        except Exception:
            raise ProviderUnavailable("Reserved secret version not found.") from None

    def get_version(self, key: str, version: str | None) -> SecretMaterial:
        try:
            record = self._client.get_secret(self.key(key), version)
            if version is not None and record.properties.version != version:
                raise ValueError
            return SecretMaterial(value=base64.b64decode(record.value, validate=True).decode())
        except Exception:
            raise ProviderUnavailable("Secret read unavailable.") from None

    def get(self, key: str) -> SecretMaterial:
        return self.get_version(key, None)

    def schedule_delete(self, key: str) -> None:
        try:
            self._client.begin_delete_secret(self.key(key))
        except self._missing:
            return
        except Exception:
            raise ProviderUnavailable("Secret deletion unavailable.") from None

    def deleted(self, key: str) -> bool:
        try:
            self._client.get_secret(self.key(key))
        except self._missing:
            try:
                self._client.get_deleted_secret(self.key(key))
            except self._missing:
                return True
            except Exception:
                raise ProviderUnavailable("Secret deletion state unavailable.") from None
        except Exception:
            raise ProviderUnavailable("Secret deletion state unavailable.") from None
        return False


class GoogleSlots:
    name = "google-secret-manager"
    development_only = False

    def __init__(
        self, client: Any, project: str, missing: type[Exception], exists: type[Exception]
    ):
        self._client = client
        self._parent = f"projects/{project}"
        self._missing = missing
        self._exists = exists

    def key(self, key: str) -> str:
        return f"{self._parent}/secrets/riswan-{sha256(key.encode()).hexdigest()}"

    def put(self, key: str, material: SecretMaterial) -> str:
        name = self.key(key)
        value = checked_material(material)
        try:
            created = False
            try:
                self._client.create_secret(
                    request={
                        "parent": self._parent,
                        "secret_id": name.rsplit("/", 1)[1],
                        "secret": {
                            "replication": {"automatic": {}},
                            "version_destroy_ttl": {"seconds": 604800},
                        },
                    },
                    timeout=10,
                    retry=None,
                )
                created = True
            except self._exists:
                pass
            if created:
                version = self._client.add_secret_version(
                    request={"parent": name, "payload": {"data": value}}, timeout=10, retry=None
                )
            else:
                # Existing empty slots are ambiguous after a crash. A new operation ID is required.
                (version,) = list(
                    self._client.list_secret_versions(
                        request={"parent": name, "page_size": 2}, timeout=10, retry=None
                    )
                )
            native = version.name.removeprefix(name + "/versions/")
            if not native.isascii() or not native.isdecimal():
                raise ValueError
            if checked_material(self.get_version(key, native)) != value:
                raise ValueError
            return native
        except Exception:
            raise ProviderUnavailable("Secret storage unavailable.") from None

    def recover_version(self, key: str) -> str:
        name = self.key(key)
        try:
            (version,) = list(
                self._client.list_secret_versions(
                    request={"parent": name, "page_size": 2}, timeout=10, retry=None
                )
            )
            native = version.name.removeprefix(name + "/versions/")
            if not native.isascii() or not native.isdecimal():
                raise ValueError
            return native
        except Exception:
            raise ProviderUnavailable("Reserved secret version not found.") from None

    def get_version(self, key: str, version: str | None) -> SecretMaterial:
        try:
            record = self._client.access_secret_version(
                request={"name": f"{self.key(key)}/versions/{version or 'latest'}"},
                timeout=10,
                retry=None,
            )
            return SecretMaterial(value=record.payload.data.decode())
        except Exception:
            raise ProviderUnavailable("Secret read unavailable.") from None

    def get(self, key: str) -> SecretMaterial:
        return self.get_version(key, None)

    def schedule_delete(self, key: str) -> None:
        # The control plane marks pending before calling this destructive adapter. Google exposes
        # version destruction separately, so destroy only the platform-owned slot's version.
        parent = self.key(key)
        try:
            secret = self._client.get_secret(request={"name": parent}, timeout=10, retry=None)
            if secret.version_destroy_ttl.total_seconds() < 86400:
                raise ValueError
            for version in self._client.list_secret_versions(
                request={"parent": parent}, timeout=10, retry=None
            ):
                if version.state.name != "DESTROYED":
                    self._client.destroy_secret_version(
                        request={"name": version.name}, timeout=10, retry=None
                    )
        except self._missing:
            return
        except Exception:
            raise ProviderUnavailable("Secret deletion unavailable.") from None

    def deleted(self, key: str) -> bool:
        try:
            return all(
                version.state.name == "DESTROYED"
                for version in self._client.list_secret_versions(
                    request={"parent": self.key(key)}, timeout=10, retry=None
                )
            )
        except self._missing:
            return True
        except Exception:
            raise ProviderUnavailable("Secret deletion state unavailable.") from None
