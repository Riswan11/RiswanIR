"""Secret value providers. Provider exceptions never cross the boundary."""

import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from riswan_platform.secrets import ProviderUnavailable, SecretMaterial, checked_material


class MemoryProvider:
    name = "memory"
    development_only = True

    def __init__(self):
        self._values: dict[str, bytes] = {}

    def put(self, key: str, material: SecretMaterial) -> None:
        value = checked_material(material)
        if self._values.setdefault(key, value) != value:
            raise ProviderUnavailable("Credential version conflict.")

    def get(self, key: str) -> SecretMaterial:
        try:
            return SecretMaterial(value=self._values[key].decode())
        except KeyError:
            raise ProviderUnavailable("Credential unavailable.") from None

    def schedule_delete(self, key: str) -> None:
        self._values.pop(key, None)

    def deleted(self, key: str) -> bool:
        return key not in self._values


class EncryptedProvider:
    name = "encrypted-local"
    development_only = True

    def __init__(self, path: Path, key: bytes):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if len(key) != 32:
            raise ValueError("The local provider requires a 32-byte AES key.")
        self._cipher = AESGCM(key)
        self.path = path
        if os.name == "posix":
            try:
                os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            except FileExistsError:
                pass
        with closing(sqlite3.connect(path)) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS encrypted_material (id TEXT PRIMARY KEY, content BLOB NOT NULL)"
            )

    def put(self, key: str, material: SecretMaterial) -> None:
        value = checked_material(material)
        nonce = os.urandom(12)
        try:
            with closing(sqlite3.connect(self.path)) as db, db:
                cursor = db.execute(
                    "INSERT OR IGNORE INTO encrypted_material VALUES (?, ?)",
                    (key, nonce + self._cipher.encrypt(nonce, value, key.encode())),
                )
                if not cursor.rowcount and checked_material(self.get(key)) != value:
                    raise ProviderUnavailable("Credential version conflict.")
        except Exception:
            raise ProviderUnavailable("Credential storage unavailable.") from None

    def get(self, key: str) -> SecretMaterial:
        try:
            with closing(sqlite3.connect(self.path)) as db:
                data = db.execute(
                    "SELECT content FROM encrypted_material WHERE id = ?", (key,)
                ).fetchone()[0]
            return SecretMaterial(
                value=self._cipher.decrypt(data[:12], data[12:], key.encode()).decode()
            )
        except Exception:
            raise ProviderUnavailable("Credential unavailable.") from None

    def schedule_delete(self, key: str) -> None:
        try:
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute("DELETE FROM encrypted_material WHERE id = ?", (key,))
        except sqlite3.Error:
            raise ProviderUnavailable("Credential storage unavailable.") from None

    def deleted(self, key: str) -> bool:
        with closing(sqlite3.connect(self.path)) as db:
            return (
                db.execute("SELECT 1 FROM encrypted_material WHERE id = ?", (key,)).fetchone()
                is None
            )


class AWSSecretsProvider:
    name = "aws-secrets-manager"
    development_only = False

    def __init__(self, client: Any, kms_key: str):
        if not kms_key:
            raise ValueError("Configure a Secrets Manager KMS key.")
        self._client = client
        self._kms_key = kms_key

    def put(self, key: str, material: SecretMaterial) -> None:
        value = checked_material(material)
        try:
            self._client.create_secret(
                Name=key,
                SecretBinary=value,
                KmsKeyId=self._kms_key,
                ClientRequestToken=key.rsplit("/", 1)[1],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceExistsException":
                if checked_material(self.get(key)) == value:
                    return
            raise ProviderUnavailable("Credential storage unavailable.") from None
        except Exception:
            raise ProviderUnavailable("Credential storage unavailable.") from None

    def get(self, key: str) -> SecretMaterial:
        try:
            return SecretMaterial(
                value=self._client.get_secret_value(SecretId=key)["SecretBinary"].decode()
            )
        except Exception:
            raise ProviderUnavailable("Credential unavailable.") from None

    def schedule_delete(self, key: str) -> None:
        try:
            if self._client.describe_secret(SecretId=key).get("DeletedDate") is None:
                self._client.delete_secret(SecretId=key, RecoveryWindowInDays=7)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise ProviderUnavailable("Credential deletion unavailable.") from None
        except Exception:
            raise ProviderUnavailable("Credential deletion unavailable.") from None

    def deleted(self, key: str) -> bool:
        try:
            self._client.describe_secret(SecretId=key)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise ProviderUnavailable("Credential status unavailable.") from None
        except Exception:
            raise ProviderUnavailable("Credential status unavailable.") from None
        return False
