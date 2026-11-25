"""Local configuration and state for telemetry sources."""

import hashlib
from enum import StrEnum
from typing import Annotated, Self

from pydantic import AwareDatetime, ConfigDict, Field, SecretStr, StringConstraints, model_validator

from .base import DomainModel, Text

AccountId = Annotated[str, StringConstraints(pattern=r"^[0-9]{12}$")]
Region = Annotated[str, StringConstraints(pattern=r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$")]


class ConnectorKind(StrEnum):
    HISTORY = "cloudtrail"
    S3 = "s3"


class CloudAccount(DomainModel):
    model_config = ConfigDict(extra="forbid")

    account_id: AccountId
    region: Region
    profile: Text | None = None
    role_arn: (
        Annotated[
            str,
            StringConstraints(
                pattern=r"^arn:aws(?:-[a-z]+)*:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+$"
            ),
        ]
        | None
    ) = None
    external_id: SecretStr | None = None

    @model_validator(mode="after")
    def match_role_account(self) -> Self:
        if self.role_arn and self.role_arn.split(":")[4] != self.account_id:
            raise ValueError("Role ARN must belong to the configured account.")
        if self.external_id is not None and not self.role_arn:
            raise ValueError("External ID requires a role ARN.")
        return self


class S3LogSource(DomainModel):
    model_config = ConfigDict(extra="forbid")

    bucket: Annotated[
        str,
        StringConstraints(min_length=3, max_length=63, pattern=r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$"),
    ]
    bucket_region: Region
    owner_account_id: AccountId
    prefix: Annotated[str, StringConstraints(max_length=400, pattern=r"^[A-Za-z0-9_.=/!-]*$")] = ""
    organization_id: Annotated[str, StringConstraints(pattern=r"^o-[a-z0-9]{10,32}$")] | None = None
    kms_key_arn: (
        Annotated[
            str,
            StringConstraints(
                pattern=r"^arn:aws(?:-[a-z]+)*:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$"
            ),
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def safe_prefix(self) -> Self:
        if any(part in (".", "..", "AWSLogs") for part in self.prefix.split("/")):
            raise ValueError("Use only the optional prefix before AWSLogs.")
        return self


class ConnectorConfig(DomainModel):
    model_config = ConfigDict(extra="forbid")

    kind: ConnectorKind
    account: CloudAccount
    principal: Text
    s3: S3LogSource | None = None
    interval_seconds: int = Field(default=300, ge=30, le=86400)
    window_minutes: int = Field(default=60, ge=1, le=10080)
    overlap_minutes: int = Field(default=15, ge=0, le=10080)
    max_requests: int = Field(default=200, ge=3, le=10000)
    max_events: int = Field(default=10000, ge=1, le=100000)
    max_object_bytes: int = Field(default=8_000_000, ge=1024, le=64_000_000)

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if (self.kind == ConnectorKind.S3) != (self.s3 is not None):
            raise ValueError("S3 settings are required only for the S3 connector.")
        if (
            self.s3
            and self.s3.kms_key_arn
            and self.s3.kms_key_arn.split(":")[3] != self.s3.bucket_region
        ):
            raise ValueError("Use a KMS key in the bucket region.")
        return self

    @property
    def scope(self) -> str:
        parts = [self.kind.value, self.account.account_id, self.account.region, self.principal]
        if self.s3:
            parts.extend(
                [
                    self.s3.bucket,
                    self.s3.bucket_region,
                    self.s3.owner_account_id,
                    self.s3.prefix.strip("/"),
                    self.s3.organization_id or "",
                ]
            )
        return hashlib.sha256("\x00".join(parts).encode()).hexdigest()


class ConnectorCapabilities(DomainModel):
    kind: ConnectorKind
    operations: tuple[str, ...]
    management_events: bool = True
    data_events: bool = False


class CollectionError(DomainModel):
    operation: str
    code: str


class ConnectorStatus(DomainModel):
    scope: str
    attempted_at: AwareDatetime
    healthy: bool
    error: CollectionError | None = None


class CollectionCheckpoint(DomainModel):
    scope: str
    through: AwareDatetime
