"""Shared ownership and protection policy contracts."""

from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID

from pydantic import AwareDatetime, Field

from riswan_platform.core.context import PlatformContext
from riswan_platform.secrets import Model


class ProtectionDenied(PermissionError):
    """An operation cannot satisfy the applicable protection policy."""


class Classification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Ownership(Model):
    tenant_id: UUID
    product_id: str = Field(min_length=1, max_length=64)

    def require(self, context: PlatformContext) -> None:
        if (self.tenant_id, self.product_id) != (context.tenant_id, context.product_id):
            raise ProtectionDenied("Data unavailable for this scope.")


class Residency(Model):
    regions: frozenset[str] = Field(min_length=1)

    def require(self, *destinations: str) -> None:
        if not destinations or any(
            item == "global" or item not in self.regions for item in destinations
        ):
            raise ProtectionDenied("Destination cannot satisfy data residency.")


class Retention(Model):
    days: int = Field(ge=1, le=36500)

    def eligible(self, created_at: AwareDatetime, now: datetime, *, legal_hold: bool) -> bool:
        return not legal_hold and now >= created_at + timedelta(days=self.days)


class DataPolicy(Model):
    classification: Classification
    residency: Residency
    retention: Retention

    @property
    def encrypted(self) -> bool:
        return self.classification in {Classification.CONFIDENTIAL, Classification.RESTRICTED}
