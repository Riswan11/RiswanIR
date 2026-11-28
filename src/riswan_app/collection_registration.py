"""Trusted operator configuration for AWS telemetry collection."""

from uuid import UUID

from pydantic import AwareDatetime

from riswan_ir.models.connector import ConnectorConfig
from riswan_platform.secrets import Model
from riswan_platform.secrets.providers import AWSNamespace


class CollectionRegistration(Model):
    integration_id: UUID
    instance_id: UUID
    tenant_id: UUID
    workload_id: UUID
    membership_joined: AwareDatetime
    namespace: AWSNamespace
    connector: ConnectorConfig
