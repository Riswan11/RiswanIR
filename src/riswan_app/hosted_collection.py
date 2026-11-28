"""Hosted, registered read-only CloudTrail collection."""

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic
from typing import Any
from uuid import UUID

from pydantic import TypeAdapter

from riswan_ir.connectors.aws.authentication import service_client
from riswan_ir.connectors.aws.cloudtrail import CloudTrailHistory
from riswan_ir.connectors.aws.requests import RequestBudget
from riswan_ir.connectors.aws.s3 import S3CloudTrailLogs
from riswan_ir.connectors.base import CollectionFailure, TelemetryConnector
from riswan_ir.models import CloudTrailRecord, InvestigationRequest
from riswan_ir.models.collection import CollectionRequest
from riswan_ir.models.connector import ConnectorConfig
from riswan_ir.storage.sqlite import Store
from riswan_platform.authorization.enforcement import AccessDenied
from riswan_platform.core.context import bind_context
from riswan_platform.identity.models import VerifiedPrincipal
from riswan_platform.secrets import ProviderUnavailable
from riswan_platform.secrets.providers import (
    Binding,
    Capability,
    CredentialProvider,
    CredentialRequest,
    Entry,
    ExternalReference,
    Registry,
)
from riswan_security_data.provenance import CollectionContext

from .collection_registration import CollectionRegistration
from .credential_broker import AWSSTS, AWSRoleOperation
from .postgres_collections import PostgresCollections
from .registered_credentials import CredentialRegistration, RegisteredCredentialBroker
from .secrets import Secrets


def _source(
    config: ConnectorConfig, session: Any, check: Callable[[], None] | None = None
) -> TelemetryConnector:
    budget = RequestBudget(min(config.max_requests, 20), check=check)
    if config.s3 is None:
        return CloudTrailHistory(
            config, service_client(session, "cloudtrail", config.account.region), budget
        )
    return S3CloudTrailLogs(config, service_client(session, "s3", config.s3.bucket_region), budget)


def _collect(store: Store, entry: CollectionRegistration, session: Any) -> None:
    config = entry.connector
    now = datetime.now(UTC)
    source = _source(config, session)
    records: list[CloudTrailRecord] = []
    limit = min(config.max_events, 2000)
    for batch in source.collect(
        CollectionRequest(start=now - timedelta(minutes=15), end=now, incremental=False)
    ):
        records.extend(batch.records[: limit - len(records)])
        if len(records) >= limit:
            break
    if records:
        store.create(
            InvestigationRequest(
                title="Hosted AWS telemetry collection",
                principal=config.principal,
                records=records,
                provenance=CollectionContext(
                    collection_method="connector",
                    collector_id=str(entry.integration_id),
                    collection_account_id=config.account.account_id,
                    collection_region=config.account.region,
                ),
            )
        )


def _credential(entry: CollectionRegistration) -> tuple[Binding, CredentialRequest]:
    role = entry.connector.account.role_arn
    if role is None:
        raise ValueError("Collection integrations require an AWS role.")
    return (
        Binding(
            instance_id=entry.instance_id,
            tenant_id=entry.tenant_id,
            product_id="ir",
            namespace=entry.namespace,
            capabilities={Capability.CREDENTIAL_ISSUE},
        ),
        CredentialRequest(
            integration_id=entry.integration_id,
            workload_id=entry.workload_id,
            purpose="collect",
            audience="sts.amazonaws.com",
            resource=ExternalReference(namespace=entry.namespace, native_id=role),
        ),
    )


def load_collections(path: Path, service: Secrets, store: Store) -> RegisteredCredentialBroker:
    with path.open("rb") as stream:
        data = stream.read(262145)
    if len(data) > 262144:
        raise ValueError("Collection registrations are too large.")
    entries: list[Entry[CredentialProvider]] = []
    registrations: dict[UUID, CredentialRegistration] = {}
    for entry in TypeAdapter(list[CollectionRegistration]).validate_json(data):
        if entry.integration_id in registrations or not entry.connector.account.role_arn:
            raise ValueError("Collection integrations require a unique ID and an AWS role.")
        binding, request = _credential(entry)

        def operation(session: Any, registered: CollectionRegistration = entry) -> None:
            _collect(store, registered, session)

        entries.append(
            Entry(binding, AWSRoleOperation(request, entry.connector, AWSSTS(), operation))
        )
        registrations[entry.integration_id] = CredentialRegistration(
            entry.instance_id,
            entry.tenant_id,
            "ir",
            entry.membership_joined.astimezone(UTC).isoformat(),
            request,
        )
    return RegisteredCredentialBroker(
        service, Registry(entries, environment="production"), registrations
    )


class CollectionAPI:
    def __init__(self, service: Secrets, broker: RegisteredCredentialBroker):
        self.service = service
        self.broker = broker

    def route(self, env, principal: VerifiedPrincipal, request_id: str):
        route = re.fullmatch(r"/v1/integrations/([a-f0-9-]{36})/collect", env["PATH_INFO"])
        tenant = env.get("HTTP_X_RISWAN_TENANT", "")
        if (
            not route
            or env["REQUEST_METHOD"] != "POST"
            or not re.fullmatch(r"[a-f0-9-]{36}", tenant)
        ):
            raise AccessDenied
        try:
            tenant_id, integration_id = UUID(tenant), UUID(route[1])
        except ValueError as exc:
            raise AccessDenied from exc
        context = self.service.tenancy.context_for(principal, tenant_id, "ir", request_id)
        if context is None:
            raise AccessDenied
        with bind_context(context):
            try:
                self._execute(integration_id)
            except ProviderUnavailable:
                return 503, {"error": "Collection unavailable."}
        return 204, None

    def _execute(self, integration_id: UUID) -> None:
        self.broker.execute(integration_id, "collect")


@dataclass(frozen=True, slots=True)
class PreviewCollection:
    registration: CollectionRegistration
    provider: AWSSTS


class PostgresCollectionAPI(CollectionAPI):
    def __init__(
        self,
        service: Secrets,
        repository: PostgresCollections,
        entries: tuple[PreviewCollection, ...],
    ):
        self.service = service
        self._repository = repository
        self._entries: dict[UUID, tuple[PreviewCollection, Binding, CredentialRequest]] = {}
        for item in entries:
            entry = item.registration
            if item.provider.development_only is not True or entry.integration_id in self._entries:
                raise ValueError(
                    "Preview collections require unique registrations and development-only adapters."
                )
            binding, request = _credential(entry)
            AWSRoleOperation(request, entry.connector, item.provider, lambda _: None)
            self._entries[entry.integration_id] = (item, binding, request)

    def _execute(self, integration_id: UUID) -> None:
        from psycopg import Error
        from psycopg_pool import PoolClosed, PoolTimeout

        configured = self._entries.get(integration_id)
        if configured is None:
            raise AccessDenied
        item, binding, request = configured
        entry = item.registration
        captured: list[Any] = []
        provider = AWSRoleOperation(request, entry.connector, item.provider, captured.append)
        registry: Registry[CredentialProvider] = Registry(
            [Entry(binding, provider)], environment="development"
        )
        registration = CredentialRegistration(
            entry.instance_id,
            entry.tenant_id,
            "ir",
            entry.membership_joined.astimezone(UTC).isoformat(),
            request,
        )
        broker = RegisteredCredentialBroker(self.service, registry, {integration_id: registration})
        try:
            with broker.enrollment(integration_id, "collect"):
                self._repository.register(entry)
                expected, window = self._repository.reserve_window(entry, datetime.now(UTC))
            if window is None:
                return
            lease = broker.execute(
                integration_id,
                "collect",
                preflight=lambda: self._repository.confirm_registration(entry),
            )
            deadline = monotonic() + 120

            def check() -> None:
                self._repository._require_live(deadline, lease.expires_at)

            self._repository.collect_and_publish(
                entry,
                window,
                expected,
                _source(entry.connector, captured.pop(), check),
                authorize=lambda: broker.publication(integration_id, "collect"),
                expires_at=lease.expires_at,
            )
        except CollectionFailure as exc:
            if exc.error.code == "registration_conflict":
                raise AccessDenied from None
            raise ProviderUnavailable("Collection could not be published.") from None
        except (Error, PoolClosed, PoolTimeout):
            raise ProviderUnavailable("Collection storage unavailable.") from None
        finally:
            captured.clear()
