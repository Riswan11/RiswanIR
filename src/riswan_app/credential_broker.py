"""Trusted connector-only AWS STS credential brokering."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import boto3

from riswan_ir.connectors.aws.authentication import assume_read_only, service_client
from riswan_ir.connectors.aws.requests import RequestBudget
from riswan_ir.models.connector import ConnectorConfig
from riswan_platform.authorization.enforcement import AccessDenied
from riswan_platform.identity.models import IdentityType
from riswan_platform.identity.principal import require_principal
from riswan_platform.secrets import CredentialLease, ProviderUnavailable, Result
from riswan_platform.secrets.providers import AWSNamespace, CredentialRequest

from .secrets import Secrets


@dataclass(frozen=True, slots=True)
class RegisteredIntegration:
    tenant_id: UUID
    product_id: str
    workload_id: UUID
    membership_joined: str
    purpose: str
    config: ConnectorConfig


class AWSSTS:
    def session(self, config: ConnectorConfig, now: datetime) -> tuple[Any, CredentialLease]:
        try:
            account = config.account
            source = boto3.Session(region_name=account.region)
            issued = assume_read_only(config, source, RequestBudget(4))
            expiry = issued["Expiration"]
            if not isinstance(expiry, datetime) or not now < expiry <= now + timedelta(minutes=16):
                raise ValueError
            session = boto3.Session(
                aws_access_key_id=issued["AccessKeyId"],
                aws_secret_access_key=issued["SecretAccessKey"],
                aws_session_token=issued["SessionToken"],
                region_name=account.region,
            )
            if (
                service_client(session, "sts", account.region).get_caller_identity()["Account"]
                != account.account_id
            ):
                raise ValueError
            return session, CredentialLease(id=uuid4(), expires_at=expiry)
        except Exception:
            raise ProviderUnavailable("Temporary credential issuance unavailable.") from None


class AWSRoleOperation:
    """Adapt a registered AWS collection operation to the shared lease contract."""

    def __init__(
        self,
        registration: CredentialRequest,
        config: ConnectorConfig,
        provider: AWSSTS,
        perform: Callable[[Any], None],
    ):
        account = config.account
        namespace = registration.resource.namespace
        if (
            not isinstance(namespace, AWSNamespace)
            or (namespace.account, namespace.region) != (account.account_id, account.region)
            or account.role_arn != registration.resource.native_id
            or not account.role_arn.startswith(f"arn:{namespace.partition}:")
            or account.profile is not None
            or account.external_id is None
            or not account.external_id.get_secret_value()
            or registration.audience != "sts.amazonaws.com"
        ):
            raise ValueError("AWS workload must match the registered role and account.")
        self._registration = registration
        self._config = config
        self._provider = provider
        self._perform = perform

    def execute(self, request: CredentialRequest) -> CredentialLease:
        if request != self._registration:
            raise ProviderUnavailable("Credential target unavailable.")
        try:
            session, lease = self._provider.session(self._config, datetime.now(UTC))
            if lease.expires_at <= datetime.now(UTC):
                raise ValueError
            self._perform(session)
            return lease
        except Exception:
            raise ProviderUnavailable("Credential operation unavailable.") from None


class CredentialBroker:
    def __init__(
        self,
        service: Secrets,
        registrations: Mapping[UUID, RegisteredIntegration],
        provider: AWSSTS,
    ):
        self._service = service
        self._registrations = dict(registrations)
        self._provider = provider

    def execute(self, integration_id: UUID, purpose: str, run: Callable[[Any], Result]) -> Result:
        with self._service._operation(integration_id, None, "credential.lease") as context:
            registration = self._registrations.get(integration_id)
            principal = require_principal()
            if (
                registration is None
                or registration.tenant_id != context.tenant_id
                or registration.product_id != context.product_id
                or str(registration.workload_id) != context.actor_id
                or registration.purpose != purpose
                or principal.identity.identity_type
                not in {IdentityType.SERVICE, IdentityType.INTEGRATION}
                or registration.config.account.role_arn is None
                or registration.config.account.external_id is None
                or registration.config.account.profile is not None
            ):
                raise AccessDenied
            with self._service.repository._connection() as db:
                row = db.execute(
                    """SELECT 1 FROM organization_memberships WHERE tenant_id = ? AND identity_id = ?
                    AND joined_at = ? AND revoked_at IS NULL""",
                    (str(context.tenant_id), context.actor_id, registration.membership_joined),
                ).fetchone()
            if row is None:
                raise AccessDenied
            session, lease = self._provider.session(registration.config, datetime.now(UTC))
            if lease.expires_at <= datetime.now(UTC):
                raise AccessDenied
            self._service._audit(
                context, integration_id, "credential.lease.issued", "success", "ISSUED"
            )
            try:
                return run(session)
            except Exception:
                raise ProviderUnavailable("Credential operation failed.") from None
