"""Credential lifecycle and sensitive boundary regressions."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from riswan_app.authorization_repository import AuthorizationRepository
from riswan_app.secret_providers import AWSSecretsProvider, EncryptedProvider, MemoryProvider
from riswan_app.secrets import Secrets
from riswan_app.tenancy import Tenancy
from riswan_platform.authorization.enforcement import AccessDenied
from riswan_platform.core.context import bind_context
from riswan_platform.identity.models import (
    IdentityStatus,
    IdentityType,
    PlatformIdentity,
    VerifiedPrincipal,
)
from riswan_platform.identity.principal import bind_principal
from riswan_platform.secrets import (
    ProviderUnavailable,
    Registration,
    RotationRequest,
    SecretAccessPolicy,
    SecretError,
    SecretMaterial,
    SecretReference,
)
from riswan_platform.tenancy import OrganizationInput

VALUE = "synthetic-test-value"


@pytest.fixture
def secrets(tmp_path):
    now = [datetime.now(UTC)]

    def actor(kind):
        identity = PlatformIdentity(
            uuid4(),
            kind,
            "test",
            kind.value,
            kind.value,
            None,
            IdentityStatus.ACTIVE,
            now[0],
            now[0],
        )
        return VerifiedPrincipal(identity, "bearer", True)

    owner, worker = actor(IdentityType.HUMAN), actor(IdentityType.INTEGRATION)
    storage = AuthorizationRepository(tmp_path / "control.sqlite3")
    tenancy = Tenancy(storage, lambda _: True, lambda key: key == worker.identity.identity_id)
    org = tenancy.create(owner, OrganizationInput(name="Test"), "request")
    tenancy.register_workload(owner, org.id, worker.identity.identity_id, "request")
    provider = MemoryProvider()

    def validator(_, material):
        if material.value.get_secret_value() == "bad":
            raise RuntimeError(VALUE)
        return True

    service = Secrets(
        tenancy, provider, environment="test", validate=validator, clock=lambda: now[0]
    )
    return service, owner, worker, org, now


def contexts(service, actor, org, product="ir"):
    return bind_principal(actor), bind_context(
        service.tenancy.context_for(actor, org.tenant_id, product, "test")
    )


def test_rotation_failure_idempotency_and_revoked_membership(secrets, caplog):
    service, owner, worker, org, now = secrets
    owner_principal, owner_context = contexts(service, owner, org)
    item = Registration(id=uuid4(), name="Connector", kind="api_key", value=VALUE)
    ref = SecretReference(id=item.id)
    with owner_principal, owner_context:
        first = service.register(item)
        assert first.current_version == item.id
        assert VALUE not in repr(item) and VALUE not in item.model_dump_json()
        grant = SecretAccessPolicy(
            workload_id=worker.identity.identity_id,
            purpose="collect",
            expires_at=now[0] + timedelta(hours=1),
        )
        service.set_policy(ref.id, grant)
        with pytest.raises(AccessDenied):
            service.use(ref, "collect", lambda material: material)
        with pytest.raises(SecretError, match="Credential validation failed") as failed:
            service.rotate(ref.id, RotationRequest(operation_id=uuid4(), value="bad"))
        assert VALUE not in str(failed.value)
        assert service.metadata(ref.id).current_version == first.current_version
    principal, context = contexts(service, worker, org)
    with principal, context:
        assert service.use(
            ref, "collect", lambda material: material.value.get_secret_value() == VALUE
        )
        with pytest.raises(AccessDenied):
            service.use(ref, "different", lambda material: material)
    principal, context = contexts(service, worker, org, "other")
    with principal, context, pytest.raises(AccessDenied):
        service.use(ref, "collect", lambda material: material)
    replacement = RotationRequest(operation_id=uuid4(), value="new-test-value")

    def rotate(_):
        principal, context = contexts(service, owner, org)
        with principal, context:
            return service.rotate(ref.id, replacement).current_version

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(rotate, range(2))) == [replacement.operation_id] * 2
    principal, context = contexts(service, owner, org)
    with principal, context:
        versions = service.versions(ref.id)
        assert [item.state for item in versions] == ["active", "candidate", "retired"]
        service.tenancy.revoke_member(owner, org.id, worker.identity.identity_id, "revoke")
        service.tenancy.register_workload(owner, org.id, worker.identity.identity_id, "re-enroll")
    principal, context = contexts(service, worker, org)
    with principal, context, pytest.raises(AccessDenied):
        service.use(ref, "collect", lambda material: material)
    assert VALUE not in caplog.text
    assert VALUE.encode() not in service.repository.path.read_bytes()


def test_expiration_and_mandatory_audit(secrets, monkeypatch):
    service, owner, worker, org, now = secrets
    principal, context = contexts(service, owner, org)
    request = Registration(
        id=uuid4(),
        name="Expiring",
        kind="oauth_refresh",
        value=VALUE,
        expires_at=now[0] + timedelta(seconds=1),
    )
    with principal, context:
        service.register(request)
        service.set_policy(
            request.id,
            SecretAccessPolicy(
                workload_id=worker.identity.identity_id,
                purpose="use",
                expires_at=now[0] + timedelta(hours=1),
            ),
        )
    now[0] += timedelta(seconds=2)
    principal, context = contexts(service, worker, org)
    with principal, context, pytest.raises(AccessDenied):
        service.use(SecretReference(id=request.id), "use", lambda material: material)
    principal, context = contexts(service, owner, org)
    with principal, context:
        assert any(item.action == "secret.expired" for item in service.audit(request.id))
        called = []

        def unavailable(*args):
            raise RuntimeError("audit offline")

        monkeypatch.setattr(service, "_audit", unavailable)
        monkeypatch.setattr(service.provider, "put", lambda *args: called.append(args))
        with pytest.raises(RuntimeError, match="audit offline"):
            service.register(request.model_copy(update={"id": uuid4(), "expires_at": None}))
        assert called == []


def test_development_provider_guard_and_authenticated_encryption(tmp_path, secrets):
    service, *_ = secrets
    with pytest.raises(ValueError, match="not permitted"):
        Secrets(service.tenancy, MemoryProvider(), environment="production")
    pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    path = tmp_path / "encrypted.sqlite3"
    provider = EncryptedProvider(path, b"x" * 32)
    material = SecretMaterial(value=VALUE)
    provider.put("a", material)
    provider.put("a", material)
    assert provider.get("a").value == material.value
    with pytest.raises(ProviderUnavailable):
        provider.put("a", SecretMaterial(value="other-value"))
    assert VALUE.encode() not in path.read_bytes()
    with pytest.raises(ProviderUnavailable):
        EncryptedProvider(path, b"y" * 32).get("a")
    provider.schedule_delete("a")
    assert provider.deleted("a")


def test_aws_provider_masks_sdk_errors():
    from unittest.mock import Mock

    from botocore.exceptions import ClientError

    client = Mock()
    provider = AWSSecretsProvider(client, "managed-test-key")
    key = "riswan/synthetic/" + uuid4().hex
    material = SecretMaterial(value=VALUE)
    provider.put(key, material)
    assert client.create_secret.call_args.kwargs["KmsKeyId"] == "managed-test-key"
    client.get_secret_value.return_value = {"SecretBinary": VALUE.encode()}
    assert provider.get(key).value == material.value
    client.describe_secret.return_value = {}
    provider.schedule_delete(key)
    client.delete_secret.assert_called_once_with(SecretId=key, RecoveryWindowInDays=7)
    assert not provider.deleted(key)
    client.describe_secret.side_effect = ClientError(
        {"Error": {"Code": "ResourceNotFoundException"}}, "DescribeSecret"
    )
    assert provider.deleted(key)
    client.get_secret_value.side_effect = TimeoutError(VALUE)
    with pytest.raises(ProviderUnavailable) as error:
        provider.get(key)
    assert VALUE not in str(error.value)


def test_broker_issues_short_scoped_sessions_only_to_registered_workload(secrets, monkeypatch):
    from unittest.mock import Mock

    from riswan_app import credential_broker as module
    from riswan_ir.models.connector import ConnectorConfig

    service, owner, worker, org, now = secrets
    with service.repository.atomic() as db:
        joined = db.execute(
            "SELECT joined_at FROM organization_memberships WHERE tenant_id = ? AND identity_id = ?",
            (str(org.tenant_id), str(worker.identity.identity_id)),
        ).fetchone()[0]
    config = ConnectorConfig.model_validate(
        {
            "kind": "cloudtrail",
            "principal": "arn:aws:iam::123456789012:user/synthetic",
            "account": {
                "account_id": "123456789012",
                "region": "us-east-1",
                "role_arn": "arn:aws:iam::123456789012:role/Telemetry",
                "external_id": "synthetic-integration-binding",
            },
        }
    )
    sdk = Mock()
    sts = Mock()
    issued = {
        "AccessKeyId": "synthetic-access",
        "SecretAccessKey": VALUE,
        "SessionToken": "synthetic-session",
        "Expiration": now[0] + timedelta(minutes=15),
    }
    sts.assume_role.return_value = {"Credentials": issued}
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    sdk.client.return_value = sts
    sdk.get_partition_for_region.return_value = "aws"
    monkeypatch.setattr(module.boto3, "Session", lambda **_: sdk)
    registered = module.RegisteredIntegration(
        org.tenant_id, "ir", worker.identity.identity_id, joined, "collect", config
    )
    identifier = uuid4()
    broker = module.CredentialBroker(service, {identifier: registered}, module.AWSSTS())
    principal, context = contexts(service, owner, org)
    with principal, context, pytest.raises(AccessDenied):
        broker.execute(identifier, "collect", lambda _: True)
    principal, context = contexts(service, worker, org)
    with principal, context:
        with pytest.raises(AccessDenied):
            broker.execute(uuid4(), "collect", lambda _: True)
        with pytest.raises(AccessDenied):
            broker.execute(identifier, "unknown", lambda _: True)
        sts.assume_role.assert_not_called()
        assert broker.execute(identifier, "collect", lambda session: session is sdk)
        assert sts.assume_role.call_args.kwargs["DurationSeconds"] == 900
        assert '"cloudtrail:LookupEvents"' in sts.assume_role.call_args.kwargs["Policy"]
        assert sts.assume_role.call_args.kwargs["ExternalId"] == "synthetic-integration-binding"
        issued["Expiration"] = now[0] - timedelta(seconds=1)
        with pytest.raises(ProviderUnavailable):
            broker.execute(identifier, "collect", lambda _: True)


def test_metadata_expiration_rollback_and_redaction(secrets):
    from riswan_platform.secrets import redact_fields

    service, owner, _, org, now = secrets
    request = Registration(
        id=uuid4(),
        kind="webhook",
        name="Webhook",
        value=VALUE,
        expires_at=now[0] + timedelta(seconds=5),
    )
    principal, context = contexts(service, owner, org)
    with principal, context:
        service.register(request)
        service.rotate(request.id, RotationRequest(operation_id=uuid4(), value="different"))
        assert service.rollback(request.id, request.id).current_version == request.id
        with pytest.raises(AccessDenied):
            service.rollback(request.id, request.id)
        now[0] += timedelta(seconds=6)
        assert service.metadata(request.id).status == "expired"
    assert redact_fields(
        {"secret": VALUE, "result": "ok", "item": SecretMaterial(value=VALUE)},
        allowed=frozenset({"result", "item"}),
    ) == {"result": "ok"}


def test_registered_broker_authorizes_before_resolving_provider(secrets):
    from unittest.mock import Mock

    from riswan_app.registered_credentials import CredentialRegistration, RegisteredCredentialBroker
    from riswan_platform.secrets import CredentialLease
    from riswan_platform.secrets.providers import (
        Binding,
        Capability,
        CredentialRequest,
        Entry,
        ExternalReference,
        GCPNamespace,
        Registry,
    )

    service, owner, worker, org, now = secrets
    with service.repository.atomic() as db:
        joined = db.execute(
            "SELECT joined_at FROM organization_memberships WHERE tenant_id = ? AND identity_id = ?",
            (str(org.tenant_id), str(worker.identity.identity_id)),
        ).fetchone()[0]
    namespace = GCPNamespace(project="synthetic", location="global")
    request = CredentialRequest(
        integration_id=uuid4(),
        workload_id=worker.identity.identity_id,
        resource=ExternalReference(namespace=namespace, native_id="integration"),
        audience="synthetic-audience",
        purpose="collect",
    )
    binding = Binding(
        instance_id=uuid4(),
        tenant_id=org.tenant_id,
        product_id="ir",
        namespace=namespace,
        capabilities={Capability.CREDENTIAL_ISSUE},
    )
    provider = Mock()
    provider.execute.return_value = CredentialLease(
        id=uuid4(), expires_at=now[0] + timedelta(minutes=5)
    )
    registry = Registry([Entry(binding, provider)], environment="test")
    registration = CredentialRegistration(binding.instance_id, org.tenant_id, "ir", joined, request)
    broker = RegisteredCredentialBroker(service, registry, {request.integration_id: registration})
    principal, context = contexts(service, owner, org)
    with principal, context, pytest.raises(AccessDenied):
        broker.execute(request.integration_id, "collect")
    provider.execute.assert_not_called()
    principal, context = contexts(service, worker, org)
    with principal, context:
        with pytest.raises(AccessDenied):
            broker.execute(request.integration_id, "different")
        assert broker.execute(request.integration_id, "collect") == provider.execute.return_value
        provider.execute.assert_called_once_with(request)
        expired = CredentialLease(id=uuid4(), expires_at=now[0])
        provider.execute.return_value = expired
        with pytest.raises(AccessDenied):
            broker.execute(request.integration_id, "collect")
    service.tenancy.revoke_member(owner, org.id, worker.identity.identity_id, "revoke")
    service.tenancy.register_workload(owner, org.id, worker.identity.identity_id, "return")
    principal, context = contexts(service, worker, org)
    with principal, context, pytest.raises(AccessDenied):
        broker.execute(request.integration_id, "collect")


def test_legacy_aws_metadata_binds_without_rewriting_provider_paths(secrets):
    from riswan_app.secret_routing import SecretDestination, SecretRouting
    from riswan_platform.secrets.providers import AWSNamespace, Binding, Capability, Entry, Registry

    service, owner, _, org, _ = secrets
    service.provider.name = "aws-secrets-manager"
    request = Registration(id=uuid4(), name="Legacy", kind="api_key", value=VALUE)
    principal, context = contexts(service, owner, org)
    with principal, context:
        legacy = service.register(request)
    assert legacy.provider_instance_id is None
    with service.repository.atomic() as db:
        db.execute(
            "UPDATE secret_metadata SET metadata = json_remove(metadata, '$.provider_instance_id') WHERE id = ?",
            (str(legacy.id),),
        )
    namespace = AWSNamespace(partition="aws", account="123456789012", region="us-east-1")
    binding = Binding(
        instance_id=uuid4(),
        tenant_id=org.tenant_id,
        product_id="ir",
        namespace=namespace,
        capabilities={Capability.SECRET_READ, Capability.SECRET_WRITE, Capability.SECRET_DELETE},
    )
    destination = SecretDestination(binding.instance_id, namespace)
    routing = SecretRouting(
        Registry([Entry(binding, service.provider)], environment="test"),
        {(org.tenant_id, "ir"): destination},
    )
    configured = Secrets(service.tenancy, None, environment="test", routing=routing)
    principal, context = contexts(configured, owner, org)
    with principal, context:
        migrated = configured.bind_existing(legacy.id)
        assert migrated.provider_instance_id == binding.instance_id
        assert migrated.current_version == legacy.current_version
        assert (
            configured.rotate(
                legacy.id, RotationRequest(operation_id=uuid4(), value="second")
            ).provider_instance_id
            == binding.instance_id
        )


def test_native_rotation_retry_reconciles_ambiguous_write_without_replay(secrets):
    from types import SimpleNamespace
    from unittest.mock import Mock

    from riswan_app.native_secret_slots import AzureSlots
    from riswan_app.secret_routing import SecretDestination, SecretRouting
    from riswan_platform.secrets.providers import (
        AzureNamespace,
        Binding,
        Capability,
        Entry,
        Registry,
    )

    service, owner, _, org, _ = secrets

    class Missing(Exception):
        pass

    client = Mock()
    records = {}

    def get(name, version=None):
        if name not in records:
            raise Missing
        if version is not None:
            assert records[name].properties.version == version
        return records[name]

    def write(name, value):
        records[name] = SimpleNamespace(value=value, properties=SimpleNamespace(version="native-1"))
        raise TimeoutError(VALUE)

    client.get_secret.side_effect = get
    client.set_secret.side_effect = write
    provider = AzureSlots(client, Missing)
    namespace = AzureNamespace(directory_id=uuid4(), subscription_id=uuid4(), vault="synthetic")
    binding = Binding(
        instance_id=uuid4(),
        tenant_id=org.tenant_id,
        product_id="ir",
        namespace=namespace,
        capabilities={Capability.SECRET_READ, Capability.SECRET_WRITE, Capability.SECRET_DELETE},
    )
    routing = SecretRouting(
        Registry([Entry(binding, provider)], environment="test"),
        {(org.tenant_id, "ir"): SecretDestination(binding.instance_id, namespace)},
    )
    configured = Secrets(service.tenancy, None, environment="test", routing=routing)
    principal, context = contexts(configured, owner, org)
    request = Registration(id=uuid4(), name="Native", kind="api_key", value=VALUE)
    with principal, context:
        with pytest.raises(ProviderUnavailable):
            configured.register(request)
        assert configured.metadata(request.id).status == "created"
        active = configured.register(request)
        assert active.provider_instance_id == binding.instance_id
        assert configured.versions(request.id)[0].native_version == "native-1"
    client.set_secret.assert_called_once()
    assert VALUE.encode() not in service.repository.path.read_bytes()


def test_secret_lifecycle_rejects_invalid_transitions(secrets, monkeypatch, caplog):
    from riswan_platform.secrets import Update

    service, owner, worker, org, now = secrets
    request = Registration(id=uuid4(), name="Fixture", kind="api_key", value=VALUE)
    principal, context = contexts(service, owner, org)
    assert service.provider is not None
    provider = service.provider
    expiry = now[0] + timedelta(hours=1)
    with principal, context:
        active = service.register(request)
        assert service.register(request) == active
        with pytest.raises(AccessDenied):
            service.delete(request.id, confirm=True)
        with pytest.raises(AccessDenied):
            service.rollback(request.id, request.id)
        with pytest.raises(AccessDenied):
            service.rollback(request.id, uuid4())
        with pytest.raises(SecretError):
            service.update(request.id, Update(name=None))
        changed = service.update(
            request.id, Update.model_validate({"rotation": {"interval_days": 2}})
        )
        assert changed.next_rotation_at == changed.last_rotated_at + timedelta(days=2)
        policy = SecretAccessPolicy(
            workload_id=worker.identity.identity_id, purpose="read", expires_at=expiry
        )
        service.set_policy(request.id, policy)
        with pytest.raises(AccessDenied):
            service.set_policy(
                request.id, policy.model_copy(update={"workload_id": owner.identity.identity_id})
            )

    def provider_timeout(*args):
        raise TimeoutError(VALUE)

    with monkeypatch.context() as patches:
        patches.setattr(provider, "get", provider_timeout)
        principal, context = contexts(service, worker, org)
        with principal, context, pytest.raises(ProviderUnavailable) as failure:
            service.use(SecretReference(id=request.id), "read", lambda _: None)
        assert VALUE not in str(failure.value)

    principal, context = contexts(service, owner, org)
    with principal, context:
        service.set_policy(request.id, policy, revoke=True)
        revoked = service.revoke(request.id)
        assert service.revoke(request.id) == revoked
        with pytest.raises(AccessDenied):
            service.rotate(request.id, RotationRequest(operation_id=uuid4(), value=VALUE))
        with pytest.raises(AccessDenied):
            service.update(request.id, Update(name="Changed"))
        service.delete(request.id)
        with monkeypatch.context() as patches:
            patches.setattr(provider, "deleted", lambda _: False)
            assert service.delete(request.id, confirm=True).status == "pending_deletion"
        deleted = service.delete(request.id, confirm=True)
        assert service.delete(request.id) == deleted
    assert VALUE not in caplog.text
