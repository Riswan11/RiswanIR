"""Conformance assertions for managed cloud keys and tenant-bound registry selection."""

from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from riswan_app.managed_keys import aws_kms, azure_key_vault, gcp_kms
from riswan_platform.secrets import ProviderUnavailable
from riswan_platform.secrets.providers import (
    AWSNamespace,
    AzureNamespace,
    Binding,
    Capability,
    Entry,
    ExternalReference,
    GCPNamespace,
    KeyAlgorithm,
    KeyRequest,
    Registry,
)


@pytest.mark.parametrize("cloud", ["aws", "azure", "gcp"])
def test_managed_key_conformance(cloud):
    client = Mock()
    if cloud == "aws":
        resource = ExternalReference(
            namespace=AWSNamespace(partition="aws", account="123456789012", region="us-east-1"),
            native_id="arn:aws:kms:us-east-1:123456789012:key/synthetic",
        )
        client.encrypt.return_value = {"CiphertextBlob": b"ciphertext"}
        client.decrypt.return_value = {"Plaintext": b"synthetic"}
        provider = aws_kms(client, resource)
    elif cloud == "azure":
        resource = ExternalReference(
            namespace=AzureNamespace(
                directory_id=uuid4(), subscription_id=uuid4(), vault="synthetic"
            ),
            native_id="https://synthetic.vault.azure.net/keys/example/v1",
            native_version="v1",
        )
        client.key_id = resource.native_id
        provider = azure_key_vault(client, resource)
    else:
        resource = ExternalReference(
            namespace=GCPNamespace(project="example", location="global"),
            native_id="projects/example/locations/global/keyRings/example/cryptoKeys/example",
        )
        provider = gcp_kms(client, resource)
    if cloud != "aws":
        client.encrypt.return_value = SimpleNamespace(ciphertext=b"ciphertext")
        client.decrypt.return_value = SimpleNamespace(plaintext=b"synthetic")
    algorithm = KeyAlgorithm.RSA_OAEP_SHA256 if cloud == "azure" else KeyAlgorithm.MANAGED_SYMMETRIC
    request = KeyRequest(resource=resource, algorithm=algorithm, payload=b"synthetic")
    assert "payload" not in request.model_dump()
    assert provider.encrypt(request) == b"ciphertext"
    assert provider.decrypt(request.model_copy(update={"payload": b"ciphertext"})) == b"synthetic"
    rejected = resource.model_copy(update={"native_id": resource.native_id + "-other"})
    with pytest.raises(ProviderUnavailable):
        provider.encrypt(request.model_copy(update={"resource": rejected}))
    assert client.encrypt.call_count == 1
    client.encrypt.side_effect = TimeoutError("sensitive payload")
    with pytest.raises(ProviderUnavailable) as failure:
        provider.encrypt(request)
    assert "sensitive payload" not in str(failure.value)


def test_provider_registry_denies_other_tenants_products_and_instances():
    target = GCPNamespace(project="example", location="global")
    binding = Binding(
        instance_id=uuid4(),
        tenant_id=uuid4(),
        product_id="ir",
        namespace=target,
        capabilities={Capability.KEY_ENCRYPT},
    )
    entry = Entry(binding, object())
    registry = Registry([entry], environment="production")
    key = (binding.instance_id, binding.tenant_id, "ir", target)
    assert registry.capabilities(*key) == {Capability.KEY_ENCRYPT}
    assert registry.resolve(*key, Capability.KEY_ENCRYPT) is entry.provider
    with pytest.raises(ProviderUnavailable):
        registry.resolve(*key, Capability.KEY_DECRYPT)
    with pytest.raises(ValueError):
        Registry([entry, entry], environment="production")
    with pytest.raises(ValueError):
        Registry(
            [Entry(binding.model_copy(update={"development_only": True}), object())],
            environment="production",
        )
    for args in (
        (uuid4(), binding.tenant_id, "ir", target),
        (binding.instance_id, uuid4(), "ir", target),
        (binding.instance_id, binding.tenant_id, "other", target),
        (
            binding.instance_id,
            binding.tenant_id,
            "ir",
            GCPNamespace(project="other", location="global"),
        ),
    ):
        with pytest.raises(ProviderUnavailable):
            registry.resolve(*args, Capability.KEY_ENCRYPT)


@pytest.mark.parametrize("cloud", ["azure", "gcp"])
def test_native_secret_versions_preserve_binary_and_reject_unbound_refs(cloud):
    from base64 import b64encode

    from riswan_app.multicloud_secrets import AzureSecretVault, GoogleSecretVersions
    from riswan_platform.secrets.providers import SecretPayload

    class Missing(Exception):
        pass

    client = Mock()
    value = b"\xff\x00binary"
    if cloud == "azure":
        namespace = AzureNamespace(directory_id=uuid4(), subscription_id=uuid4(), vault="test")
        client.vault_url = "https://test.vault.azure.net"
        client.get_secret.return_value = SimpleNamespace(
            value=b64encode(value), properties=SimpleNamespace(version="v1")
        )
        client.set_secret.return_value = client.get_secret.return_value
        ref = ExternalReference(namespace=namespace, native_id="allowed")
        provider = AzureSecretVault(client, namespace, "allowed", Missing)
    else:
        namespace = GCPNamespace(project="example", location="us-central1")
        name = "projects/example/locations/us-central1/secrets/allowed"
        client.add_secret_version.return_value = SimpleNamespace(name=f"{name}/versions/1")
        client.access_secret_version.return_value = SimpleNamespace(
            payload=SimpleNamespace(data=value)
        )
        ref = ExternalReference(namespace=namespace, native_id=name)
        provider = GoogleSecretVersions(client, namespace, "allowed", Missing)
    version = provider.write(ref, SecretPayload(value=value))
    assert version.native_version in {"v1", "1"}
    assert provider.read(version).value == value
    assert provider.read(version).model_dump() == {}
    with pytest.raises(ProviderUnavailable):
        provider.read(ref)
    with pytest.raises(ProviderUnavailable):
        provider.write(
            ref.model_copy(update={"native_id": ref.native_id + "-other"}),
            SecretPayload(value=value),
        )
    if cloud == "azure":
        with pytest.raises(ProviderUnavailable):
            provider.schedule_delete(version)
        provider.schedule_delete(ref)
        assert not provider.deleted(ref)
        client.get_secret.side_effect = Missing
        assert not provider.deleted(ref)
        client.get_deleted_secret.side_effect = Missing
        assert provider.deleted(ref)
    else:
        provider.schedule_delete(version)
        client.get_secret_version.return_value = SimpleNamespace(
            state=SimpleNamespace(name="DISABLED")
        )
        assert not provider.deleted(version)
        client.get_secret_version.return_value.state.name = "DESTROYED"
        assert provider.deleted(version)


def test_credential_contract_rejects_audience_and_expired_tokens():
    from datetime import UTC, datetime, timedelta

    from riswan_app.federated_credentials import BoundTokenOperation
    from riswan_platform.secrets.providers import CredentialRequest

    now = datetime.now(UTC)
    request = CredentialRequest(
        integration_id=uuid4(),
        workload_id=uuid4(),
        purpose="collect",
        audience="https://vault.azure.net/.default",
        resource=ExternalReference(
            namespace=AzureNamespace(
                directory_id=uuid4(), subscription_id=uuid4(), vault="example"
            ),
            native_id="example",
        ),
    )
    acquire = Mock(return_value=("synthetic", now + timedelta(minutes=30)))
    operation = Mock()
    provider = BoundTokenOperation(request, acquire, operation, clock=lambda: now)
    with pytest.raises(ProviderUnavailable):
        provider.execute(request.model_copy(update={"audience": "https://other.example"}))
    acquire.assert_not_called()
    lease = provider.execute(request)
    assert lease.expires_at > now
    assert "synthetic" not in lease.model_dump_json()
    operation.assert_called_once_with("synthetic")
    acquire.return_value = ("synthetic", now - timedelta(seconds=1))
    with pytest.raises(ProviderUnavailable):
        provider.execute(request)
    operation.assert_called_once()


@pytest.mark.parametrize("cloud", ["azure", "gcp"])
def test_federation_factories_bind_sdk_endpoints_and_audiences(cloud, monkeypatch, tmp_path):
    import sys
    from datetime import UTC, datetime, timedelta

    from riswan_app.federated_credentials import azure_workload, google_workload
    from riswan_platform.secrets.providers import CredentialRequest

    expiry = datetime.now(UTC) + timedelta(minutes=15)
    sdk = Mock()
    create = Mock(return_value=sdk)
    perform = Mock()
    token_file = tmp_path / "workload-token"
    if cloud == "azure":
        namespace = AzureNamespace(directory_id=uuid4(), subscription_id=uuid4(), vault="synthetic")
        audience = "https://vault.azure.net/.default"
        monkeypatch.setitem(
            sys.modules, "azure.identity", SimpleNamespace(WorkloadIdentityCredential=create)
        )
        sdk.get_token.return_value = SimpleNamespace(
            token="example-token", expires_on=expiry.timestamp()
        )
        tenant_app = uuid4()

        def factory(request):
            return azure_workload(request, tenant_app, token_file, perform)
    else:
        namespace = GCPNamespace(project="example", location="global")
        audience = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider"
        monkeypatch.setitem(
            sys.modules,
            "google.auth",
            SimpleNamespace(identity_pool=SimpleNamespace(Credentials=create)),
        )
        monkeypatch.setitem(
            sys.modules, "google.auth.transport.requests", SimpleNamespace(Request=Mock())
        )
        sdk.token = "example-token"
        sdk.expiry = expiry.replace(tzinfo=None)

        def factory(request):
            return google_workload(
                request,
                "123",
                "pool",
                "provider",
                token_file,
                perform,
                service_account="worker@example.iam.gserviceaccount.com",
            )

    request = CredentialRequest(
        integration_id=uuid4(),
        workload_id=uuid4(),
        purpose="collect",
        audience=audience,
        resource=ExternalReference(namespace=namespace, native_id="registered"),
    )
    with pytest.raises(ValueError):
        factory(request.model_copy(update={"audience": "incorrect"}))
    create.assert_not_called()
    provider = factory(request)
    assert provider.execute(request).expires_at == expiry
    perform.assert_called_once_with("example-token")
    if cloud == "azure":
        create.assert_called_once_with(
            tenant_id=str(namespace.directory_id),
            client_id=str(tenant_app),
            token_file_path=str(token_file),
        )
        sdk.get_token.assert_called_once_with(audience)
    else:
        assert create.call_args.kwargs["token_url"] == "https://sts.googleapis.com/v1/token"
        assert create.call_args.kwargs["audience"] == audience
        assert create.call_args.kwargs["service_account_impersonation_url"].endswith(
            "/worker@example.iam.gserviceaccount.com:generateAccessToken"
        )
        with pytest.raises(ValueError):
            google_workload(
                request,
                "123",
                "pool",
                "provider",
                token_file,
                perform,
                service_account="worker@other.iam.gserviceaccount.com",
            )
