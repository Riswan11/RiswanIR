"""Construct tenant-bound storage from a trusted operator configuration file."""

from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, TypeAdapter

from riswan_platform.secrets import Model, SecretProvider
from riswan_platform.secrets.providers import (
    AWSNamespace,
    AzureNamespace,
    Binding,
    Capability,
    Entry,
    GCPNamespace,
    Registry,
)

from .native_secret_slots import AzureSlots, GoogleSlots
from .secret_providers import AWSSecretsProvider
from .secret_routing import SecretDestination, SecretRouting


class AWSStorage(Model):
    cloud: Literal["aws"]
    namespace: AWSNamespace
    kms_key: str


class AzureStorage(Model):
    cloud: Literal["azure"]
    namespace: AzureNamespace
    client_id: UUID
    federated_token_file: Path


class GoogleStorage(Model):
    cloud: Literal["gcp"]
    namespace: GCPNamespace


Storage = Annotated[AWSStorage | AzureStorage | GoogleStorage, Field(discriminator="cloud")]


class ConfiguredStorage(Model):
    tenant_id: UUID
    instance_id: UUID
    product_id: Literal["ir"] = "ir"
    storage: Storage


def _provider(config: Storage) -> SecretProvider:
    if isinstance(config, AWSStorage):
        import boto3
        from botocore.config import Config

        namespace = config.namespace
        if not config.kms_key.startswith(
            f"arn:{namespace.partition}:kms:{namespace.region}:{namespace.account}:key/"
        ):
            raise ValueError("KMS key must match the configured AWS provider namespace.")
        options = Config(
            retries={"total_max_attempts": 1},
            connect_timeout=5,
            read_timeout=10,
            ignore_configured_endpoint_urls=True,
        )
        session = boto3.Session(region_name=namespace.region)
        if (
            session.get_partition_for_region(namespace.region) != namespace.partition
            or session.client("sts", config=options).get_caller_identity()["Account"]
            != namespace.account
        ):
            raise ValueError("AWS storage credentials must match the registered account.")
        return AWSSecretsProvider(session.client("secretsmanager", config=options), config.kms_key)
    if isinstance(config, AzureStorage):
        from azure.core.exceptions import ResourceNotFoundError
        from azure.identity import WorkloadIdentityCredential
        from azure.keyvault.secrets import SecretClient

        namespace_azure = config.namespace
        credential = WorkloadIdentityCredential(
            tenant_id=str(namespace_azure.directory_id),
            client_id=str(config.client_id),
            token_file_path=str(config.federated_token_file),
        )
        return AzureSlots(
            SecretClient(
                vault_url=f"https://{namespace_azure.vault}.vault.azure.net",
                credential=credential,
                retry_total=0,
                connection_timeout=5,
                read_timeout=10,
            ),
            ResourceNotFoundError,
        )
    import google.auth
    from google.api_core.exceptions import AlreadyExists, NotFound
    from google.auth.compute_engine import Credentials as AttachedCredentials
    from google.auth.external_account import Credentials as FederatedCredentials
    from google.cloud.secretmanager import SecretManagerServiceClient

    if config.namespace.location != "global":
        raise ValueError("Hosted Google secret storage currently requires the global endpoint.")
    credentials, _project = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    if not isinstance(credentials, (FederatedCredentials, AttachedCredentials)):
        raise ValueError("Google storage requires attached identity or workload federation.")
    return GoogleSlots(
        SecretManagerServiceClient(credentials=credentials),
        config.namespace.project,
        NotFound,
        AlreadyExists,
    )


def load_secret_routing(path: Path) -> SecretRouting:
    with path.open("rb") as stream:
        data = stream.read(262145)
    if len(data) > 262144:
        raise ValueError("Provider configuration is too large.")
    entries = TypeAdapter(list[ConfiguredStorage]).validate_json(data)
    capabilities = frozenset(
        {Capability.SECRET_READ, Capability.SECRET_WRITE, Capability.SECRET_DELETE}
    )
    routes: dict[tuple[UUID, str], SecretDestination] = {}
    instances: list[Entry[SecretProvider]] = []
    for entry in entries:
        scope = entry.tenant_id, entry.product_id
        if scope in routes:
            raise ValueError(
                "Only one active secret destination is supported per tenant and product."
            )
        namespace = entry.storage.namespace
        binding = Binding(
            instance_id=entry.instance_id,
            tenant_id=entry.tenant_id,
            product_id=entry.product_id,
            namespace=namespace,
            capabilities=capabilities,
        )
        routes[scope] = SecretDestination(entry.instance_id, namespace)
        instances.append(Entry(binding, _provider(entry.storage)))
    return SecretRouting(Registry(instances, environment="production"), routes)
