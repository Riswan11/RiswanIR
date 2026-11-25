"""Compose the OIDC runtime with its separate identity database."""

from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from jwt.algorithms import has_crypto

from riswan_ir.storage.sqlite import Store
from riswan_platform.identity.application import IdentityApplication
from riswan_platform.identity.configuration import OIDCSettings
from riswan_platform.identity.provider import OIDCProvider
from riswan_platform.identity.service import IdentityService

from .authorization_repository import AuthorizationRepository
from .cloud_storage_config import load_secret_routing
from .hosted_collection import CollectionAPI, load_collections
from .hosted_product import HostedPostgresCases, HostedProduct
from .identity_repository import SQLiteIdentityRepository
from .postgres_cases import PostgresCases
from .secret_api import SecretAPI
from .secret_providers import AWSSecretsProvider
from .secrets import Secrets
from .tenancy import Tenancy
from .tenant_api import TenantAPI


def compose_identity(
    config: Path,
    identity_db: Path,
    product_db: Path,
    *,
    control_db: Path | None = None,
    postgres_case_pool: Any = None,
    hosted_db: Path | None = None,
    secrets_region: str | None = None,
    secrets_providers: Path | None = None,
    collection_config: Path | None = None,
    secrets_kms_key: str | None = None,
) -> IdentityApplication:
    if (secrets_region is None) != (secrets_kms_key is None) or (
        secrets_region and control_db is None
    ):
        raise ValueError("Configure a KMS key and region for the hosted secret provider.")
    if (secrets_providers is not None or collection_config is not None) and control_db is None:
        raise ValueError("Hosted providers require a control database.")
    if not has_crypto:
        raise ValueError("Install the identity extra for OIDC cryptographic verification.")
    if postgres_case_pool is not None:
        if control_db is None or hosted_db is not None or collection_config is not None:
            raise ValueError(
                "PostgreSQL preview requires control storage and no SQLite product or collector."
            )
    elif (control_db is None) != (hosted_db is None):
        raise ValueError("Configure both control and hosted product databases.")
    paths = [path for path in (identity_db, product_db, control_db, hosted_db) if path is not None]
    for index, path in enumerate(paths):
        if any(
            path.resolve() == prior.resolve()
            or (path.exists() and prior.exists() and path.samefile(prior))
            for prior in paths[:index]
        ):
            raise ValueError(
                "Identity, control, hosted and workstation databases must be separate."
            )
    with config.open("rb") as stream:
        data = stream.read(262_145)
    if len(data) > 262_144:
        raise ValueError("OIDC configuration is too large.")
    settings = OIDCSettings.model_validate_json(data)
    identities = SQLiteIdentityRepository(identity_db)
    routes = None
    if control_db is not None:
        tenancy = Tenancy(
            AuthorizationRepository(control_db),
            identities.is_active_human,
            identities.is_active_workload,
        )
        fallback = None
        if secrets_region and secrets_kms_key:
            client = boto3.client(
                "secretsmanager",
                region_name=secrets_region,
                verify=True,
                config=Config(
                    retries={"total_max_attempts": 1},
                    connect_timeout=5,
                    read_timeout=10,
                    ignore_configured_endpoint_urls=True,
                ),
            )
            fallback = AWSSecretsProvider(client, secrets_kms_key)
        routing = load_secret_routing(secrets_providers) if secrets_providers else None
        hosted: HostedProduct | HostedPostgresCases
        local_store = None
        if postgres_case_pool is not None:
            hosted = HostedPostgresCases(tenancy, PostgresCases(postgres_case_pool))
        else:
            if hosted_db is None:
                raise ValueError("Hosted product storage unavailable.")
            local_store = Store(hosted_db, hosted=True)
            hosted = HostedProduct(tenancy, local_store)
        service = Secrets(tenancy, fallback, environment="production", routing=routing)
        secret_routes = SecretAPI(service) if fallback or routing else None
        collections = (
            CollectionAPI(service, load_collections(collection_config, service, local_store))
            if collection_config and local_store is not None
            else None
        )
        routes = TenantAPI(tenancy, hosted, settings.origin, secret_routes, collections)
    return IdentityApplication(
        IdentityService(
            OIDCProvider(settings),
            identities,
            settings,
        ),
        authenticated_routes=routes,
    )
