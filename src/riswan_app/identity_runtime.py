"""Compose the OIDC runtime with its separate identity database."""

import os
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
from .hosted_collection import (
    CollectionAPI,
    PostgresCollectionAPI,
    PreviewCollection,
    load_collections,
)
from .hosted_product import HostedPostgresCases, HostedProduct
from .identity_repository import SQLiteIdentityRepository
from .postgres_cases import PostgresCases
from .postgres_collections import PostgresCollections
from .postgres_control import PostgresAuthorizationRepository
from .postgres_identity import PostgresIdentityRepository
from .secret_api import SecretAPI
from .secret_providers import AWSSecretsProvider
from .secret_routing import SecretRouting
from .secrets import Secrets
from .tenancy import Tenancy
from .tenant_api import TenantAPI


def compose_identity(
    config: Path,
    identity_db: Path | None,
    product_db: Path,
    *,
    control_db: Path | None = None,
    postgres_case_pool: Any = None,
    enable_postgres_preview: bool = False,
    preview_secret_routing: SecretRouting | None = None,
    preview_collections: tuple[PreviewCollection, ...] = (),
    postgres_identity_pool: Any = None,
    postgres_control_pool: Any = None,
    hosted_db: Path | None = None,
    secrets_region: str | None = None,
    secrets_providers: Path | None = None,
    collection_config: Path | None = None,
    secrets_kms_key: str | None = None,
) -> IdentityApplication:
    if postgres_case_pool is not None and (
        enable_postgres_preview is not True
        or os.getenv("RISWAN_IR_ENV") != "development"
        or os.getenv("SENTINELFORGE_ENV", "development") != "development"
        or any(
            item is not None
            for item in (secrets_region, secrets_kms_key, secrets_providers, collection_config)
        )
    ):
        raise ValueError(
            "PostgreSQL preview requires explicit development opt-in without providers."
        )
    if preview_collections and (postgres_control_pool is None or postgres_case_pool is None):
        raise ValueError("Preview collection requires PostgreSQL product and control storage.")
    if preview_secret_routing is not None and postgres_control_pool is None:
        raise ValueError("Preview secret routing requires PostgreSQL control storage.")
    if postgres_control_pool is not None and (
        postgres_identity_pool is None
        or control_db is not None
        or secrets_region is not None
        or secrets_providers is not None
        or collection_config is not None
    ):
        raise ValueError(
            "PostgreSQL control requires PostgreSQL identity and excludes legacy controls."
        )
    if postgres_identity_pool is not None:
        if identity_db is not None or postgres_case_pool is None:
            raise ValueError(
                "PostgreSQL identity requires the hosted preview and no SQLite identity database."
            )
    elif identity_db is None:
        raise ValueError("Configure identity storage.")
    if (secrets_region is None) != (secrets_kms_key is None) or (
        secrets_region and control_db is None
    ):
        raise ValueError("Configure a KMS key and region for the hosted secret provider.")
    if (secrets_providers is not None or collection_config is not None) and control_db is None:
        raise ValueError("Hosted providers require a control database.")
    if preview_secret_routing is not None:
        preview_secret_routing.require_development_only()
    if not has_crypto:
        raise ValueError("Install the identity extra for OIDC cryptographic verification.")
    if postgres_case_pool is not None:
        if (
            (control_db is None and postgres_control_pool is None)
            or hosted_db is not None
            or collection_config is not None
        ):
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
    identities = (
        PostgresIdentityRepository(postgres_identity_pool)
        if identity_db is None
        else SQLiteIdentityRepository(identity_db)
    )
    routes = None
    if control_db is not None or postgres_control_pool is not None:
        authorization = (
            AuthorizationRepository(control_db)
            if control_db is not None
            else PostgresAuthorizationRepository(postgres_control_pool)
        )
        tenancy = Tenancy(
            authorization,
            identities.is_active_human,
            identities.is_active_workload,
            identities.workload_guard
            if isinstance(identities, PostgresIdentityRepository)
            else None,
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
        cases = None
        if postgres_case_pool is not None:
            cases = PostgresCases(postgres_case_pool)
            hosted = HostedPostgresCases(tenancy, cases)
        else:
            if hosted_db is None:
                raise ValueError("Hosted product storage unavailable.")
            local_store = Store(hosted_db, hosted=True)
            hosted = HostedProduct(tenancy, local_store)
        secret_routes = None
        collections: CollectionAPI | None = None
        if preview_secret_routing is not None:
            secret_routes = SecretAPI(
                Secrets(tenancy, None, environment="development", routing=preview_secret_routing)
            )
        if preview_collections and cases is not None:
            collections = PostgresCollectionAPI(
                Secrets(tenancy, None, environment="development", routing=preview_secret_routing),
                PostgresCollections(cases, postgres_case_pool),
                preview_collections,
            )
        if control_db is not None:
            service = Secrets(tenancy, fallback, environment="production", routing=routing)
            secret_routes = SecretAPI(service) if fallback or routing else None
            if collection_config and local_store is not None:
                collections = CollectionAPI(
                    service, load_collections(collection_config, service, local_store)
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
