"""Compose the OIDC runtime with its separate identity database."""

from pathlib import Path

from jwt.algorithms import has_crypto

from riswan_ir.storage.sqlite import Store
from riswan_platform.identity.application import IdentityApplication
from riswan_platform.identity.configuration import OIDCSettings
from riswan_platform.identity.provider import OIDCProvider
from riswan_platform.identity.service import IdentityService

from .authorization_repository import AuthorizationRepository
from .hosted_product import HostedProduct
from .identity_repository import SQLiteIdentityRepository
from .tenancy import Tenancy
from .tenant_api import TenantAPI


def compose_identity(
    config: Path,
    identity_db: Path,
    product_db: Path,
    *,
    control_db: Path | None = None,
    hosted_db: Path | None = None,
) -> IdentityApplication:
    if not has_crypto:
        raise ValueError("Install the identity extra for OIDC cryptographic verification.")
    if (control_db is None) != (hosted_db is None):
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
    if control_db is not None and hosted_db is not None:
        tenancy = Tenancy(AuthorizationRepository(control_db), identities.is_active_human)
        routes = TenantAPI(
            tenancy, HostedProduct(tenancy, Store(hosted_db, hosted=True)), settings.origin
        )
    return IdentityApplication(
        IdentityService(
            OIDCProvider(settings),
            identities,
            settings,
        ),
        authenticated_routes=routes,
    )
