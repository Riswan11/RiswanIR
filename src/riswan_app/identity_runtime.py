"""Compose the OIDC runtime with its separate identity database."""

from pathlib import Path

from jwt.algorithms import has_crypto

from riswan_platform.identity.application import IdentityApplication
from riswan_platform.identity.configuration import OIDCSettings
from riswan_platform.identity.provider import OIDCProvider
from riswan_platform.identity.service import IdentityService

from .identity_repository import SQLiteIdentityRepository


def compose_identity(config: Path, identity_db: Path, product_db: Path) -> IdentityApplication:
    if not has_crypto:
        raise ValueError("Install the identity extra for OIDC cryptographic verification.")
    if identity_db.resolve() == product_db.resolve() or (
        identity_db.exists() and product_db.exists() and identity_db.samefile(product_db)
    ):
        raise ValueError("Identity persistence must use a separate database.")
    with config.open("rb") as stream:
        data = stream.read(262_145)
    if len(data) > 262_144:
        raise ValueError("OIDC configuration is too large.")
    settings = OIDCSettings.model_validate_json(data)
    return IdentityApplication(
        IdentityService(
            OIDCProvider(settings),
            SQLiteIdentityRepository(identity_db),
            settings,
        )
    )
