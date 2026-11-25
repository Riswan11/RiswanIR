"""Trusted, bounded configuration for the OIDC identity runtime."""

from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Label = Annotated[str, StringConstraints(min_length=1, max_length=256)]


def https_url(value: str) -> str:
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or any(ord(char) <= 32 for char in value)
    ):
        raise ValueError("OIDC endpoints require unambiguous HTTPS URLs.")
    return value


class ServiceRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    client_id: Label
    identity_type: Literal["service", "integration"] = "service"
    required_scopes: Annotated[frozenset[Label], Field(min_length=1, max_length=20)]


class OIDCSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    provider: Literal["oidc", "cognito"] = "oidc"
    issuer: Label
    jwks_url: Label
    authorization_url: Label
    token_url: Label
    redirect_uri: Label
    client_id: Label
    access_audience: Label | None = None
    logout_url: Label | None = None
    post_logout_redirect_uri: Label | None = None
    invited_subjects: Annotated[frozenset[Label], Field(max_length=1000)]
    services: Annotated[dict[Label, ServiceRegistration], Field(max_length=100)] = Field(
        default_factory=dict
    )
    privileged_subjects: Annotated[frozenset[Label], Field(max_length=1000)] = frozenset()
    require_human_mfa: bool = True
    trusted_mfa_acr: Annotated[frozenset[Label], Field(max_length=10)] = frozenset()
    clock_skew_seconds: Annotated[int, Field(ge=0, le=60, strict=True)] = 30
    access_lifetime_seconds: Annotated[int, Field(ge=300, le=900, strict=True)] = 900
    session_idle_seconds: Annotated[int, Field(ge=60, le=1800, strict=True)] = 1800
    session_absolute_seconds: Annotated[int, Field(ge=60, le=28800, strict=True)] = 28800

    @model_validator(mode="after")
    def validate_configuration(self) -> Self:
        for value in (
            self.issuer,
            self.jwks_url,
            self.authorization_url,
            self.token_url,
            self.redirect_uri,
            self.logout_url,
            self.post_logout_redirect_uri,
        ):
            if value is not None:
                https_url(value)
        if urlsplit(self.redirect_uri).path != "/v1/auth/callback":
            raise ValueError("OIDC callback URL must target /v1/auth/callback.")
        if urlsplit(self.issuer).netloc != urlsplit(self.jwks_url).netloc:
            raise ValueError("JWKS must use the configured issuer origin.")
        if urlsplit(self.authorization_url).netloc != urlsplit(self.token_url).netloc:
            raise ValueError("Authorization and token endpoints must use the same origin.")
        if self.provider == "oidc" and not self.access_audience:
            raise ValueError("Generic OIDC requires an explicit API token audience.")
        if (
            self.provider == "cognito"
            and self.jwks_url != self.issuer.rstrip("/") + "/.well-known/jwks.json"
        ):
            raise ValueError("Cognito JWKS must use the selected user pool.")
        if bool(self.logout_url) != bool(self.post_logout_redirect_uri):
            raise ValueError("Provider logout requires both configured URLs.")
        if (
            self.post_logout_redirect_uri
            and urlsplit(self.post_logout_redirect_uri).netloc != urlsplit(self.redirect_uri).netloc
        ):
            raise ValueError("Post-logout redirect must use the application origin.")
        if (
            self.invited_subjects & self.services.keys()
            or not self.privileged_subjects <= self.invited_subjects
        ):
            raise ValueError(
                "Human, privileged and service subjects must have consistent enrollment."
            )
        return self

    @property
    def origin(self) -> str:
        return "https://" + urlsplit(self.redirect_uri).netloc
