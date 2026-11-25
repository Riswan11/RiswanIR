"""Selected CloudTrail network and TLS metadata."""

from .base import DomainModel


class TLSDetails(DomainModel):
    version: str | None = None
    cipher_suite: str | None = None
    client_host: str | None = None
