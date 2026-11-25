"""Trusted outbound token issuance using explicitly configured SDK credentials."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from riswan_platform.secrets import CredentialLease, ProviderUnavailable
from riswan_platform.secrets.providers import AzureNamespace, CredentialRequest, GCPNamespace


class BoundTokenOperation:
    def __init__(
        self,
        registration: CredentialRequest,
        acquire: Callable[[], tuple[str, datetime]],
        perform: Callable[[str], None],
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        self._registration = registration
        self._acquire = acquire
        self._perform = perform
        self._clock = clock

    def execute(self, request: CredentialRequest) -> CredentialLease:
        if request != self._registration:
            raise ProviderUnavailable("Credential target unavailable.")
        try:
            token, expires = self._acquire()
            now = self._clock()
            if not token or not now < expires <= now + timedelta(hours=2):
                raise ValueError
            self._perform(token)
            return CredentialLease(id=uuid4(), expires_at=expires)
        except Exception:
            raise ProviderUnavailable("Credential operation unavailable.") from None


def azure_workload(
    registration: CredentialRequest,
    client_id: UUID,
    token_file: Path,
    perform: Callable[[str], None],
) -> BoundTokenOperation:
    from azure.identity import WorkloadIdentityCredential

    namespace = registration.resource.namespace
    if (
        not isinstance(namespace, AzureNamespace)
        or registration.audience != "https://vault.azure.net/.default"
    ):
        raise ValueError("Azure workload must target the registered Key Vault scope.")
    credential = WorkloadIdentityCredential(
        tenant_id=str(namespace.directory_id),
        client_id=str(client_id),
        token_file_path=str(token_file),
    )

    def acquire() -> tuple[str, datetime]:
        token = credential.get_token(registration.audience)
        return token.token, datetime.fromtimestamp(token.expires_on, UTC)

    return BoundTokenOperation(registration, acquire, perform)


def google_workload(
    registration: CredentialRequest,
    project_number: str,
    pool: str,
    provider: str,
    token_file: Path,
    perform: Callable[[str], None],
    *,
    service_account: str | None = None,
) -> BoundTokenOperation:
    import re

    from google.auth import identity_pool
    from google.auth.transport.requests import Request

    namespace = registration.resource.namespace
    if (
        not isinstance(namespace, GCPNamespace)
        or not re.fullmatch(r"[0-9]{1,20}", project_number)
        or not all(re.fullmatch(r"[a-z0-9-]{4,32}", item) for item in (pool, provider))
    ):
        raise ValueError("Invalid Google workload target.")
    audience = (
        f"//iam.googleapis.com/projects/{project_number}/locations/global/"
        f"workloadIdentityPools/{pool}/providers/{provider}"
    )
    if registration.audience != audience:
        raise ValueError("Google workload audience must match the registered pool.")
    impersonation = None
    if service_account:
        if not re.fullmatch(
            r"[a-z0-9-]{6,30}@" + re.escape(namespace.project) + r"\.iam\.gserviceaccount\.com",
            service_account,
        ):
            raise ValueError("Impersonation must target the registered Google Cloud project.")
        impersonation = (
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
            + service_account
            + ":generateAccessToken"
        )
    credential = identity_pool.Credentials(
        audience=audience,
        subject_token_type="urn:ietf:params:oauth:token-type:jwt",
        token_url="https://sts.googleapis.com/v1/token",
        credential_source={"file": str(token_file)},
        service_account_impersonation_url=impersonation,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    transport = Request()

    def acquire() -> tuple[str, datetime]:
        credential.refresh(transport)
        token, expiry = credential.token, credential.expiry
        if not token or expiry is None:
            raise ValueError
        return token, expiry.replace(tzinfo=UTC) if expiry.tzinfo is None else expiry

    return BoundTokenOperation(registration, acquire, perform)
