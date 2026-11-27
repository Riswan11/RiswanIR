"""Authenticated organization API and active tenant routing."""

import logging
import re
import sqlite3
from uuid import UUID

from riswan_ir.api.http import Application
from riswan_platform.authorization.enforcement import AccessDenied
from riswan_platform.core.exceptions import ContextRequiredError
from riswan_platform.data_protection import ProtectionDenied
from riswan_platform.identity.models import ProviderUnavailable, VerifiedPrincipal
from riswan_platform.tenancy import (
    Acceptance,
    InvitationRequest,
    LifecycleChange,
    OrganizationInput,
    OwnershipTransfer,
)

from .hosted_collection import CollectionAPI
from .hosted_product import HostedPostgresCases, HostedProduct
from .secret_api import BASE as SECRETS_BASE
from .secret_api import SecretAPI
from .tenancy import Tenancy

LOGGER = logging.getLogger(__name__)
BASE = "/v1/organizations"
NOT_FOUND = {"error": "Resource not found."}


class TenantAPI:
    def __init__(
        self,
        tenancy: Tenancy,
        product: HostedProduct | HostedPostgresCases,
        origin: str,
        secrets: SecretAPI | None = None,
        collections: CollectionAPI | None = None,
    ):
        self.tenancy = tenancy
        self.product = product
        self.origin = origin
        self.secrets = secrets
        self.collections = collections

    def __call__(self, env, principal: VerifiedPrincipal, request_id: str):
        path = env["PATH_INFO"]
        if not (
            path in {BASE, SECRETS_BASE}
            or path.startswith(
                (
                    BASE + "/",
                    SECRETS_BASE + "/",
                    "/v1/investigations",
                    "/v1/memory",
                    "/v1/integrations/",
                )
            )
        ):
            return None
        if (
            env["REQUEST_METHOD"] != "GET"
            and principal.session_id is not None
            and env.get("HTTP_ORIGIN") != self.origin
        ):
            return 403, {"error": "Trusted same-origin session required."}
        try:
            return self._route(env, principal, request_id)
        except (AccessDenied, ContextRequiredError):
            try:
                self.tenancy.record_denial(principal, request_id)
            except (ProviderUnavailable, sqlite3.Error):
                LOGGER.error("Tenant denial audit unavailable")
            return 404, NOT_FOUND
        except (ValueError, RecursionError):
            return 400, {"error": "Invalid request."}
        except ProtectionDenied:
            return 409, {"error": "Data protection policy prevents this operation."}
        except FileExistsError:
            return 409, {"error": "Resource already has a decision."}
        except (ProviderUnavailable, sqlite3.Error):
            LOGGER.error("Tenant storage unavailable")
            return 503, {"error": "Tenant storage unavailable."}
        except Exception as exc:
            LOGGER.error("Tenant request failed (%s)", type(exc).__name__)
            return 500, {"error": "Internal server error."}

    def _route(self, env, principal: VerifiedPrincipal, request_id: str):
        method, path = env["REQUEST_METHOD"], env["PATH_INFO"]
        if path.startswith("/v1/integrations/"):
            if self.collections is None:
                raise AccessDenied
            return self.collections.route(env, principal, request_id)
        if path == SECRETS_BASE or path.startswith(SECRETS_BASE + "/"):
            if self.secrets is None:
                raise AccessDenied
            return self.secrets.route(env, principal, request_id)
        if path.startswith(("/v1/investigations", "/v1/memory")):
            key = env.get("HTTP_X_RISWAN_TENANT", "")
            if not re.fullmatch(r"[0-9a-f-]{36}", key):
                raise AccessDenied
            try:
                tenant = UUID(key)
            except ValueError as exc:
                raise AccessDenied from exc
            return self.product.route(env, principal, tenant, request_id)
        if (method, path) == ("GET", BASE):
            return 200, [
                item.model_dump(mode="json") for item in self.tenancy.organizations(principal)
            ]
        if (method, path) == ("POST", BASE):
            request = OrganizationInput.model_validate(Application.body(env))
            return 201, self.tenancy.create(principal, request, request_id).model_dump(mode="json")
        if (method, path) == ("POST", BASE + "/invitations/accept"):
            acceptance = Acceptance.model_validate(Application.body(env))
            tenant = self.tenancy.accept(principal, acceptance.token, request_id)
            return 200, {"tenant_id": str(tenant)}
        location = re.fullmatch(BASE + r"/([0-9a-f-]{36})(.*)", path)
        if location is None:
            raise AccessDenied
        try:
            organization_id = UUID(location[1])
        except ValueError as exc:
            raise AccessDenied from exc
        suffix = location[2]
        if method == "GET" and not suffix:
            organization = self.tenancy.organization(principal, organization_id)
            return 200, organization.model_dump(mode="json")
        if method == "POST" and suffix == "/activate":
            organization = self.tenancy.organization(principal, organization_id)
            if (
                self.tenancy.context_for(principal, organization.tenant_id, "platform", request_id)
                is None
            ):
                raise AccessDenied
            return 200, {"tenant_id": str(organization.tenant_id)}
        if method == "PUT" and not suffix:
            request = OrganizationInput.model_validate(Application.body(env))
            return 200, self.tenancy.update(
                principal, organization_id, request, request_id
            ).model_dump(mode="json")
        if method == "POST" and suffix == "/lifecycle":
            change = LifecycleChange.model_validate(Application.body(env))
            return 200, self.tenancy.lifecycle(
                principal, organization_id, change.status, request_id
            ).model_dump(mode="json")
        if method == "GET" and suffix == "/members":
            return 200, [
                item.model_dump(mode="json")
                for item in self.tenancy.members(principal, organization_id, request_id)
            ]
        if method == "POST" and suffix == "/invitations":
            membership = InvitationRequest.model_validate(Application.body(env))
            return 201, self.tenancy.invite(
                principal, organization_id, membership, request_id
            ).model_dump(mode="json")
        if method == "PUT" and suffix == "/members/role":
            membership = InvitationRequest.model_validate(Application.body(env))
            self.tenancy.change_role(principal, organization_id, membership, request_id)
            return 204, None
        if method == "POST" and suffix == "/workloads":
            workload = OwnershipTransfer.model_validate(Application.body(env))
            self.tenancy.register_workload(
                principal, organization_id, workload.identity_id, request_id
            )
            return 204, None
        if method == "POST" and suffix == "/ownership":
            transfer = OwnershipTransfer.model_validate(Application.body(env))
            self.tenancy.transfer(principal, organization_id, transfer.identity_id, request_id)
            return 204, None
        target = re.fullmatch(r"/(members|invitations)/([0-9a-f-]{36})", suffix)
        if method == "DELETE" and target:
            try:
                key = UUID(target[2])
            except ValueError as exc:
                raise AccessDenied from exc
            if target[1] == "members":
                self.tenancy.revoke_member(principal, organization_id, key, request_id)
            else:
                self.tenancy.revoke_invitation(principal, organization_id, key, request_id)
            return 204, None
        raise AccessDenied
