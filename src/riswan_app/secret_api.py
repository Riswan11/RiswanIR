"""Authenticated secret metadata and lifecycle routes. Material never leaves this adapter."""

import re
from uuid import UUID

from riswan_ir.api.http import Application
from riswan_platform.authorization.enforcement import AccessDenied
from riswan_platform.core.context import bind_context
from riswan_platform.identity.models import VerifiedPrincipal
from riswan_platform.secrets import (
    ProviderUnavailable,
    Registration,
    RollbackRequest,
    RotationRequest,
    SecretAccessPolicy,
    SecretError,
    Update,
)

from .secrets import Secrets

BASE = "/v1/secrets"


class SecretAPI:
    def __init__(self, service: Secrets):
        self.service = service

    def route(self, env, principal: VerifiedPrincipal, request_id: str):
        raw = env.get("HTTP_X_RISWAN_TENANT", "")
        if not re.fullmatch(r"[0-9a-f-]{36}", raw):
            raise AccessDenied
        try:
            tenant_id = UUID(raw)
        except ValueError as exc:
            raise AccessDenied from exc
        context = self.service.tenancy.context_for(principal, tenant_id, "ir", request_id)
        if context is None:
            raise AccessDenied
        with bind_context(context):
            try:
                return self._route(env)
            except ProviderUnavailable:
                return 503, {"error": "Credential provider unavailable."}
            except SecretError:
                return 409, {"error": "Credential operation could not complete."}

    def _route(self, env):
        method, path = env["REQUEST_METHOD"], env["PATH_INFO"]
        s = self.service
        if path == BASE:
            if method == "GET":
                return 200, [item.model_dump(mode="json") for item in s.list_metadata()]
            if method == "POST":
                request = Registration.model_validate(Application.body(env))
                return 201, s.register(request).model_dump(mode="json")
        match = re.fullmatch(BASE + r"/([0-9a-f-]{36})(/[^/]+)?", path)
        if match is None:
            raise AccessDenied
        try:
            key = UUID(match[1])
        except ValueError as exc:
            raise AccessDenied from exc
        operation = (method, match[2])
        if operation == ("GET", None):
            return 200, s.metadata(key).model_dump(mode="json")
        if operation == ("PATCH", None):
            request_update = Update.model_validate(Application.body(env))
            return 200, s.update(key, request_update).model_dump(mode="json")
        if operation == ("POST", "/bind-provider"):
            return 200, s.bind_existing(key).model_dump(mode="json")
        if operation == ("GET", "/versions"):
            return 200, [item.model_dump(mode="json") for item in s.versions(key)]
        if operation == ("POST", "/rotate"):
            replacement = RotationRequest.model_validate(Application.body(env))
            return 200, s.rotate(key, replacement).model_dump(mode="json")
        if operation == ("POST", "/rollback"):
            rollback = RollbackRequest.model_validate(Application.body(env))
            return 200, s.rollback(key, rollback.version_id).model_dump(mode="json")
        if operation == ("POST", "/revoke"):
            return 200, s.revoke(key).model_dump(mode="json")
        if operation == ("DELETE", None):
            return 202, s.delete(key).model_dump(mode="json")
        if operation == ("POST", "/confirm-deletion"):
            return 200, s.delete(key, confirm=True).model_dump(mode="json")
        if operation == ("GET", "/audit"):
            return 200, [item.model_dump(mode="json") for item in s.audit(key)]
        if operation in {("PUT", "/policy"), ("DELETE", "/policy")}:
            policy = SecretAccessPolicy.model_validate(Application.body(env))
            s.set_policy(key, policy, revoke=method == "DELETE")
            return 204, None
        raise AccessDenied
