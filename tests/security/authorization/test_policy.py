"""Exercise authorization against trusted policy and untrusted request attributes."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4
from wsgiref.util import setup_testing_defaults

import pytest

from riswan_app.authorization_repository import AuthorizationRepository
from riswan_ir.api.http import Application
from riswan_ir.product import IRProduct
from riswan_platform.authorization import (
    Assignment,
    AuthorizationRequest,
    Evaluator,
    Grant,
    Permission,
    Resource,
    Role,
    Scope,
    ScopeType,
    SubjectPolicy,
)
from riswan_platform.authorization.enforcement import AccessDenied, Enforcement
from riswan_platform.core.context import PlatformContext, bind_context
from riswan_platform.identity.models import (
    IdentityStatus,
    IdentityType,
    PlatformIdentity,
    VerifiedPrincipal,
)
from riswan_platform.identity.principal import bind_principal


@pytest.fixture
def policy_setup(tmp_path):
    instant = datetime.now(UTC)
    actor, tenant = uuid4(), uuid4()
    identity = PlatformIdentity(
        actor,
        IdentityType.HUMAN,
        "trusted",
        "subject",
        "Analyst",
        None,
        IdentityStatus.ACTIVE,
        instant,
        instant,
    )
    principal = VerifiedPrincipal(identity, "session", True)
    context = PlatformContext(tenant, str(actor), "human", "ir", "request", "correlation")
    product = Scope(ScopeType.PRODUCT, "ir")
    resource = Resource(tenant, "ir", Scope(ScopeType.INVESTIGATION, "case"), (product,))
    assignment = Assignment(Role.ANALYST, product, actor, instant - timedelta(days=1))
    grant = Grant(Permission.READ, resource.scope)
    repository = AuthorizationRepository(tmp_path / "authorization.sqlite3")
    repository.replace_snapshot(actor, tenant, SubjectPolicy((assignment,), (grant,)))
    request = AuthorizationRequest(principal, context, Permission.READ, resource)
    return repository, request, assignment, grant


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("valid", "ALLOWED"),
        ("cross_tenant", "CROSS_TENANT"),
        ("no_membership", "NO_MEMBERSHIP"),
        ("deny", "EXPLICIT_DENY"),
        ("no_grant", "RESOURCE_SCOPE_MISMATCH"),
        ("revoked", "NO_PERMISSION"),
        ("expired", "NO_PERMISSION"),
        ("suspended", "INVALID_ACTOR"),
        ("wrong_actor", "INVALID_ACTOR"),
        ("wrong_product", "INVALID_SCOPE"),
        ("platform_action", "INVALID_SCOPE"),
        ("execute", "OPERATION_DISABLED"),
        ("restricted", "MFA_REQUIRED"),
        ("operator", "NO_PERMISSION"),
    ],
)
def test_policy_decisions(policy_setup, scenario, expected):
    repository, request, assignment, grant = policy_setup
    actor, tenant = request.principal.identity.identity_id, request.context.tenant_id
    grants = (grant,)
    if scenario == "cross_tenant":
        request = replace(request, resource=replace(request.resource, tenant_id=uuid4()))
    elif scenario == "deny":
        grants += (replace(grant, deny=True),)
    elif scenario == "no_grant":
        grants = ()
    elif scenario == "revoked":
        assignment = replace(assignment, revoked=True)
    elif scenario == "expired":
        assignment = replace(assignment, expires_at=assignment.created_at + timedelta(seconds=1))
    elif scenario == "suspended":
        principal = replace(
            request.principal,
            identity=replace(request.principal.identity, status=IdentityStatus.SUSPENDED),
        )
        request = replace(request, principal=principal)
    elif scenario == "wrong_actor":
        request = replace(request, context=replace(request.context, actor_id=str(uuid4())))
    elif scenario == "wrong_product":
        request = replace(request, resource=replace(request.resource, product_id="other"))
    elif scenario == "platform_action":
        request = replace(request, action=Permission.IDENTITY_READ)
    elif scenario == "execute":
        request = replace(request, action=Permission.EXECUTE)
    elif scenario == "restricted":
        request = replace(
            request,
            resource=replace(request.resource, restricted=True),
            principal=replace(request.principal, mfa_verified=False),
        )
    elif scenario == "operator":
        assignment = replace(assignment, role=Role.OPERATOR)
    policy = None if scenario == "no_membership" else SubjectPolicy((assignment,), grants)
    repository.replace_snapshot(actor, tenant, policy)
    decision = Evaluator(repository, repository).evaluate(request)
    assert decision.reason_code == expected
    assert decision.allowed is (expected == "ALLOWED")
    assert decision.correlation_id == request.context.correlation_id


@pytest.mark.parametrize("own_proposal", [True, False])
def test_response_approval_requires_independence(policy_setup, own_proposal):
    repository, request, assignment, _ = policy_setup
    actor, tenant = request.principal.identity.identity_id, request.context.tenant_id
    scope = Scope(ScopeType.RESPONSE, "proposal")
    resource = replace(
        request.resource, scope=scope, proposer_id=actor if own_proposal else uuid4()
    )
    repository.replace_snapshot(
        actor,
        tenant,
        SubjectPolicy(
            (replace(assignment, role=Role.APPROVER),),
            (Grant(Permission.APPROVE, scope),),
        ),
    )
    decision = Evaluator(repository, repository).evaluate(
        replace(request, action=Permission.APPROVE, resource=resource)
    )
    assert decision.allowed is not own_proposal


def test_workload_and_evaluation_fail_closed(policy_setup):
    repository, request, _, _ = policy_setup
    agent = replace(
        request.principal,
        identity=replace(
            request.principal.identity,
            identity_type=IdentityType.AGENT,
        ),
    )
    assert (
        Evaluator(repository, repository)
        .evaluate(
            replace(
                request,
                principal=agent,
                context=replace(request.context, actor_type="agent"),
                action=Permission.APPROVE,
            )
        )
        .reason_code
        == "WORKLOAD_RESTRICTED"
    )

    class Unavailable:
        def policy_for(self, *args):
            raise RuntimeError("unavailable")

        def record(self, *args):
            raise RuntimeError("unavailable")

    assert Evaluator(Unavailable(), repository).evaluate(request).reason_code == "EVALUATION_FAILED"
    denied = replace(request, action=Permission.EXECUTE)
    assert Evaluator(repository, Unavailable()).evaluate(denied).reason_code == "AUDIT_UNAVAILABLE"


def test_invalid_policy_configuration(policy_setup):
    _, _, assignment, _ = policy_setup
    with pytest.raises(ValueError):
        Scope(ScopeType.INVESTIGATION, "")
    with pytest.raises(ValueError):
        replace(assignment, expires_at=assignment.created_at)
    with pytest.raises(ValueError):
        Grant("ir.*", assignment.scope)


def test_scoped_api_and_revocation(policy_setup, store, investigation_request):
    repository, request, assignment, grant = policy_setup
    allowed = store.create(investigation_request)
    hidden = store.create(investigation_request)
    resources = tuple(
        replace(request.resource, scope=Scope(ScopeType.INVESTIGATION, report.id))
        for report in (allowed, hidden)
    )

    class Directory:
        def resolve(self, kind, key):
            return next((r for r in resources if r.scope == Scope(kind, key)), None)

        def investigations(self):
            return resources

    actor, tenant = request.principal.identity.identity_id, request.context.tenant_id
    repository.replace_snapshot(
        actor,
        tenant,
        SubjectPolicy(
            (assignment,),
            (replace(grant, scope=resources[0].scope),),
        ),
    )
    guard = Enforcement(Evaluator(repository, repository), Directory())
    app = Application(
        store,
        context_provider=lambda: request.context,
        tenant_id=tenant,
        product=IRProduct(),
        enforcement=guard,
    )

    def get(path):
        env = {}
        setup_testing_defaults(env)
        env.update(PATH_INFO=path, HTTP_HOST="localhost", HTTP_X_ROLE="ir.administrator")
        result = []
        body = b"".join(app(env, lambda status, headers: result.append(status)))
        return result[0], body

    base = "/v1/investigations"
    assert get(base)[0].startswith("404")
    with bind_principal(request.principal):
        status, body = get(base)
        assert status.startswith("200")
        assert allowed.id.encode() in body and hidden.id.encode() not in body
        assert get(f"{base}/{allowed.id}")[0].startswith("200")
        assert get(f"{base}/{hidden.id}") == get(f"{base}/{'0' * 32}")
        assert get(f"{base}/{allowed.id}/evidence")[0].startswith("404")
        repository.replace_snapshot(actor, tenant, None)
        assert get(base)[1] == b"[]"
        with bind_context(request.context), pytest.raises(AccessDenied):
            guard.require(Permission.READ, ScopeType.INVESTIGATION, allowed.id)
