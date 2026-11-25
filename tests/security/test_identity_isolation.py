import copy

from riswan_ir.correlation.aws import AWSIdentityResolver
from riswan_ir.investigation.correlation import correlate_with_context
from riswan_ir.models.identity import CloudIdentity
from tests.integration.test_identity_correlation import ACTOR, ROLE, chain


def test_identity_resolution_scopes_principal_ids_to_account_and_partition():
    resolver = AWSIdentityResolver()
    user = CloudIdentity(type="IAMUser", principal_id="same-id", account_id="123456789012")
    different = user.model_copy(update={"account_id": "999988887777"})
    assert resolver.resolve(user, "one").id == resolver.resolve(user, "two").id
    assert resolver.resolve(user, "one").id != resolver.resolve(different, "two").id
    assert resolver.resolve(user, "one").id != resolver.resolve(user, "one", "cn-north-1").id
    service = CloudIdentity(
        type="AWSService", account_id="123456789012", invoked_by="ecs.amazonaws.com"
    )
    assert resolver.resolve(service, "one").aliases[0].value == "ecs.amazonaws.com"
    assert resolver.resolve(None, "one").id != resolver.resolve(None, "two").id


def test_unrelated_issuance_makes_reused_credential_ambiguous():
    first, second, _ = chain()
    unrelated = copy.deepcopy(first)
    unrelated["eventID"] = "unrelated"
    unrelated["eventTime"] = "2025-01-01T00:01:30Z"
    unrelated["userIdentity"]["arn"] = "arn:aws:iam::123456789012:user/other"
    evidence, result = correlate_with_context([second, unrelated, first], ACTOR)
    assert [event.id for event in evidence] == ["initial"]
    assert "conflicting" in result.unresolved[0]


def test_fingerprint_does_not_override_scope_or_issuer_conflicts():
    first, second, _ = chain()
    for identity in [
        {**second["userIdentity"], "accountId": "123456789012"},
        {**second["userIdentity"], "principalId": "Different:reused-name"},
        {**second["userIdentity"], "sessionContext": {"sourceIdentity": "other"}},
        {
            **second["userIdentity"],
            "sessionContext": {"sessionIssuer": {"arn": ROLE + "-different"}},
        },
    ]:
        evidence, _ = correlate_with_context([first, {**second, "userIdentity": identity}], ACTOR)
        assert [event.id for event in evidence] == ["initial"]


def test_arn_issuer_and_creation_time_can_corroborate_absent_credential():
    first, second, _ = chain()
    del second["userIdentity"]["accessKeyId"]
    evidence, result = correlate_with_context([second, first], ACTOR)
    assert evidence[-1].query == "Corroborated STS session match"
    assert any(
        edge.relationship == "CHAINED_TO" and edge.confidence == "high"
        for edge in result.relationships
    )
    second["userIdentity"]["sessionContext"]["attributes"]["creationDate"] = "2025-01-01T00:01:35Z"
    first["sourceIPAddress"] = second["sourceIPAddress"] = "203.0.113.8"
    first["userAgent"] = second["userAgent"] = "fixture"
    assert [item.id for item in correlate_with_context([first, second], ACTOR)[0]] == ["initial"]
