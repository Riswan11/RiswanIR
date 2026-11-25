import pytest

from sentinelforge.knowledge_graph.models import SecurityGraph
from sentinelforge.knowledge_graph.ontology import REGISTRY, VERSION, Entity, Relation
from sentinelforge.models import InvestigationRequest
from tests.fixtures.cloudtrail import ROOT, record


def test_ontology_rejects_impossible_edges_versions_and_false_provenance(
    store, investigation_request
):
    graph = store.security_graph(store.create(investigation_request).id)
    for operation, error in [
        (lambda data: data.update(ontology_version="0.1.0"), "Unsupported security ontology"),
        (lambda data: data["nodes"].append(data["nodes"][0]), "Duplicate graph"),
        (
            lambda data: (
                data["relationships"][0].update(relation=Relation.ASSUMED_ROLE)
                if data["relationships"][0]["relation"] != Relation.ASSUMED_ROLE
                else data["relationships"][0].update(relation=Relation.DERIVED_FROM)
            ),
            "Relationship endpoints",
        ),
        (
            lambda data: data["relationships"][0]["observations"][0].update(source="other"),
            "references evidence",
        ),
        (
            lambda data: data["relationships"][0]["observations"][0].update(evidence_id="outside"),
            "references evidence",
        ),
        (lambda data: data.update(investigation_id="another-case"), "matching investigation"),
    ]:
        data = graph.model_dump(mode="json")
        operation(data)
        with pytest.raises(ValueError, match=error):
            SecurityGraph.model_validate(data)
    assert (Entity.IDENTITY, Entity.IDENTITY) in REGISTRY[VERSION][Relation.ASSUMED_ROLE]


def test_permission_and_mutation_require_explicit_successful_operations(store):
    policy = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    records = [
        record(
            "attach",
            1,
            "AttachUserPolicy",
            eventSource="iam.amazonaws.com",
            requestParameters={"userName": "John", "policyArn": policy},
        ),
        record(
            "failed-attach",
            2,
            "AttachUserPolicy",
            eventSource="iam.amazonaws.com",
            requestParameters={"userName": "John", "policyArn": policy},
            errorCode="Denied",
        ),
        record(
            "write",
            3,
            "PutObject",
            eventSource="s3.amazonaws.com",
            requestParameters={"bucketName": "example"},
        ),
        record(
            "failed-write",
            4,
            "PutObject",
            eventSource="s3.amazonaws.com",
            requestParameters={"bucketName": "example"},
            errorCode="Denied",
        ),
    ]
    report = store.create(
        InvestigationRequest(title="Review change", principal=ROOT, records=records)
    )
    graph = store.security_graph(report.id)
    nodes = {node.id: node for node in graph.nodes}
    (grant,) = [edge for edge in graph.relationships if edge.relation == Relation.HAS_PERMISSION]
    assert nodes[grant.source].label == ROOT and nodes[grant.target].label == policy
    assert [item.event_id for item in grant.observations] == ["attach"]
    (mutation,) = [edge for edge in graph.relationships if edge.relation == Relation.MODIFIED]
    assert [item.event_id for item in mutation.observations] == ["write"]
    assert nodes[mutation.target].label == "example"


def test_bucket_name_and_arn_resolve_to_same_account_entity(store):
    bucket = "example"
    account = ROOT.split(":")[4]
    reads = [
        record(
            "with-arn",
            1,
            "GetObject",
            eventSource="s3.amazonaws.com",
            recipientAccountId=account,
            requestParameters={"bucketName": bucket},
            resources=[{"ARN": f"arn:aws:s3:::{bucket}", "accountId": account}],
            vpcEndpointId="vpce-0123456789",
        ),
        record(
            "with-name",
            2,
            "GetObject",
            eventSource="s3.amazonaws.com",
            recipientAccountId=account,
            requestParameters={"bucketName": bucket},
        ),
    ]
    report = store.create(InvestigationRequest(title="Review reads", principal=ROOT, records=reads))
    graph = store.security_graph(report.id)
    (resource,) = [node for node in graph.nodes if node.kind == Entity.RESOURCE]
    assert resource.label == bucket and resource.account == account
    assert {
        obs.event_id
        for edge in graph.relationships
        if edge.relation == Relation.ACCESSED_RESOURCE and edge.target == resource.id
        for obs in edge.observations
    } == {"with-arn", "with-name"}
    (endpoint,) = [node for node in graph.nodes if node.kind == Entity.NETWORK]
    assert any(
        edge.relation == Relation.VIA_NETWORK and edge.target == endpoint.id
        for edge in graph.relationships
    )
