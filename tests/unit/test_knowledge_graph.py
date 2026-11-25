from trailhound.investigation.analysis import analyze
from trailhound.models import Relationship


def test_graph_connects_actors_targets_and_issuance_events(investigation_request):
    report = analyze(investigation_request)
    edges = {(edge.source, edge.relationship, edge.target) for edge in report.graph}
    assert (investigation_request.principal, Relationship.CALLED, "role-issued") in edges
    assert ("key-used", Relationship.TARGETED, "example-archive") in edges
    assert ("role-issued", Relationship.ISSUED_CREDENTIAL_USED_IN, "key-created") in edges
    assert ("key-created", Relationship.ISSUED_CREDENTIAL_USED_IN, "key-used") in edges
    assert len(edges) == len(report.graph)
