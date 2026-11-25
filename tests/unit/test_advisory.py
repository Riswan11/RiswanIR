from sentinelforge.investigation.analysis import analyze
from sentinelforge.response.advisory import recommend


def test_advisory_uses_only_access_key_creation_evidence(investigation_request):
    evidence = analyze(investigation_request).evidence
    recommendation = recommend(evidence)
    assert recommendation.mode == "advisory"
    assert recommendation.evidence_ids == ["key-created"]
    assert recommend([evidence[0], evidence[-1]]) is None
