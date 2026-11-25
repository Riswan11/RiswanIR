from sentinelforge.investigation.analysis import analyze
from sentinelforge.memory.similarity import similar_investigations
from sentinelforge.models import Disposition, InvestigationReport


def test_ranks_by_shared_events_limits_results_and_ignores_zero_overlap(investigation_request):
    def report(identifier, records):
        result = analyze(investigation_request.model_copy(update={"records": records}))
        return InvestigationReport(id=identifier, created_at="2025-01-01T00:00:00Z", **dict(result))

    current = report("current", investigation_request.records)
    partial = report("partial", investigation_request.records[:1])
    empty = report("empty", [])
    history = [(partial, Disposition.BENIGN), (empty, Disposition.BENIGN)]
    history += [
        (report(f"prior-{index}", investigation_request.records), Disposition.SUSPICIOUS)
        for index in range(6)
    ]
    matches = similar_investigations(current, history)
    assert [match.id for match in matches] == [f"prior-{index}" for index in range(5)]
    assert matches[0].shared_events == ["AssumeRole", "CreateAccessKey", "GetObject"]
    assert matches[0].disposition is Disposition.SUSPICIOUS
    assert [match.id for match in similar_investigations(current, history[:2])] == ["partial"]
