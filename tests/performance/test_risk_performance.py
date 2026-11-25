from time import perf_counter

from riswan_ir.risk.engine import calculate
from riswan_ir.risk.registry import default_policy
from tests.unit.test_risk_engine import NOW, standard_inputs


def test_weighted_scoring_benchmark(record_property):
    count = 1000
    inputs, policy = standard_inputs(), default_policy()
    start = perf_counter()
    results = [calculate(str(index), inputs, policy, NOW, "initial") for index in range(count)]
    elapsed = perf_counter() - start
    record_property("risk_elapsed_seconds", round(elapsed, 4))
    record_property("risk_assessments_per_second", round(count / elapsed))
    assert {item.assessment.risk.score for item in results} == {87.5}
    assert len({item.assessment.id for item in results}) == count
    assert elapsed < 10
