from riswan_ir.evidence.integrity import seal_evidence
from riswan_ir.normalization.cloudtrail import normalize


def test_hash_is_stable_under_raw_field_reordering_and_binds_provenance(cloudtrail):
    record = cloudtrail["Records"][1]
    event = normalize(record)
    original = seal_evidence(event, "role-issued")
    reordered = normalize(dict(reversed(list(record.items()))))
    assert original.integrity_hash == seal_evidence(reordered, "role-issued").integrity_hash
    assert original.integrity_hash != seal_evidence(event, None).integrity_hash
    assert original.linked_from_evidence_id == "role-issued"
