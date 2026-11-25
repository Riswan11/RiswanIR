"""Trace successful calls and downstream credential use."""

from ..core.fields import mapping, text_field, utc_timestamp
from ..evidence.integrity import integrity_hash
from ..normalization.cloudtrail import issued_credential, normalize


def correlate(records, principal):
    unique = {}
    for record in records:
        item = normalize(record)
        identity = mapping(record, "userIdentity")
        row = (item, text_field(identity, "accessKeyId"), issued_credential(record, item), bool(record.get("errorCode")))
        if unique.setdefault(item["id"], row) != row:
            raise ValueError("Conflicting CloudTrail records share an eventID.")
    ordered = sorted(unique.values(), key=lambda row: (row[0]["observed_at"], row[0]["id"]))
    evidence = []
    issued = {}
    for item, key, credential, failed in ordered:
        if failed:
            continue
        parent = None
        timestamp = utc_timestamp(item["observed_at"])
        for origin, expected_arn, expires_at in issued.get(key, ()):
            if origin["observed_at"] >= item["observed_at"]:
                continue
            if expected_arn and item["principal"] and expected_arn != item["principal"]:
                continue
            if expires_at and timestamp >= expires_at:
                continue
            parent = origin
            break
        if item["principal"] != principal and parent is None:
            continue
        item["query"] = "Issued access key match" if parent else "Exact principal ARN match"
        item["linked_from_evidence_id"] = parent["id"] if parent else None
        item["integrity_hash"] = integrity_hash(item)
        evidence.append(item)
        issued_key, session_arn, expires_at = credential
        if issued_key:
            issued.setdefault(issued_key, []).append((item, session_arn, expires_at))
    return evidence
