"""Project evidence into actor, target, and credential-use edges."""




def build_graph(evidence):
    return (
        [{"from": item["principal"], "relationship": "CALLED", "to": item["id"]}
         for item in evidence if item["principal"]]
        + [{"from": item["id"], "relationship": "TARGETED", "to": item["target"]}
           for item in evidence if item["target"]]
        + [{"from": item["linked_from_evidence_id"], "relationship": "ISSUED_CREDENTIAL_USED_IN", "to": item["id"]}
           for item in evidence if item["linked_from_evidence_id"]]
    )
