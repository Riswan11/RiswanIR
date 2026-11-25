"""Build analyst advisories from evidence."""




def recommend(evidence):
    persistence = [item["id"] for item in evidence if item["event"] == "CreateAccessKey"]
    if not persistence:
        return None
    return {
        "id": "review-access-key",
        "summary": "Verify the new key and its owners before considering containment.",
        "mode": "advisory",
        "evidence_ids": persistence,
    }
