"""Build analyst advisories from evidence."""

from ..models import AdvisoryAction, Evidence


def recommend(evidence: list[Evidence]) -> AdvisoryAction | None:
    persistence = [item.id for item in evidence if item.event == "CreateAccessKey"]
    if not persistence:
        return None
    return AdvisoryAction(
        id="review-access-key",
        summary="Verify the new key and its owners before considering containment.",
        mode="advisory",
        evidence_ids=persistence,
    )
