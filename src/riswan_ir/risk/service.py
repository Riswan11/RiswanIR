"""Validate case-scoped assessment API lookups and page bounds."""

import re
from typing import Protocol
from urllib.parse import parse_qs

from pydantic import Field

from riswan_security_data.canonical_event import CanonicalModel

from ..core.errors import NotFoundError
from .models import Assessment


class Page(CanonicalModel):
    limit: int = Field(default=25, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=100_000)


class RiskSource(Protocol):
    def risk_page(
        self,
        case_id: str,
        limit: int,
        offset: int,
        subject: tuple[str, str] | None,
        *,
        scoped: bool = False,
    ) -> list[Assessment]: ...
    def risk_assessment(
        self, case_id: str, assessment_id: str, *, replay: bool, scoped: bool = False
    ) -> Assessment: ...


def serve(
    store: RiskSource, case_id: str, suffix: str, query_string: str, *, scoped: bool = False
) -> dict[str, object]:
    if len(query_string) > 1024:
        raise ValueError("Risk query string is too large.")
    query = parse_qs(query_string, strict_parsing=True, max_num_fields=5, keep_blank_values=True)
    if any(len(values) != 1 for values in query.values()):
        raise ValueError("Duplicate risk query parameter.")
    assessment = re.fullmatch(r"/risk/([a-f0-9]{64})(/replay)?", suffix)
    if assessment:
        if query:
            raise ValueError("Risk assessment details do not take filters.")
        return store.risk_assessment(
            case_id, assessment[1], replay=bool(assessment[2]), scoped=scoped
        ).payload()
    history = re.fullmatch(r"/risk/(finding|incident)/((?:sha256:)?[a-f0-9]{64})/history", suffix)
    if suffix != "/risk" and history is None:
        raise NotFoundError("Risk assessment route not found.")
    page = Page.model_validate({key: values[0] for key, values in query.items()})
    subject = (history[1], history[2]) if history else None
    rows = store.risk_page(case_id, page.limit + 1, page.offset, subject, scoped=scoped)
    return {
        "assessments": [item.payload() for item in rows[: page.limit]],
        "next_offset": page.offset + page.limit if len(rows) > page.limit else None,
    }
