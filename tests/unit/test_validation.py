from datetime import timezone

import pytest

from trailhound.core.fields import mapping, now, required, text_field, utc_timestamp
from trailhound.ingestion.exports import export_records


@pytest.mark.parametrize("value", [None, 123, " ", "x" * 301])
def test_required_rejects_invalid_text(value):
    with pytest.raises(ValueError, match="Provide field"):
        required({"field": value}, "field")


def test_safe_field_extraction_and_utc_conversion():
    assert required({"field": " text "}, "field") == "text"
    assert mapping({"nested": []}, "nested") == {}
    assert text_field({"field": ""}, "field") is None
    assert text_field({"field": "abcdef"}, "field", 3) == "abc"
    assert utc_timestamp("2025-01-01T01:00:00+01:00").isoformat() == "2025-01-01T00:00:00+00:00"
    assert utc_timestamp(now()).tzinfo is timezone.utc


@pytest.mark.parametrize("entries", [None, {}, [None] * 2001])
def test_lookup_event_size_and_type(entries):
    with pytest.raises(ValueError, match="2,000"):
        export_records({"Events": entries})
