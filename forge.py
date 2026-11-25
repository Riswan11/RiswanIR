"""Compatibility imports for scripts run from the source checkout."""

from src.trailhound.core.errors import NotFoundError
from src.trailhound.investigation.analysis import analyze as analyze_request
from src.trailhound.models import InvestigationRequest
from src.trailhound.storage.sqlite import Store

__all__ = ["NotFoundError", "Store", "analyze"]


def analyze(data):
    """Return a JSON-compatible report for existing checkout scripts."""
    return analyze_request(InvestigationRequest.model_validate(data)).payload()
