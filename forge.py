"""Compatibility imports for scripts run from the source checkout."""

from src.sentinelforge.core.errors import NotFoundError
from src.sentinelforge.investigation.analysis import analyze as analyze_request
from src.sentinelforge.models import InvestigationRequest
from src.sentinelforge.storage.sqlite import Store

__all__ = ["NotFoundError", "Store", "analyze"]


def analyze(data):
    """Return a JSON-compatible report for existing checkout scripts."""
    return analyze_request(InvestigationRequest.model_validate(data)).payload()
