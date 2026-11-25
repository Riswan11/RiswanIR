"""Compatibility imports for scripts run from the source checkout."""

from src.riswan_ir.core.errors import NotFoundError
from src.riswan_ir.investigation.analysis import analyze as analyze_request
from src.riswan_ir.models import InvestigationRequest
from src.riswan_ir.storage.sqlite import Store

__all__ = ["NotFoundError", "Store", "analyze"]


def analyze(data):
    """Return a JSON-compatible report for existing checkout scripts."""
    return analyze_request(InvestigationRequest.model_validate(data)).payload()
