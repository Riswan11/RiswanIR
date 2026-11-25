"""Compatibility imports for scripts run from the source checkout."""

from riswan_ir.core.errors import NotFoundError
from riswan_ir.investigation.analysis import analyze as analyze_request
from riswan_ir.models import InvestigationRequest
from riswan_ir.storage.sqlite import Store

__all__ = ["NotFoundError", "Store", "analyze"]


def analyze(data):
    """Return a JSON-compatible report for existing checkout scripts."""
    return analyze_request(InvestigationRequest.model_validate(data)).payload()
