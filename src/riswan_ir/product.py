"""Riswan IR's published module descriptor."""

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version


def installed_version() -> str:
    try:
        return version("riswan-ir")
    except PackageNotFoundError:
        return "0.1.0"


@dataclass(frozen=True, slots=True)
class IRProduct:
    product_id: str = "ir"
    display_name: str = "Riswan IR"
    version: str = installed_version()

    def capabilities(self) -> tuple[str, ...]:
        return (
            "security_event_ingestion",
            "evidence_preservation",
            "threat_detection",
            "security_knowledge_graph",
            "threat_correlation",
            "risk_assessment",
            "historical_investigation_memory",
        )
