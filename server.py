"""Run SentinelForge directly from the source checkout."""

from src.sentinelforge.__main__ import main
from src.sentinelforge.api.http import Application

__all__ = ["Application", "main"]

if __name__ == "__main__":
    main()
