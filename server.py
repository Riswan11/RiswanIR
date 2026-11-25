"""Run TrailHound directly from the source checkout."""

from src.trailhound.__main__ import main
from src.trailhound.api.http import Application

__all__ = ["Application", "main"]

if __name__ == "__main__":
    main()
