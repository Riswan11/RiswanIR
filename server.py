"""Run Riswan IR directly from the source checkout."""

from src.riswan_ir.__main__ import main
from src.riswan_ir.api.http import Application

__all__ = ["Application", "main"]

if __name__ == "__main__":
    main()
