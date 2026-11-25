"""Run Riswan IR directly from the source checkout."""

from riswan_ir.__main__ import main
from riswan_ir.api.http import Application

__all__ = ["Application", "main"]

if __name__ == "__main__":
    main(local_launcher=True)
