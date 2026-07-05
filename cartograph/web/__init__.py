"""Local web UI for Cartograph (optional; requires the ``web`` extra).

``service`` has no web-framework dependency and is always importable; ``app`` imports FastAPI and is
loaded lazily by the ``cartograph serve`` command.
"""

from cartograph.web.service import ScanOptions, ScanResult, is_valid_domain, run_scan

__all__ = ["ScanOptions", "ScanResult", "is_valid_domain", "run_scan"]
