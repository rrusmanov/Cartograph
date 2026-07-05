"""Default exposure-feature weights.

Kept in one place so they're easy to audit and calibrate. Higher weight = a stronger prior that the
signal is worth looking at first:

- ``tls_expiry`` / ``takeover_cname`` (3.0) – strongest, most concrete signals.
- ``off_primary_asn`` / ``nonprod_naming`` (2.0) – shadow IT and dev/staging hosts.
- ``orphan_stale`` / ``concentration`` (1.5) – dangling names and risk-concentration nodes.
- ``wildcard`` (1.0) – broadens exposure but common and weak on its own.

These are expert-set starting points, not tuned; M4 reports calibration.
"""

from __future__ import annotations

DEFAULT_WEIGHTS: dict[str, float] = {
    "tls_expiry": 3.0,
    "takeover_cname": 3.0,
    "off_primary_asn": 2.0,
    "nonprod_naming": 2.0,
    "orphan_stale": 1.5,
    "concentration": 1.5,
    "wildcard": 1.0,
}
