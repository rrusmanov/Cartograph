"""Configuration and the scope-guard.

Passive collection is always allowed. Active operations (anything that sends a packet to the target)
are refused unless the host is in a user-provided allowlist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


class ScopeViolation(RuntimeError):
    """Raised when an active operation is attempted against an out-of-scope target."""


@dataclass
class ScopeGuard:
    """Allowlist-based authorization gate for active operations.

    ``allow`` holds apex domains the user has confirmed they are authorized to actively test
    (a bug-bounty scope, or domains they own). A host is in scope if it equals, or is a subdomain
    of, any allowlisted apex.
    """

    allow: set[str] = field(default_factory=set)

    @classmethod
    def from_file(cls, path: str | Path) -> ScopeGuard:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        entries = data.get("allow", []) if isinstance(data, dict) else data
        allow = {str(e).strip().rstrip(".").lower() for e in entries if str(e).strip()}
        return cls(allow=allow)

    def is_allowed(self, host: str) -> bool:
        host = host.strip().rstrip(".").lower()
        return any(host == apex or host.endswith("." + apex) for apex in self.allow)

    def enforce(self, host: str) -> None:
        """Raise :class:`ScopeViolation` unless ``host`` is authorized for active operations."""
        if not self.allow:
            raise ScopeViolation(
                "Active operations require a scope allowlist. Provide --scope <file.yml> "
                "listing only targets you are authorized to test."
            )
        if not self.is_allowed(host):
            raise ScopeViolation(f"'{host}' is not covered by the scope allowlist; refusing active operation.")


@dataclass
class Settings:
    """Runtime settings shared across a run."""

    cache_dir: str = ".cache"
    min_interval: float = 1.0
    scope: ScopeGuard = field(default_factory=ScopeGuard)
    allow_active: bool = False  # active liveness stays off unless explicitly enabled (M6)
