"""Tests for the scope-guard – the safety core that gates active operations."""

from __future__ import annotations

from pathlib import Path

import pytest

from cartograph.config import ScopeGuard, ScopeViolation


def test_empty_allowlist_refuses_everything() -> None:
    guard = ScopeGuard()
    assert not guard.is_allowed("example.com")
    with pytest.raises(ScopeViolation):
        guard.enforce("example.com")


def test_apex_and_subdomains_allowed() -> None:
    guard = ScopeGuard(allow={"example.com"})
    assert guard.is_allowed("example.com")
    assert guard.is_allowed("api.dev.example.com")
    guard.enforce("api.example.com")  # must not raise


def test_lookalike_is_not_in_scope() -> None:
    guard = ScopeGuard(allow={"example.com"})
    assert not guard.is_allowed("example.com.evil.test")
    assert not guard.is_allowed("notexample.com")
    with pytest.raises(ScopeViolation):
        guard.enforce("example.com.evil.test")


def test_from_file_parses_allowlist(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.yml"
    scope_file.write_text("allow:\n  - Example.com\n  - test.org.\n", encoding="utf-8")
    guard = ScopeGuard.from_file(scope_file)
    assert guard.allow == {"example.com", "test.org"}
    assert guard.is_allowed("api.example.com")
    assert guard.is_allowed("test.org")
