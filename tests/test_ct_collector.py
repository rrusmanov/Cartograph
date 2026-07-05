"""Tests for the Certificate Transparency collector (no live network)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import respx

from cartograph.cache import ResponseCache
from cartograph.collectors.ct import CertificateTransparencyCollector
from cartograph.graph.model import EdgeType, NodeType

SAMPLE_ROWS: list[dict[str, Any]] = [
    {
        "id": 1001,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com",
        "not_before": "2024-01-01T00:00:00",
        "not_after": "2024-04-01T00:00:00",
    },
    {
        "id": 1002,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "*.dev.example.com",
        "name_value": "*.dev.example.com",
        "not_before": "2024-02-01T00:00:00",
        "not_after": "2024-05-01T00:00:00",
    },
    {
        # noise: a lookalike domain that must be filtered out of scope
        "id": 1003,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "example.com.evil.test",
        "name_value": "example.com.evil.test\nadmin@example.com",
        "not_before": "2024-02-01T00:00:00",
        "not_after": "2024-05-01T00:00:00",
    },
]


def _collector(tmp_path: Path) -> CertificateTransparencyCollector:
    return CertificateTransparencyCollector(cache=ResponseCache(tmp_path / "cache"))


def test_parse_discovers_subdomains(tmp_path: Path) -> None:
    result = _collector(tmp_path).parse("example.com", SAMPLE_ROWS)
    values = {n.value for n in result.nodes}
    assert "example.com" in values
    assert "www.example.com" in values
    assert "*.dev.example.com" in values


def test_parse_filters_out_of_scope_and_emails(tmp_path: Path) -> None:
    result = _collector(tmp_path).parse("example.com", SAMPLE_ROWS)
    values = {n.value for n in result.nodes}
    assert "example.com.evil.test" not in values  # lookalike, not a real subdomain
    assert "admin@example.com" not in values  # email SAN dropped


def test_parse_flags_wildcard_certificate(tmp_path: Path) -> None:
    result = _collector(tmp_path).parse("example.com", SAMPLE_ROWS)
    certs = [n for n in result.nodes if n.type is NodeType.CERTIFICATE]
    wildcard_certs = [c for c in certs if c.attrs.get("is_wildcard")]
    assert len(wildcard_certs) == 1


def test_out_of_scope_certificate_is_not_added(tmp_path: Path) -> None:
    # rows 1001 + 1002 are in scope; row 1003 covers only a lookalike + email -> must be skipped
    result = _collector(tmp_path).parse("example.com", SAMPLE_ROWS)
    certs = [n for n in result.nodes if n.type is NodeType.CERTIFICATE]
    assert {c.value for c in certs} == {"crtsh:1001", "crtsh:1002"}


def test_parse_emits_expected_edge_types(tmp_path: Path) -> None:
    result = _collector(tmp_path).parse("example.com", SAMPLE_ROWS)
    etypes = {e.type for e in result.edges}
    assert EdgeType.HAS_SUBDOMAIN in etypes
    assert EdgeType.SHARES_CERT in etypes


def test_root_domain_typed_as_domain_not_subdomain(tmp_path: Path) -> None:
    result = _collector(tmp_path).parse("example.com", SAMPLE_ROWS)
    root = next(n for n in result.nodes if n.value == "example.com")
    assert root.type is NodeType.DOMAIN


@respx.mock
async def test_collect_uses_http_then_cache(tmp_path: Path) -> None:
    route = respx.get(host="crt.sh").mock(return_value=httpx.Response(200, json=SAMPLE_ROWS))
    collector = _collector(tmp_path)
    try:
        first = await collector.collect("example.com")
        second = await collector.collect("example.com")  # should hit cache, not network
    finally:
        await collector.aclose()

    assert route.call_count == 1  # second call served from cache
    assert {n.value for n in first.nodes} == {n.value for n in second.nodes}


@respx.mock
async def test_collect_handles_empty_result(tmp_path: Path) -> None:
    respx.get(host="crt.sh").mock(return_value=httpx.Response(200, json=[]))
    collector = _collector(tmp_path)
    try:
        result = await collector.collect("nothing.example")
    finally:
        await collector.aclose()
    # only the root domain node, no crash on empty CT data
    assert [n.value for n in result.nodes] == ["nothing.example"]
