"""Tests for the Wayback (Internet Archive) collector."""

from __future__ import annotations

from pathlib import Path

from cartograph.cache import ResponseCache
from cartograph.collectors.wayback import WaybackCollector
from cartograph.graph.model import EdgeType, NodeType

CDX_ROWS = [
    ["original"],  # header
    ["http://a.example.com/login"],
    ["https://example.com/"],
    ["http://a.example.com/login"],  # duplicate -> collapsed
    ["http://evil.test/phish"],      # out of scope
]


def _collector(tmp_path: Path) -> WaybackCollector:
    return WaybackCollector(cache=ResponseCache(tmp_path / "cache"))


def test_parse_creates_endpoints_and_hosts(tmp_path: Path) -> None:
    result = _collector(tmp_path).parse("example.com", CDX_ROWS)
    endpoints = {n.value for n in result.nodes if n.type is NodeType.ENDPOINT}
    assert "http://a.example.com/login" in endpoints
    assert "https://example.com/" in endpoints
    hosts = {n.value for n in result.nodes if n.type in (NodeType.DOMAIN, NodeType.SUBDOMAIN)}
    assert {"a.example.com", "example.com"} <= hosts


def test_parse_dedupes_endpoints(tmp_path: Path) -> None:
    result = _collector(tmp_path).parse("example.com", CDX_ROWS)
    endpoints = [n for n in result.nodes if n.type is NodeType.ENDPOINT]
    assert len(endpoints) == 2  # duplicate login collapsed


def test_parse_filters_out_of_scope(tmp_path: Path) -> None:
    result = _collector(tmp_path).parse("example.com", CDX_ROWS)
    values = {n.value for n in result.nodes}
    assert not any("evil.test" in v for v in values)


def test_parse_emits_has_endpoint_edges(tmp_path: Path) -> None:
    result = _collector(tmp_path).parse("example.com", CDX_ROWS)
    assert all(e.type is EdgeType.HAS_ENDPOINT for e in result.edges)
    assert len(result.edges) == 2


def test_parse_handles_empty(tmp_path: Path) -> None:
    assert _collector(tmp_path).parse("example.com", [["original"]]).nodes == []
