"""Tests for graph enrichers (passive DNS, ASN) with mocked HTTP."""

from __future__ import annotations

from pathlib import Path

import httpx
import respx

from cartograph.cache import ResponseCache
from cartograph.enrich.asn import AsnEnricher
from cartograph.enrich.doh import DohResolverEnricher
from cartograph.enrich.passive_dns import PassiveDnsEnricher
from cartograph.graph.model import AssetGraph, EdgeType, Node, NodeType

DOH_PAYLOAD = {
    "Status": 0,
    "Answer": [
        {"name": "www.example.com", "type": 5, "data": "cdn.example.com."},
        {"name": "cdn.example.com", "type": 1, "data": "93.184.216.34"},
    ],
}

PDNS_PAYLOAD = {
    "data": [
        {"rrtype": "a", "answer": "93.184.216.34"},
        {"rrtype": "cname", "answer": "cdn.example.com"},
    ]
}

RIPESTAT_PAYLOAD = {
    "status": "ok",
    "data": {
        "resource": "93.184.216.0/24",
        "asns": [{"asn": 15133, "holder": "EDGECAST, US"}],
    },
}


def _seed_hosts() -> AssetGraph:
    g = AssetGraph()
    g.add_node(Node(type=NodeType.DOMAIN, value="example.com", sources={"ct"}))
    g.add_node(Node(type=NodeType.SUBDOMAIN, value="www.example.com", sources={"ct"}))
    return g


@respx.mock
async def test_passive_dns_adds_ip_and_resolves_edges(tmp_path: Path) -> None:
    respx.get(host="api.mnemonic.no").mock(
        return_value=httpx.Response(200, json=PDNS_PAYLOAD)
    )
    graph = _seed_hosts()
    enricher = PassiveDnsEnricher(cache=ResponseCache(tmp_path / "c"), min_interval=0.0)
    try:
        stats = await enricher.enrich(graph)
    finally:
        await enricher.aclose()

    ips = {n.value for n in graph.nodes_by_type(NodeType.IP)}
    assert "93.184.216.34" in ips
    resolves = [e for e in graph.edges() if e.type is EdgeType.RESOLVES_TO]
    assert resolves  # host -> ip / host -> cname edges exist
    assert stats.nodes_added > 0


@respx.mock
async def test_passive_dns_respects_max_targets(tmp_path: Path) -> None:
    route = respx.get(host="api.mnemonic.no").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    graph = _seed_hosts()
    enricher = PassiveDnsEnricher(
        cache=ResponseCache(tmp_path / "c"), min_interval=0.0, max_targets=1
    )
    try:
        await enricher.enrich(graph)
    finally:
        await enricher.aclose()
    assert route.call_count == 1  # only one host queried despite two in the graph


@respx.mock
async def test_doh_resolver_adds_ip_and_marks_checked(tmp_path: Path) -> None:
    respx.get(host="cloudflare-dns.com").mock(
        return_value=httpx.Response(200, json=DOH_PAYLOAD)
    )
    graph = _seed_hosts()
    enricher = DohResolverEnricher(cache=ResponseCache(tmp_path / "c"), min_interval=0.0)
    try:
        stats = await enricher.enrich(graph)
    finally:
        await enricher.aclose()

    ips = {n.value for n in graph.nodes_by_type(NodeType.IP)}
    assert "93.184.216.34" in ips
    assert any(e.type is EdgeType.RESOLVES_TO for e in graph.edges())
    # in-scope CNAME target becomes a node; host is marked resolution_checked
    www = next(n for n in graph.nodes() if n.value == "www.example.com")
    assert www.attrs.get("resolution_checked") is True
    assert stats.nodes_added > 0


@respx.mock
async def test_asn_enricher_adds_asn_node_and_edge(tmp_path: Path) -> None:
    respx.get(host="stat.ripe.net").mock(
        return_value=httpx.Response(200, json=RIPESTAT_PAYLOAD)
    )
    graph = AssetGraph()
    graph.add_node(Node(type=NodeType.IP, value="93.184.216.34", sources={"pdns"}))
    enricher = AsnEnricher(cache=ResponseCache(tmp_path / "c"), min_interval=0.0)
    try:
        stats = await enricher.enrich(graph)
    finally:
        await enricher.aclose()

    asns = {n.value for n in graph.nodes_by_type(NodeType.ASN)}
    assert "AS15133" in asns
    assert any(e.type is EdgeType.PART_OF_ASN for e in graph.edges())
    assert stats.edges_added == 1


@respx.mock
async def test_asn_enricher_stores_holder_and_prefix(tmp_path: Path) -> None:
    respx.get(host="stat.ripe.net").mock(
        return_value=httpx.Response(200, json=RIPESTAT_PAYLOAD)
    )
    graph = AssetGraph()
    graph.add_node(Node(type=NodeType.IP, value="93.184.216.34"))
    enricher = AsnEnricher(cache=ResponseCache(tmp_path / "c"), min_interval=0.0)
    try:
        await enricher.enrich(graph)
    finally:
        await enricher.aclose()
    asn = graph.nodes_by_type(NodeType.ASN)[0]
    assert asn.attrs.get("holder") == "EDGECAST, US"
    edge = next(e for e in graph.edges() if e.type is EdgeType.PART_OF_ASN)
    assert edge.attrs.get("prefix") == "93.184.216.0/24"


@respx.mock
async def test_asn_enricher_handles_empty_payload(tmp_path: Path) -> None:
    respx.get(host="stat.ripe.net").mock(
        return_value=httpx.Response(200, json={"status": "ok", "data": {"asns": []}})
    )
    graph = AssetGraph()
    graph.add_node(Node(type=NodeType.IP, value="1.2.3.4"))
    enricher = AsnEnricher(cache=ResponseCache(tmp_path / "c"), min_interval=0.0)
    try:
        stats = await enricher.enrich(graph)
    finally:
        await enricher.aclose()
    assert graph.nodes_by_type(NodeType.ASN) == []
    assert stats.nodes_added == 0
