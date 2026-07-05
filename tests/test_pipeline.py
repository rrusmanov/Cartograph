"""End-to-end pipeline test with all sources mocked: integration + determinism."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import respx

from cartograph.graph.model import AssetGraph, EdgeType, NodeType
from cartograph.pipeline import (
    PipelineConfig,
    build_collectors,
    build_enrichers,
    run_pipeline,
)

CT_ROWS = [
    {
        "id": 1,
        "issuer_name": "CN=R3",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com",
    }
]
RDAP_PAYLOAD = {
    "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["org", {}, "text", "Example Org"]]],
        }
    ],
}
CDX_ROWS = [["original"], ["https://www.example.com/app"]]
DOH_PAYLOAD = {"Status": 0, "Answer": [{"name": "www.example.com", "type": 1, "data": "93.184.216.34"}]}
RIPESTAT_PAYLOAD = {
    "status": "ok",
    "data": {"resource": "93.184.216.0/24", "asns": [{"asn": 15133, "holder": "Edgecast"}]},
}


def _install_routes() -> None:
    respx.get(host="crt.sh").mock(return_value=httpx.Response(200, json=CT_ROWS))
    respx.get(host="rdap.org").mock(return_value=httpx.Response(200, json=RDAP_PAYLOAD))
    respx.get(host="web.archive.org").mock(return_value=httpx.Response(200, json=CDX_ROWS))
    respx.get(host="cloudflare-dns.com").mock(return_value=httpx.Response(200, json=DOH_PAYLOAD))
    respx.get(host="stat.ripe.net").mock(return_value=httpx.Response(200, json=RIPESTAT_PAYLOAD))


async def _run(cache_dir: Path) -> AssetGraph:
    config = PipelineConfig(cache_dir=str(cache_dir), min_interval=0.0)
    collectors = build_collectors(config)
    enrichers = build_enrichers(config)
    try:
        return await run_pipeline("example.com", collectors, enrichers, config)
    finally:
        await asyncio.gather(*(f.aclose() for f in [*collectors, *enrichers]))


@respx.mock
async def test_pipeline_builds_connected_graph(tmp_path: Path) -> None:
    _install_routes()
    graph = await _run(tmp_path / "cache")

    types = {n.type for n in graph.nodes()}
    # every source contributed a node type
    assert {NodeType.DOMAIN, NodeType.SUBDOMAIN, NodeType.ORG, NodeType.ENDPOINT,
            NodeType.IP, NodeType.ASN} <= types

    etypes = {e.type for e in graph.edges()}
    # connectivity spanning collectors + enrichers
    assert {EdgeType.HAS_SUBDOMAIN, EdgeType.REGISTERED_BY, EdgeType.HAS_ENDPOINT,
            EdgeType.RESOLVES_TO, EdgeType.PART_OF_ASN} <= etypes


@respx.mock
async def test_pipeline_is_deterministic(tmp_path: Path) -> None:
    _install_routes()
    g1 = await _run(tmp_path / "c1")
    g2 = await _run(tmp_path / "c2")
    assert g1.to_dict() == g2.to_dict()
