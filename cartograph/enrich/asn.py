"""Map each IP to its origin ASN via RIPEstat, adding ``asn`` nodes and ``part_of_asn`` edges.

Grouping IPs by ASN shows which assets share a network/provider, and flags hosts sitting outside the
org's main ASN. RIPEstat (stat.ripe.net) is public and key-free; the base URL is configurable.
"""

from __future__ import annotations

import logging
from typing import Any

from cartograph.enrich.base import Enricher, EnrichStats
from cartograph.graph.model import AssetGraph, Edge, EdgeType, Node, NodeType

logger = logging.getLogger("cartograph")

RIPESTAT_URL = "https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"


class AsnEnricher(Enricher):
    """Map discovered IPs to their origin ASN using RIPEstat."""

    name = "asn"

    def __init__(self, *, base_url: str = RIPESTAT_URL, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.base_url = base_url

    async def enrich(self, graph: AssetGraph) -> EnrichStats:
        ips = sorted({n.value for n in graph.nodes_by_type(NodeType.IP)})[: self.max_targets]

        nodes_before, edges_before = len(graph), len(graph.edges())
        for ip in ips:
            try:
                payload = await self._query(ip)
            except Exception as exc:  # noqa: BLE001 - skip one IP, keep enriching the rest
                logger.warning(
                    "asn lookup failed for %s: %s: %s", ip, type(exc).__name__, exc
                )
                continue
            info = self._parse(payload)
            if info is not None:
                self._apply(graph, ip, info)
        return EnrichStats(
            nodes_added=len(graph) - nodes_before,
            edges_added=len(graph.edges()) - edges_before,
        )

    async def _query(self, ip: str) -> Any:
        url = self.base_url.format(ip=ip)
        return await self.get_json(url, cache_key=f"asn:{ip}", allow_status=(404, 429))

    @staticmethod
    def _parse(payload: Any) -> dict[str, Any] | None:
        """Extract origin ASN + holder + prefix from a RIPEstat prefix-overview response."""
        if not isinstance(payload, dict):
            return None
        data = payload.get("data")
        if not isinstance(data, dict):
            return None
        asns = data.get("asns")
        if not isinstance(asns, list) or not asns:
            return None
        first = asns[0]
        if not isinstance(first, dict) or first.get("asn") is None:
            return None
        return {
            "asn": first.get("asn"),
            "holder": first.get("holder"),
            "prefix": data.get("resource"),
        }

    def _apply(self, graph: AssetGraph, ip: str, info: dict[str, Any]) -> None:
        asn_node = Node(
            type=NodeType.ASN,
            value=f"AS{info['asn']}",
            sources={self.name},
            attrs={"holder": info.get("holder")},
        )
        graph.add_node(asn_node)
        ip_id = Node(type=NodeType.IP, value=ip).id
        try:
            graph.add_edge(
                Edge(
                    src=ip_id,
                    dst=asn_node.id,
                    type=EdgeType.PART_OF_ASN,
                    sources={self.name},
                    attrs={"prefix": info.get("prefix")},
                )
            )
        except KeyError:
            pass
