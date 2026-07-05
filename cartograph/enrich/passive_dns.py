"""Passive DNS enrichment via Mnemonic PassiveDNS.

Looks up historically observed records per host and adds IPs / resolves_to edges. Mnemonic's free
tier now returns HTTP 402, so the default pipeline uses the DoH resolver instead.
"""

from __future__ import annotations

import logging
from typing import Any

from cartograph.enrich._resolution import DnsRecord, apply_dns_records, resolvable_hosts
from cartograph.enrich.base import Enricher, EnrichStats
from cartograph.graph.model import AssetGraph, NodeType

logger = logging.getLogger("cartograph")

MNEMONIC_URL = "https://api.mnemonic.no/pdns/v3/{query}"


class PassiveDnsEnricher(Enricher):
    """Resolve discovered hosts to IPs/CNAMEs using a passive-DNS database."""

    name = "pdns"

    def __init__(self, *, base_url: str = MNEMONIC_URL, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.base_url = base_url

    async def enrich(self, graph: AssetGraph) -> EnrichStats:
        hosts = resolvable_hosts(graph, self.max_targets)
        scope_domains = tuple(n.value for n in graph.nodes_by_type(NodeType.DOMAIN))

        nodes_before, edges_before = len(graph), len(graph.edges())
        for host in hosts:
            try:
                payload = await self._query(host)
            except Exception as exc:  # noqa: BLE001 - skip one host, keep enriching the rest
                logger.warning("pdns lookup failed for %s: %s: %s", host, type(exc).__name__, exc)
                continue
            apply_dns_records(graph, host, self._records(payload), scope_domains, self.name)
        return EnrichStats(
            nodes_added=len(graph) - nodes_before,
            edges_added=len(graph.edges()) - edges_before,
        )

    async def _query(self, host: str) -> Any:
        url = self.base_url.format(query=host)
        return await self.get_json(url, cache_key=f"pdns:{host}", allow_status=(404, 500))

    @staticmethod
    def _records(payload: Any) -> list[DnsRecord]:
        if not payload:
            return []
        data = payload.get("data") if isinstance(payload, dict) else payload
        if not isinstance(data, list):
            return []
        records: list[DnsRecord] = []
        for rec in data:
            if isinstance(rec, dict):
                records.append(DnsRecord(rrtype=str(rec.get("rrtype", "")), answer=str(rec.get("answer", ""))))
        return records
