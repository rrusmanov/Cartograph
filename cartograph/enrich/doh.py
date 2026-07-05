"""Resolve hosts via DNS-over-HTTPS (Cloudflare by default).

Queries go to a public resolver, not the target, so this stays passive. Unlike passive DNS this is
current resolution, which is what reliably populates IP/ASN connectivity. Key-free.
"""

from __future__ import annotations

import logging
from typing import Any

from cartograph.enrich._resolution import DnsRecord, apply_dns_records, resolvable_hosts
from cartograph.enrich.base import Enricher, EnrichStats
from cartograph.graph.model import AssetGraph, NodeType

logger = logging.getLogger("cartograph")

CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query"
_DNS_JSON = {"Accept": "application/dns-json"}
# DNS record type numbers -> our rrtype names
_TYPE_MAP = {1: "a", 28: "aaaa", 5: "cname"}


class DohResolverEnricher(Enricher):
    """Resolve discovered hosts via a public DNS-over-HTTPS endpoint."""

    name = "doh"

    def __init__(self, *, base_url: str = CLOUDFLARE_DOH, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.base_url = base_url

    async def enrich(self, graph: AssetGraph) -> EnrichStats:
        hosts = resolvable_hosts(graph, self.max_targets)
        scope_domains = tuple(n.value for n in graph.nodes_by_type(NodeType.DOMAIN))

        nodes_before, edges_before = len(graph), len(graph.edges())
        for host in hosts:
            records: list[DnsRecord] = []
            for qtype in ("A", "AAAA"):
                try:
                    payload = await self._query(host, qtype)
                except Exception as exc:  # noqa: BLE001 - skip, keep resolving the rest
                    logger.warning(
                        "doh lookup failed for %s/%s: %s: %s",
                        host,
                        qtype,
                        type(exc).__name__,
                        exc,
                    )
                    continue
                records.extend(self._records(payload))
            if records:
                apply_dns_records(graph, host, records, scope_domains, self.name)
        return EnrichStats(
            nodes_added=len(graph) - nodes_before,
            edges_added=len(graph.edges()) - edges_before,
        )

    async def _query(self, host: str, qtype: str) -> Any:
        url = f"{self.base_url}?name={host}&type={qtype}"
        return await self.get_json(url, cache_key=f"doh:{qtype}:{host}", allow_status=(400, 404), headers=_DNS_JSON)

    @staticmethod
    def _records(payload: Any) -> list[DnsRecord]:
        if not isinstance(payload, dict):
            return []
        answers = payload.get("Answer")
        if not isinstance(answers, list):
            return []
        records: list[DnsRecord] = []
        for ans in answers:
            if not isinstance(ans, dict):
                continue
            rrtype = _TYPE_MAP.get(int(ans.get("type", -1)))
            data = str(ans.get("data", ""))
            if rrtype and data:
                records.append(DnsRecord(rrtype=rrtype, answer=data))
        return records
