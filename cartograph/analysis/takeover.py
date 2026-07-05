"""Passive subdomain-takeover candidates.

Flags hosts whose CNAME points at a takeover-prone provider, or is dangling (CNAME on record but no
IP). A heuristic for manual, authorized verification – it never touches the target.
"""

from __future__ import annotations

from dataclasses import dataclass

from cartograph.fingerprints import match_fingerprint
from cartograph.graph.model import AssetGraph, EdgeType, NodeType


@dataclass
class TakeoverCandidate:
    host: str
    cname: str
    provider: str  # fingerprint label, or "dangling"
    reason: str


def takeover_candidates(graph: AssetGraph) -> list[TakeoverCandidate]:
    """Return takeover candidates (passive heuristic), sorted for deterministic output."""
    hosts_with_ip: set[str] = set()
    pdns_ran = False
    nodes = {n.id: n for n in graph.nodes()}
    for edge in graph.edges():
        if edge.type is EdgeType.RESOLVES_TO:
            pdns_ran = True
            dst = nodes.get(edge.dst)
            if dst is not None and dst.type is NodeType.IP:
                hosts_with_ip.add(edge.src)

    candidates: list[TakeoverCandidate] = []
    for node in graph.nodes():
        if node.type not in (NodeType.DOMAIN, NodeType.SUBDOMAIN):
            continue
        externals = [str(c) for c in node.attrs.get("external_cnames", [])]
        for cname in externals:
            provider = match_fingerprint(cname)
            if provider is not None:
                candidates.append(
                    TakeoverCandidate(
                        host=node.value,
                        cname=cname,
                        provider=provider,
                        reason=f"CNAME to takeover-prone provider ({provider}) – verify if claimed",
                    )
                )
            elif pdns_ran and node.id not in hosts_with_ip:
                candidates.append(
                    TakeoverCandidate(
                        host=node.value,
                        cname=cname,
                        provider="dangling",
                        reason="CNAME present but host resolves to no IP – possible dangling record",
                    )
                )

    candidates.sort(key=lambda c: (c.host, c.cname))
    return candidates
