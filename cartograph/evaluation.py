"""Metrics for the M4 experiment: connectivity, precision@k/lift, source ablation.

Kept in the tested package since the whitepaper reports these numbers. Note that the "interesting"
label uses the same signals the scorer aggregates, so precision@k is a behavioral check, not
prediction of an independent label – see the whitepaper's validity section.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from cartograph.analysis.clusters import shared_infrastructure_clusters
from cartograph.analysis.takeover import takeover_candidates
from cartograph.graph.model import AssetGraph, Node, NodeType
from cartograph.scoring.features import (
    ScoringContext,
    build_context,
    f_nonprod_naming,
    f_off_primary_asn,
    f_takeover_cname,
    f_tls_expiry,
)

_HOST_TYPES = (NodeType.DOMAIN, NodeType.SUBDOMAIN)


def host_ids(graph: AssetGraph) -> list[str]:
    """All host (domain/subdomain) node ids."""
    return [n.id for n in graph.nodes() if n.type in _HOST_TYPES]


def risk_signal_count(node: Node, graph: AssetGraph, ctx: ScoringContext) -> int:
    """Number of distinct, objective risk signals a host carries.

    Signals (each documented and passive): no current valid TLS (newest cert expired), a
    takeover-prone / dangling CNAME, non-production naming, and hosting outside the dominant ASN.
    """
    count = 0
    if f_tls_expiry(node, graph, ctx).value >= 1.0:
        count += 1
    if f_takeover_cname(node, graph, ctx).value > 0:
        count += 1
    if f_nonprod_naming(node, graph, ctx).value > 0:
        count += 1
    if f_off_primary_asn(node, graph, ctx).value > 0:
        count += 1
    return count


def interesting_host_ids(
    graph: AssetGraph, *, now: datetime | None = None, min_signals: int = 2
) -> set[str]:
    """Hosts worth urgent triage: those carrying ``min_signals`` or more distinct risk signals.

    A single signal (notably expired TLS) is near-universal on a target with a long Certificate
    Transparency history – passive recon surfaces many long-dead subdomains. Requiring several
    coinciding signals yields a discriminating "look here first" label.
    """
    ctx = build_context(graph, now=now)
    return {
        node.id
        for node in graph.nodes()
        if node.type in _HOST_TYPES and risk_signal_count(node, graph, ctx) >= min_signals
    }


def precision_at_k(ranked_ids: list[str], interesting: set[str], k: int) -> float:
    """Fraction of the top-``k`` ranked hosts that are interesting."""
    top = ranked_ids[:k]
    if not top:
        return 0.0
    return sum(1 for i in top if i in interesting) / len(top)


def base_rate(interesting: set[str], all_hosts: list[str]) -> float:
    """The fraction of all hosts that are interesting (the random-ordering expectation)."""
    return len(interesting) / len(all_hosts) if all_hosts else 0.0


def lift_at_k(ranked_ids: list[str], interesting: set[str], all_hosts: list[str], k: int) -> float:
    """precision@k divided by the base rate – how much better than random the ordering does."""
    br = base_rate(interesting, all_hosts)
    if br == 0.0:
        return 0.0
    return precision_at_k(ranked_ids, interesting, k) / br


def all_sources(graph: AssetGraph) -> list[str]:
    """Every provenance tag present on nodes or edges."""
    seen: set[str] = set()
    for n in graph.nodes():
        seen |= n.sources
    for e in graph.edges():
        seen |= e.sources
    return sorted(seen)


def source_ablation(graph: AssetGraph, source: str) -> dict[str, int]:
    """What survives if ``source`` is removed – its *unique* contribution.

    Computed offline from provenance: a node/edge survives iff some *other* source also asserted it.
    This measures each source's marginal value without re-running any collection.
    """
    hosts = [n for n in graph.nodes() if n.type in _HOST_TYPES]
    hosts_after = [n for n in hosts if n.sources - {source}]
    edges = graph.edges()
    edges_after = [e for e in edges if e.sources - {source}]
    return {
        "hosts_before": len(hosts),
        "hosts_after": len(hosts_after),
        "hosts_lost": len(hosts) - len(hosts_after),
        "edges_before": len(edges),
        "edges_after": len(edges_after),
        "edges_lost": len(edges) - len(edges_after),
    }


def connectivity_report(graph: AssetGraph) -> dict[str, object]:
    """Structure a flat host list cannot express: typed edges, clusters, takeover candidates."""
    edge_counts: Counter[str] = Counter(e.type.value for e in graph.edges())
    return {
        "hosts": len(host_ids(graph)),
        "total_nodes": len(graph),
        "typed_edges": dict(sorted(edge_counts.items())),
        "total_edges": sum(edge_counts.values()),
        "shared_cert_clusters": len(shared_infrastructure_clusters(graph)),
        "takeover_candidates": len(takeover_candidates(graph)),
    }
