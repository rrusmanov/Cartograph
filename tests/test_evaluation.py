"""Tests for the evaluation metrics used in the M4 experiment."""

from __future__ import annotations

from datetime import datetime

from cartograph.evaluation import (
    all_sources,
    base_rate,
    connectivity_report,
    host_ids,
    interesting_host_ids,
    lift_at_k,
    precision_at_k,
    source_ablation,
)
from cartograph.graph.model import AssetGraph, Edge, EdgeType, Node, NodeType

NOW = datetime(2025, 1, 1)


def _expired_cert(g: AssetGraph, host: Node, tag: str) -> None:
    cert = Node(type=NodeType.CERTIFICATE, value=f"crtsh:{tag}", attrs={"not_after": "2020-01-01T00:00:00"})
    g.add_node(cert)
    g.add_edge(Edge(src=host.id, dst=cert.id, type=EdgeType.SHARES_CERT))


def _graph_with_signals() -> AssetGraph:
    g = AssetGraph()
    # 2 signals: non-prod naming + expired TLS  -> interesting
    staging = Node(type=NodeType.SUBDOMAIN, value="staging.example.com")
    g.add_node(staging)
    _expired_cert(g, staging, "staging")
    # 2 signals: non-prod naming + takeover CNAME -> interesting
    g.add_node(
        Node(type=NodeType.SUBDOMAIN, value="dev.example.com", attrs={"external_cnames": ["x.herokuapp.com"]})
    )
    # 1 signal: expired TLS only -> NOT interesting
    cdn = Node(type=NodeType.SUBDOMAIN, value="cdn.example.com")
    g.add_node(cdn)
    _expired_cert(g, cdn, "cdn")
    # clean host -> NOT interesting
    g.add_node(Node(type=NodeType.SUBDOMAIN, value="www.example.com"))
    return g


def test_interesting_requires_two_signals() -> None:
    g = _graph_with_signals()
    interesting = interesting_host_ids(g, now=NOW)
    assert "subdomain:staging.example.com" in interesting  # nonprod + expired TLS
    assert "subdomain:dev.example.com" in interesting       # nonprod + takeover
    assert "subdomain:cdn.example.com" not in interesting   # only expired TLS
    assert "subdomain:www.example.com" not in interesting   # clean


def test_base_rate() -> None:
    g = _graph_with_signals()
    hosts = host_ids(g)
    interesting = interesting_host_ids(g, now=NOW)
    assert base_rate(interesting, hosts) == 2 / 4


def test_precision_at_k_perfect_ranking() -> None:
    interesting = {"a", "b"}
    ranked = ["a", "b", "c", "d"]
    assert precision_at_k(ranked, interesting, 2) == 1.0
    assert precision_at_k(ranked, interesting, 4) == 0.5


def test_lift_is_precision_over_base_rate() -> None:
    interesting = {"a", "b"}
    all_hosts = ["a", "b", "c", "d"]  # base rate 0.5
    ranked = ["a", "b", "c", "d"]     # precision@2 = 1.0
    assert lift_at_k(ranked, interesting, all_hosts, 2) == 2.0


def test_connectivity_report_counts_structure() -> None:
    g = _graph_with_signals()
    report = connectivity_report(g)
    assert report["hosts"] == 4
    assert "shares_cert" in report["typed_edges"]  # type: ignore[operator]
    assert report["takeover_candidates"] >= 1


def test_source_ablation_measures_unique_contribution() -> None:
    g = AssetGraph()
    # host asserted only by CT -> removing CT loses it
    g.add_node(Node(type=NodeType.SUBDOMAIN, value="only-ct.example.com", sources={"ct"}))
    # host asserted by CT and DoH -> survives CT removal
    g.add_node(Node(type=NodeType.SUBDOMAIN, value="both.example.com", sources={"ct", "doh"}))

    ablate = source_ablation(g, "ct")
    assert ablate["hosts_before"] == 2
    assert ablate["hosts_after"] == 1  # only 'both' survives
    assert ablate["hosts_lost"] == 1
    assert "ct" in all_sources(g)
