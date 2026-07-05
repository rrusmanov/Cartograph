"""Tests for graph analytics: centrality, clusters, takeover, diff."""

from __future__ import annotations

from cartograph.analysis import (
    centrality_ranking,
    diff_graphs,
    shared_infrastructure_clusters,
    takeover_candidates,
)
from cartograph.graph.model import AssetGraph, Edge, EdgeType, Node, NodeType


def _sub(g: AssetGraph, value: str, **attrs: object) -> Node:
    n = Node(type=NodeType.SUBDOMAIN, value=value, attrs=dict(attrs))
    g.add_node(n)
    return n


def test_centrality_ranks_hub_first() -> None:
    g = AssetGraph()
    hub = _sub(g, "hub.example.com")
    for i in range(4):
        leaf = _sub(g, f"leaf{i}.example.com")
        g.add_edge(Edge(src=hub.id, dst=leaf.id, type=EdgeType.RESOLVES_TO))
    ranking = centrality_ranking(g, top=3)
    assert ranking[0].value == "hub.example.com"


def test_clusters_group_hosts_sharing_a_certificate() -> None:
    g = AssetGraph()
    a = _sub(g, "a.example.com")
    b = _sub(g, "b.example.com")
    cert = Node(type=NodeType.CERTIFICATE, value="crtsh:1")
    g.add_node(cert)
    g.add_edge(Edge(src=a.id, dst=cert.id, type=EdgeType.SHARES_CERT))
    g.add_edge(Edge(src=b.id, dst=cert.id, type=EdgeType.SHARES_CERT))

    clusters = shared_infrastructure_clusters(g)
    assert len(clusters) == 1
    assert clusters[0].hosts == ["a.example.com", "b.example.com"]
    assert "crtsh:1" in clusters[0].linked_via


def test_clusters_ignore_singletons() -> None:
    g = AssetGraph()
    a = _sub(g, "a.example.com")
    cert = Node(type=NodeType.CERTIFICATE, value="crtsh:1")
    g.add_node(cert)
    g.add_edge(Edge(src=a.id, dst=cert.id, type=EdgeType.SHARES_CERT))
    assert shared_infrastructure_clusters(g) == []


def test_takeover_flags_fingerprinted_cname() -> None:
    g = AssetGraph()
    _sub(g, "app.example.com", external_cnames=["thing.herokuapp.com"])
    candidates = takeover_candidates(g)
    assert len(candidates) == 1
    assert candidates[0].provider == "heroku"
    assert candidates[0].host == "app.example.com"


def test_takeover_flags_dangling_cname() -> None:
    g = AssetGraph()
    _sub(g, "old.example.com", external_cnames=["gone.example.net"])
    live = _sub(g, "www.example.com")
    ip = Node(type=NodeType.IP, value="1.2.3.4")
    g.add_node(ip)
    g.add_edge(Edge(src=live.id, dst=ip.id, type=EdgeType.RESOLVES_TO))
    candidates = takeover_candidates(g)
    assert any(c.provider == "dangling" and c.host == "old.example.com" for c in candidates)


def test_diff_reports_added_and_removed() -> None:
    old = AssetGraph()
    _sub(old, "a.example.com")
    new = AssetGraph()
    _sub(new, "a.example.com")
    _sub(new, "b.example.com")

    d = diff_graphs(old, new)
    assert "subdomain:b.example.com" in d.added_nodes
    assert d.removed_nodes == []
    assert not d.is_empty


def test_diff_empty_when_identical() -> None:
    g1 = AssetGraph()
    _sub(g1, "a.example.com")
    g2 = AssetGraph()
    _sub(g2, "a.example.com")
    assert diff_graphs(g1, g2).is_empty
