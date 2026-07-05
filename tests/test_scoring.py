"""Unit tests for exposure features and the aggregator."""

from __future__ import annotations

from datetime import datetime

from cartograph.graph.model import AssetGraph, Edge, EdgeType, Node, NodeType
from cartograph.scoring.features import (
    build_context,
    f_concentration,
    f_nonprod_naming,
    f_off_primary_asn,
    f_orphan_stale,
    f_takeover_cname,
    f_tls_expiry,
    f_wildcard,
)
from cartograph.scoring.model import score_graph, score_node

NOW = datetime(2025, 1, 1)


def _host(g: AssetGraph, value: str, **attrs: object) -> Node:
    n = Node(type=NodeType.SUBDOMAIN, value=value, attrs=dict(attrs))
    g.add_node(n)
    return n


# --- F1 TLS expiry -------------------------------------------------------


def test_f1_expired_cert_scores_max() -> None:
    g = AssetGraph()
    host = _host(g, "a.example.com")
    cert = Node(type=NodeType.CERTIFICATE, value="crtsh:1", attrs={"not_after": "2020-01-01T00:00:00"})
    g.add_node(cert)
    g.add_edge(Edge(src=host.id, dst=cert.id, type=EdgeType.SHARES_CERT))
    ctx = build_context(g, now=NOW)
    assert f_tls_expiry(host, g, ctx).value == 1.0


def test_f1_valid_cert_scores_zero() -> None:
    g = AssetGraph()
    host = _host(g, "a.example.com")
    cert = Node(type=NodeType.CERTIFICATE, value="crtsh:1", attrs={"not_after": "2030-01-01T00:00:00"})
    g.add_node(cert)
    g.add_edge(Edge(src=host.id, dst=cert.id, type=EdgeType.SHARES_CERT))
    ctx = build_context(g, now=NOW)
    assert f_tls_expiry(host, g, ctx).value == 0.0


def test_f1_expired_plus_current_cert_scores_zero() -> None:
    # a host with an old expired cert AND a currently-valid one is NOT flagged (judged on newest)
    g = AssetGraph()
    host = _host(g, "a.example.com")
    old = Node(type=NodeType.CERTIFICATE, value="crtsh:old", attrs={"not_after": "2019-01-01T00:00:00"})
    cur = Node(type=NodeType.CERTIFICATE, value="crtsh:cur", attrs={"not_after": "2030-01-01T00:00:00"})
    g.add_node(old)
    g.add_node(cur)
    g.add_edge(Edge(src=host.id, dst=old.id, type=EdgeType.SHARES_CERT))
    g.add_edge(Edge(src=host.id, dst=cur.id, type=EdgeType.SHARES_CERT))
    ctx = build_context(g, now=NOW)
    assert f_tls_expiry(host, g, ctx).value == 0.0


# --- F2 wildcard ---------------------------------------------------------


def test_f2_wildcard_host_entry() -> None:
    g = AssetGraph()
    host = _host(g, "*.example.com", is_wildcard=True)
    ctx = build_context(g, now=NOW)
    assert f_wildcard(host, g, ctx).value == 1.0


def test_f2_covered_by_wildcard_cert() -> None:
    g = AssetGraph()
    host = _host(g, "a.example.com")
    cert = Node(type=NodeType.CERTIFICATE, value="crtsh:1", attrs={"is_wildcard": True})
    g.add_node(cert)
    g.add_edge(Edge(src=host.id, dst=cert.id, type=EdgeType.SHARES_CERT))
    ctx = build_context(g, now=NOW)
    assert f_wildcard(host, g, ctx).value == 0.5


# --- F3 takeover ---------------------------------------------------------


def test_f3_takeover_prone_cname() -> None:
    g = AssetGraph()
    host = _host(g, "a.example.com", external_cnames=["myapp.herokuapp.com"])
    ctx = build_context(g, now=NOW)
    fs = f_takeover_cname(host, g, ctx)
    assert fs.value == 1.0
    assert "heroku" in fs.detail


def test_f3_dangling_cname_without_a_record() -> None:
    g = AssetGraph()
    host = _host(g, "a.example.com", external_cnames=["gone.example.net"])
    # pdns ran (some other host resolves) but this host has no IP
    other = _host(g, "b.example.com")
    ip = Node(type=NodeType.IP, value="1.2.3.4")
    g.add_node(ip)
    g.add_edge(Edge(src=other.id, dst=ip.id, type=EdgeType.RESOLVES_TO))
    ctx = build_context(g, now=NOW)
    assert f_takeover_cname(host, g, ctx).value == 0.6


# --- F5 non-prod naming --------------------------------------------------


def test_f5_nonprod_token() -> None:
    g = AssetGraph()
    host = _host(g, "staging.example.com")
    ctx = build_context(g, now=NOW)
    assert f_nonprod_naming(host, g, ctx).value == 1.0


def test_f5_prod_host_scores_zero() -> None:
    g = AssetGraph()
    host = _host(g, "www.example.com")
    ctx = build_context(g, now=NOW)
    assert f_nonprod_naming(host, g, ctx).value == 0.0


# --- F6 orphan / stale ---------------------------------------------------


def test_f6_orphan_when_checked_but_host_never_resolves() -> None:
    g = AssetGraph()
    orphan = _host(g, "old.example.com", resolution_checked=True)  # checked, found nothing
    live = _host(g, "www.example.com", resolution_checked=True)
    ip = Node(type=NodeType.IP, value="1.2.3.4")
    g.add_node(ip)
    g.add_edge(Edge(src=live.id, dst=ip.id, type=EdgeType.RESOLVES_TO))
    ctx = build_context(g, now=NOW)
    assert f_orphan_stale(orphan, g, ctx).value == 0.6
    assert f_orphan_stale(live, g, ctx).value == 0.0


def test_f6_no_signal_when_host_not_checked() -> None:
    g = AssetGraph()
    # host was never successfully checked by passive DNS (e.g. lookup failed) -> no orphan signal
    host = _host(g, "old.example.com")
    ctx = build_context(g, now=NOW)
    assert f_orphan_stale(host, g, ctx).value == 0.0


# --- F7 off-primary ASN --------------------------------------------------


def test_f7_off_primary_asn() -> None:
    g = AssetGraph()
    host = _host(g, "a.example.com")
    other = _host(g, "b.example.com")
    ip1 = Node(type=NodeType.IP, value="1.1.1.1")
    ip2 = Node(type=NodeType.IP, value="2.2.2.2")
    ip3 = Node(type=NodeType.IP, value="3.3.3.3")
    for ip in (ip1, ip2, ip3):
        g.add_node(ip)
    asn_a = Node(type=NodeType.ASN, value="AS100")
    asn_b = Node(type=NodeType.ASN, value="AS200")
    g.add_node(asn_a)
    g.add_node(asn_b)
    # make AS100 dominant (2 IPs) vs AS200 (1 IP)
    g.add_edge(Edge(src=other.id, dst=ip3.id, type=EdgeType.RESOLVES_TO))
    g.add_edge(Edge(src=ip3.id, dst=asn_a.id, type=EdgeType.PART_OF_ASN))
    g.add_edge(Edge(src=host.id, dst=ip1.id, type=EdgeType.RESOLVES_TO))
    g.add_edge(Edge(src=host.id, dst=ip2.id, type=EdgeType.RESOLVES_TO))
    g.add_edge(Edge(src=ip1.id, dst=asn_a.id, type=EdgeType.PART_OF_ASN))
    g.add_edge(Edge(src=ip2.id, dst=asn_b.id, type=EdgeType.PART_OF_ASN))
    ctx = build_context(g, now=NOW)
    assert ctx.dominant_asn == "AS100"
    assert f_off_primary_asn(host, g, ctx).value == 0.5


# --- F4 concentration ----------------------------------------------------


def test_f4_central_node_scores_above_leaf() -> None:
    g = AssetGraph()
    hub = _host(g, "hub.example.com")
    for i in range(4):
        leaf = _host(g, f"leaf{i}.example.com")
        g.add_edge(Edge(src=hub.id, dst=leaf.id, type=EdgeType.RESOLVES_TO))
    ctx = build_context(g, now=NOW)
    hub_score = f_concentration(hub, g, ctx).value
    leaf_score = f_concentration(Node(type=NodeType.SUBDOMAIN, value="leaf0.example.com"), g, ctx).value
    assert hub_score > leaf_score


# --- aggregator ----------------------------------------------------------


def test_score_is_bounded_and_ranked() -> None:
    g = AssetGraph()
    # risky host: expired cert + dev naming
    risky = _host(g, "dev.example.com")
    cert = Node(type=NodeType.CERTIFICATE, value="crtsh:1", attrs={"not_after": "2020-01-01T00:00:00"})
    g.add_node(cert)
    g.add_edge(Edge(src=risky.id, dst=cert.id, type=EdgeType.SHARES_CERT))
    # clean host
    _host(g, "www.example.com")

    scores = score_graph(g, now=NOW)
    assert all(0.0 <= s.exposure <= 100.0 for s in scores)
    assert scores[0].host == "dev.example.com"  # risky ranks first
    assert scores[0].exposure > scores[-1].exposure


def test_score_contributions_sum_to_exposure() -> None:
    g = AssetGraph()
    host = _host(g, "dev.example.com")
    cert = Node(type=NodeType.CERTIFICATE, value="crtsh:1", attrs={"not_after": "2020-01-01T00:00:00"})
    g.add_node(cert)
    g.add_edge(Edge(src=host.id, dst=cert.id, type=EdgeType.SHARES_CERT))
    result = score_node(host, g, build_context(g, now=NOW))
    # contributions are per-feature points of the score; they sum to the exposure (within rounding)
    assert abs(sum(result.contributions.values()) - result.exposure) <= 0.2


def test_score_writes_back_attrs_and_is_deterministic() -> None:
    g = AssetGraph()
    _host(g, "dev.example.com")
    s1 = score_graph(g, now=NOW)
    node = next(n for n in g.nodes() if n.value == "dev.example.com")
    assert "exposure" in node.attrs
    s2 = score_graph(g, now=NOW)
    assert [(s.host, s.exposure) for s in s1] == [(s.host, s.exposure) for s in s2]


def test_scored_attrs_survive_json_roundtrip() -> None:
    g = AssetGraph()
    host = _host(g, "dev.example.com")
    cert = Node(type=NodeType.CERTIFICATE, value="crtsh:1", attrs={"not_after": "2020-01-01T00:00:00"})
    g.add_node(cert)
    g.add_edge(Edge(src=host.id, dst=cert.id, type=EdgeType.SHARES_CERT))
    score_graph(g, now=NOW)

    restored = AssetGraph.from_dict(g.to_dict())
    node = next(n for n in restored.nodes() if n.value == "dev.example.com")
    assert node.attrs["exposure"] > 0
    assert "score_contributions" in node.attrs
    assert isinstance(node.attrs["exposure_reasons"], list)
