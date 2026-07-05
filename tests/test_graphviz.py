"""Tests for the visualization node-selection logic (pure; no pyvis/rendering)."""

from __future__ import annotations

from pathlib import Path

from cartograph.graph.model import AssetGraph, Edge, EdgeType, Node, NodeType
from cartograph.render.graphviz import exposure_color, render_html, select_visible


def _sub(g: AssetGraph, value: str, **attrs: object) -> Node:
    n = Node(type=NodeType.SUBDOMAIN, value=value, attrs=dict(attrs))
    g.add_node(n)
    return n


def _build() -> AssetGraph:
    g = AssetGraph()
    a = _sub(g, "a.example.com")
    b = _sub(g, "b.example.com")
    c = _sub(g, "c.example.com")
    shared = Node(type=NodeType.CERTIFICATE, value="crtsh:shared")
    single = Node(type=NodeType.CERTIFICATE, value="crtsh:single")
    ip = Node(type=NodeType.IP, value="1.2.3.4")
    asn = Node(type=NodeType.ASN, value="AS100")
    ep = Node(type=NodeType.ENDPOINT, value="http://a.example.com/x")
    for n in (shared, single, ip, asn, ep):
        g.add_node(n)
    # shared cert links a and b (degree 2); single cert only c (degree 1)
    g.add_edge(Edge(src=a.id, dst=shared.id, type=EdgeType.SHARES_CERT))
    g.add_edge(Edge(src=b.id, dst=shared.id, type=EdgeType.SHARES_CERT))
    g.add_edge(Edge(src=c.id, dst=single.id, type=EdgeType.SHARES_CERT))
    g.add_edge(Edge(src=a.id, dst=ip.id, type=EdgeType.RESOLVES_TO))
    g.add_edge(Edge(src=ip.id, dst=asn.id, type=EdgeType.PART_OF_ASN))
    g.add_edge(Edge(src=a.id, dst=ep.id, type=EdgeType.HAS_ENDPOINT))
    return g


def test_default_view_includes_shared_cert_only() -> None:
    visible = select_visible(_build())
    assert "certificate:crtsh:shared" in visible
    assert "certificate:crtsh:single" not in visible


def test_default_view_excludes_endpoints() -> None:
    visible = select_visible(_build())
    assert "endpoint:http://a.example.com/x" not in visible


def test_endpoints_included_with_flag() -> None:
    visible = select_visible(_build(), include_endpoints=True)
    assert "endpoint:http://a.example.com/x" in visible


def test_all_certs_flag_includes_singletons() -> None:
    visible = select_visible(_build(), all_certs=True)
    assert "certificate:crtsh:single" in visible


def test_hosts_ip_asn_always_included() -> None:
    visible = select_visible(_build())
    for nid in ("subdomain:a.example.com", "ip:1.2.3.4", "asn:AS100"):
        assert nid in visible


def test_cap_keeps_highest_exposure_hosts() -> None:
    g = AssetGraph()
    _sub(g, "low.example.com", exposure=5.0)
    _sub(g, "high.example.com", exposure=90.0)
    _sub(g, "mid.example.com", exposure=40.0)
    visible = select_visible(g, max_nodes=1)
    assert visible == {"subdomain:high.example.com"}


def test_exposure_color_is_hex() -> None:
    for score in (0.0, 25.0, 50.0, 75.0, 100.0):
        color = exposure_color(score)
        assert color.startswith("#") and len(color) == 7


def test_render_html_writes_self_contained_file(tmp_path: Path) -> None:
    out = tmp_path / "g.html"
    drawn = render_html(_build(), out)
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "<canvas" in text              # self-contained canvas renderer
    assert "<script src" not in text      # no external CDN dependency
    assert "a.example.com" in text        # embeds node data
    assert 'id="info"' in text            # has the click-info panel
    assert drawn > 0
