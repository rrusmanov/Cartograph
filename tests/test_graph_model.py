"""Tests for the typed graph model: identity, merging, determinism, persistence."""

from __future__ import annotations

from datetime import datetime

import pytest

from cartograph.graph.model import (
    AssetGraph,
    Edge,
    EdgeType,
    Node,
    NodeType,
    canonicalize,
)


def test_node_identity_is_canonical() -> None:
    a = Node(type=NodeType.SUBDOMAIN, value="API.Example.com.")
    b = Node(type=NodeType.SUBDOMAIN, value="api.example.com")
    assert a.id == b.id == "subdomain:api.example.com"


def test_canonicalize_trims_and_lowercases_hosts() -> None:
    assert canonicalize(NodeType.DOMAIN, "  Example.COM. ") == "example.com"
    # non-host types are only trimmed, not lowercased
    assert canonicalize(NodeType.CERTIFICATE, " crtsh:ABC ") == "crtsh:ABC"


def test_empty_value_rejected() -> None:
    with pytest.raises(ValueError):
        Node(type=NodeType.DOMAIN, value="   ")


def test_add_node_merges_sources_and_attrs() -> None:
    g = AssetGraph()
    g.add_node(
        Node(type=NodeType.SUBDOMAIN, value="a.example.com", sources={"ct"}, attrs={"x": 1})
    )
    g.add_node(
        Node(type=NodeType.SUBDOMAIN, value="a.example.com", sources={"pdns"}, attrs={"y": 2})
    )
    assert len(g) == 1
    node = g.nodes()[0]
    assert node.sources == {"ct", "pdns"}
    assert node.attrs == {"x": 1, "y": 2}


def test_merge_widens_time_span() -> None:
    early = datetime(2020, 1, 1)
    late = datetime(2024, 1, 1)
    n1 = Node(type=NodeType.DOMAIN, value="example.com", first_seen=late, last_seen=late)
    n2 = Node(type=NodeType.DOMAIN, value="example.com", first_seen=early, last_seen=early)
    merged = n1.merged_with(n2)
    assert merged.first_seen == early
    assert merged.last_seen == late


def test_add_edge_requires_existing_endpoints() -> None:
    g = AssetGraph()
    g.add_node(Node(type=NodeType.DOMAIN, value="example.com"))
    with pytest.raises(KeyError):
        g.add_edge(
            Edge(src="domain:example.com", dst="ip:1.2.3.4", type=EdgeType.RESOLVES_TO)
        )


def test_roundtrip_json_is_stable() -> None:
    g = AssetGraph()
    g.add_node(Node(type=NodeType.DOMAIN, value="example.com", sources={"ct"}))
    g.add_node(Node(type=NodeType.SUBDOMAIN, value="a.example.com", sources={"ct"}))
    g.add_edge(
        Edge(
            src="domain:example.com",
            dst="subdomain:a.example.com",
            type=EdgeType.HAS_SUBDOMAIN,
            sources={"ct"},
        )
    )
    d1 = g.to_dict()
    g2 = AssetGraph.from_dict(d1)
    assert g2.to_dict() == d1  # deterministic serialization survives a roundtrip


def test_nodes_and_edges_are_sorted() -> None:
    g = AssetGraph()
    for value in ["c.example.com", "a.example.com", "b.example.com"]:
        g.add_node(Node(type=NodeType.SUBDOMAIN, value=value))
    values = [n.value for n in g.nodes()]
    assert values == sorted(values)
