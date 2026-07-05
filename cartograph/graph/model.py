"""Typed attack-surface graph over NetworkX.

Node identity is ``(type, canonical value)``, so the same asset seen by two sources becomes one node.
Nodes and edges keep the set of sources that asserted them, which we use for source ablation.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import networkx as nx
from pydantic import BaseModel, Field, field_validator


class NodeType(StrEnum):
    """Semantic type of an attack-surface asset."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    ORG = "org"
    CERTIFICATE = "certificate"
    ENDPOINT = "endpoint"


class EdgeType(StrEnum):
    """Semantic type of a relationship between two assets."""

    RESOLVES_TO = "resolves_to"  # (sub)domain -> ip
    PART_OF_ASN = "part_of_asn"  # ip -> asn
    SHARES_CERT = "shares_cert"  # (sub)domain -> certificate
    REGISTERED_BY = "registered_by"  # domain -> org
    HISTORICALLY_SERVED = "historically_served"  # (sub)domain -> endpoint (from archives)
    HAS_SUBDOMAIN = "has_subdomain"  # domain -> subdomain
    HAS_ENDPOINT = "has_endpoint"  # (sub)domain -> endpoint


def canonicalize(node_type: NodeType, value: str) -> str:
    """Return a stable, comparable form of an asset value.

    Hostnames/orgs are lowercased and stripped of a trailing dot; other types are trimmed.
    Keeping this centralized is what guarantees two collectors reference the *same* node id.
    """
    value = value.strip()
    if node_type in (NodeType.DOMAIN, NodeType.SUBDOMAIN, NodeType.ORG):
        value = value.rstrip(".").lower()
    return value


class Node(BaseModel):
    """A typed asset in the attack-surface graph."""

    type: NodeType
    value: str
    attrs: dict[str, Any] = Field(default_factory=dict)
    sources: set[str] = Field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @field_validator("value")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Node.value must be non-empty")
        return v

    @property
    def id(self) -> str:
        """Deterministic identity: ``<type>:<canonical value>``."""
        return f"{self.type.value}:{canonicalize(self.type, self.value)}"

    def merged_with(self, other: Node) -> Node:
        """Combine two assertions of the same node (union sources, merge attrs, widen time span)."""
        if other.id != self.id:
            raise ValueError(f"cannot merge different nodes: {self.id} vs {other.id}")
        attrs = {**self.attrs, **{k: v for k, v in other.attrs.items() if v is not None}}
        first = _min_dt(self.first_seen, other.first_seen)
        last = _max_dt(self.last_seen, other.last_seen)
        return Node(
            type=self.type,
            value=self.value,
            attrs=attrs,
            sources=self.sources | other.sources,
            first_seen=first,
            last_seen=last,
        )


class Edge(BaseModel):
    """A typed, directed relationship between two nodes (referenced by node id)."""

    src: str
    dst: str
    type: EdgeType
    attrs: dict[str, Any] = Field(default_factory=dict)
    sources: set[str] = Field(default_factory=set)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.src, self.type.value, self.dst)


class AssetGraph:
    """A NetworkX ``MultiDiGraph`` wrapper that speaks in typed :class:`Node`/:class:`Edge`.

    Adding a node that already exists merges provenance and attributes rather than overwriting,
    so calling collectors in any order yields the same graph (order-independence).
    """

    def __init__(self) -> None:
        self._g: nx.MultiDiGraph = nx.MultiDiGraph()

    # -- mutation ---------------------------------------------------------
    def add_node(self, node: Node) -> str:
        nid = node.id
        if self._g.has_node(nid):
            existing = self._node_from_data(nid, self._g.nodes[nid])
            node = existing.merged_with(node)
        self._g.add_node(
            nid,
            type=node.type.value,
            value=node.value,
            attrs=node.attrs,
            sources=set(node.sources),
            first_seen=node.first_seen,
            last_seen=node.last_seen,
        )
        return nid

    def add_edge(self, edge: Edge) -> None:
        if not self._g.has_node(edge.src) or not self._g.has_node(edge.dst):
            raise KeyError(f"edge {edge.key} references a node not in the graph; add nodes first")
        key = edge.type.value
        if self._g.has_edge(edge.src, edge.dst, key=key):
            data = self._g.edges[edge.src, edge.dst, key]
            data["sources"] = set(data.get("sources", set())) | edge.sources
            data["attrs"] = {**data.get("attrs", {}), **edge.attrs}
        else:
            self._g.add_edge(
                edge.src,
                edge.dst,
                key=key,
                type=edge.type.value,
                attrs=dict(edge.attrs),
                sources=set(edge.sources),
            )

    # -- access -----------------------------------------------------------
    @property
    def raw(self) -> nx.MultiDiGraph:
        """The underlying NetworkX graph (for analysis modules, e.g. centrality)."""
        return self._g

    def __len__(self) -> int:
        return int(self._g.number_of_nodes())

    def nodes(self) -> list[Node]:
        return [self._node_from_data(nid, data) for nid, data in sorted(self._g.nodes(data=True), key=lambda t: t[0])]

    def edges(self) -> list[Edge]:
        out = [
            Edge(
                src=u,
                dst=v,
                type=EdgeType(data["type"]),
                attrs=dict(data.get("attrs", {})),
                sources=set(data.get("sources", set())),
            )
            for u, v, data in self._g.edges(data=True)
        ]
        return sorted(out, key=lambda e: e.key)

    def nodes_by_type(self, node_type: NodeType) -> list[Node]:
        return [n for n in self.nodes() if n.type is node_type]

    # -- persistence ------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": "0.0.1",
            "nodes": [_node_to_json(n) for n in self.nodes()],
            "edges": [_edge_to_json(e) for e in self.edges()],
        }

    def to_json(self, path: str | Path, *, indent: int = 2) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=indent, sort_keys=False, default=str),
            encoding="utf-8",
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssetGraph:
        g = cls()
        for nd in data.get("nodes", []):
            g.add_node(_node_from_json(nd))
        for ed in data.get("edges", []):
            g.add_edge(_edge_from_json(ed))
        return g

    @classmethod
    def from_json(cls, path: str | Path) -> AssetGraph:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def to_graphml(self, path: str | Path) -> None:
        """Export a flattened view for external graph tooling (Gephi, yEd, etc.)."""
        h: nx.MultiDiGraph = nx.MultiDiGraph()
        for nid, data in self._g.nodes(data=True):
            h.add_node(
                nid,
                type=str(data.get("type", "")),
                value=str(data.get("value", "")),
                sources=",".join(sorted(data.get("sources", set()))),
            )
        for u, v, data in self._g.edges(data=True):
            h.add_edge(
                u,
                v,
                type=str(data.get("type", "")),
                sources=",".join(sorted(data.get("sources", set()))),
            )
        nx.write_graphml(h, str(path))

    # -- internals --------------------------------------------------------
    @staticmethod
    def _node_from_data(nid: str, data: dict[str, Any]) -> Node:
        return Node(
            type=NodeType(data["type"]),
            value=data["value"],
            attrs=dict(data.get("attrs", {})),
            sources=set(data.get("sources", set())),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
        )


def _min_dt(a: datetime | None, b: datetime | None) -> datetime | None:
    return min([d for d in (a, b) if d is not None], default=None)


def _max_dt(a: datetime | None, b: datetime | None) -> datetime | None:
    return max([d for d in (a, b) if d is not None], default=None)


def _node_to_json(n: Node) -> dict[str, Any]:
    return {
        "id": n.id,
        "type": n.type.value,
        "value": n.value,
        "attrs": n.attrs,
        "sources": sorted(n.sources),
        "first_seen": n.first_seen.isoformat() if n.first_seen else None,
        "last_seen": n.last_seen.isoformat() if n.last_seen else None,
    }


def _node_from_json(d: dict[str, Any]) -> Node:
    return Node(
        type=NodeType(d["type"]),
        value=d["value"],
        attrs=dict(d.get("attrs", {})),
        sources=set(d.get("sources", [])),
        first_seen=_parse_dt(d.get("first_seen")),
        last_seen=_parse_dt(d.get("last_seen")),
    )


def _edge_to_json(e: Edge) -> dict[str, Any]:
    return {
        "src": e.src,
        "dst": e.dst,
        "type": e.type.value,
        "attrs": e.attrs,
        "sources": sorted(e.sources),
    }


def _edge_from_json(d: dict[str, Any]) -> Edge:
    return Edge(
        src=d["src"],
        dst=d["dst"],
        type=EdgeType(d["type"]),
        attrs=dict(d.get("attrs", {})),
        sources=set(d.get("sources", [])),
    )


def _parse_dt(v: Any) -> datetime | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v
    return datetime.fromisoformat(str(v))
