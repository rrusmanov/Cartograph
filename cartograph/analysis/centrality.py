"""Degree and betweenness centrality – hubs and bridges in the surface.

Degree finds shared-cert/IP hubs; betweenness finds bridges between clusters. Computed on an
undirected projection; deterministic for a fixed graph.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from cartograph.graph.model import AssetGraph


@dataclass
class CentralityEntry:
    node_id: str
    value: str
    node_type: str
    degree: float
    betweenness: float


def _undirected(graph: AssetGraph) -> nx.Graph:
    ug: nx.Graph = nx.Graph()
    ug.add_nodes_from(graph.raw.nodes())
    for u, v in graph.raw.edges():
        if u != v:
            ug.add_edge(u, v)
    return ug


def centrality_ranking(graph: AssetGraph, *, top: int = 15) -> list[CentralityEntry]:
    """Rank nodes by degree then betweenness centrality; return the top ``top`` entries."""
    ug = _undirected(graph)
    if ug.number_of_nodes() == 0:
        return []

    degree = nx.degree_centrality(ug)
    betweenness = nx.betweenness_centrality(ug) if ug.number_of_nodes() > 2 else dict.fromkeys(ug.nodes(), 0.0)
    nodes = {n.id: n for n in graph.nodes()}

    entries = [
        CentralityEntry(
            node_id=nid,
            value=nodes[nid].value if nid in nodes else nid,
            node_type=nodes[nid].type.value if nid in nodes else "?",
            degree=round(float(degree.get(nid, 0.0)), 4),
            betweenness=round(float(betweenness.get(nid, 0.0)), 4),
        )
        for nid in ug.nodes()
    ]
    entries.sort(key=lambda e: (-e.degree, -e.betweenness, e.node_id))
    return entries[:top]
