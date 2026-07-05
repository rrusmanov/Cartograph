"""Group hosts tied together by a shared certificate or IP.

Connected components over ``shares_cert`` and ``resolves_to`` edges; sorted output for determinism.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from cartograph.graph.model import AssetGraph, EdgeType, NodeType

_LINKING_EDGES = (EdgeType.SHARES_CERT, EdgeType.RESOLVES_TO)


@dataclass
class Cluster:
    """A connected group of assets sharing infrastructure."""

    hosts: list[str]
    size: int
    linked_via: list[str]  # the shared cert/ip node values that connect them


def shared_infrastructure_clusters(graph: AssetGraph, *, min_size: int = 2) -> list[Cluster]:
    """Return clusters of hosts connected through shared certificates or IPs (size >= ``min_size``)."""
    nodes = {n.id: n for n in graph.nodes()}
    ug: nx.Graph = nx.Graph()

    for edge in graph.edges():
        if edge.type in _LINKING_EDGES:
            ug.add_edge(edge.src, edge.dst)

    clusters: list[Cluster] = []
    for component in nx.connected_components(ug):
        hosts = sorted(
            {
                nodes[nid].value
                for nid in component
                if nid in nodes and nodes[nid].type in (NodeType.DOMAIN, NodeType.SUBDOMAIN)
            }
        )
        if len(hosts) < min_size:
            continue
        linked_via = sorted(
            {
                nodes[nid].value
                for nid in component
                if nid in nodes and nodes[nid].type in (NodeType.CERTIFICATE, NodeType.IP)
            }
        )
        clusters.append(Cluster(hosts=hosts, size=len(hosts), linked_via=linked_via))

    clusters.sort(key=lambda c: (-c.size, c.hosts[0] if c.hosts else ""))
    return clusters
