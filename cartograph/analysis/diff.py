"""Diff two saved graphs – added/removed nodes and edges. Set-based, so deterministic."""

from __future__ import annotations

from dataclasses import dataclass, field

from cartograph.graph.model import AssetGraph


@dataclass
class GraphDiff:
    added_nodes: list[str] = field(default_factory=list)
    removed_nodes: list[str] = field(default_factory=list)
    added_edges: list[str] = field(default_factory=list)
    removed_edges: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.added_nodes or self.removed_nodes or self.added_edges or self.removed_edges)


def _edge_keys(graph: AssetGraph) -> set[str]:
    return {f"{e.src} -[{e.type.value}]-> {e.dst}" for e in graph.edges()}


def diff_graphs(old: AssetGraph, new: AssetGraph) -> GraphDiff:
    """Compute node/edge additions and removals from ``old`` to ``new``."""
    old_nodes = {n.id for n in old.nodes()}
    new_nodes = {n.id for n in new.nodes()}
    old_edges = _edge_keys(old)
    new_edges = _edge_keys(new)

    return GraphDiff(
        added_nodes=sorted(new_nodes - old_nodes),
        removed_nodes=sorted(old_nodes - new_nodes),
        added_edges=sorted(new_edges - old_edges),
        removed_edges=sorted(old_edges - new_edges),
    )
