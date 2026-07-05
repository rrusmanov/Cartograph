"""Enricher: expand a graph using assets it already contains (host->IP, IP->ASN).

Where a collector finds hosts, an enricher finds the links between them. Mutates the graph in place.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from cartograph.cache import ResponseCache
from cartograph.graph.model import AssetGraph
from cartograph.net import AsyncFetcher


@dataclass
class EnrichStats:
    """Summary of what an enricher added, for reporting and tests."""

    nodes_added: int = 0
    edges_added: int = 0


class Enricher(AsyncFetcher, ABC):
    """Base class for graph enrichers.

    Subclasses implement :meth:`enrich`, which reads assets from ``graph`` and adds new nodes/edges.
    A ``max_targets`` cap bounds fan-out for politeness and determinism (targets are processed in
    sorted order, so the same cap yields the same subset every run).
    """

    name: str = "enricher"

    def __init__(
        self,
        *,
        max_targets: int = 200,
        client: httpx.AsyncClient | None = None,
        cache: ResponseCache | None = None,
        min_interval: float = 1.0,
        timeout: float = 20.0,
    ) -> None:
        super().__init__(
            client=client, cache=cache, min_interval=min_interval, timeout=timeout
        )
        self.max_targets = max_targets

    @abstractmethod
    async def enrich(self, graph: AssetGraph) -> EnrichStats:
        """Expand ``graph`` in place; return what was added."""
        raise NotImplementedError
