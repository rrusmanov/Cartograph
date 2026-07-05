"""Base class for passive collectors: take a root domain, return typed graph fragments.

Collectors read public sources only. Anything that works on already-discovered assets (host->IP,
IP->ASN) is an Enricher instead.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from cartograph.graph.model import Edge, Node
from cartograph.net import AsyncFetcher


@dataclass
class CollectResult:
    """What a collector produces for one target."""

    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    raw: Any = None  # unmodified source payload, kept for snapshots/reproducibility


class Collector(AsyncFetcher, ABC):
    """Base class for passive, target-driven collectors.

    Shared HTTP/cache/throttle plumbing comes from :class:`~cartograph.net.AsyncFetcher`;
    subclasses only implement :meth:`collect`.
    """

    name: str = "base"

    @abstractmethod
    async def collect(self, target: str) -> CollectResult:
        """Collect graph fragments for ``target`` (a root domain)."""
        raise NotImplementedError
