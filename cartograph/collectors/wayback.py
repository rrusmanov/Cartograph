"""Historical endpoints from the Wayback Machine CDX API.

Each captured URL becomes an ``endpoint`` node with a ``has_endpoint`` edge from its host. Old paths,
API versions and staging hosts often show up here. Results are capped and de-duplicated.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from cartograph.collectors.base import Collector, CollectResult
from cartograph.graph.model import Edge, EdgeType, Node, NodeType

CDX_URL = "http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"


class WaybackCollector(Collector):
    """Passive historical-endpoint discovery from the Internet Archive."""

    name = "wayback"

    def __init__(self, *, limit: int = 1000, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.limit = limit

    async def collect(self, target: str) -> CollectResult:
        target = target.strip().rstrip(".").lower()
        rows = await self.get_json(
            CDX_URL.format(domain=target, limit=self.limit),
            cache_key=f"wayback:{target}:{self.limit}",
            allow_status=(404,),
        )
        return self.parse(target, rows)

    def parse(self, target: str, rows: Any) -> CollectResult:
        """Pure transformation of CDX rows into graph fragments.

        CDX JSON is a list-of-lists whose first row is a header (``["original"]``).
        """
        result = CollectResult(raw=rows)
        if not isinstance(rows, list) or len(rows) <= 1:
            return result

        seen_hosts: set[str] = set()
        seen_endpoints: set[str] = set()

        for row in rows[1:]:  # skip header
            url = row[0] if isinstance(row, list) and row else None
            if not isinstance(url, str):
                continue
            parsed = self._normalize(url)
            if parsed is None:
                continue
            host, endpoint_value = parsed
            if not self._in_scope(host, target):
                continue

            if host not in seen_hosts:
                seen_hosts.add(host)
                node_type = NodeType.DOMAIN if host == target else NodeType.SUBDOMAIN
                result.nodes.append(Node(type=node_type, value=host, sources={self.name}))

            if endpoint_value not in seen_endpoints:
                seen_endpoints.add(endpoint_value)
                ep = Node(type=NodeType.ENDPOINT, value=endpoint_value, sources={self.name})
                result.nodes.append(ep)
                host_id = Node(type=NodeType.SUBDOMAIN, value=host).id
                if host == target:
                    host_id = Node(type=NodeType.DOMAIN, value=host).id
                result.edges.append(
                    Edge(
                        src=host_id,
                        dst=ep.id,
                        type=EdgeType.HAS_ENDPOINT,
                        sources={self.name},
                    )
                )
        return result

    @staticmethod
    def _normalize(url: str) -> tuple[str, str] | None:
        parts = urlsplit(url if "://" in url else f"http://{url}")
        host = parts.hostname
        if not host:
            return None
        host = host.rstrip(".").lower()
        path = parts.path or "/"
        endpoint_value = f"{parts.scheme}://{host}{path}"
        return host, endpoint_value

    @staticmethod
    def _in_scope(host: str, target: str) -> bool:
        return host == target or host.endswith("." + target)
