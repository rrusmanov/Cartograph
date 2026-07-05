"""Subdomain + certificate discovery from Certificate Transparency logs (crt.sh).

Certificates list the hostnames they cover (CN + SANs), which makes CT one of the best passive
sources of subdomains. We emit host and certificate nodes plus ``has_subdomain`` and ``shares_cert``
edges; the shared-certificate links are the connectivity a flat subdomain list loses.
"""

from __future__ import annotations

from typing import Any

from cartograph.collectors.base import CollectResult, Collector
from cartograph.graph.model import Edge, EdgeType, Node, NodeType

CRTSH_URL = "https://crt.sh/?q=%25.{target}&output=json"


class CertificateTransparencyCollector(Collector):
    """Passive subdomain + certificate discovery from Certificate Transparency logs."""

    name = "ct"

    async def collect(self, target: str) -> CollectResult:
        target = target.strip().rstrip(".").lower()
        url = CRTSH_URL.format(target=target)
        rows: Any = await self.get_json(url, cache_key=f"crtsh:{target}")
        return self.parse(target, rows)

    def parse(self, target: str, rows: list[dict[str, Any]]) -> CollectResult:
        """Pure transformation of crt.sh rows into graph fragments (unit-testable, no network)."""
        result = CollectResult(raw=rows)

        root = Node(type=NodeType.DOMAIN, value=target, sources={self.name})
        result.nodes.append(root)
        root_id = root.id

        seen_hosts: set[str] = set()
        seen_certs: set[str] = set()

        for row in rows or []:
            names = self._extract_names(row)
            in_scope = [h for h in names if self._in_scope(h, target)]
            if not in_scope:
                # a certificate covering only out-of-scope names (e.g. a lookalike domain)
                # is not part of this target's surface – skip it entirely.
                continue

            cert_id = str(row.get("id") or row.get("serial_number") or "")
            cert_node: Node | None = None
            if cert_id:
                cert_value = f"crtsh:{cert_id}"
                if cert_value not in seen_certs:
                    seen_certs.add(cert_value)
                    cert_node = Node(
                        type=NodeType.CERTIFICATE,
                        value=cert_value,
                        sources={self.name},
                        attrs={
                            "issuer": row.get("issuer_name"),
                            "common_name": row.get("common_name"),
                            "not_before": row.get("not_before"),
                            "not_after": row.get("not_after"),
                            "is_wildcard": any(n.startswith("*.") for n in in_scope),
                        },
                    )
                    result.nodes.append(cert_node)
                else:
                    cert_node = Node(type=NodeType.CERTIFICATE, value=cert_value)

            for host in in_scope:
                is_wildcard = host.startswith("*.")
                node_type = NodeType.DOMAIN if host == target else NodeType.SUBDOMAIN
                host_node = Node(
                    type=node_type,
                    value=host,
                    sources={self.name},
                    attrs={"is_wildcard": is_wildcard} if is_wildcard else {},
                )
                if host not in seen_hosts:
                    seen_hosts.add(host)
                    result.nodes.append(host_node)

                if node_type is NodeType.SUBDOMAIN:
                    result.edges.append(
                        Edge(
                            src=root_id,
                            dst=host_node.id,
                            type=EdgeType.HAS_SUBDOMAIN,
                            sources={self.name},
                        )
                    )
                if cert_node is not None:
                    result.edges.append(
                        Edge(
                            src=host_node.id,
                            dst=cert_node.id,
                            type=EdgeType.SHARES_CERT,
                            sources={self.name},
                        )
                    )

        return result

    @staticmethod
    def _extract_names(row: dict[str, Any]) -> list[str]:
        raw = str(row.get("name_value", ""))
        names: set[str] = set()
        for line in raw.splitlines():
            host = line.strip().rstrip(".").lower()
            if host and "@" not in host:  # skip email SANs
                names.add(host)
        cn = str(row.get("common_name", "")).strip().rstrip(".").lower()
        if cn and "@" not in cn:
            names.add(cn)
        return sorted(names)

    @staticmethod
    def _in_scope(host: str, target: str) -> bool:
        """Keep only the target itself and hosts under it (incl. wildcards like ``*.x.target``)."""
        bare = host[2:] if host.startswith("*.") else host
        return bare == target or bare.endswith("." + target)
