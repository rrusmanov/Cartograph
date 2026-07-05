"""Turn DNS records into graph fragments – shared by the passive-DNS and DoH resolvers.

A/AAAA answers become ``ip`` nodes + ``resolves_to`` edges; in-scope CNAME targets become host nodes;
out-of-scope CNAME targets are recorded on the host for takeover analysis. A host that was actually
checked is marked ``resolution_checked`` so the orphan feature can tell "no address" from "not checked".
"""

from __future__ import annotations

from dataclasses import dataclass

from cartograph.graph.model import AssetGraph, Edge, EdgeType, Node, NodeType


@dataclass
class DnsRecord:
    """A normalized DNS answer: ``rrtype`` in {a, aaaa, cname} and the answer value."""

    rrtype: str
    answer: str


def host_type(graph: AssetGraph, host: str) -> NodeType:
    """Type a hostname as DOMAIN if it already exists as a domain node, else SUBDOMAIN."""
    for n in graph.nodes_by_type(NodeType.DOMAIN):
        if n.value == host:
            return NodeType.DOMAIN
    return NodeType.SUBDOMAIN


def apply_dns_records(
    graph: AssetGraph,
    host: str,
    records: list[DnsRecord],
    scope_domains: tuple[str, ...],
    source: str,
) -> None:
    """Fold resolved records for ``host`` into the graph (marks the host as resolution-checked)."""
    htype = host_type(graph, host)
    host_node = Node(type=htype, value=host, sources={source}, attrs={"resolution_checked": True})
    graph.add_node(host_node)
    external_cnames: set[str] = set()

    for rec in records:
        rrtype = rec.rrtype.lower()
        answer = rec.answer.strip().rstrip(".")
        if not answer:
            continue

        if rrtype in ("a", "aaaa"):
            ip_node = Node(type=NodeType.IP, value=answer, sources={source})
            graph.add_node(ip_node)
            _add_edge(
                graph,
                Edge(
                    src=host_node.id,
                    dst=ip_node.id,
                    type=EdgeType.RESOLVES_TO,
                    sources={source},
                    attrs={"rrtype": rrtype},
                ),
            )
        elif rrtype == "cname":
            target = answer.lower()
            if any(target == d or target.endswith("." + d) for d in scope_domains):
                tnode = Node(type=host_type(graph, target), value=target, sources={source})
                graph.add_node(tnode)
                _add_edge(
                    graph,
                    Edge(
                        src=host_node.id,
                        dst=tnode.id,
                        type=EdgeType.RESOLVES_TO,
                        sources={source},
                        attrs={"rrtype": "cname"},
                    ),
                )
            else:
                external_cnames.add(target)

    if external_cnames:
        graph.add_node(
            Node(
                type=htype,
                value=host,
                sources={source},
                attrs={"external_cnames": sorted(external_cnames)},
            )
        )


def resolvable_hosts(graph: AssetGraph, limit: int) -> list[str]:
    """The hosts a resolver should query: non-wildcard domains/subdomains, sorted and capped."""
    hosts = {
        n.value
        for n in graph.nodes()
        if n.type in (NodeType.DOMAIN, NodeType.SUBDOMAIN) and not n.value.startswith("*.")
    }
    return sorted(hosts)[:limit]


def _add_edge(graph: AssetGraph, edge: Edge) -> None:
    try:
        graph.add_edge(edge)
    except KeyError:
        pass
