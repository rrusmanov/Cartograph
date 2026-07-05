"""Per-host exposure features (F1–F7).

Each feature is a pure ``(node, graph, ctx) -> FeatureScore`` returning a value in [0, 1]. Shared
context (dominant ASN, centrality, resolution maps, "now") is built once in :func:`build_context`.
Rationale for each feature is in docs/design_m2_scoring.md.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import networkx as nx

from cartograph.fingerprints import match_fingerprint
from cartograph.graph.model import AssetGraph, EdgeType, Node, NodeType

# hostname labels that indicate non-production / higher-value assets
NONPROD_TOKENS: frozenset[str] = frozenset(
    {
        "dev",
        "development",
        "staging",
        "stage",
        "test",
        "testing",
        "uat",
        "qa",
        "preprod",
        "pre",
        "sandbox",
        "sbx",
        "demo",
        "internal",
        "int",
        "intranet",
        "admin",
        "jenkins",
        "gitlab",
        "jira",
        "vpn",
        "beta",
        "old",
        "legacy",
        "backup",
    }
)


@dataclass
class FeatureScore:
    """One feature's contribution: a normalized value in [0, 1] and why."""

    name: str
    value: float
    detail: str = ""


@dataclass
class ScoringContext:
    """Graph-wide facts computed once and shared across feature evaluations."""

    now: datetime
    centrality: dict[str, float] = field(default_factory=dict)
    dominant_asn: str | None = None
    host_certs: dict[str, list[Node]] = field(default_factory=dict)
    host_ips: dict[str, set[str]] = field(default_factory=dict)
    host_resolves: set[str] = field(default_factory=set)
    ip_asn: dict[str, str] = field(default_factory=dict)
    pdns_ran: bool = False


def build_context(graph: AssetGraph, now: datetime | None = None) -> ScoringContext:
    """Precompute everything the feature functions need from the graph (deterministic)."""
    now = now or datetime.now(UTC).replace(tzinfo=None)

    nodes_by_id = {n.id: n for n in graph.nodes()}
    host_certs: dict[str, list[Node]] = {}
    host_ips: dict[str, set[str]] = {}
    host_resolves: set[str] = set()
    ip_asn: dict[str, str] = {}
    asn_ip_count: dict[str, int] = {}
    pdns_ran = False

    for edge in graph.edges():
        if edge.type is EdgeType.SHARES_CERT:
            cert = nodes_by_id.get(edge.dst)
            if cert is not None:
                host_certs.setdefault(edge.src, []).append(cert)
        elif edge.type is EdgeType.RESOLVES_TO:
            pdns_ran = True
            host_resolves.add(edge.src)
            dst = nodes_by_id.get(edge.dst)
            if dst is not None and dst.type is NodeType.IP:
                host_ips.setdefault(edge.src, set()).add(edge.dst)
        elif edge.type is EdgeType.PART_OF_ASN:
            asn_value = nodes_by_id[edge.dst].value if edge.dst in nodes_by_id else edge.dst
            ip_asn[edge.src] = asn_value
            asn_ip_count[asn_value] = asn_ip_count.get(asn_value, 0) + 1

    dominant_asn = max(asn_ip_count, key=lambda a: asn_ip_count[a]) if asn_ip_count else None

    return ScoringContext(
        now=now,
        centrality=_degree_centrality(graph),
        dominant_asn=dominant_asn,
        host_certs=host_certs,
        host_ips=host_ips,
        host_resolves=host_resolves,
        ip_asn=ip_asn,
        pdns_ran=pdns_ran,
    )


def _degree_centrality(graph: AssetGraph) -> dict[str, float]:
    ug: nx.Graph = nx.Graph()
    ug.add_nodes_from(graph.raw.nodes())
    for u, v in graph.raw.edges():
        if u != v:
            ug.add_edge(u, v)
    if ug.number_of_nodes() <= 1:
        return {n: 0.0 for n in ug.nodes()}
    return {str(k): float(v) for k, v in nx.degree_centrality(ug).items()}


# --- features ------------------------------------------------------------


def f_tls_expiry(node: Node, graph: AssetGraph, ctx: ScoringContext) -> FeatureScore:
    """F1: the host has no *current* valid TLS – its freshest certificate is expired or expiring.

    Judged on the newest certificate (max ``not_after``), not on any historical one: a long-lived
    host accumulates old expired certs in CT, so "some expired cert exists" is nearly universal and
    meaningless. "Newest cert is expired" means the host genuinely lacks current TLS.
    """
    not_afters: list[datetime] = []
    for cert in ctx.host_certs.get(node.id, []):
        dt = _parse_dt(cert.attrs.get("not_after"))
        if dt is not None:
            not_afters.append(dt)
    if not not_afters:
        return FeatureScore("tls_expiry", 0.0)
    days = (max(not_afters) - ctx.now).days
    if days < 0:
        return FeatureScore("tls_expiry", 1.0, f"newest TLS expired {abs(days)}d ago")
    if days < 30:
        return FeatureScore("tls_expiry", 0.6, f"TLS expires in {days}d")
    if days < 90:
        return FeatureScore("tls_expiry", 0.3, f"TLS expires in {days}d")
    return FeatureScore("tls_expiry", 0.0)


def f_takeover_cname(node: Node, graph: AssetGraph, ctx: ScoringContext) -> FeatureScore:
    """F3: CNAME to a takeover-prone provider, or a dangling CNAME with no A record."""
    externals = [str(c) for c in node.attrs.get("external_cnames", [])]
    for cname in externals:
        provider = match_fingerprint(cname)
        if provider is not None:
            return FeatureScore("takeover_cname", 1.0, f"CNAME -> {cname} ({provider})")
    if externals and not ctx.host_ips.get(node.id):
        return FeatureScore("takeover_cname", 0.6, f"dangling CNAME -> {externals[0]} (no A record)")
    return FeatureScore("takeover_cname", 0.0)


def f_off_primary_asn(node: Node, graph: AssetGraph, ctx: ScoringContext) -> FeatureScore:
    """F7: host resolves into an ASN other than the org's dominant ASN."""
    if ctx.dominant_asn is None:
        return FeatureScore("off_primary_asn", 0.0)
    ips = ctx.host_ips.get(node.id, set())
    asns = [ctx.ip_asn[ip] for ip in ips if ip in ctx.ip_asn]
    if not asns:
        return FeatureScore("off_primary_asn", 0.0)
    off = [a for a in asns if a != ctx.dominant_asn]
    value = len(off) / len(asns)
    detail = f"hosted in {sorted(set(off))}" if off else ""
    return FeatureScore("off_primary_asn", value, detail)


def f_nonprod_naming(node: Node, graph: AssetGraph, ctx: ScoringContext) -> FeatureScore:
    """F5: hostname contains a non-production / high-value token."""
    labels = node.value.lower().lstrip("*.").split(".")
    for label in labels:
        for token in NONPROD_TOKENS:
            if label == token or token in label.split("-"):
                return FeatureScore("nonprod_naming", 1.0, f"non-prod token '{token}'")
    return FeatureScore("nonprod_naming", 0.0)


def f_orphan_stale(node: Node, graph: AssetGraph, ctx: ScoringContext) -> FeatureScore:
    """F6: a name that passive DNS *successfully checked* yet found no address for.

    Only fires when the host was actually queried and returned no A/AAAA record – a host whose lookup
    failed (e.g. the pDNS source errored) or was never queried carries no signal, avoiding false
    positives when passive DNS is unavailable.
    """
    if node.value.startswith("*.") or not node.attrs.get("resolution_checked"):
        return FeatureScore("orphan_stale", 0.0)
    if node.id not in ctx.host_resolves:
        return FeatureScore("orphan_stale", 0.6, "never resolves (no passive-DNS records)")
    return FeatureScore("orphan_stale", 0.0)


def f_concentration(node: Node, graph: AssetGraph, ctx: ScoringContext) -> FeatureScore:
    """F4: structural centrality – shared certs/IPs and bridges concentrate blast radius."""
    value = ctx.centrality.get(node.id, 0.0)
    detail = "high graph centrality" if value >= 0.1 else ""
    return FeatureScore("concentration", min(value, 1.0), detail)


def f_wildcard(node: Node, graph: AssetGraph, ctx: ScoringContext) -> FeatureScore:
    """F2: wildcard exposure – the host is a wildcard entry or is covered by a wildcard cert."""
    if node.attrs.get("is_wildcard"):
        return FeatureScore("wildcard", 1.0, "wildcard host entry")
    if any(c.attrs.get("is_wildcard") for c in ctx.host_certs.get(node.id, [])):
        return FeatureScore("wildcard", 0.5, "covered by wildcard certificate")
    return FeatureScore("wildcard", 0.0)


FeatureFn = Callable[[Node, AssetGraph, "ScoringContext"], FeatureScore]

#: feature registry – names MUST match keys in scoring.weights.DEFAULT_WEIGHTS
FEATURES: list[tuple[str, FeatureFn]] = [
    ("tls_expiry", f_tls_expiry),
    ("takeover_cname", f_takeover_cname),
    ("off_primary_asn", f_off_primary_asn),
    ("nonprod_naming", f_nonprod_naming),
    ("orphan_stale", f_orphan_stale),
    ("concentration", f_concentration),
    ("wildcard", f_wildcard),
]


def _parse_dt(value: object) -> datetime | None:
    s = str(value).strip() if value is not None else ""
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt
