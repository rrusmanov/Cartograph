"""Scan orchestration for the web UI (no web-framework dependency, so it's unit-testable).

Wraps the pipeline + scoring + analytics + graph HTML into one ScanResult.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field

from cartograph.analysis.clusters import shared_infrastructure_clusters
from cartograph.analysis.takeover import takeover_candidates
from cartograph.pipeline import (
    PipelineConfig,
    build_collectors,
    build_enrichers,
    run_pipeline,
)
from cartograph.render.graphviz import build_html
from cartograph.scoring.model import score_graph

# a permissive but safe hostname check (labels of letters/digits/hyphens, a dot, a TLD)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$", re.IGNORECASE)


def is_valid_domain(domain: str) -> bool:
    """True if ``domain`` looks like a bare registrable hostname (no scheme, path or port)."""
    return bool(_DOMAIN_RE.match(domain.strip().rstrip(".")))


@dataclass
class ScanOptions:
    score: bool = True
    max_hosts: int = 60
    max_ips: int = 60
    include_endpoints: bool = False
    cache_dir: str = ".cache"
    min_interval: float = 0.5
    timeout: float = 300.0  # hard cap on collection so a slow source can't hang the request


@dataclass
class ScanResult:
    domain: str
    node_count: int
    top: list[dict[str, object]] = field(default_factory=list)
    takeover: list[dict[str, str]] = field(default_factory=list)
    clusters: list[dict[str, object]] = field(default_factory=list)
    graph_html: str = ""
    graph_json: str = ""


async def run_scan(domain: str, opts: ScanOptions | None = None) -> ScanResult:
    """Run the passive pipeline for ``domain`` and assemble a web-ready result."""
    opts = opts or ScanOptions()
    domain = domain.strip().rstrip(".").lower()
    if not is_valid_domain(domain):
        raise ValueError(f"invalid domain: {domain!r}")

    config = PipelineConfig(
        cache_dir=opts.cache_dir,
        min_interval=opts.min_interval,
        max_hosts=opts.max_hosts,
        max_ips=opts.max_ips,
    )
    collectors = build_collectors(config)
    enrichers = build_enrichers(config)
    try:
        graph = await asyncio.wait_for(
            run_pipeline(domain, collectors, enrichers, config), timeout=opts.timeout
        )
    finally:
        await asyncio.gather(*(f.aclose() for f in [*collectors, *enrichers]))

    if opts.score:
        scores = score_graph(graph)
        top: list[dict[str, object]] = [
            {"score": s.exposure, "host": s.host, "reasons": s.reasons[:4]}
            for s in scores
            if s.exposure > 0
        ][:25]
    else:
        top = []

    takeover = [
        {"host": c.host, "cname": c.cname, "provider": c.provider}
        for c in takeover_candidates(graph)
    ]
    clusters = [
        {"size": c.size, "hosts": c.hosts[:8]}
        for c in shared_infrastructure_clusters(graph)
    ][:15]

    graph_html, node_count = build_html(graph, include_endpoints=opts.include_endpoints)

    return ScanResult(
        domain=domain,
        node_count=node_count,
        top=top,
        takeover=takeover,
        clusters=clusters,
        graph_html=graph_html,
        graph_json=json.dumps(graph.to_dict()),
    )
