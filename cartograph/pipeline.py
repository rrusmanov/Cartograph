"""Two-phase pipeline: collect assets from the target, then enrich the graph (host->IP, IP->ASN).

Enrichers run after collection so they see the union of everything the collectors found.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from cartograph.cache import ResponseCache
from cartograph.collectors.base import Collector
from cartograph.enrich.base import Enricher, EnrichStats
from cartograph.graph.model import AssetGraph

logger = logging.getLogger("cartograph")


@dataclass
class PipelineConfig:
    """Which sources to run and how far to fan out."""

    use_ct: bool = True
    use_rdap: bool = True
    use_wayback: bool = True
    use_doh: bool = True  # DNS-over-HTTPS resolver (key-less, reliable) – primary resolution source
    use_pdns: bool = False  # Mnemonic passive DNS (now paid / HTTP 402) – off by default
    use_asn: bool = True
    cache_dir: str = ".cache"
    min_interval: float = 1.0
    wayback_limit: int = 1000
    max_hosts: int = 200  # resolver fan-out cap (DoH / passive DNS)
    max_ips: int = 200  # ASN fan-out cap
    enrich_stats: dict[str, EnrichStats] = field(default_factory=dict)


async def collect_all(target: str, collectors: list[Collector]) -> AssetGraph:
    """Run every collector for ``target`` concurrently and fold fragments into one graph.

    A collector that fails (network error, bad response) is logged and skipped rather than aborting
    the whole run – recon sources are flaky by nature, and partial results are still useful.
    """
    outcomes = await asyncio.gather(*(c.collect(target) for c in collectors), return_exceptions=True)

    good = []
    for collector, outcome in zip(collectors, outcomes, strict=True):
        if isinstance(outcome, BaseException):
            logger.warning(
                "collector '%s' failed: %s: %s",
                collector.name,
                type(outcome).__name__,
                outcome,
            )
        else:
            good.append(outcome)

    graph = AssetGraph()
    for result in good:
        for node in result.nodes:
            graph.add_node(node)
    for result in good:
        for edge in result.edges:
            try:
                graph.add_edge(edge)
            except KeyError:
                continue
    return graph


async def run_pipeline(
    target: str,
    collectors: list[Collector],
    enrichers: list[Enricher],
    config: PipelineConfig | None = None,
) -> AssetGraph:
    """Collect, then enrich. Enrichers run sequentially (later ones depend on earlier assets)."""
    graph = await collect_all(target, collectors)
    for enricher in enrichers:
        try:
            stats = await enricher.enrich(graph)
        except Exception as exc:  # noqa: BLE001 - a failing enricher must not abort the run
            logger.warning("enricher '%s' failed: %s: %s", enricher.name, type(exc).__name__, exc)
            continue
        if config is not None:
            config.enrich_stats[enricher.name] = stats
    return graph


def build_collectors(config: PipelineConfig) -> list[Collector]:
    """Instantiate the enabled target-collectors, sharing one cache."""
    from cartograph.collectors.ct import CertificateTransparencyCollector
    from cartograph.collectors.rdap import RdapCollector
    from cartograph.collectors.wayback import WaybackCollector

    cache = ResponseCache(config.cache_dir)
    collectors: list[Collector] = []
    if config.use_ct:
        collectors.append(CertificateTransparencyCollector(cache=cache, min_interval=config.min_interval))
    if config.use_rdap:
        collectors.append(RdapCollector(cache=cache, min_interval=config.min_interval))
    if config.use_wayback:
        collectors.append(
            WaybackCollector(
                cache=cache,
                min_interval=config.min_interval,
                limit=config.wayback_limit,
                timeout=45.0,  # the Wayback CDX API is slow on large domains
                retries=1,  # bound worst-case wait; a timeout here rarely clears on retry
            )
        )
    return collectors


def build_enrichers(config: PipelineConfig) -> list[Enricher]:
    """Instantiate the enabled enrichers, sharing one cache. Order matters: resolvers before ASN."""
    from cartograph.enrich.asn import AsnEnricher
    from cartograph.enrich.doh import DohResolverEnricher
    from cartograph.enrich.passive_dns import PassiveDnsEnricher

    cache = ResponseCache(config.cache_dir)
    enrichers: list[Enricher] = []
    if config.use_doh:
        enrichers.append(
            DohResolverEnricher(
                cache=cache,
                # Cloudflare DoH is built for high volume; don't over-throttle it
                min_interval=min(config.min_interval, 0.2),
                max_targets=config.max_hosts,
            )
        )
    if config.use_pdns:
        enrichers.append(
            PassiveDnsEnricher(cache=cache, min_interval=config.min_interval, max_targets=config.max_hosts)
        )
    if config.use_asn:
        enrichers.append(AsnEnricher(cache=cache, min_interval=config.min_interval, max_targets=config.max_ips))
    return enrichers
