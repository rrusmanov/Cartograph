"""Exposure aggregator: ``score = 100 * Σ(weight_i · feature_i) / Σ(weight_i)``.

Features are in [0, 1] and weights are fixed, so the score is bounded to [0, 100] and decomposes into
per-feature contributions that sum to it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from cartograph.graph.model import AssetGraph, Node, NodeType
from cartograph.scoring.features import (
    FEATURES,
    ScoringContext,
    build_context,
)
from cartograph.scoring.weights import DEFAULT_WEIGHTS

_SCORED_TYPES = (NodeType.DOMAIN, NodeType.SUBDOMAIN)


@dataclass
class ExposureScore:
    """The exposure result for one host."""

    node_id: str
    host: str
    exposure: float  # 0–100
    contributions: dict[str, float] = field(default_factory=dict)  # feature -> points of the score
    reasons: list[str] = field(default_factory=list)  # human-readable, highest-contribution first


def score_node(
    node: Node,
    graph: AssetGraph,
    ctx: ScoringContext,
    weights: dict[str, float] | None = None,
) -> ExposureScore:
    """Score a single host node into an :class:`ExposureScore`."""
    weights = weights or DEFAULT_WEIGHTS
    total_w = sum(weights.values()) or 1.0

    acc = 0.0
    contributions: dict[str, float] = {}
    scored: list[tuple[float, str]] = []  # (contribution_points, reason_text)

    for name, func in FEATURES:
        fs = func(node, graph, ctx)
        weight = weights.get(name, 0.0)
        points = 100.0 * weight * fs.value / total_w
        acc += weight * fs.value
        if fs.value > 0.0:
            contributions[name] = round(points, 1)
            reason = fs.detail or name.replace("_", " ")
            scored.append((points, reason))

    exposure = round(100.0 * acc / total_w, 1)
    reasons = [text for _, text in sorted(scored, key=lambda t: (-t[0], t[1]))]
    return ExposureScore(
        node_id=node.id,
        host=node.value,
        exposure=exposure,
        contributions=contributions,
        reasons=reasons,
    )


def score_graph(
    graph: AssetGraph,
    *,
    ctx: ScoringContext | None = None,
    now: datetime | None = None,
    weights: dict[str, float] | None = None,
    write_back: bool = True,
) -> list[ExposureScore]:
    """Score every host in the graph.

    When ``write_back`` is set, each host node gains ``exposure``, ``score_contributions`` and
    ``exposure_reasons`` attributes. Returns the scores sorted by exposure (desc), then host (asc),
    which is deterministic for a fixed graph + ``now``.
    """
    ctx = ctx or build_context(graph, now=now)

    results: list[ExposureScore] = []
    for node in graph.nodes():
        if node.type not in _SCORED_TYPES:
            continue
        result = score_node(node, graph, ctx, weights)
        results.append(result)
        if write_back:
            graph.add_node(
                Node(
                    type=node.type,
                    value=node.value,
                    attrs={
                        "exposure": result.exposure,
                        "score_contributions": result.contributions,
                        "exposure_reasons": result.reasons,
                    },
                )
            )

    results.sort(key=lambda r: (-r.exposure, r.host))
    return results
