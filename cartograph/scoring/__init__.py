"""Transparent, feature-based exposure scoring.

The score is a bounded, decomposable aggregation of named per-host features (see ``docs/design_m2_scoring.md``).
Nothing here probes a target – every feature is computed from data already in the graph.
"""

from cartograph.scoring.features import ScoringContext, build_context
from cartograph.scoring.model import ExposureScore, score_graph, score_node

__all__ = [
    "ExposureScore",
    "ScoringContext",
    "build_context",
    "score_graph",
    "score_node",
]
