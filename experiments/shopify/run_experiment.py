"""Reproducible M4 experiment for Cartograph, on a saved (scored) attack-surface graph.

Runs entirely offline from a saved graph JSON – no network, deterministic. Reports:
  * connectivity a flat host list cannot express (RQ1),
  * prioritization: precision@k and lift-over-random of the exposure ranking (RQ2),
  * determinism of scoring and per-source ablation (RQ3).

Usage:
    python experiments/shopify/run_experiment.py [path/to/graph.json]

Writes ``results.json`` (and ``precision_at_k.png`` if matplotlib is installed) next to this file.
Produce the input first, e.g.:
    cartograph collect shopify.com --score -o out/shopify.json
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cartograph.evaluation import (
    all_sources,
    base_rate,
    connectivity_report,
    host_ids,
    interesting_host_ids,
    lift_at_k,
    precision_at_k,
    source_ablation,
)
from cartograph.graph.model import AssetGraph
from cartograph.scoring.model import score_graph

K_VALUES = [5, 10, 20, 50, 100]
HERE = Path(__file__).resolve().parent


def run(graph_path: Path) -> dict[str, object]:
    graph = AssetGraph.from_json(graph_path)
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    # --- RQ2: prioritization (single `now` shared by ranking and the interesting label) ---
    ranked = [s.node_id for s in score_graph(graph, now=now, write_back=False)]
    interesting = interesting_host_ids(graph, now=now)
    hosts = host_ids(graph)
    br = base_rate(interesting, hosts)
    prioritization = {
        "base_rate": round(br, 4),
        "interesting_hosts": len(interesting),
        "total_hosts": len(hosts),
        "precision_at_k": {k: round(precision_at_k(ranked, interesting, k), 4) for k in K_VALUES},
        "lift_at_k": {k: round(lift_at_k(ranked, interesting, hosts, k), 2) for k in K_VALUES},
    }

    # --- RQ1: connectivity ---
    connectivity = connectivity_report(graph)

    # --- RQ3: determinism (re-score, compare rankings) ---
    ranked2 = [s.node_id for s in score_graph(graph, now=now, write_back=False)]
    determinism = {"deterministic": ranked == ranked2}

    # --- RQ3: per-source ablation (offline, from provenance) ---
    ablation = {src: source_ablation(graph, src) for src in all_sources(graph)}

    return {
        "input": str(graph_path),
        "connectivity": connectivity,
        "prioritization": prioritization,
        "determinism": determinism,
        "ablation": ablation,
    }


def _print(results: dict[str, object]) -> None:
    c = results["connectivity"]  # type: ignore[assignment]
    p = results["prioritization"]  # type: ignore[assignment]
    print("\n=== Connectivity (RQ1) – structure absent from a flat host list ===")
    print(f"  hosts: {c['hosts']}   total nodes: {c['total_nodes']}   total edges: {c['total_edges']}")
    print(f"  typed edges: {c['typed_edges']}")
    print(f"  shared-cert clusters: {c['shared_cert_clusters']}")
    print(f"  takeover candidates:  {c['takeover_candidates']}")

    print("\n=== Prioritization (RQ2) – exposure ranking vs random ===")
    print(f"  base rate (interesting/all): {p['base_rate']}  ({p['interesting_hosts']}/{p['total_hosts']})")
    print(f"  {'k':>5} {'precision@k':>12} {'lift':>8}")
    for k in K_VALUES:
        print(f"  {k:>5} {p['precision_at_k'][k]:>12} {p['lift_at_k'][k]:>8}")

    print("\n=== Determinism (RQ3) ===")
    print(f"  scoring deterministic: {results['determinism']['deterministic']}")  # type: ignore[index]

    print("\n=== Source ablation (RQ3) – unique contribution per source ===")
    print(f"  {'source':>10} {'hosts_lost':>11} {'edges_lost':>11}")
    for src, a in results["ablation"].items():  # type: ignore[union-attr]
        print(f"  {src:>10} {a['hosts_lost']:>11} {a['edges_lost']:>11}")


def _plot(results: dict[str, object]) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n(matplotlib not installed – skipping precision_at_k.png; pip install matplotlib)")
        return
    p = results["prioritization"]  # type: ignore[assignment]
    ks = K_VALUES
    prec = [p["precision_at_k"][k] for k in ks]
    br = p["base_rate"]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(ks, prec, marker="o", label="precision@k (Cartograph ranking)")
    ax.axhline(br, ls="--", color="gray", label=f"base rate (random) = {br}")
    ax.set_xlabel("k (top-ranked hosts)")
    ax.set_ylabel("fraction interesting")
    ax.set_title("Exposure ranking concentrates flagged hosts")
    ax.set_ylim(0, 1)
    ax.legend()
    fig.tight_layout()
    fig.savefig(HERE / "precision_at_k.png", dpi=130)
    print(f"\nWrote {HERE / 'precision_at_k.png'}")


def main() -> None:
    graph_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/shopify.json")
    if not graph_path.exists():
        print(f"Graph not found: {graph_path}\nRun: cartograph collect shopify.com --score -o {graph_path}")
        raise SystemExit(1)

    results = run(graph_path)
    _print(results)
    (HERE / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nWrote {HERE / 'results.json'}")
    _plot(results)


if __name__ == "__main__":
    main()
