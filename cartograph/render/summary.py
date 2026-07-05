"""Human-readable summary of an AssetGraph for the terminal."""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.table import Table

from cartograph.graph.model import AssetGraph, NodeType


def render_summary(graph: AssetGraph, *, console: Console | None = None) -> None:
    """Print node/edge type breakdowns and a sample of discovered subdomains."""
    console = console or Console()

    node_counts: Counter[str] = Counter(n.type.value for n in graph.nodes())
    edge_counts: Counter[str] = Counter(e.type.value for e in graph.edges())

    table = Table(title="Attack-surface graph summary", show_edge=False)
    table.add_column("Node type", style="cyan")
    table.add_column("Count", justify="right", style="green")
    for node_type in NodeType:
        table.add_row(node_type.value, str(node_counts.get(node_type.value, 0)))
    table.add_row("[bold]total nodes[/bold]", f"[bold]{len(graph)}[/bold]")
    console.print(table)

    if edge_counts:
        etable = Table(title="Relationships", show_edge=False)
        etable.add_column("Edge type", style="magenta")
        etable.add_column("Count", justify="right", style="green")
        for etype, count in edge_counts.most_common():
            etable.add_row(etype, str(count))
        console.print(etable)

    subs = [n.value for n in graph.nodes_by_type(NodeType.SUBDOMAIN)]
    if subs:
        console.print(f"\n[bold]{len(subs)}[/bold] subdomains discovered. Sample:")
        for value in subs[:15]:
            console.print(f"  • {value}")
        if len(subs) > 15:
            console.print(f"  … and {len(subs) - 15} more")
