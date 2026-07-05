"""Terminal reports for scoring and analytics."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from cartograph.analysis.centrality import CentralityEntry
from cartograph.analysis.clusters import Cluster
from cartograph.analysis.diff import GraphDiff
from cartograph.analysis.takeover import TakeoverCandidate
from cartograph.scoring.model import ExposureScore


def render_top_exposed(scores: list[ExposureScore], *, top: int = 15, console: Console | None = None) -> None:
    console = console or Console()
    ranked = [s for s in scores if s.exposure > 0][:top]
    if not ranked:
        console.print("[dim]No exposure signals found.[/dim]")
        return
    table = Table(title=f"Top exposed assets (of {len(scores)} scored)", show_edge=False)
    table.add_column("Score", justify="right", style="bold red")
    table.add_column("Host", style="cyan")
    table.add_column("Reasons", style="dim")
    for s in ranked:
        table.add_row(f"{s.exposure:.0f}", s.host, "; ".join(s.reasons[:3]))
    console.print(table)


def render_takeover(candidates: list[TakeoverCandidate], *, console: Console | None = None) -> None:
    console = console or Console()
    if not candidates:
        console.print("[green]No subdomain-takeover candidates found.[/green]")
        return
    table = Table(title="Subdomain-takeover candidates (verify manually)", show_edge=False)
    table.add_column("Host", style="cyan")
    table.add_column("CNAME", style="yellow")
    table.add_column("Provider", style="magenta")
    for c in candidates:
        table.add_row(c.host, c.cname, c.provider)
    console.print(table)
    console.print("[dim]Heuristic only – confirm with authorization before acting.[/dim]")


def render_clusters(clusters: list[Cluster], *, top: int = 10, console: Console | None = None) -> None:
    console = console or Console()
    if not clusters:
        console.print("[dim]No shared-infrastructure clusters found.[/dim]")
        return
    table = Table(title="Shared-infrastructure clusters", show_edge=False)
    table.add_column("Size", justify="right", style="green")
    table.add_column("Hosts", style="cyan")
    table.add_column("Linked via", style="dim")
    for c in clusters[:top]:
        hosts = ", ".join(c.hosts[:5]) + (" …" if len(c.hosts) > 5 else "")
        via = ", ".join(c.linked_via[:3]) + (" …" if len(c.linked_via) > 3 else "")
        table.add_row(str(c.size), hosts, via)
    console.print(table)


def render_centrality(entries: list[CentralityEntry], *, console: Console | None = None) -> None:
    console = console or Console()
    if not entries:
        console.print("[dim]Empty graph.[/dim]")
        return
    table = Table(title="Most central nodes", show_edge=False)
    table.add_column("Degree", justify="right", style="green")
    table.add_column("Betweenness", justify="right", style="green")
    table.add_column("Type", style="magenta")
    table.add_column("Node", style="cyan")
    for e in entries:
        table.add_row(f"{e.degree:.3f}", f"{e.betweenness:.3f}", e.node_type, e.value)
    console.print(table)


def render_diff(diff: GraphDiff, *, console: Console | None = None) -> None:
    console = console or Console()
    if diff.is_empty:
        console.print("[green]No changes between snapshots.[/green]")
        return
    console.print(
        f"[bold green]+{len(diff.added_nodes)}[/bold green] nodes, "
        f"[bold red]-{len(diff.removed_nodes)}[/bold red] nodes, "
        f"[bold green]+{len(diff.added_edges)}[/bold green] edges, "
        f"[bold red]-{len(diff.removed_edges)}[/bold red] edges"
    )
    for nid in diff.added_nodes[:30]:
        console.print(f"  [green]+[/green] {nid}")
    for nid in diff.removed_nodes[:30]:
        console.print(f"  [red]-[/red] {nid}")
