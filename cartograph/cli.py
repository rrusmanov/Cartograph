"""Cartograph command-line interface."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler

from cartograph import __version__
from cartograph.analysis import (
    centrality_ranking,
    diff_graphs,
    shared_infrastructure_clusters,
    takeover_candidates,
)
from cartograph.graph.model import AssetGraph
from cartograph.pipeline import (
    PipelineConfig,
    build_collectors,
    build_enrichers,
    run_pipeline,
)
from cartograph.render import (
    render_centrality,
    render_clusters,
    render_diff,
    render_html,
    render_summary,
    render_takeover,
    render_top_exposed,
)
from cartograph.scoring import score_graph

app = typer.Typer(
    add_completion=False,
    help="Graph-based, passive attack-surface intelligence.",
)
console = Console()


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_time=False, show_path=False, markup=True)],
    )


@app.command()
def collect(
    target: str = typer.Argument(..., help="Root domain, e.g. example.com"),
    out: Path = typer.Option(
        Path("out") / "graph.cartograph.json",
        "--out",
        "-o",
        help="Where to write the graph JSON.",
    ),
    cache_dir: str = typer.Option(".cache", help="Directory for the response cache."),
    min_interval: float = typer.Option(1.0, help="Minimum seconds between live requests (rate-limit politeness)."),
    graphml: bool = typer.Option(False, "--graphml", help="Also export a .graphml file."),
    ct: bool = typer.Option(True, help="Certificate Transparency collector."),
    rdap: bool = typer.Option(True, help="RDAP registration-data collector."),
    wayback: bool = typer.Option(True, help="Wayback historical-endpoint collector."),
    doh: bool = typer.Option(True, help="DoH resolver enrichment (host -> IP, key-less)."),
    pdns: bool = typer.Option(False, help="Mnemonic passive-DNS enrichment (now paid / 402)."),
    asn: bool = typer.Option(True, help="ASN enrichment (IP -> AS)."),
    max_hosts: int = typer.Option(200, help="Max hosts to resolve via passive DNS."),
    max_ips: int = typer.Option(200, help="Max IPs to map to ASNs."),
    score: bool = typer.Option(False, "--score", help="Compute exposure scores and show top assets."),
    html: Path | None = typer.Option(None, "--html", help="Also render an interactive HTML graph."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
) -> None:
    """Passively collect and enrich the attack surface of TARGET, then write the graph."""
    _setup_logging(verbose)
    config = PipelineConfig(
        use_ct=ct,
        use_rdap=rdap,
        use_wayback=wayback,
        use_doh=doh,
        use_pdns=pdns,
        use_asn=asn,
        cache_dir=cache_dir,
        min_interval=min_interval,
        max_hosts=max_hosts,
        max_ips=max_ips,
    )
    collectors = build_collectors(config)
    enrichers = build_enrichers(config)
    sources = [c.name for c in collectors] + [e.name for e in enrichers]
    console.print(f"[cyan]Mapping[/cyan] {target} using: {', '.join(sources)}")

    async def _run() -> AssetGraph:
        try:
            return await run_pipeline(target, collectors, enrichers, config)
        finally:
            await asyncio.gather(*(f.aclose() for f in [*collectors, *enrichers]))

    graph = asyncio.run(_run())

    exposure = score_graph(graph) if score else []

    out.parent.mkdir(parents=True, exist_ok=True)
    graph.to_json(out)
    console.print(f"[green]Wrote[/green] {out}  ({len(graph)} nodes)")
    if graphml:
        gpath = out.with_suffix(".graphml")
        graph.to_graphml(gpath)
        console.print(f"[green]Wrote[/green] {gpath}")

    for name, stats in config.enrich_stats.items():
        console.print(f"[dim]enrich[/dim] {name}: +{stats.nodes_added} nodes, +{stats.edges_added} edges")

    if score:
        render_top_exposed(exposure, console=console)

    if html is not None:
        drawn = render_html(graph, html)
        console.print(f"[green]Wrote[/green] {html}  ({drawn} nodes drawn)")

    if len(graph) == 0:
        console.print(
            "[yellow]No assets collected.[/yellow] Every source failed or returned nothing – "
            "check your network/proxy, or retry (public sources like crt.sh are often rate-limited). "
            "Run with [bold]-v[/bold] to see per-source errors."
        )
    render_summary(graph, console=console)


@app.command()
def show(
    path: Path = typer.Argument(..., help="Path to a saved *.cartograph.json graph."),
) -> None:
    """Print a summary of a previously saved graph."""
    if not path.exists():
        console.print(f"[red]No such file:[/red] {path}")
        raise typer.Exit(code=1)
    graph = AssetGraph.from_json(path)
    render_summary(graph, console=console)


def _load_graph(path: Path) -> AssetGraph:
    if not path.exists():
        console.print(f"[red]No such file:[/red] {path}")
        raise typer.Exit(code=1)
    return AssetGraph.from_json(path)


@app.command()
def score(
    path: Path = typer.Argument(..., help="Path to a saved *.cartograph.json graph."),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write the scored graph back to this path."),
    top: int = typer.Option(15, help="How many top assets to show."),
) -> None:
    """Compute exposure scores for a saved graph and show the most exposed assets."""
    graph = _load_graph(path)
    scores = score_graph(graph)
    render_top_exposed(scores, top=top, console=console)
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        graph.to_json(out)
        console.print(f"[green]Wrote[/green] {out}")


@app.command()
def analyze(
    path: Path = typer.Argument(..., help="Path to a saved *.cartograph.json graph."),
    takeover: bool = typer.Option(False, "--takeover", help="List subdomain-takeover candidates."),
    clusters: bool = typer.Option(False, "--clusters", help="List shared-infrastructure clusters."),
    centrality: bool = typer.Option(False, "--centrality", help="List most central nodes."),
) -> None:
    """Run graph analytics on a saved graph. With no flag, runs all analyses."""
    graph = _load_graph(path)
    run_all = not (takeover or clusters or centrality)
    if takeover or run_all:
        render_takeover(takeover_candidates(graph), console=console)
    if clusters or run_all:
        render_clusters(shared_infrastructure_clusters(graph), console=console)
    if centrality or run_all:
        render_centrality(centrality_ranking(graph), console=console)


@app.command()
def diff(
    old: Path = typer.Argument(..., help="Older graph snapshot."),
    new: Path = typer.Argument(..., help="Newer graph snapshot."),
) -> None:
    """Show what changed between two saved graph snapshots."""
    render_diff(diff_graphs(_load_graph(old), _load_graph(new)), console=console)


@app.command()
def visualize(
    path: Path = typer.Argument(..., help="Path to a saved *.cartograph.json graph."),
    out: Path = typer.Option(Path("out") / "graph.html", "--out", "-o", help="Output HTML file."),
    endpoints: bool = typer.Option(False, "--endpoints", help="Include endpoint nodes."),
    all_certs: bool = typer.Option(False, "--all-certs", help="Include all certs, not just shared."),
    max_nodes: int = typer.Option(1500, help="Cap on nodes drawn (highest-exposure kept first)."),
) -> None:
    """Render an interactive HTML visualization of a saved graph (score it first for color-coding)."""
    graph = _load_graph(path)
    drawn = render_html(graph, out, include_endpoints=endpoints, all_certs=all_certs, max_nodes=max_nodes)
    console.print(f"[green]Wrote[/green] {out}  ({drawn} nodes drawn)")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address (keep local – do not expose)."),
    port: int = typer.Option(8666, help="Port to listen on."),
) -> None:
    """Launch the local web UI: enter a domain in the browser and get the interactive map."""
    try:
        import uvicorn

        from cartograph.web.app import create_app
    except ImportError:
        console.print('[red]The web UI needs the "web" extra:[/red] pip install -e ".[web]"')
        raise typer.Exit(code=1) from None

    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            f"[yellow]Warning:[/yellow] binding to {host} exposes a recon server to the network. "
            "Use 127.0.0.1 unless you understand the risk."
        )
    console.print(f"Cartograph web UI: [cyan]http://{host}:{port}[/cyan]  (Ctrl+C to stop)")
    uvicorn.run(create_app(), host=host, port=port, log_level="warning")


@app.command()
def version() -> None:
    """Print the Cartograph version."""
    console.print(f"cartograph {__version__}")


if __name__ == "__main__":
    app()
