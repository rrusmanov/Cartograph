"""Self-contained interactive HTML graph (native canvas, no external libraries).

The full graph is a hairball of certificate/endpoint nodes, so the default view keeps hosts (colored
by exposure), the IPs/ASNs/org they touch, and only shared certificates as connectors. Layout is
computed in Python; the page does pan/zoom/click on a canvas – no CDN, works offline.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import networkx as nx

from cartograph.graph.model import AssetGraph, EdgeType, Node, NodeType

_TYPE_COLORS: dict[NodeType, str] = {
    NodeType.DOMAIN: "#1f77b4",
    NodeType.SUBDOMAIN: "#4c9be8",
    NodeType.IP: "#2ca02c",
    NodeType.ASN: "#9467bd",
    NodeType.ORG: "#8c564b",
    NodeType.CERTIFICATE: "#c7c7c7",
    NodeType.ENDPOINT: "#e377c2",
}

# priority for capping (lower = kept first)
_TYPE_PRIORITY: dict[NodeType, int] = {
    NodeType.DOMAIN: 0,
    NodeType.SUBDOMAIN: 1,
    NodeType.IP: 2,
    NodeType.ASN: 2,
    NodeType.ORG: 3,
    NodeType.CERTIFICATE: 4,
    NodeType.ENDPOINT: 5,
}


def exposure_color(score: float) -> str:
    """Map an exposure score (0–100) to a green→amber→red hex color."""
    score = max(0.0, min(100.0, score))
    if score <= 50:
        # green -> amber
        r = int(255 * (score / 50))
        g = 200
    else:
        r = 255
        g = int(200 * (1 - (score - 50) / 50))
    return f"#{r:02x}{g:02x}44"


def _shared_cert_ids(graph: AssetGraph) -> set[str]:
    deg: Counter[str] = Counter()
    for e in graph.edges():
        if e.type is EdgeType.SHARES_CERT:
            deg[e.dst] += 1
    return {cid for cid, count in deg.items() if count >= 2}


def select_visible(
    graph: AssetGraph,
    *,
    include_endpoints: bool = False,
    all_certs: bool = False,
    max_nodes: int = 1500,
) -> set[str]:
    """Choose which node ids to draw. Pure function – no rendering side effects.

    Always includes hosts, IPs, ASNs and org; includes shared certificates (degree >= 2) as
    connectors; optionally all certificates and/or endpoints. If the selection exceeds ``max_nodes``,
    keeps the highest-priority nodes (hosts by exposure first, infra next, certs/endpoints last).
    """
    shared_certs = _shared_cert_ids(graph)
    keep: list[Node] = []
    for n in graph.nodes():
        if (
            n.type in (NodeType.DOMAIN, NodeType.SUBDOMAIN, NodeType.IP, NodeType.ASN, NodeType.ORG)
            or n.type is NodeType.CERTIFICATE
            and (all_certs or n.id in shared_certs)
            or n.type is NodeType.ENDPOINT
            and include_endpoints
        ):
            keep.append(n)

    if len(keep) <= max_nodes:
        return {n.id for n in keep}

    def sort_key(n: Node) -> tuple[int, float, str]:
        exposure = float(n.attrs.get("exposure", 0.0) or 0.0)
        return (_TYPE_PRIORITY.get(n.type, 9), -exposure, n.value)

    keep.sort(key=sort_key)
    return {n.id for n in keep[:max_nodes]}


def _node_visual(node: Node) -> tuple[str, int, str]:
    """Return (color, size, hover-title) for a node."""
    exposure = node.attrs.get("exposure")
    if node.type in (NodeType.DOMAIN, NodeType.SUBDOMAIN) and exposure is not None:
        score = float(exposure)
        color = exposure_color(score)
        size = int(16 + score / 2.5)  # 16..56
        reasons = node.attrs.get("exposure_reasons", []) or []
        title = f"{node.value}\nexposure: {score:.0f}\n" + "\n".join(f"• {r}" for r in reasons[:5])
        return color, size, title
    color = _TYPE_COLORS.get(node.type, "#999999")
    size = 26 if node.type in (NodeType.ASN, NodeType.ORG) else 16
    return color, size, f"{node.value} ({node.type.value})"


def _label(node: Node) -> str:
    v = node.value
    return v if len(v) <= 42 else v[:39] + "…"


_LAYOUT_W = 2000
_LAYOUT_H = 1300
_PADDING = 60


def _layout(visible: set[str], edges: list[tuple[str, str]]) -> dict[str, tuple[float, float]]:
    """Deterministic 2D layout mapped into a fixed pixel canvas.

    Uses networkx spring layout (needs numpy); falls back to a deterministic grid if that is
    unavailable, so rendering never fails.
    """
    h: nx.Graph = nx.Graph()
    h.add_nodes_from(sorted(visible))
    for src, dst in edges:
        h.add_edge(src, dst)
    try:
        raw = nx.spring_layout(h, seed=42, iterations=50)
    except Exception:  # noqa: BLE001 - numpy missing or layout failure -> deterministic fallback
        return _grid_layout(sorted(visible))

    xs = [float(p[0]) for p in raw.values()] or [0.0]
    ys = [float(p[1]) for p in raw.values()] or [0.0]
    minx, maxx, miny, maxy = min(xs), max(xs), min(ys), max(ys)
    spanx = (maxx - minx) or 1.0
    spany = (maxy - miny) or 1.0

    pos: dict[str, tuple[float, float]] = {}
    for nid, p in raw.items():
        px = _PADDING + (float(p[0]) - minx) / spanx * (_LAYOUT_W - 2 * _PADDING)
        py = _PADDING + (float(p[1]) - miny) / spany * (_LAYOUT_H - 2 * _PADDING)
        pos[nid] = (round(px, 1), round(py, 1))
    return pos


def _resolve_collisions(
    pos: dict[str, tuple[float, float]],
    radii: dict[str, float],
    *,
    iterations: int = 60,
    gap: float = 9.0,
) -> dict[str, tuple[float, float]]:
    """Push overlapping nodes apart so circles don't cover each other.

    Grid-bucketed so it stays fast on large graphs (only neighboring cells are compared).
    """
    import math

    ids = list(pos)
    xs = {i: float(pos[i][0]) for i in ids}
    ys = {i: float(pos[i][1]) for i in ids}
    max_r = max(radii.values(), default=10.0)
    cell = 2.0 * max_r + gap

    for _ in range(iterations):
        grid: dict[tuple[int, int], list[str]] = {}
        for i in ids:
            key = (int(xs[i] // cell), int(ys[i] // cell))
            grid.setdefault(key, []).append(i)

        moved = False
        for (cx, cy), members in grid.items():
            neighbors: list[str] = []
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    neighbors.extend(grid.get((cx + dx, cy + dy), []))
            for a in members:
                for b in neighbors:
                    if b <= a:
                        continue
                    ddx = xs[b] - xs[a]
                    ddy = ys[b] - ys[a]
                    dist = math.hypot(ddx, ddy) or 0.01
                    min_dist = (radii.get(a, 6.0) + radii.get(b, 6.0)) * 1.15 + gap
                    if dist < min_dist:
                        push = (min_dist - dist) / 2.0
                        ux, uy = ddx / dist, ddy / dist
                        xs[a] -= ux * push
                        ys[a] -= uy * push
                        xs[b] += ux * push
                        ys[b] += uy * push
                        moved = True
        if not moved:
            break

    return {i: (round(xs[i], 1), round(ys[i], 1)) for i in ids}


def _grid_layout(ids: list[str]) -> dict[str, tuple[float, float]]:
    """A deterministic grid fallback layout (no numpy required)."""
    import math

    n = len(ids)
    cols = max(1, math.ceil(math.sqrt(n)))
    rows = max(1, math.ceil(n / cols))
    pos: dict[str, tuple[float, float]] = {}
    for i, nid in enumerate(ids):
        cx, cy = i % cols, i // cols
        px = _PADDING + (cx / max(1, cols - 1)) * (_LAYOUT_W - 2 * _PADDING)
        py = _PADDING + (cy / max(1, rows - 1)) * (_LAYOUT_H - 2 * _PADDING)
        pos[nid] = (round(px, 1), round(py, 1))
    return pos


def build_html(
    graph: AssetGraph,
    *,
    include_endpoints: bool = False,
    all_certs: bool = False,
    max_nodes: int = 1500,
) -> tuple[str, int]:
    """Build the self-contained interactive graph HTML. Returns ``(html, node_count)``.

    The layout is precomputed with networkx; the page draws it on a native canvas with pan/zoom and a
    click-to-inspect panel. No external libraries. Hosts are colored by exposure.
    """
    visible = select_visible(graph, include_endpoints=include_endpoints, all_certs=all_certs, max_nodes=max_nodes)
    nodes = {n.id: n for n in graph.nodes() if n.id in visible}
    edges = [(e.src, e.dst) for e in graph.edges() if e.src in visible and e.dst in visible]

    radii = {nid: float(max(4, round(_node_visual(node)[1] * 0.5))) for nid, node in nodes.items()}
    pos = _layout(visible, edges)
    pos = _resolve_collisions(pos, radii)

    node_data: list[dict[str, object]] = []
    for nid, node in nodes.items():
        color, size, _ = _node_visual(node)
        x, y = pos.get(nid, (_LAYOUT_W / 2, _LAYOUT_H / 2))
        node_data.append(
            {
                "id": nid,
                "label": _label(node),
                "x": x,
                "y": y,
                "color": color,
                "r": max(4, round(size * 0.5)),
                "info": {
                    "type": node.type.value,
                    "value": node.value,
                    "exposure": node.attrs.get("exposure"),
                    "reasons": node.attrs.get("exposure_reasons", []) or [],
                    "sources": sorted(node.sources),
                },
            }
        )

    edge_data = [{"from": s, "to": d} for s, d in edges]

    html = (
        _HTML_TEMPLATE.replace("__NODES__", json.dumps(node_data))
        .replace("__EDGES__", json.dumps(edge_data))
        .replace("__COUNT__", str(len(node_data)))
    )
    return html, len(nodes)


def render_html(
    graph: AssetGraph,
    path: str | Path,
    *,
    include_endpoints: bool = False,
    all_certs: bool = False,
    max_nodes: int = 1500,
) -> int:
    """Write the interactive graph HTML to ``path``. Returns the node count drawn."""
    html, count = build_html(graph, include_endpoints=include_endpoints, all_certs=all_certs, max_nodes=max_nodes)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return count


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cartograph – attack-surface graph</title>
<style>
  html,body{margin:0;height:100%;background:#0e1116;color:#e6edf3;font-family:Segoe UI,Arial,sans-serif}
  #net{position:absolute;top:0;left:0;right:340px;bottom:0}
  #cv{width:100%;height:100%;display:block;cursor:grab}
  #cv.drag{cursor:grabbing}
  #side{position:absolute;top:0;right:0;bottom:0;width:340px;box-sizing:border-box;
        padding:16px;background:#161b22;border-left:1px solid #30363d;overflow:auto}
  #side h1{font-size:15px;margin:0 0 4px;color:#58a6ff}
  #side .hint{font-size:12px;color:#8b949e;margin-bottom:14px}
  #info h2{font-size:15px;margin:0 0 2px;word-break:break-all}
  #info .type{display:inline-block;font-size:11px;color:#8b949e;text-transform:uppercase;margin-bottom:8px}
  #info .exp{font-weight:700;margin:6px 0}
  #info ul{padding-left:18px;margin:6px 0}
  #info li{margin:2px 0;font-size:13px}
  #info .src{font-size:11px;color:#8b949e;margin-top:10px;word-break:break-all}
  .legend{margin-top:16px;font-size:12px;color:#8b949e}
  .legend span{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
</style>
</head>
<body>
<div id="net"><canvas id="cv"></canvas></div>
<div id="side">
  <h1>Cartograph</h1>
  <div class="hint">__COUNT__ nodes · click a node for details · scroll to zoom · drag to pan</div>
  <div id="info"><div class="hint">No node selected.</div></div>
  <div class="legend">
    <div><span style="background:#ff4444"></span>high exposure &nbsp; <span style="background:#c8c844"></span>medium &nbsp; <span style="background:#00c844"></span>low</div>
    <div style="margin-top:6px"><span style="background:#2ca02c"></span>IP &nbsp; <span style="background:#9467bd"></span>ASN &nbsp; <span style="background:#c7c7c7"></span>cert &nbsp; <span style="background:#8c564b"></span>org</div>
  </div>
</div>
<script>
  const NODES = __NODES__;
  const EDGES = __EDGES__;
  const byId = {}; NODES.forEach(n => byId[n.id] = n);
  const cv = document.getElementById("cv");
  const ctx = cv.getContext("2d");
  let zoom = 1, panX = 0, panY = 0;

  function resize() {
    cv.width = cv.clientWidth; cv.height = cv.clientHeight; draw();
  }
  function fit() {
    let minx = Infinity, miny = Infinity, maxx = -Infinity, maxy = -Infinity;
    NODES.forEach(n => { minx = Math.min(minx, n.x); miny = Math.min(miny, n.y);
                         maxx = Math.max(maxx, n.x); maxy = Math.max(maxy, n.y); });
    if (!isFinite(minx)) { minx = 0; miny = 0; maxx = 1; maxy = 1; }
    const gw = (maxx - minx) || 1, gh = (maxy - miny) || 1;
    // >1 fills the viewport tightly (a touch zoomed-in by default)
    zoom = Math.min(cv.width / gw, cv.height / gh) * 1.05;
    const cx = (minx + maxx) / 2, cy = (miny + maxy) / 2;
    panX = cv.width / 2 - cx * zoom;
    panY = cv.height / 2 - cy * zoom;
  }
  function draw() {
    ctx.clearRect(0, 0, cv.width, cv.height);
    ctx.lineWidth = 1; ctx.strokeStyle = "rgba(130,140,160,0.20)";
    ctx.beginPath();
    EDGES.forEach(e => {
      const a = byId[e.from], b = byId[e.to]; if (!a || !b) return;
      ctx.moveTo(a.x * zoom + panX, a.y * zoom + panY);
      ctx.lineTo(b.x * zoom + panX, b.y * zoom + panY);
    });
    ctx.stroke();
    NODES.forEach(n => {
      const sx = n.x * zoom + panX, sy = n.y * zoom + panY, r = Math.max(2, n.r * zoom);
      ctx.beginPath(); ctx.fillStyle = n.color; ctx.arc(sx, sy, r, 0, 6.2832); ctx.fill();
    });
    if (zoom > 0.85) {
      ctx.fillStyle = "#c9d1d9"; ctx.font = "12px Segoe UI";
      NODES.forEach(n => {
        if (n.r >= 9 || zoom > 1.4) {
          const sx = n.x * zoom + panX, sy = n.y * zoom + panY;
          ctx.fillText(n.label, sx + n.r * zoom + 3, sy + 4);
        }
      });
    }
  }

  const rel = e => { const b = cv.getBoundingClientRect(); return { x: e.clientX - b.left, y: e.clientY - b.top }; };
  let drag = null, moved = false;
  cv.addEventListener("mousedown", e => { const p = rel(e); drag = { x: p.x, y: p.y, px: panX, py: panY }; moved = false; cv.classList.add("drag"); });
  window.addEventListener("mousemove", e => {
    if (!drag) return; const p = rel(e); const dx = p.x - drag.x, dy = p.y - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) moved = true;
    panX = drag.px + dx; panY = drag.py + dy; draw();
  });
  window.addEventListener("mouseup", () => { drag = null; cv.classList.remove("drag"); });
  cv.addEventListener("wheel", e => {
    e.preventDefault(); const p = rel(e); const f = e.deltaY < 0 ? 1.12 : 0.89;
    panX = p.x - (p.x - panX) * f; panY = p.y - (p.y - panY) * f; zoom *= f; draw();
  }, { passive: false });

  const esc = s => String(s).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  function showInfo(i) {
    const info = document.getElementById("info");
    let h = '<h2>' + esc(i.value) + '</h2><div class="type">' + esc(i.type) + '</div>';
    if (i.exposure !== null && i.exposure !== undefined) h += '<div class="exp">exposure: ' + i.exposure + ' / 100</div>';
    if (i.reasons && i.reasons.length) h += '<ul>' + i.reasons.map(r => '<li>' + esc(r) + '</li>').join('') + '</ul>';
    if (i.sources && i.sources.length) h += '<div class="src">sources: ' + i.sources.map(esc).join(', ') + '</div>';
    info.innerHTML = h;
  }
  cv.addEventListener("click", e => {
    if (moved) return; const p = rel(e);
    const wx = (p.x - panX) / zoom, wy = (p.y - panY) / zoom;
    let best = null, bd = Infinity;
    NODES.forEach(n => { const d = (n.x - wx) ** 2 + (n.y - wy) ** 2; if (d < bd) { bd = d; best = n; } });
    if (best && Math.sqrt(bd) <= Math.max(7, best.r) + 4) showInfo(best.info);
  });

  window.addEventListener("resize", resize);
  resize(); fit(); draw();
</script>
</body>
</html>
"""
