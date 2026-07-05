# Design – Local Web UI (`cartograph serve`)

**Status:** DRAFT – awaiting sign-off. No code until approved.
**Goal:** a browser front-end where you type a domain and get the interactive graph + findings, wrapping
the existing passive pipeline. **Not** a public service – local-only by design.

## 1. Problem / scope

Today the tool is CLI-only. A small local web app makes it demo-friendly: enter a domain → see the graph,
the top exposed assets, takeover candidates and clusters, with download buttons. This is a thin UI over
existing building blocks (`run_pipeline`, `score_graph`, `render_html`, analytics) – no new analysis.

**In scope (MVP):** one page with a form; on submit, run the passive pipeline synchronously (browser shows
a spinner), then render results. **Out of scope:** background jobs, scan history, live per-source progress,
accounts, any public/remote hosting, any active scanning.

## 2. Security (by design)

- Binds to **127.0.0.1 only** (configurable host, but documented as local-use). Never `0.0.0.0` by default.
- Passive pipeline only (same as CLI default); the active module stays off and scope-guarded.
- Input is a single domain, validated (basic hostname regex) before use.
- Rationale stated in the UI and README: a server that fires recon requests must not be exposed, to avoid
  becoming an SSRF/abuse relay against public sources.

## 3. UX flow

1. `GET /` – page with: domain input; options (score on/off, max hosts, max IPs, include endpoints).
2. Submit → JS `fetch POST /api/scan` with the form; page shows a spinner ("collecting… this takes a
   minute"). Long request is acceptable for localhost; a generous client timeout is set.
3. Response renders:
   - **Interactive graph** (the existing canvas HTML, embedded via `<iframe srcdoc>`).
   - **Top exposure table** (score · host · reasons).
   - **Takeover candidates** and **shared-infra clusters** (tables).
   - **Download** buttons: graph HTML and graph JSON.

## 4. Architecture

```
cartograph/web/
├── app.py        # FastAPI app: routes GET / , POST /api/scan , GET /download/{id}
├── service.py    # pure-ish: run scan -> ScanResult (graph, top, takeover, clusters, html, json)
└── templates.py  # the index page HTML (inline, self-contained, no CDN)
cli.py            # new `cartograph serve [--host 127.0.0.1] [--port 8666]`
```

- `service.run_scan(domain, opts) -> ScanResult` orchestrates `run_pipeline` + `score_graph` +
  `render_html` + analytics, and stores artifacts (JSON/HTML) under a per-scan id in a temp dir.
- Routes are thin; `POST /api/scan` returns JSON: `{graph_html, top: [...], takeover: [...],
  clusters: [...], download_json, download_html}`. Frontend renders tables from that JSON.
- Reuses everything; the only new logic is assembling the web payload (which is unit-tested).

## 5. Stack & dependencies

- **FastAPI** + **uvicorn**, added as an optional extra `[web]` (kept out of the core install).
- FastAPI's async model matches the async pipeline (`await run_pipeline(...)` directly in the handler).
- No front-end framework or CDN: the page is inline HTML/JS; the graph reuses the dependency-free canvas
  renderer.

## 6. Testing

- Unit-test `service.run_scan` against a **mocked pipeline** (respx) so it needs no network: assert the
  ScanResult contains a graph, a non-empty top table when signals exist, and valid download artifacts.
- Test the payload builder (graph → top/takeover/clusters JSON) with a crafted graph.
- Route smoke test with FastAPI `TestClient` (mocked pipeline). Keep the strict-mypy + ruff + pytest gate
  green (FastAPI/uvicorn go in the `[web]`/`[dev]` extra; mypy config adjusted).

## 7. Build plan

- **W1** – `service.run_scan` + payload builder + tests (mocked). No web server yet.
- **W2** – FastAPI app (routes), inline index template, `cartograph serve` command.
- **W3** – Polish: spinner/error states, download endpoints, README section + screenshot.

## 8. Open questions

1. **Port** – default `8666` ok, or prefer `8000`?
2. **Result scope for active** – keep the UI strictly passive (recommended), or later add a clearly-labelled,
   scope-guarded active toggle? (I recommend passive-only for now.)
3. **Caps in the form** – expose max-hosts/max-ips to the user (default e.g. 60/60 for snappy scans), or hide
   them with sensible fixed defaults?

---

**Sign-off:** on your "да" (+ answers to §8) I build W1 first (service + tests, no server), same test-first
cadence. Nothing runs a server until the service layer is tested.
