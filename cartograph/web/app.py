"""FastAPI app for the local web UI (loaded lazily by ``cartograph serve``).

Bind to 127.0.0.1 only – this server fires recon requests at public sources and must not be exposed.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from cartograph.web.service import ScanOptions, is_valid_domain, run_scan
from cartograph.web.templates import INDEX_HTML

_MAX_ARTIFACTS = 50


class ScanRequest(BaseModel):
    domain: str
    score: bool = True
    max_hosts: int = Field(default=60, ge=1, le=500)
    max_ips: int = Field(default=60, ge=1, le=500)
    include_endpoints: bool = False


def create_app() -> FastAPI:
    app = FastAPI(title="Cartograph", docs_url=None, redoc_url=None)
    artifacts: dict[str, dict[str, str]] = {}

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return INDEX_HTML

    @app.post("/api/scan")
    async def scan(req: ScanRequest) -> dict[str, Any]:
        if not is_valid_domain(req.domain):
            raise HTTPException(status_code=400, detail="Enter a bare domain like example.com")
        opts = ScanOptions(
            score=req.score,
            max_hosts=req.max_hosts,
            max_ips=req.max_ips,
            include_endpoints=req.include_endpoints,
        )
        try:
            result = await run_scan(req.domain, opts)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except TimeoutError as exc:
            raise HTTPException(
                status_code=504,
                detail="Collection timed out – try lower max hosts/IPs, or retry (the cache is warm now).",
            ) from exc

        sid = uuid.uuid4().hex[:12]
        artifacts[sid] = {"html": result.graph_html, "json": result.graph_json}
        for stale in list(artifacts)[:-_MAX_ARTIFACTS]:  # bound memory
            artifacts.pop(stale, None)

        return {
            "id": sid,
            "domain": result.domain,
            "node_count": result.node_count,
            "graph_html": result.graph_html,
            "top": result.top,
            "takeover": result.takeover,
            "clusters": result.clusters,
        }

    @app.get("/download/{sid}.html")
    async def download_html(sid: str) -> Response:
        art = artifacts.get(sid)
        if art is None:
            raise HTTPException(status_code=404, detail="result expired")
        return HTMLResponse(
            art["html"],
            headers={"Content-Disposition": f'attachment; filename="cartograph-{sid}.html"'},
        )

    @app.get("/download/{sid}.json")
    async def download_json(sid: str) -> Response:
        art = artifacts.get(sid)
        if art is None:
            raise HTTPException(status_code=404, detail="result expired")
        return Response(
            art["json"],
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="cartograph-{sid}.json"'},
        )

    return app
