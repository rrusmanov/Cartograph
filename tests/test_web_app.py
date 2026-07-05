"""Smoke tests for the FastAPI routes (scan is mocked; needs the 'web' extra)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from cartograph.web import app as webapp  # noqa: E402
from cartograph.web.service import ScanOptions, ScanResult  # noqa: E402


async def _fake_scan(domain: str, opts: ScanOptions | None = None) -> ScanResult:
    return ScanResult(
        domain=domain,
        node_count=3,
        top=[{"score": 90, "host": "dev.example.com", "reasons": ["expired TLS"]}],
        takeover=[],
        clusters=[],
        graph_html="<canvas id='cv'></canvas>",
        graph_json='{"nodes": [], "edges": []}',
    )


def test_index_served() -> None:
    client = TestClient(webapp.create_app())
    r = client.get("/")
    assert r.status_code == 200
    assert "Cartograph" in r.text


def test_scan_rejects_invalid_domain() -> None:
    client = TestClient(webapp.create_app())
    r = client.post("/api/scan", json={"domain": "not a domain"})
    assert r.status_code == 400


def test_scan_and_download(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webapp, "run_scan", _fake_scan)
    client = TestClient(webapp.create_app())

    r = client.post("/api/scan", json={"domain": "example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["node_count"] == 3
    assert "<canvas" in body["graph_html"]
    assert body["top"][0]["host"] == "dev.example.com"

    sid = body["id"]
    dj = client.get(f"/download/{sid}.json")
    assert dj.status_code == 200
    assert "nodes" in dj.text
    assert client.get("/download/nonexistent.json").status_code == 404
