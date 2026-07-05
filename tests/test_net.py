"""Tests for shared HTTP plumbing: retry semantics."""

from __future__ import annotations

from pathlib import Path

import httpx
import respx

from cartograph.cache import ResponseCache
from cartograph.collectors.ct import CertificateTransparencyCollector


@respx.mock
async def test_retries_on_transient_502_then_succeeds(tmp_path: Path) -> None:
    route = respx.get(host="crt.sh").mock(
        side_effect=[
            httpx.Response(502),
            httpx.Response(200, json=[{"id": 1, "name_value": "a.example.com"}]),
        ]
    )
    collector = CertificateTransparencyCollector(cache=ResponseCache(tmp_path / "c"), min_interval=0.0, backoff=0.0)
    try:
        result = await collector.collect("example.com")
    finally:
        await collector.aclose()

    assert route.call_count == 2  # first 502 retried, second 200 used
    assert any(n.value == "a.example.com" for n in result.nodes)


@respx.mock
async def test_gives_up_after_retries(tmp_path: Path) -> None:
    respx.get(host="crt.sh").mock(return_value=httpx.Response(503))
    collector = CertificateTransparencyCollector(
        cache=ResponseCache(tmp_path / "c"), min_interval=0.0, backoff=0.0, retries=1
    )
    try:
        raised = False
        try:
            await collector.collect("example.com")
        except httpx.HTTPStatusError:
            raised = True
    finally:
        await collector.aclose()
    assert raised  # persistent 503 eventually surfaces as an error (caught by the pipeline)
