"""Tests for the web scan service (mocked pipeline; no FastAPI, no network)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from cartograph.web.service import ScanOptions, is_valid_domain, run_scan

CT_ROWS: list[dict[str, Any]] = [
    {
        "id": 1,
        "issuer_name": "CN=R3",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com\ndev.example.com",
        "not_after": "2020-01-01T00:00:00",
    }
]
RDAP_PAYLOAD = {"entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["org", {}, "text", "Example Org"]]]}]}
CDX_ROWS = [["original"], ["https://www.example.com/app"]]
DOH_PAYLOAD = {"Status": 0, "Answer": [{"name": "www.example.com", "type": 1, "data": "93.184.216.34"}]}
RIPESTAT_PAYLOAD = {"status": "ok", "data": {"resource": "93.184.216.0/24", "asns": [{"asn": 15133}]}}


def _install() -> None:
    respx.get(host="crt.sh").mock(return_value=httpx.Response(200, json=CT_ROWS))
    respx.get(host="rdap.org").mock(return_value=httpx.Response(200, json=RDAP_PAYLOAD))
    respx.get(host="web.archive.org").mock(return_value=httpx.Response(200, json=CDX_ROWS))
    respx.get(host="cloudflare-dns.com").mock(return_value=httpx.Response(200, json=DOH_PAYLOAD))
    respx.get(host="stat.ripe.net").mock(return_value=httpx.Response(200, json=RIPESTAT_PAYLOAD))


def test_is_valid_domain() -> None:
    assert is_valid_domain("example.com")
    assert is_valid_domain("a.b.example.co")
    assert not is_valid_domain("http://example.com")
    assert not is_valid_domain("example")
    assert not is_valid_domain("example.com/path")
    assert not is_valid_domain("1.2.3.4")


async def test_run_scan_rejects_invalid_domain() -> None:
    with pytest.raises(ValueError):
        await run_scan("not a domain")


@respx.mock
async def test_run_scan_assembles_result(tmp_path: Path) -> None:
    _install()
    opts = ScanOptions(cache_dir=str(tmp_path / "c"), min_interval=0.0)
    result = await run_scan("example.com", opts)

    assert result.domain == "example.com"
    assert result.node_count > 0
    assert "<canvas" in result.graph_html  # embedded interactive graph
    assert "example.com" in result.graph_json  # serialized graph
    assert len(result.top) > 0  # expired certs -> scored hosts
    assert all({"score", "host", "reasons"} <= set(row) for row in result.top)
