"""Tests for the RDAP collector (registration data -> org graph)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cartograph.cache import ResponseCache
from cartograph.collectors.rdap import RdapCollector
from cartograph.graph.model import EdgeType, NodeType

RDAP_PAYLOAD: dict[str, Any] = {
    "objectClassName": "domain",
    "ldhName": "example.com",
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
    ],
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Example Inc."],
                    ["org", {}, "text", "Example Organization"],
                ],
            ],
        }
    ],
}


def _collector(tmp_path: Path) -> RdapCollector:
    return RdapCollector(cache=ResponseCache(tmp_path / "cache"))


def test_parse_extracts_registrant_org(tmp_path: Path) -> None:
    result = _collector(tmp_path).parse("example.com", RDAP_PAYLOAD)
    orgs = [n for n in result.nodes if n.type is NodeType.ORG]
    assert [o.value for o in orgs] == ["Example Organization"]


def test_parse_emits_registered_by_edge(tmp_path: Path) -> None:
    result = _collector(tmp_path).parse("example.com", RDAP_PAYLOAD)
    assert any(e.type is EdgeType.REGISTERED_BY for e in result.edges)


def test_parse_stores_registration_events_on_domain(tmp_path: Path) -> None:
    result = _collector(tmp_path).parse("example.com", RDAP_PAYLOAD)
    domain = next(n for n in result.nodes if n.type is NodeType.DOMAIN)
    assert domain.attrs.get("rdap_registration") == "1995-08-14T04:00:00Z"
    assert domain.attrs.get("rdap_expiration") == "2027-08-13T04:00:00Z"


def test_parse_handles_missing_payload(tmp_path: Path) -> None:
    result = _collector(tmp_path).parse("example.com", None)
    # still yields the domain node, no org, no crash
    assert [n.value for n in result.nodes] == ["example.com"]
    assert not result.edges


def test_parse_falls_back_to_fn_when_no_org(tmp_path: Path) -> None:
    payload = {
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Just A Name"]],
                ],
            }
        ]
    }
    result = _collector(tmp_path).parse("example.com", payload)
    orgs = [n for n in result.nodes if n.type is NodeType.ORG]
    assert [o.value for o in orgs] == ["Just A Name"]
