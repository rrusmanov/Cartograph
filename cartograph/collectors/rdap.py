"""RDAP registration data (via rdap.org): registrant org + registration/expiration dates.

Adds an ``org`` node and a ``registered_by`` edge so the graph can group domains by registrant.
"""

from __future__ import annotations

from typing import Any

from cartograph.collectors.base import Collector, CollectResult
from cartograph.graph.model import Edge, EdgeType, Node, NodeType

RDAP_URL = "https://rdap.org/domain/{domain}"


class RdapCollector(Collector):
    """Passive registration-data collection via RDAP."""

    name = "rdap"

    async def collect(self, target: str) -> CollectResult:
        target = target.strip().rstrip(".").lower()
        payload = await self.get_json(
            RDAP_URL.format(domain=target),
            cache_key=f"rdap:{target}",
            allow_status=(404,),
        )
        return self.parse(target, payload)

    def parse(self, target: str, payload: Any) -> CollectResult:
        """Pure transformation of an RDAP response into graph fragments."""
        result = CollectResult(raw=payload)
        events = self._events(payload) if isinstance(payload, dict) else {}
        domain = Node(
            type=NodeType.DOMAIN,
            value=target,
            sources={self.name},
            attrs={k: v for k, v in events.items() if v},
        )
        result.nodes.append(domain)

        if not isinstance(payload, dict):
            return result

        org_name = self._registrant_org(payload)
        if org_name:
            org = Node(type=NodeType.ORG, value=org_name, sources={self.name})
            result.nodes.append(org)
            result.edges.append(
                Edge(
                    src=domain.id,
                    dst=org.id,
                    type=EdgeType.REGISTERED_BY,
                    sources={self.name},
                )
            )
        return result

    @staticmethod
    def _events(payload: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for ev in payload.get("events", []) or []:
            if not isinstance(ev, dict):
                continue
            action = str(ev.get("eventAction", "")).replace(" ", "_")
            date = ev.get("eventDate")
            if action and date:
                out[f"rdap_{action}"] = date
        return out

    @staticmethod
    def _registrant_org(payload: dict[str, Any]) -> str | None:
        """Extract an organization name from the registrant (or first) entity's vCard."""
        entities = payload.get("entities")
        if not isinstance(entities, list):
            return None

        def org_from_entity(entity: dict[str, Any]) -> str | None:
            vcard = entity.get("vcardArray")
            # vCard jCard shape: ["vcard", [ [name, params, type, value], ... ]]
            if not (isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list)):
                return None
            org: str | None = None
            fn: str | None = None
            for field in vcard[1]:
                if not (isinstance(field, list) and len(field) >= 4):
                    continue
                key = str(field[0]).lower()
                value = field[3]
                text = value if isinstance(value, str) else None
                if key == "org" and text:
                    org = text
                elif key == "fn" and text:
                    fn = text
            return org or fn

        # prefer an entity explicitly marked as registrant
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            roles = [str(r).lower() for r in entity.get("roles", []) or []]
            if "registrant" in roles:
                name = org_from_entity(entity)
                if name:
                    return name.strip()
        # fall back to the first entity carrying an org/fn
        for entity in entities:
            if isinstance(entity, dict):
                name = org_from_entity(entity)
                if name:
                    return name.strip()
        return None
