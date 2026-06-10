import re
import time
from datetime import datetime, timezone

import httpx

from app.config import settings

_LABEL_TS_RE = re.compile(r"_(\d+)$")

_API_BASE = "https://api.linode.com/v4"


def _auth_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {settings.linode_token}",
        "Content-Type": "application/json",
    }


async def get_firewall_rules() -> dict:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{_API_BASE}/networking/firewalls/{settings.firewall_id}/rules",
            headers=_auth_headers(),
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()


async def add_inbound_rule(ip: str, label: str) -> dict:
    current = await get_firewall_rules()

    inbound: list[dict] = current.get("inbound", [])

    for rule in inbound:
        if ip in rule.get("addresses", {}).get("ipv4", []):
            existing_label = rule.get("label", "")
            match = _LABEL_TS_RE.search(existing_label)
            if match:
                expires_dt = datetime.fromtimestamp(int(match.group(1)), tz=timezone.utc)
                raise ValueError(
                    f"{ip} is already allowed until {expires_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                )
            raise ValueError(f"{ip} is already present in the firewall rules")

    inbound.append(
        {
            "action": "ACCEPT",
            "addresses": {"ipv4": [ip]},
            "description": f"Auto-added rule for {ip}",
            "label": label,
            "ports": "443",
            "protocol": "TCP",
        }
    )

    payload = {
        "inbound": inbound,
        "inbound_policy": current.get("inbound_policy", "DROP"),
        "outbound": current.get("outbound", []),
        "outbound_policy": current.get("outbound_policy", "ACCEPT"),
    }

    async with httpx.AsyncClient() as client:
        resp = await client.put(
            f"{_API_BASE}/networking/firewalls/{settings.firewall_id}/rules",
            headers=_auth_headers(),
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()


async def delete_expired_rules() -> list[str]:
    """Remove inbound rules whose label timestamp is in the past. Returns deleted labels."""
    current = await get_firewall_rules()
    inbound: list[dict] = current.get("inbound", [])

    now = int(time.time())
    active: list[dict] = []
    removed: list[str] = []

    for rule in inbound:
        label = rule.get("label", "")
        match = _LABEL_TS_RE.search(label)
        if match and int(match.group(1)) < now:
            removed.append(label)
        else:
            active.append(rule)

    if not removed:
        return []

    payload = {
        "inbound": active,
        "inbound_policy": current.get("inbound_policy", "DROP"),
        "outbound": current.get("outbound", []),
        "outbound_policy": current.get("outbound_policy", "ACCEPT"),
    }

    async with httpx.AsyncClient() as client:
        resp = await client.put(
            f"{_API_BASE}/networking/firewalls/{settings.firewall_id}/rules",
            headers=_auth_headers(),
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()

    return removed
