"""
VPN/proxy/hosting detection via ip-api.com free tier.
Fails open — if the API is unreachable, the check returns (False, None).
"""

import requests

_VPN_KEYWORDS = [
    "vpn", "proxy", "nordvpn", "expressvpn", "surfshark", "cyberghost",
    "private internet access", "protonvpn", "proton vpn", "mullvad",
    "windscribe", "tunnelbear", "ipvanish", "hotspot shield", "hide.me",
    "purevpn", "vyprvpn", "torguard", "perfect privacy", "privado",
    "digitalocean", "amazon", "aws", "google cloud", "azure",
    "microsoft corporation", "ovh", "hetzner", "vultr", "linode",
    "akamai", "choopa", "m247", "leaseweb", "contabo", "datacamp",
    "hostwinds", "psychz", "worldstream", "iweb", "cloudflare",
    "hosting", "datacenter", "data center", "colocation", "dedicated server",
]


def _lookup(ip: str) -> dict | None:
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,isp,org,as,proxy,hosting,query"},
            timeout=4,
        )
        data = resp.json()
        return data if data.get("status") == "success" else None
    except Exception:
        return None


def is_vpn_or_proxy(ip: str) -> tuple[bool, str | None]:
    """
    Returns (is_vpn: bool, label: str | None).
    label is a short human-readable reason for the admin panel.
    """
    if not ip or ip in ("127.0.0.1", "::1"):
        return False, None

    data = _lookup(ip)
    if not data:
        return False, None  # fail open

    isp      = data.get("isp") or ""
    org      = data.get("org") or ""
    asname   = data.get("as")  or ""
    haystack = f"{isp} {org} {asname}".lower()
    label    = isp or org or asname or "unknown ISP"

    if data.get("proxy"):
        return True, f"Flagged proxy/VPN ({label})"
    if data.get("hosting"):
        return True, f"Hosting/Datacenter ({label})"

    for kw in _VPN_KEYWORDS:
        if kw in haystack:
            return True, label

    return False, None
