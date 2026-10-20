# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Publishing `_atproto.<handle>` TXT records in Cloudflare DNS, so handles
resolve over DNS without the handle host needing its own TLS cert."""

import json
from urllib.parse import quote


class HandleDnsError(Exception):
    """Cloudflare refused a handle's TXT record; the message has its status and errors."""


async def _cloudflare_call(what: str, response) -> dict:
    try:
        body = response.json()
        if not isinstance(body, dict):
            body = {}
    except ValueError:
        body = {}
    if not response.ok or body.get("success") is False:
        detail = "; ".join(f"{error.get('code')} {error.get('message')}" for error in body.get("errors") or [])
        raise HandleDnsError(f"Cloudflare DNS {what} failed ({response.status})" + (f": {detail}" if detail else ""))
    return body


async def publish_handle_dns(env, handle: str, did: str) -> None:
    """No-op when CLOUDFLARE_DNS_TOKEN is unset (handles then resolve over HTTPS)."""
    if not env.CLOUDFLARE_DNS_TOKEN:
        return
    if not env.CLOUDFLARE_ZONE_ID:
        raise HandleDnsError("CLOUDFLARE_ZONE_ID is required when CLOUDFLARE_DNS_TOKEN is set")
    base = f"https://api.cloudflare.com/client/v4/zones/{env.CLOUDFLARE_ZONE_ID}/dns_records"
    headers = {"Authorization": f"Bearer {env.CLOUDFLARE_DNS_TOKEN}", "Content-Type": "application/json"}
    name = f"_atproto.{handle}"
    record = json.dumps({"type": "TXT", "name": name, "content": f'"did={did}"', "ttl": 300}, separators=(",", ":"))
    listing = await _cloudflare_call(
        f"lookup for {name}",
        await env.http.fetch(f"{base}?type=TXT&name={quote(name, safe='')}", headers=headers),
    )
    existing = (listing.get("result") or [None])[0]
    if existing:
        response = await env.http.fetch(f"{base}/{existing['id']}", method="PUT", headers=headers, body=record)
    else:
        response = await env.http.fetch(base, method="POST", headers=headers, body=record)
    await _cloudflare_call(f"write for {name}", response)
