# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Move every account on a roost host from one handle domain to another, keeping
each name: alice.agent.latha.org becomes alice.roost.latha.org. Run it after
deploying with the new ROOKERY_HANDLE_DOMAIN.

    uv run python scripts/rename_handles.py [did ...]

For each repo HOST lists whose handle ends with FROM_DOMAIN, the host re-signs
the DID's PLC document with the new handle, records it in its directory, emits
an #identity event and writes the `_atproto.<handle>` TXT record (when the
Worker has CLOUDFLARE_DNS_TOKEN). Then each new handle is checked over DNS and
the relays are asked to crawl HOST. Accounts already on TO_DOMAIN are skipped,
so re-running is safe. HOST defaults to https://roost.latha.org, FROM_DOMAIN to
.agent.latha.org, TO_DOMAIN to .roost.latha.org; the operator token comes from
ROOKERY_OPERATOR_TOKEN, or else the file `pixi run cf-operator-token` saved.
"""

import os
import sys
from urllib.parse import urlsplit

import httpx

from migrate_host import RELAYS, list_dids, ok, operator_token

DOH = "https://dns.google/resolve"


def txt_did(http: httpx.Client, handle: str) -> str | None:
    answers = ok(http.get(DOH, params={"name": f"_atproto.{handle}", "type": "TXT"},
                          headers={"accept": "application/dns-json"}), f"DNS {handle}").json().get("Answer") or []
    for answer in answers:
        value = answer["data"].strip('"')
        if value.startswith("did="):
            return value[4:]
    return None


def main() -> None:
    host = os.environ.get("HOST", "https://roost.latha.org").rstrip("/")
    old = os.environ.get("FROM_DOMAIN", ".agent.latha.org")
    new = os.environ.get("TO_DOMAIN", ".roost.latha.org")
    auth = {"authorization": f"Bearer {operator_token()}"}

    with httpx.Client(timeout=120) as http:
        dids = sys.argv[1:] or list_dids(http, host)
        print(f"moving {len(dids)} DID(s) on {host} from *{old} to *{new}")
        renamed = {}
        for did in dids:
            handle = ok(http.get(f"{host}/xrpc/com.atproto.repo.describeRepo", params={"repo": did}),
                        f"describeRepo {did}").json()["handle"]
            if handle.endswith(new):
                print(f"{did}: already {handle}")
                renamed[did] = handle
                continue
            if not handle.endswith(old):
                print(f"{did}: {handle} is not under {old}, skipped")
                continue
            target = handle[: -len(old)] + new
            synced = ok(http.post(f"{host}/operator/identity/sync", json={"did": did, "handle": target}, headers=auth),
                        f"identity sync {did}").json()
            print(f"{did}: {handle} -> {synced['handle']}")
            renamed[did] = synced["handle"]

        missing = [(did, handle) for did, handle in renamed.items() if txt_did(http, handle) != did]
        for did, handle in missing:
            print(f"no TXT yet: _atproto.{handle} should be \"did={did}\"")

        hostname = urlsplit(host).hostname
        for relay in RELAYS:
            ok(http.post(f"{relay}/xrpc/com.atproto.sync.requestCrawl", json={"hostname": hostname}), f"requestCrawl {relay}")
            print(f"asked {relay} to crawl {hostname}")
        if missing:
            raise SystemExit(f"{len(missing)} handle(s) have no TXT record yet; they won't verify until it exists")


if __name__ == "__main__":
    main()
