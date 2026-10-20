# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Point every DID on a roost host at that host after a hostname change: for
each repo HOST lists, re-sign its PLC document (PDS endpoint and handle) with
the account's rotation key, then ask the relays to crawl HOST.

    HOST=https://roost.latha.org ROOKERY_OPERATOR_TOKEN=... \\
      uv run python scripts/sync_identities.py [did ...]

With no DIDs it syncs every repo HOST lists. DIDs whose PLC document already
names HOST are skipped, so re-running is safe.
"""

import os
import sys
from urllib.parse import urlsplit

import httpx

from migrate_host import RELAYS, list_dids, ok

PLC = "https://plc.directory"


def main() -> None:
    host, token = os.environ.get("HOST"), os.environ.get("ROOKERY_OPERATOR_TOKEN")
    if not host or not token:
        print("HOST and ROOKERY_OPERATOR_TOKEN are required", file=sys.stderr)
        raise SystemExit(2)
    host = host.rstrip("/")
    auth = {"authorization": f"Bearer {token}"}

    with httpx.Client(timeout=120) as http:
        dids = sys.argv[1:] or list_dids(http, host)
        print(f"syncing {len(dids)} DID(s) to {host}")
        for did in dids:
            doc = ok(http.get(f"{PLC}/{did}/data"), f"PLC {did}").json()
            if doc["services"]["atproto_pds"]["endpoint"] == host:
                print(f"{did}: already on {host}")
                continue
            described = ok(http.get(f"{host}/xrpc/com.atproto.repo.describeRepo", params={"repo": did}), f"describeRepo {did}")
            synced = ok(http.post(f"{host}/operator/identity/sync", json={"did": did, "handle": described.json()["handle"]},
                                  headers=auth), f"identity sync {did}").json()
            print(f"{did}: PLC now names {synced['pds']} as the PDS of {synced['handle']}")

        hostname = urlsplit(host).hostname
        for relay in RELAYS:
            ok(http.post(f"{relay}/xrpc/com.atproto.sync.requestCrawl", json={"hostname": hostname}), f"requestCrawl {relay}")
            print(f"asked {relay} to crawl {hostname}")


if __name__ == "__main__":
    main()
