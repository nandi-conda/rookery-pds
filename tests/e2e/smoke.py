# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""End-to-end smoke test against a running roost Worker (pywrangler dev).

    python tests/e2e/smoke.py http://localhost:8799 [--car out.car]

Needs the Worker configured with ROOKERY_HOSTNAME=rookery.test,
ROOKERY_HANDLE_DOMAIN=.rookery.test and ROOKERY_PLC_URL pointing at the fake
PLC this script starts on 127.0.0.1:8790.
"""

import argparse
import asyncio
import json
import secrets
import sys
import threading
from pathlib import Path

import httpx
import websockets

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent import Agent  # noqa: E402
from fake_plc import serve as serve_plc  # noqa: E402
from roost import car, cbor  # noqa: E402

ORIGIN = "https://rookery.test"
OPERATOR_TOKEN = "test-operator-token"


def check(condition, message, detail=None):
    if not condition:
        raise AssertionError(f"{message}: {detail}")
    print(f"ok  {message}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base")
    parser.add_argument("--car")
    args = parser.parse_args()
    plc = serve_plc(8790)
    threading.Thread(target=plc.serve_forever, daemon=True).start()
    http = httpx.Client(base_url=args.base, timeout=60)

    tos = http.get("/tos").text
    agent = Agent(ORIGIN, tos)
    name = "smoke" + secrets.token_hex(3)
    response = http.post("/api/signup", json=agent.signup_body(name), headers={"DPoP": agent.dpop("POST", "/api/signup")})
    check(response.status_code == 200, "signup", response.text)
    did = response.json()["did"]
    handle = response.json()["handle"]
    check(did in plc.state.log, "genesis op reached PLC")

    def xrpc_post(method, body):
        path = f"/xrpc/{method}"
        return http.post(path, json=body, headers=agent.auth_headers("POST", path))

    def xrpc_get(method, **params):
        path = f"/xrpc/{method}"
        return http.get(path, params=params, headers=agent.auth_headers("GET", path))

    response = xrpc_post("com.atproto.repo.createRecord", {
        "repo": did, "collection": "app.bsky.feed.post",
        "record": {"$type": "app.bsky.feed.post", "text": "hello from python", "createdAt": "2026-10-20T00:00:00Z"},
    })
    check(response.status_code == 200, "createRecord", response.text)
    uri = response.json()["uri"]
    rkey = uri.rsplit("/", 1)[1]

    response = http.get("/xrpc/com.atproto.repo.getRecord", params={"repo": did, "collection": "app.bsky.feed.post", "rkey": rkey})
    check(response.status_code == 200 and response.json()["value"]["text"] == "hello from python", "getRecord", response.text)

    response = xrpc_post("com.atproto.repo.putRecord", {
        "repo": handle, "collection": "app.bsky.actor.profile", "rkey": "self",
        "record": {"displayName": "Smoke", "score": 1.5},
    })
    check(response.status_code == 400, "putRecord rejects floats", response.text)
    response = xrpc_post("com.atproto.repo.putRecord", {
        "repo": handle, "collection": "app.bsky.actor.profile", "rkey": "self", "record": {"displayName": "Smoke"},
    })
    check(response.status_code == 200, "putRecord", response.text)

    response = xrpc_post("com.atproto.repo.applyWrites", {"repo": did, "writes": [
        {"$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "rkey": f"p{i}",
         "record": {"text": f"post {i}", "createdAt": "2026-10-20T00:00:00Z"}}
        for i in range(5)
    ]})
    check(response.status_code == 200 and len(response.json()["results"]) == 5, "applyWrites", response.text)

    pages, cursor = [], None
    while True:
        params = {"repo": did, "collection": "app.bsky.feed.post", "limit": 2}
        if cursor:
            params["cursor"] = cursor
        page = http.get("/xrpc/com.atproto.repo.listRecords", params=params).json()
        pages += [record["uri"] for record in page["records"]]
        cursor = page.get("cursor")
        if not cursor:
            break
    check(len(pages) == 6 and len(set(pages)) == 6, "listRecords pages without duplicates", pages)

    response = xrpc_post("com.atproto.repo.deleteRecord", {"repo": did, "collection": "app.bsky.feed.post", "rkey": "p0"})
    check(response.status_code == 200, "deleteRecord", response.text)

    blob = secrets.token_bytes(5000)
    path = "/xrpc/com.atproto.repo.uploadBlob"
    response = http.post(path, content=blob, headers=dict(agent.auth_headers("POST", path), **{"Content-Type": "image/png"}))
    check(response.status_code == 200, "uploadBlob", response.text)
    blob_cid = response.json()["blob"]["ref"]["$link"]
    response = http.get("/xrpc/com.atproto.sync.getBlob", params={"did": did, "cid": blob_cid})
    check(response.content == blob and response.headers["content-type"] == "image/png", "getBlob round-trips bytes")
    check(http.get("/xrpc/com.atproto.sync.listBlobs", params={"did": did}).json()["cids"] == [blob_cid], "listBlobs")

    check(xrpc_get("com.atproto.server.getSession").json()["did"] == did, "getSession")
    response = xrpc_get("com.atproto.server.getServiceAuth", aud="did:web:example.com", lxm="com.example.method")
    check(response.status_code == 200 and response.json()["token"].count(".") == 2, "getServiceAuth", response.text)

    described = http.get("/xrpc/com.atproto.repo.describeRepo", params={"repo": did}).json()
    check(described["collections"] == ["app.bsky.actor.profile", "app.bsky.feed.post"], "describeRepo", described)
    latest = http.get("/xrpc/com.atproto.sync.getLatestCommit", params={"did": did}).json()
    repos = http.get("/xrpc/com.atproto.sync.listRepos").json()["repos"]
    check(any(repo["did"] == did and repo["head"] == latest["cid"] for repo in repos), "listRepos head matches")
    check(http.get("/xrpc/com.atproto.sync.getRepoStatus", params={"did": did}).json()["active"] is True, "getRepoStatus")
    check(http.get("/xrpc/com.atproto.identity.resolveHandle", params={"handle": handle}).json()["did"] == did, "resolveHandle")
    check(http.get("/.well-known/atproto-did", headers={"x-forwarded-host": handle}).text == did, "atproto-did")

    response = http.get("/xrpc/com.atproto.sync.getRepo", params={"did": did})
    check(response.headers["content-type"] == "application/vnd.ipld.car", "getRepo", response.status_code)
    roots, blocks = car.read_car(response.content)
    check(str(roots[0]) == latest["cid"], "CAR root is the latest commit")
    if args.car:
        Path(args.car).write_bytes(response.content)
        signing_key = plc.state.log[did][0]["operation"]["verificationMethods"]["atproto"]
        Path(args.car + ".json").write_text(json.dumps({"did": did, "signingKey": signing_key}))

    async def firehose():
        ws_url = args.base.replace("http", "ws", 1) + "/xrpc/com.atproto.sync.subscribeRepos?cursor=0"
        frames = []
        async with websockets.connect(ws_url, max_size=None) as ws:
            while True:
                try:
                    frames.append(await asyncio.wait_for(ws.recv(), 3))
                except TimeoutError:
                    return frames
    frames = asyncio.run(firehose())
    decoded = []
    for frame in frames:
        header, end = cbor.decode_first(frame)
        decoded.append((header["t"], cbor.decode_first(frame, end)[0]))
    commits = [body for t, body in decoded if t == "#commit" and body["repo"] == did]
    check(len(commits) == 4, "firehose replays this repo's commits", [t for t, _ in decoded][-10:])
    check(all(car.read_car(body["blocks"])[0][0] == body["commit"] for body in commits), "commit frames carry their CAR")

    new_handle = name + "x.rookery.test"
    path = "/xrpc/com.atproto.identity.updateHandle"
    response = http.post(path, json={"handle": new_handle}, headers=agent.auth_headers("POST", path))
    check(response.status_code == 200, "updateHandle", response.text)
    check(plc.state.log[did][-1]["operation"]["alsoKnownAs"] == [f"at://{new_handle}"], "PLC update op signed and sent")

    response = http.get("/operator/account/export", params={"did": did}, headers={"Authorization": f"Bearer {OPERATOR_TOKEN}"})
    check(response.status_code == 200, "operator export", response.text[:200])
    exported = cbor.decode(response.content)
    check(exported["state"]["did"] == did and blob_cid in exported["blobBytes"], "export carries state and blobs")
    print("all ok", did)


if __name__ == "__main__":
    main()
