# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The cross-host paths: a syncer registered for notifications, a remote PDS
notifying this space host, a remote space host this PDS notifies (with retry),
and human password sign-in on the OAuth consent page."""

import asyncio
import json
import time
from urllib.parse import parse_qs, urlencode, urlsplit

from fakes import FakeEnv
from rookery.encoding import b64url_encode
from rookery.keys import Secp256k1Keypair
from rookery.net import HttpResponse
from rookery.oauth import store as oauth_store
from rookery.spaces.httpsig import P256Keypair
from test_spaces_flow import FORUM, POST, S, X, account, call, credential_for, setup, signed

PUBLIC = {"$type": "com.atproto.simplespace.defs#publicPolicy"}


def run(coro):
    return asyncio.run(coro)


def service_jwt(key: Secp256k1Keypair, iss: str, aud: str, lxm: str) -> str:
    header = {"typ": "JWT", "alg": "ES256K"}
    payload = {"iss": iss, "aud": aud, "lxm": lxm, "exp": int(time.time()) + 60, "jti": "x"}
    signing_input = ".".join(b64url_encode(json.dumps(p).encode()) for p in (header, payload))
    return f"{signing_input}.{b64url_encode(key.sign(signing_input.encode()))}"


def publish_plc(env, did, key: Secp256k1Keypair, endpoint):
    env.http.plc_ops[did] = {
        "alsoKnownAs": [], "verificationMethods": {"atproto": key.did()},
        "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": endpoint}},
    }


def test_registered_syncer_receives_write_notifications():
    async def go():
        env = FakeEnv()
        alice, bob, carol, space = await setup(env)
        received = []

        async def syncer(url, method, headers, body):
            if url.endswith("/.well-known/did.json"):
                doc = {"id": "did:web:syncer.test",
                       "service": [{"id": "#atproto_space_syncer", "type": "X", "serviceEndpoint": "https://syncer.test"}]}
                return HttpResponse(200, json.dumps(doc).encode())
            received.append((url, headers, json.loads(body)))
            return HttpResponse(200, b"")
        env.http.routes["https://syncer.test/"] = syncer

        key = P256Keypair()
        credential = (await credential_for(env, bob, space, key))["credential"]
        registered = await call(env, "POST", X + "registerNotify", headers=signed(key, credential, alice["did"]),
                                space=space, service="did:web:syncer.test#atproto_space_syncer")
        assert registered["expiresAt"]
        await call(env, "POST", X + "createRecord", bob, space=space, repo=bob["did"], collection=POST,
                   rkey="n", record={"text": "notify me"})
        assert len(received) == 1
        url, headers, notice = received[0]
        assert url == "https://syncer.test/xrpc/com.atproto.space.notifyWrite"
        assert notice["space"] == space and notice["repo"] == bob["did"] and notice["spaceRev"]
        assert headers["Authorization"].startswith("Bearer ")

        await call(env, "POST", X + "unregisterNotify", headers=signed(key, credential, alice["did"]),
                   space=space, service="did:web:syncer.test#atproto_space_syncer")
        await call(env, "POST", X + "createRecord", bob, space=space, repo=bob["did"], collection=POST,
                   rkey="m", record={"text": "quiet"})
        assert len(received) == 1
    run(go())


def test_remote_writer_notifies_this_space_host():
    async def go():
        env = FakeEnv()
        alice = await account(env, "alice")
        created = await call(env, "POST", S + "createSpace", alice, spaceType=FORUM, skey="open",
                             readPolicy=PUBLIC, writePolicy=PUBLIC,
                             appAccess={"$type": "com.atproto.simplespace.defs#open"})
        space = created["uri"]
        remote_key, remote_did = Secp256k1Keypair.create(), "did:plc:remotewriter0000000000"
        publish_plc(env, remote_did, remote_key, "https://elsewhere.test")
        token = service_jwt(remote_key, remote_did, f"{alice['did']}#atproto_space_host", "com.atproto.space.notifyWrite")
        notice = {"space": space, "repo": remote_did, "repoRev": "3m2xyzabcde22",
                  "hash": {"$bytes": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}}
        await call(env, "POST", X + "notifyWrite", headers={"authorization": f"Bearer {token}"}, **notice)

        forged = service_jwt(Secp256k1Keypair.create(), remote_did, alice["did"], "com.atproto.space.notifyWrite")
        await call(env, "POST", X + "notifyWrite", headers={"authorization": f"Bearer {forged}"}, expect=401, **notice)
        other = service_jwt(remote_key, remote_did, alice["did"], "com.atproto.space.notifyWrite")
        await call(env, "POST", X + "notifyWrite", headers={"authorization": f"Bearer {other}"}, expect=403,
                   **dict(notice, repo="did:plc:someoneelse0000000000"))

        key = P256Keypair()
        credential = (await credential_for(env, alice, space, key))["credential"]
        repos = await call(env, "GET", f"{X}listRepos?space={space}", headers=signed(key, credential, alice["did"]))
        assert [repo["did"] for repo in repos["repos"]] == [remote_did]
    run(go())


def test_writes_to_a_remote_space_notify_its_host_and_retry():
    async def go():
        env = FakeEnv()
        bob = await account(env, "bob")
        host_did = "did:plc:remoteauthority00000000"
        publish_plc(env, host_did, Secp256k1Keypair.create(), "https://remote.test")
        space = f"at://{host_did}/space/{FORUM}/x"
        attempts = []

        async def remote(url, method, headers, body):
            attempts.append(json.loads(body))
            return HttpResponse(503 if len(attempts) == 1 else 200, b"")
        env.http.routes["https://remote.test/"] = remote

        await call(env, "POST", X + "createRecord", bob, space=space, repo=bob["did"], collection=POST,
                   rkey="1", record={"text": "first"})
        assert len(attempts) == 1
        do = env.accounts[(await env.db.first("SELECT do_id FROM accounts WHERE did = ?", bob["did"]))["do_id"]]
        queued = do.spaces.sql.exec("SELECT * FROM space_notification_retry")
        assert len(queued) == 1 and queued[0]["repo_rev"] == attempts[0]["repoRev"]

        do.spaces.sql.exec("UPDATE space_notification_retry SET retry_at = 0")
        await call(env, "POST", X + "createRecord", bob, space=space, repo=bob["did"], collection=POST,
                   rkey="2", record={"text": "second"})
        # The new write is delivered and clears the older pending notice for the same space.
        assert len(attempts) == 2
        assert do.spaces.sql.exec("SELECT * FROM space_notification_retry") == []
    run(go())


def test_human_password_consent_on_oauth_authorize():
    async def go():
        env = FakeEnv()
        alice = await account(env, "alice")
        await oauth_store.init_oauth(env.db)
        par = {"request_uri": "urn:ietf:params:oauth:request_uri:abc", "client_id": "https://app.test/client.json",
               "params": json.dumps({"state": "s1", "client_name": "Test App"}), "code_challenge": "c",
               "redirect_uri": "https://app.test/cb", "scope": "atproto transition:generic",
               "dpop_jkt": "jkt", "exp": int(time.time()) + 300}
        await oauth_store.insert_par_request(env.db, par, int(time.time()))
        query = urlencode({"request_uri": par["request_uri"], "client_id": par["client_id"]})
        page = await env.request("GET", f"/oauth/authorize?{query}", headers={"accept": "text/html"})
        assert page.status == 200 and b"Test App" in page.body
        form = {"request_uri": par["request_uri"], "client_id": par["client_id"], "identifier": "alice.pds.test",
                "decision": "allow"}
        headers = {"content-type": "application/x-www-form-urlencoded"}
        wrong = await env.request("POST", "/oauth/authorize", headers=headers,
                                  body=urlencode(dict(form, password="not it at all")))
        assert wrong.status == 401 and b"Invalid identifier or password" in wrong.body
        ok = await env.request("POST", "/oauth/authorize", headers=headers,
                               body=urlencode(dict(form, password="long enough pw")))
        assert ok.status == 302
        location = urlsplit(ok.header("Location"))
        params = parse_qs(location.query)
        assert location.netloc == "app.test" and params["state"] == ["s1"] and params["code"]
        code = await env.db.first("SELECT did FROM oauth_codes")
        assert code["did"] == alice["did"]
    run(go())
