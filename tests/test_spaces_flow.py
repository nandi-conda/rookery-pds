# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""End to end through the app and the Durable Object RPC boundary: an owner
creates a member-list space, a member writes to it, an app exchanges a
delegation token for a space credential and syncs the member's repo."""

from human import call, human
from rookery import car, cbor
from rookery.cbor import CID
from rookery.encoding import b64_decode
from rookery.spaces.commit import verify_commit
from rookery.spaces.httpsig import P256Keypair, create_space_sig_headers
from rookery.spaces.lthash import LtHash

FORUM = "com.example.forum"
POST = "com.example.forum.post"
X = "/xrpc/com.atproto.space."
S = "/xrpc/com.atproto.simplespace."


async def credential_for(client, user, space, key, expect=200):
    token = (await call(client, "GET", f"{X}getDelegationToken?space={space}", user))["token"]
    headers = create_space_sig_headers(key, f"Bearer {token}")
    return await call(client, "POST", X + "getSpaceCredential", headers=headers, expect=expect, space=space)


def signed(key, credential, audience):
    return create_space_sig_headers(key, f"Atproto-Space {credential}", audience=audience)


async def setup(client):
    alice, bob, carol = [await human(client, name) for name in ("alice", "bob", "carol")]
    member_list = {"$type": "com.atproto.simplespace.defs#memberListPolicy"}
    created = await call(client, "POST", S + "createSpace", alice, spaceType=FORUM, skey="general",
                         readPolicy=member_list, writePolicy=member_list,
                         appAccess={"$type": "com.atproto.simplespace.defs#open"})
    space = created["uri"]
    assert space == f"at://{alice['did']}/space/{FORUM}/general"
    await call(client, "POST", S + "putMember", alice, space=space, did=bob["did"], read=True, write=True)
    return alice, bob, carol, space


async def test_member_writes_and_app_syncs_with_credential(client, env):
    alice, bob, carol, space = await setup(client)

    first = await call(client, "POST", X + "createRecord", bob, space=space, repo=bob["did"], collection=POST,
                       rkey="hello", record={"text": "hi from bob"})
    assert first["uri"] == f"{space}/{bob['did']}/{POST}/hello"
    await call(client, "POST", X + "createRecord", bob, expect=400, space=space, repo=bob["did"],
               collection=POST, rkey="hello", record={"text": "again"})
    await call(client, "POST", X + "putRecord", alice, space=space, repo=alice["did"], collection=POST,
               rkey="welcome", record={"text": "welcome"})
    batch = await call(client, "POST", X + "applyWrites", bob, space=space, repo=bob["did"], writes=[
        {"$type": "com.atproto.space.applyWrites#create", "collection": POST, "rkey": "two",
         "value": {"text": "two"}},
        {"$type": "com.atproto.space.applyWrites#update", "collection": POST, "rkey": "hello",
         "value": {"text": "hi, edited"}},
        {"$type": "com.atproto.space.applyWrites#create", "collection": POST, "rkey": "gone",
         "value": {"text": "short-lived"}},
        {"$type": "com.atproto.space.applyWrites#delete", "collection": POST, "rkey": "gone"},
    ])
    assert [r["$type"].rpartition("#")[2] for r in batch["results"]] == [
        "createResult", "updateResult", "createResult", "deleteResult"]

    # The app holds a P-256 key and trades bob's delegation token for a credential.
    key = P256Keypair()
    credential = (await credential_for(client, bob, space, key))["credential"]

    # The space host lists the writer set...
    repos = await call(client, "GET", f"{X}listRepos?space={space}", headers=signed(key, credential, alice["did"]))
    writers = {repo["did"]: repo for repo in repos["repos"]}
    assert set(writers) == {alice["did"], bob["did"]}

    # ...and the repo host serves bob's records, commit and CAR to the credential.
    bob_headers = signed(key, credential, bob["did"])
    record = await call(client, "GET", f"{X}getRecord?space={space}&repo={bob['did']}&collection={POST}&rkey=hello",
                        headers=bob_headers)
    assert record["value"] == {"$type": POST, "text": "hi, edited"}
    listed = await call(client, "GET", f"{X}listRecords?space={space}&repo={bob['did']}", headers=bob_headers)
    assert sorted(r["rkey"] for r in listed["records"]) == ["hello", "two"]

    latest = (await call(client, "GET", f"{X}getLatestCommit?space={space}&repo={bob['did']}",
                         headers=bob_headers))["commit"]
    commit = {k: (b64_decode(v["$bytes"]) if isinstance(v, dict) else v) for k, v in latest.items()}
    bob_key = await env.account((await env.db.first("SELECT do_id FROM accounts WHERE did = ?",
                                                     bob["did"]))["do_id"]).space_signing_key()
    assert verify_commit(commit, space, bob["did"], commit["rev"], bob_key)
    assert writers[bob["did"]]["hash"]["$bytes"] == latest["hash"]["$bytes"]
    assert writers[bob["did"]]["repoRev"] == commit["rev"]

    car_response = await call(client, "GET", f"{X}getRepo?space={space}&repo={bob['did']}", headers=bob_headers)
    roots, blocks = car.read_car(car_response.body)
    index = cbor.decode(blocks[roots[1]])
    assert list(index) == [f"{POST}/two", f"{POST}/hello"]  # canonical: shorter keys first
    set_hash = LtHash()
    for path, cid in index.items():
        set_hash.add(f"{path}/{cid}")
        assert CID.for_cbor(blocks[cid]) == cid
    assert set_hash.digest() == commit["hash"]

    ops = await call(client, "GET", f"{X}listRepoOps?space={space}&repo={bob['did']}", headers=bob_headers)
    assert [(op["rkey"], op["prev"] is not None) for op in ops["ops"]] == [
        ("hello", False), ("two", False), ("hello", True), ("gone", False), ("gone", True)]
    assert ops["commit"]["rev"] == commit["rev"]
    replay = LtHash()
    for op in ops["ops"]:
        if op["prev"]:
            replay.remove(f"{op['collection']}/{op['rkey']}/{op['prev']}")
        if op["cid"]:
            replay.add(f"{op['collection']}/{op['rkey']}/{op['cid']}")
    assert replay.digest() == commit["hash"]

    # The credential is not the owner's: no credential reads another space or audience.
    await call(client, "GET", f"{X}getRecord?space={space}&repo={bob['did']}&collection={POST}&rkey=hello",
               headers=signed(key, credential, carol["did"]), expect=401)
    await call(client, "GET", f"{X}getRecord?space={space}&repo={bob['did']}&collection={POST}&rkey=hello",
               headers=signed(P256Keypair(), credential, bob["did"]), expect=401)
    # Without a credential, only bob reads bob's repo.
    await call(client, "GET", f"{X}getRecord?space={space}&repo={bob['did']}&collection={POST}&rkey=hello", carol,
               expect=400)
    own = await call(client, "GET", f"{X}listSpaces", bob)
    assert own["spaces"] == [{"uri": space}]


async def test_non_member_is_refused_and_delegation_is_single_use(client, env):
    alice, bob, carol, space = await setup(client)
    key = P256Keypair()
    refused = await credential_for(client, carol, space, key, expect=400)
    assert refused["error"] == "UserNotAuthorized"

    token = (await call(client, "GET", f"{X}getDelegationToken?space={space}", bob))["token"]
    headers = create_space_sig_headers(key, f"Bearer {token}")
    await call(client, "POST", X + "getSpaceCredential", headers=headers, space=space)
    replayed = await call(client, "POST", X + "getSpaceCredential", headers=headers, expect=401, space=space)
    assert replayed["error"] == "JwtReplayed"

    # carol's own PDS stores what she writes, but the space host does not sequence her.
    await call(client, "POST", X + "createRecord", carol, space=space, repo=carol["did"], collection=POST,
               rkey="x", record={"text": "not a member"})
    credential = (await credential_for(client, bob, space, key))["credential"]
    repos = await call(client, "GET", f"{X}listRepos?space={space}", headers=signed(key, credential, alice["did"]))
    assert carol["did"] not in {repo["did"] for repo in repos["repos"]}


async def test_owner_governance_and_delete(client, env):
    alice, bob, carol, space = await setup(client)
    await call(client, "POST", S + "putMember", bob, expect=400, space=space, did=carol["did"], read=True,
               write=False)
    members = await call(client, "GET", f"{S}listMembers?space={space}", alice)
    assert members["members"] == [{"did": bob["did"], "read": True, "write": True}]
    described = await call(client, "GET", f"{S}getSpace?space={space}", alice)
    assert described["readPolicy"]["$type"].endswith("#memberListPolicy")
    await call(client, "POST", S + "updateSpace", alice, space=space,
               readPolicy={"$type": "com.atproto.simplespace.defs#publicPolicy"})
    key = P256Keypair()
    await credential_for(client, carol, space, key)  # public read now

    await call(client, "POST", X + "createRecord", alice, space=space, repo=alice["did"], collection=POST,
               rkey="a", record={"text": "a"})
    await call(client, "POST", S + "deleteSpace", alice, space=space)
    gone = await credential_for(client, bob, space, key, expect=400)
    assert gone["error"] == "SpaceDeleted"
    write = await call(client, "POST", X + "createRecord", alice, expect=400, space=space, repo=alice["did"],
                       collection=POST, rkey="b", record={"text": "b"})
    assert write["error"] == "SpaceNotFound"
    assert (await call(client, "GET", f"{X}listSpaces", alice))["spaces"] == []


async def test_space_blob_is_served_only_through_its_space(client, env):
    alice, bob, carol, space = await setup(client)
    uploaded = await client.post("/xrpc/com.atproto.repo.uploadBlob",
                               headers=dict(bob["auth"], **{"content-type": "image/png"}), body=b"\x89PNG...")
    blob = uploaded.json()["blob"]
    await call(client, "POST", X + "createRecord", bob, space=space, repo=bob["did"], collection=POST, rkey="pic",
               record={"text": "pic", "image": blob})
    key = P256Keypair()
    credential = (await credential_for(client, bob, space, key))["credential"]
    headers = signed(key, credential, bob["did"])
    cid = blob["ref"]["$link"]
    listed = await call(client, "GET", f"{X}listBlobs?space={space}&repo={bob['did']}", headers=headers)
    assert listed["cids"] == [cid]
    got = await call(client, "GET", f"{X}getBlob?space={space}&repo={bob['did']}&cid={cid}", headers=headers)
    assert got.body == b"\x89PNG..." and got.headers["content-security-policy"]
    other = await call(client, "POST", X + "createRecord", bob, expect=400, space=space, repo=bob["did"],
                       collection=POST, rkey="nope",
                       record={"image": dict(blob, ref={"$link": "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"})})
    assert other["error"] == "BlobNotFound"
