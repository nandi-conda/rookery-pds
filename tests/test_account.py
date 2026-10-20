# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The Account Durable Object, driven through the same string RPC boundary the Worker uses."""

import pytest

from fakes import AccountDO, Blobs, SequencerDO
from roost import rpc
from roost.keys import Secp256k1Keypair

DID = "did:plc:test123456789"
HANDLE = "test.rookery.test"
POST = "app.bsky.feed.post"


@pytest.fixture
def account():
    return rpc.AccountClient(AccountDO(SequencerDO(), Blobs()).rpc)


@pytest.fixture
async def provisioned(account):
    signing, rotation = Secp256k1Keypair.create(), Secp256k1Keypair.create()
    await account.init_account(
        did=DID, handle=HANDLE,
        signing_key_hex=signing.export_hex(), signing_key_pub=signing.did().rsplit(":", 1)[1],
        rotation_key_hex=rotation.export_hex(), rotation_key_pub=rotation.did().rsplit(":", 1)[1],
    )
    return account


async def test_state_is_empty_until_provisioned(account):
    assert await account.get_state() is None
    assert await account.get_latest_commit() is None


async def test_provisioning_creates_the_repo(provisioned):
    state = await provisioned.get_state()
    assert state["did"] == DID and state["handle"] == HANDLE and state["active"] is True and state["root_cid"]
    commit = await provisioned.get_latest_commit()
    assert commit["cid"] == state["root_cid"] and commit["rev"]


async def test_create_and_get_a_record(provisioned):
    result = await provisioned.create_record(collection=POST, rkey=None, record={"text": "Hello from roost!"})
    assert result["uri"].startswith(f"at://{DID}/{POST}/")
    assert result["cid"] and result["commit"]["cid"] and result["commit"]["rev"]
    record = await provisioned.get_record(collection=POST, rkey=result["uri"].rsplit("/", 1)[1])
    assert record["cid"] == result["cid"]


async def test_describe_repo_lists_collections(provisioned):
    await provisioned.create_record(collection=POST, rkey=None, record={"text": "test"})
    described = await provisioned.describe_repo()
    assert described["did"] == DID and POST in described["collections"] and described["cid"]
    assert described["handle"] == HANDLE and described["handleIsCorrect"] is True


async def test_delete_record(provisioned):
    await provisioned.create_record(collection=POST, rkey="test-rkey", record={"text": "to delete"})
    assert (await provisioned.delete_record(collection=POST, rkey="test-rkey"))["commit"]["cid"]
    assert await provisioned.get_record(collection=POST, rkey="test-rkey") is None


async def test_put_record_creates_then_updates(provisioned):
    created = await provisioned.put_record(collection=POST, rkey="put-rkey", record={"text": "first"})
    assert created["uri"] == f"at://{DID}/{POST}/put-rkey"
    updated = await provisioned.put_record(collection=POST, rkey="put-rkey", record={"text": "second"})
    assert updated["uri"] == created["uri"] and updated["cid"] != created["cid"]
    assert (await provisioned.get_record(collection=POST, rkey="put-rkey"))["record"]["text"] == "second"


async def test_apply_writes_creates_and_updates(provisioned):
    created = await provisioned.apply_writes(writes=[
        {"$type": "com.atproto.repo.applyWrites#create", "collection": POST, "record": {"text": "post 1"}},
        {"$type": "com.atproto.repo.applyWrites#create", "collection": POST, "record": {"text": "post 2"}},
    ])
    assert created["commit"]["cid"] and len(created["results"]) == 2

    await provisioned.create_record(collection=POST, rkey="update-rkey", record={"text": "before"})
    updated = await provisioned.apply_writes(writes=[{
        "$type": "com.atproto.repo.applyWrites#update", "collection": POST, "rkey": "update-rkey", "record": {"text": "after"},
    }])
    (result,) = updated["results"]
    assert result["$type"] == "com.atproto.repo.applyWrites#updateResult"
    assert result["uri"] == f"at://{DID}/{POST}/update-rkey" and result["cid"]
    assert (await provisioned.get_record(collection=POST, rkey="update-rkey"))["record"]["text"] == "after"


async def test_only_allowlisted_methods_cross_the_boundary(account):
    with pytest.raises(AttributeError):
        account.storage  # noqa: B018 - not an RPC method
    response = await AccountDO(SequencerDO(), Blobs()).rpc(rpc.request("_state", {}))
    with pytest.raises(rpc.RemoteError):
        rpc.unwrap(response)


# Health check and landing page

async def test_root_is_a_json_health_check(client):
    response = await client.get("/")
    assert response.status == 200 and response.json() == {"status": "ok"}


async def test_root_serves_the_landing_page_to_browsers(client):
    response = await client.get("/", headers={"accept": "text/html,*/*"})
    assert response.status == 200
    assert "text/html" in response.headers["content-type"]
    assert "<h1>roost</h1>" in response.text and "agents hosted" in response.text
