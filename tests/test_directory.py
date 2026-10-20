# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The D1 account directory: handle resolution, listRepos, invites."""

import asyncio
import re

import pytest

from conftest import unique
from fakes import D1
from rookery import directory


@pytest.fixture
async def db(env):
    await directory.init_directory(env.db)
    return env.db


# Handle resolution and repo listing

async def test_resolves_a_known_handle(client, enroll):
    rook = await enroll(unique("alice"))
    response = await client.get("/xrpc/com.atproto.identity.resolveHandle", params={"handle": rook.handle})
    assert response.status == 200 and response.json()["did"] == rook.did


async def test_resolve_handle_requires_the_param_and_404s_unknown(client):
    assert (await client.get("/xrpc/com.atproto.identity.resolveHandle")).status == 400
    assert (await client.get("/xrpc/com.atproto.identity.resolveHandle", params={"handle": "nobody.rookery.test"})).status == 404


async def test_resolved_do_id_recovers_the_account(env, enroll):
    rook = await enroll()
    resolved = await directory.resolve_repo(env.db, rook.handle)
    assert resolved["did"] == rook.did
    state = await env.account(resolved["do_id"]).get_state()
    assert state["did"] == rook.did and state["handle"] == rook.handle


async def test_list_repos_orders_by_did_and_paginates(client, enroll):
    for _ in range(3):
        await enroll()
    everything = (await client.get("/xrpc/com.atproto.sync.listRepos")).json()
    dids = [repo["did"] for repo in everything["repos"]]
    assert len(dids) == 3 and dids == sorted(dids)
    assert all(isinstance(repo["head"], str) and isinstance(repo["rev"], str) for repo in everything["repos"])
    assert "cursor" not in everything

    first = (await client.get("/xrpc/com.atproto.sync.listRepos", params={"limit": "1"})).json()
    assert len(first["repos"]) == 1 and first["cursor"]
    second = (await client.get("/xrpc/com.atproto.sync.listRepos", params={"limit": "1", "cursor": first["cursor"]})).json()
    assert len(second["repos"]) == 1 and second["repos"][0]["did"] > first["repos"][0]["did"]


async def test_describe_server_reports_the_account_count(client, enroll):
    await enroll()
    body = (await client.get("/xrpc/com.atproto.server.describeServer")).json()
    assert body["availableUserDomains"] == ["rookery.test"]
    assert body["inviteCodeRequired"] is False
    assert body["accounts"] == 1


async def test_well_known_atproto_did_by_host(client, enroll):
    rook = await enroll()
    found = await client.get("/.well-known/atproto-did", headers={"host": rook.handle})
    assert found.status == 200 and found.text == rook.did
    assert (await client.get("/.well-known/atproto-did", headers={"host": "unknown.rookery.test"})).status == 404


# Invites

def test_invite_tokens_are_ten_lowercase_crockford_chars():
    alphabet = re.compile(r"^[0123456789abcdefghjkmnpqrstvwxyz]{10}$")
    assert all(alphabet.match(directory.generate_invite_token()) for _ in range(5000))


async def test_mint_rook_invite_stops_at_the_quota(db):
    did = f"did:plc:{unique('dir-mint')}"
    first = await directory.mint_rook_invite(db, did, 1)
    assert first and first["remaining"] == 0
    assert await directory.mint_rook_invite(db, did, 1) is None


async def test_spends_an_invite_only_once(db):
    token = unique("dir-spend")
    await db.run("INSERT INTO invites (token) VALUES (?)", token)
    assert await directory.spend_invite_pending(db, token) is True
    assert await directory.spend_invite_pending(db, token) is False


async def test_unspends_only_with_the_matching_predicate(db):
    token = unique("dir-unspend")
    await db.run("INSERT INTO invites (token) VALUES (?)", token)
    assert await directory.spend_invite_pending(db, token)
    assert await directory.unspend_invite(db, token, "did:plc:not-pending") is False
    pending = await db.first("SELECT spent_by_did, spent_at FROM invites WHERE token = ?", token)
    assert pending["spent_by_did"] == "pending" and pending["spent_at"]
    assert await directory.unspend_invite(db, token, "pending") is True
    assert await db.first("SELECT spent_by_did, spent_at FROM invites WHERE token = ?", token) == {"spent_by_did": None, "spent_at": None}


async def test_org_mints_are_idempotent_per_key(db):
    key = unique("dir-idem")
    first = await directory.mint_org_invite(db, key)
    assert first["replayed"] is False and len(first["token"]) == 10
    replay = await directory.mint_org_invite(db, key)
    assert replay == {"token": first["token"], "replayed": True}
    other = await directory.mint_org_invite(db, f"{key}-other")
    assert other["replayed"] is False and other["token"] != first["token"]
    a, b = await directory.mint_org_invite(db), await directory.mint_org_invite(db)
    assert a["replayed"] is False and a["token"] != b["token"]


async def test_concurrent_same_key_mints_collapse_to_one_invite(db):
    key = unique("dir-idem-race")
    results = await asyncio.gather(*(directory.mint_org_invite(db, key) for _ in range(6)))
    assert len({r["token"] for r in results}) == 1
    assert len([r for r in results if not r["replayed"]]) == 1
    assert (await db.first("SELECT COUNT(*) AS count FROM invites WHERE idempotency_key = ?", key))["count"] == 1


class _LateWinner(D1):
    """A D1 where another request mints the same key between our check and our insert."""

    def __init__(self, key: str):
        super().__init__()
        self.key = key
        self.raced = False

    async def first(self, sql, *params):
        if not self.raced and "idempotency_key = ?" in sql:
            self.raced = True
            self.connection.execute("INSERT INTO invites (token, minted_by, idempotency_key) VALUES ('winner0000', 'org', ?)", (self.key,))
            return None
        return await super().first(sql, *params)


async def test_losing_insert_of_a_key_race_resolves_to_the_winner():
    key = unique("dir-race")
    db = _LateWinner(key)
    await directory.init_directory(db)
    assert await directory.mint_org_invite(db, key) == {"token": "winner0000", "replayed": True}


async def test_revoke_invite_outcomes(db):
    prefix = unique("dir-revoke")
    await db.run("INSERT INTO invites (token) VALUES (?)", f"{prefix}-unspent")
    assert await directory.revoke_invite(db, f"{prefix}-unspent") == "revoked"
    assert await db.first("SELECT 1 FROM invites WHERE token = ?", f"{prefix}-unspent") is None
    assert await directory.revoke_invite(db, f"{prefix}-missing") == "not_found"
    await db.run("INSERT INTO invites (token, spent_by_did, spent_at) VALUES (?, ?, datetime('now'))", f"{prefix}-spent", "did:plc:x")
    assert await directory.revoke_invite(db, f"{prefix}-spent") == "spent"
    await db.run("INSERT INTO invites (token) VALUES (?)", f"{prefix}-pending")
    assert await directory.spend_invite_pending(db, f"{prefix}-pending")
    assert await directory.revoke_invite(db, f"{prefix}-pending") == "spent"


async def test_list_invites_state_filter(db):
    prefix = unique("dir-state")
    await db.batch([
        ("INSERT INTO invites (token, minted_at) VALUES (?, ?)", [f"{prefix}-u", "2099-07-01 00:00:00"]),
        ("INSERT INTO invites (token, minted_at, spent_by_did, spent_at) VALUES (?, ?, ?, ?)",
         [f"{prefix}-s", "2099-07-02 00:00:00", "did:plc:s", "2099-07-03 00:00:00"]),
        ("INSERT INTO invites (token, minted_at, spent_by_did, spent_at) VALUES (?, ?, 'pending', ?)",
         [f"{prefix}-p", "2099-07-04 00:00:00", "2099-07-05 00:00:00"]),
    ])
    assert [r["token"] for r in await directory.list_invites(db, 500, state="unspent")] == [f"{prefix}-u"]
    assert {r["token"] for r in await directory.list_invites(db, 500, state="spent")} == {f"{prefix}-s", f"{prefix}-p"}


async def test_init_directory_tolerates_concurrent_invocation(env):
    await asyncio.gather(*(directory.init_directory(env.db) for _ in range(8)))
    assert len((await directory.mint_org_invite(env.db))["token"]) == 10
