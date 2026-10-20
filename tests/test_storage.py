# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The Account DO's SQLite repo storage: blocks, head, commits, collections, blobs, dump/restore."""

import pytest

from fakes import Sql
from roost import cbor
from roost.cbor import CID
from roost.storage import RepoStorage


@pytest.fixture
def storage():
    storage = RepoStorage(Sql())
    storage.init_schema()
    return storage


def block(value) -> tuple[CID, bytes]:
    raw = cbor.encode(value)
    return CID.for_cbor(raw), raw


def commit(storage, value, rev: str, new: list, removed: set = frozenset()) -> CID:
    cid, raw = block(value)
    storage.apply_commit(cid=cid, rev=rev, data_cid=cid, new_blocks=dict(new + [(cid, raw)]), removed=set(removed))
    return cid


def test_stores_and_retrieves_blocks(storage):
    cid, raw = block({"hello": "world"})
    assert storage.get_block(cid) is None and not storage.has_block(cid)
    commit(storage, {"type": "commit"}, "rev1", [(cid, raw)])
    assert storage.get_block(cid) == raw and storage.has_block(cid)
    assert len(storage.all_blocks()) == 2


def test_head_starts_empty_and_moves_with_commits(storage):
    state = storage.get_state()
    assert state["root_cid"] is None and state["rev"] is None
    head = commit(storage, {"root": "commit1"}, "rev1", [])
    state = storage.get_state()
    assert state["root_cid"] == str(head) and state["rev"] == "rev1"


def test_applying_a_commit_drops_removed_blocks(storage):
    old = block({"old": "data"})
    commit(storage, {"type": "commit", "rev": 1}, "rev1", [old])
    assert storage.has_block(old[0])
    new = block({"new": "data"})
    head = commit(storage, {"type": "commit", "rev": 2}, "rev2", [new], {old[0]})
    assert not storage.has_block(old[0]) and storage.has_block(new[0])
    assert storage.get_state()["root_cid"] == str(head) and storage.get_state()["rev"] == "rev2"


def test_a_removed_block_that_is_also_new_is_kept(storage):
    shared = block({"shared": True})
    commit(storage, {"rev": 1}, "rev1", [shared])
    commit(storage, {"rev": 2}, "rev2", [shared], {shared[0]})
    assert storage.has_block(shared[0])


def test_collections_are_a_sorted_set(storage):
    assert storage.get_collections() == []
    for collection in ("app.bsky.feed.post", "app.bsky.feed.like", "app.bsky.feed.post"):
        storage.add_collection(collection)
    assert storage.get_collections() == ["app.bsky.feed.like", "app.bsky.feed.post"]


def test_blob_listing_pages_by_cid(storage):
    for cid in ("c", "a", "b"):
        storage.insert_blob(cid, "text/plain", 1)
    storage.insert_blob("a", "text/plain", 1)
    first = storage.list_blobs(2)
    assert first == {"cids": ["a", "b"], "cursor": "b"}
    assert storage.list_blobs(2, first["cursor"]) == {"cids": ["c"]}


def test_dump_and_restore_round_trip(storage):
    storage.init_account_state(did="did:plc:x", handle="x.rookery.test", signing_key_hex="aa", signing_key_pub="zA",
                               rotation_key_hex="bb", rotation_key_pub="zB", jwk_thumbprint="jkt")
    data = block({"record": 1})
    commit(storage, {"rev": 1}, "rev1", [data])
    storage.add_collection("com.example.x")
    storage.insert_blob("bafyblob", "image/png", 7)
    dump = storage.dump()

    copy = RepoStorage(Sql())
    copy.init_schema()
    copy.restore(dump)
    assert copy.get_state() == storage.get_state()
    assert sorted(copy.all_blocks()) == sorted(storage.all_blocks())
    assert copy.get_collections() == ["com.example.x"]
    assert copy.list_blobs() == {"cids": ["bafyblob"]}
    with pytest.raises(ValueError, match="already provisioned"):
        copy.restore(dump)


def test_dump_requires_a_provisioned_account(storage):
    with pytest.raises(ValueError, match="not provisioned"):
        storage.dump()


def test_delete_all_wipes_the_account(storage):
    commit(storage, {"rev": 1}, "rev1", [])
    storage.add_collection("com.example.x")
    storage.delete_all()
    assert storage.get_state() is None and storage.all_blocks() == [] and storage.get_collections() == []
