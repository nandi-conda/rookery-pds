# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Commits over a permissioned repo, as RepoCommit in @atproto/space.

A commit carries no signature: `data` is the sha256 of the repo's LtHash state,
and the repo host authenticates the commit to each syncer with a MAC in a
response header (see mac.py).
"""

from .lthash import LtHash

COMMIT_VERSION = 1


def set_hash_element(collection: str, rkey: str, cid: str) -> str:
    return f"{collection}/{rkey}/{cid}"


def apply_op(set_hash: LtHash, collection: str, rkey: str, cid: str | None, prev: str | None) -> None:
    if prev:
        set_hash.remove(set_hash_element(collection, rkey, prev))
    if cid:
        set_hash.add(set_hash_element(collection, rkey, cid))


def build_commit(state: bytes, space: str, repo: str, rev: str) -> dict:
    """com.atproto.space.defs#commit"""
    return {"ver": COMMIT_VERSION, "repo": repo, "space": space, "rev": rev, "data": LtHash(state).digest()}
