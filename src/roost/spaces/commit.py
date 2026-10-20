# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Signed commits over a permissioned repo, as RepoCommit in @atproto/space.

The signature covers only the context (space, author, rev, ikm), never the
digest, so a leaked commit proves nothing about what the author wrote; the
digest is bound to the context by an HMAC keyed from the per-commit ikm.
"""

import hashlib
import hmac
import secrets

from ..keys import Secp256k1Keypair, verify_did_key_signature
from .lthash import LtHash

COMMIT_VERSION = 1
DOMAIN_PREFIX = b"atproto-space-v1"


def set_hash_element(collection: str, rkey: str, cid: str) -> str:
    return f"{collection}/{rkey}/{cid}"


def encode_ctx(space: str, author: str, rev: str, ikm: bytes) -> bytes:
    out = bytearray(DOMAIN_PREFIX)
    for field in (space.encode(), author.encode(), rev.encode(), ikm):
        if len(field) > 0xFFFF:
            raise ValueError("commit ctx field exceeds uint16 length prefix")
        out += len(field).to_bytes(2, "big") + field
    return bytes(out)


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int = 32) -> bytes:
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def compute_mac(ikm: bytes, ctx: bytes, digest: bytes) -> bytes:
    return hmac.new(hkdf_expand_sha256(ikm, ctx), digest, hashlib.sha256).digest()


def apply_op(set_hash: LtHash, collection: str, rkey: str, cid: str | None, prev: str | None) -> None:
    if prev:
        set_hash.remove(set_hash_element(collection, rkey, prev))
    if cid:
        set_hash.add(set_hash_element(collection, rkey, cid))


def sign_commit(state: bytes, space: str, author: str, rev: str, keypair: Secp256k1Keypair) -> dict:
    digest = LtHash(state).digest()
    ikm = secrets.token_bytes(32)
    ctx = encode_ctx(space, author, rev, ikm)
    return {
        "ver": COMMIT_VERSION,
        "hash": digest,
        "ikm": ikm,
        "mac": compute_mac(ikm, ctx, digest),
        "sig": keypair.sign(ctx),
        "rev": rev,
    }


def verify_commit(commit: dict, space: str, author: str, rev: str, did_key: str) -> bool:
    if commit.get("ver") != COMMIT_VERSION or commit.get("rev") != rev:
        return False
    ctx = encode_ctx(space, author, rev, commit["ikm"])
    if not hmac.compare_digest(compute_mac(commit["ikm"], ctx, commit["hash"]), commit["mac"]):
        return False
    return verify_did_key_signature(did_key, ctx, commit["sig"])
