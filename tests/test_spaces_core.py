# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Spaces primitives, checked against BLAKE3's official vectors and against
values computed with the reference implementation's own code paths
(@atproto/space lthash.ts / repo-commit.ts on @noble/hashes)."""

import pytest

from roost.keys import Secp256k1Keypair
from roost.spaces.blake3 import blake3
from roost.spaces.commit import compute_mac, encode_ctx, sign_commit, verify_commit
from roost.spaces.httpsig import P256Keypair, SpaceSignatureError, create_space_sig_headers, verify_space_signature
from roost.spaces.lthash import LtHash
from roost.spaces.refs import InvalidSpaceRef, SpaceRef
from roost.spaces.scopes import parse_space_scope, space_scope_denial
from roost.web import Headers


def official_input(n):
    return bytes(i % 251 for i in range(n))


@pytest.mark.parametrize("length,expected", [
    (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
    (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
    (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
])
def test_blake3_official_vectors(length, expected):
    assert blake3(official_input(length)).hex() == expected


def test_blake3_xof_matches_noble():
    assert blake3(b"hello", 2048)[-32:].hex() == "0dece546ec43f56b6f082194f7f5dfdb94992c07d9e5a519588468ec3fba2499"


def test_lthash_matches_reference():
    h = LtHash().add("app.bsky.feed.post/3k2a/bafyreia").add("x.y.z/abc/bafyreib")
    h.remove("app.bsky.feed.post/3k2a/bafyreia").add("q.r.s/1/bafyreic")
    assert h.digest().hex() == "964a96c802bca454ce8cd64697d608d5fa8f2aefb7395ca452df6c669ac7ed65"
    assert h.state()[:16].hex() == "c99cc8d3e5058cc47884c1891a876b0e"


def test_lthash_set_semantics():
    a = LtHash().add("a").add("b")
    assert a == LtHash().add("b").add("a")
    assert LtHash(a.state()) == a
    assert LtHash().add("a").remove("a").is_empty()
    assert not LtHash().add("a").add("a").remove("a").is_empty()
    with pytest.raises(ValueError):
        LtHash(b"\0" * 32)


def test_commit_ctx_and_mac_match_reference():
    ikm = bytes(range(32))
    ctx = encode_ctx("at://did:plc:abc/space/com.example.forum/self", "did:plc:xyz", "3l3l3l3l3l3l2", ikm)
    assert ctx.hex() == (
        "617470726f746f2d73706163652d7631002d61743a2f2f6469643a706c633a6162632f73706163652f636f6d2e6578616d"
        "706c652e666f72756d2f73656c66000b6469643a706c633a78797a000d336c336c336c336c336c336c320020000102030405"
        "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    h = LtHash().add("app.bsky.feed.post/3k2a/bafyreia").add("x.y.z/abc/bafyreib")
    h.remove("app.bsky.feed.post/3k2a/bafyreia").add("q.r.s/1/bafyreic")
    assert compute_mac(ikm, ctx, h.digest()).hex() == "bab867eba739a36faf4e8ab9cfdf3a67e90b6a7b4162c296d329da982f64c34e"


def test_commit_sign_verify():
    key = Secp256k1Keypair.create()
    state = LtHash().add("a.b.c/1/bafy").state()
    space = "at://did:plc:abc/space/com.example.forum/self"
    commit = sign_commit(state, space, "did:plc:xyz", "3l3l3l3l3l3l2", key)
    assert verify_commit(commit, space, "did:plc:xyz", "3l3l3l3l3l3l2", key.did())
    assert not verify_commit(commit, space, "did:plc:other", "3l3l3l3l3l3l2", key.did())
    assert not verify_commit(dict(commit, hash=b"\0" * 32), space, "did:plc:xyz", "3l3l3l3l3l3l2", key.did())


def test_space_ref():
    ref = SpaceRef.parse("at://did:plc:abc/space/com.example.forum/self")
    assert (ref.did, ref.type, ref.skey) == ("did:plc:abc", "com.example.forum", "self")
    assert ref.record_uri("did:plc:x", "a.b.c", "1") == "at://did:plc:abc/space/com.example.forum/self/did:plc:x/a.b.c/1"
    for bad in ("at://did:plc:abc/com.example.forum/self", "at://did:plc:abc/space/notnsid/self", "x"):
        with pytest.raises(InvalidSpaceRef):
            SpaceRef.parse(bad)


def test_http_signature_roundtrip():
    key = P256Keypair()
    headers = create_space_sig_headers(key, "Bearer abc.def.ghi")
    assert verify_space_signature(Headers(headers.items())) == key.did()
    bound = create_space_sig_headers(key, "Atproto-Space x.y.z", audience="did:plc:aud")
    assert verify_space_signature(Headers(bound.items()), key.did()) == key.did()
    tampered = dict(bound, **{"atproto-space-audience": "did:plc:other"})
    with pytest.raises(SpaceSignatureError):
        verify_space_signature(Headers(tampered.items()), key.did())
    with pytest.raises(SpaceSignatureError):
        verify_space_signature(Headers(bound.items()), P256Keypair().did())


def test_space_scopes():
    perm = parse_space_scope("space:com.example.forum?collection=com.example.post")
    assert perm["authority"] == "self" and perm["action"] == ("read", "create", "update", "delete")
    ref = {"type": "com.example.forum", "authority": "did:plc:me", "skey": "x"}
    scope = "atproto space:com.example.forum?collection=com.example.post"
    assert space_scope_denial(scope, "did:plc:me", ref, action="create", collection="com.example.post") is None
    assert space_scope_denial(scope, "did:plc:me", ref, action="create", collection="com.example.other")
    assert space_scope_denial(scope, "did:plc:me", dict(ref, authority="did:plc:them"), action="read")
    assert space_scope_denial(scope, "did:plc:me", ref, manage="create")
    assert space_scope_denial("atproto space:*?authority=*&manage=create", "did:plc:me", ref, manage="create") is None
    assert parse_space_scope("space:not-an-nsid") is None
