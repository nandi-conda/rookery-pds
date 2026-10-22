# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Spaces primitives, checked against BLAKE3's official vectors and against
values computed with the reference implementation's own code paths
(@atproto/space lthash.ts, kem.ts, mac.ts and star.ts)."""

import pytest

from roost import cbor
from roost.cbor import CID, _varint
from roost.keys import P256Keypair, Secp256k1Keypair
from roost.spaces import mac, star
from roost.spaces.blake3 import blake3
from roost.spaces.commit import build_commit
from roost.spaces.httpsig import SpaceSignatureError, create_space_sig_headers, verify_credential_sig
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


# Computed with @atproto/space and @atproto/crypto 0.0.0-spaces-alpha-20261022141228:
# P256Keypair.import of the keys below, decapsulate(author, syncer.did()), then
# computeCommitMac / computeRecordMac / formatWantMacHeader / formatMacHeader / serializeRepo.
AUTHOR_KEM, SYNCER_KEY = P256Keypair.import_hex("11" * 32), P256Keypair.import_hex("22" * 32)
SPACE = "at://did:plc:abc/space/com.example.forum/self"
COMMIT = {"ver": 1, "repo": "did:plc:xyz", "space": SPACE, "rev": "3l3l3l3l3l3l2", "data": bytes([7]) * 32}
SECRET = "76bccf1264f5f7f5b7df0b78b6c1037f2e22fb513288207ad2dede881710d4c3"
STAR = (
    "2a6c01009e01a6637265766d336c336c336c336c336c336c326376657201646461746158200707070707070707070707070707070707070"
    "707070707070707070707070707647265706f6b6469643a706c633a78797a65247479706572617470726f746f2d73706163652d7265706f"
    "657370616365782d61743a2f2f6469643a706c633a6162632f73706163652f636f6d2e6578616d706c652e666f72756d2f73656c660961"
    "2e622e632e642f7912a261740265247479706567612e622e632e6407612e622e632f7810a261740165247479706565612e622e63"
)


def test_kem_and_macs_match_reference():
    assert AUTHOR_KEM.did() == "did:key:zDnaeQa8zprPhHA7Yuxcgc2Uh6XNQgaKjmFZE4EaA9fk5svmJ"
    secret = mac.decapsulate(AUTHOR_KEM, SYNCER_KEY.did())
    assert secret.hex() == SECRET
    key_share, syncer_secret = mac.encapsulate(AUTHOR_KEM.did())
    assert mac.decapsulate(AUTHOR_KEM, key_share) == syncer_secret
    assert mac.compute_commit_mac(secret, COMMIT).hex() == (
        "8ace15bde70a5021a2aebac34b01785f93034ad3beda3100b2faa402d7a4b266")
    uri = f"{SPACE}/did:plc:xyz/a.b.c/x"
    cid = CID.parse("bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm")
    assert mac.compute_record_mac(secret, uri, cid.bytes).hex() == (
        "6a94eb72227e4ec11ad02f109bfb7baf5891319cb57af072a2e24d5bdb536062")
    assert mac.compute_commit_mac(secret, dict(COMMIT, repo="did:plc:other")) != mac.compute_commit_mac(secret, COMMIT)


def test_mac_headers_match_reference():
    want = mac.format_want_mac_header(mac.RECORD_MAC_TYPE, SYNCER_KEY.did())
    assert want == f'type="atproto-space-record", ver=1, key_share="{SYNCER_KEY.did()}"'
    assert mac.parse_want_mac_header(want, mac.RECORD_MAC_TYPE) == SYNCER_KEY.did()
    header = mac.format_mac_header(mac.COMMIT_MAC_TYPE, bytes([1]) * 32)
    assert header == 'type="atproto-space-repo", ver=1, mac=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:'
    assert mac.parse_mac_header(header.rstrip(":=") + ":", mac.COMMIT_MAC_TYPE) == bytes([1]) * 32
    for bad in (None, "nonsense(", want, want.replace("ver=1", "ver=2"),
                want.replace('"atproto-space-record"', "atproto-space-repo"),
                want.replace("key_share=", "other=")):
        with pytest.raises(mac.SpaceMacError):
            mac.parse_want_mac_header(bad, mac.COMMIT_MAC_TYPE if bad == want else mac.RECORD_MAC_TYPE)
    with pytest.raises(mac.SpaceMacError):
        mac.decapsulate(AUTHOR_KEM, Secp256k1Keypair.create().did())


def test_star_matches_reference_and_rejects_bad_archives():
    records = [("a.b.c.d/y", cbor.encode({"$type": "a.b.c.d", "t": 2})),
               ("a.b.c/x", cbor.encode({"$type": "a.b.c", "t": 1}))]
    data = star.write_repo_star(COMMIT, records)
    assert data.hex() == STAR
    meta, pairs = star.read_repo_star(data)
    assert meta == dict(COMMIT, **{"$type": "atproto-space-repo"}) and pairs == records
    assert star.read_repo_star(star.write_repo_star(COMMIT, []))[1] == []
    with pytest.raises(ValueError):
        star.write_repo_star(COMMIT, list(reversed(records)))
    for bad in (data[:-1], b"\0" + data[1:], data + data[-20:]):
        with pytest.raises(star.StarParseError):
            star.read_repo_star(bad)
    oversized = star.STAR_MAGIC + data[4:].split(b"\x09a.b.c.d/y")[0] + b"\x01a" + _varint(star.MAX_RECORD_SIZE + 1)
    with pytest.raises(star.StarParseError):
        star.read_repo_star(oversized + b"\0" * (star.MAX_RECORD_SIZE + 1))


def test_commit_data_is_the_lthash_digest():
    state = LtHash().add("a.b.c/1/bafy").state()
    commit = build_commit(state, SPACE, "did:plc:xyz", "3l3l3l3l3l3l2")
    assert commit == {"ver": 1, "repo": "did:plc:xyz", "space": SPACE, "rev": "3l3l3l3l3l3l2",
                      "data": LtHash(state).digest()}


def test_space_ref():
    ref = SpaceRef.parse("at://did:plc:abc/space/com.example.forum/self")
    assert (ref.did, ref.type, ref.skey) == ("did:plc:abc", "com.example.forum", "self")
    assert ref.record_uri("did:plc:x", "a.b.c", "1") == "at://did:plc:abc/space/com.example.forum/self/did:plc:x/a.b.c/1"
    for bad in ("at://did:plc:abc/com.example.forum/self", "at://did:plc:abc/space/notnsid/self", "x"):
        with pytest.raises(InvalidSpaceRef):
            SpaceRef.parse(bad)


def test_http_signature_roundtrip():
    key = P256Keypair()
    headers = create_space_sig_headers(key, "Atproto-Space-Credential x.y.z", "did:plc:aud")
    assert headers["signature-input"] == (
        'atproto-space-credential=("authorization" "atproto-space-audience");tag="atproto-space-credential"')
    verify_credential_sig(Headers(headers.items()), key.did())
    unpadded = dict(headers, signature=headers["signature"].rstrip(":=") + ":")
    verify_credential_sig(Headers(unpadded.items()), key.did())
    # The scheme is matched case-insensitively, but the signature covers the bytes sent.
    lowered = dict(headers, authorization="atproto-space-credential x.y.z")
    with pytest.raises(SpaceSignatureError):
        verify_credential_sig(Headers(lowered.items()), key.did())
    tampered = dict(headers, **{"atproto-space-audience": "did:plc:other"})
    untagged = dict(headers, **{"signature-input": headers["signature-input"].split(";")[0]})
    old_label = {k: v.replace("atproto-space-credential=", "atproto-space=") for k, v in headers.items()}
    for bad, signer in ((tampered, key), (untagged, key), (old_label, key), (headers, P256Keypair())):
        with pytest.raises(SpaceSignatureError):
            verify_credential_sig(Headers(bad.items()), signer.did())


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
