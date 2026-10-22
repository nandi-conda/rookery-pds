# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Commit and record MACs keyed by a per-request shared secret, as kem.ts and
mac.ts in @atproto/space.

A syncer reading with a space credential sends a fresh ephemeral P-256 key in
`Atproto-Space-Want-Mac`; the repo host agrees a secret with it using the
author's #atproto_kem key (DHKEM(P-256, HKDF-SHA256), RFC 9180 §4.1) and returns
an HMAC over the commit or record in `Atproto-Space-Mac`. A leaked response
proves nothing about authorship to a third party.
"""

import hashlib
import hmac

from ..keys import P256Keypair, p256_did_key_point
from .commit import COMMIT_VERSION
from .sfv import SfvError, Token, parse_dictionary, serialize_dictionary

COMMIT_MAC_TYPE = "atproto-space-repo"
RECORD_MAC_TYPE = "atproto-space-record"
RECORD_MAC_VERSION = 1
WANT_MAC_HEADER = "Atproto-Space-Want-Mac"
MAC_HEADER = "Atproto-Space-Mac"
KEM_PREFIX = b"HPKE-v1" + b"KEM" + (0x0010).to_bytes(2, "big")


class SpaceMacError(Exception):
    code = "BadSpaceMac"


def mac_version(mac_type: str) -> int:
    return COMMIT_VERSION if mac_type == COMMIT_MAC_TYPE else RECORD_MAC_VERSION


def _hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 extract-and-expand with an empty salt."""
    prk = hmac.new(b"", ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_shared_secret(dh: bytes, syncer_point: bytes, author_point: bytes) -> bytes:
    info = (32).to_bytes(2, "big") + KEM_PREFIX + b"shared_secret" + syncer_point + author_point
    return _hkdf_sha256(KEM_PREFIX + b"eae_prk" + dh, info)


def _kem_point(did_key: str) -> bytes:
    point = p256_did_key_point(did_key)
    if point is None:
        raise SpaceMacError("KEM key must be a P-256 did:key")
    return point


def encapsulate(author_kem_key: str) -> tuple[str, bytes]:
    """Syncer side (used by tests): (key_share, shared_secret) against the author's key."""
    author_point = _kem_point(author_kem_key)
    ephemeral = P256Keypair()
    return ephemeral.did(), derive_shared_secret(
        ephemeral.ecdh(author_point), ephemeral.public_bytes(compressed=False), author_point,
    )


def decapsulate(kem_keypair: P256Keypair, key_share: str) -> bytes:
    """Repo host side: the shared secret for a syncer's key share."""
    syncer_point = _kem_point(key_share)
    return derive_shared_secret(
        kem_keypair.ecdh(syncer_point), syncer_point, kem_keypair.public_bytes(compressed=False),
    )


def _length_prefixed(value: str) -> bytes:
    raw = value.encode()
    if len(raw) > 0xFFFF:
        raise ValueError("MAC context field exceeds uint16 length prefix")
    return len(raw).to_bytes(2, "big") + raw


def compute_commit_mac(secret: bytes, commit: dict) -> bytes:
    context = (f"{COMMIT_MAC_TYPE}-v{COMMIT_VERSION}".encode() + _length_prefixed(commit["space"])
               + _length_prefixed(commit["repo"]) + _length_prefixed(commit["rev"]))
    return hmac.new(secret, context + commit["data"], hashlib.sha256).digest()


def compute_record_mac(secret: bytes, uri: str, cid_bytes: bytes) -> bytes:
    context = f"{RECORD_MAC_TYPE}-v{RECORD_MAC_VERSION}".encode() + _length_prefixed(uri)
    return hmac.new(secret, context + cid_bytes, hashlib.sha256).digest()


def _parse(value, mac_type: str) -> dict:
    if not isinstance(value, str):
        raise SpaceMacError("missing or malformed MAC header")
    try:
        members = parse_dictionary(value)
    except SfvError as exc:
        raise SpaceMacError("malformed MAC header") from exc
    fields = {}
    for name, member in members.items():
        if member[0] != "item":
            raise SpaceMacError(f"malformed MAC header field: {name}")
        fields[name] = member[1]
    kind = fields.get("type")
    if isinstance(kind, Token) or kind != mac_type:
        raise SpaceMacError(f"unsupported MAC type, expected {mac_type}")
    version = fields.get("ver")
    if isinstance(version, bool) or version != mac_version(mac_type) or not isinstance(version, int):
        raise SpaceMacError(f"unsupported MAC version for {mac_type}")
    return fields


def format_want_mac_header(mac_type: str, key_share: str) -> str:
    return serialize_dictionary({"type": mac_type, "ver": mac_version(mac_type), "key_share": key_share})


def parse_want_mac_header(value, mac_type: str) -> str:
    """The request header's key_share; raises SpaceMacError."""
    key_share = _parse(value, mac_type).get("key_share")
    if not isinstance(key_share, str) or isinstance(key_share, Token):
        raise SpaceMacError("missing or malformed key_share")
    return key_share


def format_mac_header(mac_type: str, mac: bytes) -> str:
    return serialize_dictionary({"type": mac_type, "ver": mac_version(mac_type), "mac": mac})


def parse_mac_header(value, mac_type: str) -> bytes:
    mac = _parse(value, mac_type).get("mac")
    if not isinstance(mac, bytes):
        raise SpaceMacError("missing or malformed mac")
    return mac
