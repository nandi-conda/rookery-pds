# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""secp256k1 keypairs for repo commits, service auth and PLC operations, and
P-256 keypairs for space request signatures and space KEM keys.

Signatures match @atproto/crypto: ECDSA over SHA-256, compact r||s, low-S.
"""

from .crypto import lib

from .encoding import b58_decode, b58_encode

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_DID_PREFIX = bytes([0xE7, 0x01])
P256_DID_PREFIX = bytes([0x80, 0x24])


class Secp256k1Keypair:
    def __init__(self, private_key):
        self._key = private_key

    @classmethod
    def create(cls) -> "Secp256k1Keypair":
        c = lib()
        return cls(c.ec.generate_private_key(c.ec.SECP256K1()))

    @classmethod
    def import_hex(cls, hex_key: str) -> "Secp256k1Keypair":
        value = int(hex_key, 16)
        c = lib()
        return cls(c.ec.derive_private_key(value, c.ec.SECP256K1()))

    def export_hex(self) -> str:
        return self._key.private_numbers().private_value.to_bytes(32, "big").hex()

    def public_bytes(self) -> bytes:
        c = lib()
        return self._key.public_key().public_bytes(
            c.serialization.Encoding.X962, c.serialization.PublicFormat.CompressedPoint
        )

    def did(self) -> str:
        return "did:key:z" + b58_encode(SECP256K1_DID_PREFIX + self.public_bytes())

    def sign(self, message: bytes) -> bytes:
        c = lib()
        der = self._key.sign(message, c.ec.ECDSA(c.hashes.SHA256()))
        r, s = c.decode_dss_signature(der)
        if s > SECP256K1_ORDER // 2:
            s = SECP256K1_ORDER - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class P256Keypair:
    """Signs space requests (clients and tests) and, as an account's #atproto_kem
    key, agrees shared secrets with syncers (ECDH)."""

    def __init__(self, private_key=None):
        self._key = private_key or lib().ec.generate_private_key(lib().ec.SECP256R1())

    @classmethod
    def import_hex(cls, hex_key: str) -> "P256Keypair":
        return cls(lib().ec.derive_private_key(int(hex_key, 16), lib().ec.SECP256R1()))

    def export_hex(self) -> str:
        return self._key.private_numbers().private_value.to_bytes(32, "big").hex()

    def public_bytes(self, compressed: bool = True) -> bytes:
        c = lib()
        point = c.serialization.PublicFormat.CompressedPoint if compressed else c.serialization.PublicFormat.UncompressedPoint
        return self._key.public_key().public_bytes(c.serialization.Encoding.X962, point)

    def did(self) -> str:
        return "did:key:z" + b58_encode(P256_DID_PREFIX + self.public_bytes())

    def sign(self, message: bytes) -> bytes:
        r, s = lib().decode_dss_signature(self._key.sign(message, lib().ec.ECDSA(lib().hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def ecdh(self, public_point: bytes) -> bytes:
        """The x-coordinate of the shared point with a SEC1-encoded P-256 public key."""
        public = lib().ec.EllipticCurvePublicKey.from_encoded_point(lib().ec.SECP256R1(), public_point)
        return self._key.exchange(lib().ec.ECDH(), public)


def p256_did_key_point(did_key) -> bytes | None:
    """The uncompressed point (0x04 || x || y) of a P-256 did:key, or None."""
    if not isinstance(did_key, str) or not did_key.startswith("did:key:z"):
        return None
    try:
        raw = b58_decode(did_key[len("did:key:z"):])
    except Exception:
        return None
    if not raw.startswith(P256_DID_PREFIX):
        return None
    c = lib()
    try:
        public = c.ec.EllipticCurvePublicKey.from_encoded_point(c.ec.SECP256R1(), raw[2:])
    except ValueError:
        return None
    return public.public_bytes(c.serialization.Encoding.X962, c.serialization.PublicFormat.UncompressedPoint)


def verify_did_key_signature(did_key: str, message: bytes, signature: bytes) -> bool:
    """Verify a compact low-S signature against a secp256k1 or P-256 did:key."""
    if not did_key.startswith("did:key:z") or len(signature) != 64:
        return False
    c = lib()
    raw = b58_decode(did_key[len("did:key:z"):])
    if raw.startswith(SECP256K1_DID_PREFIX):
        curve, order = c.ec.SECP256K1(), SECP256K1_ORDER
    elif raw.startswith(P256_DID_PREFIX):
        curve = c.ec.SECP256R1()
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    else:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if s > order // 2:
        return False
    try:
        public = c.ec.EllipticCurvePublicKey.from_encoded_point(curve, raw[2:])
        public.verify(c.encode_dss_signature(r, s), message, c.ec.ECDSA(c.hashes.SHA256()))
        return True
    except Exception:
        return False
