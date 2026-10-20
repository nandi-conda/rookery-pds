# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""secp256k1 keypairs for repo commits, service auth and PLC operations.

Signatures match @atproto/crypto: ECDSA over SHA-256, compact r||s, low-S.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .encoding import b58_decode, b58_encode

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_DID_PREFIX = bytes([0xE7, 0x01])
P256_DID_PREFIX = bytes([0x80, 0x24])


class Secp256k1Keypair:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey):
        self._key = private_key

    @classmethod
    def create(cls) -> "Secp256k1Keypair":
        return cls(ec.generate_private_key(ec.SECP256K1()))

    @classmethod
    def import_hex(cls, hex_key: str) -> "Secp256k1Keypair":
        value = int(hex_key, 16)
        return cls(ec.derive_private_key(value, ec.SECP256K1()))

    def export_hex(self) -> str:
        return self._key.private_numbers().private_value.to_bytes(32, "big").hex()

    def public_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )

    def did(self) -> str:
        return "did:key:z" + b58_encode(SECP256K1_DID_PREFIX + self.public_bytes())

    def sign(self, message: bytes) -> bytes:
        der = self._key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        if s > SECP256K1_ORDER // 2:
            s = SECP256K1_ORDER - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_did_key_signature(did_key: str, message: bytes, signature: bytes) -> bool:
    """Verify a compact low-S signature against a secp256k1 or P-256 did:key."""
    if not did_key.startswith("did:key:z") or len(signature) != 64:
        return False
    raw = b58_decode(did_key[len("did:key:z"):])
    if raw.startswith(SECP256K1_DID_PREFIX):
        curve, order = ec.SECP256K1(), SECP256K1_ORDER
    elif raw.startswith(P256_DID_PREFIX):
        curve = ec.SECP256R1()
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    else:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if s > order // 2:
        return False
    try:
        public = ec.EllipticCurvePublicKey.from_encoded_point(curve, raw[2:])
        public.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
