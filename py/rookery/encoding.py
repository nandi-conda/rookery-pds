# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Byte/text encodings used across atproto: base64url, base32, base58btc, s32."""

import base64
import hashlib

B32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
S32_ALPHABET = "234567abcdefghijklmnopqrstuvwxyz"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Lenient like atob: accepts base64url or base64, with or without padding."""
    cleaned = text.replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)
    return base64.b64decode(cleaned, validate=True)


def b64_encode_nopad(data: bytes) -> str:
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def b64_decode(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.b64decode(padded, validate=True)


def sha256(data: bytes | str) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


def sha256_b64url(data: bytes | str) -> str:
    return b64url_encode(sha256(data))


def sha256_hex(data: bytes | str) -> str:
    return sha256(data).hex()


def b32_encode(data: bytes) -> str:
    """RFC 4648 base32, lowercase, no padding."""
    return base64.b32encode(data).decode("ascii").rstrip("=").lower()


def b32_decode(text: str) -> bytes:
    upper = text.upper()
    return base64.b32decode(upper + "=" * (-len(upper) % 8))


def b58_encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = B58_ALPHABET[rem] + out
    zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * zeros + out


def b58_decode(text: str) -> bytes:
    num = 0
    for char in text:
        num = num * 58 + B58_ALPHABET.index(char)
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    zeros = len(text) - len(text.lstrip("1"))
    return b"\x00" * zeros + body


def s32_encode(value: int) -> str:
    out = ""
    while value > 0:
        value, rem = divmod(value, 32)
        out = S32_ALPHABET[rem] + out
    return out


def s32_decode(text: str) -> int:
    value = 0
    for char in text:
        value = value * 32 + S32_ALPHABET.index(char)
    return value
