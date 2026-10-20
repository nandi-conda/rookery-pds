# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""DAG-CBOR (the atproto subset) and CIDv1.

Encoding is canonical: map keys sorted by length then bytes, minimal integer
heads, CIDs as tag 42. Floats are refused, as the AT data model has none.
Decoding accepts any well-formed DAG-CBOR, floats included, so stored blocks
written by other software always read back.
"""

import struct

from .encoding import b32_decode, b32_encode, b58_decode, sha256

CODEC_DAG_CBOR = 0x71
CODEC_RAW = 0x55
MULTIHASH_SHA256 = 0x12
MAX_SAFE_INTEGER = 2**53 - 1


class CborError(ValueError):
    pass


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise CborError("truncated varint")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            raise CborError("varint too long")


class CID:
    """A content identifier. Holds the binary form; compares and hashes by it."""

    __slots__ = ("bytes",)

    def __init__(self, raw: bytes):
        self.bytes = bytes(raw)

    @classmethod
    def for_cbor(cls, block: bytes) -> "CID":
        return cls.create(CODEC_DAG_CBOR, block)

    @classmethod
    def create(cls, codec: int, block: bytes) -> "CID":
        digest = sha256(block)
        return cls(b"\x01" + _varint(codec) + bytes([MULTIHASH_SHA256, len(digest)]) + digest)

    @classmethod
    def parse(cls, text: str) -> "CID":
        if not isinstance(text, str) or not text:
            raise CborError("CID must be a non-empty string")
        if text.startswith("Qm") and len(text) == 46:
            # CIDv0: bare base58btc sha256 multihash, implicitly dag-pb.
            return cls(b58_decode(text))
        if text[0] != "b":
            raise CborError("unsupported CID multibase")
        try:
            raw = b32_decode(text[1:])
        except Exception as exc:
            raise CborError("invalid CID base32") from exc
        cid = cls(raw)
        cid._validate()
        return cid

    def _validate(self) -> None:
        version, pos = _read_varint(self.bytes, 0)
        if version != 1:
            raise CborError("unsupported CID version")
        _, pos = _read_varint(self.bytes, pos)
        _, pos = _read_varint(self.bytes, pos)
        size, pos = _read_varint(self.bytes, pos)
        if len(self.bytes) != pos + size:
            raise CborError("CID digest length mismatch")

    @property
    def codec(self) -> int:
        if self.bytes[:1] == b"\x12":
            return 0x70
        _, pos = _read_varint(self.bytes, 0)
        codec, _ = _read_varint(self.bytes, pos)
        return codec

    def __str__(self) -> str:
        if self.bytes[:1] == b"\x12":
            from .encoding import b58_encode

            return b58_encode(self.bytes)
        return "b" + b32_encode(self.bytes)

    def __repr__(self) -> str:
        return f"CID({self})"

    def __eq__(self, other) -> bool:
        return isinstance(other, CID) and other.bytes == self.bytes

    def __hash__(self) -> int:
        return hash(self.bytes)


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    if value < 0x10000:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 0x100000000:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def _key_order(key: str) -> tuple[int, bytes]:
    raw = key.encode("utf-8")
    return (len(raw), raw)


def _encode(value, out: bytearray) -> None:
    if value is None:
        out.append(0xF6)
    elif value is True:
        out.append(0xF5)
    elif value is False:
        out.append(0xF4)
    elif isinstance(value, int):
        if value > MAX_SAFE_INTEGER or value < -MAX_SAFE_INTEGER:
            raise CborError("integers beyond 2^53 are not allowed by the AT data model")
        if value >= 0:
            out += _head(0, value)
        else:
            out += _head(1, -1 - value)
    elif isinstance(value, float):
        raise CborError("Non-integer numbers are not allowed by the AT Data Model")
    elif isinstance(value, str):
        raw = value.encode("utf-8")
        out += _head(3, len(raw))
        out += raw
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        out += _head(2, len(raw))
        out += raw
    elif isinstance(value, CID):
        payload = b"\x00" + value.bytes
        out += _head(6, 42)
        out += _head(2, len(payload))
        out += payload
    elif isinstance(value, (list, tuple)):
        out += _head(4, len(value))
        for item in value:
            _encode(item, out)
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CborError("map keys must be strings")
        keys = sorted(value.keys(), key=_key_order)
        out += _head(5, len(keys))
        for key in keys:
            raw = key.encode("utf-8")
            out += _head(3, len(raw))
            out += raw
            _encode(value[key], out)
    else:
        raise CborError(f"cannot encode {type(value).__name__} as DAG-CBOR")


def encode(value) -> bytes:
    out = bytearray()
    _encode(value, out)
    return bytes(out)


class _Decoder:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        end = self.pos + count
        if end > len(self.data):
            raise CborError("unexpected end of CBOR data")
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    def argument(self, info: int) -> int:
        if info < 24:
            return info
        if info == 24:
            return self.take(1)[0]
        if info == 25:
            return int.from_bytes(self.take(2), "big")
        if info == 26:
            return int.from_bytes(self.take(4), "big")
        if info == 27:
            return int.from_bytes(self.take(8), "big")
        raise CborError("indefinite lengths are not allowed in DAG-CBOR")

    def value(self):
        initial = self.take(1)[0]
        major = initial >> 5
        info = initial & 0x1F
        if major == 7:
            if info == 20:
                return False
            if info == 21:
                return True
            if info == 22:
                return None
            if info == 25:
                return _half_to_float(self.take(2))
            if info == 26:
                return struct.unpack(">f", self.take(4))[0]
            if info == 27:
                return struct.unpack(">d", self.take(8))[0]
            raise CborError("unsupported CBOR simple value")
        arg = self.argument(info)
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            return self.take(arg)
        if major == 3:
            try:
                return self.take(arg).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CborError("invalid UTF-8 string") from exc
        if major == 4:
            return [self.value() for _ in range(arg)]
        if major == 5:
            result = {}
            for _ in range(arg):
                key = self.value()
                if not isinstance(key, str):
                    raise CborError("map keys must be strings")
                result[key] = self.value()
            return result
        if major == 6:
            if arg != 42:
                raise CborError(f"unsupported CBOR tag {arg}")
            payload = self.value()
            if not isinstance(payload, bytes) or payload[:1] != b"\x00":
                raise CborError("invalid CID link")
            return CID(payload[1:])
        raise CborError("invalid CBOR major type")


def _half_to_float(raw: bytes) -> float:
    return struct.unpack(">e", raw)[0]


def decode(data: bytes):
    decoder = _Decoder(bytes(data))
    result = decoder.value()
    if decoder.pos != len(decoder.data):
        raise CborError("trailing bytes after CBOR value")
    return result


def decode_first(data: bytes, pos: int = 0):
    """Decode one value starting at pos; returns (value, next position)."""
    decoder = _Decoder(bytes(data))
    decoder.pos = pos
    return decoder.value(), decoder.pos
