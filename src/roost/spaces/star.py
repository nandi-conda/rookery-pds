# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""STAR-lite v1 archives, as star.ts in @atproto/space: getRepo's encoding.

    [ magic | len | meta ] [ len | key | len | value ] ...

Each len is a minimal unsigned varint. For the `atproto-space-repo` profile the
metadata is the repo's commit plus `$type`, and each pair is a record path
`{collection}/{rkey}` and its DRISL bytes, in strict byte order of the path.
"""

from .. import cbor
from ..cbor import _varint

STAR_MAGIC = bytes([0x2A, 0x6C, 0x01, 0x00])
REPO_STAR_TYPE = "atproto-space-repo"
MAX_RECORD_SIZE = 1024 * 1024
MAX_VARINT_BYTES = 6


class StarParseError(ValueError):
    pass


def _frame(raw: bytes) -> bytes:
    return _varint(len(raw)) + raw


def write_repo_star(commit: dict, records) -> bytes:
    """`records` yields (path, record bytes) in strict path order."""
    out = bytearray(STAR_MAGIC)
    out += _frame(cbor.encode({"$type": REPO_STAR_TYPE, **commit}))
    last = None
    for path, value in records:
        key = path.encode()
        if last is not None and key <= last:
            raise ValueError("STAR records must be in strict path order")
        last = key
        out += _frame(key) + _frame(value)
    return bytes(out)


def _read_varint(data: bytes, pos: int) -> tuple[int | None, int]:
    value = 0
    for i in range(MAX_VARINT_BYTES):
        if pos + i >= len(data):
            if i == 0:
                return None, pos
            raise StarParseError("unexpected end of archive")
        byte = data[pos + i]
        value += (byte & 0x7F) << (7 * i)
        if byte < 0x80:
            if byte == 0 and i > 0:
                raise StarParseError("non-canonical varint")
            return value, pos + i + 1
    raise StarParseError("varint too long")


def _read_frame(data: bytes, pos: int, max_length: int) -> tuple[bytes | None, int]:
    length, pos = _read_varint(data, pos)
    if length is None:
        return None, pos
    if length > max_length:
        raise StarParseError(f"length {length} exceeds limit of {max_length}")
    if pos + length > len(data):
        raise StarParseError("unexpected end of archive")
    return data[pos:pos + length], pos + length


def read_repo_star(data: bytes) -> tuple[dict, list[tuple[str, bytes]]]:
    """(metadata, [(path, record bytes)]) of a whole archive; raises StarParseError."""
    if data[:4] != STAR_MAGIC:
        raise StarParseError("invalid magic bytes")
    meta_bytes, pos = _read_frame(data, 4, len(data))
    if meta_bytes is None:
        raise StarParseError("missing metadata")
    try:
        meta = cbor.decode(meta_bytes)
    except Exception as exc:
        raise StarParseError("invalid metadata") from exc
    if not isinstance(meta, dict) or meta.get("$type") != REPO_STAR_TYPE or cbor.encode(meta) != meta_bytes:
        raise StarParseError("metadata must be a canonical atproto-space-repo map")
    pairs, last = [], None
    while True:
        key, pos = _read_frame(data, pos, len(data))
        if key is None:
            return meta, pairs
        value, pos = _read_frame(data, pos, MAX_RECORD_SIZE)
        if value is None:
            raise StarParseError("missing value for key")
        if last is not None and key <= last:
            raise StarParseError("duplicate or out-of-order key")
        last = key
        pairs.append((key.decode(), value))
