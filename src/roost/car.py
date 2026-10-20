# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""CAR v1 files: a DAG-CBOR header naming the root, then varint-framed blocks."""

from . import cbor
from .cbor import CID, _read_varint, _varint


def write_car(root: CID | None, blocks) -> bytes:
    """`blocks` is an iterable of (CID, bytes); a CAR without a root (getBlocks) has no roots."""
    header = cbor.encode({"version": 1, "roots": [root] if root else []})
    out = bytearray(_varint(len(header)))
    out += header
    for cid, raw in blocks:
        cid_bytes = cid.bytes if isinstance(cid, CID) else CID.parse(cid).bytes
        out += _varint(len(cid_bytes) + len(raw))
        out += cid_bytes
        out += raw
    return bytes(out)


def read_car(data: bytes) -> tuple[list[CID], dict[CID, bytes]]:
    length, pos = _read_varint(data, 0)
    header = cbor.decode(data[pos:pos + length])
    pos += length
    blocks: dict[CID, bytes] = {}
    while pos < len(data):
        length, pos = _read_varint(data, pos)
        end = pos + length
        version, cid_end = _read_varint(data, pos)
        _, cid_end = _read_varint(data, cid_end)
        _, cid_end = _read_varint(data, cid_end)
        size, cid_end = _read_varint(data, cid_end)
        cid_end += size
        blocks[CID(data[pos:cid_end])] = data[cid_end:end]
        pos = end
    return header["roots"], blocks
