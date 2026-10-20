# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The homomorphic set hash behind a permissioned repo's commit, as in @atproto/space.

Each element expands (BLAKE3 XOF) to 1024 little-endian u16 lanes, summed into
the state mod 2^16, so the state depends only on the current set.
"""

import hashlib
from array import array

from .blake3 import blake3

LANES = 1024
STATE_BYTES = LANES * 2


def _lanes(raw: bytes) -> array:
    lanes = array("H")
    lanes.frombytes(raw)
    if array("H", [1]).tobytes() != b"\x01\x00":
        lanes.byteswap()
    return lanes


def _bytes(lanes: array) -> bytes:
    if array("H", [1]).tobytes() != b"\x01\x00":
        lanes = array("H", lanes)
        lanes.byteswap()
    return lanes.tobytes()


class LtHash:
    def __init__(self, state: bytes | None = None):
        if state is not None and len(state) != STATE_BYTES:
            raise ValueError(f"LtHash state must be {STATE_BYTES} bytes, got {len(state)}")
        self._lanes = _lanes(bytes(state) if state is not None else bytes(STATE_BYTES))

    def _apply(self, element: str, sign: int) -> "LtHash":
        expanded = _lanes(blake3(element.encode("utf-8"), STATE_BYTES))
        lanes = self._lanes
        for i in range(LANES):
            lanes[i] = (lanes[i] + sign * expanded[i]) & 0xFFFF
        return self

    def add(self, element: str) -> "LtHash":
        return self._apply(element, 1)

    def remove(self, element: str) -> "LtHash":
        return self._apply(element, -1)

    def state(self) -> bytes:
        return _bytes(self._lanes)

    def digest(self) -> bytes:
        return hashlib.sha256(self.state()).digest()

    def is_empty(self) -> bool:
        return not any(self._lanes)

    def __eq__(self, other) -> bool:
        return isinstance(other, LtHash) and self._lanes == other._lanes
