# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Timestamp identifiers (TIDs) for commit revs, as in @atproto/common-web.

Workers freeze the clock within a request, so a per-isolate counter keeps
TIDs minted in the same millisecond distinct and increasing.
"""

import random
import time

from .encoding import s32_decode, s32_encode

_last_ms = 0
_count = 0
_clock_id = random.randrange(32)


def _from_time(timestamp_us: int, clock_id: int) -> str:
    return s32_encode(timestamp_us) + s32_encode(clock_id).rjust(2, "2")


def next_tid(prev: str | None = None) -> str:
    global _last_ms, _count
    now_ms = max(int(time.time() * 1000), _last_ms)
    if now_ms == _last_ms:
        _count += 1
    _last_ms = now_ms
    tid = _from_time(now_ms * 1000 + _count, _clock_id)
    if prev is None or tid > prev:
        return tid
    return _from_time(s32_decode(prev[:11]) + 1, _clock_id)
