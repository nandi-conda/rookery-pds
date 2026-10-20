# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""BLAKE3 in pure Python, hash mode only, with extendable output.

The space set hash expands each element to 2048 bytes with BLAKE3's XOF, and
neither hashlib nor the Workers runtime has BLAKE3. Inputs here are short
(a record path and CID), so speed is not a concern.
"""

IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
CHUNK_START, CHUNK_END, PARENT, ROOT = 1, 2, 4, 8
BLOCK_LEN, CHUNK_LEN = 64, 1024
MASK = 0xFFFFFFFF


def _g(s, a, b, c, d, x, y):
    s[a] = (s[a] + s[b] + x) & MASK
    v = s[d] ^ s[a]
    s[d] = ((v >> 16) | (v << 16)) & MASK
    s[c] = (s[c] + s[d]) & MASK
    v = s[b] ^ s[c]
    s[b] = ((v >> 12) | (v << 20)) & MASK
    s[a] = (s[a] + s[b] + y) & MASK
    v = s[d] ^ s[a]
    s[d] = ((v >> 8) | (v << 24)) & MASK
    s[c] = (s[c] + s[d]) & MASK
    v = s[b] ^ s[c]
    s[b] = ((v >> 7) | (v << 25)) & MASK


def _compress(cv, block_words, counter, block_len, flags) -> list[int]:
    s = list(cv) + list(IV[:4]) + [counter & MASK, (counter >> 32) & MASK, block_len, flags]
    m = list(block_words)
    for round_index in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1])
        _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5])
        _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9])
        _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13])
        _g(s, 3, 4, 9, 14, m[14], m[15])
        if round_index < 6:
            m = [m[i] for i in MSG_PERMUTATION]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _words(block: bytes) -> list[int]:
    block = block.ljust(BLOCK_LEN, b"\0")
    return [int.from_bytes(block[i:i + 4], "little") for i in range(0, BLOCK_LEN, 4)]


class _Output:
    def __init__(self, cv, block_words, counter, block_len, flags):
        self.cv, self.block_words, self.counter = cv, block_words, counter
        self.block_len, self.flags = block_len, flags

    def chaining_value(self) -> list[int]:
        return _compress(self.cv, self.block_words, self.counter, self.block_len, self.flags)[:8]

    def root_bytes(self, length: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            words = _compress(self.cv, self.block_words, counter, self.block_len, self.flags | ROOT)
            out += b"".join(word.to_bytes(4, "little") for word in words)
            counter += 1
        return bytes(out[:length])


def _chunk_output(chunk: bytes, chunk_counter: int) -> _Output:
    cv = list(IV)
    blocks = [chunk[i:i + BLOCK_LEN] for i in range(0, len(chunk), BLOCK_LEN)] or [b""]
    for index, block in enumerate(blocks):
        flags = (CHUNK_START if index == 0 else 0) | (CHUNK_END if index == len(blocks) - 1 else 0)
        if index == len(blocks) - 1:
            return _Output(cv, _words(block), chunk_counter, len(block), flags)
        cv = _compress(cv, _words(block), chunk_counter, BLOCK_LEN, flags)[:8]
    raise AssertionError("unreachable")


def _parent_output(left: list[int], right: list[int]) -> _Output:
    return _Output(list(IV), left + right, 0, BLOCK_LEN, PARENT)


def blake3(data: bytes, length: int = 32) -> bytes:
    chunks = [data[i:i + CHUNK_LEN] for i in range(0, len(data), CHUNK_LEN)] or [b""]
    stack: list[list[int]] = []
    for counter, chunk in enumerate(chunks[:-1]):
        cv = _chunk_output(chunk, counter).chaining_value()
        total = counter + 1
        while total & 1 == 0:
            cv = _parent_output(stack.pop(), cv).chaining_value()
            total >>= 1
        stack.append(cv)
    output = _chunk_output(chunks[-1], len(chunks) - 1)
    while stack:
        output = _parent_output(stack.pop(), output.chaining_value())
    return output.root_bytes(length)
