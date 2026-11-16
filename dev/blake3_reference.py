#!/usr/bin/env python3
"""Independent pure-Python BLAKE3 reference implementation.

This is a direct, line-by-line port of the BLAKE3 team's specification
reference implementation (``reference_impl/reference_impl.rs`` in
https://github.com/BLAKE3-team/BLAKE3).  It shares *no code* with the native
``blake3`` package used by the optimized engine, so agreement between the two
is evidence of implementation correctness (Panel recommendation #5), not just
self-consistency.

It is intentionally simple and slow (roughly 1 MiB/s): it is used only for
verification, never for evidence hashing or benchmarking.
"""

from __future__ import annotations

from typing import List, Optional

OUT_LEN = 32
KEY_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
KEYED_HASH = 1 << 4
DERIVE_KEY_CONTEXT = 1 << 5
DERIVE_KEY_MATERIAL = 1 << 6

IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
MASK = 0xFFFFFFFF


def _rotr(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (32 - amount))) & MASK


def _g(state: List[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    state[a] = (state[a] + state[b] + mx) & MASK
    state[d] = _rotr(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotr(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & MASK
    state[d] = _rotr(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotr(state[b] ^ state[c], 7)


def _round(state: List[int], m: List[int]) -> None:
    # Mix the columns.
    _g(state, 0, 4, 8, 12, m[0], m[1])
    _g(state, 1, 5, 9, 13, m[2], m[3])
    _g(state, 2, 6, 10, 14, m[4], m[5])
    _g(state, 3, 7, 11, 15, m[6], m[7])
    # Mix the diagonals.
    _g(state, 0, 5, 10, 15, m[8], m[9])
    _g(state, 1, 6, 11, 12, m[10], m[11])
    _g(state, 2, 7, 8, 13, m[12], m[13])
    _g(state, 3, 4, 9, 14, m[14], m[15])


def _permute(m: List[int]) -> List[int]:
    return [m[MSG_PERMUTATION[i]] for i in range(16)]


def _compress(
    chaining_value: List[int],
    block_words: List[int],
    counter: int,
    block_len: int,
    flags: int,
) -> List[int]:
    state = [
        *chaining_value[:8],
        IV[0], IV[1], IV[2], IV[3],
        counter & MASK, (counter >> 32) & MASK, block_len, flags,
    ]
    block = list(block_words)
    for round_index in range(7):
        _round(state, block)
        if round_index < 6:
            block = _permute(block)
    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= chaining_value[i]
    return state


def _words_from_le_bytes(data: bytes) -> List[int]:
    return [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]


class _Output:
    def __init__(self, input_cv, block_words, counter, block_len, flags):
        self.input_chaining_value = input_cv
        self.block_words = block_words
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self) -> List[int]:
        return _compress(
            self.input_chaining_value, self.block_words,
            self.counter, self.block_len, self.flags,
        )[:8]

    def root_output_bytes(self, length: int) -> bytes:
        out = bytearray()
        output_block_counter = 0
        while len(out) < length:
            words = _compress(
                self.input_chaining_value, self.block_words,
                output_block_counter, self.block_len, self.flags | ROOT,
            )
            for word in words:
                out += word.to_bytes(4, "little")
            output_block_counter += 1
        return bytes(out[:length])


class _ChunkState:
    def __init__(self, key_words: List[int], chunk_counter: int, flags: int):
        self.chaining_value = list(key_words)
        self.chunk_counter = chunk_counter
        self.block = bytearray(BLOCK_LEN)
        self.block_len = 0
        self.blocks_compressed = 0
        self.flags = flags

    def length(self) -> int:
        return BLOCK_LEN * self.blocks_compressed + self.block_len

    def _start_flag(self) -> int:
        return CHUNK_START if self.blocks_compressed == 0 else 0

    def update(self, data: memoryview) -> None:
        while len(data):
            if self.block_len == BLOCK_LEN:
                block_words = _words_from_le_bytes(bytes(self.block))
                self.chaining_value = _compress(
                    self.chaining_value, block_words, self.chunk_counter,
                    BLOCK_LEN, self.flags | self._start_flag(),
                )[:8]
                self.blocks_compressed += 1
                self.block = bytearray(BLOCK_LEN)
                self.block_len = 0
            want = BLOCK_LEN - self.block_len
            take = min(want, len(data))
            self.block[self.block_len:self.block_len + take] = data[:take]
            self.block_len += take
            data = data[take:]

    def output(self) -> _Output:
        block_words = _words_from_le_bytes(bytes(self.block))
        return _Output(
            self.chaining_value, block_words, self.chunk_counter,
            self.block_len, self.flags | self._start_flag() | CHUNK_END,
        )


def _parent_output(left_cv, right_cv, key_words, flags) -> _Output:
    return _Output(key_words, list(left_cv) + list(right_cv), 0, BLOCK_LEN, PARENT | flags)


class ReferenceHasher:
    """Incremental BLAKE3 hasher (hash, keyed_hash, derive_key modes)."""

    def __init__(self, key_words: Optional[List[int]] = None, flags: int = 0):
        self.key_words = list(key_words) if key_words is not None else list(IV)
        self.flags = flags
        self.chunk_state = _ChunkState(self.key_words, 0, flags)
        self.cv_stack: List[List[int]] = []

    @classmethod
    def new_keyed(cls, key: bytes) -> "ReferenceHasher":
        if len(key) != KEY_LEN:
            raise ValueError("key must be exactly 32 bytes")
        return cls(_words_from_le_bytes(key), KEYED_HASH)

    @classmethod
    def new_derive_key(cls, context: str) -> "ReferenceHasher":
        context_hasher = cls(list(IV), DERIVE_KEY_CONTEXT)
        context_hasher.update(context.encode("utf-8"))
        context_key = context_hasher.finalize(KEY_LEN)
        return cls(_words_from_le_bytes(context_key), DERIVE_KEY_MATERIAL)

    def _add_chunk_chaining_value(self, new_cv: List[int], total_chunks: int) -> None:
        # Merge completed subtrees: one merge per trailing zero bit.
        while total_chunks & 1 == 0:
            new_cv = _parent_output(
                self.cv_stack.pop(), new_cv, self.key_words, self.flags
            ).chaining_value()
            total_chunks >>= 1
        self.cv_stack.append(new_cv)

    def update(self, data: bytes) -> "ReferenceHasher":
        view = memoryview(bytes(data))
        while len(view):
            if self.chunk_state.length() == CHUNK_LEN:
                chunk_cv = self.chunk_state.output().chaining_value()
                total_chunks = self.chunk_state.chunk_counter + 1
                self._add_chunk_chaining_value(chunk_cv, total_chunks)
                self.chunk_state = _ChunkState(self.key_words, total_chunks, self.flags)
            want = CHUNK_LEN - self.chunk_state.length()
            take = min(want, len(view))
            self.chunk_state.update(view[:take])
            view = view[take:]
        return self

    def finalize(self, length: int = OUT_LEN) -> bytes:
        output = self.chunk_state.output()
        parent_nodes_remaining = len(self.cv_stack)
        while parent_nodes_remaining > 0:
            parent_nodes_remaining -= 1
            output = _parent_output(
                self.cv_stack[parent_nodes_remaining],
                output.chaining_value(),
                self.key_words,
                self.flags,
            )
        return output.root_output_bytes(length)


def reference_hash(data: bytes, length: int = OUT_LEN) -> bytes:
    return ReferenceHasher().update(data).finalize(length)


def reference_keyed_hash(key: bytes, data: bytes, length: int = OUT_LEN) -> bytes:
    return ReferenceHasher.new_keyed(key).update(data).finalize(length)


def reference_derive_key(context: str, material: bytes, length: int = OUT_LEN) -> bytes:
    return ReferenceHasher.new_derive_key(context).update(material).finalize(length)
