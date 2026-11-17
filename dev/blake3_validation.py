#!/usr/bin/env python3
"""Verification procedures for the optimized BLAKE3 implementation.

Procedures
----------
V1  Official test vectors – all 35 BLAKE3-team vectors in hash, keyed_hash and
    derive_key modes, full 131-byte extended output, checked against both the
    native package and an independent pure-Python reference implementation.
V2  Independent cross-implementation check – native package vs the reference
    implementation on seeded random inputs that cross block, chunk and tree
    boundaries.
V3  Configuration consistency – the same input must yield one digest under
    every buffer size, thread count, I/O path (stream, mmap, in-memory, small-
    file batch worker) and every factorial configuration of the study.
V4  Repeatability – repeated hashing of the same input is deterministic.
V5  Avalanche diagnostics – Hamming distance distribution (mean z-test,
    chi-square fit to Binomial(256, ½)) and the strict avalanche criterion.
V6  Output bit balance and duplicate-digest screen.

Scope of conclusions
--------------------
V1–V4 establish that *this implementation and its optimizations* compute
standard BLAKE3 correctly. V5–V6 are empirical diagnostics that the outputs
behave as expected for a well-mixed hash on the tested inputs. None of them
proves collision resistance, preimage resistance, or any other security
property; those rest on the published cryptanalysis of BLAKE3, which this
study neither modifies nor re-evaluates.
"""

from __future__ import annotations

import argparse
import io
import json
import math
import os
import random
import statistics
import tempfile
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

import blake3

from benchmark_blake3 import binomial_bins, chi_square_sf
from optimized_blake3 import (
    BLAKE3_CONFIGS,
    MIB,
    SMALL_FILE_LIMIT,
    _small_batch_worker,
    _small_file_worker,
    hash_file,
    hash_file_config,
    hash_stream,
    logical_cpu_count,
    physical_cpu_count,
    self_test,
)

VECTOR_PATH = Path(__file__).resolve().parent / "test_vectors" / "test_vectors.json"
VECTOR_SOURCE = ("https://github.com/BLAKE3-team/BLAKE3/blob/master/"
                 "test_vectors/test_vectors.json")
Z_CRITICAL = 3.29  # two-sided p = 0.001
CONSISTENCY_MAX_FILE_BYTES = 1024 * MIB
CONSISTENCY_SAMPLE_BYTES = 512 * MIB

LIMITATIONS = (
    "These procedures verify that this implementation computes standard BLAKE3 "
    "correctly under every optimization, and that its outputs behave as expected on "
    "the tested inputs. They do not prove collision or preimage resistance; BLAKE3's "
    "security rests on its published design and cryptanalysis, which this study does "
    "not modify."
)

ProgressCallback = Optional[Callable[[str, float], None]]


# ─────────────────────────────────────────────────────────────────────────────
# Independent pure-Python BLAKE3 reference implementation
# ─────────────────────────────────────────────────────────────────────────────
# Independent pure-Python BLAKE3 reference implementation.
#
# This is a direct, line-by-line port of the BLAKE3 team's specification
# reference implementation (``reference_impl/reference_impl.rs`` in
# https://github.com/BLAKE3-team/BLAKE3).  It shares *no code* with the native
# ``blake3`` package used by the optimized engine, so agreement between the two
# is evidence of implementation correctness, not just
# self-consistency.
#
# It is intentionally simple and slow (roughly 1 MiB/s): it is used only for
# verification, never for evidence hashing or benchmarking.

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




def _vector_input(length: int) -> bytes:
    return bytes(i % 251 for i in range(length))


# ── V1 ──────────────────────────────────────────────────────────────────────

def official_test_vectors(path: Path = VECTOR_PATH) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    key = data["key"].encode("ascii")
    context = data["context_string"]
    cases = []
    failures = 0
    for case in data["cases"]:
        payload = _vector_input(case["input_len"])
        length = len(case["hash"]) // 2
        checks = {
            "native_hash": blake3.blake3(payload).digest(length).hex() == case["hash"],
            "native_keyed": blake3.blake3(payload, key=key).digest(length).hex() == case["keyed_hash"],
            "native_derive": blake3.blake3(payload, derive_key_context=context)
            .digest(length).hex() == case["derive_key"],
            "native_multithread": blake3.blake3(payload, max_threads=blake3.blake3.AUTO)
            .digest(length).hex() == case["hash"],
            "reference_hash": reference_hash(payload, length).hex() == case["hash"],
            "reference_keyed": reference_keyed_hash(key, payload, length).hex() == case["keyed_hash"],
            "reference_derive": reference_derive_key(context, payload, length).hex() == case["derive_key"],
        }
        passed = all(checks.values())
        failures += not passed
        cases.append({"input_len": case["input_len"], "passed": passed, "checks": checks})
    return {
        "procedure": "V1 official test vectors",
        "passed": failures == 0,
        "source": VECTOR_SOURCE,
        "vector_file_sha256": __import__("hashlib").sha256(path.read_bytes()).hexdigest(),
        "cases_total": len(cases),
        "cases_failed": failures,
        "checks_per_case": 7,
        "output_bytes_checked": len(data["cases"][0]["hash"]) // 2,
        "cases": cases,
        "interpretation": "Both the native engine and the independent reference implementation "
                          "reproduce the BLAKE3 team's published outputs.",
    }


# ── V2 ──────────────────────────────────────────────────────────────────────

def reference_cross_check(seed: int = 0xB1A3E3, random_cases: int = 24) -> Dict[str, Any]:
    rng = random.Random(seed)
    boundary = [0, 1, 63, 64, 65, 1023, 1024, 1025, 2047, 2048, 2049, 4096, 8193, 65537]
    lengths = boundary + [rng.randrange(0, 200_000) for _ in range(random_cases)]
    failures = []
    for length in lengths:
        payload = rng.randbytes(length)
        native = blake3.blake3(payload).hexdigest()
        reference = reference_hash(payload).hex()
        if native != reference:
            failures.append(length)
    return {
        "procedure": "V2 independent cross-implementation check",
        "passed": not failures,
        "inputs_tested": len(lengths),
        "lengths": lengths,
        "failures": failures,
        "seed": seed,
        "interpretation": "Native extension and pure-Python reference agree on every input.",
    }


# ── V3 ──────────────────────────────────────────────────────────────────────

def configuration_consistency(
    path: Optional[os.PathLike[str] | str] = None,
    *,
    synthetic_size: int = SMALL_FILE_LIMIT + 3 * MIB + 17,
    progress: ProgressCallback = None,
    max_file_bytes: int = CONSISTENCY_MAX_FILE_BYTES,
) -> Dict[str, Any]:
    """Hash one input every supported way and require a single digest.

    About forty full passes are needed, so a selected file larger than
    ``max_file_bytes`` is checked on a copy of its first CONSISTENCY_SAMPLE_BYTES
    (which still crosses the multithreading and memory-mapping thresholds).
    """
    temporary: Optional[tempfile.TemporaryDirectory] = None
    source_label = None
    if path is None:
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name) / "consistency_input.bin"
        rng = random.Random(0xC0451)
        Path(path).write_bytes(rng.randbytes(synthetic_size))
        source_label = "synthetic %d bytes" % synthetic_size
    elif Path(path).stat().st_size > max_file_bytes:
        original = Path(path)
        temporary = tempfile.TemporaryDirectory()
        sample = Path(temporary.name) / "consistency_sample.bin"
        with open(original, "rb") as reader, open(sample, "wb") as writer:
            remaining = CONSISTENCY_SAMPLE_BYTES
            while remaining:
                block = reader.read(min(8 * MIB, remaining))
                if not block:
                    break
                writer.write(block)
                remaining -= len(block)
        source_label = "first %d MiB of %s (sample: the full file is too large for ~40 passes)" % (
            CONSISTENCY_SAMPLE_BYTES // MIB, original)
        path = sample
    file_path = Path(path)
    size = file_path.stat().st_size
    try:
        expected = hash_file(file_path, threads=1, allow_mmap=False).digest
        observations: List[Dict[str, Any]] = []

        def observe(label: str, digest: str) -> None:
            observations.append({"variant": label, "digest": digest, "matches": digest == expected})

        buffers = [64 * 1024, 256 * 1024, 512 * 1024, 1 * MIB, 2 * MIB, 8 * MIB, 16 * MIB]
        thread_counts = sorted({1, 2, physical_cpu_count(), logical_cpu_count()})
        steps = len(buffers) * len(thread_counts) + 8
        done = 0
        for buffer in buffers:
            for threads in thread_counts:
                hasher = blake3.blake3(max_threads=threads)
                view = memoryview(bytearray(buffer))
                with open(file_path, "rb", buffering=0) as source:
                    while True:
                        count = source.readinto(view)
                        if not count:
                            break
                        hasher.update(view[:count])
                view.release()
                observe("stream buffer=%d KiB threads=%d" % (buffer // 1024, threads), hasher.hexdigest())
                done += 1
                if progress:
                    progress("Consistency: buffer %d KiB × %d threads" % (buffer // 1024, threads),
                             done / steps)
        for config in BLAKE3_CONFIGS:
            observe("configuration: " + config.label, hash_file_config(file_path, config).digest)
        observe("configuration: Optimized with mapping disabled (background-read fallback)",
                hash_file_config(file_path, "optimized", allow_mmap=False).digest)
        observe("mmap (engine default policy)", hash_file(file_path, allow_mmap=True).digest)
        if size <= 512 * MIB:
            data = file_path.read_bytes()
            observe("in-memory one-shot, 1 thread", blake3.blake3(data, max_threads=1).hexdigest())
            observe("in-memory one-shot, auto threads",
                    blake3.blake3(data, max_threads=blake3.blake3.AUTO).hexdigest())
            observe("stream API (hash_stream)",
                    hash_stream(io.BytesIO(data), len(data), collect_metrics=False).digest)
        if size < SMALL_FILE_LIMIT:
            observe("small-file worker (unbatched)", _small_file_worker(str(file_path))[0])
            observe("small-file worker (batched)", _small_batch_worker([str(file_path)])[0][0])
        if progress:
            progress("Consistency checks complete", 1.0)
        mismatches = [o["variant"] for o in observations if not o["matches"]]
        return {
            "procedure": "V3 configuration consistency",
            "passed": not mismatches,
            "input": source_label or str(file_path),
            "input_bytes": size,
            "expected_digest": expected,
            "variants_tested": len(observations),
            "mismatches": mismatches,
            "observations": observations,
            "interpretation": "Buffer size, thread count, I/O path and every studied optimization "
                              "change only performance, never the digest.",
        }
    finally:
        if temporary is not None:
            temporary.cleanup()


# ── V4 ──────────────────────────────────────────────────────────────────────

def repeatability(payload: bytes, repetitions: int = 50) -> Dict[str, Any]:
    digests = {blake3.blake3(payload, max_threads=blake3.blake3.AUTO if i % 2 else 1).hexdigest()
               for i in range(repetitions)}
    return {
        "procedure": "V4 repeatability",
        "passed": len(digests) == 1,
        "repetitions": repetitions,
        "distinct_digests": len(digests),
        "interpretation": "Hashing the same bytes repeatedly yields one digest.",
    }


# ── V5 ──────────────────────────────────────────────────────────────────────

def avalanche_analysis(
    payload: bytes, samples: int = 1000, seed: int = 0xA11A1A
) -> Dict[str, Any]:
    """Single-bit-flip analysis on ``payload`` (formulas F15–F18)."""
    if not payload:
        return {"procedure": "V5 avalanche", "passed": False, "applicable": False,
                "error": "empty input has no bit to flip"}
    rng = random.Random(seed)
    original = bytearray(payload)
    original_digest = blake3.blake3(original).digest()
    positions = rng.sample(range(len(original) * 8), min(samples, len(original) * 8))
    distances: List[int] = []
    bit_flips = [0] * 256
    for position in positions:
        byte_index, bit_index = divmod(position, 8)
        original[byte_index] ^= 1 << bit_index
        digest = blake3.blake3(original).digest()
        original[byte_index] ^= 1 << bit_index
        diff = bytes(a ^ b for a, b in zip(original_digest, digest))
        distances.append(sum(b.bit_count() for b in diff))
        for byte_number, value in enumerate(diff):
            for bit in range(8):
                if value >> bit & 1:
                    bit_flips[byte_number * 8 + bit] += 1
    n = len(distances)
    mean = statistics.fmean(distances)
    sd = statistics.stdev(distances) if n > 1 else 0.0
    z = (mean - 128.0) / (8.0 / math.sqrt(n))

    bins = binomial_bins(256, 0.5, n)
    observed = [sum(1 for d in distances if lo <= d <= hi) for lo, hi, _e in bins]
    chi_square = sum((o - e) ** 2 / e for o, (_lo, _hi, e) in zip(observed, bins))
    df = max(1, len(bins) - 1)
    chi_p = chi_square_sf(chi_square, df)

    probabilities = [count / n for count in bit_flips]
    band = Z_CRITICAL * math.sqrt(0.25 / n)
    outside = [i for i, p in enumerate(probabilities) if abs(p - 0.5) > band]
    expected_outside = 256 * 0.001
    # Allow a generous count before flagging: Poisson(0.256) exceeds 3 with p < 0.003.
    sac_passed = len(outside) <= 3

    histogram = [0] * 16
    for d in distances:
        histogram[min(15, d * 16 // 256)] += 1
    passed = abs(z) < Z_CRITICAL and chi_p > 0.001 and sac_passed
    return {
        "procedure": "V5 avalanche diagnostics",
        "passed": passed,
        "applicable": True,
        "samples": n,
        "input_bytes": len(payload),
        "seed": seed,
        "mean_changed_bits": round(mean, 3),
        "mean_changed_percent": round(mean / 256 * 100, 3),
        "stdev_bits": round(sd, 3),
        "expected_mean_bits": 128.0,
        "expected_stdev_bits": 8.0,
        "minimum_bits": min(distances),
        "maximum_bits": max(distances),
        "mean_z": round(z, 3),
        "mean_test_passed": abs(z) < Z_CRITICAL,
        "chi_square": round(chi_square, 3),
        "chi_square_df": df,
        "chi_square_p": chi_p,
        "chi_square_passed": chi_p > 0.001,
        "sac_min_probability": round(min(probabilities), 4),
        "sac_max_probability": round(max(probabilities), 4),
        "sac_band": [round(0.5 - band, 4), round(0.5 + band, 4)],
        "sac_bits_outside_band": len(outside),
        "sac_expected_outside_by_chance": round(expected_outside, 3),
        "sac_passed": sac_passed,
        "histogram_16_bins": histogram,
        "interpretation": "Empirical diagnostic: single-bit input changes alter about half of the "
                          "output bits, independently per output bit, on the tested input. "
                          "Not a security proof.",
    }


# ── V6 ──────────────────────────────────────────────────────────────────────

def collision_screen(payload: bytes, variants: int = 2000, seed: int = 0xC0111510) -> Dict[str, Any]:
    rng = random.Random(seed)
    seen: Dict[bytes, int] = {blake3.blake3(payload).digest(): -1}
    digests = [next(iter(seen))]
    duplicates = []
    for index in range(variants):
        variant = bytes(payload) + index.to_bytes(8, "little") + rng.randbytes(8)
        digest = blake3.blake3(variant).digest()
        if digest in seen:
            duplicates.append((seen[digest], index))
        else:
            seen[digest] = index
        digests.append(digest)
    return {
        "procedure": "V6a duplicate-digest screen",
        "passed": not duplicates,
        "inputs_tested": variants + 1,
        "duplicates": duplicates,
        "digests": [d.hex() for d in digests],
        "interpretation": "No duplicate digests among the tested inputs. With 2^256 possible "
                          "outputs, a duplicate would only be expected after about 2^128 inputs, "
                          "so this screen cannot demonstrate collision resistance.",
    }


def bit_balance(digest_hexes: Sequence[str]) -> Dict[str, Any]:
    values = [bytes.fromhex(h) for h in digest_hexes]
    if not values:
        return {"procedure": "V6b output bit balance", "passed": False, "error": "no digests"}
    ones = sum(b.bit_count() for value in values for b in value)
    total = len(values) * 256
    fraction = ones / total
    z = (ones - total / 2) / math.sqrt(total / 4)
    return {
        "procedure": "V6b output bit balance",
        "passed": abs(z) < Z_CRITICAL,
        "digests_tested": len(values),
        "total_bits": total,
        "ones": ones,
        "zeros": total - ones,
        "ones_percent": round(fraction * 100, 3),
        "z": round(z, 3),
        "interpretation": "Ones and zeros occur in roughly equal proportion (F19).",
    }


# ── Orchestration ───────────────────────────────────────────────────────────

def run_validation(
    path: Optional[os.PathLike[str] | str] = None,
    *,
    avalanche_samples: int = 1000,
    collision_variants: int = 2000,
    sample_bytes: int = 4 * MIB,
    progress: ProgressCallback = None,
) -> Dict[str, Any]:
    def report(message: str, fraction: float) -> None:
        if progress:
            progress(message, fraction)

    started = time.perf_counter()
    report("V1 official test vectors…", 0.02)
    vectors = official_test_vectors()
    report("V2 cross-implementation check…", 0.12)
    cross = reference_cross_check()
    report("V3 configuration consistency…", 0.25)
    consistency = configuration_consistency(
        path, progress=lambda m, f: report(m, 0.25 + 0.4 * f))
    if path is not None:
        with open(path, "rb") as source:
            sample = source.read(sample_bytes)
        sample_scope = ("entire file" if os.path.getsize(path) <= sample_bytes
                        else "first %d MiB of the file" % (sample_bytes // MIB))
    else:
        sample = random.Random(0x5A3E).randbytes(64 * 1024)
        sample_scope = "64 KiB seeded random input"
    report("V4 repeatability…", 0.68)
    repeat = repeatability(sample)
    report("V5 avalanche analysis…", 0.72)
    avalanche = avalanche_analysis(sample, samples=avalanche_samples)
    report("V6 duplicate screen and bit balance…", 0.88)
    collisions = collision_screen(sample, variants=collision_variants)
    balance = bit_balance(collisions.pop("digests"))
    report("Verification complete", 1.0)
    procedures = [vectors, cross, consistency, repeat, avalanche, collisions, balance]
    return {
        "schema_version": 2,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "passed": all(p.get("passed") for p in procedures if p.get("applicable", True)),
        "input": str(path) if path else "synthetic",
        "diagnostic_sample_scope": sample_scope,
        "engine_self_test": self_test(),
        "procedures": procedures,
        "limitations": LIMITATIONS,
        "duration_seconds": round(time.perf_counter() - started, 2),
    }


# Backward-compatible wrappers used by older callers/tests.
def deterministic_correctness(seed: int = 0xB1A3E3) -> Dict[str, Any]:
    rng = random.Random(seed)
    failures = []
    for size in [0, 1, 63, 64, 1023, 1024, 1025, 2048, 8192, 65537, 1_048_577]:
        payload = rng.randbytes(size)
        reference = blake3.blake3(payload, max_threads=1).hexdigest()
        first = hash_stream(io.BytesIO(payload), size, threads=1, collect_metrics=False)
        second = hash_stream(io.BytesIO(payload), size, threads=physical_cpu_count(),
                             collect_metrics=False)
        if not (first.digest == reference == second.digest):
            failures.append(size)
    return {"passed": not failures, "failures": failures}


def avalanche_effect(payload_size: int = 4096, samples: int = 256, seed: int = 0xA11A1A):
    payload = random.Random(seed).randbytes(payload_size)
    return avalanche_analysis(payload, samples=samples, seed=seed)


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("path", nargs="?", help="optional file to verify against")
    parser.add_argument("--avalanche-samples", type=int, default=1000)
    parser.add_argument("--collision-variants", type=int, default=2000)
    parser.add_argument("--output", help="write the JSON report here")
    args = parser.parse_args(argv)
    result = run_validation(args.path, avalanche_samples=args.avalanche_samples,
                            collision_variants=args.collision_variants)
    encoded = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    for procedure in result["procedures"]:
        print("%-45s %s" % (procedure["procedure"], "PASS" if procedure.get("passed") else "FAIL"))
    print("Limitations:", result["limitations"])
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
