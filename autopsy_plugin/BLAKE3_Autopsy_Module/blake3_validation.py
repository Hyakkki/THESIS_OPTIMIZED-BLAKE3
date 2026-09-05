#!/usr/bin/env python3
"""Cryptographic integrity checks for the optimized BLAKE3 engine.

These checks establish implementation correctness and reproducibility.  The
avalanche and no-collision corpus checks are empirical diagnostics, not proofs
of BLAKE3's security claims.
"""

from __future__ import annotations

import argparse
import io
import json
import math
import random
import statistics
from typing import Any, Dict, List, Optional, Sequence

import blake3

from optimized_blake3 import KNOWN_VECTORS, hash_stream, physical_cpu_count, self_test


def hamming_distance(left: bytes, right: bytes) -> int:
    if len(left) != len(right):
        raise ValueError("digests must have equal length")
    return sum((a ^ b).bit_count() for a, b in zip(left, right))


def deterministic_correctness(seed: int = 0xB1A3E3) -> Dict[str, Any]:
    rng = random.Random(seed)
    sizes = [0, 1, 63, 64, 1023, 1024, 1025, 2048, 8192, 65537, 1_048_577]
    failures: List[Dict[str, Any]] = []
    cases: List[Dict[str, Any]] = []
    for size in sizes:
        payload = rng.randbytes(size)
        reference = blake3.blake3(payload, max_threads=1).hexdigest()
        first = hash_stream(io.BytesIO(payload), size, threads=1, collect_metrics=False)
        second = hash_stream(
            io.BytesIO(payload), size, threads=physical_cpu_count(), collect_metrics=False
        )
        passed = (
            first.status == "ok"
            and second.status == "ok"
            and first.digest == reference
            and second.digest == reference
        )
        case = {"size_bytes": size, "passed": passed, "digest": reference}
        cases.append(case)
        if not passed:
            failures.append(case)
    return {"passed": not failures, "cases": cases, "failures": failures}


def avalanche_effect(
    payload_size: int = 4096, samples: int = 256, seed: int = 0xA11A1A
) -> Dict[str, Any]:
    if payload_size <= 0 or samples <= 0:
        raise ValueError("payload_size and samples must be positive")
    rng = random.Random(seed)
    original = bytearray(rng.randbytes(payload_size))
    original_digest = blake3.blake3(original).digest()
    bit_positions = rng.sample(
        range(payload_size * 8), min(samples, payload_size * 8)
    )
    distances: List[int] = []
    for bit_position in bit_positions:
        byte_index, bit_index = divmod(bit_position, 8)
        modified = bytearray(original)
        modified[byte_index] ^= 1 << bit_index
        distances.append(hamming_distance(original_digest, blake3.blake3(modified).digest()))

    mean = statistics.fmean(distances)
    expected = 128.0
    # A broad, preregistered diagnostic interval avoids presenting this as a
    # statistical proof. Each BLAKE3-256 output has 256 bits.
    passed = 112.0 <= mean <= 144.0 and min(distances) > 80 and max(distances) < 176
    return {
        "passed": passed,
        "samples": len(distances),
        "digest_bits": 256,
        "expected_mean_changed_bits": expected,
        "mean_changed_bits": round(mean, 3),
        "mean_changed_percent": round(mean / 256.0 * 100.0, 3),
        "stddev_bits": round(statistics.pstdev(distances), 3),
        "minimum_bits": min(distances),
        "maximum_bits": max(distances),
        "interpretation": "empirical avalanche diagnostic; not a security proof",
    }


def output_consistency_and_collision_check(
    corpus_size: int = 10_000, seed: int = 0xC0111510
) -> Dict[str, Any]:
    if corpus_size <= 1:
        raise ValueError("corpus_size must be greater than one")
    rng = random.Random(seed)
    seen: Dict[str, int] = {}
    collisions: List[Dict[str, int]] = []
    inconsistent: List[int] = []
    for index in range(corpus_size):
        length = rng.randrange(0, 8193)
        payload = index.to_bytes(8, "little") + rng.randbytes(length)
        first = blake3.blake3(payload, max_threads=1).hexdigest()
        second = blake3.blake3(
            payload, max_threads=max(1, physical_cpu_count())
        ).hexdigest()
        if first != second:
            inconsistent.append(index)
        prior = seen.get(first)
        if prior is not None:
            collisions.append({"first_index": prior, "second_index": index})
        else:
            seen[first] = index
    return {
        "passed": not collisions and not inconsistent,
        "corpus_size": corpus_size,
        "unique_digests": len(seen),
        "collisions_observed": collisions,
        "inconsistent_indexes": inconsistent,
        "interpretation": "empirical consistency/collision screen; not a proof of collision resistance",
    }


def run_validation(
    avalanche_samples: int = 256, corpus_size: int = 10_000
) -> Dict[str, Any]:
    vector_report = self_test()
    correctness = deterministic_correctness()
    avalanche = avalanche_effect(samples=avalanche_samples)
    consistency = output_consistency_and_collision_check(corpus_size=corpus_size)
    passed = bool(
        vector_report["passed"]
        and correctness["passed"]
        and avalanche["passed"]
        and consistency["passed"]
    )
    return {
        "schema_version": 1,
        "passed": passed,
        "published_vectors": vector_report,
        "deterministic_correctness": correctness,
        "avalanche_effect": avalanche,
        "output_consistency_collision_screen": consistency,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--avalanche-samples", type=int, default=256)
    parser.add_argument("--corpus-size", type=int, default=10_000)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args(argv)
    report = run_validation(args.avalanche_samples, args.corpus_size)
    print(json.dumps(report, indent=None if args.compact else 2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
