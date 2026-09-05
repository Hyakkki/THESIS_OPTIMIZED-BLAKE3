from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import blake3

import optimized_blake3 as engine
from blake3_validation import avalanche_effect, deterministic_correctness


class PolicyTests(unittest.TestCase):
    def test_small_files_are_single_threaded(self):
        policy = engine.select_policy(engine.SMALL_FILE_LIMIT - 1, threads=64)
        self.assertEqual(policy.max_threads, 1)
        self.assertFalse(policy.use_mmap)

    def test_large_files_enable_mmap_and_native_threads(self):
        policy = engine.select_policy(engine.MMAP_MIN_BYTES, threads=4)
        self.assertEqual(policy.max_threads, 4)
        self.assertTrue(policy.use_mmap)

    def test_150_mib_autopsy_stream_uses_eight_mib_buffer(self):
        policy = engine.select_policy(150 * engine.MIB, threads=8)
        self.assertEqual(policy.chunk_size, 8 * engine.MIB)
        self.assertEqual(policy.max_threads, 8)


class HashingTests(unittest.TestCase):
    def test_published_vectors(self):
        self.assertTrue(engine.self_test()["passed"])

    def test_stream_matches_reference(self):
        payload = bytes(range(256)) * 8193
        result = engine.hash_stream(io.BytesIO(payload), len(payload), threads=8)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.digest, blake3.blake3(payload).hexdigest())
        self.assertEqual(result.bytes_read, len(payload))

    def test_short_stream_is_rejected_without_padding(self):
        result = engine.hash_stream(io.BytesIO(b"abc"), 4)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.bytes_read, 3)
        self.assertEqual(result.digest, "")

    def test_file_hash_matches_reference(self):
        payload = os.urandom(2 * engine.MIB + 17)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "sample.pdf")
            path.write_bytes(payload)
            result = engine.hash_file(path)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.digest, blake3.blake3(payload).hexdigest())

    def test_server_protocol_handles_multiple_requests(self):
        request = io.BytesIO(b"3\nabc0\n")
        response = io.BytesIO()
        self.assertEqual(engine.serve_forever(request, response, threads=1), 0)
        lines = response.getvalue().decode("utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        first, second = [json.loads(line) for line in lines]
        self.assertEqual(first["digest"], engine.KNOWN_VECTORS[b"abc"])
        self.assertEqual(second["digest"], engine.KNOWN_VECTORS[b""])

    def test_baseline_profile_matches_optimized_digest(self):
        payload = os.urandom(3 * engine.MIB + 19)
        baseline = engine.hash_stream_profile(
            io.BytesIO(payload), len(payload), profile="blake3_baseline"
        )
        optimized = engine.hash_stream_profile(
            io.BytesIO(payload), len(payload), profile="blake3_optimized"
        )
        self.assertEqual(baseline.status, "ok")
        self.assertEqual(baseline.digest, optimized.digest)
        self.assertEqual(baseline.threads_used, 1)
        self.assertEqual(baseline.chunk_size, engine.MIB)

    def test_reference_profiles_match_hashlib(self):
        import hashlib

        payload = os.urandom(100_003)
        for profile in ("md5", "sha1", "sha256"):
            result = engine.hash_stream_profile(
                io.BytesIO(payload), len(payload), profile=profile
            )
            self.assertEqual(result.digest, hashlib.new(profile, payload).hexdigest())

    def test_server_json_header_selects_baseline(self):
        payload = b"abc"
        header = json.dumps({"size": len(payload), "profile": "blake3_baseline"})
        request = io.BytesIO(header.encode("ascii") + b"\n" + payload)
        response = io.BytesIO()
        engine.serve_forever(request, response, threads=1)
        result = json.loads(response.getvalue())
        self.assertEqual(result["digest"], engine.KNOWN_VECTORS[payload])
        self.assertIn("baseline", result["profile"])


class ValidationTests(unittest.TestCase):
    def test_deterministic_correctness(self):
        self.assertTrue(deterministic_correctness()["passed"])

    def test_avalanche_diagnostic(self):
        self.assertTrue(avalanche_effect(samples=64)["passed"])


if __name__ == "__main__":
    unittest.main()
