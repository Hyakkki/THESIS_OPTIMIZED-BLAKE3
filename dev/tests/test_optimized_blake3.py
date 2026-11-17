from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

import blake3

import optimized_blake3 as engine
from optimized_blake3 import SMALL_FILE_LIMIT, OperationCancelled

fh = engine  # hash_paths / hash lists
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

    def test_large_streamed_input_uses_pipeline_chunk(self):
        # Streams (e.g. the Autopsy pipe) cannot be mapped; they use the 4 MiB chunk.
        policy = engine.select_policy(150 * engine.MIB, threads=8, allow_mmap=False)
        self.assertEqual(policy.chunk_size, engine.PIPELINE_CHUNK_BYTES)
        self.assertEqual(policy.max_threads, 8)
        self.assertFalse(policy.use_mmap)

    def test_default_threads_use_all_logical_cores(self):
        policy = engine.select_policy(engine.SMALL_FILE_LIMIT)
        self.assertEqual(policy.max_threads, engine.logical_cpu_count())


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

    def test_complete_file_snapshot_and_memory_benchmark(self):
        payload = os.urandom(engine.MIB + 17)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "sample.bin")
            path.write_bytes(payload)
            snapshot = engine.load_file_snapshot(path, max_bytes=2 * engine.MIB)

        self.assertTrue(snapshot.complete)
        self.assertEqual(snapshot.file_size, len(payload))
        self.assertEqual(snapshot.bytes_loaded, len(payload))
        result = engine.benchmark_memory(
            snapshot.data, threads=1, repeats=3, warmups=1
        )
        self.assertEqual(result.digest, blake3.blake3(payload).hexdigest())
        self.assertEqual(result.bytes_hashed, len(payload))
        self.assertEqual(result.repeats, 3)
        self.assertEqual(result.threads_used, 1)
        self.assertGreater(result.median_elapsed_ms, 0)
        self.assertGreater(result.median_throughput_mib_s, 0)

    def test_capped_file_snapshot_is_labelled_incomplete(self):
        payload = os.urandom(4096)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "large.bin")
            path.write_bytes(payload)
            snapshot = engine.load_file_snapshot(path, max_bytes=1024)

        self.assertFalse(snapshot.complete)
        self.assertEqual(snapshot.file_size, len(payload))
        self.assertEqual(snapshot.bytes_loaded, 1024)
        self.assertEqual(bytes(snapshot.data), payload[:1024])

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


class TechniqueConfigTests(unittest.TestCase):
    def test_factor_levels_map_to_policies(self):
        large = engine.SMALL_FILE_LIMIT + engine.MIB
        policies = {c.key: engine.policy_for_config(c, large, threads=4)
                    for c in engine.BLAKE3_CONFIGS}
        self.assertEqual((policies["baseline"].chunk_size, policies["baseline"].max_threads),
                         (engine.MIB, 1))
        # Adaptive buffering on a large file = whole-file memory map (+ fallback chunk).
        self.assertTrue(policies["buffer_only"].use_mmap)
        self.assertEqual(policies["buffer_only"].chunk_size, engine.adaptive_chunk_size(large))
        self.assertEqual(policies["buffer_only"].max_threads, 1)
        self.assertFalse(policies["threads_only"].use_mmap)
        self.assertEqual(policies["threads_only"].chunk_size, engine.MIB)
        self.assertEqual(policies["threads_only"].max_threads, 4)
        self.assertTrue(policies["optimized"].use_mmap)
        self.assertEqual(policies["optimized"].max_threads, 4)
        self.assertFalse(policies["baseline"].use_mmap)

    def test_small_files_are_never_mapped(self):
        policy = engine.policy_for_config(engine.CONFIGS_BY_KEY["optimized"],
                                          engine.SMALL_FILE_LIMIT - 1)
        self.assertFalse(policy.use_mmap)
        self.assertEqual(policy.max_threads, 1)

    def test_threads_never_apply_below_threshold(self):
        policy = engine.policy_for_config(engine.CONFIGS_BY_KEY["optimized"],
                                          engine.SMALL_FILE_LIMIT - 1, threads=8)
        self.assertEqual(policy.max_threads, 1)

    def test_all_configs_and_references_hash_correctly(self):
        import hashlib
        payload = os.urandom(engine.MIB + 333)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "x.bin")
            path.write_bytes(payload)
            for config in engine.BLAKE3_CONFIGS:
                self.assertEqual(engine.hash_file_config(path, config).digest,
                                 blake3.blake3(payload).hexdigest())
            for algorithm in ("md5", "sha1", "sha256"):
                result = engine.hash_file_reference(path, algorithm)
                self.assertEqual(result.digest, hashlib.new(algorithm, payload).hexdigest())
                self.assertEqual(result.chunk_size, engine.MIB)

    def test_small_file_modes_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index in range(25):
                path = Path(directory, "s%d" % index)
                path.write_bytes(os.urandom(100 + index * 50))
                paths.append(str(path))
            expected = [(blake3.blake3(Path(p).read_bytes()).hexdigest(), os.path.getsize(p))
                        for p in paths]
            pool, startup = engine.make_worker_pool(2)
            try:
                for mode in engine.SMALL_FILE_MODES:
                    self.assertEqual(engine.hash_small_files(paths, mode, pool=pool, batch_size=4),
                                     expected, mode.key)
            finally:
                pool.shutdown()
            self.assertGreater(startup, 0)


class PipelineAndFallbackTests(unittest.TestCase):
    def test_pipelined_update_matches_reference(self):
        for size in (0, 1, 4096, engine.PIPELINE_CHUNK_BYTES, 3 * engine.PIPELINE_CHUNK_BYTES + 77):
            payload = os.urandom(size)
            hasher = blake3.blake3(max_threads=2)
            count = engine._pipelined_update(hasher, io.BytesIO(payload), size,
                                             engine.PIPELINE_CHUNK_BYTES)
            self.assertEqual(count, size)
            self.assertEqual(hasher.hexdigest(), blake3.blake3(payload).hexdigest())

    def test_pipelined_update_reports_short_read(self):
        hasher = blake3.blake3()
        self.assertEqual(engine._pipelined_update(hasher, io.BytesIO(b"abc"), 10, 4), 3)

    def test_pipelined_update_propagates_read_errors(self):
        class Broken(io.BytesIO):
            def readinto(self, _buffer):
                raise OSError("simulated bad sector")
        with self.assertRaises(OSError):
            engine._pipelined_update(blake3.blake3(), Broken(b"x" * 100), 100, 16)

    def test_large_file_mmap_and_forced_fallback_agree(self):
        payload = os.urandom(engine.SMALL_FILE_LIMIT + 4321)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "evidence.dd")
            path.write_bytes(payload)
            mapped = engine.hash_file_config(path, "optimized")
            streamed = engine.hash_file_config(path, "optimized", allow_mmap=False)
        expected = blake3.blake3(payload).hexdigest()
        self.assertEqual(mapped.digest, expected)
        self.assertEqual(streamed.digest, expected)
        self.assertIn("mmap", mapped.io_strategy)
        self.assertIn("background-read", streamed.io_strategy)

    def test_mmap_failure_falls_back_automatically(self):
        payload = os.urandom(engine.SMALL_FILE_LIMIT + 99)
        original = engine.mmap.mmap

        def refuse(*_args, **_kwargs):
            raise OSError("mapping not supported on this share")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "share.bin")
            path.write_bytes(payload)
            engine.mmap.mmap = refuse
            try:
                result = engine.hash_file_config(path, "optimized")
            finally:
                engine.mmap.mmap = original
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.digest, blake3.blake3(payload).hexdigest())
        self.assertIn("mmap unavailable", result.io_strategy)


class WarmPoolTests(unittest.TestCase):
    def test_warm_pool_is_reused_and_left_running(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index in range(engine.WARM_POOL_MIN_FILES + 5):
                path = Path(directory, "f%03d.txt" % index)
                path.write_bytes(os.urandom(50 + index))
                paths.append(path)
            pool, _startup = engine.make_worker_pool(2)
            try:
                report = engine.hash_paths(paths, pool=pool)
                self.assertTrue(report["small_file_batching"])
                self.assertTrue(report["worker_pool_warm"])
                self.assertFalse(report["worker_pool_failed"])
                for record in report["files"]:
                    self.assertEqual(record["blake3"],
                                     blake3.blake3(Path(record["path"]).read_bytes()).hexdigest())
                # The caller's pool must still accept work afterwards.
                self.assertEqual(pool.submit(engine._worker_ready).result() > 0, True)
            finally:
                pool.shutdown()

    def test_few_files_skip_the_pool_even_when_warm(self):
        self.assertFalse(engine.should_use_pool(engine.WARM_POOL_MIN_FILES - 1, 0, warm=True))
        self.assertTrue(engine.should_use_pool(engine.WARM_POOL_MIN_FILES, 0, warm=True))

    def test_broken_pool_still_completes(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index in range(engine.WARM_POOL_MIN_FILES):
                path = Path(directory, "g%03d.txt" % index)
                path.write_bytes(os.urandom(64))
                paths.append(path)
            pool, _startup = engine.make_worker_pool(2)
            pool.shutdown()  # simulate a dead pool
            report = engine.hash_paths(paths, pool=pool)
        self.assertEqual(report["ok_count"], len(paths))
        self.assertTrue(report["worker_pool_failed"])



class ScaleAndAdaptivityTests(unittest.TestCase):
    def test_windowed_mapping_matches_reference_for_odd_sizes(self):
        granularity = getattr(engine.mmap, "ALLOCATIONGRANULARITY", 65536)
        for size in (granularity * 3, granularity * 3 + 1, granularity * 7 - 5):
            payload = os.urandom(size)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory, "w.bin")
                path.write_bytes(payload)
                seen = []
                hasher = blake3.blake3(max_threads=2)
                with open(path, "rb", buffering=0) as source:
                    count = engine._mapped_update(hasher, source, size, window=granularity * 2,
                                                  progress=seen.append)
            self.assertEqual(count, size)
            self.assertEqual(hasher.hexdigest(), blake3.blake3(payload).hexdigest())
            self.assertEqual(seen, sorted(seen))
            self.assertEqual(seen[-1], size)

    def test_progress_reaches_file_size_and_cancel_stops(self):
        payload = os.urandom(engine.SMALL_FILE_LIMIT + 12345)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "big.dd")
            path.write_bytes(payload)
            seen = []
            result = engine.hash_file_config(path, "optimized", progress=seen.append)
            self.assertEqual(result.digest, blake3.blake3(payload).hexdigest())
            self.assertEqual(seen[-1], len(payload))
            cancel = threading.Event()
            cancel.set()
            with self.assertRaises(OperationCancelled):
                engine.hash_file_config(path, "optimized", cancel=cancel)
            with self.assertRaises(OperationCancelled):
                engine.hash_file_config(path, "optimized", allow_mmap=False, cancel=cancel)

    def test_sequential_storage_uses_background_reads(self):
        payload = os.urandom(engine.SMALL_FILE_LIMIT + 7)
        original = engine.IO_MODE
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "hdd.bin")
            path.write_bytes(payload)
            engine.IO_MODE = "stream"  # behave as if the file were on an HDD / network share
            try:
                streamed = engine.hash_file_config(path, "optimized")
                plain = engine.hash_file(path)
            finally:
                engine.IO_MODE = original
        self.assertEqual(streamed.digest, blake3.blake3(payload).hexdigest())
        self.assertIn("background-read", streamed.io_strategy)
        self.assertNotIn("mmap", plain.io_strategy)

    def test_storage_profile_and_network_paths(self):
        profile = engine.storage_profile(__file__)
        for key in ("kind", "drive_type", "seek_penalty", "sequential_preferred"):
            self.assertIn(key, profile)
        self.assertIn(profile["kind"], ("ssd", "hdd", "network", "unknown"))
        if os.name == "nt":
            network = engine.storage_profile("\\\\server\\share\\evidence.E01")
            self.assertEqual(network["kind"], "network")
            self.assertTrue(network["sequential_preferred"])

    def test_system_summary(self):
        summary = engine.system_summary()
        self.assertEqual(summary["logical_threads"], engine.logical_cpu_count())
        self.assertTrue(summary["cpu_model"])

    def test_cache_warmup_skipped_when_data_exceeds_memory(self):
        original = engine.available_memory_bytes
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "a.bin")
            path.write_bytes(os.urandom(4096))
            engine.available_memory_bytes = lambda: 1024  # pretend RAM is tiny
            try:
                report = engine.hash_paths([path, path], extra_algorithms=["blake3_standard"])
            finally:
                engine.available_memory_bytes = original
        self.assertEqual(report["file_count"], 1)  # duplicate path removed
        self.assertTrue(report["standard_comparison"]["cache_warmup"].startswith("skipped"))
        self.assertTrue(report["files"][0]["matches_standard"])

    def test_progress_messages_are_throttled_and_complete(self):
        messages = []
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index in range(50):
                path = Path(directory, "s%02d" % index)
                path.write_bytes(os.urandom(100))
                paths.append(path)
            engine.hash_paths(paths, progress=lambda text, fraction: messages.append(fraction))
        self.assertLess(len(messages), 50)  # throttled, not one message per file
        self.assertAlmostEqual(messages[-1], 1.0)


class ValidationTests(unittest.TestCase):
    def test_deterministic_correctness(self):
        self.assertTrue(deterministic_correctness()["passed"])

    def test_avalanche_diagnostic(self):
        self.assertTrue(avalanche_effect(samples=64)["passed"])



class HashPathsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.small = []
        for index in range(12):
            path = self.root / ("doc_%02d.txt" % index)
            path.write_bytes(os.urandom(100 + index * 333))
            self.small.append(path)
        (self.root / "empty.bin").write_bytes(b"")
        self.small.append(self.root / "empty.bin")

    def tearDown(self):
        self.directory.cleanup()

    def assertCorrect(self, report, extras=()):
        for record in report["files"]:
            data = Path(record["path"]).read_bytes()
            self.assertEqual(record["status"], "ok", record["error"])
            self.assertEqual(record["blake3"], blake3.blake3(data).hexdigest())
            for algorithm in extras:
                self.assertEqual(record[algorithm], hashlib.new(algorithm, data).hexdigest())

    def test_sequential_small_files_with_extras(self):
        report = fh.hash_paths(self.small, extra_algorithms=["sha256", "md5"])
        self.assertFalse(report["small_file_batching"])
        self.assertCorrect(report, ["sha256", "md5"])
        self.assertEqual([r["path"] for r in report["files"]], [str(p.resolve()) for p in self.small])

    def test_batched_worker_processes(self):
        report = fh.hash_paths(self.small, force_pool=True, workers=2, batch_size=4)
        self.assertTrue(report["small_file_batching"])
        self.assertCorrect(report)
        self.assertTrue(report["files"][0]["method"].startswith("batched"))

    def test_large_file_uses_optimized_configuration(self):
        big = self.root / "image.dd"
        big.write_bytes(os.urandom(SMALL_FILE_LIMIT + 1234))
        report = fh.hash_paths([big])
        self.assertCorrect(report)
        self.assertIn("threads", report["files"][0]["method"])

    def test_missing_file_is_reported_not_raised(self):
        report = fh.hash_paths([self.small[0], self.root / "nope.bin"])
        self.assertEqual(report["ok_count"], 1)
        self.assertEqual(report["files"][1]["status"], "error")

    def test_standard_blake3_option_matches_optimized(self):
        big = self.root / "image.dd"
        big.write_bytes(os.urandom(SMALL_FILE_LIMIT + 99))
        report = fh.hash_paths(self.small + [big], extra_algorithms=["blake3_standard", "sha256"])
        self.assertCorrect(report, ["sha256"])
        for record in report["files"]:
            self.assertEqual(record["blake3_standard"], record["blake3"])
            self.assertTrue(record["matches_standard"])
        comparison = report["standard_comparison"]
        self.assertEqual(comparison["files_compared"], len(self.small) + 1)
        self.assertEqual(comparison["identical_digests"], comparison["files_compared"])
        self.assertGreater(comparison["speedup"], 0)
        self.assertEqual(report["algorithm_labels"]["blake3"], "Optimized BLAKE3")
        written = fh.write_hash_report(report, self.root / "out", "cmp")
        self.assertNotIn("blake3_standard", written)
        self.assertIn("matches_standard", Path(written["csv"]).read_text(encoding="utf-8"))

    def test_optimized_is_default_and_only_pass(self):
        report = fh.hash_paths(self.small[:2])
        self.assertEqual(report["algorithms"], ["blake3"])
        self.assertIsNone(report["standard_comparison"])

    def test_pool_heuristic(self):
        self.assertFalse(fh.should_use_pool(100, 10 * 1024 * 1024))
        self.assertTrue(fh.should_use_pool(3000, 10 * 1024 * 1024))
        self.assertTrue(fh.should_use_pool(100, 512 * 1024 * 1024))
        self.assertFalse(fh.should_use_pool(10, 512 * 1024 * 1024))

    def test_cancel(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(OperationCancelled):
            fh.hash_paths(self.small, cancel=cancel)

    def test_save_and_verify_round_trip(self):
        report = fh.hash_paths(self.small, extra_algorithms=["sha1"])
        written = fh.write_hash_report(report, self.root / "out", "case")
        line = Path(written["blake3"]).read_text(encoding="utf-8").splitlines()[0]
        self.assertRegex(line, r"^[0-9a-f]{64}  .+doc_00\.txt$")
        self.assertTrue(fh.verify_hash_list(written["blake3"])["passed"])
        self.assertTrue(fh.verify_hash_list(written["sha1"])["passed"])
        self.small[1].write_bytes(b"altered evidence")
        self.small[2].unlink()
        result = fh.verify_hash_list(written["blake3"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["counts"]["mismatch"], 1)
        self.assertEqual(result["counts"]["missing"], 1)

    def test_relative_paths_and_b3sum_star_format(self):
        digest = blake3.blake3(self.small[0].read_bytes()).hexdigest()
        list_path = self.root / "list.b3"
        list_path.write_text("# comment\n%s *%s\n" % (digest, self.small[0].name), encoding="utf-8")
        self.assertTrue(fh.verify_hash_list(list_path)["passed"])

    def test_bad_list_is_rejected(self):
        bad = self.root / "bad.b3"
        bad.write_text("not-a-hash  file.txt\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            fh.parse_hash_list(bad)


if __name__ == "__main__":
    unittest.main()
