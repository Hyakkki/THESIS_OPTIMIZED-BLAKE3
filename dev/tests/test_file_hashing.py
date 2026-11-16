import hashlib
import os
import tempfile
import threading
import unittest
from pathlib import Path

import blake3

import file_hashing as fh
from optimized_blake3 import SMALL_FILE_LIMIT, OperationCancelled


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
        written = fh.write_report(report, self.root / "out", "cmp")
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
        written = fh.write_report(report, self.root / "out", "case")
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
