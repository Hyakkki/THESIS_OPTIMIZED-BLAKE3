import os
import tempfile
import unittest
from pathlib import Path

import blake3

import benchmark_blake3 as bench
from optimized_blake3 import SMALL_FILE_LIMIT


class LargeFileAblationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.path = Path(cls.directory.name, "sample.pdf")
        cls.payload = os.urandom(3 * 1024 * 1024 + 11)
        cls.path.write_bytes(cls.payload)
        cls.report = bench.run_large_file_ablation([cls.path], trials=6, warmups=1)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_all_conditions_and_comparisons_present(self):
        file_report = self.report["files"][0]
        self.assertEqual(
            list(file_report["conditions"]),
            ["baseline", "buffer_only", "threads_only", "optimized", "sha256", "sha1", "md5"],
        )
        technique = [c for c in file_report["comparisons"] if c["family"] == "technique"]
        reference = [c for c in file_report["comparisons"] if c["family"] == "reference"]
        self.assertEqual([c["candidate"] for c in technique],
                         ["buffer_only", "threads_only", "optimized"])
        self.assertEqual({c["reference"] for c in reference}, {"sha256", "sha1", "md5"})
        for comparison in technique + reference:
            self.assertIn("p_holm", comparison)
            self.assertIn(comparison["verdict"], (
                "significantly faster", "significantly slower", "no significant difference"))
            self.assertEqual(len(comparison["speedup_ci95"]), 2)

    def test_digest_is_standard_blake3(self):
        self.assertEqual(self.report["files"][0]["blake3_digest"],
                         blake3.blake3(self.payload).hexdigest())

    def test_every_condition_runs_once_per_round(self):
        runs = self.report["runs"]
        self.assertEqual(len(runs), 7 * 6)
        for round_number in range(1, 7):
            positions = sorted(r["position"] for r in runs if r["round"] == round_number)
            self.assertEqual(positions, list(range(1, 8)))
        self.assertTrue(all(not r["warmup"] for r in runs))

    def test_below_threshold_file_flags_threading(self):
        self.assertLess(self.path.stat().st_size, SMALL_FILE_LIMIT)
        self.assertEqual(self.report["files"][0]["conditions"]["threads_only"]["threads"], 1)
        self.assertTrue(any("threshold" in w for w in self.report["files"][0]["warnings"]))

    def test_export_writes_three_files(self):
        with tempfile.TemporaryDirectory() as out:
            paths = bench.export_report(self.report, out, "test")
            for path in paths.values():
                self.assertTrue(Path(path).stat().st_size > 0)

    def test_backward_compatible_percent(self):
        self.assertEqual(bench.optimization_percent(10.0, 7.5), 25.0)


class SmallFileAblationTests(unittest.TestCase):
    def test_four_modes_with_identical_digests(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index in range(40):
                path = Path(directory, "f%02d.txt" % index)
                path.write_bytes(os.urandom(500 + index * 101))
                paths.append(path)
            report = bench.run_small_file_ablation(paths, trials=3, warmups=1, workers=2,
                                                   batch_size=8)
        self.assertEqual(list(report["summary"]),
                         ["sequential", "sequential_batched", "parallel", "parallel_batched"])
        self.assertEqual(len(report["comparisons"]), 3)
        self.assertEqual(report["workload"]["files"], 40)
        self.assertIsNotNone(report["factorial"]["interaction"])
        self.assertTrue(any("preliminary" in w for w in report["warnings"]))

    def test_cancellation(self):
        import threading
        cancel = threading.Event()
        cancel.set()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "a.bin")
            path.write_bytes(b"x" * 1000)
            with self.assertRaises(bench.BenchmarkCancelled):
                bench.run_large_file_ablation([path], trials=2, warmups=0, cancel=cancel)


if __name__ == "__main__":
    unittest.main()
