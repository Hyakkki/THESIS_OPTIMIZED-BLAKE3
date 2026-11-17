import itertools
import math
import os
import statistics
import tempfile
import unittest
from pathlib import Path

import blake3

import benchmark_blake3 as bench

metrics = bench  # formulas and statistics live in benchmark_blake3
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



class IndicatorTests(unittest.TestCase):
    def test_indicators(self):
        self.assertAlmostEqual(metrics.throughput_mib_s(2 * metrics.MIB, 0.5), 4.0)
        self.assertEqual(metrics.speedup(10.0, 4.0), 2.5)
        self.assertEqual(metrics.percent_time_reduction(10.0, 7.5), 25.0)
        self.assertEqual(metrics.percent_time_reduction(10.0, 12.0), -20.0)
        self.assertIsNone(metrics.speedup(0.0, 1.0))
        self.assertAlmostEqual(metrics.normalized_cpu_percent(6.0, 1.0, 12), 50.0)

    def test_describe(self):
        stats = metrics.describe([1, 2, 3, 4, 100])
        self.assertEqual(stats["median"], 3)
        self.assertEqual(stats["q1"], 2)
        self.assertEqual(stats["q3"], 4)
        self.assertAlmostEqual(stats["stdev"], statistics.stdev([1, 2, 3, 4, 100]))

    def test_every_formula_is_documented(self):
        ids = [f["id"] for f in metrics.FORMULAS]
        self.assertEqual(ids, ["F%d" % i for i in range(1, len(ids) + 1)])
        for formula in metrics.FORMULAS:
            for key in ("name", "expression", "symbols", "function"):
                self.assertTrue(formula[key])


class WilcoxonTests(unittest.TestCase):
    def test_exact_distribution_matches_enumeration(self):
        for n in range(1, 11):
            sums = [sum(r for r, s in zip(range(1, n + 1), signs) if s)
                    for signs in itertools.product((0, 1), repeat=n)]
            for w in range(0, n * (n + 1) // 2 + 1):
                brute = sum(1 for s in sums if s <= w) / 2 ** n
                self.assertAlmostEqual(metrics._wilcoxon_exact_cdf(n, w), brute)

    def test_clear_difference_is_significant(self):
        baseline = [10.0 + i * 0.1 for i in range(30)]
        faster = [b * 0.8 for b in baseline]
        result = metrics.wilcoxon_signed_rank(baseline, faster)
        self.assertEqual(result["method"], "exact")
        self.assertLess(result["p_value"], 1e-6)
        self.assertEqual(result["rank_biserial"], 1.0)

    def test_known_small_sample(self):
        # Differences 1..8 all positive except rank 1: W- = 1 → two-sided exact p = 4/256.
        baseline = [i + 1.0 for i in range(1, 9)]
        configuration = [1.0] * 8
        configuration[0] = 3.0  # difference -1 (rank 1)
        result = metrics.wilcoxon_signed_rank(baseline, configuration)
        self.assertAlmostEqual(result["p_value"], 2 * 2 / 256)

    def test_ties_use_normal_approximation(self):
        result = metrics.wilcoxon_signed_rank([2, 2, 2, 3, 3, 5], [1, 1, 1, 1, 1, 1])
        self.assertIn("normal", result["method"])
        self.assertLess(result["p_value"], 0.05)

    def test_no_difference(self):
        self.assertEqual(metrics.wilcoxon_signed_rank([1, 2], [1, 2])["p_value"], 1.0)


class EffectSizeAndAdjustmentTests(unittest.TestCase):
    def test_cliffs_delta(self):
        self.assertEqual(metrics.cliffs_delta([5, 6, 7], [1, 2, 3])["delta"], 1.0)
        self.assertEqual(metrics.cliffs_delta([1, 2, 3], [1, 2, 3])["delta"], 0.0)
        self.assertEqual(metrics.cliffs_delta([1, 2, 3], [1, 2, 3])["magnitude"], "negligible")
        self.assertEqual(metrics.cliffs_delta([1, 4], [2, 3])["delta"], 0.0)

    def test_holm(self):
        adjusted = metrics.holm_adjust([0.01, 0.04, 0.03, None])
        self.assertAlmostEqual(adjusted[0], 0.03)
        self.assertAlmostEqual(adjusted[2], 0.06)
        self.assertAlmostEqual(adjusted[1], 0.06)
        self.assertIsNone(adjusted[3])

    def test_factorial(self):
        effects = metrics.factorial_effects(2.0, 3.0, 6.0)
        self.assertAlmostEqual(effects["interaction"], 1.0)
        self.assertAlmostEqual(effects["effect_a"], 2.0)
        self.assertAlmostEqual(effects["effect_b"], 3.0)
        self.assertIsNone(metrics.factorial_effects(None, 1.0, 1.0)["interaction"])

    def test_bootstrap_ratio_ci_contains_true_ratio(self):
        baseline = [10.0 + (i % 5) * 0.2 for i in range(30)]
        configuration = [b / 2.0 for b in baseline]
        low, high = metrics.bootstrap_ratio_ci(baseline, configuration)
        self.assertLessEqual(low, 2.0)
        self.assertGreaterEqual(high, 2.0)
        self.assertEqual(metrics.bootstrap_ratio_ci(baseline, configuration), [low, high])

    def test_verdict_rule(self):
        self.assertEqual(metrics.verdict({"p_holm": 0.01, "speedup_ci95": [1.1, 1.3]}),
                         "significantly faster")
        self.assertEqual(metrics.verdict({"p_holm": 0.01, "speedup_ci95": [0.7, 0.9]}),
                         "significantly slower")
        self.assertEqual(metrics.verdict({"p_holm": 0.20, "speedup_ci95": [1.1, 1.3]}),
                         "no significant difference")


class DistributionTests(unittest.TestCase):
    def test_chi_square_known_values(self):
        self.assertAlmostEqual(metrics.chi_square_sf(3.841458820694124, 1), 0.05, places=6)
        self.assertAlmostEqual(metrics.chi_square_sf(18.307038053275146, 10), 0.05, places=6)
        for x in (0.5, 2.0, 7.0, 30.0):
            self.assertAlmostEqual(metrics.chi_square_sf(x, 2), math.exp(-x / 2), places=10)

    def test_binomial_bins(self):
        bins = metrics.binomial_bins(256, 0.5, 1000)
        self.assertEqual(bins[0][0], 0)
        self.assertEqual(bins[-1][1], 256)
        self.assertAlmostEqual(sum(e for _lo, _hi, e in bins), 1000.0, places=6)
        self.assertTrue(all(e >= 5.0 for _lo, _hi, e in bins))


if __name__ == "__main__":
    unittest.main()
