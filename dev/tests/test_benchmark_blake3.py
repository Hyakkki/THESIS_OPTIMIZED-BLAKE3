import unittest
from pathlib import Path

from benchmark_blake3 import benchmark_files, optimization_percent


class BenchmarkComparisonTests(unittest.TestCase):
    def test_optimization_percent_is_elapsed_time_reduction(self):
        self.assertEqual(optimization_percent(10.0, 7.5), 25.0)
        self.assertEqual(optimization_percent(10.0, 12.0), -20.0)
        self.assertIsNone(optimization_percent(0.0, 0.0))

    def test_single_file_report_contains_all_comparison_rows(self):
        path = Path(__file__).resolve().parents[2] / "README.md"
        report = benchmark_files([path], rounds=5)

        by_algorithm = {row["algorithm"]: row for row in report["summary"]}
        self.assertEqual(
            list(by_algorithm),
            [
                "BLAKE3 (Optimized)",
                "BLAKE3 (Baseline)",
                "MD5",
                "SHA-1",
                "SHA-256",
            ],
        )
        self.assertIn("optimization_percent", by_algorithm["BLAKE3 (Optimized)"])
        for row in by_algorithm.values():
            self.assertIn("median_elapsed_ms", row)
            self.assertIn("median_throughput_mb_s", row)
            self.assertIn("median_cpu_utilization_percent", row)
            self.assertIn("median_peak_rss_mb", row)
            self.assertIn("elapsed_stdev_ms", row)
            self.assertIn("elapsed_cv_percent", row)
            self.assertIn("optimized_time_change_percent", row)
            self.assertIn("optimized_speedup_ratio", row)
        self.assertEqual(
            by_algorithm["BLAKE3 (Optimized)"]["optimized_time_change_percent"],
            0.0,
        )
        self.assertEqual(report["methodology"]["warmups_per_profile"], 1)
        self.assertEqual(report["methodology"]["measured_trials_per_profile"], 5)
        self.assertTrue(report["validation"][0]["blake3_profiles_match"])
        for algorithm in by_algorithm:
            positions = sorted(
                row["execution_position"]
                for row in report["runs"]
                if row["algorithm"] == algorithm
            )
            self.assertEqual(positions, [1, 2, 3, 4, 5])

        digests = {
            row["algorithm"]: row["digest"]
            for row in report["runs"]
            if row["status"] == "ok"
        }
        self.assertEqual(
            digests["BLAKE3 (Optimized)"], digests["BLAKE3 (Baseline)"]
        )


if __name__ == "__main__":
    unittest.main()
