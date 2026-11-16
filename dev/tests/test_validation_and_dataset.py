import json
import os
import random
import tempfile
import unittest
from pathlib import Path

import blake3

import blake3_validation as validation
import dataset_tool
from blake3_reference import reference_hash
from optimized_blake3 import MIB, SMALL_FILE_LIMIT


class VerificationTests(unittest.TestCase):
    def test_official_vectors(self):
        result = validation.official_test_vectors()
        self.assertTrue(result["passed"])
        self.assertEqual(result["cases_total"], 35)

    def test_reference_matches_native(self):
        rng = random.Random(7)
        for length in (0, 1, 1024, 1025, 5000, 70000):
            payload = rng.randbytes(length)
            self.assertEqual(reference_hash(payload).hex(), blake3.blake3(payload).hexdigest())

    def test_configuration_consistency_on_small_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "doc.txt")
            path.write_bytes(os.urandom(300_000))
            result = validation.configuration_consistency(path)
        self.assertTrue(result["passed"], result["mismatches"])
        variants = [o["variant"] for o in result["observations"]]
        self.assertTrue(any("batched" in v for v in variants))

    def test_avalanche_reports_all_diagnostics(self):
        result = validation.avalanche_analysis(random.Random(1).randbytes(4096), samples=400)
        self.assertTrue(result["passed"])
        for key in ("mean_z", "chi_square_p", "sac_bits_outside_band", "interpretation"):
            self.assertIn(key, result)
        self.assertIn("Not a security proof", result["interpretation"])

    def test_empty_input_is_not_applicable(self):
        self.assertFalse(validation.avalanche_analysis(b"")["applicable"])

    def test_collision_screen_and_balance(self):
        screen = validation.collision_screen(b"evidence", variants=300)
        self.assertTrue(screen["passed"])
        self.assertTrue(validation.bit_balance(screen["digests"])["passed"])


class DatasetTests(unittest.TestCase):
    def test_tiers_follow_engine_thresholds(self):
        self.assertTrue(dataset_tool.size_tier(SMALL_FILE_LIMIT - 1).startswith("T3"))
        self.assertTrue(dataset_tool.size_tier(SMALL_FILE_LIMIT).startswith("T4"))
        self.assertTrue(dataset_tool.size_tier(0).startswith("T1"))

    def test_classification(self):
        self.assertEqual(dataset_tool.classify_format("case.E01"), "Disk & Forensic Images")
        self.assertEqual(dataset_tool.classify_format("a.JPG"), "Images")
        self.assertEqual(dataset_tool.classify_format("noext"), "Other")

    def test_generation_is_deterministic_and_manifest_detects_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sweep = dataset_tool.generate_size_sweep(root / "sweep", [1024, 2 * MIB])
            first = sweep[1].read_bytes()
            sweep[1].unlink()
            dataset_tool.generate_size_sweep(root / "sweep", [1024, 2 * MIB])
            self.assertEqual(sweep[1].read_bytes(), first)
            dataset_tool.generate_small_file_corpus(root / "small", count=20)
            (root / "sources.json").write_text(json.dumps({"small": {"source": "unit test"}}))
            manifest = dataset_tool.build_manifest(root)
            self.assertEqual(manifest["file_count"], 22)
            self.assertTrue(any("Disk & Forensic Images" in gap for gap in manifest["gaps"]))
            small_entry = next(e for e in manifest["files"] if e["relative_path"].startswith("small/"))
            self.assertEqual(small_entry["provenance_source"], "unit test")
            json_path, _csv = dataset_tool.write_manifest(manifest, root)
            self.assertTrue(dataset_tool.verify_manifest(json_path)["passed"])
            with open(sweep[0], "r+b") as handle:
                handle.write(b"tampered")
            self.assertEqual(dataset_tool.verify_manifest(json_path)["changed"],
                             ["sweep/" + sweep[0].name])


if __name__ == "__main__":
    unittest.main()
