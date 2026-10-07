#!/usr/bin/env python3
"""Reproducible BLAKE3/SHA/MD5 file benchmark with equal timing scope."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
import os
import platform
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import blake3 as _blake3

from optimized_blake3 import (
    MIB,
    _MetricSampler,
    detected_simd_tier,
    hash_file,
    physical_cpu_count,
    self_test,
)


EVIDENCE_EXTENSIONS = {
    "Documents": {".pdf", ".docx", ".txt"},
    "Images": {".jpg", ".jpeg", ".png"},
    "Audio": {".mp3", ".wav"},
    "Video": {".mp4", ".avi"},
    "Executables": {".exe", ".elf"},
    "Disk Images": {".dd", ".e01", ".vmdk"},
}


def evidence_category(path: os.PathLike[str] | str) -> str:
    extension = Path(path).suffix.lower()
    for category, extensions in EVIDENCE_EXTENSIONS.items():
        if extension in extensions:
            return category
    return "Other"


def _baseline_hash(path: str, algorithm: str) -> Dict[str, Any]:
    hasher = hashlib.new(algorithm)
    size = os.path.getsize(path)
    sampler = _MetricSampler(True)
    with sampler:
        with open(path, "rb", buffering=0) as source:
            if size:
                with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                    hasher.update(mapped)
        elapsed_s, cpu_percent, process_percent, peak_rss_mb = sampler.finish()
    return {
        "status": "ok",
        "algorithm": algorithm.upper().replace("SHA", "SHA-"),
        "digest": hasher.hexdigest(),
        "bytes_read": size,
        "elapsed_ms": round(elapsed_s * 1000.0, 3),
        "throughput_mb_s": round(size / MIB / elapsed_s, 3) if elapsed_s else 0.0,
        "cpu_utilization_percent": round(cpu_percent, 3) if cpu_percent is not None else None,
        "process_cpu_percent": round(process_percent, 3)
        if process_percent is not None
        else None,
        "peak_rss_mb": peak_rss_mb,
        "io_strategy": "mmap",
    }


def _baseline_blake3_hash(path: str) -> Dict[str, Any]:
    """Hash with the study's fixed-buffer, single-thread BLAKE3 control."""
    hasher = _blake3.blake3(max_threads=1)
    size = os.path.getsize(path)
    bytes_read = 0
    sampler = _MetricSampler(True)
    with sampler:
        with open(path, "rb", buffering=0) as source:
            while True:
                block = source.read(MIB)
                if not block:
                    break
                hasher.update(block)
                bytes_read += len(block)
        digest = hasher.hexdigest()
        elapsed_s, cpu_percent, process_percent, peak_rss_mb = sampler.finish()
    if bytes_read != size:
        return {
            "status": "error",
            "algorithm": "BLAKE3 (Baseline)",
            "digest": "",
            "bytes_read": bytes_read,
            "elapsed_ms": round(elapsed_s * 1000.0, 3),
            "throughput_mb_s": 0.0,
            "cpu_utilization_percent": None,
            "process_cpu_percent": None,
            "peak_rss_mb": peak_rss_mb,
            "io_strategy": "fixed-1MiB-single-thread-baseline",
            "message": "short read: expected %d bytes, received %d" % (size, bytes_read),
        }
    return {
        "status": "ok",
        "algorithm": "BLAKE3 (Baseline)",
        "digest": digest,
        "bytes_read": bytes_read,
        "elapsed_ms": round(elapsed_s * 1000.0, 3),
        "throughput_mb_s": round(size / MIB / elapsed_s, 3) if elapsed_s else 0.0,
        "cpu_utilization_percent": round(cpu_percent, 3) if cpu_percent is not None else None,
        "process_cpu_percent": round(process_percent, 3)
        if process_percent is not None
        else None,
        "peak_rss_mb": peak_rss_mb,
        "io_strategy": "fixed-1MiB-single-thread-baseline",
    }


def optimization_percent(comparison_ms: float, optimized_ms: float) -> Optional[float]:
    """Return optimized BLAKE3's elapsed-time change versus a comparison profile."""
    comparison = float(comparison_ms)
    optimized = float(optimized_ms)
    if comparison <= 0.0 or optimized < 0.0:
        return None
    return ((comparison - optimized) / comparison) * 100.0


def _operations(path: str):
    """Create fresh callables for every full-file comparison profile."""
    return [
        ("BLAKE3 (Optimized)", lambda: hash_file(path).to_dict()),
        ("BLAKE3 (Baseline)", lambda: _baseline_blake3_hash(path)),
        ("SHA-256", lambda: _baseline_hash(path, "sha256")),
        ("SHA-1", lambda: _baseline_hash(path, "sha1")),
        ("MD5", lambda: _baseline_hash(path, "md5")),
    ]


def _distribution(values: List[float]) -> Dict[str, Optional[float]]:
    """Return report-ready descriptive statistics for repeated measurements."""
    if not values:
        return {
            "median": None,
            "mean": None,
            "stdev": None,
            "cv_percent": None,
            "minimum": None,
            "maximum": None,
        }
    mean = statistics.mean(values)
    stdev = statistics.stdev(values) if len(values) > 1 else 0.0
    return {
        "median": statistics.median(values),
        "mean": mean,
        "stdev": stdev,
        "cv_percent": (stdev / mean * 100.0) if mean else None,
        "minimum": min(values),
        "maximum": max(values),
    }


def benchmark_files(
    paths: Iterable[os.PathLike[str] | str], rounds: int = 5, warmups: int = 1
) -> Dict[str, Any]:
    if rounds < 1:
        raise ValueError("rounds must be at least 1")
    if warmups < 0:
        raise ValueError("warmups cannot be negative")
    normalized = [str(Path(path).resolve()) for path in paths]
    if not normalized:
        raise ValueError("at least one benchmark file is required")

    runs: List[Dict[str, Any]] = []
    validation: List[Dict[str, Any]] = []
    for file_index, path in enumerate(normalized):
        before = os.stat(path)
        size = int(before.st_size)
        category = evidence_category(path)

        # Warm every profile without including these passes in reported results.
        # A deterministic shuffle avoids always warming the same profile first.
        warmup_operations = _operations(path)
        random.Random(0xB1A3E3 + file_index).shuffle(warmup_operations)
        for warmup_number in range(warmups):
            shift = warmup_number % len(warmup_operations)
            ordered_warmups = warmup_operations[shift:] + warmup_operations[:shift]
            for algorithm_name, operation in ordered_warmups:
                warmup_result = operation()
                if warmup_result.get("status") != "ok":
                    raise RuntimeError(
                        "%s warm-up failed for %s: %s"
                        % (algorithm_name, path, warmup_result.get("message", "unknown error"))
                    )

        # Rotate a shuffled base order. With five measured trials, every profile
        # occupies every execution position exactly once.
        base_operations = _operations(path)
        random.Random(0xC0DE + file_index).shuffle(base_operations)
        expected_digests: Dict[str, str] = {}
        for round_number in range(1, rounds + 1):
            shift = (round_number - 1) % len(base_operations)
            operations = base_operations[shift:] + base_operations[:shift]
            round_results: Dict[str, Dict[str, Any]] = {}
            for execution_position, (algorithm_name, operation) in enumerate(
                operations, start=1
            ):
                record = operation()
                record["algorithm"] = algorithm_name
                if record.get("status") != "ok":
                    raise RuntimeError(
                        "%s failed for %s: %s"
                        % (algorithm_name, path, record.get("message", "unknown error"))
                    )
                digest = str(record.get("digest", ""))
                expected = expected_digests.setdefault(algorithm_name, digest)
                if not digest or digest != expected:
                    raise RuntimeError(
                        "%s produced an inconsistent digest for %s"
                        % (algorithm_name, path)
                    )
                record.update(
                    {
                        "path": path,
                        "file_name": os.path.basename(path),
                        "category": category,
                        "file_size_bytes": size,
                        "round": round_number,
                        "execution_position": execution_position,
                        "timing_scope": "open+mmap/read+hash+digest-finalize",
                    }
                )
                runs.append(record)
                round_results[algorithm_name] = record

            optimized_digest = round_results["BLAKE3 (Optimized)"]["digest"]
            baseline_digest = round_results["BLAKE3 (Baseline)"]["digest"]
            if optimized_digest != baseline_digest:
                raise RuntimeError(
                    "optimized and baseline BLAKE3 digests disagree for %s" % path
                )

        after = os.stat(path)
        if (
            int(after.st_size) != size
            or int(after.st_mtime_ns) != int(before.st_mtime_ns)
        ):
            raise RuntimeError("file changed during benchmark: %s" % path)
        validation.append(
            {
                "path": path,
                "file_size_bytes": size,
                "digest_consistency": "passed",
                "blake3_profiles_match": True,
            }
        )

    summaries: List[Dict[str, Any]] = []
    algorithm_order = {
        "BLAKE3 (Optimized)": 0,
        "BLAKE3 (Baseline)": 1,
        "MD5": 2,
        "SHA-1": 3,
        "SHA-256": 4,
    }
    keys = sorted(
        {(run["category"], run["algorithm"]) for run in runs},
        key=lambda item: (item[0], algorithm_order.get(item[1], 99), item[1]),
    )
    for category, algorithm in keys:
        matching = [
            run
            for run in runs
            if run["category"] == category
            and run["algorithm"] == algorithm
            and run["status"] == "ok"
        ]
        throughputs = [float(run["throughput_mb_s"]) for run in matching]
        elapsed = [float(run["elapsed_ms"]) for run in matching]
        cpu_utilization = [
            float(run["cpu_utilization_percent"])
            for run in matching
            if run.get("cpu_utilization_percent") is not None
        ]
        peak_rss = [
            float(run["peak_rss_mb"])
            for run in matching
            if run.get("peak_rss_mb") is not None
        ]
        elapsed_stats = _distribution(elapsed)
        throughput_stats = _distribution(throughputs)
        summaries.append(
            {
                "category": category,
                "algorithm": algorithm,
                "runs": len(matching),
                "median_throughput_mb_s": round(throughput_stats["median"], 3)
                if throughput_stats["median"] is not None
                else 0.0,
                "mean_throughput_mb_s": round(throughput_stats["mean"], 3)
                if throughput_stats["mean"] is not None
                else 0.0,
                "throughput_stdev_mb_s": round(throughput_stats["stdev"], 3)
                if throughput_stats["stdev"] is not None
                else None,
                "throughput_cv_percent": round(throughput_stats["cv_percent"], 3)
                if throughput_stats["cv_percent"] is not None
                else None,
                "median_elapsed_ms": round(elapsed_stats["median"], 6)
                if elapsed_stats["median"] is not None
                else 0.0,
                "mean_elapsed_ms": round(elapsed_stats["mean"], 6)
                if elapsed_stats["mean"] is not None
                else 0.0,
                "elapsed_stdev_ms": round(elapsed_stats["stdev"], 6)
                if elapsed_stats["stdev"] is not None
                else None,
                "elapsed_cv_percent": round(elapsed_stats["cv_percent"], 3)
                if elapsed_stats["cv_percent"] is not None
                else None,
                "min_elapsed_ms": round(elapsed_stats["minimum"], 6)
                if elapsed_stats["minimum"] is not None
                else None,
                "max_elapsed_ms": round(elapsed_stats["maximum"], 6)
                if elapsed_stats["maximum"] is not None
                else None,
                "median_cpu_utilization_percent": round(
                    statistics.median(cpu_utilization), 3
                )
                if cpu_utilization
                else None,
                "median_peak_rss_mb": round(statistics.median(peak_rss), 3)
                if peak_rss
                else None,
            }
        )
    for category in {entry["category"] for entry in summaries}:
        by_algorithm = {
            entry["algorithm"]: entry
            for entry in summaries
            if entry["category"] == category
        }
        optimized = by_algorithm.get("BLAKE3 (Optimized)")
        baseline = by_algorithm.get("BLAKE3 (Baseline)")
        if optimized is not None:
            optimized_ms = float(optimized["median_elapsed_ms"])
            for entry in by_algorithm.values():
                comparison_ms = float(entry["median_elapsed_ms"])
                time_change = optimization_percent(comparison_ms, optimized_ms)
                entry["optimized_time_change_percent"] = (
                    round(time_change, 3) if time_change is not None else None
                )
                entry["optimized_speedup_ratio"] = (
                    round(comparison_ms / optimized_ms, 3)
                    if optimized_ms > 0.0
                    else None
                )
        if optimized is not None and baseline is not None:
            baseline_ms = float(baseline["median_elapsed_ms"])
            percent = optimization_percent(baseline_ms, optimized_ms)
            optimized["optimization_percent"] = (
                round(percent, 3) if percent is not None else None
            )
            optimized["speedup_vs_baseline"] = (
                round(baseline_ms / optimized_ms, 3) if optimized_ms > 0.0 else None
            )
            baseline["optimization_percent"] = 0.0
            baseline["speedup_vs_baseline"] = 1.0

    warnings: List[str] = []
    if rounds < 5:
        warnings.append(
            "Fewer than five measured trials were used; treat percentage differences as preliminary."
        )
    short_measurements: List[str] = []
    variable_measurements: List[str] = []
    for entry in summaries:
        if 0.0 < float(entry["median_elapsed_ms"]) < 10.0:
            short_measurements.append(entry["algorithm"])
        cv = entry.get("elapsed_cv_percent")
        if cv is not None and float(cv) > 10.0:
            variable_measurements.append(
                "%s (%.2f%%)" % (entry["algorithm"], float(cv))
            )
    if short_measurements:
        warnings.append(
            "Sub-10 ms measurements detected for %s; use a larger file for stable CPU and memory sampling."
            % ", ".join(short_measurements)
        )
    if variable_measurements:
        warnings.append(
            "Timing CV exceeded 10%% for %s; increase trials or reduce background load."
            % ", ".join(variable_measurements)
        )
    return {
        "schema_version": 2,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": {
            "platform": platform.platform(),
            "python": sys.version,
            "logical_cpu_count": os.cpu_count(),
            "physical_cpu_count": physical_cpu_count(),
            "processor": platform.processor() or "unknown",
            "blake3_version": str(getattr(_blake3, "__version__", "unknown")),
            "simd_tier": detected_simd_tier(),
        },
        "methodology": {
            "timing_scope": "open+read/mmap+hash+digest-finalize for every algorithm",
            "comparison_scope": "end-to-end application profiles; this measures I/O strategy, threading, and hashing together rather than isolated compression-function speed",
            "warmups_per_profile": warmups,
            "measured_trials_per_profile": rounds,
            "cache_policy": "warm-cache application benchmark; warm-up passes are excluded",
            "order_control": "deterministically shuffled base order with cyclic rotation; five trials place every profile in every position once",
            "statistics": "median is primary; mean, sample standard deviation, coefficient of variation, minimum, and maximum are also reported",
            "unit": "MiB/s (2^20 bytes/s), displayed as MB/s for Autopsy compatibility",
            "optimization_formula": "(comparison profile median time - optimized BLAKE3 median time) / comparison profile median time * 100",
        },
        "self_test": self_test(),
        "validation": validation,
        "warnings": warnings,
        "runs": runs,
        "summary": summaries,
    }


def _write_csv(path: str, runs: List[Dict[str, Any]]) -> None:
    columns = [
        "file_name",
        "path",
        "category",
        "file_size_bytes",
        "round",
        "execution_position",
        "algorithm",
        "digest",
        "elapsed_ms",
        "throughput_mb_s",
        "cpu_utilization_percent",
        "process_cpu_percent",
        "peak_rss_mb",
        "io_strategy",
        "timing_scope",
        "status",
        "message",
    ]
    with open(path, "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(runs)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="evidence files to benchmark")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--json-output")
    parser.add_argument("--csv-output")
    args = parser.parse_args(argv)
    report = benchmark_files(
        args.paths, rounds=max(1, args.rounds), warmups=max(0, args.warmups)
    )
    encoded = json.dumps(report, indent=2)
    if args.json_output:
        Path(args.json_output).write_text(encoded + "\n", encoding="utf-8")
    else:
        print(encoded)
    if args.csv_output:
        _write_csv(args.csv_output, report["runs"])
    return 0 if report["self_test"]["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
