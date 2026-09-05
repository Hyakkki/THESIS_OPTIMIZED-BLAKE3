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
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from optimized_blake3 import MIB, _MetricSampler, hash_file, self_test


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


def benchmark_files(
    paths: Iterable[os.PathLike[str] | str], rounds: int = 3
) -> Dict[str, Any]:
    normalized = [str(Path(path).resolve()) for path in paths]
    runs: List[Dict[str, Any]] = []
    for path in normalized:
        size = os.path.getsize(path)
        category = evidence_category(path)
        for round_number in range(1, rounds + 1):
            operations = [
                ("BLAKE3", lambda: hash_file(path).to_dict()),
                ("SHA-256", lambda: _baseline_hash(path, "sha256")),
                ("SHA-1", lambda: _baseline_hash(path, "sha1")),
                ("MD5", lambda: _baseline_hash(path, "md5")),
            ]
            # Rotate the order each round so warm-cache position is not always
            # assigned to the same algorithm.
            shift = (round_number - 1) % len(operations)
            operations = operations[shift:] + operations[:shift]
            algorithms = []
            for algorithm_name, operation in operations:
                record = operation()
                record["algorithm"] = algorithm_name
                algorithms.append(record)
            for record in algorithms:
                record.update(
                    {
                        "path": path,
                        "file_name": os.path.basename(path),
                        "category": category,
                        "file_size_bytes": size,
                        "round": round_number,
                        "timing_scope": "open+mmap/read+hash+digest-finalize",
                    }
                )
                runs.append(record)

    summaries: List[Dict[str, Any]] = []
    keys = sorted({(run["category"], run["algorithm"]) for run in runs})
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
        summaries.append(
            {
                "category": category,
                "algorithm": algorithm,
                "runs": len(matching),
                "median_throughput_mb_s": round(statistics.median(throughputs), 3)
                if throughputs
                else 0.0,
                "median_elapsed_ms": round(statistics.median(elapsed), 3)
                if elapsed
                else 0.0,
            }
        )
    return {
        "schema_version": 1,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": {
            "platform": platform.platform(),
            "python": sys.version,
            "logical_cpu_count": os.cpu_count(),
        },
        "methodology": {
            "timing_scope": "open+mmap/read+hash+digest-finalize for every algorithm",
            "cache_note": "Algorithm order rotates each round; report cold/warm cache controls separately in the thesis.",
            "unit": "MiB/s (2^20 bytes/s), displayed as MB/s for Autopsy compatibility",
        },
        "self_test": self_test(),
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
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--json-output")
    parser.add_argument("--csv-output")
    args = parser.parse_args(argv)
    report = benchmark_files(args.paths, max(1, args.rounds))
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
