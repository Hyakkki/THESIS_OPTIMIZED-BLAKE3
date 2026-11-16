#!/usr/bin/env python3
"""Controlled technique-isolation benchmarks with statistical analysis.

Two experiments (Panel recommendations #2, #3, #22):

* **Large-file experiment** – a 2×2 factorial design over the two techniques
  that act on a single file: adaptive buffering (A) and multithreading (B).
  Cells: Baseline (A off, B off), Buffer only, Threads only, Optimized (both).
  SHA-256, SHA-1 and MD5 are measured with the Baseline I/O path as reference
  algorithms "as configured".
* **Small-file experiment** – a 2×2 factorial design over the techniques that
  act on many small files: batching and parallel dispatch.

Both use a randomized complete block design: each round runs every condition
once in a seeded random order. Warm-ups are excluded. Every execution must
reproduce the expected digest, otherwise the benchmark aborts. Statistics and
formulas are defined in ``metrics.py``.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import random
import statistics
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import blake3 as _blake3

import metrics
from dataset_tool import classify_format, size_tier
from optimized_blake3 import (
    BLAKE3_CONFIGS,
    DEFAULT_BATCH_SIZE,
    EXPLORATORY_CONFIGS,
    MIB,
    OperationCancelled,
    REFERENCE_ALGORITHMS,
    SMALL_FILE_LIMIT,
    SMALL_FILE_MODES,
    _MetricSampler,
    adaptive_chunk_size,
    detected_simd_tier,
    hash_file_config,
    hash_file_reference,
    hash_small_files,
    logical_cpu_count,
    make_worker_pool,
    physical_cpu_count,
    self_test,
)

DEFAULT_TRIALS = 30
DEFAULT_WARMUPS = 2
MIN_TRIALS = 10
CV_LIMIT_PERCENT = 10.0
SHORT_MEASUREMENT_MS = 10.0

ProgressCallback = Optional[Callable[[str, float], None]]

# Backward-compatible names.
optimization_percent = metrics.percent_time_reduction


class BenchmarkCancelled(OperationCancelled):
    """Raised when the caller's cancel event is set between executions."""


def host_information() -> Dict[str, Any]:
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "processor": platform.processor() or "unknown",
        "logical_cpu_count": logical_cpu_count(),
        "physical_cpu_count": physical_cpu_count(),
        "blake3_package_version": str(getattr(_blake3, "__version__", "unknown")),
        "simd_tier": detected_simd_tier(),
        "simd_note": "Native SIMD dispatch is identical in every BLAKE3 configuration "
                     "(held constant; not a studied technique).",
    }


def _check_cancel(cancel: Optional[threading.Event]) -> None:
    if cancel is not None and cancel.is_set():
        raise BenchmarkCancelled("benchmark cancelled by user")


class _Progress:
    """Progress fractions plus a simple remaining-time estimate."""

    def __init__(self, callback: ProgressCallback, total_steps: int):
        self.callback = callback
        self.total = max(1, total_steps)
        self.done = 0
        self.started = time.perf_counter()

    def step(self, message: str) -> None:
        self.done += 1
        if self.callback is None:
            return
        fraction = min(1.0, self.done / self.total)
        elapsed = time.perf_counter() - self.started
        if 0 < fraction < 1:
            remaining = elapsed / fraction - elapsed
            message += "  ·  about %s left" % _format_duration(remaining)
        self.callback(message, fraction)


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "%d s" % seconds
    if seconds < 3600:
        return "%d min %d s" % divmod(seconds, 60)
    hours, rest = divmod(seconds, 3600)
    return "%d h %d min" % (hours, rest // 60)


def _summarize_condition(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    elapsed = [run["elapsed_ms"] for run in runs]
    throughput = [run["throughput_mib_s"] for run in runs]
    cpu = [run["cpu_percent"] for run in runs if run.get("cpu_percent") is not None]
    rss = [run["peak_rss_mib"] for run in runs if run.get("peak_rss_mib") is not None]
    time_stats = metrics.describe(elapsed)
    return {
        "elapsed_ms": time_stats,
        "elapsed_median_ci95": metrics.bootstrap_ci(elapsed),
        "throughput_mib_s": metrics.describe(throughput),
        "cpu_percent_median": statistics.median(cpu) if cpu else None,
        "peak_rss_mib_median": statistics.median(rss) if rss else None,
        "stable": (time_stats["cv_percent"] or 0.0) <= CV_LIMIT_PERCENT
        and (time_stats["median"] or 0.0) >= SHORT_MEASUREMENT_MS,
    }


def _comparisons(
    by_condition: Dict[str, List[float]],
    pairs: Sequence[Tuple[str, str, str]],
    seed: int,
) -> List[Dict[str, Any]]:
    """``pairs``: (family, slower/reference key, faster/candidate key)."""
    results: List[Dict[str, Any]] = []
    for family, reference, candidate in pairs:
        if reference not in by_condition or candidate not in by_condition:
            continue
        comparison = metrics.compare_to_baseline(
            by_condition[reference], by_condition[candidate], seed=seed
        )
        comparison.update({"family": family, "reference": reference, "candidate": candidate})
        results.append(comparison)
    for family in {item["family"] for item in results}:
        members = [item for item in results if item["family"] == family]
        for item, adjusted in zip(members, metrics.holm_adjust([m["p_value"] for m in members])):
            item["p_holm"] = adjusted
    for item in results:
        item["verdict"] = metrics.verdict(item)
    return results


def _paired_times(runs: List[Dict[str, Any]], keys: Sequence[str]) -> Dict[str, List[float]]:
    """Elapsed times per condition ordered by round, so index i pairs block i."""
    table: Dict[str, Dict[int, float]] = {key: {} for key in keys}
    for run in runs:
        if run["condition"] in table:
            table[run["condition"]][run["round"]] = run["elapsed_ms"]
    rounds = sorted(set.intersection(*(set(v) for v in table.values()))) if table else []
    return {key: [table[key][r] for r in rounds] for key in keys}


def _warnings_for(summary: Dict[str, Dict[str, Any]], labels: Dict[str, str]) -> List[str]:
    warnings = []
    for key, item in summary.items():
        stats = item["elapsed_ms"]
        if stats["median"] is not None and stats["median"] < SHORT_MEASUREMENT_MS:
            warnings.append("%s: median below %.0f ms; timer and sampling noise dominate — "
                            "use a larger input." % (labels[key], SHORT_MEASUREMENT_MS))
        if stats["cv_percent"] is not None and stats["cv_percent"] > CV_LIMIT_PERCENT:
            warnings.append("%s: CV %.1f %% exceeds %.0f %%; re-run on a quieter system."
                            % (labels[key], stats["cv_percent"], CV_LIMIT_PERCENT))
    return warnings


# ─────────────────────────────────────────────────────────────────────────────
# Experiment 1: large files (adaptive buffering × multithreading)
# ─────────────────────────────────────────────────────────────────────────────

def _large_conditions(include_references: bool, include_exploratory: bool, threads: Optional[int]):
    conditions = []
    for config in BLAKE3_CONFIGS + (EXPLORATORY_CONFIGS if include_exploratory else ()):
        conditions.append((config.key, config.label, "exploratory" if config.exploratory else "blake3",
                           lambda p, c=config: hash_file_config(p, c, threads=threads)))
    if include_references:
        for algorithm, label in REFERENCE_ALGORITHMS:
            conditions.append((algorithm, label, "reference",
                               lambda p, a=algorithm: hash_file_reference(p, a)))
    return conditions


def run_large_file_ablation(
    paths: Sequence[os.PathLike[str] | str],
    *,
    trials: int = DEFAULT_TRIALS,
    warmups: int = DEFAULT_WARMUPS,
    include_references: bool = True,
    include_exploratory: bool = False,
    threads: Optional[int] = None,
    seed: int = 0xC0DE,
    progress: ProgressCallback = None,
    cancel: Optional[threading.Event] = None,
) -> Dict[str, Any]:
    if trials < 1 or warmups < 0:
        raise ValueError("trials must be ≥ 1 and warmups ≥ 0")
    files = [str(Path(p).resolve()) for p in paths]
    if not files:
        raise ValueError("select at least one file")
    conditions = _large_conditions(include_references, include_exploratory, threads)
    labels = {key: label for key, label, _kind, _fn in conditions}
    kinds = {key: kind for key, _label, kind, _fn in conditions}
    tracker = _Progress(progress, len(files) * len(conditions) * (trials + warmups))
    validation = self_test()
    if not validation["passed"]:
        raise RuntimeError("engine self-test failed: " + validation["message"])

    all_runs: List[Dict[str, Any]] = []
    file_reports: List[Dict[str, Any]] = []
    for file_index, path in enumerate(files):
        name = os.path.basename(path)
        before = os.stat(path)
        size = int(before.st_size)
        expected: Dict[str, str] = {}
        warmup_records: List[Dict[str, Any]] = []
        file_runs: List[Dict[str, Any]] = []

        def execute(key: str, fn, round_number: int, position: int, warmup: bool):
            _check_cancel(cancel)
            result = fn(path)
            if result.status != "ok":
                raise RuntimeError("%s failed on %s: %s" % (labels[key], name, result.error))
            # BLAKE3 configurations must all agree; each reference must be stable.
            digest_group = "blake3" if kinds[key] in ("blake3", "exploratory") else key
            reference_digest = expected.setdefault(digest_group, result.digest)
            if result.digest != reference_digest:
                raise RuntimeError("digest mismatch: %s produced a different digest for %s; "
                                   "results discarded" % (labels[key], name))
            record = {
                "file": name, "path": path, "size_bytes": size,
                "category": classify_format(path), "size_tier": size_tier(size),
                "round": round_number, "position": position, "warmup": warmup,
                "condition": key, "label": labels[key], "kind": kinds[key],
                "elapsed_ms": result.elapsed_ms,
                "throughput_mib_s": result.throughput_mb_s,
                "cpu_percent": result.cpu_utilization_percent,
                "process_cpu_percent": result.process_cpu_percent,
                "peak_rss_mib": result.peak_rss_mb,
                "buffer_bytes": result.chunk_size,
                "threads": result.threads_used,
                "io_strategy": result.io_strategy,
                "digest": result.digest,
            }
            tracker.step("%s · %s · %s %d" % (
                name, labels[key], "warm-up" if warmup else "round", round_number))
            return record

        for warmup_number in range(1, warmups + 1):
            order = list(conditions)
            random.Random(seed ^ (file_index << 16) ^ (0xAAAA + warmup_number)).shuffle(order)
            for position, (key, _label, _kind, fn) in enumerate(order, 1):
                warmup_records.append(execute(key, fn, warmup_number, position, True))

        for round_number in range(1, trials + 1):
            order = list(conditions)
            random.Random(seed ^ (file_index << 16) ^ round_number).shuffle(order)
            for position, (key, _label, _kind, fn) in enumerate(order, 1):
                file_runs.append(execute(key, fn, round_number, position, False))

        after = os.stat(path)
        if int(after.st_size) != size or int(after.st_mtime_ns) != int(before.st_mtime_ns):
            raise RuntimeError("file changed during benchmark: %s" % name)

        keys = [key for key, *_ in conditions]
        summary = {key: _summarize_condition([r for r in file_runs if r["condition"] == key])
                   for key in keys}
        for key in keys:
            summary[key].update({"label": labels[key], "kind": kinds[key]})
            first = next((r for r in warmup_records if r["condition"] == key), None)
            summary[key]["first_warmup_ms"] = first["elapsed_ms"] if first else None
            sample = next(r for r in file_runs if r["condition"] == key)
            summary[key].update({"buffer_bytes": sample["buffer_bytes"],
                                 "threads": sample["threads"],
                                 "io_strategy": sample["io_strategy"]})
        paired = _paired_times(file_runs, keys)
        pairs = [("technique", "baseline", c.key) for c in BLAKE3_CONFIGS[1:]]
        if include_exploratory:
            pairs += [("technique", "baseline", c.key) for c in EXPLORATORY_CONFIGS]
        if include_references:
            pairs += [("reference", algorithm, "optimized") for algorithm, _ in REFERENCE_ALGORITHMS]
        comparisons = _comparisons(paired, pairs, seed)
        speedups = {c["candidate"]: c["speedup"] for c in comparisons if c["family"] == "technique"}
        factorial = metrics.factorial_effects(
            speedups.get("buffer_only"), speedups.get("threads_only"), speedups.get("optimized"))
        factorial.update({"factor_a": "adaptive buffering", "factor_b": "multithreading"})
        warnings = _warnings_for(summary, labels)
        if size < SMALL_FILE_LIMIT:
            warnings.append("File is below the %s multithreading threshold, so 'Multithreading "
                            "only' equals Baseline by design." % _mib(SMALL_FILE_LIMIT))
        file_reports.append({
            "file": name, "path": path, "size_bytes": size,
            "category": classify_format(path), "size_tier": size_tier(size),
            "adaptive_buffer_bytes": adaptive_chunk_size(size),
            "blake3_digest": expected.get("blake3", ""),
            "conditions": summary, "comparisons": comparisons,
            "factorial": factorial, "warnings": warnings,
            "warmup_runs": warmup_records,
        })
        all_runs.extend(file_runs)

    return {
        "schema_version": 3,
        "experiment": "large-file technique isolation (adaptive buffering × multithreading)",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": host_information(),
        "self_test": validation,
        "design": _design(trials, warmups, seed),
        "conditions": [{"key": k, "label": l, "kind": kd} for k, l, kd, _ in conditions],
        "files": file_reports,
        "tier_summary": _tier_summary(file_reports),
        "runs": all_runs,
        "warnings": [w for report in file_reports for w in
                     ("%s: %s" % (report["file"], text) for text in report["warnings"])]
        + ([] if trials >= MIN_TRIALS else
           ["Fewer than %d trials: treat results as preliminary." % MIN_TRIALS]),
    }


def _mib(value: int) -> str:
    return "%d MiB" % (value // MIB)


def _design(trials: int, warmups: int, seed: int) -> Dict[str, Any]:
    return {
        "type": "randomized complete block design (round = block)",
        "measured_trials_per_condition": trials,
        "warmups_per_condition": warmups,
        "order_seed": seed,
        "cache_state": "warm (file pages cached by the OS after warm-ups); first warm-up "
                       "timings are retained separately as first-access observations",
        "timing_scope": "open + read + hash + digest finalization (F1)",
        "primary_indicator": "elapsed time, median (F1, F7)",
        "tests": "paired Wilcoxon signed-rank (F10) with Holm adjustment per family (F13); "
                 "bootstrap 95 % CI of speedup (F9); Cliff's delta (F12)",
        "alpha": 0.05,
        "formulas": "see metrics.FORMULAS",
    }


def _geometric_mean(values: Sequence[float]) -> Optional[float]:
    values = [v for v in values if v and v > 0]
    if not values:
        return None
    return math.exp(sum(math.log(v) for v in values) / len(values))


def _tier_summary(file_reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    tiers = sorted({report["size_tier"] for report in file_reports})
    for tier in tiers:
        members = [r for r in file_reports if r["size_tier"] == tier]
        for candidate in [c.key for c in BLAKE3_CONFIGS[1:] + EXPLORATORY_CONFIGS]:
            items = [c for r in members for c in r["comparisons"]
                     if c["family"] == "technique" and c["candidate"] == candidate]
            if not items:
                continue
            rows.append({
                "size_tier": tier,
                "condition": candidate,
                "files": len(items),
                "geometric_mean_speedup": _geometric_mean([i["speedup"] for i in items]),
                "significantly_faster": sum(1 for i in items if i["verdict"] == "significantly faster"),
                "significantly_slower": sum(1 for i in items if i["verdict"] == "significantly slower"),
            })
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Experiment 2: small files (parallel dispatch × batching)
# ─────────────────────────────────────────────────────────────────────────────

def run_small_file_ablation(
    paths: Sequence[os.PathLike[str] | str],
    *,
    trials: int = DEFAULT_TRIALS,
    warmups: int = DEFAULT_WARMUPS,
    workers: Optional[int] = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    seed: int = 0x5EED,
    progress: ProgressCallback = None,
    cancel: Optional[threading.Event] = None,
) -> Dict[str, Any]:
    candidates = [str(Path(p).resolve()) for p in paths]
    files = [p for p in candidates if os.path.getsize(p) < SMALL_FILE_LIMIT]
    excluded = len(candidates) - len(files)
    if len(files) < 2:
        raise ValueError("the small-file experiment needs at least two files below %s"
                         % _mib(SMALL_FILE_LIMIT))
    total_bytes = sum(os.path.getsize(p) for p in files)
    snapshot = {p: os.stat(p).st_mtime_ns for p in files}
    labels = {mode.key: mode.label for mode in SMALL_FILE_MODES}
    tracker = _Progress(progress, len(SMALL_FILE_MODES) * (trials + warmups) + 2)

    expected = hash_small_files(files, "sequential")  # outside timing
    tracker.step("Computed reference digests for %d files" % len(files))
    pool, pool_startup_s = make_worker_pool(workers)
    worker_count = max(1, int(workers or physical_cpu_count()))
    tracker.step("Started %d worker processes (%.3f s, reported separately)"
                 % (worker_count, pool_startup_s))
    runs: List[Dict[str, Any]] = []
    warmup_records: List[Dict[str, Any]] = []
    try:
        def execute(mode, round_number, position, warmup):
            _check_cancel(cancel)
            sampler = _MetricSampler(True, include_children=mode.parallel)
            with sampler:
                results = hash_small_files(files, mode, pool=pool, batch_size=batch_size)
                elapsed_s, cpu, process_cpu, rss = sampler.finish()
            if results != expected:
                raise RuntimeError("digest mismatch in mode %s; results discarded" % mode.label)
            record = {
                "round": round_number, "position": position, "warmup": warmup,
                "condition": mode.key, "label": mode.label,
                "files": len(files), "total_bytes": total_bytes,
                "elapsed_ms": round(elapsed_s * 1000.0, 3),
                "throughput_mib_s": round(metrics.throughput_mib_s(total_bytes, elapsed_s), 3),
                "files_per_second": round(len(files) / elapsed_s, 3) if elapsed_s else 0.0,
                "cpu_percent": round(cpu, 3) if cpu is not None else None,
                "process_cpu_percent": round(process_cpu, 3) if process_cpu is not None else None,
                "peak_rss_mib": rss,
                "workers": worker_count if mode.parallel else 1,
                "batch_size": batch_size if mode.batched else 1,
            }
            tracker.step("%s · %s %d" % (mode.label, "warm-up" if warmup else "round", round_number))
            return record

        for warmup_number in range(1, warmups + 1):
            order = list(SMALL_FILE_MODES)
            random.Random(seed ^ (0xAAAA + warmup_number)).shuffle(order)
            for position, mode in enumerate(order, 1):
                warmup_records.append(execute(mode, warmup_number, position, True))
        for round_number in range(1, trials + 1):
            order = list(SMALL_FILE_MODES)
            random.Random(seed ^ round_number).shuffle(order)
            for position, mode in enumerate(order, 1):
                runs.append(execute(mode, round_number, position, False))
    finally:
        pool.shutdown(wait=True, cancel_futures=True)

    for path, mtime in snapshot.items():
        if os.stat(path).st_mtime_ns != mtime:
            raise RuntimeError("file changed during benchmark: %s" % path)

    keys = [mode.key for mode in SMALL_FILE_MODES]
    summary = {key: _summarize_condition([r for r in runs if r["condition"] == key]) for key in keys}
    for key in keys:
        files_per_second = [r["files_per_second"] for r in runs if r["condition"] == key]
        summary[key].update({
            "label": labels[key],
            "files_per_second_median": statistics.median(files_per_second),
            "first_warmup_ms": next((r["elapsed_ms"] for r in warmup_records
                                     if r["condition"] == key), None),
        })
    paired = _paired_times(runs, keys)
    comparisons = _comparisons(paired, [("technique", "sequential", key) for key in keys[1:]], seed)
    speedups = {c["candidate"]: c["speedup"] for c in comparisons}
    factorial = metrics.factorial_effects(
        speedups.get("sequential_batched"), speedups.get("parallel"), speedups.get("parallel_batched"))
    factorial.update({"factor_a": "batching", "factor_b": "parallel dispatch"})
    sizes = [os.path.getsize(p) for p in files]
    return {
        "schema_version": 3,
        "experiment": "small-file technique isolation (batching × parallel dispatch)",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": host_information(),
        "design": dict(_design(trials, warmups, seed),
                       timing_scope="dispatch + open + read + hash + digest finalization for the "
                                    "whole file set (F1); worker-pool start-up excluded and "
                                    "reported separately",
                       cpu_scope="process tree (parent + worker processes) for parallel modes"),
        "workload": {
            "files": len(files), "excluded_large_files": excluded,
            "total_bytes": total_bytes, "median_file_bytes": statistics.median(sizes),
            "min_file_bytes": min(sizes), "max_file_bytes": max(sizes),
            "workers": worker_count, "batch_size": batch_size,
            "pool_startup_seconds": round(pool_startup_s, 4),
        },
        "conditions": [{"key": m.key, "label": m.label, "parallel": m.parallel,
                        "batched": m.batched} for m in SMALL_FILE_MODES],
        "summary": summary,
        "comparisons": comparisons,
        "factorial": factorial,
        "warnings": _warnings_for(summary, labels)
        + ([] if trials >= MIN_TRIALS else
           ["Fewer than %d trials: treat results as preliminary." % MIN_TRIALS])
        + (["Peak memory of parallel modes includes idle worker processes; compare memory "
            "within the same dispatch level."]),
        "warmup_runs": warmup_records,
        "runs": runs,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────────────────

def write_runs_csv(path: os.PathLike[str] | str, runs: List[Dict[str, Any]]) -> None:
    if not runs:
        return
    columns = list(runs[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(runs)


def summary_rows(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flat per-condition rows (one per file × condition) for spreadsheets."""
    groups = report["files"] if "files" in report else [dict(
        file="small-file workload (%d files)" % report["workload"]["files"],
        size_bytes=report["workload"]["total_bytes"], size_tier="", category="",
        conditions=report["summary"], comparisons=report["comparisons"])]
    rows = []
    for group in groups:
        comparisons = {c["candidate"]: c for c in group["comparisons"] if c["family"] == "technique"}
        references = {c["reference"]: c for c in group["comparisons"] if c["family"] == "reference"}
        for key, item in group["conditions"].items():
            comparison = comparisons.get(key) or references.get(key) or {}
            ci = item["elapsed_median_ci95"] or [None, None]
            speedup_ci = comparison.get("speedup_ci95") or [None, None]
            rows.append({
                "file": group["file"], "size_bytes": group["size_bytes"],
                "size_tier": group["size_tier"], "category": group["category"],
                "condition": key, "label": item["label"],
                "median_ms": item["elapsed_ms"]["median"],
                "median_ci95_low_ms": ci[0], "median_ci95_high_ms": ci[1],
                "iqr_ms": item["elapsed_ms"]["iqr"], "mean_ms": item["elapsed_ms"]["mean"],
                "stdev_ms": item["elapsed_ms"]["stdev"], "cv_percent": item["elapsed_ms"]["cv_percent"],
                "median_throughput_mib_s": item["throughput_mib_s"]["median"],
                "median_cpu_percent": item["cpu_percent_median"],
                "median_peak_rss_mib": item["peak_rss_mib_median"],
                "comparison": ("%s vs %s" % (comparison["candidate"], comparison["reference"])
                               if comparison else ""),
                "speedup": comparison.get("speedup"),
                "speedup_ci95_low": speedup_ci[0], "speedup_ci95_high": speedup_ci[1],
                "percent_time_reduction": comparison.get("percent_time_reduction"),
                "wilcoxon_p": comparison.get("p_value"), "p_holm": comparison.get("p_holm"),
                "cliffs_delta": comparison.get("cliffs_delta"),
                "cliffs_magnitude": comparison.get("cliffs_magnitude"),
                "verdict": comparison.get("verdict", "reference condition"),
            })
    return rows


def write_summary_csv(path: os.PathLike[str] | str, report: Dict[str, Any]) -> None:
    rows = summary_rows(report)
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def export_report(report: Dict[str, Any], folder: os.PathLike[str] | str, stem: str) -> Dict[str, str]:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": str(folder / (stem + ".json")),
        "runs_csv": str(folder / (stem + "_runs.csv")),
        "summary_csv": str(folder / (stem + "_summary.csv")),
    }
    Path(paths["json"]).write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_runs_csv(paths["runs_csv"], report["runs"])
    write_summary_csv(paths["summary_csv"], report)
    return paths


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="experiment", required=True)
    for name in ("large", "small"):
        command = sub.add_parser(name)
        command.add_argument("paths", nargs="+", help="files, or one folder for 'small'")
        command.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
        command.add_argument("--warmups", type=int, default=DEFAULT_WARMUPS)
        command.add_argument("--output", default=".", help="folder for JSON/CSV results")
        if name == "large":
            command.add_argument("--no-references", action="store_true")
            command.add_argument("--exploratory", action="store_true")
        else:
            command.add_argument("--workers", type=int)
            command.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    args = parser.parse_args(argv)
    printer = lambda message, fraction: print("[%5.1f%%] %s" % (fraction * 100, message), file=sys.stderr)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    if args.experiment == "large":
        report = run_large_file_ablation(
            args.paths, trials=args.trials, warmups=args.warmups,
            include_references=not args.no_references,
            include_exploratory=args.exploratory, progress=printer)
        written = export_report(report, args.output, "large_file_ablation_" + stamp)
    else:
        paths = args.paths
        if len(paths) == 1 and os.path.isdir(paths[0]):
            paths = [str(p) for p in sorted(Path(paths[0]).rglob("*")) if p.is_file()]
        report = run_small_file_ablation(
            paths, trials=args.trials, warmups=args.warmups,
            workers=args.workers, batch_size=args.batch_size, progress=printer)
        written = export_report(report, args.output, "small_file_ablation_" + stamp)
    print(json.dumps(written, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
