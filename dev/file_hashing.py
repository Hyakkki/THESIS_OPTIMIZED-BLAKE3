#!/usr/bin/env python3
"""Everyday evidence hashing with the optimized engine.

``hash_paths`` hashes any mix of files with the study's optimized techniques:

* files below SMALL_FILE_LIMIT are hashed single-threaded; when there are many
  of them they are batched across worker processes (batched processing);
* larger files use the adaptive buffer and native multithreading
  (configuration ``optimized``).

Hash lists use the ``b3sum`` / ``sha256sum`` text format
(``<hex digest>  <path>``), so they can be checked with those tools as well as
with ``verify_hash_list``.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

import blake3 as _blake3

from optimized_blake3 import (
    DEFAULT_BATCH_SIZE,
    SMALL_FILE_LIMIT,
    OperationCancelled,
    chunked,
    detected_simd_tier,
    hash_file_config,
    hash_file_reference,
    make_worker_pool,
    physical_cpu_count,
)

ProgressCallback = Optional[Callable[[str, float], None]]
# "blake3" is always the Optimized BLAKE3 pass. The extras are optional:
# "blake3_standard" is plain BLAKE3 without the study's optimizations (fixed
# 1 MiB buffer, one thread, one file at a time) — same algorithm, same digest.
EXTRA_ALGORITHMS = ("blake3_standard", "sha256", "sha1", "md5")
ALGORITHM_LABELS = {"blake3": "Optimized BLAKE3", "blake3_standard": "Standard BLAKE3",
                    "sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}
DIGEST_LENGTHS = {"blake3": 64, "blake3_standard": 64, "sha256": 64, "sha1": 40, "md5": 32}
LIST_EXTENSIONS = {".b3": "blake3", ".blake3": "blake3", ".sha256": "sha256",
                   ".sha1": "sha1", ".md5": "md5"}
# Starting worker processes costs roughly half a second, so batched parallel
# hashing is used only when the small-file set is big enough to repay it.
POOL_THRESHOLD = 64
POOL_MIN_FILES = 2000
POOL_MIN_BYTES = 256 * 1024 * 1024


def should_use_pool(count: int, total_bytes: int, threshold: int = POOL_THRESHOLD) -> bool:
    return count >= threshold and (count >= POOL_MIN_FILES or total_bytes >= POOL_MIN_BYTES)


def _small_file_task(path: str) -> Dict[str, Any]:
    """Hash one small file; never raises (errors are returned per file)."""
    try:
        expected = os.path.getsize(path)
        started = time.perf_counter()
        hasher = _blake3.blake3(max_threads=1)
        total = 0
        with open(path, "rb", buffering=0) as source:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                hasher.update(block)
                total += len(block)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if total != expected:
            return {"status": "error", "error": "short read: expected %d bytes, read %d"
                    % (expected, total), "digest": "", "elapsed_ms": elapsed_ms}
        return {"status": "ok", "error": "", "digest": hasher.hexdigest(), "elapsed_ms": elapsed_ms}
    except Exception as exc:
        return {"status": "error", "error": str(exc), "digest": "", "elapsed_ms": None}


def _small_batch_task(paths: Sequence[str]) -> List[Dict[str, Any]]:
    return [_small_file_task(path) for path in paths]


def _check_cancel(cancel: Optional[threading.Event]) -> None:
    if cancel is not None and cancel.is_set():
        raise OperationCancelled("hashing cancelled by user")


def hash_paths(
    paths: Sequence[os.PathLike[str] | str],
    *,
    extra_algorithms: Sequence[str] = (),
    workers: Optional[int] = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    pool_threshold: int = POOL_THRESHOLD,
    force_pool: Optional[bool] = None,
    progress: ProgressCallback = None,
    cancel: Optional[threading.Event] = None,
) -> Dict[str, Any]:
    """Hash files with the optimized engine; results keep the input order.

    ``force_pool`` overrides the automatic choice of batched worker processes
    for small files (None = automatic, see ``should_use_pool``).
    """
    extras = [a for a in extra_algorithms if a in EXTRA_ALGORITHMS]
    items: List[str] = []
    for path in paths:
        resolved = str(Path(path).resolve())
        if resolved not in items:
            items.append(resolved)
    records: Dict[str, Dict[str, Any]] = {}
    for path in items:
        record: Dict[str, Any] = {"path": path, "name": os.path.basename(path),
                                  "folder": os.path.dirname(path), "status": "pending",
                                  "error": "", "blake3": "", "elapsed_ms": None, "method": ""}
        try:
            record["size_bytes"] = os.path.getsize(path)
        except OSError as exc:
            record.update(size_bytes=0, status="error", error=str(exc))
        records[path] = record

    readable = [p for p in items if records[p]["status"] == "pending"]
    total_bytes = sum(records[p]["size_bytes"] for p in readable)
    compare_standard = "blake3_standard" in extras
    passes = 1 + len(extras) + (1 if compare_standard else 0)
    work_total = float(max(1, total_bytes * passes))
    done = [0]

    def advance(byte_count: int, message: str) -> None:
        done[0] += byte_count
        if progress:
            progress(message, min(1.0, done[0] / work_total))

    if compare_standard:
        # Untimed read of every file so the Optimized and Standard passes both
        # start from the same (warm) operating-system cache; otherwise whichever
        # pass runs first pays the disk reads and the comparison is biased.
        for path in readable:
            _check_cancel(cancel)
            try:
                with open(path, "rb", buffering=0) as source:
                    while source.read(8 * 1024 * 1024):
                        pass
            except OSError:
                pass
            advance(records[path]["size_bytes"], "Preparing a fair comparison: reading %s into cache"
                    % records[path]["name"])

    small = [p for p in readable if records[p]["size_bytes"] < SMALL_FILE_LIMIT]
    large = [p for p in readable if records[p]["size_bytes"] >= SMALL_FILE_LIMIT]
    started = time.perf_counter()

    small_bytes = sum(records[p]["size_bytes"] for p in small)
    use_pool = (should_use_pool(len(small), small_bytes, pool_threshold)
                if force_pool is None else (force_pool and len(small) > 1))
    if use_pool:
        pool, _startup = make_worker_pool(workers)
        try:
            batches = chunked(small, batch_size)
            futures = [(batch, pool.submit(_small_batch_task, batch)) for batch in batches]
            for batch, future in futures:
                _check_cancel(cancel)
                for path, result in zip(batch, future.result()):
                    records[path].update(status=result["status"], error=result["error"],
                                         blake3=result["digest"], elapsed_ms=None,
                                         method="batched (%d per task, worker processes)" % batch_size)
                advance(sum(records[p]["size_bytes"] for p in batch),
                        "Hashed batch of %d small files" % len(batch))
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
    else:
        for path in small:
            _check_cancel(cancel)
            result = _small_file_task(path)
            records[path].update(status=result["status"], error=result["error"],
                                 blake3=result["digest"], elapsed_ms=result["elapsed_ms"],
                                 method="single-thread")
            advance(records[path]["size_bytes"], "Hashed %s" % records[path]["name"])

    for path in large:
        _check_cancel(cancel)
        if progress:
            progress("Hashing %s (multithreaded)…" % records[path]["name"], done[0] / work_total)
        result = hash_file_config(path, "optimized", collect_metrics=False)
        records[path].update(
            status=result.status, error=result.error or "", blake3=result.digest,
            elapsed_ms=result.elapsed_ms,
            method="adaptive buffer %d KiB + %d threads" % (result.chunk_size // 1024,
                                                            result.threads_used))
        advance(records[path]["size_bytes"], "Hashed %s" % records[path]["name"])

    blake3_seconds = time.perf_counter() - started
    algorithm_seconds: Dict[str, float] = {"blake3": round(blake3_seconds, 4)}
    for algorithm in extras:
        pass_started = time.perf_counter()
        for path in readable:
            _check_cancel(cancel)
            record = records[path]
            if record["status"] != "ok":
                advance(record["size_bytes"], "Skipped %s" % record["name"])
                continue
            if algorithm == "blake3_standard":
                result = hash_file_config(path, "baseline", collect_metrics=False)
            else:
                result = hash_file_reference(path, algorithm, collect_metrics=False)
            record[algorithm] = result.digest if result.status == "ok" else ""
            record[algorithm + "_ms"] = result.elapsed_ms
            if result.status != "ok":
                record.update(status="error", error="%s: %s" % (ALGORITHM_LABELS[algorithm], result.error))
            elif algorithm == "blake3_standard":
                # Correctness gate: optimization must never change the digest.
                record["matches_standard"] = result.digest == record["blake3"]
                if not record["matches_standard"]:
                    record.update(status="error",
                                  error="Optimized and Standard BLAKE3 digests differ")
            advance(record["size_bytes"], "%s of %s" % (ALGORITHM_LABELS[algorithm], record["name"]))
        algorithm_seconds[algorithm] = round(time.perf_counter() - pass_started, 4)

    files = [records[p] for p in items]
    hashed_bytes = sum(r["size_bytes"] for r in files if r["status"] == "ok")
    standard_comparison = None
    if "blake3_standard" in extras:
        standard_s = algorithm_seconds["blake3_standard"]
        compared = [r for r in files if "matches_standard" in r]
        standard_comparison = {
            "files_compared": len(compared),
            "identical_digests": sum(1 for r in compared if r["matches_standard"]),
            "optimized_seconds": round(blake3_seconds, 4),
            "standard_seconds": standard_s,
            "speedup": round(standard_s / blake3_seconds, 3) if blake3_seconds > 0 else None,
            "note": "Quick comparison: one pass each after an untimed cache warm-up read, so both "
                    "start from the same cache state (files larger than free RAM may not stay "
                    "cached). Use the Technique Benchmark for controlled, repeated measurements.",
        }
    return {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": "Optimized BLAKE3 Forensic Toolkit",
        "small_file_batching": use_pool,
        "engine": {
            "blake3_package_version": str(getattr(_blake3, "__version__", "unknown")),
            "simd_tier": detected_simd_tier(),
            "physical_cpu_count": physical_cpu_count(),
            "platform": platform.platform(),
            "python": sys.version.split()[0],
        },
        "algorithms": ["blake3"] + extras,
        "algorithm_labels": {a: ALGORITHM_LABELS[a] for a in ["blake3"] + extras},
        "algorithm_seconds": algorithm_seconds,
        "standard_comparison": standard_comparison,
        "files": files,
        "file_count": len(files),
        "ok_count": sum(1 for r in files if r["status"] == "ok"),
        "error_count": sum(1 for r in files if r["status"] != "ok"),
        "total_bytes": hashed_bytes,
        "blake3_seconds": round(blake3_seconds, 4),
        "blake3_throughput_mib_s": round(hashed_bytes / (1024 * 1024) / blake3_seconds, 2)
        if blake3_seconds > 0 else 0.0,
        "total_seconds": round(time.perf_counter() - started, 4),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Hash lists (b3sum / sha256sum format)
# ─────────────────────────────────────────────────────────────────────────────

def write_hash_list(report: Dict[str, Any], path: os.PathLike[str] | str,
                    algorithm: str = "blake3") -> int:
    """Write ``<digest>  <absolute path>`` lines; returns the number of entries."""
    lines = [
        "%s  %s" % (record[algorithm], record["path"])
        for record in report["files"]
        if record["status"] == "ok" and record.get(algorithm)
    ]
    Path(path).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return len(lines)


def write_report(report: Dict[str, Any], folder: os.PathLike[str] | str, stem: str) -> Dict[str, str]:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    paths = {"json": str(folder / (stem + ".json")), "csv": str(folder / (stem + ".csv"))}
    Path(paths["json"]).write_text(json.dumps(report, indent=2), encoding="utf-8")
    columns = ["name", "folder", "size_bytes"] + report["algorithms"] + [
        "elapsed_ms", "method"]
    columns += [a + "_ms" for a in report["algorithms"][1:]]
    if "blake3_standard" in report["algorithms"]:
        columns.append("matches_standard")
    columns += ["status", "error", "path"]
    with open(paths["csv"], "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(report["files"])
    for algorithm in report["algorithms"]:
        if algorithm == "blake3_standard":
            continue  # identical digests to the Optimized list; no separate file needed
        extension = ".b3" if algorithm == "blake3" else "." + algorithm
        list_path = folder / (stem + extension)
        write_hash_list(report, list_path, algorithm)
        paths[algorithm] = str(list_path)
    return paths


def parse_hash_list(path: os.PathLike[str] | str) -> Dict[str, Any]:
    list_path = Path(path)
    algorithm = LIST_EXTENSIONS.get(list_path.suffix.lower())
    entries = []
    for number, raw in enumerate(list_path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise ValueError("line %d is not '<digest>  <path>'" % number)
        digest, file_part = parts[0].lower(), parts[1].lstrip("*").strip()
        try:
            int(digest, 16)
        except ValueError:
            raise ValueError("line %d does not start with a hexadecimal digest" % number)
        file_path = Path(file_part)
        if not file_path.is_absolute():
            file_path = list_path.parent / file_path
        entries.append({"line": number, "expected": digest, "path": str(file_path.resolve())})
    if not entries:
        raise ValueError("the hash list is empty")
    if algorithm is None:
        length = len(entries[0]["expected"])
        algorithm = {64: "blake3", 40: "sha1", 32: "md5"}.get(length)
        if algorithm is None:
            raise ValueError("cannot tell the algorithm from a %d-character digest" % length)
    for entry in entries:
        if len(entry["expected"]) != DIGEST_LENGTHS[algorithm]:
            raise ValueError("line %d has the wrong digest length for %s"
                             % (entry["line"], ALGORITHM_LABELS[algorithm]))
    return {"algorithm": algorithm, "entries": entries}


def verify_hash_list(
    path: os.PathLike[str] | str,
    *,
    progress: ProgressCallback = None,
    cancel: Optional[threading.Event] = None,
) -> Dict[str, Any]:
    """Re-hash every file in a hash list and report matches, mismatches, missing files."""
    parsed = parse_hash_list(path)
    algorithm = parsed["algorithm"]
    entries = parsed["entries"]
    present = [e for e in entries if os.path.isfile(e["path"])]
    if algorithm == "blake3":
        report = hash_paths([e["path"] for e in present], progress=progress, cancel=cancel)
        actual = {r["path"]: (r["blake3"], r["status"], r["error"]) for r in report["files"]}
    else:
        actual = {}
        for index, entry in enumerate(present, 1):
            _check_cancel(cancel)
            result = hash_file_reference(entry["path"], algorithm, collect_metrics=False)
            actual[entry["path"]] = (result.digest, result.status, result.error or "")
            if progress:
                progress("Checked %s" % os.path.basename(entry["path"]), index / len(present))
    results = []
    for entry in entries:
        if entry["path"] not in actual:
            outcome, digest, error = "missing", "", "file not found"
        else:
            digest, status, error = actual[entry["path"]]
            outcome = ("match" if digest == entry["expected"] else "mismatch") if status == "ok" else "error"
        results.append(dict(entry, actual=digest, outcome=outcome, error=error))
    counts = {kind: sum(1 for r in results if r["outcome"] == kind)
              for kind in ("match", "mismatch", "missing", "error")}
    return {"list": str(path), "algorithm": algorithm, "results": results, "counts": counts,
            "passed": counts["match"] == len(results)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = argparse.ArgumentParser(description="Hash evidence files with optimized BLAKE3.")
    parser.add_argument("paths", nargs="*", help="files or folders")
    parser.add_argument("--extra", nargs="*", default=[], choices=EXTRA_ALGORITHMS,
                        help="optional extra passes; Optimized BLAKE3 always runs")
    parser.add_argument("--save", help="folder for the report and hash lists")
    parser.add_argument("--check", help="verify files against a saved hash list")
    args = parser.parse_args(argv)
    if args.check:
        result = verify_hash_list(args.check)
        for item in result["results"]:
            print("%-8s %s" % (item["outcome"].upper(), item["path"]))
        print(json.dumps(result["counts"]))
        return 0 if result["passed"] else 1
    files: List[str] = []
    for path in args.paths:
        if os.path.isdir(path):
            files.extend(str(p) for p in sorted(Path(path).rglob("*")) if p.is_file())
        else:
            files.append(path)
    if not files:
        parser.error("give files/folders to hash, or --check LIST")
    report = hash_paths(files, extra_algorithms=args.extra)
    for record in report["files"]:
        if record["status"] == "ok":
            print("%s  %s" % (record["blake3"], record["path"]))
        else:
            print("ERROR  %s: %s" % (record["path"], record["error"]), file=sys.stderr)
    if args.save:
        print(json.dumps(write_report(report, args.save, "hashes_" + time.strftime("%Y%m%d_%H%M%S")),
                         indent=2))
    return 0 if report["error_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
