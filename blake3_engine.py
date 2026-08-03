import csv
import hashlib
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable, Iterable

import cpuinfo
import psutil
from blake3 import blake3


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASELINE_CHUNK_SIZE = 1024 * 1024  # 1 MiB – fixed for the baseline mode
MMAP_THRESHOLD = 64 * 1024 * 1024  # 64 MiB – switch to mmap above this size
PARALLEL_MIN_SIZE = 1 * 1024 * 1024  # 1 MiB – enable max_threads above this


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class HashMetrics:
    algorithm: str
    mode: str
    digest: str
    elapsed_s: float
    throughput_mb_s: float
    cpu_percent: float
    memory_mb: float
    simd_tier: str = ""
    threads_used: int = 1


@dataclass
class BenchmarkRow:
    file_path: str
    file_type: str
    file_size_bytes: int
    algorithm: str
    mode: str
    run_index: int
    elapsed_s: float
    throughput_mb_s: float
    cpu_percent: float
    memory_mb: float
    digest: str
    simd_tier: str = ""
    threads_used: int = 1


# ---------------------------------------------------------------------------
# Stage 3 – SIMD-aware Execution: Detect CPU capabilities
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def detect_simd_capabilities() -> dict[str, bool | str]:
    """Detect which SIMD instruction sets the CPU supports.

    Returns a dict with boolean flags for each tier and a 'best' key
    indicating the highest tier available for BLAKE3.
    """
    try:
        info = cpuinfo.get_cpu_info()
        flags = set(info.get("flags", []))
    except Exception:
        flags = set()

    has_sse2 = "sse2" in flags
    has_sse41 = "sse4_1" in flags or "sse4.1" in flags
    has_avx2 = "avx2" in flags
    has_avx512 = "avx512f" in flags and "avx512vl" in flags

    # Determine best tier available for BLAKE3
    if has_avx512:
        best = "AVX-512"
    elif has_avx2:
        best = "AVX2"
    elif has_sse41:
        best = "SSE4.1"
    elif has_sse2:
        best = "SSE2"
    else:
        best = "Portable"

    return {
        "sse2": has_sse2,
        "sse41": has_sse41,
        "avx2": has_avx2,
        "avx512": has_avx512,
        "best": best,
    }


def get_simd_summary() -> str:
    """Return a human-readable string describing the active SIMD tier."""
    caps = detect_simd_capabilities()
    supported = [name.upper() for name in ("sse2", "sse41", "avx2", "avx512") if caps.get(name)]
    detail = ", ".join(supported) if supported else "none"
    return f"{caps['best']} ({detail})"


# ---------------------------------------------------------------------------
# File type classification
# ---------------------------------------------------------------------------

def classify_file_type(file_path: str) -> str:
    suffix = Path(file_path).suffix.lower()
    documents = {".pdf", ".doc", ".docx", ".txt", ".xlsx", ".ppt", ".pptx", ".csv"}
    images = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp"}
    audio = {".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a"}
    video = {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm"}
    executables = {".exe", ".dll", ".sys", ".msi", ".bin"}
    disk_images = {".img", ".iso", ".vmdk", ".vhd", ".dd", ".e01", ".aff4"}

    if suffix in documents:
        return "document"
    if suffix in images:
        return "image"
    if suffix in audio:
        return "audio"
    if suffix in video:
        return "video"
    if suffix in executables:
        return "executable"
    if suffix in disk_images:
        return "disk_image"
    return "other"


# ---------------------------------------------------------------------------
# Stage 1 – Adaptive Chunk & Buffer Handling
# ---------------------------------------------------------------------------

def adaptive_chunk_size(file_size: int) -> int:
    """Select chunk size based on file size to balance I/O and memory."""
    if file_size < 4 * 1024 * 1024:
        return 256 * 1024  # 256 KiB for small files
    if file_size < 128 * 1024 * 1024:
        return 1024 * 1024  # 1 MiB for medium files
    return 8 * 1024 * 1024  # 8 MiB for large files


def adaptive_buffer(chunk_size: int) -> tuple[bytearray, memoryview]:
    """Dynamically allocate a reusable buffer matching the adaptive chunk size."""
    buffer = bytearray(chunk_size)
    view = memoryview(buffer)
    return buffer, view


# ---------------------------------------------------------------------------
# Resource monitoring helpers
# ---------------------------------------------------------------------------

def _compute_cpu_percent(start_cpu_total: float, elapsed_s: float) -> float:
    if elapsed_s <= 0:
        return 0.0
    process = psutil.Process(os.getpid())
    cpu_times = process.cpu_times()
    end_cpu_total = cpu_times.user + cpu_times.system
    cpu_delta = max(0.0, end_cpu_total - start_cpu_total)
    cpu_count = max(1, psutil.cpu_count(logical=True) or 1)
    return (cpu_delta / elapsed_s) * (100.0 / cpu_count)


def _memory_mb() -> float:
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)


def _available_threads() -> int:
    """Return the number of logical CPU cores available for multithreading."""
    return max(1, os.cpu_count() or 1)


# ---------------------------------------------------------------------------
# Hashing backends – Baseline (non-optimized)
# ---------------------------------------------------------------------------

def _hash_stream_baseline(file_path: str, chunk_size: int) -> str:
    """Baseline: fixed chunk reads, single-threaded, no buffer reuse."""
    hasher = blake3()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# Hashing backends – Optimized
# ---------------------------------------------------------------------------

def _hash_stream_optimized(file_path: str, chunk_size: int, use_parallel: bool = True) -> str:
    """Optimized stream: adaptive buffer reuse + multithreaded BLAKE3.

    Stages applied:
        1. Adaptive Buffer Handling  – readinto() with pre-allocated buffer
        2. Multithreaded Processing  – blake3(max_threads=AUTO) for large files,
                                       blake3(max_threads=1) for small files
        3. SIMD-aware Execution      – automatic inside blake3
    """
    hasher = blake3(max_threads=blake3.AUTO if use_parallel else 1)
    buffer, view = adaptive_buffer(chunk_size)

    with open(file_path, "rb") as f:
        while True:
            read_len = f.readinto(buffer)
            if read_len == 0:
                break
            hasher.update(view[:read_len])

    return hasher.hexdigest()


def _hash_mmap_optimized(file_path: str) -> str:
    """Optimized mmap: blake3 built-in memory-mapped I/O + multithreading.

    Stages applied:
        1. Adaptive Buffer Handling  – memory-mapped file (OS manages pages)
        2. Multithreaded Processing  – blake3(max_threads=AUTO)
        3. SIMD-aware Execution      – automatic inside blake3
    """
    hasher = blake3(max_threads=blake3.AUTO)
    hasher.update_mmap(file_path)
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# Public hashing functions
# ---------------------------------------------------------------------------

def hash_file_baseline(file_path: str) -> HashMetrics:
    """Baseline BLAKE3: fixed 1 MiB chunks, single-threaded, no optimizations."""
    file_size = os.path.getsize(file_path)
    process = psutil.Process(os.getpid())
    start_cpu = process.cpu_times().user + process.cpu_times().system
    start = time.perf_counter()

    digest = _hash_stream_baseline(file_path, BASELINE_CHUNK_SIZE)

    elapsed = time.perf_counter() - start
    throughput = (file_size / (1024 * 1024)) / elapsed if elapsed > 0 else 0.0
    return HashMetrics(
        algorithm="blake3",
        mode="baseline",
        digest=digest,
        elapsed_s=elapsed,
        throughput_mb_s=throughput,
        cpu_percent=_compute_cpu_percent(start_cpu, elapsed),
        memory_mb=_memory_mb(),
        simd_tier="N/A",
        threads_used=1,
    )


def hash_file_optimized(file_path: str) -> HashMetrics:
    """Optimized BLAKE3 – four-stage pipeline matching the thesis architecture.

    Pipeline:
        Stage 1 – Adaptive Chunk & Buffer Handling
                   Selects chunk size based on file size; chooses mmap for
                   large files or buffer-reuse streaming for smaller files.

        Stage 2 – Multithreaded Parallel Processing
                   blake3 hasher is created with max_threads=AUTO so that
                   BLAKE3's internal Merkle tree hashing distributes work
                   across all available CPU cores.

        Stage 3 – SIMD-aware Execution
                   The blake3 library auto-detects the highest SIMD tier
                   (SSE2 → SSE4.1 → AVX2 → AVX-512) and uses it.
                   We detect and report the active tier.

        Stage 4 – BLAKE3 Hashing Engine
                   Data flows through BLAKE3's binary Merkle tree.
                   Chunks are hashed at leaf nodes and combined
                   hierarchically to produce a single root digest.
    """
    file_size = os.path.getsize(file_path)
    process = psutil.Process(os.getpid())
    start_cpu = process.cpu_times().user + process.cpu_times().system

    # --- Stage 1: Adaptive Chunk & Buffer Handling ---
    chunk_size = adaptive_chunk_size(file_size)
    use_mmap = file_size >= MMAP_THRESHOLD

    # --- Stage 2: Multithreaded Processing ---
    # Only use parallel threads for files large enough to benefit (>= 1 MiB).
    # For small files, threading overhead exceeds the gain and causes CPU
    # contention with the Jython extraction process in server mode.
    use_parallel = file_size >= PARALLEL_MIN_SIZE
    threads = _available_threads() if use_parallel else 1

    # --- Stage 3: SIMD-aware Execution (detection) ---
    simd_caps = detect_simd_capabilities()
    simd_tier = simd_caps["best"]

    # --- Stage 4: BLAKE3 Hashing Engine ---
    start = time.perf_counter()

    if use_mmap:
        # Large files: memory-mapped I/O + multithreaded BLAKE3
        digest = _hash_mmap_optimized(file_path)
    else:
        # Small/medium files: adaptive buffer reuse, threads based on size
        digest = _hash_stream_optimized(file_path, chunk_size, use_parallel)

    elapsed = time.perf_counter() - start
    throughput = (file_size / (1024 * 1024)) / elapsed if elapsed > 0 else 0.0
    return HashMetrics(
        algorithm="blake3",
        mode="optimized",
        digest=digest,
        elapsed_s=elapsed,
        throughput_mb_s=throughput,
        cpu_percent=_compute_cpu_percent(start_cpu, elapsed),
        memory_mb=_memory_mb(),
        simd_tier=simd_tier,
        threads_used=threads,
    )


def hash_file_blake2(file_path: str) -> HashMetrics:
    """BLAKE2b baseline for comparison with the BLAKE algorithm family."""
    file_size = os.path.getsize(file_path)
    chunk_size = adaptive_chunk_size(file_size)
    process = psutil.Process(os.getpid())
    start_cpu = process.cpu_times().user + process.cpu_times().system
    start = time.perf_counter()

    hasher = hashlib.blake2b()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)

    elapsed = time.perf_counter() - start
    throughput = (file_size / (1024 * 1024)) / elapsed if elapsed > 0 else 0.0
    return HashMetrics(
        algorithm="blake2b",
        mode="baseline",
        digest=hasher.hexdigest(),
        elapsed_s=elapsed,
        throughput_mb_s=throughput,
        cpu_percent=_compute_cpu_percent(start_cpu, elapsed),
        memory_mb=_memory_mb(),
        simd_tier="N/A",
        threads_used=1,
    )


# ---------------------------------------------------------------------------
# File gathering
# ---------------------------------------------------------------------------

def gather_files(dataset_path: str, recursive: bool = True) -> list[str]:
    root = Path(dataset_path)
    if root.is_file():
        return [str(root)]

    pattern = "**/*" if recursive else "*"
    files = [str(path) for path in root.glob(pattern) if path.is_file()]
    files.sort()
    return files


# ---------------------------------------------------------------------------
# Benchmarking
# ---------------------------------------------------------------------------

def benchmark_files(
    file_paths: Iterable[str],
    repeats: int = 3,
    include_blake2: bool = False,
) -> list[BenchmarkRow]:
    rows: list[BenchmarkRow] = []

    methods: list[Callable[[str], HashMetrics]] = [hash_file_baseline, hash_file_optimized]
    if include_blake2:
        methods.append(hash_file_blake2)

    for file_path in file_paths:
        file_size = os.path.getsize(file_path)
        file_type = classify_file_type(file_path)

        for method in methods:
            for run_index in range(1, repeats + 1):
                metrics = method(file_path)
                rows.append(
                    BenchmarkRow(
                        file_path=file_path,
                        file_type=file_type,
                        file_size_bytes=file_size,
                        algorithm=metrics.algorithm,
                        mode=metrics.mode,
                        run_index=run_index,
                        elapsed_s=metrics.elapsed_s,
                        throughput_mb_s=metrics.throughput_mb_s,
                        cpu_percent=metrics.cpu_percent,
                        memory_mb=metrics.memory_mb,
                        digest=metrics.digest,
                        simd_tier=metrics.simd_tier,
                        threads_used=metrics.threads_used,
                    )
                )

    return rows


def _benchmark_single_file(args: tuple[str, int, bool]) -> list[BenchmarkRow]:
    """Worker function for ProcessPoolExecutor – hashes a single file."""
    file_path, repeats, include_blake2 = args
    return benchmark_files([file_path], repeats=repeats, include_blake2=include_blake2)


def benchmark_files_parallel(
    file_paths: Iterable[str],
    repeats: int = 3,
    workers: int | None = None,
    include_blake2: bool = False,
) -> list[BenchmarkRow]:
    """Parallel benchmark using ProcessPoolExecutor across files.

    Each file is dispatched to a separate process, avoiding the GIL
    and matching the thesis requirement for ProcessPoolExecutor.
    Within each process, blake3(max_threads=AUTO) provides additional
    chunk-level parallelism.
    """
    file_list = list(file_paths)
    if workers is None:
        workers = min(32, max(2, (os.cpu_count() or 2)))

    rows: list[BenchmarkRow] = []
    task_args = [(path, repeats, include_blake2) for path in file_list]

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_benchmark_single_file, args) for args in task_args]
        for future in as_completed(futures):
            rows.extend(future.result())

    return rows


# ---------------------------------------------------------------------------
# Hash consistency verification (Stage 5)
# ---------------------------------------------------------------------------

def validate_consistency(rows: Iterable[BenchmarkRow]) -> list[str]:
    issues: list[str] = []
    groups: dict[tuple[str, str, str], set[str]] = {}

    for row in rows:
        key = (row.file_path, row.algorithm, row.mode)
        groups.setdefault(key, set()).add(row.digest)

    for (file_path, algorithm, mode), digests in groups.items():
        if len(digests) > 1:
            issues.append(f"Inconsistent digest for {file_path} ({algorithm}/{mode})")

    # Verify baseline vs optimized BLAKE3 parity.
    blake3_pairs: dict[str, dict[str, str]] = {}
    for row in rows:
        if row.algorithm != "blake3":
            continue
        file_map = blake3_pairs.setdefault(row.file_path, {})
        file_map[row.mode] = row.digest

    for file_path, mode_map in blake3_pairs.items():
        if "baseline" in mode_map and "optimized" in mode_map and mode_map["baseline"] != mode_map["optimized"]:
            issues.append(f"Digest mismatch between baseline and optimized BLAKE3 for {file_path}")

    return issues


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

def write_benchmark_csv(rows: Iterable[BenchmarkRow], output_csv: str) -> None:
    fieldnames = [
        "file_path",
        "file_type",
        "file_size_bytes",
        "algorithm",
        "mode",
        "run_index",
        "elapsed_s",
        "throughput_mb_s",
        "cpu_percent",
        "memory_mb",
        "simd_tier",
        "threads_used",
        "digest",
    ]

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "file_path": row.file_path,
                    "file_type": row.file_type,
                    "file_size_bytes": row.file_size_bytes,
                    "algorithm": row.algorithm,
                    "mode": row.mode,
                    "run_index": row.run_index,
                    "elapsed_s": f"{row.elapsed_s:.6f}",
                    "throughput_mb_s": f"{row.throughput_mb_s:.3f}",
                    "cpu_percent": f"{row.cpu_percent:.2f}",
                    "memory_mb": f"{row.memory_mb:.2f}",
                    "simd_tier": row.simd_tier,
                    "threads_used": row.threads_used,
                    "digest": row.digest,
                }
            )


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------

def summarize_rows(rows: Iterable[BenchmarkRow]) -> dict[str, dict[str, float]]:
    totals: dict[str, dict[str, float]] = {}

    for row in rows:
        key = f"{row.algorithm}:{row.mode}"
        entry = totals.setdefault(
            key,
            {
                "runs": 0,
                "elapsed_sum": 0.0,
                "throughput_sum": 0.0,
                "cpu_sum": 0.0,
                "memory_sum": 0.0,
            },
        )
        entry["runs"] += 1
        entry["elapsed_sum"] += row.elapsed_s
        entry["throughput_sum"] += row.throughput_mb_s
        entry["cpu_sum"] += row.cpu_percent
        entry["memory_sum"] += row.memory_mb

    summary: dict[str, dict[str, float]] = {}
    for key, value in totals.items():
        runs = value["runs"]
        summary[key] = {
            "runs": runs,
            "avg_elapsed_s": value["elapsed_sum"] / runs if runs else 0.0,
            "avg_throughput_mb_s": value["throughput_sum"] / runs if runs else 0.0,
            "avg_cpu_percent": value["cpu_sum"] / runs if runs else 0.0,
            "avg_memory_mb": value["memory_sum"] / runs if runs else 0.0,
        }

    return summary
