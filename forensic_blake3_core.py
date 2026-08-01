import csv
import hashlib
import mmap
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

import psutil
from blake3 import blake3


BASELINE_CHUNK_SIZE = 1024 * 1024  # 1 MiB
MMAP_MIN_SIZE = 2 * 1024 * 1024 * 1024  # 2 GiB


@dataclass
class HashMetrics:
    algorithm: str
    mode: str
    digest: str
    elapsed_s: float
    throughput_mb_s: float
    cpu_percent: float
    memory_mb: float


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


def adaptive_chunk_size(file_size: int) -> int:
    if file_size < 4 * 1024 * 1024:
        return 256 * 1024  # 256 KiB
    if file_size < 128 * 1024 * 1024:
        return 1024 * 1024  # 1 MiB
    return 8 * 1024 * 1024  # 8 MiB


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


def _hash_stream(file_path: str, chunk_size: int) -> str:
    hasher = blake3()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _hash_stream_reuse_buffer(file_path: str, chunk_size: int) -> str:
    hasher = blake3()
    buffer = bytearray(chunk_size)
    view = memoryview(buffer)

    with open(file_path, "rb") as f:
        while True:
            read_len = f.readinto(buffer)
            if read_len == 0:
                break
            hasher.update(view[:read_len])

    return hasher.hexdigest()


def _hash_mmap(file_path: str, chunk_size: int) -> str:
    hasher = blake3()
    file_size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            offset = 0
            while offset < file_size:
                hasher.update(mm[offset : offset + chunk_size])
                offset += chunk_size
    return hasher.hexdigest()


def hash_file_baseline(file_path: str) -> HashMetrics:
    file_size = os.path.getsize(file_path)
    process = psutil.Process(os.getpid())
    start_cpu = process.cpu_times().user + process.cpu_times().system
    start = time.perf_counter()

    digest = _hash_stream(file_path, BASELINE_CHUNK_SIZE)

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
    )


def hash_file_optimized(file_path: str) -> HashMetrics:
    file_size = os.path.getsize(file_path)
    chunk_size = adaptive_chunk_size(file_size)
    process = psutil.Process(os.getpid())
    start_cpu = process.cpu_times().user + process.cpu_times().system
    start = time.perf_counter()

    if file_size >= MMAP_MIN_SIZE:
        digest = _hash_mmap(file_path, chunk_size)
    else:
        digest = _hash_stream_reuse_buffer(file_path, chunk_size)

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
    )


def hash_file_blake2(file_path: str) -> HashMetrics:
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
    )


def gather_files(dataset_path: str, recursive: bool = True) -> list[str]:
    root = Path(dataset_path)
    if root.is_file():
        return [str(root)]

    pattern = "**/*" if recursive else "*"
    files = [str(path) for path in root.glob(pattern) if path.is_file()]
    files.sort()
    return files


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
                    )
                )

    return rows


def benchmark_files_parallel(
    file_paths: Iterable[str],
    repeats: int = 3,
    workers: int | None = None,
    include_blake2: bool = False,
) -> list[BenchmarkRow]:
    # Parallel execution is applied across files, not within BLAKE3 internals.
    file_list = list(file_paths)
    if workers is None:
        workers = min(32, max(2, (os.cpu_count() or 2)))

    rows: list[BenchmarkRow] = []

    def run_single(file_path: str) -> list[BenchmarkRow]:
        return benchmark_files([file_path], repeats=repeats, include_blake2=include_blake2)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(run_single, path) for path in file_list]
        for future in as_completed(futures):
            rows.extend(future.result())

    return rows


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
                    "digest": row.digest,
                }
            )


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
