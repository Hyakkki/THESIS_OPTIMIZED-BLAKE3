#!/usr/bin/env python3
"""Standards-compliant, native BLAKE3 hashing for forensic workloads.

The module deliberately delegates BLAKE3 tree construction and SIMD dispatch to
the official ``blake3`` native extension.  Splitting a file, hashing each part,
and hashing the resulting digests is *not* equivalent to BLAKE3 and is never
done here.

The public API is ``hash_file()``, ``hash_stream()``, and ``hash_many()``.  The
``--server`` mode is a persistent length-prefixed bridge for Autopsy/Jython:

    <ASCII byte count>\n<exactly that many raw bytes>

One compact JSON result line is returned for each request.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import mmap
import os
import platform
import statistics
import sys
import threading
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import blake3 as _blake3_module
except ImportError as exc:  # pragma: no cover - exercised by deployment checks
    raise RuntimeError(
        "The official native 'blake3' package is required. "
        "Install dependencies with: python -m pip install -r requirements.txt"
    ) from exc

try:
    import psutil as _psutil
except ImportError:  # Metrics still work, with a documented RSS fallback.
    _psutil = None


MIB = 1024 * 1024
SMALL_FILE_LIMIT = 16 * MIB
MMAP_MIN_BYTES = 64 * MIB
KNOWN_VECTORS = {
    b"": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    b"abc": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
}


@dataclass(frozen=True)
class HashPolicy:
    chunk_size: int
    max_threads: int
    use_mmap: bool
    strategy: str


@dataclass
class HashResult:
    status: str
    digest: str
    bytes_read: int
    elapsed_ms: float
    throughput_mb_s: float
    cpu_utilization_percent: Optional[float]
    process_cpu_percent: Optional[float]
    peak_rss_mb: Optional[float]
    simd_tier: str
    threads_used: int
    io_strategy: str
    chunk_size: int
    backend: str
    backend_version: str
    algorithm: str
    profile: str
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        # Compatibility names used by the original Autopsy plugin.
        result["message"] = self.error or ""
        result["threads_semantics"] = "maximum native worker threads"
        return result


def physical_cpu_count() -> int:
    """Return physical cores when psutil can distinguish them."""
    if _psutil is not None:
        count = _psutil.cpu_count(logical=False)
        if count:
            return max(1, int(count))
    return max(1, int(os.cpu_count() or 1))


def logical_cpu_count() -> int:
    if _psutil is not None:
        count = _psutil.cpu_count(logical=True)
        if count:
            return max(1, int(count))
    return max(1, int(os.cpu_count() or 1))


def adaptive_chunk_size(size_bytes: int) -> int:
    """Choose a reusable I/O buffer; BLAKE3's internal chunk is still 1 KiB."""
    if size_bytes < 1 * MIB:
        return 64 * 1024
    if size_bytes < SMALL_FILE_LIMIT:
        return 256 * 1024
    if size_bytes < 64 * MIB:
        return 2 * MIB
    if size_bytes < 256 * MIB:
        return 8 * MIB
    if size_bytes < 2 * 1024 * MIB:
        return 8 * MIB
    return 16 * MIB


def select_policy(
    size_bytes: int,
    *,
    threads: Optional[int] = None,
    allow_mmap: bool = True,
    workload: str = "balanced",
) -> HashPolicy:
    """Select an allocation/parallelism policy without changing hash semantics."""
    if size_bytes < 0:
        raise ValueError("size_bytes must be non-negative")
    if workload not in ("balanced", "latency", "throughput"):
        raise ValueError("workload must be balanced, latency, or throughput")

    chunk_size = adaptive_chunk_size(size_bytes)
    if size_bytes < SMALL_FILE_LIMIT:
        # Native thread-pool startup costs more than it saves for small inputs.
        max_threads = 1
        strategy = "buffered-single-thread"
    else:
        requested = physical_cpu_count() if threads is None else int(threads)
        max_threads = max(1, requested)
        if workload == "latency":
            max_threads = min(max_threads, 2)
        strategy = "buffered-native-tree-parallel"

    use_mmap = bool(allow_mmap and size_bytes >= MMAP_MIN_BYTES)
    if use_mmap:
        strategy = "mmap-native-tree-parallel"
    return HashPolicy(chunk_size, max_threads, use_mmap, strategy)


def _cpu_flags() -> set[str]:
    try:
        import cpuinfo  # type: ignore

        return {str(flag).lower() for flag in cpuinfo.get_cpu_info().get("flags", [])}
    except Exception:
        pass

    # Windows exposes the capabilities needed for a conservative display label.
    if os.name == "nt":
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            feature_ids = {"avx": 39, "avx2": 40, "avx512f": 41}
            return {
                name
                for name, feature_id in feature_ids.items()
                if kernel32.IsProcessorFeaturePresent(feature_id)
            }
        except Exception:
            return set()
    return set()


def detected_simd_tier() -> str:
    """Report host capability; the native backend performs runtime dispatch."""
    machine = platform.machine().lower()
    flags = _cpu_flags()
    if "avx512f" in flags:
        return "AVX-512 capable (native runtime dispatch)"
    if "avx2" in flags:
        return "AVX2 capable (native runtime dispatch)"
    if "avx" in flags:
        return "AVX capable (native runtime dispatch)"
    if machine in ("aarch64", "arm64"):
        return "NEON capable (native runtime dispatch)"
    if machine in ("x86_64", "amd64", "i386", "i686"):
        return "x86 SIMD (native runtime dispatch)"
    return "portable/native runtime dispatch"


def _native_hasher(max_threads: int):
    return _blake3_module.blake3(max_threads=max(1, int(max_threads)))


def _windows_peak_rss_bytes() -> Optional[int]:
    if os.name != "nt":
        return None
    try:
        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        process = ctypes.WinDLL("kernel32").GetCurrentProcess()
        ok = ctypes.WinDLL("psapi").GetProcessMemoryInfo(
            process, ctypes.byref(counters), counters.cb
        )
        return int(counters.PeakWorkingSetSize) if ok else None
    except Exception:
        return None


class _MetricSampler:
    """Low-frequency RSS sampling plus high-resolution wall/CPU deltas."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.wall_start_ns = 0
        self.cpu_start = 0.0
        self.peak_rss = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._process = _psutil.Process(os.getpid()) if enabled and _psutil else None

    def __enter__(self) -> "_MetricSampler":
        if self._process is not None:
            try:
                self.peak_rss = int(self._process.memory_info().rss)
                self._thread = threading.Thread(target=self._sample, daemon=True)
                self._thread.start()
            except Exception:
                self._process = None
        self.cpu_start = time.process_time()
        self.wall_start_ns = time.perf_counter_ns()
        return self

    def _sample(self) -> None:
        assert self._process is not None
        while not self._stop.wait(0.010):
            try:
                self.peak_rss = max(self.peak_rss, int(self._process.memory_info().rss))
            except Exception:
                return

    def finish(self) -> Tuple[float, Optional[float], Optional[float], Optional[float]]:
        elapsed_s = max(0.0, (time.perf_counter_ns() - self.wall_start_ns) / 1e9)
        cpu_s = max(0.0, time.process_time() - self.cpu_start)
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=0.1)
        if self._process is not None:
            try:
                self.peak_rss = max(self.peak_rss, int(self._process.memory_info().rss))
            except Exception:
                pass
        # psutil sampling provides a per-operation peak. The Windows API value
        # is process-lifetime peak working set, so use it only as a fallback;
        # mixing it into later runs would make per-profile memory comparisons
        # cumulative and misleading.
        if self._process is None:
            windows_peak = _windows_peak_rss_bytes()
            if windows_peak is not None:
                self.peak_rss = max(self.peak_rss, windows_peak)

        if elapsed_s <= 0:
            return elapsed_s, None, None, self._peak_mb()
        process_percent = 100.0 * cpu_s / elapsed_s
        normalized_percent = process_percent / logical_cpu_count()
        return elapsed_s, normalized_percent, process_percent, self._peak_mb()

    def _peak_mb(self) -> Optional[float]:
        return round(self.peak_rss / MIB, 3) if self.peak_rss else None

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._stop.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=0.1)


def _result(
    *,
    digest: str,
    bytes_read: int,
    policy: HashPolicy,
    metrics: Tuple[float, Optional[float], Optional[float], Optional[float]],
    algorithm: str = "BLAKE3",
    profile: str = "optimized",
    backend: str = "blake3 native extension",
    backend_version: Optional[str] = None,
    simd_tier: Optional[str] = None,
    error: Optional[str] = None,
) -> HashResult:
    elapsed_s, cpu_percent, process_percent, peak_rss_mb = metrics
    throughput = (bytes_read / MIB / elapsed_s) if elapsed_s > 0 else 0.0
    return HashResult(
        status="error" if error else "ok",
        digest=digest,
        bytes_read=bytes_read,
        elapsed_ms=round(elapsed_s * 1000.0, 3),
        throughput_mb_s=round(throughput, 3),
        cpu_utilization_percent=(round(cpu_percent, 3) if cpu_percent is not None else None),
        process_cpu_percent=(
            round(process_percent, 3) if process_percent is not None else None
        ),
        peak_rss_mb=peak_rss_mb,
        simd_tier=simd_tier or detected_simd_tier(),
        threads_used=policy.max_threads,
        io_strategy=policy.strategy,
        chunk_size=policy.chunk_size,
        backend=backend,
        backend_version=(
            backend_version
            if backend_version is not None
            else str(getattr(_blake3_module, "__version__", "unknown"))
        ),
        algorithm=algorithm,
        profile=profile,
        error=error,
    )


def _update_from_stream(
    hasher: Any, stream: BinaryIO, size_bytes: int, chunk_size: int
) -> int:
    buffer = bytearray(max(1, chunk_size))
    view = memoryview(buffer)
    remaining = size_bytes
    total = 0
    while remaining:
        requested = min(remaining, len(buffer))
        if hasattr(stream, "readinto"):
            count = stream.readinto(view[:requested])
        else:  # pragma: no cover - unusual file-like compatibility path
            data = stream.read(requested)
            count = len(data)
            view[:count] = data
        if not count:
            break
        hasher.update(view[:count])
        total += int(count)
        remaining -= int(count)
    view.release()
    return total


def hash_stream(
    stream: BinaryIO,
    size_bytes: int,
    *,
    threads: Optional[int] = None,
    collect_metrics: bool = True,
    workload: str = "balanced",
) -> HashResult:
    """Hash exactly ``size_bytes`` from a binary stream without zero padding."""
    return hash_stream_profile(
        stream,
        size_bytes,
        profile="blake3_optimized",
        threads=threads,
        collect_metrics=collect_metrics,
        workload=workload,
    )


def hash_stream_profile(
    stream: BinaryIO,
    size_bytes: int,
    *,
    profile: str,
    threads: Optional[int] = None,
    collect_metrics: bool = True,
    workload: str = "balanced",
) -> HashResult:
    """Hash a stream using one explicitly named comparison profile.

    ``blake3_baseline`` is the official BLAKE3 package in its default
    single-threaded configuration with a fixed 1 MiB streaming buffer. It
    disables the study's adaptive buffering and multithreaded application
    profile. The public Python API does not expose a switch to disable native
    SIMD dispatch, so that backend property is held constant for baseline and
    optimized BLAKE3.
    """
    profile = str(profile).lower()
    if profile == "blake3_optimized":
        policy = select_policy(
            size_bytes, threads=threads, allow_mmap=False, workload=workload
        )
        hasher_factory = lambda: _native_hasher(policy.max_threads)
        algorithm = "BLAKE3"
        display_profile = "optimized adaptive/native-tree-parallel"
        backend = "blake3 native extension"
        backend_version = str(getattr(_blake3_module, "__version__", "unknown"))
        simd = detected_simd_tier()
    elif profile == "blake3_baseline":
        policy = HashPolicy(
            chunk_size=1 * MIB,
            max_threads=1,
            use_mmap=False,
            strategy="fixed-1MiB-single-thread-baseline",
        )
        hasher_factory = lambda: _native_hasher(1)
        algorithm = "BLAKE3"
        display_profile = "baseline fixed-buffer/single-thread"
        backend = "blake3 native extension"
        backend_version = str(getattr(_blake3_module, "__version__", "unknown"))
        simd = detected_simd_tier() + " (held constant)"
    elif profile in ("md5", "sha1", "sha256"):
        policy = HashPolicy(
            chunk_size=1 * MIB,
            max_threads=1,
            use_mmap=False,
            strategy="fixed-1MiB-independent-reference-pass",
        )
        hasher_factory = lambda: hashlib.new(profile)
        algorithm = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[profile]
        display_profile = "Autopsy reference independent full pass"
        backend = "Python hashlib / operating-system crypto backend"
        backend_version = platform.python_version()
        simd = "backend managed"
    else:
        raise ValueError("unsupported hashing profile: %s" % profile)

    sampler = _MetricSampler(collect_metrics)
    with sampler:
        hasher = hasher_factory()
        try:
            actual = _update_from_stream(hasher, stream, size_bytes, policy.chunk_size)
            if actual != size_bytes:
                metrics = sampler.finish()
                return _result(
                    digest="",
                    bytes_read=actual,
                    policy=policy,
                    metrics=metrics,
                    algorithm=algorithm,
                    profile=display_profile,
                    backend=backend,
                    backend_version=backend_version,
                    simd_tier=simd,
                    error="short read: expected %d bytes, received %d" % (size_bytes, actual),
                )
            digest = hasher.hexdigest()
            metrics = sampler.finish()
            return _result(
                digest=digest,
                bytes_read=actual,
                policy=policy,
                metrics=metrics,
                algorithm=algorithm,
                profile=display_profile,
                backend=backend,
                backend_version=backend_version,
                simd_tier=simd,
            )
        except Exception as exc:
            metrics = sampler.finish()
            return _result(
                digest="",
                bytes_read=locals().get("actual", 0),
                policy=policy,
                metrics=metrics,
                algorithm=algorithm,
                profile=display_profile,
                backend=backend,
                backend_version=backend_version,
                simd_tier=simd,
                error=str(exc),
            )


def hash_file(
    path: os.PathLike[str] | str,
    *,
    threads: Optional[int] = None,
    allow_mmap: bool = True,
    collect_metrics: bool = True,
    expected_size: Optional[int] = None,
    workload: str = "balanced",
) -> HashResult:
    """Hash one stable file, validating size before and after the operation."""
    file_path = Path(path)
    before = file_path.stat()
    size_bytes = int(before.st_size)
    if expected_size is not None and size_bytes != int(expected_size):
        raise ValueError(
            "size mismatch before hashing: expected %d, found %d"
            % (expected_size, size_bytes)
        )
    policy = select_policy(
        size_bytes, threads=threads, allow_mmap=allow_mmap, workload=workload
    )
    sampler = _MetricSampler(collect_metrics)
    actual = 0
    try:
        with sampler:
            hasher = _native_hasher(policy.max_threads)
            with file_path.open("rb", buffering=0) as source:
                if policy.use_mmap and size_bytes:
                    with mmap.mmap(source.fileno(), length=0, access=mmap.ACCESS_READ) as mapped:
                        hasher.update(mapped)
                        actual = len(mapped)
                else:
                    actual = _update_from_stream(
                        hasher, source, size_bytes, policy.chunk_size
                    )
            digest = hasher.hexdigest()
            metrics = sampler.finish()

        after = file_path.stat()
        identity_changed = (
            int(after.st_size) != size_bytes
            or int(after.st_mtime_ns) != int(before.st_mtime_ns)
            or (
                getattr(before, "st_ino", 0)
                and getattr(after, "st_ino", 0)
                and before.st_ino != after.st_ino
            )
        )
        if actual != size_bytes:
            return _result(
                digest="",
                bytes_read=actual,
                policy=policy,
                metrics=metrics,
                error="short read: expected %d bytes, received %d" % (size_bytes, actual),
            )
        if identity_changed:
            return _result(
                digest="",
                bytes_read=actual,
                policy=policy,
                metrics=metrics,
                error="file metadata changed while hashing; digest rejected",
            )
        return _result(
            digest=digest,
            bytes_read=actual,
            policy=policy,
            metrics=metrics,
        )
    except Exception as exc:
        # finish() is safe even if the failure happened inside the mapping/read.
        metrics = sampler.finish() if sampler.wall_start_ns else (0.0, None, None, None)
        return _result(
            digest="",
            bytes_read=actual,
            policy=policy,
            metrics=metrics,
            error=str(exc),
        )


def _hash_file_worker(arguments: Tuple[str, bool, bool]) -> Dict[str, Any]:
    path, allow_mmap, collect_metrics = arguments
    # One native worker per process prevents N processes each spawning N threads.
    return hash_file(
        path,
        threads=1,
        allow_mmap=allow_mmap,
        collect_metrics=collect_metrics,
        workload="throughput",
    ).to_dict()


def hash_many(
    paths: Iterable[os.PathLike[str] | str],
    *,
    workers: Optional[int] = None,
    allow_mmap: bool = True,
    collect_metrics: bool = True,
) -> List[HashResult]:
    """Hash independent files with a process pool, preserving input order.

    A single file uses native tree parallelism.  Multiple small files stay in
    process to avoid dispatch overhead.  Multiple >=16 MiB files use processes,
    each with one native BLAKE3 worker, avoiding nested oversubscription.
    """
    normalized = [str(Path(path)) for path in paths]
    if not normalized:
        return []
    if len(normalized) == 1:
        return [hash_file(normalized[0], allow_mmap=allow_mmap, collect_metrics=collect_metrics)]

    sizes = [os.path.getsize(path) for path in normalized]
    large_indexes = [i for i, size in enumerate(sizes) if size >= SMALL_FILE_LIMIT]
    results: List[Optional[HashResult]] = [None] * len(normalized)
    for index, (path, size) in enumerate(zip(normalized, sizes)):
        if size < SMALL_FILE_LIMIT:
            results[index] = hash_file(
                path, threads=1, allow_mmap=False, collect_metrics=collect_metrics
            )

    if large_indexes:
        max_workers = max(1, min(workers or physical_cpu_count(), len(large_indexes)))
        if max_workers == 1:
            for index in large_indexes:
                results[index] = hash_file(
                    normalized[index],
                    allow_mmap=allow_mmap,
                    collect_metrics=collect_metrics,
                )
        else:
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(
                        _hash_file_worker,
                        (normalized[index], allow_mmap, collect_metrics),
                    ): index
                    for index in large_indexes
                }
                for future in as_completed(futures):
                    index = futures[future]
                    results[index] = HashResult(
                        **{
                            key: value
                            for key, value in future.result().items()
                            if key not in ("message", "threads_semantics")
                        }
                    )
    return [result for result in results if result is not None]


def self_test() -> Dict[str, Any]:
    """Validate published vectors and single/multi-thread output consistency."""
    failures: List[str] = []
    for payload, expected in KNOWN_VECTORS.items():
        actual_single = _blake3_module.blake3(payload, max_threads=1).hexdigest()
        actual_parallel = _blake3_module.blake3(
            payload, max_threads=max(1, physical_cpu_count())
        ).hexdigest()
        if actual_single != expected:
            failures.append("published vector mismatch for %r" % payload)
        if actual_parallel != actual_single:
            failures.append("thread-mode mismatch for %r" % payload)
    return {
        "passed": not failures,
        "status": "ok" if not failures else "error",
        "message": "all published vectors passed" if not failures else "; ".join(failures),
        "backend": "blake3 native extension",
        "backend_version": str(getattr(_blake3_module, "__version__", "unknown")),
        "simd_tier": detected_simd_tier(),
    }


def serve_forever(
    input_stream: Optional[BinaryIO] = None,
    output_stream: Optional[BinaryIO] = None,
    *,
    threads: Optional[int] = None,
) -> int:
    """Run the Autopsy length-prefixed protocol until clean EOF."""
    source = input_stream or sys.stdin.buffer
    sink = output_stream or sys.stdout.buffer
    while True:
        header = source.readline()
        if not header:
            return 0
        try:
            stripped = header.strip()
            if stripped.startswith(b"{"):
                request = json.loads(stripped.decode("utf-8"))
                size_bytes = int(request["size"])
                profile = str(request.get("profile", "blake3_optimized"))
            else:
                size_bytes = int(stripped)
                profile = "blake3_optimized"
            if size_bytes < 0:
                raise ValueError("negative byte count")
            result = hash_stream_profile(
                source,
                size_bytes,
                profile=profile,
                threads=threads,
            )
            payload = result.to_dict()
        except Exception as exc:
            payload = {"status": "error", "message": str(exc), "bytes_read": 0}
        sink.write((json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))
        sink.flush()


def _benchmark(paths: Sequence[str], rounds: int, threads: Optional[int]) -> Dict[str, Any]:
    all_runs: List[Dict[str, Any]] = []
    for path in paths:
        for round_number in range(1, rounds + 1):
            result = hash_file(path, threads=threads)
            record = result.to_dict()
            record.update({"path": str(Path(path).resolve()), "round": round_number})
            all_runs.append(record)
    successful = [run for run in all_runs if run["status"] == "ok"]
    throughputs = [float(run["throughput_mb_s"]) for run in successful]
    return {
        "schema_version": 1,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "self_test": self_test(),
        "runs": all_runs,
        "summary": {
            "successful_runs": len(successful),
            "failed_runs": len(all_runs) - len(successful),
            "median_throughput_mb_s": round(statistics.median(throughputs), 3)
            if throughputs
            else 0.0,
            "mean_throughput_mb_s": round(statistics.fmean(throughputs), 3)
            if throughputs
            else 0.0,
        },
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="files to hash")
    parser.add_argument("--server", action="store_true", help="run Autopsy stream server")
    parser.add_argument("--threads", type=int, help="maximum native worker threads")
    parser.add_argument("--no-mmap", action="store_true", help="disable mmap for local files")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of digest lines")
    parser.add_argument("--self-test", action="store_true", help="run standard-vector validation")
    parser.add_argument("--benchmark", action="store_true", help="record precision metrics")
    parser.add_argument("--rounds", type=int, default=3, help="benchmark repetitions")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.server:
        return serve_forever(threads=args.threads)
    if args.self_test:
        report = self_test()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["passed"] else 2
    if not args.paths:
        raise SystemExit("provide at least one file, --server, or --self-test")
    if args.benchmark:
        print(json.dumps(_benchmark(args.paths, max(1, args.rounds), args.threads), indent=2))
        return 0

    exit_code = 0
    for path in args.paths:
        result = hash_file(
            path,
            threads=args.threads,
            allow_mmap=not args.no_mmap,
        )
        if args.json:
            payload = result.to_dict()
            payload["path"] = str(Path(path).resolve())
            print(json.dumps(payload, sort_keys=True))
        elif result.status == "ok":
            print("%s  %s" % (result.digest, path))
        else:
            print("ERROR  %s: %s" % (path, result.error), file=sys.stderr)
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
