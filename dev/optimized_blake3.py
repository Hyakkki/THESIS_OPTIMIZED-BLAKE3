#!/usr/bin/env python3
"""Standards-compliant, native BLAKE3 hashing for forensic workloads.

The module deliberately delegates BLAKE3 tree construction and SIMD dispatch to
the official ``blake3`` native extension.  Splitting a file, hashing each part,
and hashing the resulting digests is *not* equivalent to BLAKE3 and is never
done here.

The public API is ``hash_file()``, ``hash_stream()``, ``hash_file_config()`` and
``hash_small_files()``; everyday multi-file hashing lives in ``file_hashing.py``.  The
``--server`` mode is a persistent length-prefixed bridge for Autopsy/Jython:

    <ASCII byte count>\n<exactly that many raw bytes>

One compact JSON result line is returned for each request.
"""

from __future__ import annotations

import argparse
import ctypes
import functools
import hashlib
import json
import mmap
import os
import platform
import statistics
import sys
import threading
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Sequence, Tuple

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
# Below this threshold the native thread-pool startup cost outweighs any
# benefit, so small files use a single thread.  Also controls the per-file
# multithreading gate in select_policy() and policy_for_config().
# Override with BLAKE3_SMALL_FILE_LIMIT (bytes) for testing.
SMALL_FILE_LIMIT = int(os.environ.get("BLAKE3_SMALL_FILE_LIMIT", str(32 * MIB)))
MMAP_MIN_BYTES = 64 * MIB
DEFAULT_MEMORY_BENCHMARK_LIMIT = int(
    os.environ.get("BLAKE3_MEMORY_BENCHMARK_LIMIT", str(512 * MIB))
)
KNOWN_VECTORS = {
    b"": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    b"abc": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
}


class OperationCancelled(Exception):
    """Raised when a long-running operation is cancelled by the user."""


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


@dataclass
class MemoryBenchmarkResult:
    """Summary of repeated BLAKE3 runs over an already-resident buffer."""

    digest: str
    bytes_hashed: int
    repeats: int
    warmups: int
    median_elapsed_ms: float
    median_throughput_mib_s: float
    min_throughput_mib_s: float
    max_throughput_mib_s: float
    elapsed_samples_ms: List[float]
    threads_used: int
    timing_scope: str = "hasher creation+memory hash+digest finalization"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FileSnapshot:
    """Stable file bytes prepared outside the benchmark timer."""

    data: bytearray
    file_size: int
    bytes_loaded: int
    complete: bool


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


def recommended_memory_benchmark_limit() -> int:
    """Return a conservative RAM budget for the interactive benchmark."""
    configured = max(1 * MIB, DEFAULT_MEMORY_BENCHMARK_LIMIT)
    if _psutil is None:
        return configured
    try:
        # Leave ample headroom for Windows, Tk, and the native worker pool.
        available = int(_psutil.virtual_memory().available)
        return max(16 * MIB, min(configured, available // 4))
    except Exception:
        return configured


def load_file_snapshot(
    path: os.PathLike[str] | str,
    *,
    max_bytes: Optional[int] = None,
) -> FileSnapshot:
    """Load a stable file or prefix into owned RAM, without timing the I/O.

    When ``max_bytes`` is smaller than the file, the returned data is a prefix
    used only as a content-representative algorithm benchmark.  ``complete``
    distinguishes that case from a snapshot whose digest represents the whole
    file.
    """
    file_path = Path(path)
    before = file_path.stat()
    file_size = int(before.st_size)
    if max_bytes is not None and int(max_bytes) < 0:
        raise ValueError("max_bytes must be non-negative or None")
    bytes_to_load = file_size if max_bytes is None else min(file_size, int(max_bytes))

    data = bytearray(bytes_to_load)
    view = memoryview(data)
    offset = 0
    try:
        with file_path.open("rb", buffering=0) as source:
            while offset < bytes_to_load:
                count = source.readinto(view[offset:])
                if not count:
                    raise EOFError(
                        "short read: expected %d bytes, received %d"
                        % (bytes_to_load, offset)
                    )
                offset += count
    finally:
        view.release()

    after = file_path.stat()
    identity_changed = (
        int(after.st_size) != file_size
        or int(after.st_mtime_ns) != int(before.st_mtime_ns)
        or (
            getattr(before, "st_ino", 0)
            and getattr(after, "st_ino", 0)
            and before.st_ino != after.st_ino
        )
    )
    if identity_changed:
        raise RuntimeError("file changed while the in-memory snapshot was loaded")

    return FileSnapshot(
        data=data,
        file_size=file_size,
        bytes_loaded=bytes_to_load,
        complete=bytes_to_load == file_size,
    )


def benchmark_memory(
    data: bytes | bytearray | memoryview,
    *,
    threads: Optional[int] = None,
    repeats: int = 7,
    warmups: int = 2,
) -> MemoryBenchmarkResult:
    """Measure native BLAKE3 over memory, excluding all file-system work."""
    if repeats < 1:
        raise ValueError("repeats must be at least 1")
    if warmups < 1:
        raise ValueError("warmups must be at least 1")

    max_threads = physical_cpu_count() if threads is None else max(1, int(threads))
    source = memoryview(data)
    if not source.c_contiguous:
        raise ValueError("benchmark input must be C-contiguous")
    source = source.toreadonly()

    expected: Optional[bytes] = None
    for _ in range(warmups):
        current = _blake3_module.blake3(
            source, max_threads=max_threads
        ).digest()
        if expected is None:
            expected = current
        elif current != expected:
            raise RuntimeError("BLAKE3 digest changed during benchmark warm-up")

    elapsed_ns: List[int] = []
    for _ in range(repeats):
        started = time.perf_counter_ns()
        current = _blake3_module.blake3(
            source, max_threads=max_threads
        ).digest()
        duration = max(1, time.perf_counter_ns() - started)
        if current != expected:
            raise RuntimeError("BLAKE3 digest changed between benchmark repetitions")
        elapsed_ns.append(duration)

    elapsed_ms = [duration / 1e6 for duration in elapsed_ns]
    throughput = [
        (len(source) / MIB) / (duration / 1e9) if len(source) else 0.0
        for duration in elapsed_ns
    ]
    return MemoryBenchmarkResult(
        digest=(expected or b"").hex(),
        bytes_hashed=len(source),
        repeats=repeats,
        warmups=warmups,
        median_elapsed_ms=round(statistics.median(elapsed_ms), 3),
        median_throughput_mib_s=round(statistics.median(throughput), 3),
        min_throughput_mib_s=round(min(throughput), 3),
        max_throughput_mib_s=round(max(throughput), 3),
        elapsed_samples_ms=[round(value, 3) for value in elapsed_ms],
        threads_used=max_threads,
    )


def adaptive_chunk_size(size_bytes: int) -> int:
    """Choose a reusable I/O buffer; BLAKE3's internal chunk is still 1 KiB.

    Adjacent tiers differ by at most 4× to avoid pipeline starvation at tier
    boundaries (the previous implementation had an 8× jump from 256 KiB to
    2 MiB at the old 16 MiB threshold).  Larger buffers amortise the
    Python→C call overhead; too-large buffers evict useful data from L3 cache.
    """
    if size_bytes < 512 * 1024:       # < 512 KiB  — tiny files
        return 64 * 1024
    if size_bytes < 4 * MIB:          # 512 KiB – 4 MiB — small
        return 256 * 1024
    if size_bytes < SMALL_FILE_LIMIT:  # 4 MiB – SMALL_FILE_LIMIT — medium
        return 512 * 1024
    if size_bytes < 128 * MIB:        # SMALL_FILE_LIMIT – 128 MiB — large
        return 2 * MIB
    if size_bytes < 1024 * MIB:       # 128 MiB – 1 GiB — very large
        return 8 * MIB
    return 16 * MIB                   # ≥ 1 GiB — bulk


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


@functools.lru_cache(maxsize=1)
def detected_simd_tier() -> str:
    """Report host capability; the native backend performs runtime dispatch.

    Cached: CPU feature detection (py-cpuinfo) takes over a second and the
    answer cannot change while the process runs.
    """
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
    """Low-frequency RSS sampling plus high-resolution wall/CPU deltas.

    With ``include_children=True`` CPU time and RSS cover the whole process
    tree, which is required when work is dispatched to worker processes
    (their CPU time is otherwise invisible to ``time.process_time``).
    """

    def __init__(self, enabled: bool = True, include_children: bool = False) -> None:
        self.enabled = enabled
        self.include_children = bool(include_children and _psutil is not None)
        self.wall_start_ns = 0
        self.cpu_start = 0.0
        self.peak_rss = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._process = _psutil.Process(os.getpid()) if enabled and _psutil else None
        if self.include_children and self._process is None:
            self._process = _psutil.Process(os.getpid())

    def _tree(self) -> List[Any]:
        assert self._process is not None
        members = [self._process]
        if self.include_children:
            try:
                members.extend(self._process.children(recursive=True))
            except Exception:
                pass
        return members

    def _rss_now(self) -> int:
        total = 0
        for member in self._tree():
            try:
                total += int(member.memory_info().rss)
            except Exception:
                pass
        return total

    def _cpu_now(self) -> float:
        if not self.include_children:
            return time.process_time()
        total = 0.0
        for member in self._tree():
            try:
                times = member.cpu_times()
                total += float(times.user) + float(times.system)
            except Exception:
                pass
        return total

    def __enter__(self) -> "_MetricSampler":
        if self._process is not None and (self.enabled or self.include_children):
            try:
                self.peak_rss = self._rss_now()
                if self.enabled:
                    self._thread = threading.Thread(target=self._sample, daemon=True)
                    self._thread.start()
            except Exception:
                self._process = None
                self.include_children = False
        self.cpu_start = self._cpu_now()
        self.wall_start_ns = time.perf_counter_ns()
        return self

    def _sample(self) -> None:
        assert self._process is not None
        while not self._stop.wait(0.010):
            try:
                self.peak_rss = max(self.peak_rss, self._rss_now())
            except Exception:
                return

    def finish(self) -> Tuple[float, Optional[float], Optional[float], Optional[float]]:
        elapsed_s = max(0.0, (time.perf_counter_ns() - self.wall_start_ns) / 1e9)
        cpu_s = max(0.0, self._cpu_now() - self.cpu_start)
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=0.1)
        if self._process is not None:
            try:
                self.peak_rss = max(self.peak_rss, self._rss_now())
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
    size_bytes = int(file_path.stat().st_size)
    if expected_size is not None and size_bytes != int(expected_size):
        raise ValueError(
            "size mismatch before hashing: expected %d, found %d"
            % (expected_size, size_bytes)
        )
    policy = select_policy(
        size_bytes, threads=threads, allow_mmap=allow_mmap, workload=workload
    )
    return _hash_file_with_policy(
        file_path, policy, collect_metrics=collect_metrics,
    )


def _hash_file_with_policy(
    file_path: Path,
    policy: HashPolicy,
    *,
    collect_metrics: bool = True,
    hasher_factory: Optional[Any] = None,
    algorithm: str = "BLAKE3",
    profile: str = "optimized",
    backend: str = "blake3 native extension",
    backend_version: Optional[str] = None,
    simd_tier: Optional[str] = None,
) -> HashResult:
    """Hash ``file_path`` exactly as ``policy`` dictates (no hidden tuning)."""
    before = file_path.stat()
    size_bytes = int(before.st_size)
    sampler = _MetricSampler(collect_metrics)
    actual = 0
    labels = dict(
        algorithm=algorithm, profile=profile, backend=backend,
        backend_version=backend_version, simd_tier=simd_tier,
    )
    try:
        with sampler:
            hasher = (
                hasher_factory() if hasher_factory is not None
                else _native_hasher(policy.max_threads)
            )
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
                **labels,
            )
        if identity_changed:
            return _result(
                digest="",
                bytes_read=actual,
                policy=policy,
                metrics=metrics,
                error="file metadata changed while hashing; digest rejected",
                **labels,
            )
        return _result(
            digest=digest,
            bytes_read=actual,
            policy=policy,
            metrics=metrics,
            **labels,
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
            **labels,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Technique configurations (Panel recommendation #2: isolate each technique)
# ─────────────────────────────────────────────────────────────────────────────

FIXED_BUFFER_BYTES = 1 * MIB


@dataclass(frozen=True)
class TechniqueConfig:
    """One cell of the large-file factorial design.

    ``adaptive_buffer``: size-dependent I/O buffer (adaptive_chunk_size) instead
    of the fixed 1 MiB buffer.
    ``multithreading``: native BLAKE3 tree parallelism on files at or above
    SMALL_FILE_LIMIT (smaller files stay single-threaded by design).
    ``use_mmap``: memory-mapped input. Not one of the study's claimed techniques;
    offered only as an exploratory configuration.
    """

    key: str
    label: str
    adaptive_buffer: bool
    multithreading: bool
    use_mmap: bool = False
    exploratory: bool = False


BLAKE3_CONFIGS: Tuple[TechniqueConfig, ...] = (
    TechniqueConfig("baseline", "Baseline BLAKE3", False, False),
    TechniqueConfig("buffer_only", "Adaptive buffer only", True, False),
    TechniqueConfig("threads_only", "Multithreading only", False, True),
    TechniqueConfig("optimized", "Optimized (buffer + threads)", True, True),
)
EXPLORATORY_CONFIGS: Tuple[TechniqueConfig, ...] = (
    TechniqueConfig("optimized_mmap", "Optimized + mmap (exploratory)", True, True,
                    use_mmap=True, exploratory=True),
)
REFERENCE_ALGORITHMS: Tuple[Tuple[str, str], ...] = (
    ("sha256", "SHA-256 (reference)"),
    ("sha1", "SHA-1 (reference)"),
    ("md5", "MD5 (reference)"),
)
CONFIGS_BY_KEY: Dict[str, TechniqueConfig] = {
    config.key: config for config in BLAKE3_CONFIGS + EXPLORATORY_CONFIGS
}


def policy_for_config(
    config: TechniqueConfig, size_bytes: int, *, threads: Optional[int] = None
) -> HashPolicy:
    """Translate the factor levels of ``config`` into a concrete policy."""
    chunk = adaptive_chunk_size(size_bytes) if config.adaptive_buffer else FIXED_BUFFER_BYTES
    if config.multithreading and size_bytes >= SMALL_FILE_LIMIT:
        max_threads = max(1, int(threads) if threads else physical_cpu_count())
    else:
        max_threads = 1
    use_mmap = bool(config.use_mmap and size_bytes >= MMAP_MIN_BYTES)
    parts = [
        "adaptive-buffer" if config.adaptive_buffer else "fixed-1MiB-buffer",
        "multithread" if max_threads > 1 else "single-thread",
    ]
    if use_mmap:
        parts.append("mmap")
    return HashPolicy(chunk, max_threads, use_mmap, "+".join(parts))


def hash_file_config(
    path: os.PathLike[str] | str,
    config: TechniqueConfig | str,
    *,
    threads: Optional[int] = None,
    collect_metrics: bool = True,
) -> HashResult:
    """Hash a file with one named factorial configuration."""
    if isinstance(config, str):
        config = CONFIGS_BY_KEY[config]
    file_path = Path(path)
    policy = policy_for_config(config, int(file_path.stat().st_size), threads=threads)
    return _hash_file_with_policy(
        file_path, policy, collect_metrics=collect_metrics, profile=config.key,
        simd_tier=detected_simd_tier() + " (held constant)",
    )


def hash_file_reference(
    path: os.PathLike[str] | str, algorithm: str, *, collect_metrics: bool = True
) -> HashResult:
    """MD5/SHA reference pass with the *same* I/O path as Baseline BLAKE3.

    Fixed 1 MiB streaming reads, one thread, Python ``hashlib``. Results describe
    these algorithms *as configured here*, not their best achievable speed
    (Panel recommendation #13).
    """
    algorithm = algorithm.lower()
    if algorithm not in ("md5", "sha1", "sha256"):
        raise ValueError("unsupported reference algorithm: %s" % algorithm)
    policy = HashPolicy(FIXED_BUFFER_BYTES, 1, False, "fixed-1MiB-buffer+single-thread")
    return _hash_file_with_policy(
        Path(path), policy, collect_metrics=collect_metrics,
        hasher_factory=lambda: hashlib.new(algorithm),
        algorithm={"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[algorithm],
        profile=algorithm,
        backend="Python hashlib (OpenSSL)",
        backend_version=platform.python_version(),
        simd_tier="backend managed",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Small-file workloads: batched processing (Panel recommendation #2)
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_BATCH_SIZE = 32


@dataclass(frozen=True)
class SmallFileMode:
    """One cell of the small-file factorial design (parallel × batched)."""

    key: str
    label: str
    parallel: bool
    batched: bool


SMALL_FILE_MODES: Tuple[SmallFileMode, ...] = (
    SmallFileMode("sequential", "Sequential per-file (baseline)", False, False),
    SmallFileMode("sequential_batched", "Batched only (single process)", False, True),
    SmallFileMode("parallel", "Parallel per-file dispatch only", True, False),
    SmallFileMode("parallel_batched", "Optimized (parallel + batched)", True, True),
)
SMALL_MODES_BY_KEY: Dict[str, SmallFileMode] = {mode.key: mode for mode in SMALL_FILE_MODES}


def _hash_small_file(path: str, buffer: Optional[bytearray] = None) -> Tuple[str, int]:
    """Hash one small file single-threaded; returns (hex digest, bytes read).

    Unbatched callers pass ``buffer=None`` so each file pays its own buffer
    allocation and hasher set-up, exactly as an independent per-file job would.
    """
    hasher = _native_hasher(1)
    if buffer is None:
        size = os.path.getsize(path)
        buffer = bytearray(adaptive_chunk_size(size))
    view = memoryview(buffer)
    total = 0
    try:
        with open(path, "rb", buffering=0) as source:
            while True:
                count = source.readinto(view)
                if not count:
                    break
                hasher.update(view[:count])
                total += count
    finally:
        view.release()
    return hasher.hexdigest(), total


def _small_file_worker(path: str) -> Tuple[str, int]:
    return _hash_small_file(path)


def _small_batch_worker(paths: Sequence[str]) -> List[Tuple[str, int]]:
    # One reusable buffer and one task round-trip for the whole batch.
    buffer = bytearray(adaptive_chunk_size(SMALL_FILE_LIMIT - 1))
    return [_hash_small_file(path, buffer) for path in paths]


def _worker_ready() -> int:
    return os.getpid()


def make_worker_pool(workers: Optional[int] = None) -> Tuple[ProcessPoolExecutor, float]:
    """Start and warm a process pool; returns (pool, start-up seconds).

    Start-up is measured once and reported separately so it does not inflate
    each parallel trial.
    """
    count = max(1, int(workers or physical_cpu_count()))
    started = time.perf_counter()
    pool = ProcessPoolExecutor(max_workers=count)
    ready = [pool.submit(_worker_ready) for _ in range(count * 2)]
    for future in ready:
        future.result()
    return pool, time.perf_counter() - started


def chunked(items: Sequence[str], size: int) -> List[List[str]]:
    size = max(1, int(size))
    return [list(items[i:i + size]) for i in range(0, len(items), size)]


def hash_small_files(
    paths: Sequence[str],
    mode: SmallFileMode | str,
    *,
    pool: Optional[ProcessPoolExecutor] = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> List[Tuple[str, int]]:
    """Hash a small-file workload in one factorial mode, preserving order."""
    if isinstance(mode, str):
        mode = SMALL_MODES_BY_KEY[mode]
    items = [str(path) for path in paths]
    if mode.parallel:
        if pool is None:
            raise ValueError("parallel modes require a worker pool")
        if mode.batched:
            results: List[Tuple[str, int]] = []
            for batch_result in pool.map(_small_batch_worker, chunked(items, batch_size)):
                results.extend(batch_result)
            return results
        return list(pool.map(_small_file_worker, items))
    if mode.batched:
        results = []
        for batch in chunked(items, batch_size):
            results.extend(_small_batch_worker(batch))
        return results
    return [_small_file_worker(path) for path in items]


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
    """Run the Autopsy length-prefixed protocol until clean EOF.

    Supports two request formats on the same persistent connection:

    Legacy single-file::

        {"size": N, "profile": "blake3_optimized"}\n  (followed by N raw bytes)
        → one JSON result line

    Batch (N files, zero extra round-trips)::

        {"batch": M, "requests": [{"size": s0, "profile": p0}, ...]}\n
        (followed by s0 + s1 + … raw bytes, back-to-back)
        → M JSON result lines written in one flush
    """
    source = input_stream or sys.stdin.buffer
    sink = output_stream or sys.stdout.buffer
    while True:
        header = source.readline()
        if not header:
            return 0
        try:
            stripped = header.strip()
            if not stripped.startswith(b"{"):
                # Legacy plain-integer protocol.
                _serve_single(source, sink, int(stripped), "blake3_optimized", threads)
                continue
            request = json.loads(stripped.decode("utf-8"))
            if "batch" in request:
                _serve_batch(source, sink, request, threads)
            else:
                size_bytes = int(request["size"])
                profile = str(request.get("profile", "blake3_optimized"))
                _serve_single(source, sink, size_bytes, profile, threads)
        except Exception as exc:
            payload = {"status": "error", "message": str(exc), "bytes_read": 0}
            sink.write((json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))
            sink.flush()


def _serve_single(
    source: BinaryIO,
    sink: BinaryIO,
    size_bytes: int,
    profile: str,
    threads: Optional[int],
) -> None:
    """Handle one legacy request and write one JSON result line."""
    if size_bytes < 0:
        raise ValueError("negative byte count")
    result = hash_stream_profile(source, size_bytes, profile=profile, threads=threads)
    sink.write((json.dumps(result.to_dict(), sort_keys=True) + "\n").encode("utf-8"))
    sink.flush()


def _serve_batch(
    source: BinaryIO,
    sink: BinaryIO,
    batch_header: Dict[str, Any],
    threads: Optional[int],
) -> None:
    """Handle a batch request; write N JSON result lines in one flush.

    The client sends all file bytes back-to-back immediately after the header.
    Results are emitted in the same order so the client correlates by position.
    A single ``sink.flush()`` at the end is the key IPC saving: the sidecar
    does *not* flush after every individual result.
    """
    count = int(batch_header.get("batch", 0))
    requests = list(batch_header.get("requests", []))
    if len(requests) != count:
        raise ValueError(
            "batch count mismatch: header says %d, requests has %d" % (count, len(requests))
        )
    result_lines: List[bytes] = []
    for req in requests:
        size_bytes = int(req.get("size", 0))
        profile = str(req.get("profile", "blake3_optimized"))
        if size_bytes < 0:
            payload: Dict[str, Any] = {
                "status": "error",
                "message": "negative byte count",
                "bytes_read": 0,
            }
        else:
            result = hash_stream_profile(source, size_bytes, profile=profile, threads=threads)
            payload = result.to_dict()
        result_lines.append((json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))
    # Write all N result lines then flush exactly once.
    sink.write(b"".join(result_lines))
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
