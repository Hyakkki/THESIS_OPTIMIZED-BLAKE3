#!/usr/bin/env python3
"""Standards-compliant, native BLAKE3 hashing for forensic workloads.

The module deliberately delegates BLAKE3 tree construction and SIMD dispatch to
the official ``blake3`` native extension.  Splitting a file, hashing each part,
and hashing the resulting digests is *not* equivalent to BLAKE3 and is never
done here.

The public API is ``hash_file()``, ``hash_stream()``, ``hash_file_config()``,
``hash_small_files()`` and, for everyday multi-file hashing with hash lists,
``hash_paths()`` / ``write_hash_report()`` / ``verify_hash_list()``.  The
``--server`` mode is a persistent length-prefixed bridge for Autopsy/Jython:

    <ASCII byte count>\n<exactly that many raw bytes>

One compact JSON result line is returned for each request.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import functools
import hashlib
import json
import mmap
import os
import platform
import queue
import statistics
import sys
import threading
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, List, Optional, Sequence, Tuple

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

# ── Names: edit here to rename the tool or update the thesis title ─────────
TOOL_SHORT_NAME = "Optimized BLAKE3"
TOOL_SUBTITLE = "Forensic Toolkit"
TOOL_NAME = TOOL_SHORT_NAME + " " + TOOL_SUBTITLE
THESIS_TITLE = ("Performance Optimization for BLAKE3 for Multi-Format File Hashing "
                "in Digital Forensic Investigations")
# Below this threshold the native thread-pool startup cost outweighs any
# benefit, so small files use a single thread.  Also controls the per-file
# multithreading gate in select_policy() and policy_for_config().
# Override with BLAKE3_SMALL_FILE_LIMIT (bytes) for testing.
SMALL_FILE_LIMIT = int(os.environ.get("BLAKE3_SMALL_FILE_LIMIT", str(32 * MIB)))
# Files at or above this size are hashed from a memory map (zero-copy, whole
# file in one update) so BLAKE3's tree parallelism can use every core.
MMAP_MIN_BYTES = SMALL_FILE_LIMIT
# Read size for the background-read fallback (best measured value).
PIPELINE_CHUNK_BYTES = 4 * MIB
# Large files are mapped in windows of this size: full multithreaded speed,
# memory use bounded (~ one window) for files of any size, and a progress /
# cancel point after every window. Must be a multiple of the OS allocation
# granularity (64 KiB on Windows).
MMAP_WINDOW_BYTES = 256 * MIB
# auto: choose by storage type; mmap / stream: force one I/O path (testing).
IO_MODE = os.environ.get("BLAKE3_IO_MODE", "auto").strip().lower()
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
    # Read the next chunk on a background thread while the current one is hashed
    # (used when a file cannot be memory-mapped).
    pipelined: bool = False


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
    """Choose the streaming read buffer; BLAKE3's internal chunk is still 1 KiB.

    Small buffers suit small files (single-threaded hashing is fastest when the
    buffer stays in CPU cache). Large files are memory-mapped instead (see
    MMAP_MIN_BYTES), so their effective buffer is the whole file.
    """
    if size_bytes < 512 * 1024:       # < 512 KiB  — tiny files
        return 64 * 1024
    if size_bytes < 4 * MIB:          # 512 KiB – 4 MiB — small
        return 256 * 1024
    if size_bytes < SMALL_FILE_LIMIT:  # 4 MiB – SMALL_FILE_LIMIT — medium
        return 512 * 1024
    # ≥ SMALL_FILE_LIMIT — large: the file is normally memory-mapped (the buffer is
    # the whole file); this size applies to streamed input and the background-read
    # fallback, where 4 MiB measured fastest.
    return PIPELINE_CHUNK_BYTES


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
        requested = logical_cpu_count() if threads is None else int(threads)
        max_threads = max(1, requested)
        if workload == "latency":
            max_threads = min(max_threads, 2)
        strategy = "buffered-native-tree-parallel"

    use_mmap = bool(allow_mmap and size_bytes >= MMAP_MIN_BYTES)
    if use_mmap:
        strategy = "mmap-native-tree-parallel"
    return HashPolicy(chunk_size, max_threads, use_mmap, strategy,
                      pipelined=size_bytes >= MMAP_MIN_BYTES)


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
def cpu_model() -> str:
    """Human-readable processor name (for reports and the app's system summary)."""
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                return " ".join(str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).split())
        except Exception:
            pass
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as info:
            for line in info:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or platform.machine() or "unknown processor"


def total_memory_bytes() -> Optional[int]:
    if _psutil is None:
        return None
    try:
        return int(_psutil.virtual_memory().total)
    except Exception:
        return None


def available_memory_bytes() -> Optional[int]:
    if _psutil is None:
        return None
    try:
        return int(_psutil.virtual_memory().available)
    except Exception:
        return None


def system_summary() -> Dict[str, Any]:
    """The hardware facts the adaptive policy uses, for display and reports."""
    memory = total_memory_bytes()
    return {
        "cpu_model": cpu_model(),
        "physical_cores": physical_cpu_count(),
        "logical_threads": logical_cpu_count(),
        "memory_gib": round(memory / 1024 ** 3, 1) if memory else None,
        "simd_tier": detected_simd_tier(),
        "blake3_package_version": str(getattr(_blake3_module, "__version__", "unknown")),
    }


@functools.lru_cache(maxsize=64)
def _volume_profile(root: str) -> Dict[str, Any]:
    """Drive facts for one volume root (cached; ~2 ms per new volume)."""
    profile: Dict[str, Any] = {"root": root, "drive_type": "unknown", "seek_penalty": None}
    if os.name == "nt":
        try:
            from ctypes import wintypes
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            profile["drive_type"] = {2: "removable", 3: "fixed", 4: "network", 5: "optical",
                                     6: "ramdisk"}.get(kernel32.GetDriveTypeW(root), "unknown")
            if profile["drive_type"] in ("fixed", "removable"):
                name = ctypes.create_unicode_buffer(260)
                if kernel32.GetVolumeNameForVolumeMountPointW(root, name, 260):
                    device = name.value.rstrip("\\").replace("\\\\?\\", "\\\\.\\")
                else:
                    device = "\\\\.\\" + root.rstrip("\\")
                create = kernel32.CreateFileW
                create.restype = wintypes.HANDLE
                handle = create(device, 0, 3, None, 3, 0, None)
                if handle not in (None, wintypes.HANDLE(-1).value):
                    class _Query(ctypes.Structure):
                        _fields_ = [("PropertyId", ctypes.c_int), ("QueryType", ctypes.c_int),
                                    ("AdditionalParameters", ctypes.c_ubyte * 1)]

                    class _SeekPenalty(ctypes.Structure):
                        _fields_ = [("Version", wintypes.DWORD), ("Size", wintypes.DWORD),
                                    ("IncursSeekPenalty", ctypes.c_ubyte)]

                    query, answer, returned = _Query(7, 0), _SeekPenalty(), wintypes.DWORD()
                    # IOCTL_STORAGE_QUERY_PROPERTY / StorageDeviceSeekPenaltyProperty
                    if kernel32.DeviceIoControl(handle, 0x2D1400, ctypes.byref(query),
                                                ctypes.sizeof(query), ctypes.byref(answer),
                                                ctypes.sizeof(answer), ctypes.byref(returned), None):
                        profile["seek_penalty"] = bool(answer.IncursSeekPenalty)
                    kernel32.CloseHandle(handle)
        except Exception:
            pass
    return profile


def storage_profile(path: os.PathLike[str] | str) -> Dict[str, Any]:
    """Classify the storage holding ``path``: ssd, hdd, network or unknown.

    Spinning disks (seek penalty) and network shares favour sequential reads;
    SSD/NVMe storage favours parallel memory-mapped reads.
    """
    absolute = os.path.abspath(str(path))
    root = os.path.splitdrive(absolute)[0] + os.sep
    if os.name == "nt":
        try:
            buffer = ctypes.create_unicode_buffer(260)
            if ctypes.WinDLL("kernel32").GetVolumePathNameW(absolute, buffer, 260):
                root = buffer.value
        except Exception:
            pass
    profile = dict(_volume_profile(root))
    if absolute.startswith("\\\\") or profile["drive_type"] == "network":
        kind = "network"
    elif profile["seek_penalty"] is True:
        kind = "hdd"
    elif profile["seek_penalty"] is False:
        kind = "ssd"
    else:
        kind = "unknown"
    profile["kind"] = kind
    profile["sequential_preferred"] = kind in ("hdd", "network")
    return profile


def prefers_sequential_io(path: os.PathLike[str] | str) -> bool:
    """True when large files on ``path`` should be streamed rather than mapped."""
    if IO_MODE == "stream":
        return True
    if IO_MODE == "mmap":
        return False
    try:
        return bool(storage_profile(path)["sequential_preferred"])
    except Exception:
        return False


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


def _pipelined_update(
    hasher: Any, stream: BinaryIO, size_bytes: int, chunk_size: int, depth: int = 2,
    progress: ByteProgress = None, cancel: Optional[threading.Event] = None,
) -> int:
    """Hash ``size_bytes`` from ``stream`` while a background thread reads ahead.

    Reading and hashing overlap: while BLAKE3 hashes one buffer (releasing the
    GIL), the reader thread fills the next. Returns the number of bytes hashed
    (smaller than ``size_bytes`` on a short read, which callers reject).
    """
    free: "queue.Queue[Optional[bytearray]]" = queue.Queue()
    full: "queue.Queue[Tuple[Any, int]]" = queue.Queue()
    for _ in range(depth + 1):
        free.put(bytearray(max(1, chunk_size)))
    stop = threading.Event()

    def reader() -> None:
        remaining = size_bytes
        try:
            while remaining > 0 and not stop.is_set():
                buffer = free.get()
                if buffer is None:
                    return
                count = stream.readinto(memoryview(buffer)[:min(len(buffer), remaining)])
                if not count:
                    full.put((buffer, 0))
                    return
                remaining -= count
                full.put((buffer, count))
            full.put((None, 0))
        except BaseException as exc:  # handed to the hashing thread
            full.put((exc, 0))

    worker = threading.Thread(target=reader, daemon=True)
    worker.start()
    total = 0
    try:
        while True:
            item, count = full.get()
            if isinstance(item, BaseException):
                raise item
            if item is None or not count:
                break
            _check_cancelled(cancel)
            hasher.update(memoryview(item)[:count])
            total += count
            free.put(item)
            if progress is not None:
                progress(total)
    finally:
        stop.set()
        free.put(None)
        worker.join(timeout=5)
    return total


ByteProgress = Optional[Callable[[int], None]]


def _check_cancelled(cancel: Optional[threading.Event]) -> None:
    if cancel is not None and cancel.is_set():
        raise OperationCancelled("hashing cancelled by user")


class _MappingUnavailable(Exception):
    """The file could not be memory-mapped at all (nothing has been hashed yet)."""


def _mapped_update(
    hasher: Any, source: BinaryIO, size_bytes: int, window: int = MMAP_WINDOW_BYTES,
    progress: ByteProgress = None, cancel: Optional[threading.Event] = None,
) -> int:
    """Hash a file through successive memory-mapped windows.

    Each window is hashed with BLAKE3's multithreaded update and then unmapped,
    so memory stays bounded for files of any size (hundreds of GB to TB).
    """
    granularity = getattr(mmap, "ALLOCATIONGRANULARITY", 65536)
    window = max(granularity, (window // granularity) * granularity)
    offset = 0
    while offset < size_bytes:
        _check_cancelled(cancel)
        length = min(window, size_bytes - offset)
        try:
            mapped = mmap.mmap(source.fileno(), length, access=mmap.ACCESS_READ, offset=offset)
        except (OSError, ValueError) as exc:
            if offset == 0:
                raise _MappingUnavailable(str(exc))
            raise
        with mapped:
            hasher.update(mapped)
        offset += length
        if progress is not None:
            progress(offset)
    return offset


def _update_from_stream(
    hasher: Any, stream: BinaryIO, size_bytes: int, chunk_size: int,
    progress: ByteProgress = None, cancel: Optional[threading.Event] = None,
) -> int:
    buffer = bytearray(max(1, chunk_size))
    view = memoryview(buffer)
    remaining = size_bytes
    total = 0
    while remaining:
        _check_cancelled(cancel)
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
        if progress is not None:
            progress(total)
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
    progress: ByteProgress = None,
    cancel: Optional[threading.Event] = None,
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
    if policy.use_mmap and prefers_sequential_io(file_path):
        policy = replace(policy, use_mmap=False,
                         strategy="background-read-native-tree-parallel (sequential storage)")
    return _hash_file_with_policy(
        file_path, policy, collect_metrics=collect_metrics, progress=progress, cancel=cancel,
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
    progress: ByteProgress = None,
    cancel: Optional[threading.Event] = None,
) -> HashResult:
    """Hash ``file_path`` exactly as ``policy`` dictates (no hidden tuning).

    ``progress(bytes_done)`` is called as the file is read; setting ``cancel``
    raises OperationCancelled at the next window/chunk boundary.
    """
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
                mapped_ok = False
                if policy.use_mmap and size_bytes:
                    try:
                        actual = _mapped_update(hasher, source, size_bytes,
                                                progress=progress, cancel=cancel)
                        mapped_ok = True
                    except _MappingUnavailable as exc:
                        # e.g. some network shares or locked files: fall back to
                        # background-read streaming, which gives the same digest.
                        policy = replace(
                            policy, use_mmap=False, pipelined=True,
                            strategy=policy.strategy.replace("mmap windows", "background-read")
                            + " (mmap unavailable: %s)" % exc)
                if mapped_ok:
                    pass
                elif policy.pipelined and size_bytes:
                    actual = _pipelined_update(hasher, source, size_bytes, policy.chunk_size,
                                               progress=progress, cancel=cancel)
                else:
                    actual = _update_from_stream(
                        hasher, source, size_bytes, policy.chunk_size,
                        progress=progress, cancel=cancel,
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
    except OperationCancelled:
        raise
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
# Technique configurations (each technique can be enabled independently)
# ─────────────────────────────────────────────────────────────────────────────

FIXED_BUFFER_BYTES = 1 * MIB


@dataclass(frozen=True)
class TechniqueConfig:
    """One cell of the large-file factorial design.

    ``adaptive_buffer``: the input buffer adapts to file size instead of a fixed
    1 MiB: small buffers for small files, and for files at or above
    MMAP_MIN_BYTES the whole file, provided zero-copy by memory mapping (with a
    background-read fallback when a file cannot be mapped).
    ``multithreading``: native BLAKE3 tree parallelism on all logical cores for
    files at or above SMALL_FILE_LIMIT (smaller files stay single-threaded).
    """

    key: str
    label: str
    adaptive_buffer: bool
    multithreading: bool


BLAKE3_CONFIGS: Tuple[TechniqueConfig, ...] = (
    TechniqueConfig("baseline", "Baseline BLAKE3", False, False),
    TechniqueConfig("buffer_only", "Adaptive buffer only", True, False),
    TechniqueConfig("threads_only", "Multithreading only", False, True),
    TechniqueConfig("optimized", "Optimized (buffer + threads)", True, True),
)
REFERENCE_ALGORITHMS: Tuple[Tuple[str, str], ...] = (
    ("sha256", "SHA-256 (reference)"),
    ("sha1", "SHA-1 (reference)"),
    ("md5", "MD5 (reference)"),
)
CONFIGS_BY_KEY: Dict[str, TechniqueConfig] = {
    config.key: config for config in BLAKE3_CONFIGS
}


def policy_for_config(
    config: TechniqueConfig, size_bytes: int, *, threads: Optional[int] = None,
    sequential_storage: bool = False,
) -> HashPolicy:
    """Translate the factor levels of ``config`` into a concrete policy."""
    chunk = adaptive_chunk_size(size_bytes) if config.adaptive_buffer else FIXED_BUFFER_BYTES
    if config.multithreading and size_bytes >= SMALL_FILE_LIMIT:
        max_threads = max(1, int(threads) if threads else logical_cpu_count())
    else:
        max_threads = 1
    large = config.adaptive_buffer and size_bytes >= MMAP_MIN_BYTES
    use_mmap = large and not sequential_storage
    if not config.adaptive_buffer:
        buffer_part = "fixed-1MiB-buffer"
    elif not large:
        buffer_part = "adaptive-buffer"
    elif use_mmap:
        buffer_part = "adaptive-buffer(mmap windows)"
    else:
        buffer_part = "adaptive-buffer(background-read, sequential storage)"
    parts = [buffer_part, "multithread" if max_threads > 1 else "single-thread"]
    return HashPolicy(chunk, max_threads, use_mmap, "+".join(parts), pipelined=large)


def hash_file_config(
    path: os.PathLike[str] | str,
    config: TechniqueConfig | str,
    *,
    threads: Optional[int] = None,
    collect_metrics: bool = True,
    allow_mmap: bool = True,
    progress: ByteProgress = None,
    cancel: Optional[threading.Event] = None,
) -> HashResult:
    """Hash a file with one named factorial configuration.

    Large files are memory-mapped on SSD/NVMe storage and streamed with
    background reads on spinning disks or network shares (see storage_profile).
    ``allow_mmap=False`` forces the background-read path (used to verify it).
    """
    if isinstance(config, str):
        config = CONFIGS_BY_KEY[config]
    file_path = Path(path)
    size_bytes = int(file_path.stat().st_size)
    sequential = (not allow_mmap) or (
        config.adaptive_buffer and size_bytes >= MMAP_MIN_BYTES and prefers_sequential_io(file_path))
    policy = policy_for_config(config, size_bytes, threads=threads, sequential_storage=sequential)
    return _hash_file_with_policy(
        file_path, policy, collect_metrics=collect_metrics, profile=config.key,
        simd_tier=detected_simd_tier() + " (held constant)", progress=progress, cancel=cancel,
    )


def hash_file_reference(
    path: os.PathLike[str] | str, algorithm: str, *, collect_metrics: bool = True,
    progress: ByteProgress = None, cancel: Optional[threading.Event] = None,
) -> HashResult:
    """MD5/SHA reference pass with the *same* I/O path as Baseline BLAKE3.

    Fixed 1 MiB streaming reads, one thread, Python ``hashlib``. Results describe
    these algorithms *as configured here*, not their best achievable speed
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
        progress=progress, cancel=cancel,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Small-file workloads: batched processing
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


# ─────────────────────────────────────────────────────────────────────────────
# Everyday hashing: many files, hash lists (b3sum format), re-checking
# ─────────────────────────────────────────────────────────────────────────────
# Optimized BLAKE3 is always the main pass; Standard BLAKE3 / SHA / MD5 are
# optional extras. Hash lists use ``<hex digest>  <path>`` lines.

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


# With an already-running ("warm") pool there is no start-up cost, so batching
# pays off from far fewer files.
WARM_POOL_MIN_FILES = 100


def should_use_pool(count: int, total_bytes: int, threshold: int = POOL_THRESHOLD,
                    warm: bool = False) -> bool:
    if warm:
        return count >= WARM_POOL_MIN_FILES
    return count >= threshold and (count >= POOL_MIN_FILES or total_bytes >= POOL_MIN_BYTES)


def _small_file_task(path: str) -> Dict[str, Any]:
    """Hash one small file; never raises (errors are returned per file)."""
    try:
        expected = os.path.getsize(path)
        started = time.perf_counter()
        hasher = _blake3_module.blake3(max_threads=1)
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


def _format_rate(bytes_per_second: float) -> str:
    value = float(bytes_per_second)
    for unit in ("B/s", "KiB/s", "MiB/s", "GiB/s"):
        if value < 1024 or unit == "GiB/s":
            return "%.1f %s" % (value, unit)
        value /= 1024
    return "%.1f GiB/s" % value


def _format_eta(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "%d s" % seconds
    if seconds < 3600:
        return "%d min %02d s" % divmod(seconds, 60)
    hours, rest = divmod(seconds, 3600)
    return "%d h %02d min" % (hours, rest // 60)


class _JobProgress:
    """Byte-based progress for a hashing job: throttled, with rate and time left."""

    def __init__(self, callback: ProgressCallback, total_bytes: float, interval: float = 0.1):
        self.callback = callback
        self.total = max(1.0, float(total_bytes))
        self.done = 0.0
        self.interval = interval
        self.started = time.perf_counter()
        self._last_emit = 0.0
        self._message = ""

    def set(self, done: float, message: Optional[str] = None, force: bool = False) -> None:
        self.done = min(self.total, max(self.done, float(done)))
        if message is not None:
            self._message = message
        if self.callback is None:
            return
        now = time.perf_counter()
        if not force and now - self._last_emit < self.interval:
            return
        self._last_emit = now
        elapsed = now - self.started
        text = self._message
        if elapsed > 1.0 and self.done > 0:
            rate = self.done / elapsed
            text += "  ·  %s" % _format_rate(rate)
            remaining = (self.total - self.done) / rate if rate > 0 else 0
            if remaining >= 1:
                text += "  ·  about %s left" % _format_eta(remaining)
        self.callback(text, self.done / self.total)


def hash_paths(
    paths: Sequence[os.PathLike[str] | str],
    *,
    extra_algorithms: Sequence[str] = (),
    workers: Optional[int] = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    pool_threshold: int = POOL_THRESHOLD,
    force_pool: Optional[bool] = None,
    pool: Optional[ProcessPoolExecutor] = None,
    progress: ProgressCallback = None,
    cancel: Optional[threading.Event] = None,
) -> Dict[str, Any]:
    """Hash files with the optimized engine; results keep the input order.

    ``pool``: an already-running worker pool (kept warm by the app) to reuse for
    small-file batching; it is never shut down here. Without one, a temporary
    pool is started only for very large small-file sets.
    ``force_pool`` overrides the automatic choice (None = automatic, see
    ``should_use_pool``).
    """
    extras = [a for a in extra_algorithms if a in EXTRA_ALGORITHMS]
    items: List[str] = []
    seen: set = set()
    for path in paths:
        resolved = str(Path(path).resolve())
        if resolved not in seen:  # set lookup: fast for folders with 100k+ files
            seen.add(resolved)
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
    # Warming the cache only helps if the data fits in memory; for data larger
    # than available RAM (e.g. a 1 TB image) both passes read from storage anyway.
    available = available_memory_bytes()
    warm_cache = compare_standard and (available is None or total_bytes <= available // 2)
    passes = 1 + len(extras) + (1 if warm_cache else 0)
    job = _JobProgress(progress, total_bytes * passes)
    done = [0]

    def advance(byte_count: int, message: str) -> None:
        done[0] += byte_count
        job.set(done[0], message, force=True)

    def within(name: str, label: str):
        """Progress callback for bytes read inside one file."""
        base = done[0]
        return lambda current: job.set(base + current, "%s %s" % (label, name))

    if warm_cache:
        # Untimed read of every file so the Optimized and Standard passes both
        # start from the same (warm) operating-system cache; otherwise whichever
        # pass runs first pays the disk reads and the comparison is biased.
        for path in readable:
            _check_cancel(cancel)
            try:
                with open(path, "rb", buffering=0) as source:
                    while source.read(8 * 1024 * 1024):
                        _check_cancel(cancel)
            except OSError:
                pass
            advance(records[path]["size_bytes"], "Preparing a fair comparison: reading %s into cache"
                    % records[path]["name"])

    small = [p for p in readable if records[p]["size_bytes"] < SMALL_FILE_LIMIT]
    large = [p for p in readable if records[p]["size_bytes"] >= SMALL_FILE_LIMIT]
    started = time.perf_counter()

    small_bytes = sum(records[p]["size_bytes"] for p in small)
    warm = pool is not None
    use_pool = (should_use_pool(len(small), small_bytes, pool_threshold, warm=warm)
                if force_pool is None else (force_pool and len(small) > 1))
    pool_failed = False
    if use_pool:
        own_pool = pool is None
        active_pool = make_worker_pool(workers)[0] if own_pool else pool
        futures: List[Tuple[List[str], Any]] = []
        try:
            for batch in chunked(small, batch_size):
                try:
                    futures.append((batch, active_pool.submit(_small_batch_task, batch)))
                except Exception:  # pool already broken or shut down
                    futures.append((batch, None))
            for batch, future in futures:
                _check_cancel(cancel)
                method = "batched (%d per task, %s worker processes)" % (
                    batch_size, "warm" if warm else "new")
                try:
                    if future is None:
                        raise RuntimeError("worker pool unavailable")
                    batch_results = future.result()
                except Exception:
                    # A worker died or the pool is unusable: finish this batch here
                    # so hashing still completes, and tell the caller.
                    pool_failed = True
                    batch_results = _small_batch_task(batch)
                    method = "single-thread (worker pool unavailable)"
                for path, result in zip(batch, batch_results):
                    records[path].update(status=result["status"], error=result["error"],
                                         blake3=result["digest"], elapsed_ms=None, method=method)
                advance(sum(records[p]["size_bytes"] for p in batch),
                        "Hashed batch of %d small files" % len(batch))
        finally:
            for _batch, future in futures:
                if future is not None:
                    future.cancel()
            if own_pool:
                active_pool.shutdown(wait=True, cancel_futures=True)
    else:
        for path in small:
            _check_cancel(cancel)
            result = _small_file_task(path)
            records[path].update(status=result["status"], error=result["error"],
                                 blake3=result["digest"], elapsed_ms=result["elapsed_ms"],
                                 method="single-thread")
            done[0] += records[path]["size_bytes"]
            job.set(done[0], "Hashed %s" % records[path]["name"])

    for path in large:
        _check_cancel(cancel)
        result = hash_file_config(path, "optimized", collect_metrics=False, cancel=cancel,
                                  progress=within(records[path]["name"], "Hashing"))
        records[path].update(
            status=result.status, error=result.error or "", blake3=result.digest,
            elapsed_ms=result.elapsed_ms,
            method="%s · %d threads" % (result.io_strategy, result.threads_used))
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
            in_file = within(record["name"], ALGORITHM_LABELS[algorithm] + " of")
            if algorithm == "blake3_standard":
                result = hash_file_config(path, "baseline", collect_metrics=False,
                                          progress=in_file, cancel=cancel)
            else:
                result = hash_file_reference(path, algorithm, collect_metrics=False,
                                             progress=in_file, cancel=cancel)
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

    job.set(job.total, "Hashing complete", force=True)  # never leave the bar short
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
            "cache_warmup": ("untimed warm-up read first; both passes start from the cache"
                             if warm_cache else
                             "skipped: data larger than available memory, so both passes read "
                             "from storage"),
            "note": "Single-pass comparison. Controlled, repeated measurements are available in "
                    "Technique Evaluation.",
        }
    return {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": TOOL_NAME,
        "small_file_batching": use_pool,
        "worker_pool_warm": warm,
        "worker_pool_failed": pool_failed,
        "engine": {
            "blake3_package_version": str(getattr(_blake3_module, "__version__", "unknown")),
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


def write_hash_report(report: Dict[str, Any], folder: os.PathLike[str] | str, stem: str) -> Dict[str, str]:
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
    pool: Optional[ProcessPoolExecutor] = None,
) -> Dict[str, Any]:
    """Re-hash every file in a hash list and report matches, mismatches, missing files."""
    parsed = parse_hash_list(path)
    algorithm = parsed["algorithm"]
    entries = parsed["entries"]
    present = [e for e in entries if os.path.isfile(e["path"])]
    if algorithm == "blake3":
        report = hash_paths([e["path"] for e in present], progress=progress, cancel=cancel, pool=pool)
        actual = {r["path"]: (r["blake3"], r["status"], r["error"]) for r in report["files"]}
    else:
        actual = {}
        sizes = {e["path"]: os.path.getsize(e["path"]) for e in present}
        job = _JobProgress(progress, sum(sizes.values()))
        done = 0
        for entry in present:
            _check_cancel(cancel)
            name = os.path.basename(entry["path"])
            result = hash_file_reference(
                entry["path"], algorithm, collect_metrics=False, cancel=cancel,
                progress=lambda current, base=done, n=name: job.set(base + current, "Checking " + n))
            actual[entry["path"]] = (result.digest, result.status, result.error or "")
            done += sizes[entry["path"]]
            job.set(done, "Checked " + name, force=True)
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="files or folders to hash")
    parser.add_argument("--server", action="store_true", help="run Autopsy stream server")
    parser.add_argument("--threads", type=int, help="maximum native worker threads")
    parser.add_argument("--no-mmap", action="store_true", help="disable mmap for local files")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of digest lines")
    parser.add_argument("--self-test", action="store_true", help="run standard-vector validation")
    parser.add_argument("--benchmark", action="store_true", help="record precision metrics")
    parser.add_argument("--rounds", type=int, default=3, help="benchmark repetitions")
    parser.add_argument("--extra", nargs="*", default=[], choices=EXTRA_ALGORITHMS,
                        help="optional extra passes; Optimized BLAKE3 always runs")
    parser.add_argument("--save", help="folder for a hash report and .b3 hash list")
    parser.add_argument("--check", help="re-check files against a saved hash list")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.server:
        return serve_forever(threads=args.threads)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if args.self_test:
        report = self_test()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["passed"] else 2
    if args.check:
        checked = verify_hash_list(args.check)
        for item in checked["results"]:
            print("%-8s %s" % (item["outcome"].upper(), item["path"]))
        print(json.dumps(checked["counts"]))
        return 0 if checked["passed"] else 1
    if not args.paths:
        raise SystemExit("provide files/folders, --check LIST, --server, or --self-test")
    if args.benchmark:
        print(json.dumps(_benchmark(args.paths, max(1, args.rounds), args.threads), indent=2))
        return 0
    if args.extra or args.save or any(os.path.isdir(p) for p in args.paths):
        files: List[str] = []
        for path in args.paths:
            if os.path.isdir(path):
                files.extend(str(p) for p in sorted(Path(path).rglob("*")) if p.is_file())
            else:
                files.append(path)
        report = hash_paths(files, extra_algorithms=args.extra)
        for record in report["files"]:
            if record["status"] == "ok":
                print("%s  %s" % (record["blake3"], record["path"]))
            else:
                print("ERROR  %s: %s" % (record["path"], record["error"]), file=sys.stderr)
        if args.save:
            written = write_hash_report(report, args.save, "hashes_" + time.strftime("%Y%m%d_%H%M%S"))
            print(json.dumps(written, indent=2))
        return 0 if report["error_count"] == 0 else 1

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
