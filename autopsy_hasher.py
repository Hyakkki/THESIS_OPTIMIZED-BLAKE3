"""autopsy_hasher.py

Command-line entry point for the optimized BLAKE3 hasher.
Called by the Autopsy Jython ingest module via subprocess.

Usage:
    python autopsy_hasher.py <file_path>
    optimized_blake3_hasher.exe <file_path>

Output (stdout): A single JSON object, e.g.:
    {
        "status": "ok",
        "digest": "a1b2c3...",
        "elapsed_s": 0.0031,
        "throughput_mb_s": 124.5,
        "simd_tier": "AVX-512",
        "threads_used": 12,
        "file_size_bytes": 3145728
    }

On error:
    {"status": "error", "message": "..."}
"""

import json
import multiprocessing
import os
import sys

# Required for PyInstaller + multiprocessing (ProcessPoolExecutor) on Windows.
# Must be called before any other code when running as a frozen .exe.
multiprocessing.freeze_support()


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"status": "error", "message": "No file path provided. Usage: autopsy_hasher <file_path>"}))
        return 1

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print(json.dumps({"status": "error", "message": f"File not found: {file_path}"}))
        return 1

    try:
        # Import here so PyInstaller bundles blake3_engine and all its deps
        from blake3_engine import hash_file_optimized

        metrics = hash_file_optimized(file_path)

        result = {
            "status": "ok",
            "digest": metrics.digest,
            "elapsed_s": round(metrics.elapsed_s, 6),
            "throughput_mb_s": round(metrics.throughput_mb_s, 3),
            "cpu_percent": round(metrics.cpu_percent, 2),
            "memory_mb": round(metrics.memory_mb, 2),
            "simd_tier": metrics.simd_tier,
            "threads_used": metrics.threads_used,
            "file_size_bytes": os.path.getsize(file_path),
        }
        print(json.dumps(result))
        return 0

    except Exception as exc:
        print(json.dumps({"status": "error", "message": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
