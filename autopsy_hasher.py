"""autopsy_hasher.py

Command-line entry point for the optimized BLAKE3 hasher.
Called by the Autopsy Jython ingest module via subprocess.

Two operating modes
-------------------
1. Single-file mode (default):
       optimized_blake3_hasher.exe <file_path>
   Hashes one file, prints one JSON object to stdout, then exits.

2. Server mode:
       optimized_blake3_hasher.exe --server
   Starts a persistent server that reads file paths from stdin (one per
   line) and writes one JSON result per line to stdout.  Runs until stdin
   is closed.  Used by the Autopsy ingest module to avoid the per-file
   process-startup overhead (~100-300 ms each).

Output format (both modes):
    {"status": "ok", "digest": "a1b2c3...", "elapsed_s": 0.003,
     "throughput_mb_s": 124.5, "simd_tier": "AVX-512",
     "threads_used": 12, "file_size_bytes": 3145728}

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


def _hash_to_result(file_path: str) -> dict:
    """Hash one file and return the result dict."""
    from blake3_engine import hash_file_optimized  # noqa: PLC0415

    metrics = hash_file_optimized(file_path)
    return {
        "status": "ok",
        "digest": metrics.digest,
        "elapsed_s": round(metrics.elapsed_s, 6),
        "throughput_mb_s": round(metrics.throughput_mb_s, 3),
        "simd_tier": metrics.simd_tier,
        "threads_used": metrics.threads_used,
        "file_size_bytes": os.path.getsize(file_path),
    }


def single_file_mode(file_path: str) -> int:
    """Hash one file, print JSON, exit."""
    if not os.path.isfile(file_path):
        print(json.dumps({"status": "error", "message": f"File not found: {file_path}"}))
        return 1
    try:
        result = _hash_to_result(file_path)
        print(json.dumps(result))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "error", "message": str(exc)}))
        return 1


def server_mode() -> int:
    """
    Persistent server: read file paths from stdin, write JSON results to stdout.

    Protocol
    --------
    - Client writes: <absolute_file_path>\\n
    - Server writes: <json_result>\\n
    - Repeat until stdin is closed (EOF).

    Pre-import the engine once so every subsequent hash call is instant.
    """
    try:
        from blake3_engine import hash_file_optimized as _warmup  # noqa: F401
    except Exception:
        pass  # Will surface as error on first hash attempt

    # Use binary stdin/stdout to avoid any line-ending translation issues.
    stdin = getattr(sys.stdin, "buffer", sys.stdin)
    stdout = getattr(sys.stdout, "buffer", sys.stdout)

    while True:
        try:
            line = stdin.readline()
        except Exception:
            break

        if not line:
            break  # EOF — Autopsy ingest module has closed stdin

        file_path = line.rstrip(b"\r\n").decode("utf-8", errors="replace")
        if not file_path:
            continue

        try:
            result = _hash_to_result(file_path)
        except Exception as exc:
            result = {"status": "error", "message": str(exc)}

        out = (json.dumps(result) + "\n").encode("utf-8")
        stdout.write(out)
        stdout.flush()

    return 0


def main() -> int:
    if len(sys.argv) >= 2:
        if sys.argv[1] == "--server":
            return server_mode()
        else:
            return single_file_mode(sys.argv[1])

    # No arguments — print usage
    print(json.dumps({
        "status": "error",
        "message": "Usage: optimized_blake3_hasher.exe <file_path>  OR  --server",
    }))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
