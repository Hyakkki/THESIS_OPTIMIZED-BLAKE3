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
    Persistent bytes-streaming server.

    Protocol (one exchange per file)
    ---------------------------------
    1. Client → Server: "<file_size>\\n"     (text line with byte count)
    2. Client → Server: <file_size> raw bytes (binary, no delimiter)
    3. Server → Client: <json_result>\\n      (text line with JSON)

    Benefits over the old path-based protocol
    ------------------------------------------
    - No temp file is written to disk → no antivirus scanning
    - No extra file-system I/O (single read from Autopsy image)
    - elapsed_s measures ONLY pure BLAKE3 hashing, not I/O waits
    - Consistent, reproducible execution times across all file sizes

    Runs until stdin is closed (EOF) — i.e., until the ingest job ends.
    """
    # Pre-import engine once so every hash call is instant.
    from blake3_engine import hash_bytes_optimized  # noqa: PLC0415

    stdin  = getattr(sys.stdin,  "buffer", sys.stdin)
    stdout = getattr(sys.stdout, "buffer", sys.stdout)

    while True:
        # --- Step 1: read the file-size header ---
        try:
            header = stdin.readline()
        except Exception:
            break
        if not header:
            break  # EOF — ingest module closed stdin

        header = header.strip()
        if not header:
            continue

        try:
            file_size = int(header)
        except ValueError:
            # Malformed header; skip this exchange.
            result = {"status": "error", "message": "Bad header: " + header.decode("utf-8", "replace")}
            stdout.write((json.dumps(result) + "\n").encode("utf-8"))
            stdout.flush()
            continue

        # --- Step 2: read exactly file_size raw bytes ---
        data = bytearray()
        remaining = file_size
        try:
            while remaining > 0:
                chunk = stdin.read(min(65536, remaining))
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)
        except Exception as exc:
            result = {"status": "error", "message": "Read error: " + str(exc)}
            stdout.write((json.dumps(result) + "\n").encode("utf-8"))
            stdout.flush()
            continue

        # --- Step 3: hash in memory, send JSON result ---
        try:
            metrics = hash_bytes_optimized(bytes(data), file_size)
            result = {
                "status":           "ok",
                "digest":           metrics.digest,
                "elapsed_s":        round(metrics.elapsed_s, 6),
                "throughput_mb_s":  round(metrics.throughput_mb_s, 3),
                "simd_tier":        metrics.simd_tier,
                "threads_used":     metrics.threads_used,
                "file_size_bytes":  file_size,
            }
        except Exception as exc:
            result = {"status": "error", "message": str(exc)}

        stdout.write((json.dumps(result) + "\n").encode("utf-8"))
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
