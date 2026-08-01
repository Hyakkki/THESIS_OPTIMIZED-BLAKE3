# Optimized BLAKE3 — Forensic Hashing Toolkit

A Python toolkit for benchmarking and comparing **baseline vs. optimized BLAKE3** hashing strategies for digital forensic evidence processing.

## What This Does

- **Baseline mode**: Standard BLAKE3 hashing with a fixed 1 MiB chunk size
- **Optimized mode**: Adaptive chunk sizing, buffer reuse (`readinto` + `memoryview`), and memory-mapped I/O for large files
- **Benchmarking**: Compare throughput, elapsed time, CPU usage, and memory across modes
- **Consistency validation**: Verify that all modes produce identical digests

> **Note:** The BLAKE3 algorithm itself is not modified. The `blake3` PyPI package provides the core hashing engine (with built-in SIMD acceleration via SSE2/SSE41/AVX2/AVX512). This toolkit optimizes the **caller-side I/O strategy** around it.

## Setup

```bash
pip install blake3 psutil
```

Requires Python 3.12+ with `tkinter` (included in the standard Windows Python installer).

## How To Run

**Standard BLAKE3 hasher (simple UI):**
```bash
python simple_hasher.py
```

**Optimized vs baseline BLAKE3 hasher + benchmark UI:**
```bash
python main_app.py
```

**Command-line benchmark:**
```bash
python benchmark.py <path-to-folder>
python benchmark.py <path-to-folder> --parallel --repeats 5 --include-blake2
```

## Project Structure

```
├── blake3_engine.py             # Core hashing engine and benchmark logic
├── main_app.py                  # Tkinter UI for hashing and benchmarking
├── simple_hasher.py             # Simple single-file hasher UI
├── benchmark.py                 # CLI benchmark runner
├── digital_evidence_dataset/    # Put test files here
└── artifacts/                   # Benchmark CSV outputs
```

## Digital Evidence Dataset

Place test files in `digital_evidence_dataset/` before benchmarking. Suggested subfolders:

- `documents/` — PDF, DOCX, TXT, etc.
- `images/` — JPG, PNG, BMP, etc.
- `audio/` — MP3, WAV, FLAC, etc.
- `video/` — MP4, MKV, AVI, etc.
- `executables/` — EXE, DLL, etc.
- `disk_images/` — ISO, IMG, DD, E01, etc.
