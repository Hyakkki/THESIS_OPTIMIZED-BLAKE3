# Optimized BLAKE3 — Forensic Hashing Toolkit

> **Thesis:** *"Performance Optimization of BLAKE3 for Multi-Format File Hashing in Digital Forensic Investigations"*

A toolkit that benchmarks and deploys an **optimized BLAKE3** hashing engine for digital forensic evidence processing, integrating directly with **Autopsy** via a Jython ingest module.

---

## How It Works

The BLAKE3 algorithm itself is unchanged. Optimization is applied at the **caller level**:

| Layer | What we optimize |
|---|---|
| **I/O strategy** | Adaptive chunk sizing, `readinto` + `memoryview`, memory-mapped I/O for large files |
| **Parallelism** | Multithreaded file processing with `ProcessPoolExecutor` |
| **SIMD** | Leverages the official `blake3` Rust/C library (SSE2 / AVX2 / AVX-512 auto-detected) |
| **Autopsy bridge** | Persistent sidecar exe — starts once per session, not once per file |

---

## Architecture

```
Autopsy (Jython 2.7)
  └── AutopsyBLAKE3Ingest.py
        ├── Reads file bytes via AbstractFile.read() + & 0xFF
        ├── Writes to temp file
        └── Sends path over stdin ──► optimized_blake3_hasher.exe (server mode)
                                              └── blake3_engine.py
                                                    └── blake3 (Rust/C, AVX-512)
                                              ◄── JSON result over stdout
```

The exe runs as a **persistent server** for the entire ingest session, eliminating the ~100–300 ms startup cost per file that a single-shot approach would incur.

---

## Project Structure

```
├── blake3_engine.py                    # Core engine: hashing, benchmarking, SIMD detection
├── autopsy_hasher.py                   # CLI wrapper (single-file mode + server mode)
├── benchmark.py                        # CLI benchmark runner for thesis data
├── main_app.py                         # Tkinter UI: hash files and run benchmarks
├── simple_hasher.py                    # Simple single-file hasher UI
├── optimized_blake3_hasher.spec        # PyInstaller spec to rebuild the exe
├── README.md
│
├── autopsy_plugin/
│   └── BLAKE3_Autopsy_Module/
│       ├── AutopsyBLAKE3Ingest.py      # Autopsy ingest module (Jython 2.7)
│       ├── optimized_blake3_hasher.exe # Packaged hashing engine (server mode)
│       └── README.md
│
├── artifacts/                          # Benchmark CSV outputs
└── digital_evidence_dataset/           # Place test evidence files here
```

---

## Setup

```bash
pip install blake3 psutil
```

Requires Python 3.12+ with `tkinter` (included in the standard Windows Python installer).

---

## Autopsy Plugin Installation

1. Open Autopsy → **Tools → Python Plugins** to find the `python_modules` folder
2. Copy the entire `autopsy_plugin/BLAKE3_Autopsy_Module/` folder there
3. Restart Autopsy
4. Open or create a case → **Run Ingest** → enable **"Optimized BLAKE3 Hasher"**
5. After ingest completes, go to **Results → BLAKE3 Hash (Optimized)** in the tree

> **Note:** The plugin starts `optimized_blake3_hasher.exe` once per ingest session in server mode. Do not move or rename the exe — it must be in the same folder as `AutopsyBLAKE3Ingest.py`.

---

## Standalone Usage

**Simple file hasher (UI):**
```bash
python simple_hasher.py
```

**Optimized vs baseline benchmark UI:**
```bash
python main_app.py
```

**Command-line benchmark (generates CSV for thesis):**
```bash
python benchmark.py digital_evidence_dataset/
python benchmark.py digital_evidence_dataset/ --parallel --repeats 5
```

**Single file from command line:**
```bash
.\autopsy_plugin\BLAKE3_Autopsy_Module\optimized_blake3_hasher.exe <file_path>
```

---

## Digital Evidence Dataset

Place test files in `digital_evidence_dataset/` before benchmarking. Suggested subfolders:

- `documents/` — PDF, DOCX, TXT
- `images/` — JPG, PNG, BMP
- `audio/` — MP3, WAV, FLAC
- `video/` — MP4, MKV, AVI
- `executables/` — EXE, DLL
- `disk_images/` — ISO, IMG, DD, E01

---

## Rebuilding the Exe

If you modify `autopsy_hasher.py` or `blake3_engine.py`:

```bash
python -m PyInstaller --clean optimized_blake3_hasher.spec
copy dist\optimized_blake3_hasher.exe autopsy_plugin\BLAKE3_Autopsy_Module\
```
