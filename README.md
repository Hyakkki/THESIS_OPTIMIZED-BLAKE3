# Optimized BLAKE3 — Forensic Hashing Toolkit

> **Thesis:** *Performance Optimization for BLAKE3 for Multi-Format File Hashing in Digital Forensic Investigations*
>
> An optimization **for** BLAKE3, not **of** BLAKE3: the workflow around the algorithm is optimized; the algorithm itself is unchanged.

A standalone desktop application and set of command-line tools. They measure the effect of
implementation-level optimizations on BLAKE3 hashing of forensic evidence files, one technique
at a time and in combination, with a defined statistical procedure.

## What is optimized, and what is not

The **BLAKE3 algorithm is not modified.** Every digest is standard BLAKE3-256, which is confirmed
against the official test vectors and an independent reference implementation. The study
optimizes how files are fed to BLAKE3:

| Technique | What it does | Where it is measured |
|---|---|---|
| Adaptive input-buffer sizing | Buffer chosen by file size instead of a fixed 1 MiB: 64–512 KiB for small files; from 32 MiB the file is memory-mapped in 256 MiB windows (zero-copy, full multithreaded speed, memory bounded for files of any size). On HDDs and network shares, or when a file can't be mapped, it streams sequentially with background reads (next 4 MiB read while the current one is hashed) | Technique Evaluation (2×2 design) |
| Multithreaded processing of large files | BLAKE3 native tree parallelism on all logical cores for files ≥ 32 MiB | Technique Evaluation (2×2 design) |
| Batched processing of small files | Groups of small files share one worker task and one reusable buffer; the app keeps the worker pool warm, so batching applies from 100 small files | Batch Processing (2×2 design) |

**Held constant (not a contribution):** native SIMD dispatch (identical in baseline and optimized
runs), and the MD5/SHA reference passes, which use the same 1 MiB single-thread I/O path as
Baseline BLAKE3 and are reported "as configured".

**Note on memory-mapped input:** peak-memory figures for mapped configurations include the
mapped file's pages, which are shared, reclaimable operating-system file cache rather than memory
the program allocates. On slow spinning hard drives, parallel reads of a mapped file can be
slower than sequential streaming; the background-read path remains available as the fallback.

## Architecture

Four code files under `dev/`, one job each, plus the app:

```
main_app.py               Presentation   Tkinter UI: sidebar pages, progress, tables, charts, export
dev/optimized_blake3.py   Hashing engine adaptive policy, technique configurations, batching, process pool,
                                         Hash Files logic, hash lists (b3sum format) and re-checking
                                         └─ blake3 (native Rust/C extension, runtime SIMD dispatch)
dev/benchmark_blake3.py   Experiments    2×2 technique experiments, randomized block design, correctness
                                         gate, and all formulas/statistics (F1–F19, Wilcoxon, bootstrap,
                                         Cliff's δ, Holm)
dev/blake3_validation.py  Verification   checks V1–V6, including an independent pure-Python BLAKE3
                                         reference implementation
dev/dataset_tool.py       Dataset        size sweeps, small-file sets, manifest, coverage and gaps
dev/test_vectors/         Data           official BLAKE3 test vectors
dev/tests/                Tests          unit tests for every module
```

All tool names and the thesis title are set in one place (`TOOL_SHORT_NAME`, `TOOL_SUBTITLE`,
`THESIS_TITLE` near the top of `dev/optimized_blake3.py`).

## Setup

Python 3.10 or newer, with Tkinter (included in the standard Windows installer).

```bash
pip install -r requirements.txt
python main_app.py
```

## Hardware and real-world evidence sizes

The engine adapts to the machine and the drive it runs on, so the same build works on different
modern laptops (including multi-core gaming laptops):

- **CPU:** large files use all logical threads (detected at run time; e.g. 12 on a 6-core/12-thread
  CPU, 20–32 on current high-end laptop CPUs). Native SIMD (SSE4.1/AVX2/AVX-512/NEON) is selected
  automatically by the BLAKE3 library.
- **Storage:** each file's drive is classified (SSD/NVMe, HDD, network) using Windows' seek-penalty
  query (no administrator rights needed). SSD/NVMe → parallel memory-mapped windows; HDD/network →
  sequential background reads, which avoid slow random seeks.
- **Evidence of 500 GB – 2 TB:** memory use stays bounded (one 256 MiB window per large file), the
  progress bar moves inside each file with transfer rate and time remaining, and Cancel takes effect
  within one window. At these sizes the drive, not BLAKE3, sets the speed (roughly 7 GB/s for fast
  NVMe, 0.5 GB/s for SATA SSDs, 0.15–0.25 GB/s for HDDs, so 1 TB takes about 2.5 min to 2 h).
- **Large folders:** folders with hundreds of thousands of files are handled; the table shows the first
  5,000 rows while every file is hashed and saved.
- The Standard BLAKE3 comparison skips its cache warm-up when the data is larger than free memory, and
  Technique Evaluation warns before runs that would read more than 200 GB.

## The application

The app opens as a plain hasher (Hash Files, File Analysis, Overview, Methodology). The
evaluation and validation pages (Technique Evaluation, Batch Processing, Correctness Verification,
Test Dataset) appear when **Evaluation mode** is switched on at the bottom of the sidebar.

| Page | Purpose |
|---|---|
| **Hash Files** (opens first) | Hash files or whole folders with the optimized engine (Optimized BLAKE3; optional Standard BLAKE3 comparison, SHA-256, SHA-1, MD5); copy digests; check against an expected hash; save a `.b3` hash list (b3sum format) + CSV/JSON report; re-check files against a saved list |
| System Overview | Techniques, detected hardware and drives, controlled variables, architecture, evaluation workflow |
| File Analysis | Digest, in-memory speed, avalanche / strict avalanche criterion / bit balance / duplicate screen for one file |
| Technique Evaluation *(Evaluation mode)* | Large-file 2×2 experiment (adaptive buffer × multithreading) plus reference algorithms; speedup with 95 % CI, Holm-adjusted Wilcoxon p, Cliff's δ, factorial effects, chart, results per size tier |
| Batch Processing *(Evaluation mode)* | Small-file 2×2 experiment (batching × parallel dispatch) on a whole file set |
| Correctness Verification *(Evaluation mode)* | V1 official vectors (native + reference, 3 modes, 131-byte output) · V2 cross-implementation · V3 consistency across buffers, threads, I/O paths and every configuration · V4 repeatability · V5 avalanche (z-test, χ², SAC) · V6 duplicate screen and bit balance |
| Test Dataset *(Evaluation mode)* | Generate a size sweep across every policy tier and a small-file corpus; catalogue any folder into a manifest with SHA-256, provenance, a category × size-tier coverage matrix and a list of gaps |
| Methodology | All formulas and the statistical analysis plan; exports `methodology.md` for Chapter 3 |

Results (JSON, run-level CSV, summary CSV) are written to `results/`.

## Statistical procedure (summary)

- **Design:** randomized complete block design. Each round runs every configuration once in a
  seeded random order. 30 measured rounds by default (minimum 10) and 2 excluded warm-ups.
- **Primary indicator:** elapsed time, summarized by the median. Throughput, normalized CPU and
  peak RSS are secondary.
- **Inference:** paired Wilcoxon signed-rank test with Holm–Bonferroni adjustment, paired
  bootstrap 95 % CI of the speedup, Cliff's δ and rank-biserial effect sizes. "Significantly
  faster" requires Holm p < 0.05 **and** the whole CI above 1.
- **Correctness gate:** every timed execution must reproduce the expected digest, otherwise the
  run aborts.

The full plan and formulas are in `dev/benchmark_blake3.py` (`FORMULAS`, `STATISTICAL_PLAN`) and the Methodology page.

## Command line

```bash
cd dev
python optimized_blake3.py FILE_OR_FOLDER [...] [--extra blake3_standard sha256] [--save ../results]
python optimized_blake3.py --check ../results/hashes_YYYYMMDD_HHMMSS.b3
python dataset_tool.py sweep  ../digital_evidence_dataset/generated/size_sweep --max-size-mib 1024
python dataset_tool.py small  ../digital_evidence_dataset/generated/small_files --count 2000
python dataset_tool.py manifest ../digital_evidence_dataset
python blake3_validation.py [optional-file] --output verification.json
python benchmark_blake3.py large FILE [FILE ...] --trials 30 --output ../results
python benchmark_blake3.py small FOLDER --trials 30 --output ../results
python -m unittest discover -s tests -v
```

## Dataset guidance

Place evidence in `digital_evidence_dataset/` (git-ignored). Include files from every category:
documents, images, audio, video, archives, executables, and disk/forensic images (raw `.dd`/`.img`
and E01). Cover every size tier T1–T6, and include at least 500 small files. Record where each
file came from in `digital_evidence_dataset/sources.json`; the manifest flags undocumented
files. Public sources of forensic images include NIST CFReDS and Digital Corpora.

An E01 (or other container) is hashed as a stored file. Its digest identifies the container and
is **not** the acquisition hash recorded inside the E01.

## Scope of verification

The verification procedures show that this implementation computes standard BLAKE3 correctly
under every optimization, and that outputs behave as expected on the tested inputs. They do not
prove collision or preimage resistance. BLAKE3's security rests on its published design and
cryptanalysis, which this study does not modify.

## Autopsy plugin (secondary)

`autopsy_plugin/` contains an earlier Autopsy 4.x ingest module and its sidecar executable
(see `dev/README.md`). It is not the focus of the current work. The committed
`optimized_blake3_hasher.exe` predates the batch protocol and must be rebuilt with
`dev/build_sidecar.ps1` before the plugin will run.
