# Optimized BLAKE3 — Forensic Hashing Toolkit

> **Thesis:** *Performance Optimization of BLAKE3 for Multi-Format File Hashing in Digital Forensic Investigations*

A standalone desktop application and set of command-line tools. They measure the effect of
implementation-level optimizations on BLAKE3 hashing of forensic evidence files, one technique
at a time and in combination, with a defined statistical procedure.

## What is optimized, and what is not

The **BLAKE3 algorithm is not modified.** Every digest is standard BLAKE3-256, which is confirmed
against the official test vectors and an independent reference implementation. The study
optimizes how files are fed to BLAKE3:

| Technique | What it does | Where it is measured |
|---|---|---|
| Adaptive input-buffer sizing | Read buffer from 64 KiB up to 16 MiB, chosen by file size, instead of a fixed 1 MiB | Technique Benchmark (2×2 design) |
| Multithreaded processing of large files | BLAKE3 native tree parallelism on all physical cores for files ≥ 32 MiB | Technique Benchmark (2×2 design) |
| Batched processing of small files | Groups of small files share one worker task and one reusable buffer | Small-File Batching (2×2 design) |

**Held constant (not a contribution):** native SIMD dispatch (identical in baseline and optimized
runs), and the MD5/SHA reference passes, which use the same 1 MiB single-thread I/O path as
Baseline BLAKE3 and are reported "as configured". Memory-mapped I/O is available only as an
exploratory configuration.

## Architecture (four layers)

```
1 Presentation          main_app.py                     Tkinter UI, progress, tables, charts, export
2 Experiment control    dev/benchmark_blake3.py         randomized block experiments, correctness gate
                        dev/blake3_validation.py        verification procedures V1–V6
                        dev/dataset_tool.py             dataset generation, manifest, coverage
3 Measurement & stats   dev/metrics.py                  formulas F1–F19, Wilcoxon, bootstrap, Cliff's δ, Holm
4 Hashing engine        dev/optimized_blake3.py         policies, configurations, batching, process pool
                        dev/file_hashing.py             everyday hashing, hash lists (b3sum format), re-checking
                        └─ blake3 (native Rust/C extension, runtime SIMD dispatch)
Support                 dev/blake3_reference.py         independent pure-Python BLAKE3 (verification only)
                        dev/test_vectors/               official BLAKE3 test vectors
```

## Setup

Python 3.10 or newer, with Tkinter (included in the standard Windows installer).

```bash
pip install -r requirements.txt
python main_app.py
```

## The application

| Tab | Purpose |
|---|---|
| **Hash Files** (opens first) | Hash files or whole folders with the optimized engine (BLAKE3, optionally SHA-256/SHA-1/MD5); copy digests; check against an expected hash; save a `.b3` hash list (b3sum format) + CSV/JSON report; re-check files against a saved list |
| Overview | Contributions, constants, architecture, suggested demonstration order |
| File Analysis | Digest, in-memory speed, avalanche / strict avalanche criterion / bit balance / duplicate screen for one file |
| Technique Benchmark | Large-file 2×2 experiment (adaptive buffer × multithreading) plus reference algorithms; speedup with 95 % CI, Holm-adjusted Wilcoxon p, Cliff's δ, factorial effects, chart, results per size tier |
| Small-File Batching | Small-file 2×2 experiment (batching × parallel dispatch) on a whole file set |
| Verification | V1 official vectors (native + reference, 3 modes, 131-byte output) · V2 cross-implementation · V3 consistency across buffers, threads, I/O paths and every configuration · V4 repeatability · V5 avalanche (z-test, χ², SAC) · V6 duplicate screen and bit balance |
| Dataset | Generate a size sweep across every policy tier and a small-file corpus; catalogue any folder into a manifest with SHA-256, provenance, a category × size-tier coverage matrix and a list of gaps |
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

The full plan and formulas are in `dev/metrics.py` and the Methodology tab.

## Command line

```bash
cd dev
python file_hashing.py FILE_OR_FOLDER [...] [--extra sha256] [--save ../results]
python file_hashing.py --check ../results/hashes_YYYYMMDD_HHMMSS.b3
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
