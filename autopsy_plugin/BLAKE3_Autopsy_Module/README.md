# Optimized BLAKE3 Autopsy Module

This directory contains a standards-compliant native BLAKE3 engine, an Autopsy
4.x Jython bridge, a fair benchmarking harness, and cryptographic integrity
checks for the thesis **“Performance Optimization of BLAKE3 for Multi-Format
File Hashing in Digital Forensic Investigations.”**

## Architecture

- `optimized_blake3.py` — CPython/native engine and persistent sidecar protocol.
- `blake3_ingest_module.py` — Autopsy/Jython file and data-source ingest module.
- `optimized_blake3_hasher.exe` — packaged sidecar used by Autopsy.
- `benchmark_blake3.py` — JSON/CSV benchmark with equal timing scope.
- `blake3_validation.py` — published vectors, deterministic consistency,
  avalanche diagnostic, and empirical collision screen.
- `tests/` — regression tests.
- `build_sidecar.ps1` — reproducible PyInstaller build command.
- `OptimizedBLAKE3Ingest.py` — inactive migration marker; it prevents the old
  and new factories from both hashing the same files.

The engine uses the official `blake3` native extension. Its backend performs
standards-compliant BLAKE3 Merkle-tree parallelism and runtime SIMD dispatch.
The code does **not** combine independently computed chunk digests, because
that would produce a non-standard algorithm.

### Adaptive policy

| File size | I/O buffer | Parallel policy |
|---|---:|---|
| `< 1 MiB` | 64 KiB | one native thread |
| `1–16 MiB` | 256 KiB | one native thread |
| `16–64 MiB` | 2 MiB | physical-core native tree parallelism |
| `64–256 MiB` | 8 MiB | physical-core native tree parallelism |
| `256 MiB–2 GiB` | 8 MiB | mmap + physical-core native parallelism |
| `>= 2 GiB` | 16 MiB | mmap + physical-core native parallelism |

Local file hashing enables mmap at 64 MiB. Autopsy evidence cannot generally be
memory-mapped because `AbstractFile`/`DataSource` is a virtual content stream;
the bridge instead uses reusable Java `byte[]` buffers and one native bulk pipe
write per read. Multiple independent local files can use
`ProcessPoolExecutor`; each worker is restricted to one native BLAKE3 thread to
avoid nested oversubscription. A single large file uses native BLAKE3 tree
parallelism.

### Thesis comparison profiles

During Autopsy ingest, every readable content object receives Optimized
BLAKE3. Correctness comparisons use the first three readable files in each
category. The performance cohort is separate: it includes up to 10 files per
category that are at least 16 MiB, which is the point where the optimized
profile activates native tree parallelism. This prevents thousands of tiny
file/IPC calls from being presented as a bulk hashing benchmark. The complete
evidence source is also compared. Each measured profile uses the same sidecar
protocol and end-to-end measurement scope:

If the eligible internal-file cohort totals less than 64 MiB, the Algorithm
Comparison table uses the complete evidence source instead. This is recorded as
an evidence-source fallback and prevents a few small files from producing an
unstable or misleading throughput ranking.

1. Optimized BLAKE3: adaptive buffer and native multithreaded tree hashing.
2. Baseline BLAKE3: fixed 1 MiB buffer and one native BLAKE3 thread.
3. SHA-256: fixed 1 MiB independent reference pass.
4. SHA-1: fixed 1 MiB independent reference pass.
5. MD5: fixed 1 MiB independent reference pass.

Baseline and Optimized BLAKE3 must produce the same digest for every comparison
sample. A mismatch prevents that optimized artifact from being posted. Set
`BLAKE3_COMPARE_EVERY_FILE=1` only for a controlled benchmark corpus; doing so
causes five complete reads of every file and can greatly extend ingest. The
Python BLAKE3 API does not expose
a runtime scalar/SIMD-off switch, so native SIMD dispatch is held constant in
both BLAKE3 profiles; the experimental treatment factors are adaptive buffering
and multithreaded tree execution. Building a separately compiled scalar backend
would be required to isolate SIMD as an independent factor.

## Build and validate the sidecar

The checked-in executable was built from the new source and precision metric
schema. Rebuild it on the controlled examination/benchmark host when required:

```powershell
.\build_sidecar.ps1
.\dist\optimized_blake3_hasher.exe --self-test
```

After validation, replace `optimized_blake3_hasher.exe` with the file from
`dist`. Record the executable SHA-256 in the thesis and case notes; the Autopsy
report records it automatically.

For development:

```powershell
python -m pip install -r requirements.txt
python optimized_blake3.py --self-test
python -m unittest discover -s tests -v
python blake3_validation.py
```

## Autopsy installation

1. In Autopsy, open **Tools → Python Plugins**.
2. Copy this whole folder into the Python modules directory.
3. Ensure the newly built executable is beside `blake3_ingest_module.py`.
4. Restart Autopsy.
5. Enable **Optimized BLAKE3 Hasher** during ingest.

The module hashes the complete data source and every eligible file, including
zero-byte files. To avoid flooding Autopsy's Blackboard, it creates **BLAKE3
Hash (Optimized v4)** artifacts for the complete data source and sampled file
comparisons; all optimized per-file results remain in the HTML/JSON audit log.
Set `BLAKE3_POST_ALL_FILE_ARTIFACTS=1` if laboratory policy requires one
Blackboard artifact per readable file. After Autopsy fires
its data-source-analysis-completed event, the HTML report is registered under
**Reports** and an **Open Report / OK** dialog is displayed automatically.

It independently computes Baseline BLAKE3, MD5, SHA-1, and SHA-256 for the
stratified thesis comparison and records digest, execution time, throughput,
normalized CPU utilization, and peak RSS for each profile. The sample limit can
be changed with `BLAKE3_COMPARISON_SAMPLE_LIMIT`; the performance threshold can
be changed with `BLAKE3_PERFORMANCE_MIN_BYTES`.

Before measuring the complete evidence source, the module performs one
unmeasured Optimized BLAKE3 warm-up pass and verifies that its digest matches
the measured pass. This gives BLAKE3 and the reference algorithms the same
warmed Autopsy/libewf/operating-system cache condition. Set
`BLAKE3_EVIDENCE_CACHE_WARMUP=0` only when a documented cold-cache protocol is
being controlled externally.

The MD5/SHA-1/SHA-256 timings are independent, same-scope measurements of the
algorithms Autopsy supports; they are not timing values exported by Autopsy's
built-in hashing module. At report completion, the module also checks each
independently computed reference digest against the corresponding hash stored
by Autopsy when that value is available. The report labels those checks
`AUTOPSY MATCH`, `AUTOPSY MISMATCH`, or `AUTOPSY N/A`.

## Benchmarking

Use at least one file from every target category and multiple rounds:

```powershell
python benchmark_blake3.py evidence\document.pdf evidence\image.jpg `
  evidence\audio.mp3 evidence\video.mp4 evidence\program.exe evidence\disk.dd `
  --rounds 5 --json-output benchmark.json --csv-output benchmark.csv
```

Every algorithm is measured over the same scope:
`open + mmap/read + hash + digest finalization`. Report cache state, power plan,
CPU model, storage device, Autopsy worker count, and real-time antivirus state.
MiB/s uses `2^20` bytes even where the Autopsy label is shortened to MB/s.

Do not compare the legacy SHA `MessageDigest.update()`-only timing to BLAKE3
end-to-end timing; those scopes differ and explain much of the apparent SHA
advantage.

## Forensic reliability notes

- Published empty and `abc` BLAKE3-256 vectors are checked.
- Exact expected/actual byte counts are enforced; missing bytes are never
  padded.
- If Autopsy returns fewer bytes than a virtual file declares (for example,
  NTFS `$BadClus:$Bad-slack`), the item is recorded as `skipped`, no digest is
  accepted, and the persistent native helper is restarted and self-tested.
  This prevents the next file (often shown as `$Bitmap`) from inheriting a
  desynchronized request stream.
- Local files are rejected if size, modification time, or identity changes.
- Engine version, executable SHA-256, SIMD capability, thread cap, timing scope,
  CPU utilization, and peak RSS are auditable.
- Re-hashing every file is disabled because it doubles ingest work without
  strengthening BLAKE3. Independently verify selected exhibits when required by
  lab procedure.
- Avalanche and collision-corpus tests are diagnostics, not security proofs.
