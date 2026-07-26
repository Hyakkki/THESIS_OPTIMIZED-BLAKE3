# Research BLAKE3 Toolkit Quickstart

Use this file if you want a simple setup guide for friends or reviewers.

## Before You Run

Install these first:

- Python 3.12 or newer
- `blake3` from pip
- `psutil` from pip
- `tkinter` through the normal Windows Python installer

If you also want the Rust CLI tools in the main repo, install Rust and Cargo with rustup.

## Install Command

```bash
py -3 -m pip install blake3 psutil
```

## How To Run

Plain BLAKE3 hash only:

```bash
py -3 research_blake3_toolkit/standard_blake3_hasher.py
```

Optimized vs baseline BLAKE3 hash and benchmark UI:

```bash
py -3 research_blake3_toolkit/blake3_file_hasher_ui.py
```

Benchmark a folder from the command line:

```bash
py -3 research_blake3_toolkit/run_forensic_benchmark.py <path-to-folder>
```

## Digital Evidence Dataset Folder

Put your own files in `digital_evidence_dataset/` before testing.

Suggested subfolders:

- `applications/`
- `documents/`
- `audio/`
- `video/`
- `disk_images/`
- `misc/`

Keep large or sensitive evidence out of git unless you really want it published.