#!/usr/bin/env python3
"""Benchmark dataset generation, classification, and manifest (Panel #4, #19).

Three jobs:

1. ``generate_size_sweep`` – deterministic files at chosen sizes so every
   branch of the adaptive policy (each buffer tier and the multithreading
   threshold) is exercised.
2. ``generate_small_file_corpus`` – many small files (log-uniform sizes) for the
   batched-processing experiment.
3. ``build_manifest`` – records size, format, category, size tier, provenance,
   and SHA-256 of every dataset file, plus a category × size-tier coverage
   matrix and a list of gaps. The manifest is the audit trail that justifies
   (and lets others reproduce) the dataset.

Why synthetic content is acceptable for size sweeps: BLAKE3 processes every
input byte with the same fixed sequence of operations, so its cost depends on
the *number* of bytes and the I/O path, not on their values. Real files of each
format are still needed to show the dataset is representative of casework.

Forensic note: a container image (E01/Ex01/AFF/VMDK/VHD) is hashed *as a stored
file*. That digest identifies the container, not the acquired media; it is not
comparable to the acquisition hash recorded inside an E01.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import blake3 as _blake3

from optimized_blake3 import MIB, SMALL_FILE_LIMIT

KIB = 1024
GIB = 1024 * MIB

# Tier edges follow the engine's adaptive policy so each tier maps to one
# buffer size / threading decision.
SIZE_TIERS: Tuple[Tuple[str, int, int], ...] = (
    ("T1 tiny (< 512 KiB)", 0, 512 * KIB),
    ("T2 small (512 KiB – 4 MiB)", 512 * KIB, 4 * MIB),
    ("T3 medium (4 – 32 MiB)", 4 * MIB, SMALL_FILE_LIMIT),
    ("T4 large (32 – 128 MiB)", SMALL_FILE_LIMIT, 128 * MIB),
    ("T5 very large (128 MiB – 1 GiB)", 128 * MIB, GIB),
    ("T6 bulk (≥ 1 GiB)", GIB, 1 << 62),
)

FORMAT_CATEGORIES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("Documents", (".pdf", ".docx", ".doc", ".rtf", ".odt", ".txt", ".md", ".xls", ".xlsx",
                   ".ods", ".csv", ".tsv", ".ppt", ".pptx", ".odp")),
    ("Images", (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic",
                ".heif", ".svg", ".ico", ".cr2", ".nef", ".arw", ".psd")),
    ("Audio", (".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a", ".aiff", ".opus")),
    ("Video", (".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".mpg",
               ".mpeg", ".3gp")),
    ("Archives", (".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab")),
    ("Executables", (".exe", ".dll", ".elf", ".so", ".dylib", ".msi", ".apk", ".jar", ".sys")),
    ("Disk & Forensic Images", (".dd", ".raw", ".img", ".001", ".e01", ".ex01", ".l01", ".aff",
                                ".aff4", ".vmdk", ".vhd", ".vhdx", ".iso", ".ad1")),
    ("Databases", (".db", ".sqlite", ".sqlite3", ".mdb", ".accdb")),
    ("Email", (".pst", ".ost", ".eml", ".msg", ".mbox")),
    ("Synthetic", (".bin",)),
)
REQUIRED_CATEGORIES = (
    "Documents", "Images", "Audio", "Video", "Archives", "Executables",
    "Disk & Forensic Images",
)

DEFAULT_SWEEP_SIZES: Tuple[int, ...] = (
    1 * KIB, 64 * KIB, 256 * KIB, 1 * MIB, 4 * MIB, 16 * MIB, 32 * MIB,
    64 * MIB, 128 * MIB, 256 * MIB, 512 * MIB, 1 * GIB,
)

ProgressCallback = Optional[Callable[[str, float], None]]


def classify_format(path: os.PathLike[str] | str) -> str:
    extension = Path(path).suffix.lower()
    for category, extensions in FORMAT_CATEGORIES:
        if extension in extensions:
            return category
    return "Other"


def size_tier(size_bytes: int) -> str:
    for label, low, high in SIZE_TIERS:
        if low <= size_bytes < high:
            return label
    return SIZE_TIERS[-1][0]


def format_size(size_bytes: float) -> str:
    value = float(size_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return ("%d %s" % (value, unit)) if unit == "B" else ("%.2f %s" % (value, unit))
        value /= 1024
    return "%.2f TiB" % value


def _write_deterministic(path: Path, size: int, seed: str) -> None:
    """Pseudo-random, reproducible content from the BLAKE3 extendable output."""
    generator = _blake3.blake3(("dataset:" + seed).encode("utf-8"))
    block = 8 * MIB
    with open(path, "wb") as output:
        offset = 0
        while offset < size:
            length = min(block, size - offset)
            output.write(generator.digest(length=length, seek=offset))
            offset += length


def generate_size_sweep(
    output_dir: os.PathLike[str] | str,
    sizes: Sequence[int] = DEFAULT_SWEEP_SIZES,
    *,
    seed: str = "thesis-size-sweep-v1",
    progress: ProgressCallback = None,
) -> List[Path]:
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    total = float(sum(sizes)) or 1.0
    done = 0
    for size in sizes:
        path = folder / ("sweep_%012d_bytes.bin" % size)
        if not (path.exists() and path.stat().st_size == size):
            _write_deterministic(path, int(size), "%s:%d" % (seed, size))
        written.append(path)
        done += size
        if progress:
            progress("Wrote %s (%s)" % (path.name, format_size(size)), done / total)
    return written


def generate_small_file_corpus(
    output_dir: os.PathLike[str] | str,
    *,
    count: int = 2000,
    min_size: int = 1 * KIB,
    max_size: int = 1 * MIB,
    seed: int = 0x5A11,
    progress: ProgressCallback = None,
) -> List[Path]:
    """Many small files with log-uniform sizes (typical of user-document trees)."""
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    low, high = math.log(min_size), math.log(max_size)
    written = []
    for index in range(int(count)):
        size = int(round(math.exp(rng.uniform(low, high))))
        path = folder / ("small_%05d.bin" % index)
        if not (path.exists() and path.stat().st_size == size):
            _write_deterministic(path, size, "small:%d:%d" % (seed, index))
        written.append(path)
        if progress and (index % 50 == 0 or index == count - 1):
            progress("Wrote %d of %d small files" % (index + 1, count), (index + 1) / count)
    return written


def iter_files(root: os.PathLike[str] | str) -> Iterable[Path]:
    for directory, _subdirs, files in os.walk(root):
        for name in sorted(files):
            if name.startswith("dataset_manifest") or name == "sources.json":
                continue
            yield Path(directory) / name


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb", buffering=0) as source:
        while True:
            block = source.read(4 * MIB)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _load_sources(root: Path) -> Dict[str, Any]:
    """Optional ``sources.json``: {"relative/path/or/folder": {"source": ..., "license": ...}}."""
    path = root / "sources.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _provenance(relative: str, sources: Dict[str, Any]) -> Dict[str, str]:
    best = ""
    for key in sources:
        normalized = key.replace("\\", "/").rstrip("/")
        if relative == normalized or relative.startswith(normalized + "/"):
            if len(normalized) > len(best):
                best = key
    if best:
        entry = sources[best]
        if isinstance(entry, dict):
            return {k: str(v) for k, v in entry.items()}
        return {"source": str(entry)}
    if relative.split("/")[-1].startswith(("sweep_", "small_")):
        return {"source": "generated by dataset_tool.py (deterministic)"}
    return {"source": "not documented — add to sources.json"}


def build_manifest(
    root: os.PathLike[str] | str,
    *,
    compute_hashes: bool = True,
    progress: ProgressCallback = None,
) -> Dict[str, Any]:
    root_path = Path(root).resolve()
    sources = _load_sources(root_path)
    paths = list(iter_files(root_path))
    total_bytes = float(sum(p.stat().st_size for p in paths)) or 1.0
    done = 0
    entries = []
    for path in paths:
        stat = path.stat()
        relative = path.relative_to(root_path).as_posix()
        entry: Dict[str, Any] = {
            "relative_path": relative,
            "size_bytes": int(stat.st_size),
            "extension": path.suffix.lower() or "(none)",
            "category": classify_format(path),
            "size_tier": size_tier(int(stat.st_size)),
            "modified_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
        }
        entry.update({"provenance_" + k: v for k, v in _provenance(relative, sources).items()})
        if compute_hashes:
            entry["sha256"] = _sha256_file(path)
        entries.append(entry)
        done += stat.st_size
        if progress:
            progress("Catalogued %s" % relative, done / total_bytes)

    categories = sorted({e["category"] for e in entries} | set(REQUIRED_CATEGORIES))
    tiers = [label for label, _low, _high in SIZE_TIERS]
    matrix = {c: {t: 0 for t in tiers} for c in categories}
    for entry in entries:
        matrix[entry["category"]][entry["size_tier"]] += 1

    gaps: List[str] = []
    for category in REQUIRED_CATEGORIES:
        if not any(matrix[category].values()):
            gaps.append("No %s files." % category)
    for tier in tiers:
        if not any(matrix[c][tier] for c in categories):
            gaps.append("No files in size tier %s." % tier)
    if not any(e["category"] == "Disk & Forensic Images" and e["size_tier"].startswith(("T5", "T6"))
               for e in entries):
        gaps.append("No disk/forensic image ≥ 128 MiB (representative evidence image).")
    small_count = sum(1 for e in entries if e["size_bytes"] < SMALL_FILE_LIMIT)
    if small_count < 500:
        gaps.append("Fewer than 500 small files; the batching experiment needs a larger set.")
    undocumented = sum(1 for e in entries if e.get("provenance_source", "").startswith("not documented"))
    if undocumented:
        gaps.append("%d file(s) have no documented source (add sources.json)." % undocumented)

    return {
        "schema_version": 1,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "root": str(root_path),
        "file_count": len(entries),
        "total_bytes": int(sum(e["size_bytes"] for e in entries)),
        "size_tiers": [{"label": l, "min_bytes": lo, "max_bytes_exclusive": hi}
                       for l, lo, hi in SIZE_TIERS],
        "coverage_matrix": matrix,
        "gaps": gaps,
        "files": entries,
        "notes": [
            "Size tiers follow the engine's adaptive-buffer and multithreading thresholds.",
            "Container images are hashed as stored files; the digest is not the acquisition hash.",
        ],
    }


def write_manifest(manifest: Dict[str, Any], output_dir: os.PathLike[str] | str) -> Tuple[Path, Path]:
    folder = Path(output_dir)
    json_path = folder / "dataset_manifest.json"
    csv_path = folder / "dataset_manifest.csv"
    json_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    columns = sorted({key for entry in manifest["files"] for key in entry},
                     key=lambda k: (k != "relative_path", k))
    with open(csv_path, "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        writer.writerows(manifest["files"])
    return json_path, csv_path


def verify_manifest(manifest_path: os.PathLike[str] | str) -> Dict[str, Any]:
    """Re-hash every file listed in a manifest and report changes."""
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    root = Path(manifest["root"])
    changed, missing = [], []
    for entry in manifest["files"]:
        path = root / entry["relative_path"]
        if not path.is_file():
            missing.append(entry["relative_path"])
        elif entry.get("sha256") and _sha256_file(path) != entry["sha256"]:
            changed.append(entry["relative_path"])
    return {"passed": not changed and not missing, "changed": changed, "missing": missing,
            "checked": len(manifest["files"])}


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sweep = sub.add_parser("sweep", help="generate size-sweep files")
    sweep.add_argument("output")
    sweep.add_argument("--max-size-mib", type=float, default=1024)
    small = sub.add_parser("small", help="generate a small-file corpus")
    small.add_argument("output")
    small.add_argument("--count", type=int, default=2000)
    man = sub.add_parser("manifest", help="catalogue a dataset folder")
    man.add_argument("root")
    ver = sub.add_parser("verify", help="re-check a dataset_manifest.json")
    ver.add_argument("manifest")
    args = parser.parse_args(argv)
    if args.command == "sweep":
        sizes = [s for s in DEFAULT_SWEEP_SIZES if s <= args.max_size_mib * MIB]
        for path in generate_size_sweep(args.output, sizes):
            print(path)
    elif args.command == "small":
        print("%d files written" % len(generate_small_file_corpus(args.output, count=args.count)))
    elif args.command == "manifest":
        manifest = build_manifest(args.root)
        for path in write_manifest(manifest, args.root):
            print(path)
        for gap in manifest["gaps"]:
            print("GAP:", gap)
    else:
        report = verify_manifest(args.manifest)
        print(json.dumps(report, indent=2))
        return 0 if report["passed"] else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
