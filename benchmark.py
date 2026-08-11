import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

from blake3_engine import (
    benchmark_files,
    benchmark_files_parallel,
    gather_files,
    get_simd_summary,
    summarize_rows,
    validate_consistency,
    write_benchmark_csv,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark baseline and optimized BLAKE3 without modifying the BLAKE3 source code. "
            "Optimizations are applied only in caller-side I/O and scheduling."
        )
    )
    parser.add_argument("dataset", help="Path to a file or folder containing test files")
    parser.add_argument("--repeats", type=int, default=3, help="Runs per file per mode (default: 3)")
    parser.add_argument("--parallel", action="store_true", help="Enable parallel execution across files")
    parser.add_argument("--workers", type=int, default=None, help="Worker count for --parallel")
    parser.add_argument("--include-blake2", action="store_true", help="Also include hashlib.blake2b baseline")
    parser.add_argument(
        "--output",
        default=None,
        help="Output CSV path. Defaults to artifacts/benchmark_results_YYYYMMDD_HHMMSS.csv",
    )
    return parser


def print_summary(summary: dict[str, dict[str, float]]) -> None:
    print("\n" + "=" * 90)
    print(f"  {'Mode':<30} {'Avg (MB/s)':>12} {'StdDev':>10} {'Min':>10} {'Max':>10} {'Elapsed (s)':>12}")
    print("=" * 90)
    for key in sorted(summary.keys()):
        stats = summary[key]
        print(
            f"  {key:<30} "
            f"{stats['avg_throughput_mb_s']:>12.2f} "
            f"{stats['stddev_throughput_mb_s']:>10.2f} "
            f"{stats['min_throughput_mb_s']:>10.2f} "
            f"{stats['max_throughput_mb_s']:>10.2f} "
            f"{stats['avg_elapsed_s']:>12.4f}"
        )
    print("=" * 90)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.repeats < 1:
        print("Error: --repeats must be >= 1", file=sys.stderr)
        return 2

    dataset = os.path.abspath(args.dataset)
    if not os.path.exists(dataset):
        print(f"Error: dataset path not found: {dataset}", file=sys.stderr)
        return 2

    file_paths = gather_files(dataset, recursive=True)
    if not file_paths:
        print("Error: no files found in dataset path", file=sys.stderr)
        return 2

    if args.parallel:
        rows = benchmark_files_parallel(
            file_paths=file_paths,
            repeats=args.repeats,
            workers=args.workers,
            include_blake2=args.include_blake2,
        )
    else:
        rows = benchmark_files(
            file_paths=file_paths,
            repeats=args.repeats,
            include_blake2=args.include_blake2,
        )

    issues = validate_consistency(rows)
    summary = summarize_rows(rows)

    output = args.output
    if output is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        script_dir = Path(__file__).resolve().parent
        artifacts_dir = script_dir / "artifacts"  
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        output = str((artifacts_dir / f"benchmark_results_{ts}.csv").resolve())

    write_benchmark_csv(rows, output)

    print(f"SIMD capabilities: {get_simd_summary()}")
    print(f"Files processed: {len(file_paths)}")
    print(f"Rows written: {len(rows)}")
    print(f"CSV output: {output}")
    print_summary(summary)

    if issues:
        print("\nConsistency issues detected:")
        for issue in issues:
            print(f"- {issue}")
        return 1

    print("\nConsistency checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
