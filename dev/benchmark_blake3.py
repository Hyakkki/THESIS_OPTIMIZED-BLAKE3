#!/usr/bin/env python3
"""Controlled technique-isolation benchmarks with statistical analysis.

Two experiments:

* **Large-file experiment** – a 2×2 factorial design over the two techniques
  that act on a single file: adaptive buffering (A) and multithreading (B).
  Cells: Baseline (A off, B off), Buffer only, Threads only, Optimized (both).
  SHA-256, SHA-1 and MD5 are measured with the Baseline I/O path as reference
  algorithms "as configured".
* **Small-file experiment** – a 2×2 factorial design over the techniques that
  act on many small files: batching and parallel dispatch.

Both use a randomized complete block design: each round runs every condition
once in a seeded random order. Warm-ups are excluded. Every execution must
reproduce the expected digest, otherwise the benchmark aborts. Statistics and
formulas are defined in this module
(``FORMULAS`` F1–F19 and ``STATISTICAL_PLAN``) so the documented methodology and the code
cannot silently disagree.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import random
import statistics
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import blake3 as _blake3

from dataset_tool import classify_format, size_tier
from optimized_blake3 import (
    BLAKE3_CONFIGS,
    DEFAULT_BATCH_SIZE,
    MIB,
    OperationCancelled,
    REFERENCE_ALGORITHMS,
    SMALL_FILE_LIMIT,
    SMALL_FILE_MODES,
    _MetricSampler,
    adaptive_chunk_size,
    detected_simd_tier,
    hash_file_config,
    hash_file_reference,
    hash_small_files,
    logical_cpu_count,
    make_worker_pool,
    physical_cpu_count,
    self_test,
    storage_profile,
    system_summary,
)

# ─────────────────────────────────────────────────────────────────────────────
# Formula registry (rendered by the Methodology tab and exported to Markdown)
# ─────────────────────────────────────────────────────────────────────────────

FORMULAS: List[Dict[str, str]] = [
    {
        "id": "F1", "name": "Elapsed time",
        "expression": "t = t_end − t_start",
        "symbols": "t_start, t_end: monotonic high-resolution clock (time.perf_counter_ns) "
                   "read immediately before opening the file and after digest finalization.",
        "function": "measured in optimized_blake3._MetricSampler",
    },
    {
        "id": "F2", "name": "Throughput",
        "expression": "T = (B / 2^20) / t",
        "symbols": "B: bytes hashed; t: elapsed time in seconds; T in MiB/s (1 MiB = 2^20 bytes).",
        "function": "throughput_mib_s",
    },
    {
        "id": "F3", "name": "Speedup",
        "expression": "S = median(t_baseline) / median(t_configuration)",
        "symbols": "S > 1 means the configuration is faster than the baseline.",
        "function": "speedup",
    },
    {
        "id": "F4", "name": "Percent time reduction",
        "expression": "R = (median(t_baseline) − median(t_configuration)) / median(t_baseline) × 100",
        "symbols": "R > 0 means less time than the baseline; R = (1 − 1/S) × 100.",
        "function": "percent_time_reduction",
    },
    {
        "id": "F5", "name": "Normalized CPU utilization",
        "expression": "U = (C / t) / N_logical × 100",
        "symbols": "C: process (and worker) CPU time in seconds; t: wall time; "
                   "N_logical: logical processors. U = 100 % means every logical CPU was busy.",
        "function": "normalized_cpu_percent",
    },
    {
        "id": "F6", "name": "Peak resident memory",
        "expression": "M = max_k RSS(τ_k)",
        "symbols": "RSS sampled every 10 ms during the measurement (process tree when worker "
                   "processes are used), reported in MiB.",
        "function": "measured in optimized_blake3._MetricSampler",
    },
    {
        "id": "F7", "name": "Median and interquartile range",
        "expression": "Md = Q2;  IQR = Q3 − Q1",
        "symbols": "Quartiles by the inclusive (linear interpolation) method. The median is the "
                   "primary location estimate because timing distributions are right-skewed.",
        "function": "describe",
    },
    {
        "id": "F8", "name": "Mean, sample standard deviation, coefficient of variation",
        "expression": "x̄ = Σx_i / n;  s = √(Σ(x_i − x̄)² / (n − 1));  CV = s / x̄ × 100",
        "symbols": "CV ≤ 10 % is used as the measurement-stability criterion.",
        "function": "describe",
    },
    {
        "id": "F9", "name": "Bootstrap percentile confidence interval",
        "expression": "CI_95 = [θ*_(0.025), θ*_(0.975)] over R resamples",
        "symbols": "θ*: statistic (median, or ratio of medians for speedup) recomputed on R = 5000 "
                   "resamples drawn with replacement; paired data resample whole trial indices. "
                   "Fixed seed for reproducibility.",
        "function": "bootstrap_ci, bootstrap_ratio_ci",
    },
    {
        "id": "F10", "name": "Wilcoxon signed-rank test (paired, two-sided)",
        "expression": "d_i = t_baseline,i − t_config,i;  W+ = Σ_{d_i>0} rank(|d_i|);  "
                      "z = (W+ − n(n+1)/4 ∓ 0.5) / √(n(n+1)(2n+1)/24 − Σ(t_j³ − t_j)/48)",
        "symbols": "Pairs are trials of the same round (block). Zero differences are dropped. "
                   "Exact null distribution for n ≤ 50 without ties; otherwise the normal "
                   "approximation with tie and continuity correction. H0: median difference = 0.",
        "function": "wilcoxon_signed_rank",
    },
    {
        "id": "F11", "name": "Matched-pairs rank-biserial correlation",
        "expression": "r_rb = (W+ − W−) / (n(n+1)/2)",
        "symbols": "Effect size for the Wilcoxon test, from −1 to 1.",
        "function": "wilcoxon_signed_rank",
    },
    {
        "id": "F12", "name": "Cliff's delta",
        "expression": "δ = (#{(i,j): x_i > y_j} − #{(i,j): x_i < y_j}) / (n·m)",
        "symbols": "x: baseline times, y: configuration times. |δ| < 0.147 negligible, "
                   "< 0.33 small, < 0.474 medium, otherwise large (Romano et al., 2006).",
        "function": "cliffs_delta",
    },
    {
        "id": "F13", "name": "Holm–Bonferroni adjustment",
        "expression": "p_(k),adj = max_{j ≤ k} min(1, (m − j + 1) · p_(j))",
        "symbols": "m comparisons against the same baseline, p-values sorted ascending. "
                   "Significance level α = 0.05 after adjustment.",
        "function": "holm_adjust",
    },
    {
        "id": "F14", "name": "Factorial technique effects (2×2 design)",
        "expression": "E_A = √(S_A · S_AB / S_B);  E_B = √(S_B · S_AB / S_A);  I = S_AB / (S_A · S_B)",
        "symbols": "S_A, S_B: speedup of each technique alone; S_AB: both together. E: geometric "
                   "mean effect of a technique across levels of the other. I > 1 synergy, "
                   "I < 1 the techniques overlap/interfere, I = 1 independent.",
        "function": "factorial_effects",
    },
    {
        "id": "F15", "name": "Hamming distance and avalanche ratio",
        "expression": "HD(h, h') = Σ_k popcount(h_k ⊕ h'_k);  A = HD / 256",
        "symbols": "h: digest of the original input; h': digest after flipping one input bit. "
                   "Ideal: E[HD] = 128, SD = √(256 · 0.25) = 8.",
        "function": "blake3_validation.avalanche_analysis",
    },
    {
        "id": "F16", "name": "Avalanche mean z-test",
        "expression": "z = (mean(HD) − 128) / (8 / √n)",
        "symbols": "Pass if |z| < 3.29 (two-sided p > 0.001).",
        "function": "blake3_validation.avalanche_analysis",
    },
    {
        "id": "F17", "name": "Chi-square goodness of fit to Binomial(256, 0.5)",
        "expression": "χ² = Σ_b (O_b − E_b)² / E_b,  df = bins − 1",
        "symbols": "O_b: observed Hamming distances in bin b; E_b = n · P(HD ∈ b) from the "
                   "binomial model; tails pooled so every E_b ≥ 5. Pass if p > 0.001.",
        "function": "chi_square_sf, binomial_bins",
    },
    {
        "id": "F18", "name": "Strict avalanche criterion (per output bit)",
        "expression": "p_j = (1/n) Σ_i [bit j of h ⊕ h'_i = 1],  j = 1..256",
        "symbols": "Ideal p_j = 0.5. Bits outside the 99.9 % binomial band "
                   "0.5 ± 3.29·√(0.25/n) are counted; about 0.26 of 256 are expected by chance.",
        "function": "blake3_validation.avalanche_analysis",
    },
    {
        "id": "F19", "name": "Output bit balance",
        "expression": "P1 = (Σ popcount(h)) / (256 · N)",
        "symbols": "Fraction of one-bits across N digests; ideal 0.5.",
        "function": "blake3_validation.bit_balance",
    },
]

STATISTICAL_PLAN = """\
Statistical analysis plan
=========================

Design. Randomized complete block design. Each trial round is a block in which
every configuration of the experiment is executed exactly once on the same file
(or file set), in a freshly shuffled order (seeded pseudo-random generator, so
the order is reproducible). Warm-up executions precede the measured rounds and
are excluded from analysis; their timings are retained separately.

Trials. 30 measured rounds per configuration by default (configurable in the
application; minimum 10). Two warm-up executions per configuration.

Primary indicator. Elapsed time t (F1), summarized by the median (F7). Throughput
(F2), normalized CPU utilization (F5) and peak memory (F6) are secondary.

Comparisons. Each configuration is compared with the baseline configuration on
the same file using
  1. speedup S (F3) and percent time reduction R (F4) of the medians, with a
     95 % paired bootstrap confidence interval for S (F9);
  2. the paired two-sided Wilcoxon signed-rank test (F10), with Holm–Bonferroni
     adjustment across all comparisons made against the same baseline (F13);
  3. effect sizes: Cliff's delta (F12) and matched-pairs rank-biserial
     correlation (F11).
A configuration is reported as significantly faster only when the Holm-adjusted
p < 0.05 and the whole 95 % CI of S lies above 1.

Isolation of techniques. Adaptive buffering and multithreading form a 2×2
factorial design on large files; parallel dispatch and batching form a 2×2
design on small-file workloads. Main effects and interaction are reported with
F14, so the contribution of each technique is measured separately and jointly.

Stability. Any configuration whose timing CV (F8) exceeds 10 %, or whose median
time is below 10 ms, is flagged; such results are reported but should be
re-measured on a quieter system or with a larger input.

Correctness gate. Every measured execution must reproduce the expected digest;
any disagreement between configurations aborts the benchmark instead of
producing timing results.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Performance indicators
# ─────────────────────────────────────────────────────────────────────────────

def throughput_mib_s(byte_count: float, seconds: float) -> float:
    """F2."""
    return (float(byte_count) / MIB) / float(seconds) if seconds > 0 else 0.0


def speedup(baseline_time: float, configuration_time: float) -> Optional[float]:
    """F3."""
    if baseline_time <= 0 or configuration_time <= 0:
        return None
    return float(baseline_time) / float(configuration_time)


def percent_time_reduction(baseline_time: float, configuration_time: float) -> Optional[float]:
    """F4."""
    if baseline_time <= 0 or configuration_time < 0:
        return None
    return (float(baseline_time) - float(configuration_time)) / float(baseline_time) * 100.0


def normalized_cpu_percent(cpu_seconds: float, wall_seconds: float, logical_cpus: int) -> Optional[float]:
    """F5."""
    if wall_seconds <= 0 or logical_cpus <= 0:
        return None
    return 100.0 * float(cpu_seconds) / float(wall_seconds) / float(logical_cpus)


# ─────────────────────────────────────────────────────────────────────────────
# Descriptive statistics
# ─────────────────────────────────────────────────────────────────────────────

def describe(values: Sequence[float]) -> Dict[str, Optional[float]]:
    """F7 and F8 for one sample."""
    data = [float(v) for v in values]
    if not data:
        return {key: None for key in (
            "n", "median", "q1", "q3", "iqr", "mean", "stdev", "cv_percent", "minimum", "maximum"
        )}
    if len(data) >= 2:
        q1, _q2, q3 = statistics.quantiles(data, n=4, method="inclusive")
    else:
        q1 = q3 = data[0]
    mean = statistics.fmean(data)
    stdev = statistics.stdev(data) if len(data) > 1 else 0.0
    return {
        "n": len(data),
        "median": statistics.median(data),
        "q1": q1,
        "q3": q3,
        "iqr": q3 - q1,
        "mean": mean,
        "stdev": stdev,
        "cv_percent": (stdev / mean * 100.0) if mean else None,
        "minimum": min(data),
        "maximum": max(data),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap (F9)
# ─────────────────────────────────────────────────────────────────────────────

def _percentile(sorted_values: Sequence[float], fraction: float) -> float:
    if not sorted_values:
        raise ValueError("empty sample")
    position = fraction * (len(sorted_values) - 1)
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return float(sorted_values[low])
    weight = position - low
    return float(sorted_values[low]) * (1 - weight) + float(sorted_values[high]) * weight


def bootstrap_ci(
    values: Sequence[float],
    statistic: Callable[[Sequence[float]], float] = statistics.median,
    *,
    resamples: int = 5000,
    confidence: float = 0.95,
    seed: int = 0xB007,
) -> Optional[List[float]]:
    data = list(values)
    if len(data) < 2:
        return None
    rng = random.Random(seed)
    n = len(data)
    estimates = sorted(
        statistic([data[rng.randrange(n)] for _ in range(n)]) for _ in range(resamples)
    )
    alpha = (1.0 - confidence) / 2.0
    return [_percentile(estimates, alpha), _percentile(estimates, 1.0 - alpha)]


def bootstrap_ratio_ci(
    baseline: Sequence[float],
    configuration: Sequence[float],
    *,
    resamples: int = 5000,
    confidence: float = 0.95,
    seed: int = 0xB007,
) -> Optional[List[float]]:
    """Paired bootstrap CI for S = median(baseline) / median(configuration)."""
    if len(baseline) != len(configuration):
        raise ValueError("paired samples must have equal length")
    n = len(baseline)
    if n < 2:
        return None
    rng = random.Random(seed)
    estimates: List[float] = []
    for _ in range(resamples):
        indexes = [rng.randrange(n) for _ in range(n)]
        denominator = statistics.median([configuration[i] for i in indexes])
        if denominator <= 0:
            continue
        estimates.append(statistics.median([baseline[i] for i in indexes]) / denominator)
    if not estimates:
        return None
    estimates.sort()
    alpha = (1.0 - confidence) / 2.0
    return [_percentile(estimates, alpha), _percentile(estimates, 1.0 - alpha)]


# ─────────────────────────────────────────────────────────────────────────────
# Hypothesis tests and effect sizes
# ─────────────────────────────────────────────────────────────────────────────

def _average_ranks(values: Sequence[float]) -> List[float]:
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        average = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = average
        i = j + 1
    return ranks


def _normal_two_sided_p(z: float) -> float:
    return math.erfc(abs(z) / math.sqrt(2.0))


def _wilcoxon_exact_cdf(n: int, w: int) -> float:
    """P(W+ ≤ w) under H0 for n untied, non-zero differences (ranks 1..n)."""
    max_sum = n * (n + 1) // 2
    counts = [0] * (max_sum + 1)
    counts[0] = 1
    for rank in range(1, n + 1):
        for total in range(max_sum, rank - 1, -1):
            counts[total] += counts[total - rank]
    return sum(counts[: w + 1]) / float(2 ** n)


def wilcoxon_signed_rank(
    baseline: Sequence[float], configuration: Sequence[float]
) -> Dict[str, Any]:
    """F10 and F11: paired two-sided Wilcoxon signed-rank test."""
    if len(baseline) != len(configuration):
        raise ValueError("paired samples must have equal length")
    differences = [float(a) - float(b) for a, b in zip(baseline, configuration)]
    nonzero = [d for d in differences if d != 0.0]
    n = len(nonzero)
    if n == 0:
        return {"n": 0, "w_plus": 0.0, "w_minus": 0.0, "z": 0.0, "p_value": 1.0,
                "rank_biserial": 0.0, "method": "all differences are zero"}
    ranks = _average_ranks([abs(d) for d in nonzero])
    w_plus = sum(r for r, d in zip(ranks, nonzero) if d > 0)
    w_minus = sum(r for r, d in zip(ranks, nonzero) if d < 0)
    total = n * (n + 1) / 2.0
    rank_biserial = (w_plus - w_minus) / total

    tie_groups: Dict[float, int] = {}
    for value in (abs(d) for d in nonzero):
        tie_groups[value] = tie_groups.get(value, 0) + 1
    tie_term = sum(t ** 3 - t for t in tie_groups.values() if t > 1)

    mean = n * (n + 1) / 4.0
    variance = n * (n + 1) * (2 * n + 1) / 24.0 - tie_term / 48.0
    if variance > 0:
        correction = 0.5 if w_plus > mean else (-0.5 if w_plus < mean else 0.0)
        z = (w_plus - mean - correction) / math.sqrt(variance)
    else:
        z = 0.0

    if tie_term == 0 and n <= 50:
        w_small = int(round(min(w_plus, w_minus)))
        p_value = min(1.0, 2.0 * _wilcoxon_exact_cdf(n, w_small))
        method = "exact"
    else:
        p_value = _normal_two_sided_p(z)
        method = "normal approximation (tie + continuity corrected)"
    return {
        "n": n,
        "w_plus": w_plus,
        "w_minus": w_minus,
        "z": z,
        "p_value": p_value,
        "rank_biserial": rank_biserial,
        "method": method,
    }


def cliffs_delta(baseline: Sequence[float], configuration: Sequence[float]) -> Dict[str, Any]:
    """F12. Positive delta: baseline values tend to be larger (configuration faster)."""
    if not baseline or not configuration:
        return {"delta": None, "magnitude": "n/a"}
    greater = less = 0
    for x in baseline:
        for y in configuration:
            if x > y:
                greater += 1
            elif x < y:
                less += 1
    delta = (greater - less) / float(len(baseline) * len(configuration))
    size = abs(delta)
    if size < 0.147:
        magnitude = "negligible"
    elif size < 0.33:
        magnitude = "small"
    elif size < 0.474:
        magnitude = "medium"
    else:
        magnitude = "large"
    return {"delta": delta, "magnitude": magnitude}


def holm_adjust(p_values: Sequence[Optional[float]]) -> List[Optional[float]]:
    """F13. ``None`` entries are passed through and not counted."""
    indexed = [(p, i) for i, p in enumerate(p_values) if p is not None]
    m = len(indexed)
    adjusted: List[Optional[float]] = [None] * len(p_values)
    running = 0.0
    for rank, (p, index) in enumerate(sorted(indexed)):
        running = max(running, min(1.0, (m - rank) * p))
        adjusted[index] = running
    return adjusted


def factorial_effects(s_a: float, s_b: float, s_ab: float) -> Dict[str, Optional[float]]:
    """F14 on speedups relative to the shared baseline (both factors off)."""
    if not all(value and value > 0 for value in (s_a, s_b, s_ab)):
        return {"effect_a": None, "effect_b": None, "interaction": None}
    return {
        "effect_a": math.sqrt(s_a * s_ab / s_b),
        "effect_b": math.sqrt(s_b * s_ab / s_a),
        "interaction": s_ab / (s_a * s_b),
    }


def compare_to_baseline(
    baseline_times: Sequence[float],
    configuration_times: Sequence[float],
    *,
    seed: int = 0xB007,
) -> Dict[str, Any]:
    """Everything the analysis plan reports for one configuration vs baseline."""
    base_median = statistics.median(baseline_times)
    config_median = statistics.median(configuration_times)
    test = wilcoxon_signed_rank(baseline_times, configuration_times)
    effect = cliffs_delta(baseline_times, configuration_times)
    return {
        "speedup": speedup(base_median, config_median),
        "speedup_ci95": bootstrap_ratio_ci(baseline_times, configuration_times, seed=seed),
        "percent_time_reduction": percent_time_reduction(base_median, config_median),
        "wilcoxon": test,
        "p_value": test["p_value"],
        "cliffs_delta": effect["delta"],
        "cliffs_magnitude": effect["magnitude"],
    }


def verdict(comparison: Dict[str, Any], alpha: float = 0.05) -> str:
    """Plain-language outcome used in tables, per the decision rule in the plan."""
    p_adj = comparison.get("p_holm")
    ci = comparison.get("speedup_ci95")
    if p_adj is None or ci is None:
        return "insufficient data"
    if p_adj < alpha and ci[0] > 1.0:
        return "significantly faster"
    if p_adj < alpha and ci[1] < 1.0:
        return "significantly slower"
    return "no significant difference"


# ─────────────────────────────────────────────────────────────────────────────
# Distributions used by the avalanche analysis (F17)
# ─────────────────────────────────────────────────────────────────────────────

def _lower_gamma_series(a: float, x: float) -> float:
    term = 1.0 / a
    total = term
    ap = a
    for _ in range(10000):
        ap += 1.0
        term *= x / ap
        total += term
        if abs(term) < abs(total) * 1e-15:
            break
    return total * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _upper_gamma_continued_fraction(a: float, x: float) -> float:
    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 10000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def chi_square_sf(statistic: float, degrees_of_freedom: int) -> float:
    """Upper-tail probability P(χ²_df ≥ statistic) via the regularized gamma Q."""
    if statistic <= 0:
        return 1.0
    a = degrees_of_freedom / 2.0
    x = statistic / 2.0
    if x < a + 1.0:
        return max(0.0, 1.0 - _lower_gamma_series(a, x))
    return min(1.0, _upper_gamma_continued_fraction(a, x))


def binomial_bins(n_trials: int, p: float, sample_size: int, min_expected: float = 5.0):
    """Bins [lo, hi] over 0..n_trials whose expected counts are all ≥ min_expected."""
    pmf = [math.comb(n_trials, k) * p ** k * (1 - p) ** (n_trials - k) for k in range(n_trials + 1)]
    bins = []
    lo = 0
    accumulated = 0.0
    for k in range(n_trials + 1):
        accumulated += pmf[k]
        if accumulated * sample_size >= min_expected:
            bins.append([lo, k, accumulated])
            lo = k + 1
            accumulated = 0.0
    if accumulated > 0:
        if bins:
            bins[-1][1] = n_trials
            bins[-1][2] += accumulated
        else:
            bins.append([0, n_trials, accumulated])
    return [(lo, hi, probability * sample_size) for lo, hi, probability in bins]


# ─────────────────────────────────────────────────────────────────────────────
# Experiment settings
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_TRIALS = 30
DEFAULT_WARMUPS = 2
MIN_TRIALS = 10
CV_LIMIT_PERCENT = 10.0
SHORT_MEASUREMENT_MS = 10.0

ProgressCallback = Optional[Callable[[str, float], None]]

# Backward-compatible names.
optimization_percent = percent_time_reduction


class BenchmarkCancelled(OperationCancelled):
    """Raised when the caller's cancel event is set between executions."""


def host_information() -> Dict[str, Any]:
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "processor": system_summary()["cpu_model"],
        "memory_gib": system_summary()["memory_gib"],
        "logical_cpu_count": logical_cpu_count(),
        "physical_cpu_count": physical_cpu_count(),
        "blake3_package_version": str(getattr(_blake3, "__version__", "unknown")),
        "simd_tier": detected_simd_tier(),
        "simd_note": "Native SIMD dispatch is identical in every BLAKE3 configuration "
                     "(held constant; not a studied technique).",
    }


def planned_read_bytes(sizes: Sequence[int], trials: int, warmups: int,
                       include_references: bool = True) -> int:
    """Total bytes a large-file experiment will read (to warn before huge runs)."""
    conditions = len(BLAKE3_CONFIGS) + (len(REFERENCE_ALGORITHMS) if include_references else 0)
    return int(sum(sizes)) * conditions * (int(trials) + int(warmups))


def _check_cancel(cancel: Optional[threading.Event]) -> None:
    if cancel is not None and cancel.is_set():
        raise BenchmarkCancelled("benchmark cancelled by user")


class _Progress:
    """Progress fractions plus a simple remaining-time estimate."""

    def __init__(self, callback: ProgressCallback, total_steps: int):
        self.callback = callback
        self.total = max(1, total_steps)
        self.done = 0
        self.started = time.perf_counter()

    def step(self, message: str) -> None:
        self.done += 1
        if self.callback is None:
            return
        fraction = min(1.0, self.done / self.total)
        elapsed = time.perf_counter() - self.started
        if 0 < fraction < 1:
            remaining = elapsed / fraction - elapsed
            message += "  ·  about %s left" % _format_duration(remaining)
        self.callback(message, fraction)


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "%d s" % seconds
    if seconds < 3600:
        return "%d min %d s" % divmod(seconds, 60)
    hours, rest = divmod(seconds, 3600)
    return "%d h %d min" % (hours, rest // 60)


def _summarize_condition(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    elapsed = [run["elapsed_ms"] for run in runs]
    throughput = [run["throughput_mib_s"] for run in runs]
    cpu = [run["cpu_percent"] for run in runs if run.get("cpu_percent") is not None]
    rss = [run["peak_rss_mib"] for run in runs if run.get("peak_rss_mib") is not None]
    time_stats = describe(elapsed)
    return {
        "elapsed_ms": time_stats,
        "elapsed_median_ci95": bootstrap_ci(elapsed),
        "throughput_mib_s": describe(throughput),
        "cpu_percent_median": statistics.median(cpu) if cpu else None,
        "peak_rss_mib_median": statistics.median(rss) if rss else None,
        "stable": (time_stats["cv_percent"] or 0.0) <= CV_LIMIT_PERCENT
        and (time_stats["median"] or 0.0) >= SHORT_MEASUREMENT_MS,
    }


def _comparisons(
    by_condition: Dict[str, List[float]],
    pairs: Sequence[Tuple[str, str, str]],
    seed: int,
) -> List[Dict[str, Any]]:
    """``pairs``: (family, slower/reference key, faster/candidate key)."""
    results: List[Dict[str, Any]] = []
    for family, reference, candidate in pairs:
        if reference not in by_condition or candidate not in by_condition:
            continue
        comparison = compare_to_baseline(
            by_condition[reference], by_condition[candidate], seed=seed
        )
        comparison.update({"family": family, "reference": reference, "candidate": candidate})
        results.append(comparison)
    for family in {item["family"] for item in results}:
        members = [item for item in results if item["family"] == family]
        for item, adjusted in zip(members, holm_adjust([m["p_value"] for m in members])):
            item["p_holm"] = adjusted
    for item in results:
        item["verdict"] = verdict(item)
    return results


def _paired_times(runs: List[Dict[str, Any]], keys: Sequence[str]) -> Dict[str, List[float]]:
    """Elapsed times per condition ordered by round, so index i pairs block i."""
    table: Dict[str, Dict[int, float]] = {key: {} for key in keys}
    for run in runs:
        if run["condition"] in table:
            table[run["condition"]][run["round"]] = run["elapsed_ms"]
    rounds = sorted(set.intersection(*(set(v) for v in table.values()))) if table else []
    return {key: [table[key][r] for r in rounds] for key in keys}


def _warnings_for(summary: Dict[str, Dict[str, Any]], labels: Dict[str, str]) -> List[str]:
    warnings = []
    for key, item in summary.items():
        stats = item["elapsed_ms"]
        if stats["median"] is not None and stats["median"] < SHORT_MEASUREMENT_MS:
            warnings.append("%s: median below %.0f ms; timer and sampling noise dominate — "
                            "use a larger input." % (labels[key], SHORT_MEASUREMENT_MS))
        if stats["cv_percent"] is not None and stats["cv_percent"] > CV_LIMIT_PERCENT:
            warnings.append("%s: CV %.1f %% exceeds %.0f %%; re-run on a quieter system."
                            % (labels[key], stats["cv_percent"], CV_LIMIT_PERCENT))
    return warnings


# ─────────────────────────────────────────────────────────────────────────────
# Experiment 1: large files (adaptive buffering × multithreading)
# ─────────────────────────────────────────────────────────────────────────────

def _large_conditions(include_references: bool, threads: Optional[int]):
    conditions = []
    for config in BLAKE3_CONFIGS:
        conditions.append((config.key, config.label, "blake3",
                           lambda p, c=config: hash_file_config(p, c, threads=threads)))
    if include_references:
        for algorithm, label in REFERENCE_ALGORITHMS:
            conditions.append((algorithm, label, "reference",
                               lambda p, a=algorithm: hash_file_reference(p, a)))
    return conditions


def run_large_file_ablation(
    paths: Sequence[os.PathLike[str] | str],
    *,
    trials: int = DEFAULT_TRIALS,
    warmups: int = DEFAULT_WARMUPS,
    include_references: bool = True,
    threads: Optional[int] = None,
    seed: int = 0xC0DE,
    progress: ProgressCallback = None,
    cancel: Optional[threading.Event] = None,
) -> Dict[str, Any]:
    if trials < 1 or warmups < 0:
        raise ValueError("trials must be ≥ 1 and warmups ≥ 0")
    files = [str(Path(p).resolve()) for p in paths]
    if not files:
        raise ValueError("select at least one file")
    conditions = _large_conditions(include_references, threads)
    labels = {key: label for key, label, _kind, _fn in conditions}
    kinds = {key: kind for key, _label, kind, _fn in conditions}
    tracker = _Progress(progress, len(files) * len(conditions) * (trials + warmups))
    validation = self_test()
    if not validation["passed"]:
        raise RuntimeError("engine self-test failed: " + validation["message"])

    all_runs: List[Dict[str, Any]] = []
    file_reports: List[Dict[str, Any]] = []
    for file_index, path in enumerate(files):
        name = os.path.basename(path)
        before = os.stat(path)
        size = int(before.st_size)
        expected: Dict[str, str] = {}
        warmup_records: List[Dict[str, Any]] = []
        file_runs: List[Dict[str, Any]] = []

        def execute(key: str, fn, round_number: int, position: int, warmup: bool):
            _check_cancel(cancel)
            result = fn(path)
            if result.status != "ok":
                raise RuntimeError("%s failed on %s: %s" % (labels[key], name, result.error))
            # BLAKE3 configurations must all agree; each reference must be stable.
            digest_group = "blake3" if kinds[key] == "blake3" else key
            reference_digest = expected.setdefault(digest_group, result.digest)
            if result.digest != reference_digest:
                raise RuntimeError("digest mismatch: %s produced a different digest for %s; "
                                   "results discarded" % (labels[key], name))
            record = {
                "file": name, "path": path, "size_bytes": size,
                "category": classify_format(path), "size_tier": size_tier(size),
                "round": round_number, "position": position, "warmup": warmup,
                "condition": key, "label": labels[key], "kind": kinds[key],
                "elapsed_ms": result.elapsed_ms,
                "throughput_mib_s": result.throughput_mb_s,
                "cpu_percent": result.cpu_utilization_percent,
                "process_cpu_percent": result.process_cpu_percent,
                "peak_rss_mib": result.peak_rss_mb,
                "buffer_bytes": result.chunk_size,
                "threads": result.threads_used,
                "io_strategy": result.io_strategy,
                "digest": result.digest,
            }
            tracker.step("%s · %s · %s %d" % (
                name, labels[key], "warm-up" if warmup else "round", round_number))
            return record

        for warmup_number in range(1, warmups + 1):
            order = list(conditions)
            random.Random(seed ^ (file_index << 16) ^ (0xAAAA + warmup_number)).shuffle(order)
            for position, (key, _label, _kind, fn) in enumerate(order, 1):
                warmup_records.append(execute(key, fn, warmup_number, position, True))

        for round_number in range(1, trials + 1):
            order = list(conditions)
            random.Random(seed ^ (file_index << 16) ^ round_number).shuffle(order)
            for position, (key, _label, _kind, fn) in enumerate(order, 1):
                file_runs.append(execute(key, fn, round_number, position, False))

        after = os.stat(path)
        if int(after.st_size) != size or int(after.st_mtime_ns) != int(before.st_mtime_ns):
            raise RuntimeError("file changed during benchmark: %s" % name)

        keys = [key for key, *_ in conditions]
        summary = {key: _summarize_condition([r for r in file_runs if r["condition"] == key])
                   for key in keys}
        for key in keys:
            summary[key].update({"label": labels[key], "kind": kinds[key]})
            first = next((r for r in warmup_records if r["condition"] == key), None)
            summary[key]["first_warmup_ms"] = first["elapsed_ms"] if first else None
            sample = next(r for r in file_runs if r["condition"] == key)
            summary[key].update({"buffer_bytes": sample["buffer_bytes"],
                                 "threads": sample["threads"],
                                 "io_strategy": sample["io_strategy"]})
        paired = _paired_times(file_runs, keys)
        pairs = [("technique", "baseline", c.key) for c in BLAKE3_CONFIGS[1:]]
        if include_references:
            pairs += [("reference", algorithm, "optimized") for algorithm, _ in REFERENCE_ALGORITHMS]
        comparisons = _comparisons(paired, pairs, seed)
        speedups = {c["candidate"]: c["speedup"] for c in comparisons if c["family"] == "technique"}
        factorial = factorial_effects(
            speedups.get("buffer_only"), speedups.get("threads_only"), speedups.get("optimized"))
        factorial.update({"factor_a": "adaptive buffering", "factor_b": "multithreading"})
        warnings = _warnings_for(summary, labels)
        if size < SMALL_FILE_LIMIT:
            warnings.append("File is below the %s multithreading threshold, so 'Multithreading "
                            "only' equals Baseline by design." % _mib(SMALL_FILE_LIMIT))
        file_reports.append({
            "file": name, "path": path, "size_bytes": size,
            "category": classify_format(path), "size_tier": size_tier(size),
            "adaptive_buffer_bytes": adaptive_chunk_size(size),
            "storage": {k: v for k, v in storage_profile(path).items()
                        if k in ("kind", "drive_type", "seek_penalty")},
            "blake3_digest": expected.get("blake3", ""),
            "conditions": summary, "comparisons": comparisons,
            "factorial": factorial, "warnings": warnings,
            "warmup_runs": warmup_records,
        })
        all_runs.extend(file_runs)

    return {
        "schema_version": 3,
        "experiment": "large-file technique isolation (adaptive buffering × multithreading)",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": host_information(),
        "self_test": validation,
        "design": _design(trials, warmups, seed),
        "conditions": [{"key": k, "label": l, "kind": kd} for k, l, kd, _ in conditions],
        "files": file_reports,
        "tier_summary": _tier_summary(file_reports),
        "runs": all_runs,
        "warnings": [w for report in file_reports for w in
                     ("%s: %s" % (report["file"], text) for text in report["warnings"])]
        + ([] if trials >= MIN_TRIALS else
           ["Fewer than %d trials: treat results as preliminary." % MIN_TRIALS]),
    }


def _mib(value: int) -> str:
    return "%d MiB" % (value // MIB)


def _design(trials: int, warmups: int, seed: int) -> Dict[str, Any]:
    return {
        "type": "randomized complete block design (round = block)",
        "measured_trials_per_condition": trials,
        "warmups_per_condition": warmups,
        "order_seed": seed,
        "cache_state": "warm (file pages cached by the OS after warm-ups); first warm-up "
                       "timings are retained separately as first-access observations",
        "timing_scope": "open + read + hash + digest finalization (F1)",
        "primary_indicator": "elapsed time, median (F1, F7)",
        "tests": "paired Wilcoxon signed-rank (F10) with Holm adjustment per family (F13); "
                 "bootstrap 95 % CI of speedup (F9); Cliff's delta (F12)",
        "alpha": 0.05,
        "formulas": "see FORMULAS",
    }


def _geometric_mean(values: Sequence[float]) -> Optional[float]:
    values = [v for v in values if v and v > 0]
    if not values:
        return None
    return math.exp(sum(math.log(v) for v in values) / len(values))


def _tier_summary(file_reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    tiers = sorted({report["size_tier"] for report in file_reports})
    for tier in tiers:
        members = [r for r in file_reports if r["size_tier"] == tier]
        for candidate in [c.key for c in BLAKE3_CONFIGS[1:]]:
            items = [c for r in members for c in r["comparisons"]
                     if c["family"] == "technique" and c["candidate"] == candidate]
            if not items:
                continue
            rows.append({
                "size_tier": tier,
                "condition": candidate,
                "files": len(items),
                "geometric_mean_speedup": _geometric_mean([i["speedup"] for i in items]),
                "significantly_faster": sum(1 for i in items if i["verdict"] == "significantly faster"),
                "significantly_slower": sum(1 for i in items if i["verdict"] == "significantly slower"),
            })
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Experiment 2: small files (parallel dispatch × batching)
# ─────────────────────────────────────────────────────────────────────────────

def run_small_file_ablation(
    paths: Sequence[os.PathLike[str] | str],
    *,
    trials: int = DEFAULT_TRIALS,
    warmups: int = DEFAULT_WARMUPS,
    workers: Optional[int] = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    seed: int = 0x5EED,
    progress: ProgressCallback = None,
    cancel: Optional[threading.Event] = None,
) -> Dict[str, Any]:
    candidates = [str(Path(p).resolve()) for p in paths]
    files = [p for p in candidates if os.path.getsize(p) < SMALL_FILE_LIMIT]
    excluded = len(candidates) - len(files)
    if len(files) < 2:
        raise ValueError("the small-file experiment needs at least two files below %s"
                         % _mib(SMALL_FILE_LIMIT))
    total_bytes = sum(os.path.getsize(p) for p in files)
    snapshot = {p: os.stat(p).st_mtime_ns for p in files}
    labels = {mode.key: mode.label for mode in SMALL_FILE_MODES}
    tracker = _Progress(progress, len(SMALL_FILE_MODES) * (trials + warmups) + 2)

    expected = hash_small_files(files, "sequential")  # outside timing
    tracker.step("Computed reference digests for %d files" % len(files))
    pool, pool_startup_s = make_worker_pool(workers)
    worker_count = max(1, int(workers or physical_cpu_count()))
    tracker.step("Started %d worker processes (%.3f s, reported separately)"
                 % (worker_count, pool_startup_s))
    runs: List[Dict[str, Any]] = []
    warmup_records: List[Dict[str, Any]] = []
    try:
        def execute(mode, round_number, position, warmup):
            _check_cancel(cancel)
            sampler = _MetricSampler(True, include_children=mode.parallel)
            with sampler:
                results = hash_small_files(files, mode, pool=pool, batch_size=batch_size)
                elapsed_s, cpu, process_cpu, rss = sampler.finish()
            if results != expected:
                raise RuntimeError("digest mismatch in mode %s; results discarded" % mode.label)
            record = {
                "round": round_number, "position": position, "warmup": warmup,
                "condition": mode.key, "label": mode.label,
                "files": len(files), "total_bytes": total_bytes,
                "elapsed_ms": round(elapsed_s * 1000.0, 3),
                "throughput_mib_s": round(throughput_mib_s(total_bytes, elapsed_s), 3),
                "files_per_second": round(len(files) / elapsed_s, 3) if elapsed_s else 0.0,
                "cpu_percent": round(cpu, 3) if cpu is not None else None,
                "process_cpu_percent": round(process_cpu, 3) if process_cpu is not None else None,
                "peak_rss_mib": rss,
                "workers": worker_count if mode.parallel else 1,
                "batch_size": batch_size if mode.batched else 1,
            }
            tracker.step("%s · %s %d" % (mode.label, "warm-up" if warmup else "round", round_number))
            return record

        for warmup_number in range(1, warmups + 1):
            order = list(SMALL_FILE_MODES)
            random.Random(seed ^ (0xAAAA + warmup_number)).shuffle(order)
            for position, mode in enumerate(order, 1):
                warmup_records.append(execute(mode, warmup_number, position, True))
        for round_number in range(1, trials + 1):
            order = list(SMALL_FILE_MODES)
            random.Random(seed ^ round_number).shuffle(order)
            for position, mode in enumerate(order, 1):
                runs.append(execute(mode, round_number, position, False))
    finally:
        pool.shutdown(wait=True, cancel_futures=True)

    for path, mtime in snapshot.items():
        if os.stat(path).st_mtime_ns != mtime:
            raise RuntimeError("file changed during benchmark: %s" % path)

    keys = [mode.key for mode in SMALL_FILE_MODES]
    summary = {key: _summarize_condition([r for r in runs if r["condition"] == key]) for key in keys}
    for key in keys:
        files_per_second = [r["files_per_second"] for r in runs if r["condition"] == key]
        summary[key].update({
            "label": labels[key],
            "files_per_second_median": statistics.median(files_per_second),
            "first_warmup_ms": next((r["elapsed_ms"] for r in warmup_records
                                     if r["condition"] == key), None),
        })
    paired = _paired_times(runs, keys)
    comparisons = _comparisons(paired, [("technique", "sequential", key) for key in keys[1:]], seed)
    speedups = {c["candidate"]: c["speedup"] for c in comparisons}
    factorial = factorial_effects(
        speedups.get("sequential_batched"), speedups.get("parallel"), speedups.get("parallel_batched"))
    factorial.update({"factor_a": "batching", "factor_b": "parallel dispatch"})
    sizes = [os.path.getsize(p) for p in files]
    return {
        "schema_version": 3,
        "experiment": "small-file technique isolation (batching × parallel dispatch)",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": host_information(),
        "design": dict(_design(trials, warmups, seed),
                       timing_scope="dispatch + open + read + hash + digest finalization for the "
                                    "whole file set (F1); worker-pool start-up excluded and "
                                    "reported separately",
                       cpu_scope="process tree (parent + worker processes) for parallel modes"),
        "workload": {
            "files": len(files), "excluded_large_files": excluded,
            "total_bytes": total_bytes, "median_file_bytes": statistics.median(sizes),
            "min_file_bytes": min(sizes), "max_file_bytes": max(sizes),
            "workers": worker_count, "batch_size": batch_size,
            "pool_startup_seconds": round(pool_startup_s, 4),
        },
        "conditions": [{"key": m.key, "label": m.label, "parallel": m.parallel,
                        "batched": m.batched} for m in SMALL_FILE_MODES],
        "summary": summary,
        "comparisons": comparisons,
        "factorial": factorial,
        "warnings": _warnings_for(summary, labels)
        + ([] if trials >= MIN_TRIALS else
           ["Fewer than %d trials: treat results as preliminary." % MIN_TRIALS])
        + (["Peak memory of parallel modes includes idle worker processes; compare memory "
            "within the same dispatch level."]),
        "warmup_runs": warmup_records,
        "runs": runs,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────────────────

def write_runs_csv(path: os.PathLike[str] | str, runs: List[Dict[str, Any]]) -> None:
    if not runs:
        return
    columns = list(runs[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(runs)


def summary_rows(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flat per-condition rows (one per file × condition) for spreadsheets."""
    groups = report["files"] if "files" in report else [dict(
        file="small-file workload (%d files)" % report["workload"]["files"],
        size_bytes=report["workload"]["total_bytes"], size_tier="", category="",
        conditions=report["summary"], comparisons=report["comparisons"])]
    rows = []
    for group in groups:
        comparisons = {c["candidate"]: c for c in group["comparisons"] if c["family"] == "technique"}
        references = {c["reference"]: c for c in group["comparisons"] if c["family"] == "reference"}
        for key, item in group["conditions"].items():
            comparison = comparisons.get(key) or references.get(key) or {}
            ci = item["elapsed_median_ci95"] or [None, None]
            speedup_ci = comparison.get("speedup_ci95") or [None, None]
            rows.append({
                "file": group["file"], "size_bytes": group["size_bytes"],
                "size_tier": group["size_tier"], "category": group["category"],
                "condition": key, "label": item["label"],
                "median_ms": item["elapsed_ms"]["median"],
                "median_ci95_low_ms": ci[0], "median_ci95_high_ms": ci[1],
                "iqr_ms": item["elapsed_ms"]["iqr"], "mean_ms": item["elapsed_ms"]["mean"],
                "stdev_ms": item["elapsed_ms"]["stdev"], "cv_percent": item["elapsed_ms"]["cv_percent"],
                "median_throughput_mib_s": item["throughput_mib_s"]["median"],
                "median_cpu_percent": item["cpu_percent_median"],
                "median_peak_rss_mib": item["peak_rss_mib_median"],
                "comparison": ("%s vs %s" % (comparison["candidate"], comparison["reference"])
                               if comparison else ""),
                "speedup": comparison.get("speedup"),
                "speedup_ci95_low": speedup_ci[0], "speedup_ci95_high": speedup_ci[1],
                "percent_time_reduction": comparison.get("percent_time_reduction"),
                "wilcoxon_p": comparison.get("p_value"), "p_holm": comparison.get("p_holm"),
                "cliffs_delta": comparison.get("cliffs_delta"),
                "cliffs_magnitude": comparison.get("cliffs_magnitude"),
                "verdict": comparison.get("verdict", "reference condition"),
            })
    return rows


def write_summary_csv(path: os.PathLike[str] | str, report: Dict[str, Any]) -> None:
    rows = summary_rows(report)
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def export_report(report: Dict[str, Any], folder: os.PathLike[str] | str, stem: str) -> Dict[str, str]:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": str(folder / (stem + ".json")),
        "runs_csv": str(folder / (stem + "_runs.csv")),
        "summary_csv": str(folder / (stem + "_summary.csv")),
    }
    Path(paths["json"]).write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_runs_csv(paths["runs_csv"], report["runs"])
    write_summary_csv(paths["summary_csv"], report)
    return paths


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="experiment", required=True)
    for name in ("large", "small"):
        command = sub.add_parser(name)
        command.add_argument("paths", nargs="+", help="files, or one folder for 'small'")
        command.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
        command.add_argument("--warmups", type=int, default=DEFAULT_WARMUPS)
        command.add_argument("--output", default=".", help="folder for JSON/CSV results")
        if name == "large":
            command.add_argument("--no-references", action="store_true")
        else:
            command.add_argument("--workers", type=int)
            command.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    args = parser.parse_args(argv)
    printer = lambda message, fraction: print("[%5.1f%%] %s" % (fraction * 100, message), file=sys.stderr)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    if args.experiment == "large":
        report = run_large_file_ablation(
            args.paths, trials=args.trials, warmups=args.warmups,
            include_references=not args.no_references, progress=printer)
        written = export_report(report, args.output, "large_file_ablation_" + stamp)
    else:
        paths = args.paths
        if len(paths) == 1 and os.path.isdir(paths[0]):
            paths = [str(p) for p in sorted(Path(paths[0]).rglob("*")) if p.is_file()]
        report = run_small_file_ablation(
            paths, trials=args.trials, warmups=args.warmups,
            workers=args.workers, batch_size=args.batch_size, progress=printer)
        written = export_report(report, args.output, "small_file_ablation_" + stamp)
    print(json.dumps(written, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
