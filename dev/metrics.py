#!/usr/bin/env python3
"""Performance indicators, statistical tests, and their formal definitions.

Every number the toolkit reports is computed by a function in this module, and
every function is registered in ``FORMULAS`` with the exact expression it
implements.  The registry is what the Methodology tab displays and exports, so
Chapter 3 of the manuscript and the code cannot silently disagree
(Panel recommendations #3, #22, #23, #24).

Only the Python standard library is used, so each statistical procedure is
readable in full rather than hidden inside a third-party package.
"""

from __future__ import annotations

import math
import random
import statistics
from typing import Any, Callable, Dict, List, Optional, Sequence

MIB = 1024 * 1024

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
