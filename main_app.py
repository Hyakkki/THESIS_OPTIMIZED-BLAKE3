"""BLAKE3 Forensic Toolkit — main application.

File-centric design: select a file once, hash it, and see ALL cryptographic
property analyses (avalanche, collision resistance, hash distribution) applied
to THAT specific file — not to synthetic random data.

Tabs
----
1. File Analysis   — hash the file + avalanche / collision / distribution inline
2. Benchmark       — compare optimized/baseline BLAKE3 vs MD5/SHA-1/SHA-256
"""
from __future__ import annotations

import io
import json
import math
import os
import random
import struct
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional, Tuple

# ── engine path ──────────────────────────────────────────────────────────────
_MODULE_DIR = Path(__file__).resolve().parent / "dev"
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

from optimized_blake3 import (                              # noqa: E402
    MIB,
    benchmark_memory,
    detected_simd_tier,
    hash_file,
    load_file_snapshot,
    physical_cpu_count,
    recommended_memory_benchmark_limit,
)
from benchmark_blake3 import benchmark_files, _write_csv     # noqa: E402

import blake3 as _blake3                                     # noqa: E402

# ── palette ───────────────────────────────────────────────────────────────────
_BG      = "#f1f5f9"
_SURF    = "#ffffff"
_SURF2   = "#f8fafc"
_ACCENT  = "#0f766e"
_ACCENT2 = "#115e59"
_GREEN   = "#15803d"
_YELLOW  = "#a16207"
_RED     = "#b91c1c"
_TEXT    = "#0f172a"
_SUB     = "#64748b"
_BORDER  = "#e2e8f0"

_FH1  = ("Segoe UI", 22, "bold")
_FH2  = ("Segoe UI", 12, "bold")
_FH3  = ("Segoe UI", 10, "bold")
_FBOD = ("Segoe UI", 10)
_FMON = ("Consolas", 9)
_FCAP = ("Segoe UI", 9)


# ─────────────────────────────────────────────────────────────────────────────
# Tiny UI helpers
# ─────────────────────────────────────────────────────────────────────────────

def _card(parent: tk.Widget, **kw) -> tk.Frame:
    return tk.Frame(parent, bg=_SURF, bd=0, relief="flat",
                    highlightbackground=_BORDER, highlightthickness=1, **kw)


def _badge(parent: tk.Widget, text: str, color: str = _ACCENT) -> tk.Label:
    return tk.Label(parent, text=text, bg=color, fg="#fff",
                    font=("Segoe UI", 9, "bold"), padx=8, pady=2, relief="flat")


def _cap(parent: tk.Widget, text: str, **kw) -> tk.Label:
    return tk.Label(parent, text=text, bg=_SURF, fg=_SUB, font=_FCAP,
                    anchor="w", **kw)


def _kv(parent: tk.Frame, label: str, attr: str,
        vars_dict: Dict[str, tk.StringVar],
        label_w: int = 22) -> tk.StringVar:
    """Add a key/value row to a card, return the StringVar."""
    row = tk.Frame(parent, bg=_SURF)
    row.pack(fill="x", padx=18, pady=5)
    tk.Label(row, text=label, bg=_SURF, fg=_SUB, font=_FCAP,
             anchor="w").pack(anchor="w")
    var = tk.StringVar(value="—")
    vars_dict[attr] = var
    tk.Label(row, textvariable=var, bg=_SURF, fg=_TEXT,
             font=("Segoe UI", 10, "bold"), anchor="w",
             wraplength=290, justify="left").pack(fill="x", expand=True)
    return var


# ─────────────────────────────────────────────────────────────────────────────
# Scrollable container
# ─────────────────────────────────────────────────────────────────────────────

class _Scroll(tk.Frame):
    def __init__(self, parent: tk.Widget, **kw):
        super().__init__(parent, bg=_BG, **kw)
        self._cv = tk.Canvas(self, bg=_BG, highlightthickness=0)
        sb = ttk.Scrollbar(self, orient="vertical", command=self._cv.yview)
        self._cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._cv.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self._cv, bg=_BG)
        self._wid = self._cv.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>",
                        lambda _e: self._cv.configure(
                            scrollregion=self._cv.bbox("all")))
        self._cv.bind("<Configure>",
                      lambda e: self._cv.itemconfig(self._wid, width=e.width))
        self._cv.bind_all("<MouseWheel>", self._on_wheel, add="+")

    def _on_wheel(self, event):
        if not self.winfo_ismapped():
            return
        widget = self.winfo_containing(event.x_root, event.y_root)
        while widget is not None:
            if widget == self:
                self._cv.yview_scroll(int(-event.delta / 120), "units")
                return
            widget = widget.master


# ─────────────────────────────────────────────────────────────────────────────
# Worker: all analyses for one file
# ─────────────────────────────────────────────────────────────────────────────

def _run_avalanche(data: bytes, samples: int = 200) -> Dict[str, Any]:
    """
    Avalanche test on the ACTUAL file bytes.

    Flips individual bits inside 'data' and measures how many bits change
    in the BLAKE3 output compared to the original digest.
    Expected: ~128 / 256 bits change on every single-bit flip.
    """
    n_bits = len(data) * 8
    if n_bits == 0:
        return {"passed": False, "error": "empty file"}

    rng = random.Random(0xA11A1A)
    original   = bytearray(data)
    orig_digest = _blake3.blake3(original).digest()

    samples = min(samples, n_bits)
    positions = rng.sample(range(n_bits), samples)

    distances: List[int] = []
    for bp in positions:
        byte_i, bit_i = divmod(bp, 8)
        mod = bytearray(original)
        mod[byte_i] ^= 1 << bit_i
        d = sum((a ^ b).bit_count()
                for a, b in zip(orig_digest, _blake3.blake3(mod).digest()))
        distances.append(d)

    mean   = sum(distances) / len(distances)
    var    = sum((d - mean) ** 2 for d in distances) / len(distances)
    stddev = math.sqrt(var)

    passed = 112.0 <= mean <= 144.0 and min(distances) > 80 and max(distances) < 176

    # 16-bucket histogram (each bucket = 16 bits wide, 0-255 range)
    buckets = [0] * 16
    for d in distances:
        buckets[min(15, int(d / 256 * 16))] += 1

    return {
        "passed": passed,
        "samples": len(distances),
        "mean": round(mean, 3),
        "mean_pct": round(mean / 256 * 100, 3),
        "stddev": round(stddev, 3),
        "minimum": min(distances),
        "maximum": max(distances),
        "buckets": buckets,
        "bucket_labels": [str(i * 16) for i in range(16)],
        "note": (
            "1-bit flip applied to the actual file bytes. "
            "Each sample flips a different bit in the file."
        ),
    }


def _run_collision(data: bytes, n_variants: int = 500) -> Dict[str, Any]:
    """
    Collision check on the ACTUAL file.

    Generates n_variants modified copies of the analysis sample, checks every
    resulting digest for duplicates, and verifies that single-thread and
    automatic-thread hashing return identical results.
    """
    original_digest = _blake3.blake3(data, max_threads=1).hexdigest()
    digests = [original_digest]
    seen = {original_digest: "original sample"}
    collisions: List[Tuple[str, str]] = []
    inconsistent: List[int] = []

    rng = random.Random(0xC0111510)
    for i in range(n_variants):
        # append a unique salt so each variant is distinct
        salt = struct.pack("<Q", i) + rng.randbytes(8)
        variant = bytes(data) + salt
        h1 = _blake3.blake3(variant, max_threads=1).hexdigest()
        h2 = _blake3.blake3(variant, max_threads=_blake3.blake3.AUTO).hexdigest()
        if h1 != h2:
            inconsistent.append(i)
        input_name = f"modified sample {i + 1}"
        if h1 in seen:
            collisions.append((seen[h1], input_name))
        else:
            seen[h1] = input_name
        digests.append(h1)

    passed = not collisions and not inconsistent
    return {
        "passed": passed,
        "inputs_tested": n_variants + 1,
        "variants_tested": n_variants,
        "collisions": len(collisions),
        "inconsistent": len(inconsistent),
        "digests": digests,
        "note": (
            f"Screened the original analysis sample and {n_variants} modified "
            "versions for duplicate hashes. This is an empirical check, not "
            "a mathematical proof of collision resistance."
        ),
    }


def _run_distribution(digest_hexes: List[str]) -> Dict[str, Any]:
    """
    Bit/byte distribution analysis across actual BLAKE3 digests.

    Counts zero and one bits across the original analysis sample plus its
    modified versions. A balanced result should be close to 50 % ones.
    """
    if not digest_hexes:
        return {"passed": False, "error": "no digests supplied"}

    digest_values = [bytes.fromhex(value) for value in digest_hexes]
    if any(len(value) != 32 for value in digest_values):
        return {"passed": False, "error": "invalid BLAKE3 digest length"}

    bits_set = sum(byte.bit_count() for digest in digest_values for byte in digest)
    total_bits = len(digest_values) * 256
    bits_clear = total_bits - bits_set
    bit_freq = bits_set / total_bits

    bit_counts = [0] * 256
    for digest in digest_values:
        for byte_i, byte_value in enumerate(digest):
            for bit_i in range(8):
                if byte_value & (1 << bit_i):
                    bit_counts[byte_i * 8 + bit_i] += 1

    position_pcts = [count / len(digest_values) * 100 for count in bit_counts]
    passed = 0.48 <= bit_freq <= 0.52

    return {
        "passed": passed,
        "digest_bits": 256,
        "digests_tested": len(digest_values),
        "total_bits": total_bits,
        "bits_set": bits_set,
        "bits_clear": bits_clear,
        "bit_freq_pct": round(bit_freq * 100, 2),
        "expected_pct": 50.0,
        "position_min_pct": round(min(position_pcts), 2),
        "position_max_pct": round(max(position_pcts), 2),
        "note": (
            "Counts zeros and ones across real BLAKE3 outputs from the original "
            "analysis sample and its modified versions. This is a distribution "
            "diagnostic, not proof that the hash is random."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Tab 1 – File Analysis  (the big tab)
# ─────────────────────────────────────────────────────────────────────────────

class FileAnalysisTab(tk.Frame):
    """Hash a file and show digest + avalanche + collision + distribution."""

    _AVALANCHE_SAMPLES = 200
    _COLLISION_VARIANTS = 300
    _BENCHMARK_REPEATS = 7
    _BENCHMARK_WARMUPS = 2
    _MODE_LABELS = {
        "Optimized (recommended)": "optimized",
        "Baseline (comparison)": "baseline",
    }

    def __init__(self, parent: tk.Widget, status_var: tk.StringVar):
        super().__init__(parent, bg=_BG)
        self._status_var = status_var
        self._busy = False
        self._file_path: str = ""
        self._run_mode = "optimized"
        self._build()

    # ── layout ────────────────────────────────────────────────────────────────

    def _build(self):
        # ── top control bar (non-scrolling) ───────────────────────────────────
        ctrl = tk.Frame(self, bg=_BG)
        ctrl.pack(fill="x", padx=20, pady=(16, 0))

        tk.Label(ctrl, text="File Analysis", bg=_BG, fg=_TEXT,
                 font=_FH1).pack(anchor="w")
        tk.Label(ctrl,
                  text="Create a file fingerprint. Measure performance. Explore hash behavior.",
                  bg=_BG, fg=_SUB, font=_FBOD, wraplength=820,
                  justify="left").pack(anchor="w", pady=(2, 10))

        # file-picker row
        pick = _card(self)
        pick.pack(fill="x", padx=20, pady=(0, 8))
        inner = tk.Frame(pick, bg=_SURF)
        inner.pack(fill="x", padx=14, pady=10)

        _cap(inner, "EVIDENCE FILE").pack(anchor="w", pady=(0, 8))
        row = tk.Frame(inner, bg=_SURF)
        row.pack(fill="x")

        self._path_var = tk.StringVar()
        tk.Entry(row, textvariable=self._path_var,
                 bg=_SURF2, fg=_TEXT, insertbackground=_TEXT,
                 relief="flat", font=_FMON, bd=0,
                 ).pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))

        tk.Button(row, text="Browse…", command=self._browse,
                  bg=_SURF2, fg=_SUB, relief="flat", font=_FBOD,
                  padx=12, pady=4, cursor="hand2",
                  ).pack(side="left", padx=(0, 8))

        self._hash_btn = tk.Button(
            row, text="Analyze file  →", command=self._start,
            bg=_ACCENT, fg="#fff", relief="flat", font=_FH3,
            padx=22, pady=7, cursor="hand2",
            activebackground=_ACCENT2, activeforeground="#fff")
        self._hash_btn.pack(side="left")

        # mode selector
        opt = tk.Frame(inner, bg=_SURF)
        opt.pack(fill="x", pady=(8, 0))
        tk.Label(opt, text="Processing mode:", bg=_SURF, fg=_SUB, font=_FCAP,
                  ).pack(side="left")
        self._mode_var = tk.StringVar(value="Optimized (recommended)")
        ttk.Combobox(opt, textvariable=self._mode_var,
                     values=list(self._MODE_LABELS), width=24,
                     state="readonly").pack(side="left", padx=(8, 0))

        # progress bar (hidden until running)
        self._prog = ttk.Progressbar(self, mode="indeterminate", length=300)

        # ── scrollable results area ────────────────────────────────────────────
        self._scroll = _Scroll(self)
        self._scroll.pack(fill="both", expand=True, padx=0, pady=0)
        body = self._scroll.inner

        # ── Section A: Digest + perf metrics ─────────────────────────────────
        self._s_hash = self._section(body, "File fingerprint", subtitle="BLAKE3 · 256-bit hash")
        self._digest_var = tk.StringVar(value="The file's BLAKE3 hash will appear here")
        tk.Label(self._s_hash, textvariable=self._digest_var,
                 bg=_SURF2, fg=_ACCENT, font=("Consolas", 11),
                 anchor="w", wraplength=820, justify="left",
                 padx=16, pady=16,
                 ).pack(fill="x", padx=18, pady=(4, 10))

        # copy button
        tk.Button(self._s_hash, text="Copy digest", command=self._copy_hash,
                  bg=_SURF2, fg=_SUB, relief="flat", font=_FCAP,
                  padx=10, pady=2, cursor="hand2",
                  ).pack(anchor="w", padx=14, pady=(0, 8))

        # metric tiles
        self._mf = tk.Frame(self._s_hash, bg=_SURF)
        self._mf.pack(fill="x", padx=14, pady=(0, 12))
        for c in range(2):
            self._mf.columnconfigure(c, weight=1, uniform="metrics")
        self._mv: Dict[str, tk.StringVar] = {}
        for i, (lbl, key) in enumerate([
            ("Typical time (median)", "elapsed"),
            ("Processing speed",      "throughput"),
            ("CPU acceleration",      "simd"),
            ("Worker threads",        "threads"),
        ]):
            cell = tk.Frame(self._mf, bg=_SURF2,
                            highlightbackground=_BORDER, highlightthickness=1)
            cell.grid(row=i // 2, column=i % 2, padx=4, pady=4, sticky="nsew")
            tk.Label(cell, text=lbl, bg=_SURF2, fg=_SUB, font=_FCAP,
                     ).pack(anchor="w", padx=8, pady=(6, 0))
            var = tk.StringVar(value="—")
            self._mv[key] = var
            tk.Label(cell, textvariable=var, bg=_SURF2, fg=_TEXT,
                     font=("Segoe UI", 20 if i < 2 else 10, "bold"),
                     wraplength=420, justify="left",
                     ).pack(anchor="w", padx=8, pady=(0, 6))

        self._perf_note_var = tk.StringVar(
            value=("Performance uses repeated in-memory BLAKE3 trials; "
                   "file loading is excluded from the timer.")
        )
        tk.Label(self._s_hash, textvariable=self._perf_note_var,
                 bg=_SURF, fg=_SUB, font=_FCAP, anchor="w",
                 wraplength=820, justify="left",
                 ).pack(fill="x", padx=14, pady=(0, 12))

        checks_heading = tk.Frame(body, bg=_BG)
        checks_heading.pack(fill="x", padx=20, pady=(24, 4))
        tk.Label(checks_heading, text="Hash behavior", bg=_BG, fg=_TEXT,
                 font=_FH2).pack(anchor="w")
        tk.Label(checks_heading, text="Three diagnostics from the selected file sample",
                 bg=_BG, fg=_SUB, font=_FCAP).pack(anchor="w", pady=(3, 0))
        self._checks = tk.Frame(body, bg=_BG)
        self._checks.pack(fill="x", padx=14, pady=(0, 20))
        self._checks.bind("<Configure>", self._layout_checks)

        # ── Section B: Avalanche ──────────────────────────────────────────────
        self._s_av = self._section(
            self._checks,
            "Avalanche effect",
            subtitle=(
                "Measures how much the hash changes when one input bit changes. "
                "Expected average: about 50%."
            ), column=0)
        self._av_result_var = tk.StringVar(value="Waiting for analysis")
        self._av_result_label = tk.Label(
            self._s_av, textvariable=self._av_result_var,
            bg=_SURF, fg=_SUB, font=("Segoe UI", 12, "bold"), anchor="w",
            wraplength=290, justify="left",
        )
        self._av_result_label.pack(fill="x", padx=14, pady=(10, 5))
        self._av: Dict[str, tk.StringVar] = {"average": tk.StringVar(value="—")}
        for lbl, key in [
            ("Expected result",     "expected"),
            ("One-bit changes tested", "samples"),
            ("Observed range",      "range"),
            ("Test scope",          "scope"),
        ]:
            _kv(self._s_av, lbl, key, self._av, label_w=24)
        self._featured_value(self._s_av, self._av["average"], "AVERAGE HASH CHANGE")

        # ── Section C: Collision Resistance ───────────────────────────────────
        self._s_col = self._section(
            self._checks,
            "Collision screening",
            subtitle=(
                f"Checks the original sample and {self._COLLISION_VARIANTS} "
                "modified versions for duplicate hashes. Results apply to the tested inputs."
            ), column=1)
        self._col_result_var = tk.StringVar(value="Waiting for analysis")
        self._col_result_label = tk.Label(
            self._s_col, textvariable=self._col_result_var,
            bg=_SURF, fg=_SUB, font=("Segoe UI", 12, "bold"), anchor="w",
            wraplength=290, justify="left",
        )
        self._col_result_label.pack(fill="x", padx=14, pady=(10, 5))
        self._col: Dict[str, tk.StringVar] = {"collisions": tk.StringVar(value="—")}
        for lbl, key in [
            ("Inputs compared",       "inputs"),
            ("Repeatability check",   "threading"),
            ("Test scope",            "scope"),
        ]:
            _kv(self._s_col, lbl, key, self._col, label_w=26)
        self._featured_value(self._s_col, self._col["collisions"], "DUPLICATE HASHES")

        # ── Section D: Hash Distribution ──────────────────────────────────────
        self._s_dist = self._section(
            self._checks,
            "Hash distribution",
            subtitle=(
                "Counts zeros and ones across the tested hashes. "
                "Expected balance: approximately 50% each."
            ), column=2)
        self._dist_result_var = tk.StringVar(value="Waiting for analysis")
        self._dist_result_label = tk.Label(
            self._s_dist, textvariable=self._dist_result_var,
            bg=_SURF, fg=_SUB, font=("Segoe UI", 12, "bold"), anchor="w",
            wraplength=290, justify="left",
        )
        self._dist_result_label.pack(fill="x", padx=14, pady=(10, 5))
        self._dist: Dict[str, tk.StringVar] = {"freq": tk.StringVar(value="—")}
        for lbl, key in [
            ("Hash outputs examined", "digests"),
            ("Total bits examined",   "total_bits"),
            ("Ones / zeros counted",  "counts"),
            ("Expected balance",       "expected"),
        ]:
            _kv(self._s_dist, lbl, key, self._dist, label_w=24)
        self._featured_value(self._s_dist, self._dist["freq"], "OUTPUT BIT BALANCE")

    @staticmethod
    def _featured_value(card, variable, caption):
        featured = tk.Frame(card, bg=_SURF2)
        tk.Label(featured, text=caption, bg=_SURF2, fg=_SUB,
                 font=_FCAP, anchor="w").pack(fill="x", padx=12, pady=(12, 2))
        label = tk.Label(featured, textvariable=variable, bg=_SURF2,
                         fg=_ACCENT, font=("Segoe UI", 17, "bold"),
                         anchor="w", wraplength=290, justify="left")
        label.pack(fill="x", padx=12, pady=(0, 12))
        featured.pack(fill="x", padx=18, pady=(4, 8), before=card.winfo_children()[0])

    def _layout_checks(self, event):
        columns = 3 if event.width >= 1020 else 1
        for index in range(3):
            self._checks.columnconfigure(index, weight=1 if index < columns else 0,
                                         uniform="checks")
        for index, card in enumerate(self._checks.winfo_children()):
            card.grid_configure(row=index // columns, column=index % columns)

    @staticmethod
    def _section(parent: tk.Widget, title: str,
                 subtitle: str = "", column=None) -> tk.Frame:
        """Create a titled card section and return its inner frame."""
        wrapper = _card(parent)
        if column is None:
            wrapper.pack(fill="x", padx=20, pady=(12, 0))
        else:
            wrapper.grid(row=0, column=column, sticky="nsew", padx=6, pady=8)

        tk.Frame(wrapper, bg=_ACCENT, height=3).pack(fill="x")
        tk.Label(wrapper, text=title, bg=_SURF, fg=_TEXT,
                 font=_FH2).pack(anchor="w", padx=18, pady=(16, 4))
        if subtitle:
            tk.Label(wrapper, text=subtitle, bg=_SURF, fg=_SUB, font=_FCAP,
                     wraplength=290 if column is not None else 820,
                     justify="left").pack(anchor="w", padx=18, pady=(0, 12))

        card = tk.Frame(wrapper, bg=_SURF)
        card.pack(fill="both", expand=True, pady=(0, 16))
        return card

    # ── actions ───────────────────────────────────────────────────────────────

    def _browse(self):
        path = filedialog.askopenfilename(title="Select a file to analyse")
        if path:
            self._path_var.set(path)
            self._status_var.set("File selected — click 'Analyze File' to begin")

    def _start(self):
        if self._busy:
            messagebox.showinfo("Busy", "Please wait for the current analysis to finish.")
            return
        path = self._path_var.get().strip()
        if not path:
            messagebox.showwarning("No file", "Please select a file first.")
            return
        if not os.path.isfile(path):
            messagebox.showerror("Invalid file", "The path is not a valid file.")
            return

        self._file_path = path
        self._run_mode = self._MODE_LABELS.get(
            self._mode_var.get(), "optimized"
        )
        self._busy = True
        self._hash_btn.configure(state="disabled")
        self._prog.pack(pady=6)
        self._prog.start(12)

        # reset all result fields
        self._digest_var.set("Hashing…")
        self._perf_note_var.set(
            "Preparing the authoritative digest and RAM-only benchmark..."
        )
        for v in self._mv.values():
            v.set("…")
        for v in self._av.values():
            v.set("…")
        for v in self._col.values():
            v.set("…")
        for v in self._dist.values():
            v.set("…")
        self._av_result_var.set("Running sensitivity check…")
        self._col_result_var.set("Waiting for sensitivity check")
        self._dist_result_var.set("Waiting for duplicate-hash screen")
        self._av_result_label.configure(fg=_SUB)
        self._col_result_label.configure(fg=_SUB)
        self._dist_result_label.configure(fg=_SUB)

        self._status_var.set("Running — hashing file…")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        path = self._file_path
        try:
            file_path = Path(path)
            initial = file_path.stat()
            threads = 1 if self._run_mode == "baseline" else physical_cpu_count()
            memory_limit = recommended_memory_benchmark_limit()

            # All file I/O happens outside the benchmark timer. A complete
            # snapshot supplies the authoritative digest; oversized evidence
            # gets a separate full-file pass plus a labelled RAM sample.
            self.after(
                0,
                self._status_var.set,
                "Running — loading benchmark data into RAM (not timed)…",
            )
            try:
                snapshot = load_file_snapshot(path, max_bytes=memory_limit)
            except MemoryError:
                fallback_limit = min(int(initial.st_size), 64 * MIB)
                snapshot = load_file_snapshot(path, max_bytes=fallback_limit)

            if snapshot.complete:
                digest = ""
            else:
                self.after(
                    0,
                    self._status_var.set,
                    "Running — computing authoritative full-file digest…",
                )
                file_result = hash_file(
                    path,
                    threads=threads,
                    expected_size=int(initial.st_size),
                    workload="balanced",
                )
                if file_result.status != "ok":
                    raise RuntimeError(file_result.error or "hashing failed")
                digest = file_result.digest

            self.after(
                0,
                self._status_var.set,
                "Running — measuring RAM-only BLAKE3 throughput…",
            )
            benchmark = benchmark_memory(
                snapshot.data,
                threads=threads,
                repeats=self._BENCHMARK_REPEATS,
                warmups=self._BENCHMARK_WARMUPS,
            )
            if snapshot.complete:
                digest = benchmark.digest

            final = file_path.stat()
            if (
                int(final.st_size) != int(initial.st_size)
                or int(final.st_mtime_ns) != int(initial.st_mtime_ns)
                or (
                    getattr(initial, "st_ino", 0)
                    and getattr(final, "st_ino", 0)
                    and initial.st_ino != final.st_ino
                )
            ):
                raise RuntimeError("The evidence file changed during analysis")

            self.after(0, self._show_hash, digest, benchmark, snapshot)

            # Reuse the RAM snapshot for the validation diagnostics.
            self.after(0, self._status_var.set, "Running — avalanche effect test…")
            data = bytes(memoryview(snapshot.data)[:4 * MIB])
            diagnostic_scope = (
                "entire file"
                if int(initial.st_size) <= 4 * MIB
                else "first 4 MiB analysis sample"
            )
            del snapshot

            # ── Step 3: Avalanche ────────────────────────────────────────────
            av = _run_avalanche(data, samples=self._AVALANCHE_SAMPLES)
            av["scope"] = diagnostic_scope
            self.after(0, self._show_avalanche, av)

            # ── Step 4: Collision ────────────────────────────────────────────
            self.after(0, self._status_var.set, "Running — duplicate-hash screening…")
            col = _run_collision(data, n_variants=self._COLLISION_VARIANTS)
            col["scope"] = diagnostic_scope
            distribution_digests = col.pop("digests")
            self.after(0, self._show_collision, col)

            # ── Step 5: Distribution ─────────────────────────────────────────
            self.after(0, self._status_var.set, "Running — output-bit balance check…")
            dist = _run_distribution(distribution_digests)
            self.after(0, self._show_distribution, dist)

            self.after(0, self._done)

        except Exception as exc:
            self.after(0, self._on_error, str(exc))

    # ── result renderers ──────────────────────────────────────────────────────

    def _show_hash(self, digest, benchmark, snapshot):
        self._digest_var.set(digest)
        self._mv["elapsed"].set(f"{benchmark.median_elapsed_ms / 1000:.4f} s")
        self._mv["throughput"].set(
            f"{benchmark.median_throughput_mib_s:.2f} MiB/s"
        )
        self._mv["simd"].set(detected_simd_tier())
        self._mv["threads"].set(str(benchmark.threads_used))

        loaded_mib = snapshot.bytes_loaded / MIB
        total_mib = snapshot.file_size / MIB
        if snapshot.complete:
            scope = f"complete {loaded_mib:.1f} MiB evidence snapshot"
        else:
            scope = (
                f"first {loaded_mib:.1f} MiB of {total_mib:.1f} MiB; "
                "the full-file digest was computed separately"
            )
        self._perf_note_var.set(
            f"RAM-only median of {benchmark.repeats} trials after "
            f"{benchmark.warmups} warm-ups; {scope}. File loading is excluded. "
            f"Observed range: {benchmark.min_throughput_mib_s:.2f}–"
            f"{benchmark.max_throughput_mib_s:.2f} MiB/s."
        )

    def _show_avalanche(self, r: Dict[str, Any]):
        if r.get("error"):
            self._av_result_var.set("NOT APPLICABLE — an empty file has no bit to flip")
            self._av_result_label.configure(fg=_YELLOW)
            self._av["samples"].set("0")
            self._av["average"].set("not available")
            self._av["expected"].set("about 128 of 256 bits (50%)")
            self._av["range"].set("not available")
            self._av["scope"].set(r.get("scope", "empty file"))
            return

        passed = r.get("passed", False)
        self._av_result_var.set(
            "Expected sensitivity observed"
            if passed else
            "Outside the expected range"
        )
        self._av_result_label.configure(fg=_GREEN if passed else _YELLOW)
        self._av["samples"].set(str(r.get("samples", "—")))
        self._av["average"].set(
            f"{r['mean']:.1f} of 256 bits ({r['mean_pct']:.2f}%)"
        )
        self._av["expected"].set("about 128 of 256 bits (50%)")
        self._av["range"].set(
            f"{r['minimum']}–{r['maximum']} changed bits"
        )
        self._av["scope"].set(r.get("scope", "analysis sample"))

    def _show_collision(self, r: Dict[str, Any]):
        passed = r.get("passed", False)
        self._col_result_var.set(
            "No duplicate hashes observed"
            if passed else
            "Duplicate or inconsistent result detected"
        )
        self._col_result_label.configure(fg=_GREEN if passed else _RED)
        self._col["inputs"].set(
            f"{r['inputs_tested']} (original + {r['variants_tested']} modified)"
        )
        n_col = r["collisions"]
        n_inc = r["inconsistent"]
        self._col["collisions"].set(
            f"{n_col} observed")
        self._col["threading"].set(
            f"{'consistent results' if n_inc == 0 else f'{n_inc} mismatches'}")
        self._col["scope"].set(r.get("scope", "analysis sample"))

    def _show_distribution(self, r: Dict[str, Any]):
        passed = r.get("passed", False)
        self._dist_result_var.set(
            "Output bits are balanced"
            if passed else
            "Outside the expected balance range"
        )
        self._dist_result_label.configure(fg=_GREEN if passed else _YELLOW)
        self._dist["digests"].set(str(r["digests_tested"]))
        self._dist["total_bits"].set(f"{r['total_bits']:,}")
        self._dist["counts"].set(
            f"{r['bits_set']:,} ones / {r['bits_clear']:,} zeros"
        )
        self._dist["freq"].set(f"{r['bit_freq_pct']:.2f}% ones")
        self._dist["expected"].set("approximately 50% ones and 50% zeros")

    def _done(self):
        self._busy = False
        self._hash_btn.configure(state="normal")
        self._prog.stop()
        self._prog.pack_forget()
        fname = Path(self._file_path).name
        self._status_var.set(
            f"Analysis complete for: {fname}")

    def _on_error(self, msg: str):
        self._busy = False
        self._hash_btn.configure(state="normal")
        self._prog.stop()
        self._prog.pack_forget()
        self._digest_var.set("Error")
        self._status_var.set("Analysis failed")
        messagebox.showerror("Analysis error", msg)

    def _copy_hash(self):
        digest = self._digest_var.get()
        if len(digest) != 64:
            messagebox.showinfo("Nothing to copy", "Run an analysis first.")
            return
        self.clipboard_clear()
        self.clipboard_append(digest)
        self._status_var.set("Digest copied to clipboard")


# ─────────────────────────────────────────────────────────────────────────────
# Tab 2 – Benchmark
# ─────────────────────────────────────────────────────────────────────────────

class BenchmarkTab(tk.Frame):
    def __init__(self, parent: tk.Widget, status_var: tk.StringVar):
        super().__init__(parent, bg=_BG)
        self._status_var = status_var
        self._busy = False
        self._build()

    def _build(self):
        pad = dict(padx=20, pady=8)

        tk.Label(self, text="Hash Performance Benchmark", bg=_BG, fg=_TEXT,
                 font=_FH1).pack(anchor="w", padx=20, pady=(18, 4))
        tk.Label(self,
                 text="Compare optimized BLAKE3, baseline BLAKE3, MD5, SHA-1, and SHA-256 on the same file.",
                 bg=_BG, fg=_SUB, font=_FBOD).pack(anchor="w", padx=20, pady=(0, 10))

        ctrl_card = _card(self)
        ctrl_card.pack(fill="x", **pad)
        ctrl = tk.Frame(ctrl_card, bg=_SURF)
        ctrl.pack(fill="x", padx=14, pady=12)

        tk.Label(ctrl, text="Measured trials per profile", bg=_SURF, fg=_SUB,
                 font=_FBOD).pack(side="left")
        self._rep_var = tk.IntVar(value=5)
        ttk.Spinbox(ctrl, from_=5, to=30, increment=5, width=5,
                    textvariable=self._rep_var).pack(side="left", padx=(8, 20))
        tk.Button(ctrl, text="Select File and Run", command=self._start,
                  bg=_ACCENT, fg="#fff", relief="flat", font=_FH3,
                  padx=18, pady=6, cursor="hand2",
                  activebackground=_ACCENT2, activeforeground="#fff",
                  ).pack(side="left")
        tk.Label(ctrl, text="1 warm-up per profile is automatic and excluded",
                 bg=_SURF, fg=_SUB, font=_FCAP).pack(side="left", padx=(14, 0))

        res_card = _card(self)
        res_card.pack(fill="both", expand=True, **pad)
        _cap(res_card, "BENCHMARK RESULTS").pack(anchor="w", padx=14, pady=(10, 2))

        tf = tk.Frame(res_card, bg=_SURF)
        tf.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        self._result_title_var = tk.StringVar(value="Ready to benchmark")
        tk.Label(tf, textvariable=self._result_title_var, bg=_SURF,
                 fg=_TEXT, font=_FH2, anchor="w", justify="left",
                 wraplength=1040).pack(fill="x", pady=(4, 2))
        self._benchmark_note = tk.StringVar(
            value="Select one file. Each profile receives one warm-up and five or more measured trials."
        )
        tk.Label(tf, textvariable=self._benchmark_note, bg=_SURF,
                 fg=_SUB, font=_FBOD, anchor="w", justify="left",
                 wraplength=1040).pack(fill="x", pady=(0, 12))
        table_frame = tk.Frame(tf, bg=_SURF)
        table_frame.pack(fill="both", expand=True)
        columns = ("algorithm", "time", "speed", "cpu", "memory", "optimization")
        self._table = ttk.Treeview(table_frame, columns=columns, show="headings")
        for key, heading, width in zip(columns,
                ("Hash profile", "Median time (ms)", "Median throughput (MiB/s)",
                 "Median CPU (%)", "Median peak RSS (MiB)",
                 "Optimized BLAKE3 vs profile"),
                (190, 165, 175, 165, 165, 205)):
            self._table.heading(key, text=heading)
            self._table.column(key, width=width, minwidth=70,
                               anchor="w" if key in ("algorithm", "optimization") else "e")
        self._table.tag_configure("alternate", background=_SURF2)
        self._table.tag_configure("optimized", background="#ecfdf5", foreground=_ACCENT2)
        self._table.tag_configure("baseline", background="#f1f5f9", foreground=_TEXT)
        y_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self._table.yview)
        x_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self._table.xview)
        self._table.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        y_scroll.pack(side="right", fill="y")
        x_scroll.pack(side="bottom", fill="x")
        self._table.pack(fill="both", expand=True)
        self._metric_note_var = tk.StringVar(value=(
            "Time and throughput are median values. CPU is normalized to total "
            "logical-processor capacity. RSS is resident process memory. Time reduction = "
            "(profile time − optimized time) / profile time × 100."
        ))
        tk.Label(tf, textvariable=self._metric_note_var, bg=_SURF, fg=_SUB,
                 font=_FCAP, anchor="w", justify="left", wraplength=1040
                 ).pack(fill="x", pady=(10, 2))
        self._report_note_var = tk.StringVar(value="")
        tk.Label(tf, textvariable=self._report_note_var, bg=_SURF, fg=_SUB,
                 font=_FCAP, anchor="w", justify="left", wraplength=1040
                 ).pack(fill="x", pady=(0, 2))

    def _set_result(self, title: str, detail: str, reports: str = ""):
        self._result_title_var.set(title)
        self._benchmark_note.set(detail)
        self._report_note_var.set(reports)
        self._table.delete(*self._table.get_children())

    def _start(self):
        if self._busy:
            messagebox.showinfo("Busy", "Please wait.")
            return
        path = filedialog.askopenfilename(title="Select a file to benchmark")
        if not path:
            return
        try:
            repeats = int(self._rep_var.get())
        except (TypeError, ValueError):
            messagebox.showerror("Invalid trial count", "Trials must be a whole number.")
            return
        if repeats < 5 or repeats % 5:
            messagebox.showerror(
                "Invalid trial count",
                "Use 5, 10, 15, 20, 25, or 30 trials for balanced execution order.",
            )
            return
        self._busy = True
        self._status_var.set("Benchmark running…")
        self._set_result(
            "Benchmark in progress",
            f"Running 1 excluded warm-up and {repeats} measured trials per profile…",
        )
        threading.Thread(target=self._worker, args=(path, repeats),
                         daemon=True).start()

    def _worker(self, path: str, repeats: int):
        try:
            report   = benchmark_files([path], rounds=repeats, warmups=1)
            ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_folder = str(Path(path).resolve().parent)
            out_json = os.path.join(output_folder, f"blake3_benchmark_{ts}.json")
            out_csv  = os.path.join(output_folder, f"blake3_benchmark_{ts}.csv")
            Path(out_json).write_text(json.dumps(report, indent=2), encoding="utf-8")
            _write_csv(out_csv, report["runs"])
            self.after(0, self._on_success, report,
                       out_csv, out_json, path, repeats)
        except Exception as exc:
            self.after(0, self._on_error, str(exc))

    def _on_success(self, report, csv_p, json_p, path, reps):
        self._busy = False
        summary = report["summary"]
        optimized = next(
            (row for row in summary if row["algorithm"] == "BLAKE3 (Optimized)"), None
        )
        percent = optimized.get("optimization_percent") if optimized else None
        speedup = optimized.get("speedup_vs_baseline") if optimized else None
        if percent is None:
            result_title = "Optimization result unavailable"
        elif percent >= 0:
            result_title = (
                f"Optimized BLAKE3 reduced median time by {percent:.2f}% "
                f"({speedup:.2f}× faster)"
            )
        else:
            result_title = (
                f"Optimized BLAKE3 was {abs(percent):.2f}% slower than baseline "
                f"({speedup:.2f}× baseline speed)"
            )
        detail = (
            f"File: {Path(path).name}  •  Measured trials: {reps} per profile  •  "
            "Warm-ups: 1 excluded  •  Cache mode: warm"
        )
        warnings = report.get("warnings", [])
        if warnings:
            detail += "\nMeasurement note: " + " ".join(warnings)
        self._set_result(
            result_title,
            detail,
            f"Reports — CSV: {csv_p}  •  JSON: {json_p}",
        )
        for index, entry in enumerate(summary):
            comparison_percent = entry.get("optimized_time_change_percent")
            if entry["algorithm"] == "BLAKE3 (Optimized)":
                optimization = "Reference"
            elif comparison_percent is not None:
                optimization = (
                    f"{comparison_percent:.2f}% reduction"
                    if comparison_percent >= 0
                    else f"{abs(comparison_percent):.2f}% increase"
                )
            else:
                optimization = "N/A"
            cpu = entry.get("median_cpu_utilization_percent")
            memory = entry.get("median_peak_rss_mb")
            if entry["algorithm"] == "BLAKE3 (Optimized)":
                tags = ("optimized",)
            elif entry["algorithm"] == "BLAKE3 (Baseline)":
                tags = ("baseline",)
            else:
                tags = ("alternate",) if index % 2 else ()
            self._table.insert("", "end", values=(
                entry["algorithm"],
                f"{entry['median_elapsed_ms']:,.3f}",
                f"{entry['median_throughput_mb_s']:,.2f}",
                f"{cpu:,.2f}" if cpu is not None else "N/A",
                f"{memory:,.2f}" if memory is not None else "N/A",
                optimization,
            ), tags=tags)
        self._status_var.set(
            "Benchmark complete · Digests verified · Median results shown"
        )

    def _on_error(self, msg: str):
        self._busy = False
        self._set_result("Benchmark failed", msg)
        self._status_var.set("Benchmark failed")
        messagebox.showerror("Benchmark error", msg)


# ─────────────────────────────────────────────────────────────────────────────
# Root application
# ─────────────────────────────────────────────────────────────────────────────

class Blake3App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("BLAKE3 Forensic Toolkit")
        width = min(1240, self.winfo_screenwidth() - 80)
        height = min(900, self.winfo_screenheight() - 100)
        self.geometry(f"{width}x{height}")
        self.minsize(800, 600)
        self.configure(bg=_BG)
        self._apply_styles()
        self._status_var = tk.StringVar(
            value="Ready · Select an evidence file to begin")
        self._build_header()
        self._build_tabs()
        self._build_status()

    def _apply_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=_BG, foreground=_TEXT, font=_FBOD)
        s.configure("TNotebook", background=_BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=_SURF, foreground=_SUB,
                    padding=[24, 12], font=("Segoe UI", 10, "bold"), borderwidth=0)
        s.map("TNotebook.Tab",
              background=[("selected", _SURF2)],
              foreground=[("selected", _ACCENT)])
        s.configure("Treeview", background=_SURF, fieldbackground=_SURF,
                    foreground=_TEXT, rowheight=38, borderwidth=0, font=_FBOD)
        s.configure("Treeview.Heading", background=_SURF2, foreground=_SUB,
                    font=_FH3, padding=[12, 10], relief="flat")
        s.map("Treeview", background=[("selected", _ACCENT)],
              foreground=[("selected", "#ffffff")])
        s.configure("TScrollbar", background=_SURF2,
                    troughcolor=_SURF, arrowcolor=_SUB)
        s.configure("TCombobox",
                    fieldbackground=_SURF2, background=_SURF2,
                    foreground=_TEXT, arrowcolor=_SUB,
                    selectbackground=_ACCENT, selectforeground="#fff")
        s.configure("TSpinbox",
                    fieldbackground=_SURF2, background=_SURF2,
                    foreground=_TEXT, arrowcolor=_SUB)
        s.configure("TProgressbar",
                    troughcolor=_SURF2, background=_ACCENT, thickness=5)

    def _build_header(self):
        hdr = tk.Frame(self, bg=_SURF, height=72,
                       highlightbackground=_BORDER, highlightthickness=1)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        dot = tk.Canvas(hdr, width=40, height=40, bg=_SURF, highlightthickness=0)
        dot.create_rectangle(0, 0, 40, 40, fill=_ACCENT, outline="")
        dot.create_text(20, 20, text="B3", fill="#ffffff",
                        font=("Segoe UI", 13, "bold"))
        dot.pack(side="left", padx=(24, 8), pady=16)

        tk.Label(hdr, text="BLAKE3", bg=_SURF, fg=_TEXT,
                 font=("Segoe UI", 13, "bold")).pack(side="left", padx=(6, 0))
        tk.Label(hdr, text="Forensic Toolkit", bg=_SURF, fg=_SUB,
                 font=("Segoe UI", 10)).pack(side="left", padx=(5, 0))

        _badge(hdr, "FORENSIC ANALYSIS", _ACCENT).pack(
            side="right", padx=14, pady=14)

    def _build_tabs(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)
        for label, cls in [
            ("  File Analysis  ", FileAnalysisTab),
            ("  Benchmark  ",     BenchmarkTab),
        ]:
            frame = cls(nb, self._status_var)
            nb.add(frame, text=label)

    def _build_status(self):
        bar = tk.Frame(self, bg=_SURF, height=26,
                       highlightbackground=_BORDER, highlightthickness=1)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        tk.Label(bar, textvariable=self._status_var,
                 bg=_SURF, fg=_SUB, font=_FCAP,
                 anchor="w").pack(side="left", padx=14, pady=3)
        tk.Label(bar, text="Optimized BLAKE3  |  Native C extension",
                  bg=_SURF, fg=_SUB, font=_FCAP,
                 anchor="e").pack(side="right", padx=14, pady=3)


if __name__ == "__main__":
    app = Blake3App()
    app.mainloop()
