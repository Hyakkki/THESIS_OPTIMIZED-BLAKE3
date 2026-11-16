"""Optimized BLAKE3 Forensic Toolkit — standalone application.

Tabs
----
1. Overview             — what the study optimizes, what it holds constant, architecture
2. File Analysis        — digest + in-memory speed + hash-behaviour diagnostics for one file
3. Technique Benchmark  — large files: adaptive buffering × multithreading (2×2 design)
4. Small-File Batching  — many small files: batching × parallel dispatch (2×2 design)
5. Verification         — official vectors, reference implementation, consistency, avalanche
6. Dataset              — generate size sweeps / small-file corpora, manifest and coverage
7. Methodology          — formulas (F1–F19) and the statistical analysis plan

All computation lives in the ``dev`` package; this file is presentation only.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import traceback
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

_ROOT = Path(__file__).resolve().parent
_MODULE_DIR = _ROOT / "dev"
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

import blake3 as _blake3                                          # noqa: E402

import metrics                                                    # noqa: E402
from benchmark_blake3 import (                                    # noqa: E402
    DEFAULT_TRIALS,
    DEFAULT_WARMUPS,
    MIN_TRIALS,
    BenchmarkCancelled,
    export_report,
    run_large_file_ablation,
    run_small_file_ablation,
)
from blake3_validation import (                                   # noqa: E402
    LIMITATIONS,
    avalanche_analysis,
    bit_balance,
    collision_screen,
    run_validation,
)
from dataset_tool import (                                        # noqa: E402
    DEFAULT_SWEEP_SIZES,
    SIZE_TIERS,
    build_manifest,
    format_size,
    generate_size_sweep,
    generate_small_file_corpus,
    size_tier,
    verify_manifest,
    write_manifest,
)
from optimized_blake3 import (                                    # noqa: E402
    DEFAULT_BATCH_SIZE,
    MIB,
    SMALL_FILE_LIMIT,
    benchmark_memory,
    detected_simd_tier,
    hash_file,
    load_file_snapshot,
    logical_cpu_count,
    physical_cpu_count,
    recommended_memory_benchmark_limit,
)

RESULTS_DIR = _ROOT / "results"

# ── palette ───────────────────────────────────────────────────────────────────
_BG = "#f1f5f9"
_SURF = "#ffffff"
_SURF2 = "#f8fafc"
_ACCENT = "#0f766e"
_ACCENT2 = "#115e59"
_GREEN = "#15803d"
_YELLOW = "#a16207"
_RED = "#b91c1c"
_GRAY = "#94a3b8"
_TEXT = "#0f172a"
_SUB = "#64748b"
_BORDER = "#e2e8f0"

_FH1 = ("Segoe UI", 20, "bold")
_FH2 = ("Segoe UI", 12, "bold")
_FH3 = ("Segoe UI", 10, "bold")
_FBOD = ("Segoe UI", 10)
_FMON = ("Consolas", 9)
_FCAP = ("Segoe UI", 9)

_VERDICT_TAG = {
    "significantly faster": "win",
    "significantly slower": "loss",
    "no significant difference": "neutral",
}


# ─────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

def fmt_ms(value: Optional[float]) -> str:
    if value is None:
        return "—"
    return "%.2f s" % (value / 1000.0) if value >= 1000 else "%.2f ms" % value


def fmt_num(value: Optional[float], pattern: str = "%.2f") -> str:
    return "—" if value is None else pattern % value


def fmt_ci(ci: Optional[Sequence[float]], pattern: str = "%.2f") -> str:
    if not ci:
        return "—"
    return "[" + pattern % ci[0] + " – " + pattern % ci[1] + "]"


def fmt_p(value: Optional[float]) -> str:
    if value is None:
        return "—"
    return "< 0.001" if value < 0.001 else "%.3f" % value


def fmt_speedup(value: Optional[float]) -> str:
    return "—" if value is None else "%.2f×" % value


def interaction_text(value: Optional[float]) -> str:
    if value is None:
        return "not available"
    if value > 1.02:
        return "%.2f (synergy: the techniques reinforce each other)" % value
    if value < 0.98:
        return "%.2f (overlap: the techniques partly do the same work)" % value
    return "%.2f (approximately independent)" % value


def open_folder(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception as exc:
        messagebox.showerror("Cannot open folder", str(exc))


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# ─────────────────────────────────────────────────────────────────────────────
# Widgets
# ─────────────────────────────────────────────────────────────────────────────

def _card(parent: tk.Widget, **kw) -> tk.Frame:
    return tk.Frame(parent, bg=_SURF, bd=0, relief="flat",
                    highlightbackground=_BORDER, highlightthickness=1, **kw)


def _cap(parent: tk.Widget, text: str, bg: str = _SURF, **kw) -> tk.Label:
    return tk.Label(parent, text=text, bg=bg, fg=_SUB, font=_FCAP, anchor="w", **kw)


def _button(parent, text, command, primary=False, **kw) -> tk.Button:
    if primary:
        return tk.Button(parent, text=text, command=command, bg=_ACCENT, fg="#fff",
                         relief="flat", font=_FH3, padx=16, pady=5, cursor="hand2",
                         activebackground=_ACCENT2, activeforeground="#fff", **kw)
    return tk.Button(parent, text=text, command=command, bg=_SURF2, fg=_TEXT,
                     relief="flat", font=_FBOD, padx=10, pady=4, cursor="hand2",
                     highlightbackground=_BORDER, highlightthickness=1, **kw)


def _heading(parent, title: str, subtitle: str = "") -> None:
    frame = tk.Frame(parent, bg=_BG)
    frame.pack(fill="x", padx=20, pady=(16, 6))
    tk.Label(frame, text=title, bg=_BG, fg=_TEXT, font=_FH1).pack(anchor="w")
    if subtitle:
        tk.Label(frame, text=subtitle, bg=_BG, fg=_SUB, font=_FBOD, wraplength=1050,
                 justify="left").pack(anchor="w", pady=(2, 0))


def _section(parent, title: str, subtitle: str = "") -> tk.Frame:
    wrapper = _card(parent)
    wrapper.pack(fill="x", padx=20, pady=(10, 0))
    tk.Frame(wrapper, bg=_ACCENT, height=3).pack(fill="x")
    tk.Label(wrapper, text=title, bg=_SURF, fg=_TEXT, font=_FH2).pack(anchor="w", padx=16, pady=(12, 2))
    if subtitle:
        tk.Label(wrapper, text=subtitle, bg=_SURF, fg=_SUB, font=_FCAP, wraplength=1040,
                 justify="left").pack(anchor="w", padx=16, pady=(0, 6))
    body = tk.Frame(wrapper, bg=_SURF)
    body.pack(fill="both", expand=True, padx=16, pady=(4, 14))
    return body


class _Scroll(tk.Frame):
    """Vertically scrollable container; put content in ``.inner``."""

    def __init__(self, parent: tk.Widget, **kw):
        super().__init__(parent, bg=_BG, **kw)
        self._cv = tk.Canvas(self, bg=_BG, highlightthickness=0)
        bar = ttk.Scrollbar(self, orient="vertical", command=self._cv.yview)
        self._cv.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        self._cv.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self._cv, bg=_BG)
        self._wid = self._cv.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda _e: self._cv.configure(scrollregion=self._cv.bbox("all")))
        self._cv.bind("<Configure>", lambda e: self._cv.itemconfig(self._wid, width=e.width))
        self._cv.bind_all("<MouseWheel>", self._on_wheel, add="+")

    def _on_wheel(self, event):
        if not self.winfo_ismapped():
            return
        widget = self.winfo_containing(event.x_root, event.y_root)
        while widget is not None:
            if isinstance(widget, (ttk.Treeview, tk.Text, tk.Listbox)):
                return  # let the inner widget scroll itself
            if widget == self:
                self._cv.yview_scroll(int(-event.delta / 120), "units")
                return
            widget = widget.master


def _table(parent, columns: Sequence[Tuple[str, str, int, str]], height: int = 8) -> ttk.Treeview:
    """columns: (key, heading, width, anchor)."""
    frame = tk.Frame(parent, bg=_SURF)
    frame.pack(fill="both", expand=True)
    tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=height)
    for key, heading, width, anchor in columns:
        tree.heading(key, text=heading)
        tree.column(key, width=width, minwidth=50, anchor=anchor, stretch=True)
    tree.tag_configure("win", foreground=_GREEN)
    tree.tag_configure("loss", foreground=_RED)
    tree.tag_configure("neutral", foreground=_TEXT)
    tree.tag_configure("base", background="#eef2f7")
    tree.tag_configure("ref", foreground=_SUB)
    tree.tag_configure("pass", foreground=_GREEN)
    tree.tag_configure("fail", foreground=_RED)
    x_scroll = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    y_scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(xscrollcommand=x_scroll.set, yscrollcommand=y_scroll.set)
    y_scroll.pack(side="right", fill="y")
    x_scroll.pack(side="bottom", fill="x")
    tree.pack(fill="both", expand=True)
    return tree


class SpeedupChart(tk.Canvas):
    """Horizontal bars of speedup with 95 % CI whiskers and a 1.0× reference line."""

    def __init__(self, parent, height=220):
        super().__init__(parent, bg=_SURF, height=height, highlightthickness=0)
        self._items: List[Tuple[str, float, Optional[Sequence[float]], str]] = []
        self._title = ""
        self.bind("<Configure>", lambda _e: self._draw())

    def set_data(self, items, title=""):
        self._items = list(items)
        self._title = title
        self._draw()

    def _draw(self):
        self.delete("all")
        width = max(200, self.winfo_width())
        if not self._items:
            self.create_text(width / 2, 40, text="Run the experiment to see the chart",
                             fill=_SUB, font=_FCAP)
            return
        label_w, right_pad, top = 230, 70, 30
        row_h = 30
        needed = top + row_h * len(self._items) + 30
        if int(self["height"]) != needed:
            self.configure(height=needed)
        max_value = max(max(ci[1] if ci else value, value) for _l, value, ci, _c in self._items)
        scale_max = max(1.2, max_value * 1.1)
        plot_w = width - label_w - right_pad

        def x_of(value):
            return label_w + plot_w * value / scale_max

        self.create_text(10, 12, text=self._title, anchor="w", fill=_TEXT, font=_FH3)
        x_ref = x_of(1.0)
        self.create_line(x_ref, top - 6, x_ref, top + row_h * len(self._items),
                         fill=_SUB, dash=(4, 3))
        self.create_text(x_ref, top + row_h * len(self._items) + 12, text="1.0× = baseline",
                         fill=_SUB, font=_FCAP)
        for index, (label, value, ci, color) in enumerate(self._items):
            y = top + index * row_h + row_h / 2
            self.create_text(label_w - 10, y, text=label, anchor="e", fill=_TEXT, font=_FCAP)
            self.create_rectangle(label_w, y - 9, x_of(value), y + 9, fill=color, outline="")
            if ci:
                self.create_line(x_of(ci[0]), y, x_of(ci[1]), y, fill=_TEXT, width=1)
                for edge in ci:
                    self.create_line(x_of(edge), y - 5, x_of(edge), y + 5, fill=_TEXT)
            self.create_text(x_of(max(value, ci[1] if ci else value)) + 6, y,
                             text="%.2f×" % value, anchor="w", fill=_TEXT, font=_FH3)


class ProgressPanel(tk.Frame):
    """Determinate progress bar, message, and optional Cancel button."""

    def __init__(self, parent, bg=_SURF):
        super().__init__(parent, bg=bg)
        self._bar = ttk.Progressbar(self, mode="determinate", maximum=1000, length=420)
        self._bar.pack(side="left", padx=(0, 10))
        self._cancel = _button(self, "Cancel", self._on_cancel)
        self._message = tk.StringVar(value="")
        tk.Label(self, textvariable=self._message, bg=bg, fg=_SUB, font=_FCAP, anchor="w",
                 wraplength=560, justify="left").pack(side="left", fill="x", expand=True)
        self._cancel_event: Optional[threading.Event] = None

    def start(self, cancel_event: Optional[threading.Event] = None, message: str = "Starting…"):
        self._cancel_event = cancel_event
        self._bar["value"] = 0
        self._message.set(message)
        if cancel_event is not None:
            self._cancel.pack(side="left", padx=(0, 10), before=self._bar)
            self._cancel.configure(state="normal")

    def update_progress(self, message: str, fraction: float):
        self._bar["value"] = int(max(0.0, min(1.0, fraction)) * 1000)
        self._message.set(message)

    def finish(self, message: str):
        self._bar["value"] = 1000
        self._message.set(message)
        self._cancel.pack_forget()
        self._cancel_event = None

    def _on_cancel(self):
        if self._cancel_event is not None:
            self._cancel_event.set()
            self._cancel.configure(state="disabled")
            self._message.set("Cancelling after the current execution…")


class BackgroundTask:
    """Run ``fn(progress, cancel)`` on a worker thread; marshal results via a queue."""

    def __init__(self, widget: tk.Widget, fn, *, on_progress, on_done, on_error, on_cancel=None):
        self.cancel = threading.Event()
        self._queue: "queue.Queue[tuple]" = queue.Queue()
        self._widget = widget
        self._handlers = dict(progress=on_progress, done=on_done, error=on_error,
                              cancelled=on_cancel or (lambda: None))

        def progress(message: str, fraction: float) -> None:
            self._queue.put(("progress", message, fraction))

        def run():
            try:
                self._queue.put(("done", fn(progress, self.cancel)))
            except BenchmarkCancelled:
                self._queue.put(("cancelled",))
            except Exception as exc:  # surfaced to the user, with traceback for diagnosis
                self._queue.put(("error", str(exc), traceback.format_exc()))

        threading.Thread(target=run, daemon=True).start()
        widget.after(100, self._poll)

    def _poll(self):
        finished = False
        try:
            while True:
                item = self._queue.get_nowait()
                kind = item[0]
                if kind == "progress":
                    self._handlers["progress"](item[1], item[2])
                elif kind == "done":
                    self._handlers["done"](item[1])
                    finished = True
                elif kind == "cancelled":
                    self._handlers["cancelled"]()
                    finished = True
                else:
                    self._handlers["error"](item[1], item[2])
                    finished = True
        except queue.Empty:
            pass
        if not finished:
            self._widget.after(100, self._poll)


class _Tab(tk.Frame):
    def __init__(self, parent, app: "Blake3App"):
        super().__init__(parent, bg=_BG)
        self.app = app
        self.busy = False
        self.scroll = _Scroll(self)
        self.scroll.pack(fill="both", expand=True)
        self.body = self.scroll.inner

    def status(self, text: str) -> None:
        self.app.status_var.set(text)

    def guard_busy(self) -> bool:
        if self.busy:
            messagebox.showinfo("Busy", "Please wait for the current task to finish (or cancel it).")
            return True
        return False

    def report_error(self, message: str, trace: str) -> None:
        print(trace, file=sys.stderr)
        messagebox.showerror("Error", message)


# ─────────────────────────────────────────────────────────────────────────────
# Tab 1 — Overview
# ─────────────────────────────────────────────────────────────────────────────

class OverviewTab(_Tab):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        _heading(self.body, "Optimized BLAKE3 for multi-format forensic hashing",
                 "The study optimizes how files are fed to BLAKE3. The BLAKE3 algorithm "
                 "itself is not modified, and every digest is standard BLAKE3-256.")

        techniques = _section(self.body, "What the study optimizes (implementation level only)")
        for name, detail, where in (
            ("Adaptive input-buffer sizing",
             "The read buffer grows with file size (64 KiB → 16 MiB) instead of a fixed 1 MiB, "
             "so large files need fewer read and update calls.",
             "Technique Benchmark tab"),
            ("Multithreaded processing of large files",
             "Files of %d MiB or more use BLAKE3's own tree-parallel mode on all physical cores; "
             "smaller files stay single-threaded because thread start-up costs more than it saves."
             % (SMALL_FILE_LIMIT // MIB),
             "Technique Benchmark tab"),
            ("Batched processing of small files",
             "Small files are grouped into batches of %d per worker task, so one dispatch and one "
             "reusable buffer serve many files." % DEFAULT_BATCH_SIZE,
             "Small-File Batching tab"),
        ):
            row = tk.Frame(techniques, bg=_SURF)
            row.pack(fill="x", pady=4)
            tk.Label(row, text="●", bg=_SURF, fg=_ACCENT, font=_FH3).pack(side="left", anchor="n")
            text = tk.Frame(row, bg=_SURF)
            text.pack(side="left", fill="x", expand=True, padx=8)
            tk.Label(text, text=name, bg=_SURF, fg=_TEXT, font=_FH3, anchor="w").pack(anchor="w")
            tk.Label(text, text=detail + "  Measured in: " + where + ".", bg=_SURF, fg=_SUB,
                     font=_FCAP, wraplength=980, justify="left", anchor="w").pack(anchor="w")

        constant = _section(self.body, "What is held constant (not claimed as a contribution)")
        for line in (
            "The BLAKE3 algorithm and its output: official test vectors and an independent "
            "reference implementation confirm standard digests (Verification tab, V1–V3).",
            "Native SIMD dispatch (%s): the same in the baseline and every optimized "
            "configuration." % detected_simd_tier(),
            "Reference algorithms (SHA-256, SHA-1, MD5): use the same 1 MiB, single-thread I/O "
            "path as Baseline BLAKE3. They are measured as configured here, not at their best "
            "possible speed.",
        ):
            tk.Label(constant, text="•  " + line, bg=_SURF, fg=_TEXT, font=_FBOD, wraplength=1000,
                     justify="left", anchor="w").pack(anchor="w", pady=2)

        arch = _section(self.body, "System architecture",
                        "Four layers. Each layer calls only the layer below it.")
        for tier, modules, role in (
            ("1  Presentation", "main_app.py", "Tkinter interface: input selection, progress, "
             "tables, charts, export."),
            ("2  Experiment control", "benchmark_blake3.py · blake3_validation.py · dataset_tool.py",
             "Runs the experiments and verification procedures: randomized order, warm-ups, "
             "correctness gates, dataset manifest."),
            ("3  Measurement & statistics", "metrics.py · _MetricSampler",
             "Timing, CPU and memory sampling; formulas F1–F19; Wilcoxon, bootstrap, Cliff's δ, Holm."),
            ("4  Hashing engine", "optimized_blake3.py → blake3 native extension",
             "Adaptive policy, configurations, batching, process pool; standard BLAKE3 with "
             "native SIMD."),
        ):
            row = tk.Frame(arch, bg=_SURF2, highlightbackground=_BORDER, highlightthickness=1)
            row.pack(fill="x", pady=3)
            tk.Label(row, text=tier, bg=_SURF2, fg=_ACCENT, font=_FH3, width=26, anchor="w"
                     ).pack(side="left", padx=10, pady=8)
            col = tk.Frame(row, bg=_SURF2)
            col.pack(side="left", fill="x", expand=True, pady=6)
            tk.Label(col, text=modules, bg=_SURF2, fg=_TEXT, font=_FMON, anchor="w").pack(anchor="w")
            tk.Label(col, text=role, bg=_SURF2, fg=_SUB, font=_FCAP, anchor="w", wraplength=760,
                     justify="left").pack(anchor="w")

        flow = _section(self.body, "Suggested demonstration order")
        for step in (
            "1. Dataset: generate the size sweep and small-file set, or catalogue your evidence "
            "folder. Review the coverage matrix and gaps.",
            "2. Verification: run all procedures. Every check must pass before you trust any "
            "timing result.",
            "3. Technique Benchmark: add files from several size tiers and run 30 trials. Read the "
            "verdicts and the factorial effects.",
            "4. Small-File Batching: run on the small-file set. Batching and parallel dispatch are "
            "measured separately and together.",
            "5. Methodology: export the formulas and analysis plan for Chapter 3.",
        ):
            tk.Label(flow, text=step, bg=_SURF, fg=_TEXT, font=_FBOD, wraplength=1000,
                     justify="left", anchor="w").pack(anchor="w", pady=2)
        tk.Frame(self.body, bg=_BG, height=20).pack()


# ─────────────────────────────────────────────────────────────────────────────
# Tab 2 — File Analysis
# ─────────────────────────────────────────────────────────────────────────────

class FileAnalysisTab(_Tab):
    _AVALANCHE_SAMPLES = 1000
    _COLLISION_VARIANTS = 300
    _BENCHMARK_REPEATS = 7
    _BENCHMARK_WARMUPS = 2
    _MODES = {
        "All physical cores (optimized threading)": "optimized",
        "One thread (baseline threading)": "baseline",
    }

    def __init__(self, parent, app):
        super().__init__(parent, app)
        _heading(self.body, "File Analysis",
                 "Fingerprint one file and check its hash behaviour. The speed shown here is "
                 "in-memory BLAKE3 speed. For controlled baseline-versus-optimized comparisons, "
                 "use the Technique Benchmark tab.")
        pick = _section(self.body, "Evidence file")
        row = tk.Frame(pick, bg=_SURF)
        row.pack(fill="x")
        self._path_var = tk.StringVar()
        tk.Entry(row, textvariable=self._path_var, bg=_SURF2, fg=_TEXT, relief="flat",
                 font=_FMON).pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))
        _button(row, "Browse…", self._browse).pack(side="left", padx=(0, 8))
        self._run_btn = _button(row, "Analyze file  →", self._start, primary=True)
        self._run_btn.pack(side="left")
        opt = tk.Frame(pick, bg=_SURF)
        opt.pack(fill="x", pady=(8, 0))
        _cap(opt, "In-memory speed measured with:").pack(side="left")
        self._mode_var = tk.StringVar(value=next(iter(self._MODES)))
        ttk.Combobox(opt, textvariable=self._mode_var, values=list(self._MODES), width=40,
                     state="readonly").pack(side="left", padx=8)
        self._progress = ProgressPanel(pick)
        self._progress.pack(fill="x", pady=(8, 0))

        fp = _section(self.body, "File fingerprint", "BLAKE3-256 digest of the complete file")
        self._digest_var = tk.StringVar(value="The file's BLAKE3 hash will appear here")
        tk.Label(fp, textvariable=self._digest_var, bg=_SURF2, fg=_ACCENT, font=("Consolas", 11),
                 anchor="w", padx=14, pady=12, wraplength=1000, justify="left").pack(fill="x")
        _button(fp, "Copy digest", self._copy).pack(anchor="w", pady=(6, 8))
        tiles = tk.Frame(fp, bg=_SURF)
        tiles.pack(fill="x")
        self._tiles: Dict[str, tk.StringVar] = {}
        for index, (label, key) in enumerate((
            ("Median in-memory time", "elapsed"), ("In-memory throughput", "throughput"),
            ("File size / size tier", "size"), ("Worker threads", "threads"),
        )):
            tiles.columnconfigure(index, weight=1, uniform="tiles")
            cell = tk.Frame(tiles, bg=_SURF2, highlightbackground=_BORDER, highlightthickness=1)
            cell.grid(row=0, column=index, sticky="nsew", padx=3)
            _cap(cell, label, bg=_SURF2).pack(anchor="w", padx=8, pady=(6, 0))
            var = tk.StringVar(value="—")
            self._tiles[key] = var
            tk.Label(cell, textvariable=var, bg=_SURF2, fg=_TEXT, font=("Segoe UI", 14, "bold"),
                     wraplength=240, justify="left").pack(anchor="w", padx=8, pady=(0, 8))
        self._perf_note = tk.StringVar(value="File loading is excluded from the timer.")
        _cap(fp, "", wraplength=1000, justify="left", textvariable=self._perf_note).pack(fill="x", pady=(8, 0))

        diag = _section(self.body, "Hash behaviour diagnostics",
                        "These use the selected file (or its first 4 MiB). They are empirical "
                        "diagnostics, not proofs of security.")
        self._diag = _table(diag, [
            ("check", "Diagnostic", 210, "w"), ("result", "Result", 150, "w"),
            ("observed", "Observed", 330, "w"), ("expected", "Expected", 330, "w"),
        ], height=8)
        self._scope_var = tk.StringVar(value="")
        _cap(diag, "", textvariable=self._scope_var, wraplength=1000, justify="left").pack(fill="x", pady=(6, 0))
        tk.Frame(self.body, bg=_BG, height=20).pack()

    def _browse(self):
        path = filedialog.askopenfilename(title="Select a file to analyse")
        if path:
            self._path_var.set(path)

    def _copy(self):
        digest = self._digest_var.get()
        if len(digest) == 64:
            self.clipboard_clear()
            self.clipboard_append(digest)
            self.status("Digest copied to clipboard")

    def _start(self):
        if self.guard_busy():
            return
        path = self._path_var.get().strip()
        if not os.path.isfile(path):
            messagebox.showwarning("No file", "Select a valid file first.")
            return
        mode = self._MODES[self._mode_var.get()]
        self.busy = True
        self._run_btn.configure(state="disabled")
        self._digest_var.set("Hashing…")
        for var in self._tiles.values():
            var.set("…")
        self._diag.delete(*self._diag.get_children())
        task = BackgroundTask(self, lambda progress, cancel: self._work(path, mode, progress),
                              on_progress=self._progress.update_progress,
                              on_done=self._done, on_error=self._error)
        self._progress.start(None, "Loading file into RAM (not timed)…")
        self.status("File analysis running…")

    def _work(self, path: str, mode: str, progress) -> Dict[str, Any]:
        initial = Path(path).stat()
        threads = 1 if mode == "baseline" else physical_cpu_count()
        progress("Loading file into RAM (not timed)…", 0.05)
        try:
            snapshot = load_file_snapshot(path, max_bytes=recommended_memory_benchmark_limit())
        except MemoryError:
            snapshot = load_file_snapshot(path, max_bytes=min(int(initial.st_size), 64 * MIB))
        digest = ""
        if not snapshot.complete:
            progress("Computing full-file digest…", 0.15)
            result = hash_file(path, expected_size=int(initial.st_size))
            if result.status != "ok":
                raise RuntimeError(result.error or "hashing failed")
            digest = result.digest
        progress("Measuring in-memory BLAKE3 speed…", 0.3)
        bench = benchmark_memory(snapshot.data, threads=threads,
                                 repeats=self._BENCHMARK_REPEATS, warmups=self._BENCHMARK_WARMUPS)
        if snapshot.complete:
            digest = bench.digest
        sample = bytes(memoryview(snapshot.data)[:4 * MIB])
        del snapshot
        progress("Avalanche analysis (%d single-bit flips)…" % self._AVALANCHE_SAMPLES, 0.45)
        avalanche = avalanche_analysis(sample, samples=self._AVALANCHE_SAMPLES)
        progress("Duplicate-digest screen…", 0.75)
        collisions = collision_screen(sample, variants=self._COLLISION_VARIANTS)
        balance = bit_balance(collisions.pop("digests"))
        final = Path(path).stat()
        if final.st_size != initial.st_size or final.st_mtime_ns != initial.st_mtime_ns:
            raise RuntimeError("The evidence file changed during analysis")
        return {"path": path, "size": int(initial.st_size), "digest": digest, "bench": bench,
                "complete": bench.bytes_hashed == initial.st_size,
                "avalanche": avalanche, "collisions": collisions, "balance": balance}

    def _done(self, result):
        self.busy = False
        self._run_btn.configure(state="normal")
        bench = result["bench"]
        self._digest_var.set(result["digest"])
        self._tiles["elapsed"].set(fmt_ms(bench.median_elapsed_ms))
        self._tiles["throughput"].set("%.1f MiB/s" % bench.median_throughput_mib_s)
        self._tiles["size"].set("%s\n%s" % (format_size(result["size"]), size_tier(result["size"])))
        self._tiles["threads"].set(str(bench.threads_used))
        scope = ("complete file" if result["complete"] else
                 "first %s of %s (full-file digest computed separately)"
                 % (format_size(bench.bytes_hashed), format_size(result["size"])))
        self._perf_note.set(
            "In-memory median of %d trials after %d warm-ups over the %s; file loading excluded. "
            "Range %.1f–%.1f MiB/s." % (bench.repeats, bench.warmups, scope,
                                         bench.min_throughput_mib_s, bench.max_throughput_mib_s))
        a, c, b = result["avalanche"], result["collisions"], result["balance"]
        rows = []
        if a.get("applicable"):
            rows += [
                ("Avalanche: mean bits changed", a["mean_test_passed"],
                 "%.2f of 256 (%.2f %%), z = %.2f" % (a["mean_changed_bits"], a["mean_changed_percent"], a["mean_z"]),
                 "128 of 256 (50 %), |z| < 3.29"),
                ("Avalanche: distribution fit", a["chi_square_passed"],
                 "χ² = %.1f, df = %d, p = %s" % (a["chi_square"], a["chi_square_df"], fmt_p(a["chi_square_p"])),
                 "Binomial(256, ½), p > 0.001"),
                ("Strict avalanche criterion", a["sac_passed"],
                 "per-bit flip probability %.3f–%.3f; %d bit(s) outside band"
                 % (a["sac_min_probability"], a["sac_max_probability"], a["sac_bits_outside_band"]),
                 "every bit near 0.5; ≤ 3 outside %s" % fmt_ci(a["sac_band"], "%.3f")),
            ]
        else:
            rows.append(("Avalanche", None, "not applicable (empty file)", "—"))
        rows += [
            ("Duplicate-digest screen", c["passed"],
             "%d inputs, %d duplicates" % (c["inputs_tested"], len(c["duplicates"])), "0 duplicates"),
            ("Output bit balance", b["passed"],
             "%.2f %% ones over %d bits (z = %.2f)" % (b["ones_percent"], b["total_bits"], b["z"]),
             "≈ 50 % ones, |z| < 3.29"),
        ]
        for name, passed, observed, expected in rows:
            label = "n/a" if passed is None else ("PASS" if passed else "OUTSIDE RANGE")
            tag = () if passed is None else (("pass",) if passed else ("fail",))
            self._diag.insert("", "end", values=(name, label, observed, expected), tags=tag)
        self._scope_var.set("Sample: %s. %s" % (
            "entire file" if result["size"] <= 4 * MIB else "first 4 MiB", LIMITATIONS))
        self._progress.finish("Analysis complete")
        self.status("Analysis complete for %s" % Path(result["path"]).name)

    def _error(self, message, trace):
        self.busy = False
        self._run_btn.configure(state="normal")
        self._digest_var.set("Error")
        self._progress.finish("Failed: " + message)
        self.report_error(message, trace)


# ─────────────────────────────────────────────────────────────────────────────
# Shared controls for the two experiments
# ─────────────────────────────────────────────────────────────────────────────

class _TrialControls(tk.Frame):
    def __init__(self, parent, default_trials=DEFAULT_TRIALS):
        super().__init__(parent, bg=_SURF)
        _cap(self, "Measured trials").pack(side="left")
        self.trials = tk.IntVar(value=default_trials)
        ttk.Spinbox(self, from_=MIN_TRIALS, to=200, increment=5, width=5,
                    textvariable=self.trials).pack(side="left", padx=(6, 16))
        _cap(self, "Warm-ups (excluded)").pack(side="left")
        self.warmups = tk.IntVar(value=DEFAULT_WARMUPS)
        ttk.Spinbox(self, from_=0, to=10, width=4, textvariable=self.warmups).pack(side="left", padx=(6, 16))

    def values(self) -> Optional[Tuple[int, int]]:
        try:
            trials, warmups = int(self.trials.get()), int(self.warmups.get())
        except (TypeError, ValueError, tk.TclError):
            messagebox.showerror("Invalid settings", "Trials and warm-ups must be whole numbers.")
            return None
        if trials < MIN_TRIALS:
            messagebox.showerror("Too few trials",
                                 "Use at least %d measured trials (30 recommended)." % MIN_TRIALS)
            return None
        return trials, max(0, warmups)


def _comparison_row_values(label, item, comparison, *, reference=False):
    stats = item["elapsed_ms"]
    if comparison is None:
        speed, ci, change, p, delta, verdict = "1.00× (baseline)", "—", "—", "—", "—", "reference point"
    else:
        speed = fmt_speedup(comparison["speedup"])
        ci = fmt_ci(comparison["speedup_ci95"])
        change = fmt_num(comparison["percent_time_reduction"], "%+.1f %%")
        p = fmt_p(comparison.get("p_holm"))
        delta = "%.2f (%s)" % (comparison["cliffs_delta"], comparison["cliffs_magnitude"])
        verdict = comparison["verdict"]
        if reference:
            verdict = "Optimized " + verdict
    return (
        label, fmt_ms(stats["median"]), fmt_ci(item["elapsed_median_ci95"], "%.2f"),
        fmt_num(stats["cv_percent"], "%.1f %%"),
        fmt_num(item["throughput_mib_s"]["median"], "%.1f"),
        fmt_num(item["cpu_percent_median"], "%.1f %%"),
        fmt_num(item["peak_rss_mib_median"], "%.1f"),
        speed, ci, change, p, delta, verdict,
    )


_RESULT_COLUMNS = [
    ("config", "Configuration", 250, "w"), ("median", "Median", 85, "e"),
    ("ci", "95% CI (ms)", 135, "e"), ("cv", "CV", 60, "e"),
    ("thr", "MiB/s", 70, "e"), ("cpu", "CPU", 65, "e"), ("rss", "Peak MiB", 80, "e"),
    ("speed", "Speedup", 110, "e"), ("sci", "Speedup CI", 115, "e"),
    ("change", "Time Δ", 75, "e"), ("p", "p Holm", 70, "e"),
    ("delta", "Cliff's δ", 120, "w"), ("verdict", "Verdict", 210, "w"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Tab 3 — Technique Benchmark (large files)
# ─────────────────────────────────────────────────────────────────────────────

class TechniqueBenchmarkTab(_Tab):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self._files: List[str] = []
        self._report: Optional[Dict[str, Any]] = None
        _heading(self.body, "Technique Benchmark — large files",
                 "A 2×2 factorial experiment: adaptive buffering (on/off) × multithreading (on/off). "
                 "Every configuration runs once per round in random order. Results are paired by "
                 "round and compared with Baseline BLAKE3 (fixed 1 MiB buffer, one thread).")

        setup = _section(self.body, "1  Select files",
                         "Use files from several size tiers. Multithreading starts at %d MiB, so "
                         "smaller files show its 'off' behaviour by design." % (SMALL_FILE_LIMIT // MIB))
        buttons = tk.Frame(setup, bg=_SURF)
        buttons.pack(fill="x")
        _button(buttons, "Add files…", self._add_files).pack(side="left", padx=(0, 6))
        _button(buttons, "Add folder…", self._add_folder).pack(side="left", padx=(0, 6))
        _button(buttons, "Remove selected", self._remove).pack(side="left", padx=(0, 6))
        _button(buttons, "Clear", self._clear).pack(side="left")
        self._file_table = _table(setup, [
            ("name", "File", 380, "w"), ("size", "Size", 110, "e"),
            ("tier", "Size tier", 240, "w"), ("threads", "Multithreading applies", 170, "w"),
        ], height=5)

        run = _section(self.body, "2  Configure and run")
        self._trials = _TrialControls(run)
        self._trials.pack(fill="x")
        options = tk.Frame(run, bg=_SURF)
        options.pack(fill="x", pady=(8, 0))
        self._refs = tk.BooleanVar(value=True)
        self._mmap = tk.BooleanVar(value=False)
        tk.Checkbutton(options, text="Include SHA-256 / SHA-1 / MD5 reference algorithms",
                       variable=self._refs, bg=_SURF, font=_FBOD).pack(side="left")
        tk.Checkbutton(options, text="Include exploratory mmap configuration (not a claimed technique)",
                       variable=self._mmap, bg=_SURF, font=_FBOD).pack(side="left", padx=16)
        action = tk.Frame(run, bg=_SURF)
        action.pack(fill="x", pady=(10, 0))
        self._run_btn = _button(action, "Run experiment  →", self._start, primary=True)
        self._run_btn.pack(side="left")
        self._progress = ProgressPanel(action)
        self._progress.pack(side="left", fill="x", expand=True, padx=12)

        results = _section(self.body, "3  Results")
        top = tk.Frame(results, bg=_SURF)
        top.pack(fill="x")
        _cap(top, "Show file:").pack(side="left")
        self._file_choice = tk.StringVar()
        self._chooser = ttk.Combobox(top, textvariable=self._file_choice, width=60, state="readonly")
        self._chooser.pack(side="left", padx=8)
        self._chooser.bind("<<ComboboxSelected>>", lambda _e: self._show_file())
        _button(top, "Open results folder", lambda: open_folder(RESULTS_DIR)).pack(side="right")
        self._headline = tk.StringVar(value="No results yet.")
        tk.Label(results, textvariable=self._headline, bg=_SURF, fg=_TEXT, font=_FH2, anchor="w",
                 wraplength=1040, justify="left").pack(fill="x", pady=(10, 4))
        self._table = _table(results, _RESULT_COLUMNS, height=8)
        _cap(results, "BLAKE3 rows: Speedup = Baseline time ÷ configuration time. Reference rows "
                      "(grey): Speedup = that algorithm's time ÷ Optimized BLAKE3 time, measured with "
                      "the same 1 MiB single-thread I/O path.", wraplength=1040, justify="left"
             ).pack(fill="x", pady=(4, 0))
        self._factorial = tk.StringVar(value="")
        tk.Label(results, textvariable=self._factorial, bg=_SURF2, fg=_TEXT, font=_FBOD, anchor="w",
                 justify="left", wraplength=1040, padx=12, pady=10).pack(fill="x", pady=(10, 6))
        self._chart = SpeedupChart(results)
        self._chart.pack(fill="x", pady=(4, 6))
        _cap(results, "Speedup by size tier (geometric mean across files)").pack(anchor="w", pady=(8, 2))
        self._tier_table = _table(results, [
            ("tier", "Size tier", 260, "w"), ("config", "Configuration", 240, "w"),
            ("files", "Files", 60, "e"), ("gm", "Geometric-mean speedup", 170, "e"),
            ("faster", "Significantly faster", 150, "e"), ("slower", "Significantly slower", 150, "e"),
        ], height=5)
        self._notes = tk.StringVar(value="")
        _cap(results, "", textvariable=self._notes, wraplength=1040, justify="left").pack(fill="x", pady=(8, 0))
        tk.Frame(self.body, bg=_BG, height=20).pack()

    # file list management
    def _refresh_files(self):
        self._file_table.delete(*self._file_table.get_children())
        for path in self._files:
            size = os.path.getsize(path)
            self._file_table.insert("", "end", iid=path, values=(
                os.path.basename(path), format_size(size), size_tier(size),
                "yes" if size >= SMALL_FILE_LIMIT else "no (below threshold)"))

    def _add(self, paths):
        for path in paths:
            path = str(Path(path).resolve())
            if os.path.isfile(path) and path not in self._files:
                self._files.append(path)
        self._files.sort(key=os.path.getsize)
        self._refresh_files()

    def _add_files(self):
        self._add(filedialog.askopenfilenames(title="Select benchmark files"))

    def _add_folder(self):
        folder = filedialog.askdirectory(title="Select a folder (files in it are added, not subfolders)")
        if folder:
            self._add([str(p) for p in Path(folder).iterdir() if p.is_file()])

    def _remove(self):
        for iid in self._file_table.selection():
            self._files.remove(iid)
        self._refresh_files()

    def _clear(self):
        self._files.clear()
        self._refresh_files()

    def _start(self):
        if self.guard_busy():
            return
        if not self._files:
            messagebox.showwarning("No files", "Add at least one file.")
            return
        settings = self._trials.values()
        if settings is None:
            return
        trials, warmups = settings
        files, refs, mmap_cfg = list(self._files), self._refs.get(), self._mmap.get()
        self.busy = True
        self._run_btn.configure(state="disabled")

        def work(progress, cancel):
            report = run_large_file_ablation(files, trials=trials, warmups=warmups,
                                             include_references=refs, include_exploratory=mmap_cfg,
                                             progress=progress, cancel=cancel)
            report["exports"] = export_report(report, RESULTS_DIR, "large_file_ablation_" + timestamp())
            return report

        task = BackgroundTask(self, work, on_progress=self._progress.update_progress,
                              on_done=self._done, on_error=self._error, on_cancel=self._cancelled)
        self._progress.start(task.cancel, "Self-test and first warm-up…")
        self.status("Technique benchmark running…")

    def _done(self, report):
        self.busy = False
        self._run_btn.configure(state="normal")
        self._report = report
        names = ["%s  (%s)" % (f["file"], format_size(f["size_bytes"])) for f in report["files"]]
        self._chooser.configure(values=names)
        self._chooser.current(len(names) - 1)
        self._show_file()
        self._tier_table.delete(*self._tier_table.get_children())
        labels = {c["key"]: c["label"] for c in report["conditions"]}
        for row in report["tier_summary"]:
            self._tier_table.insert("", "end", values=(
                row["size_tier"], labels.get(row["condition"], row["condition"]), row["files"],
                fmt_speedup(row["geometric_mean_speedup"]),
                row["significantly_faster"], row["significantly_slower"]))
        exports = report["exports"]
        self._notes.set("Saved: %s · %s · %s" % (exports["json"], exports["summary_csv"], exports["runs_csv"])
                        + ("\nMeasurement notes: " + " ".join(report["warnings"]) if report["warnings"] else ""))
        self._progress.finish("Complete. Every execution reproduced the expected digest.")
        self.status("Technique benchmark complete")

    def _show_file(self):
        if not self._report:
            return
        report = self._report["files"][max(0, self._chooser.current())]
        comparisons = {(c["family"], c["candidate"] if c["family"] == "technique" else c["reference"]): c
                       for c in report["comparisons"]}
        self._table.delete(*self._table.get_children())
        chart_items = []
        for key, item in report["conditions"].items():
            reference = item["kind"] == "reference"
            comparison = comparisons.get(("reference" if reference else "technique", key))
            label = item["label"]
            if not reference:
                label += "  [%s, %d thr]" % (format_size(item["buffer_bytes"]), item["threads"])
            tag = ("base",) if key == "baseline" else (
                ("ref",) if reference else (_VERDICT_TAG.get(comparison["verdict"], "neutral"),))
            self._table.insert("", "end", values=_comparison_row_values(
                label, item, comparison, reference=reference), tags=tag)
            if comparison and not reference:
                color = {"win": _GREEN, "loss": _RED}.get(_VERDICT_TAG.get(comparison["verdict"]), _GRAY)
                chart_items.append((item["label"], comparison["speedup"], comparison["speedup_ci95"], color))
        self._chart.set_data(chart_items, "Speedup over Baseline BLAKE3 — %s" % report["file"])
        optimized = comparisons.get(("technique", "optimized"))
        if optimized:
            self._headline.set("%s (%s, %s): Optimized BLAKE3 is %s vs baseline — %s, 95 %% CI %s, "
                               "Holm-adjusted p %s." % (
                                   report["file"], format_size(report["size_bytes"]), report["size_tier"],
                                   optimized["verdict"], fmt_speedup(optimized["speedup"]),
                                   fmt_ci(optimized["speedup_ci95"]), fmt_p(optimized.get("p_holm"))))
        f = report["factorial"]
        if f.get("effect_a") is not None:
            self._factorial.set(
                "Factorial effects (F14):  adaptive buffering ×%.3f  ·  multithreading ×%.3f  ·  "
                "interaction %s" % (f["effect_a"], f["effect_b"], interaction_text(f["interaction"]))
                + ("\n" + "\n".join(report["warnings"]) if report["warnings"] else ""))
        else:
            self._factorial.set("\n".join(report["warnings"]))

    def _cancelled(self):
        self.busy = False
        self._run_btn.configure(state="normal")
        self._progress.finish("Cancelled; no partial results were saved.")
        self.status("Technique benchmark cancelled")

    def _error(self, message, trace):
        self.busy = False
        self._run_btn.configure(state="normal")
        self._progress.finish("Failed: " + message)
        self.report_error(message, trace)


# ─────────────────────────────────────────────────────────────────────────────
# Tab 4 — Small-File Batching
# ─────────────────────────────────────────────────────────────────────────────

class SmallFileTab(_Tab):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self._paths: List[str] = []
        _heading(self.body, "Small-File Batching",
                 "A 2×2 factorial experiment on a set of small files: batching (on/off) × "
                 "parallel dispatch to worker processes (on/off). One trial hashes the whole set. "
                 "The baseline is sequential, one file at a time.")
        setup = _section(self.body, "1  Select the small-file set",
                         "Every file below %d MiB in the folder and its subfolders is included. "
                         "Use 500 or more files; the Dataset tab can generate a corpus."
                         % (SMALL_FILE_LIMIT // MIB))
        row = tk.Frame(setup, bg=_SURF)
        row.pack(fill="x")
        self._folder = tk.StringVar()
        tk.Entry(row, textvariable=self._folder, bg=_SURF2, relief="flat", font=_FMON
                 ).pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))
        _button(row, "Choose folder…", self._choose).pack(side="left")
        self._set_info = tk.StringVar(value="No folder selected.")
        _cap(setup, "", textvariable=self._set_info).pack(fill="x", pady=(6, 0))

        run = _section(self.body, "2  Configure and run")
        self._trials = _TrialControls(run)
        self._trials.pack(fill="x")
        more = tk.Frame(run, bg=_SURF)
        more.pack(fill="x", pady=(8, 0))
        _cap(more, "Worker processes").pack(side="left")
        self._workers = tk.IntVar(value=physical_cpu_count())
        ttk.Spinbox(more, from_=2, to=max(2, logical_cpu_count()), width=4,
                    textvariable=self._workers).pack(side="left", padx=(6, 16))
        _cap(more, "Files per batch").pack(side="left")
        self._batch = tk.IntVar(value=DEFAULT_BATCH_SIZE)
        ttk.Spinbox(more, from_=2, to=1024, width=6, textvariable=self._batch).pack(side="left", padx=6)
        action = tk.Frame(run, bg=_SURF)
        action.pack(fill="x", pady=(10, 0))
        self._run_btn = _button(action, "Run experiment  →", self._start, primary=True)
        self._run_btn.pack(side="left")
        self._progress = ProgressPanel(action)
        self._progress.pack(side="left", fill="x", expand=True, padx=12)

        results = _section(self.body, "3  Results")
        _button(results, "Open results folder", lambda: open_folder(RESULTS_DIR)).pack(anchor="e")
        self._headline = tk.StringVar(value="No results yet.")
        tk.Label(results, textvariable=self._headline, bg=_SURF, fg=_TEXT, font=_FH2, anchor="w",
                 wraplength=1040, justify="left").pack(fill="x", pady=(6, 4))
        columns = list(_RESULT_COLUMNS)
        columns.insert(5, ("fps", "Files/s", 80, "e"))
        self._table = _table(results, columns, height=5)
        self._factorial = tk.StringVar(value="")
        tk.Label(results, textvariable=self._factorial, bg=_SURF2, fg=_TEXT, font=_FBOD, anchor="w",
                 justify="left", wraplength=1040, padx=12, pady=10).pack(fill="x", pady=(10, 6))
        self._chart = SpeedupChart(results)
        self._chart.pack(fill="x", pady=(4, 6))
        self._notes = tk.StringVar(value="")
        _cap(results, "", textvariable=self._notes, wraplength=1040, justify="left").pack(fill="x")
        tk.Frame(self.body, bg=_BG, height=20).pack()

    def _choose(self):
        folder = filedialog.askdirectory(title="Select the small-file folder")
        if not folder:
            return
        self._folder.set(folder)
        files = [str(p) for p in sorted(Path(folder).rglob("*")) if p.is_file()]
        self._paths = [p for p in files if os.path.getsize(p) < SMALL_FILE_LIMIT]
        total = sum(os.path.getsize(p) for p in self._paths)
        self._set_info.set("%d small files (%s total); %d larger files excluded."
                           % (len(self._paths), format_size(total), len(files) - len(self._paths)))

    def _start(self):
        if self.guard_busy():
            return
        if len(self._paths) < 2:
            messagebox.showwarning("No files", "Choose a folder containing at least two small files.")
            return
        settings = self._trials.values()
        if settings is None:
            return
        trials, warmups = settings
        try:
            workers, batch = int(self._workers.get()), int(self._batch.get())
        except (ValueError, tk.TclError):
            messagebox.showerror("Invalid settings", "Workers and batch size must be whole numbers.")
            return
        paths = list(self._paths)
        self.busy = True
        self._run_btn.configure(state="disabled")

        def work(progress, cancel):
            report = run_small_file_ablation(paths, trials=trials, warmups=warmups, workers=workers,
                                             batch_size=batch, progress=progress, cancel=cancel)
            report["exports"] = export_report(report, RESULTS_DIR, "small_file_ablation_" + timestamp())
            return report

        task = BackgroundTask(self, work, on_progress=self._progress.update_progress,
                              on_done=self._done, on_error=self._error, on_cancel=self._cancelled)
        self._progress.start(task.cancel, "Computing reference digests and starting workers…")
        self.status("Small-file experiment running…")

    def _done(self, report):
        self.busy = False
        self._run_btn.configure(state="normal")
        comparisons = {c["candidate"]: c for c in report["comparisons"]}
        self._table.delete(*self._table.get_children())
        chart_items = []
        for key, item in report["summary"].items():
            comparison = comparisons.get(key)
            values = list(_comparison_row_values(item["label"], item, comparison))
            values.insert(5, "%.0f" % item["files_per_second_median"])
            tag = ("base",) if comparison is None else (_VERDICT_TAG.get(comparison["verdict"], "neutral"),)
            self._table.insert("", "end", values=values, tags=tag)
            if comparison:
                color = {"win": _GREEN, "loss": _RED}.get(_VERDICT_TAG.get(comparison["verdict"]), _GRAY)
                chart_items.append((item["label"], comparison["speedup"], comparison["speedup_ci95"], color))
        workload = report["workload"]
        self._chart.set_data(chart_items, "Speedup over sequential per-file hashing — %d files"
                             % workload["files"])
        best = comparisons.get("parallel_batched")
        if best:
            self._headline.set("Parallel + batched is %s vs sequential per-file: %s, 95 %% CI %s, "
                               "Holm-adjusted p %s." % (best["verdict"], fmt_speedup(best["speedup"]),
                                                       fmt_ci(best["speedup_ci95"]), fmt_p(best.get("p_holm"))))
        f = report["factorial"]
        if f.get("effect_a") is not None:
            self._factorial.set(
                "Factorial effects (F14):  batching ×%.3f  ·  parallel dispatch ×%.3f  ·  interaction %s\n"
                "Workload: %d files, %s, median %s per file · %d workers · %d files per batch · worker "
                "start-up %.3f s (excluded from trials, reported separately)." % (
                    f["effect_a"], f["effect_b"], interaction_text(f["interaction"]),
                    workload["files"], format_size(workload["total_bytes"]),
                    format_size(workload["median_file_bytes"]), workload["workers"],
                    workload["batch_size"], workload["pool_startup_seconds"]))
        exports = report["exports"]
        self._notes.set("Saved: %s · %s · %s\nMeasurement notes: %s" % (
            exports["json"], exports["summary_csv"], exports["runs_csv"], " ".join(report["warnings"])))
        self._progress.finish("Complete. Every mode reproduced every file's digest.")
        self.status("Small-file experiment complete")

    def _cancelled(self):
        self.busy = False
        self._run_btn.configure(state="normal")
        self._progress.finish("Cancelled; no partial results were saved.")

    def _error(self, message, trace):
        self.busy = False
        self._run_btn.configure(state="normal")
        self._progress.finish("Failed: " + message)
        self.report_error(message, trace)


# ─────────────────────────────────────────────────────────────────────────────
# Tab 5 — Verification
# ─────────────────────────────────────────────────────────────────────────────

class VerificationTab(_Tab):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self._result: Optional[Dict[str, Any]] = None
        _heading(self.body, "Verification",
                 "Procedures for implementation correctness, hash consistency and avalanche "
                 "behaviour. They check that the optimizations never change a digest. They do "
                 "not re-prove BLAKE3's security.")
        setup = _section(self.body, "Input")
        row = tk.Frame(setup, bg=_SURF)
        row.pack(fill="x")
        self._path = tk.StringVar()
        tk.Entry(row, textvariable=self._path, bg=_SURF2, relief="flat", font=_FMON
                 ).pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))
        _button(row, "Browse…", self._browse).pack(side="left", padx=(0, 8))
        _button(row, "Use synthetic input", lambda: self._path.set("")).pack(side="left")
        _cap(setup, "Leave empty to use a seeded synthetic input that crosses the multithreading "
                    "threshold. A selected file is used for consistency (V3) and its first 4 MiB "
                    "for V4–V6.").pack(fill="x", pady=(6, 0))
        opts = tk.Frame(setup, bg=_SURF)
        opts.pack(fill="x", pady=(8, 0))
        _cap(opts, "Avalanche samples").pack(side="left")
        self._samples = tk.IntVar(value=1000)
        ttk.Spinbox(opts, from_=100, to=20000, increment=100, width=7,
                    textvariable=self._samples).pack(side="left", padx=(6, 16))
        _cap(opts, "Duplicate-screen inputs").pack(side="left")
        self._variants = tk.IntVar(value=2000)
        ttk.Spinbox(opts, from_=100, to=100000, increment=500, width=8,
                    textvariable=self._variants).pack(side="left", padx=6)
        action = tk.Frame(setup, bg=_SURF)
        action.pack(fill="x", pady=(10, 0))
        self._run_btn = _button(action, "Run all procedures  →", self._start, primary=True)
        self._run_btn.pack(side="left")
        self._progress = ProgressPanel(action)
        self._progress.pack(side="left", fill="x", expand=True, padx=12)

        results = _section(self.body, "Results")
        self._overall = tk.StringVar(value="Not run yet.")
        self._overall_label = tk.Label(results, textvariable=self._overall, bg=_SURF, fg=_TEXT,
                                       font=_FH2, anchor="w")
        self._overall_label.pack(fill="x", pady=(0, 6))
        self._table = _table(results, [
            ("procedure", "Procedure", 300, "w"), ("result", "Result", 80, "w"),
            ("evidence", "Evidence", 420, "w"), ("meaning", "What a pass means", 420, "w"),
        ], height=8)
        self._table.bind("<<TreeviewSelect>>", self._show_detail)
        _cap(results, "Select a row for details").pack(anchor="w", pady=(8, 2))
        self._detail = tk.Text(results, height=12, bg=_SURF2, fg=_TEXT, font=_FMON, relief="flat", wrap="word")
        self._detail.pack(fill="x")
        tk.Label(results, text="Limitations: " + LIMITATIONS, bg=_SURF, fg=_YELLOW, font=_FCAP,
                 wraplength=1040, justify="left", anchor="w").pack(fill="x", pady=(8, 0))
        self._saved = tk.StringVar(value="")
        _cap(results, "", textvariable=self._saved).pack(fill="x", pady=(4, 0))
        tk.Frame(self.body, bg=_BG, height=20).pack()

    def _browse(self):
        path = filedialog.askopenfilename(title="Select a file to verify against")
        if path:
            self._path.set(path)

    def _start(self):
        if self.guard_busy():
            return
        path = self._path.get().strip() or None
        if path and not os.path.isfile(path):
            messagebox.showwarning("Invalid file", "The selected path is not a file.")
            return
        try:
            samples, variants = int(self._samples.get()), int(self._variants.get())
        except (ValueError, tk.TclError):
            messagebox.showerror("Invalid settings", "Use whole numbers.")
            return
        self.busy = True
        self._run_btn.configure(state="disabled")

        def work(progress, cancel):
            result = run_validation(path, avalanche_samples=samples,
                                    collision_variants=variants, progress=progress)
            RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            out = RESULTS_DIR / ("verification_%s.json" % timestamp())
            out.write_text(json.dumps(result, indent=2), encoding="utf-8")
            result["saved_to"] = str(out)
            return result

        BackgroundTask(self, work, on_progress=self._progress.update_progress,
                       on_done=self._done, on_error=self._error)
        self._progress.start(None, "Starting…")
        self.status("Verification running…")

    @staticmethod
    def _evidence(p: Dict[str, Any]) -> str:
        name = p["procedure"]
        if name.startswith("V1"):
            return "%d/%d vectors × %d checks (%d-byte outputs)" % (
                p["cases_total"] - p["cases_failed"], p["cases_total"], p["checks_per_case"],
                p["output_bytes_checked"])
        if name.startswith("V2"):
            return "%d inputs, %d disagreements" % (p["inputs_tested"], len(p["failures"]))
        if name.startswith("V3"):
            return "%d variants, %d mismatches (%s)" % (p["variants_tested"], len(p["mismatches"]),
                                                       format_size(p["input_bytes"]))
        if name.startswith("V4"):
            return "%d repetitions, %d distinct digest(s)" % (p["repetitions"], p["distinct_digests"])
        if name.startswith("V5"):
            if not p.get("applicable"):
                return "not applicable"
            return "mean %.2f bits (z %.2f) · χ² p %s · SAC %d bit(s) outside band" % (
                p["mean_changed_bits"], p["mean_z"], fmt_p(p["chi_square_p"]), p["sac_bits_outside_band"])
        if name.startswith("V6a"):
            return "%d inputs, %d duplicates" % (p["inputs_tested"], len(p["duplicates"]))
        if name.startswith("V6b"):
            return "%.2f %% ones (z %.2f)" % (p["ones_percent"], p["z"])
        return ""

    def _done(self, result):
        self.busy = False
        self._run_btn.configure(state="normal")
        self._result = result
        self._table.delete(*self._table.get_children())
        for index, p in enumerate(result["procedures"]):
            passed = p.get("passed")
            if p.get("applicable", True) is False:
                label, tag = "N/A", ()
            else:
                label, tag = ("PASS", ("pass",)) if passed else ("FAIL", ("fail",))
            self._table.insert("", "end", iid=str(index), values=(
                p["procedure"], label, self._evidence(p), p.get("interpretation", "")), tags=tag)
        self._overall.set("ALL PROCEDURES PASSED" if result["passed"] else "ONE OR MORE PROCEDURES FAILED")
        self._overall_label.configure(fg=_GREEN if result["passed"] else _RED)
        self._saved.set("Saved: %s  (%.1f s)" % (result["saved_to"], result["duration_seconds"]))
        self._progress.finish("Verification complete")
        self.status("Verification complete")

    def _show_detail(self, _event=None):
        if not self._result or not self._table.selection():
            return
        procedure = dict(self._result["procedures"][int(self._table.selection()[0])])
        for bulky in ("cases", "observations", "lengths", "histogram_16_bins"):
            if bulky in procedure and isinstance(procedure[bulky], list) and len(procedure[bulky]) > 12:
                procedure[bulky] = "%d entries (see the saved JSON report)" % len(procedure[bulky])
        self._detail.delete("1.0", "end")
        self._detail.insert("1.0", json.dumps(procedure, indent=2, ensure_ascii=False))

    def _error(self, message, trace):
        self.busy = False
        self._run_btn.configure(state="normal")
        self._progress.finish("Failed: " + message)
        self.report_error(message, trace)


# ─────────────────────────────────────────────────────────────────────────────
# Tab 6 — Dataset
# ─────────────────────────────────────────────────────────────────────────────

class DatasetTab(_Tab):
    _MAX_SIZES = {"64 MiB": 64 * MIB, "256 MiB": 256 * MIB, "1 GiB": 1024 * MIB}

    def __init__(self, parent, app):
        super().__init__(parent, app)
        _heading(self.body, "Dataset",
                 "Build and document the benchmark dataset. The manifest records every file's "
                 "format, size tier, source and SHA-256. It shows what the dataset covers, what is "
                 "missing, and lets others reproduce it.")
        gen = _section(self.body, "Generate controlled inputs",
                       "Synthetic files are acceptable for size sweeps because BLAKE3's cost depends "
                       "on how many bytes there are, not on their values. Real files of each format "
                       "(documents, images, audio, video, archives, executables, disk images) are "
                       "still required to show the dataset is representative.")
        row = tk.Frame(gen, bg=_SURF)
        row.pack(fill="x")
        _cap(row, "Output folder").pack(side="left")
        self._out = tk.StringVar(value=str(_ROOT / "digital_evidence_dataset" / "generated"))
        tk.Entry(row, textvariable=self._out, bg=_SURF2, relief="flat", font=_FMON
                 ).pack(side="left", fill="x", expand=True, ipady=4, padx=8)
        _button(row, "Browse…", lambda: self._pick(self._out)).pack(side="left")
        row2 = tk.Frame(gen, bg=_SURF)
        row2.pack(fill="x", pady=(8, 0))
        _cap(row2, "Size sweep up to").pack(side="left")
        self._max = tk.StringVar(value="1 GiB")
        ttk.Combobox(row2, textvariable=self._max, values=list(self._MAX_SIZES), width=9,
                     state="readonly").pack(side="left", padx=(6, 8))
        self._gen_sweep = _button(row2, "Generate size sweep", self._sweep)
        self._gen_sweep.pack(side="left", padx=(0, 24))
        _cap(row2, "Small files").pack(side="left")
        self._count = tk.IntVar(value=2000)
        ttk.Spinbox(row2, from_=100, to=100000, increment=500, width=7, textvariable=self._count
                    ).pack(side="left", padx=(6, 8))
        self._gen_small = _button(row2, "Generate small-file corpus", self._small)
        self._gen_small.pack(side="left")
        self._gen_progress = ProgressPanel(gen)
        self._gen_progress.pack(fill="x", pady=(10, 0))

        cat = _section(self.body, "Catalogue a dataset folder",
                       "Optionally place a sources.json in the folder that maps paths to their "
                       'origin, e.g. {"disk_images/nps-2009-ntfs1.E01": {"source": '
                       '"Digital Corpora", "license": "public"}}. Note: an E01 container is hashed as '
                       "a stored file, so its digest is not the acquisition hash recorded inside it.")
        row3 = tk.Frame(cat, bg=_SURF)
        row3.pack(fill="x")
        self._root = tk.StringVar(value=str(_ROOT / "digital_evidence_dataset"))
        tk.Entry(row3, textvariable=self._root, bg=_SURF2, relief="flat", font=_FMON
                 ).pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 8))
        _button(row3, "Browse…", lambda: self._pick(self._root)).pack(side="left", padx=(0, 8))
        self._cat_btn = _button(row3, "Build manifest  →", self._catalogue, primary=True)
        self._cat_btn.pack(side="left", padx=(0, 8))
        _button(row3, "Verify existing manifest…", self._verify).pack(side="left")
        self._cat_progress = ProgressPanel(cat)
        self._cat_progress.pack(fill="x", pady=(10, 0))
        self._summary = tk.StringVar(value="")
        tk.Label(cat, textvariable=self._summary, bg=_SURF, fg=_TEXT, font=_FH3, anchor="w").pack(fill="x", pady=(8, 4))
        tiers = [label for label, _lo, _hi in SIZE_TIERS]
        self._matrix = _table(cat, [("category", "Category", 190, "w")]
                              + [("t%d" % i, label.split(" (")[0], 110, "center") for i, label in enumerate(tiers)]
                              + [("total", "Total", 70, "e")], height=11)
        _cap(cat, "Tier ranges: " + " · ".join(tiers), wraplength=1040, justify="left").pack(fill="x", pady=(6, 2))
        self._gaps = tk.Text(cat, height=6, bg=_SURF2, fg=_RED, font=_FBOD, relief="flat", wrap="word")
        self._gaps.pack(fill="x", pady=(6, 0))
        tk.Frame(self.body, bg=_BG, height=20).pack()

    def _pick(self, var: tk.StringVar):
        folder = filedialog.askdirectory(title="Select folder")
        if folder:
            var.set(folder)

    def _set_gen_state(self, state):
        self._gen_sweep.configure(state=state)
        self._gen_small.configure(state=state)

    def _run_generation(self, fn, done_text):
        if self.guard_busy():
            return
        self.busy = True
        self._set_gen_state("disabled")

        def done(paths):
            self.busy = False
            self._set_gen_state("normal")
            self._gen_progress.finish("%s: %d files in %s" % (done_text, len(paths), paths[0].parent if paths else ""))

        def error(message, trace):
            self.busy = False
            self._set_gen_state("normal")
            self._gen_progress.finish("Failed: " + message)
            self.report_error(message, trace)

        BackgroundTask(self, fn, on_progress=self._gen_progress.update_progress, on_done=done, on_error=error)
        self._gen_progress.start(None, "Writing files…")

    def _sweep(self):
        limit = self._MAX_SIZES[self._max.get()]
        sizes = [s for s in DEFAULT_SWEEP_SIZES if s <= limit]
        folder = Path(self._out.get()) / "size_sweep"
        self._run_generation(lambda progress, cancel: generate_size_sweep(folder, sizes, progress=progress),
                             "Size sweep written")

    def _small(self):
        try:
            count = int(self._count.get())
        except (ValueError, tk.TclError):
            messagebox.showerror("Invalid count", "Use a whole number.")
            return
        folder = Path(self._out.get()) / "small_files"
        self._run_generation(
            lambda progress, cancel: generate_small_file_corpus(folder, count=count, progress=progress),
            "Small-file corpus written")

    def _catalogue(self):
        if self.guard_busy():
            return
        root = self._root.get().strip()
        if not os.path.isdir(root):
            messagebox.showwarning("Invalid folder", "Select an existing dataset folder.")
            return
        self.busy = True
        self._cat_btn.configure(state="disabled")

        def work(progress, cancel):
            manifest = build_manifest(root, progress=progress)
            manifest["written"] = [str(p) for p in write_manifest(manifest, root)]
            return manifest

        BackgroundTask(self, work, on_progress=self._cat_progress.update_progress,
                       on_done=self._catalogued, on_error=self._cat_error)
        self._cat_progress.start(None, "Hashing and classifying files…")

    def _catalogued(self, manifest):
        self.busy = False
        self._cat_btn.configure(state="normal")
        self._matrix.delete(*self._matrix.get_children())
        tiers = [label for label, _lo, _hi in SIZE_TIERS]
        for category, counts in manifest["coverage_matrix"].items():
            total = sum(counts.values())
            values = [category] + [counts[t] or "·" for t in tiers] + [total]
            self._matrix.insert("", "end", values=values, tags=(() if total else ("fail",)))
        self._summary.set("%d files · %s · manifest written to %s" % (
            manifest["file_count"], format_size(manifest["total_bytes"]), manifest["written"][0]))
        self._gaps.delete("1.0", "end")
        if manifest["gaps"]:
            self._gaps.insert("1.0", "Coverage gaps to close before final benchmarking:\n• "
                              + "\n• ".join(manifest["gaps"]))
        else:
            self._gaps.insert("1.0", "No coverage gaps detected.")
        self._cat_progress.finish("Manifest complete")

    def _cat_error(self, message, trace):
        self.busy = False
        self._cat_btn.configure(state="normal")
        self._cat_progress.finish("Failed: " + message)
        self.report_error(message, trace)

    def _verify(self):
        if self.guard_busy():
            return
        path = filedialog.askopenfilename(title="Select dataset_manifest.json",
                                          filetypes=[("Manifest", "dataset_manifest.json"), ("JSON", "*.json")])
        if not path:
            return
        self.busy = True

        def done(report):
            self.busy = False
            self._cat_progress.finish("Manifest verification: %s (%d files; %d changed, %d missing)" % (
                "PASSED" if report["passed"] else "FAILED", report["checked"],
                len(report["changed"]), len(report["missing"])))

        def error(message, trace):
            self.busy = False
            self._cat_progress.finish("Failed: " + message)
            self.report_error(message, trace)

        BackgroundTask(self, lambda progress, cancel: verify_manifest(path),
                       on_progress=self._cat_progress.update_progress, on_done=done, on_error=error)
        self._cat_progress.start(None, "Re-hashing files listed in the manifest…")


# ─────────────────────────────────────────────────────────────────────────────
# Tab 7 — Methodology
# ─────────────────────────────────────────────────────────────────────────────

def methodology_markdown() -> str:
    lines = ["# Methodology: performance indicators and statistical analysis", "",
             "Generated by the Optimized BLAKE3 Forensic Toolkit on %s." % datetime.now().strftime("%Y-%m-%d"),
             "", "## Formulas", ""]
    for formula in metrics.FORMULAS:
        lines += ["### %s. %s" % (formula["id"], formula["name"]), "",
                  "    " + formula["expression"], "", formula["symbols"], "",
                  "*Implemented in:* `%s`" % formula["function"], ""]
    lines += ["## " + metrics.STATISTICAL_PLAN.splitlines()[0], ""]
    lines += metrics.STATISTICAL_PLAN.splitlines()[2:]
    lines += ["", "## Scope of verification conclusions", "", LIMITATIONS, ""]
    return "\n".join(lines)


class MethodologyTab(_Tab):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        _heading(self.body, "Methodology",
                 "Every reported number comes from one of these formulas, implemented in "
                 "dev/metrics.py. Export them for Chapter 3 so the manuscript and the code match.")
        actions = tk.Frame(self.body, bg=_BG)
        actions.pack(fill="x", padx=20)
        _button(actions, "Export as Markdown", self._export, primary=True).pack(side="left")
        self._saved = tk.StringVar(value="")
        _cap(actions, "", bg=_BG, textvariable=self._saved).pack(side="left", padx=12)
        formulas = _section(self.body, "Formulas")
        table = _table(formulas, [
            ("id", "ID", 50, "w"), ("name", "Indicator / procedure", 260, "w"),
            ("expr", "Expression", 520, "w"), ("fn", "Implemented in", 220, "w"),
        ], height=len(metrics.FORMULAS))
        for formula in metrics.FORMULAS:
            table.insert("", "end", values=(formula["id"], formula["name"],
                                            formula["expression"], formula["function"]))
        table.bind("<<TreeviewSelect>>", lambda _e: self._explain(table))
        self._explanation = tk.StringVar(value="Select a formula to see its symbols and conditions.")
        tk.Label(formulas, textvariable=self._explanation, bg=_SURF2, fg=_TEXT, font=_FBOD, anchor="w",
                 justify="left", wraplength=1040, padx=10, pady=8).pack(fill="x", pady=(8, 0))
        plan = _section(self.body, "Statistical analysis plan")
        text = tk.Text(plan, height=32, bg=_SURF2, fg=_TEXT, font=_FMON, relief="flat", wrap="word")
        text.insert("1.0", metrics.STATISTICAL_PLAN)
        text.configure(state="disabled")
        text.pack(fill="x")
        tk.Frame(self.body, bg=_BG, height=20).pack()

    def _explain(self, table):
        selection = table.selection()
        if selection:
            formula_id = table.item(selection[0], "values")[0]
            formula = next(f for f in metrics.FORMULAS if f["id"] == formula_id)
            self._explanation.set("%s — %s" % (formula["name"], formula["symbols"]))

    def _export(self):
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        path = RESULTS_DIR / "methodology.md"
        path.write_text(methodology_markdown(), encoding="utf-8")
        self._saved.set("Saved: %s" % path)


# ─────────────────────────────────────────────────────────────────────────────
# Root application
# ─────────────────────────────────────────────────────────────────────────────

class Blake3App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Optimized BLAKE3 Forensic Toolkit")
        width = min(1320, self.winfo_screenwidth() - 60)
        height = min(920, self.winfo_screenheight() - 90)
        self.geometry("%dx%d" % (width, height))
        self.minsize(900, 620)
        self.configure(bg=_BG)
        self._styles()
        self.status_var = tk.StringVar(value="Ready")
        self._header()
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)
        for label, cls in (
            ("Overview", OverviewTab), ("File Analysis", FileAnalysisTab),
            ("Technique Benchmark", TechniqueBenchmarkTab), ("Small-File Batching", SmallFileTab),
            ("Verification", VerificationTab), ("Dataset", DatasetTab), ("Methodology", MethodologyTab),
        ):
            notebook.add(cls(notebook, self), text="  %s  " % label)
        self._status_bar()

    def _styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=_BG, foreground=_TEXT, font=_FBOD)
        style.configure("TNotebook", background=_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=_SURF, foreground=_SUB, padding=[14, 9],
                        font=("Segoe UI", 10, "bold"), borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", _SURF2)], foreground=[("selected", _ACCENT)])
        style.configure("Treeview", background=_SURF, fieldbackground=_SURF, foreground=_TEXT,
                        rowheight=28, borderwidth=0, font=_FCAP)
        style.configure("Treeview.Heading", background=_SURF2, foreground=_SUB, font=_FH3,
                        padding=[8, 6], relief="flat")
        style.map("Treeview", background=[("selected", _ACCENT)], foreground=[("selected", "#ffffff")])
        style.configure("TProgressbar", troughcolor=_SURF2, background=_ACCENT, thickness=8)

    def _header(self):
        header = tk.Frame(self, bg=_SURF, height=64, highlightbackground=_BORDER, highlightthickness=1)
        header.pack(fill="x")
        header.pack_propagate(False)
        badge = tk.Canvas(header, width=38, height=38, bg=_SURF, highlightthickness=0)
        badge.create_rectangle(0, 0, 38, 38, fill=_ACCENT, outline="")
        badge.create_text(19, 19, text="B3", fill="#fff", font=("Segoe UI", 12, "bold"))
        badge.pack(side="left", padx=(20, 8), pady=12)
        tk.Label(header, text="Optimized BLAKE3", bg=_SURF, fg=_TEXT, font=("Segoe UI", 13, "bold")).pack(side="left")
        tk.Label(header, text="Forensic Toolkit", bg=_SURF, fg=_SUB, font=_FBOD).pack(side="left", padx=6)
        tk.Label(header, text="%d physical / %d logical cores  ·  %s  ·  blake3 %s" % (
            physical_cpu_count(), logical_cpu_count(), detected_simd_tier(),
            getattr(_blake3, "__version__", "?")), bg=_SURF, fg=_SUB, font=_FCAP).pack(side="right", padx=20)

    def _status_bar(self):
        bar = tk.Frame(self, bg=_SURF, height=26, highlightbackground=_BORDER, highlightthickness=1)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        tk.Label(bar, textvariable=self.status_var, bg=_SURF, fg=_SUB, font=_FCAP, anchor="w"
                 ).pack(side="left", padx=14)
        tk.Label(bar, text="Results folder: %s" % RESULTS_DIR, bg=_SURF, fg=_SUB, font=_FCAP
                 ).pack(side="right", padx=14)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    Blake3App().mainloop()
