# -*- coding: utf-8 -*-
# OptimizedBLAKE3Ingest.py
#
# Autopsy File Ingest Module: Optimized BLAKE3 Hasher
# -----------------------------------------------------
#
# SINGLE ARTIFACT TYPE DESIGN
#
# Everything is stored under ONE Blackboard artifact type:
#
#     BLAKE3 Hash (Optimized)
#
# The FIRST artifact is the complete evidence source itself
# (for example RM#1.dd). It is created by the DataSourceIngestModule.
#
# Subsequent artifacts are the individual files discovered inside
# the evidence source. They are created by the FileIngestModule.
#
# Both use exactly the same artifact type:
#
#     BLAKE3_HASH_RESULT
#     "BLAKE3 Hash (Optimized)"
#
# IMPORTANT ACCURACY RULES
# ------------------------
# 1. Evidence source hashing reads the complete raw data source.
# 2. Individual file hashing reads the complete file.
# 3. Missing bytes are NEVER padded with zeros.
# 4. A hash artifact is posted only after the expected byte count
#    has actually been read and the sidecar returns a valid result.
# 5. File Size is taken directly from Autopsy's file/data-source size.
# 6. Evidence-source Execution Time is measured end-to-end:
#       Content.read()
#       -> byte conversion
#       -> pipe transfer
#       -> BLAKE3 sidecar
#       -> result
# 7. Individual-file Execution Time is also measured end-to-end.
#
# BASELINE HASH COMPARISON (NEW, purely additive/internal)
# -----------------------------------------------------------
# For files at or below BASELINE_HASH_MAX_BYTES, MD5, SHA-1,
# SHA-256, and a non-optimized/reference BLAKE3 digest are computed
# internally purely to feed the HTML report's performance/overhead
# comparison against Optimized BLAKE3. These baseline digests are
# NEVER posted as Blackboard attributes and NEVER appear as separate
# Autopsy data artifacts/columns -- they only ever show up inside the
# generated HTML report.
#
# MD5 / SHA-1 / SHA-256 ARE HASHED THE SAME WAY AUTOPSY'S OWN HASH
# LOOKUP INGEST MODULE DOES IT: one single read pass over the file,
# updating all three java.security.MessageDigest instances from the
# same buffer as it comes in -- no repeated reads of the file just to
# get three different algorithms. The only difference from a plain
# port of Autopsy's approach is that each digest's update() call is
# timed individually (CPU time only, no extra I/O), so the report can
# still show a distinct throughput figure per algorithm without
# paying for three separate passes over potentially huge evidence.
#
# A true "baseline BLAKE3" (naive/reference implementation) IS
# computed for files within BASELINE_HASH_MAX_BYTES using Bouncy
# Castle's pure-Java Blake3Digest. It is independently timed and
# compared against the optimized sidecar digest for correctness.
# It is reporting-only and is never posted as a Blackboard artifact.
#
# REPORTING
# ---------
# When the ingest job for a data source finishes (all modules done,
# not just this one), an HTML report is generated automatically:
#     - Case name, examiner, evidence source name
#     - Report generation date/time
#     - Hashing summary (evidence digest + aggregate file stats)
#     - Baseline hash comparison (MD5/SHA-256 vs Optimized BLAKE3)
#     - Unique filename so existing reports are never overwritten
#     - Registered with the case so it shows up under the "Reports"
#       node in the Autopsy tree, plus an ingest-inbox message that
#       spells out the full path as a fallback.
#     - A Swing pop-up dialog is also shown, telling the user where
#       the report was saved, with an "Open Report" button and an
#       "OK" button.
#
# Python 2.7 / Jython compatible.

import json
import os
import threading
import datetime

from java.lang import System
from java.lang import ProcessBuilder
from java.lang import String as JString
from java.io import BufferedReader
from java.io import InputStreamReader
from java.io import File as JFile
from java.awt import Desktop
from java.security import MessageDigest
from org.bouncycastle.crypto.digests import Blake3Digest
from javax.swing import JOptionPane
from javax.swing import SwingUtilities
from jarray import zeros
from java.util import ArrayList
from java.beans import PropertyChangeListener

from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import IngestManager
from org.sleuthkit.autopsy.ingest import ModuleDataEvent

from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData


# ===========================================================================
# HASH CONSISTENCY VERIFICATION
#
# Two independent checks are used to satisfy "identical files always
# produce identical BLAKE3 hash values":
#
# 1. ENGINE SELF-TEST (cheap, runs once per sidecar process at startup):
#    hash a zero-byte input twice through the SAME sidecar process and
#    confirm both results equal each other AND the well-known published
#    BLAKE3 digest of empty input. This catches a broken/miscompiled
#    hasher engine before any evidence is touched.
#
# 2. PER-FILE RE-HASH (exact, runs per file): every file is streamed
#    through the sidecar a SECOND time after the first hash and the
#    two digests are compared. A mismatch means the result is
#    untrustworthy and the artifact is NOT posted.
# ===========================================================================

KNOWN_BLAKE3_EMPTY_DIGEST = (
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
)


# Hard ceiling on how long the startup self-test is allowed to take.
# The self-test runs on a SEPARATE, disposable sidecar process (never
# the one used for real file/evidence hashing), and if it hasn't
# finished within this many seconds, it is abandoned and forcibly
# killed -- startUp() proceeds regardless, so an --server protocol
# that doesn't support this zero-byte probe (or any other unexpected
# hang) can NEVER block real hashing.
SELF_TEST_TIMEOUT_SECONDS = 10


def run_engine_self_test(exe_path):
    """
    Spins up a temporary, throwaway sidecar process (completely
    separate from the one used for real file/evidence hashing) and
    hashes a zero-byte input through it twice, comparing both digests
    to each other and to the published BLAKE3 digest of empty input.

    Bounded by SELF_TEST_TIMEOUT_SECONDS: the actual test runs on a
    background daemon thread, and this function waits at most that
    long for it to finish. If it doesn't finish in time -- for
    example because the exe's --server protocol was never built to
    respond to a zero-byte input, and its read blocks forever -- the
    temporary process is force-destroyed and this function returns a
    "skipped, timed out" result instead of hanging. Because the
    self-test uses its own temporary process, this can NEVER block or
    corrupt the real sidecar process used for actual hashing, even in
    the timeout case.

    Returns a dict describing the outcome; never raises, never blocks
    longer than SELF_TEST_TIMEOUT_SECONDS.
    """

    result_holder = {}
    sidecar_holder = [None]

    def _do_test():

        try:

            sidecar_holder[0] = _HasherSidecar(exe_path)
            temp_sidecar = sidecar_holder[0]

            temp_sidecar.write_header(0)
            temp_sidecar.flush()
            line1 = temp_sidecar.read_result_line()

            temp_sidecar.write_header(0)
            temp_sidecar.flush()
            line2 = temp_sidecar.read_result_line()

            if not line1 or not line2:
                result_holder["result"] = {
                    "passed": False,
                    "message": "Self-test got no response from "
                               "hasher engine."
                }
                return

            result1 = json.loads(str(line1).strip())
            result2 = json.loads(str(line2).strip())

            digest1 = result1.get("digest", "")
            digest2 = result2.get("digest", "")

            if not digest1 or not digest2:
                result_holder["result"] = {
                    "passed": False,
                    "message": "Self-test hasher returned an empty "
                               "digest."
                }
                return

            if digest1 != digest2:
                result_holder["result"] = {
                    "passed": False,
                    "message": "Self-test FAILED: hashing the same "
                                "(empty) input twice produced two "
                                "different digests -- engine is not "
                                "deterministic. " +
                                digest1 + " != " + digest2
                }
                return

            if digest1.lower() != KNOWN_BLAKE3_EMPTY_DIGEST.lower():
                result_holder["result"] = {
                    "passed": False,
                    "message": "Self-test FAILED: digest of empty "
                                "input does not match the known "
                                "BLAKE3 test vector. Got " + digest1 +
                                ", expected " +
                                KNOWN_BLAKE3_EMPTY_DIGEST
                }
                return

            result_holder["result"] = {
                "passed": True,
                "message": "Self-test passed: engine is "
                            "deterministic and matches the known "
                            "BLAKE3 test vector."
            }

        except Exception as exc:

            result_holder["result"] = {
                "passed": False,
                "message": "Self-test raised an exception: " +
                           str(exc)
            }

        finally:

            if sidecar_holder[0] is not None:
                try:
                    sidecar_holder[0].close()
                except Exception:
                    pass

    test_thread = threading.Thread(target=_do_test)
    test_thread.setDaemon(True)
    test_thread.start()
    test_thread.join(SELF_TEST_TIMEOUT_SECONDS)

    if "result" in result_holder:
        return result_holder["result"]

    # Timed out. Force-kill the temporary process so its blocked read
    # unblocks (with an IOException) and the abandoned daemon thread
    # can clean itself up on its own time -- we do not wait for that
    # here. The REAL sidecar used for hashing was never touched by
    # this function, so file/evidence hashing is completely
    # unaffected.
    if sidecar_holder[0] is not None:
        try:
            sidecar_holder[0]._process.destroy()
        except Exception:
            pass

    return {
        "passed": False,
        "message": (
            "Self-test SKIPPED: no response within " +
            str(SELF_TEST_TIMEOUT_SECONDS) + "s for a zero-byte "
            "test input -- the hasher's --server protocol may not "
            "support this probe. This does NOT affect real file or "
            "evidence hashing, which uses a separate, unaffected "
            "process; it only means this extra startup check could "
            "not be completed."
        )
    }


def _is_valid_blake3_digest(digest):
    """
    A BLAKE3-256 digest is 64 lowercase/uppercase hex characters.
    Anything else means the hasher returned something malformed, and
    the result should not be trusted even if a "status: ok" was
    reported.
    """

    if not digest or len(digest) != 64:
        return False

    try:
        int(digest, 16)
    except (TypeError, ValueError):
        return False

    return True


# ===========================================================================
# BASELINE HASH COMPARISON (MD5 / SHA-1 / SHA-256), internal only
#
# Purely additive: this section does not change how BLAKE3 hashing,
# the consistency check, or artifact posting work. It only computes
# extra reference hashes for the HTML report.
#
# WHY java.security.MessageDigest
# --------------------------------
# Same reasoning as the ProcessBuilder sidecar bridge above:
# MessageDigest.update(byte[] input, int offset, int len) accepts the
# SAME Java byte[] handed back by Content.read() directly -- one
# native bulk call per chunk, no per-byte Python-level conversion.
#
# WHY ONE COMBINED PASS FOR MD5/SHA-1/SHA-256
# ---------------------------------------------------------
# This mirrors exactly how Autopsy's own built-in Hash Lookup ingest
# module hashes files: ONE read pass over the file, updating every
# configured digest algorithm (MD5 always, SHA-1/SHA-256 optionally)
# from the same bytes as they come in -- never re-reading the file
# once per algorithm.
#
# To still get an individual throughput figure per algorithm (useful
# for the report's comparison table) without paying for extra I/O,
# each digest's update() call is timed on its own with
# System.nanoTime() even though all three run inside the same read
# loop.
# ===========================================================================


def _hash_with_combined_digests(content, size_bytes):
    """
    Mirrors Autopsy's own Hash Lookup ingest module: ONE read pass
    over `content`, updating MD5, SHA-1, and SHA-256 digests together
    as each chunk comes in -- no repeated reads of the same content
    just to get three different algorithms.

    Unlike Autopsy's module (which doesn't expose per-algorithm
    timing), each digest's update() call is timed separately with
    System.nanoTime(), so MD5, SHA-1, and SHA-256 each still get
    their own individual CPU-time figure for the report -- without
    paying for three separate full reads of potentially huge
    evidence.

    Returns a dict:
        {
            "md5": hex_digest, "md5_elapsed_s": float,
            "sha1": hex_digest, "sha1_elapsed_s": float,
            "sha256": hex_digest, "sha256_elapsed_s": float,
            "actual_read": int,
        }

    Raises on unexpected errors -- caller is responsible for catching
    and reporting them.
    """

    md5_digest = MessageDigest.getInstance("MD5")
    sha1_digest = MessageDigest.getInstance("SHA-1")
    sha256_digest = MessageDigest.getInstance("SHA-256")

    READ_BUF = 1024 * 1024

    buf = zeros(
        READ_BUF,
        'b'
    )

    offset = 0
    actual_read = 0

    md5_elapsed_s = 0.0
    sha1_elapsed_s = 0.0
    sha256_elapsed_s = 0.0

    while offset < size_bytes:

        to_read = min(
            READ_BUF,
            size_bytes - offset
        )

        n_read = content.read(
            buf,
            offset,
            to_read
        )

        if n_read <= 0:
            break

        # MD5 -- timed on its own, same buffer, same chunk
        t0 = System.nanoTime()
        md5_digest.update(buf, 0, n_read)
        md5_elapsed_s += (System.nanoTime() - t0) * 1.0e-9

        # SHA-1 -- timed on its own, same buffer, same chunk
        t0 = System.nanoTime()
        sha1_digest.update(buf, 0, n_read)
        sha1_elapsed_s += (System.nanoTime() - t0) * 1.0e-9

        # SHA-256 -- timed on its own, same buffer, same chunk
        t0 = System.nanoTime()
        sha256_digest.update(buf, 0, n_read)
        sha256_elapsed_s += (System.nanoTime() - t0) * 1.0e-9

        actual_read += n_read
        offset += n_read

    if md5_elapsed_s < 0.0:
        md5_elapsed_s = 0.0

    if sha1_elapsed_s < 0.0:
        sha1_elapsed_s = 0.0

    if sha256_elapsed_s < 0.0:
        sha256_elapsed_s = 0.0

    md5_hex = "".join(
        "%02x" % (b & 0xFF) for b in md5_digest.digest()
    )

    sha1_hex = "".join(
        "%02x" % (b & 0xFF) for b in sha1_digest.digest()
    )

    sha256_hex = "".join(
        "%02x" % (b & 0xFF) for b in sha256_digest.digest()
    )

    return {
        "md5": md5_hex,
        "md5_elapsed_s": md5_elapsed_s,
        "sha1": sha1_hex,
        "sha1_elapsed_s": sha1_elapsed_s,
        "sha256": sha256_hex,
        "sha256_elapsed_s": sha256_elapsed_s,
        "actual_read": actual_read,
    }


def _hash_with_blake3_baseline(content, size_bytes):
    """
    Reads `content` completely and computes a BASELINE (naive,
    non-optimized) BLAKE3 digest using Bouncy Castle's pure-Java
    Blake3Digest -- no SIMD dispatch, no multithreading, none of the
    optimizations the packaged optimized_blake3_hasher.exe sidecar
    uses. Timed independently, in its own dedicated read pass (this
    one is NOT combined with the MD5/SHA-1/SHA-256 pass, since it's a
    different algorithm entirely and exists to isolate the optimized
    sidecar's real-world speed advantage).

    REQUIRES the Bouncy Castle provider JAR (bcprov-jdk18on or
    equivalent) to be on this Autopsy module's classpath -- e.g.
    dropped into the module's lib/ folder alongside
    optimized_blake3_hasher.exe. If the JAR is missing, importing
    Blake3Digest at the top of this file will fail at module load
    time with a clear ImportError, rather than failing silently
    later.

    Blake3Digest() with no arguments defaults to a 256-bit (32-byte)
    digest -- the same size as the standard BLAKE3 digest produced by
    the optimized sidecar -- so the two hex digests are directly
    comparable.

    Returns (hex_digest, elapsed_s, actual_read). Raises on
    unexpected errors -- caller is responsible for catching and
    reporting them.
    """

    digest = Blake3Digest()

    READ_BUF = 1024 * 1024

    buf = zeros(
        READ_BUF,
        'b'
    )

    offset = 0
    actual_read = 0

    start_ns = System.nanoTime()

    while offset < size_bytes:

        to_read = min(
            READ_BUF,
            size_bytes - offset
        )

        n_read = content.read(
            buf,
            offset,
            to_read
        )

        if n_read <= 0:
            break

        digest.update(buf, 0, n_read)

        actual_read += n_read
        offset += n_read

    elapsed_s = (System.nanoTime() - start_ns) * 1.0e-9

    if elapsed_s < 0.0:
        elapsed_s = 0.0

    out_buf = zeros(
        digest.getDigestSize(),
        'b'
    )

    digest.doFinal(out_buf, 0)

    hex_digest = "".join(
        "%02x" % (b & 0xFF) for b in out_buf
    )

    return hex_digest, elapsed_s, actual_read


def compute_baseline_hashes(content, size_bytes, optimized_digest=None):
    """
    Computes MD5, SHA-1, SHA-256 (Autopsy-style: one combined read
    pass, individually timed), AND a baseline (non-optimized) BLAKE3
    digest (its own dedicated pass) for `content` (an AbstractFile or
    a DataSource), PURELY for internal performance/correctness
    comparison in the HTML report. NONE of these are ever posted as a
    Blackboard artifact.

    optimized_digest, if given, is the hex digest already produced by
    the optimized_blake3_hasher.exe sidecar for this same content --
    used here to verify that the baseline (Bouncy Castle) BLAKE3
    implementation and the optimized sidecar implementation agree on
    the actual digest VALUE, which is the one real "correctness"
    check possible here (MD5/SHA-1/SHA-256 are different algorithms
    and will never match BLAKE3's value, by design).

    Returns:
        {"status": "ok", ...}   -- all digests computed successfully.
        {"status": "error", ...} -- something went wrong; see
                                     "message".
    """

    try:

        ref_result = _hash_with_combined_digests(content, size_bytes)

        if ref_result["actual_read"] != size_bytes:
            return {
                "status": "error",
                "message": (
                    "Reference hash pass (MD5/SHA-1/SHA-256, "
                    "Autopsy-style combined pass) read-size "
                    "mismatch. Expected=" + str(size_bytes) +
                    " Read=" + str(ref_result["actual_read"])
                )
            }

        md5_hex = ref_result["md5"]
        md5_elapsed_s = ref_result["md5_elapsed_s"]
        sha1_hex = ref_result["sha1"]
        sha1_elapsed_s = ref_result["sha1_elapsed_s"]
        sha256_hex = ref_result["sha256"]
        sha256_elapsed_s = ref_result["sha256_elapsed_s"]

        md5_throughput_mb_s = (
            (float(size_bytes) / (1024.0 * 1024.0)) / md5_elapsed_s
            if md5_elapsed_s > 0.0 else 0.0
        )

        sha1_throughput_mb_s = (
            (float(size_bytes) / (1024.0 * 1024.0)) / sha1_elapsed_s
            if sha1_elapsed_s > 0.0 else 0.0
        )

        sha256_throughput_mb_s = (
            (float(size_bytes) / (1024.0 * 1024.0)) / sha256_elapsed_s
            if sha256_elapsed_s > 0.0 else 0.0
        )

        (
            blake3_baseline_hex,
            blake3_baseline_elapsed_s,
            blake3_baseline_read
        ) = _hash_with_blake3_baseline(content, size_bytes)

        if blake3_baseline_read != size_bytes:
            return {
                "status": "error",
                "message": (
                    "Baseline BLAKE3 pass read-size mismatch. "
                    "Expected=" + str(size_bytes) +
                    " Read=" + str(blake3_baseline_read)
                )
            }

        blake3_baseline_throughput_mb_s = (
            (float(size_bytes) / (1024.0 * 1024.0)) /
            blake3_baseline_elapsed_s
            if blake3_baseline_elapsed_s > 0.0 else 0.0
        )

        # The one genuine correctness check possible here: baseline
        # (Bouncy Castle) BLAKE3 and the optimized sidecar BLAKE3 are
        # the SAME algorithm, so their digest VALUES must match. None
        # is reported (rather than True/False) when no optimized
        # digest was supplied to compare against.
        if optimized_digest:
            blake3_matches_optimized = (
                blake3_baseline_hex.lower() ==
                str(optimized_digest).lower()
            )
        else:
            blake3_matches_optimized = None

        return {
            "status": "ok",
            "md5": md5_hex,
            "md5_elapsed_s": md5_elapsed_s,
            "md5_throughput_mb_s": md5_throughput_mb_s,
            "sha1": sha1_hex,
            "sha1_elapsed_s": sha1_elapsed_s,
            "sha1_throughput_mb_s": sha1_throughput_mb_s,
            "sha256": sha256_hex,
            "sha256_elapsed_s": sha256_elapsed_s,
            "sha256_throughput_mb_s": sha256_throughput_mb_s,
            "blake3_baseline": blake3_baseline_hex,
            "blake3_baseline_elapsed_s": blake3_baseline_elapsed_s,
            "blake3_baseline_throughput_mb_s":
                blake3_baseline_throughput_mb_s,
            "blake3_baseline_matches_optimized": blake3_matches_optimized,
        }

    except Exception as exc:

        return {
            "status": "error",
            "message": str(exc)
        }


# ===========================================================================
# SIDECAR PROCESS BRIDGE
#
# Both ingest modules stream raw bytes to the SAME persistent
# optimized_blake3_hasher.exe process using this ONE class and ONE
# streaming function. This is deliberate: individual files and the
# complete evidence source are now hashed exactly the same way.
#
# WHY java.lang.ProcessBuilder INSTEAD OF PYTHON'S subprocess MODULE
# --------------------------------------------------------------------
# Content.read()/AbstractFile.read() hand back a genuine Java byte[]
# buffer. The previous implementation piped that buffer through
# Python's subprocess module, which meant every single byte had to be
# rebuilt one at a time first:
#
#     stdin.write(bytearray([(b & 0xFF) for b in buf[:n_read]]))
#
# That per-byte Python-level loop was pure overhead -- a byte stream
# only ever cares about the low 8 bits of each byte, and those bits
# are identical whether Java treats the byte as signed or Python
# treats it as unsigned. For a multi-gigabyte evidence source that
# loop alone accounted for billions of interpreted iterations and was
# the dominant cost of evidence-source hashing.
#
# Using java.lang.ProcessBuilder gives direct access to the process's
# raw java.io.OutputStream, which exposes write(byte[] b, int off,
# int len) -- the buffer from Content.read() can be written straight
# through with a single native bulk call, no conversion, no loop.
# The bytes placed on the wire are bit-for-bit identical to before,
# so hash digests are completely unaffected -- only the speed of
# getting those bytes to the hasher changes.
# ===========================================================================

class _HasherSidecar(object):
    """
    Thin wrapper around one persistent optimized_blake3_hasher.exe
    process, talking to it over raw Java streams.
    """

    def __init__(self, exe_path):

        process_builder = ProcessBuilder(
            [exe_path, "--server"]
        )

        process_builder.redirectErrorStream(False)

        self._process = process_builder.start()

        self._out_stream = self._process.getOutputStream()

        self._in_reader = BufferedReader(
            InputStreamReader(
                self._process.getInputStream()
            )
        )

    def is_alive(self):

        try:
            return self._process.isAlive()
        except Exception:
            return False

    def write_header(self, size_bytes):

        header = str(size_bytes) + "\n"

        header_bytes = JString(header).getBytes("US-ASCII")

        self._out_stream.write(header_bytes)

    def write_chunk(self, buf, n_read):
        """
        buf is the SAME Java byte[] handed back by Content.read().
        Written straight through with one native bulk call -- no
        per-byte Python-level conversion.
        """

        self._out_stream.write(buf, 0, n_read)

    def flush(self):

        self._out_stream.flush()

    def read_result_line(self):

        return self._in_reader.readLine()

    def close(self):

        try:
            self._out_stream.close()
        except Exception:
            pass

        try:
            self._process.waitFor()
        except Exception:

            try:
                self._process.destroy()
            except Exception:
                pass


def stream_content_to_sidecar(
        content,
        size_bytes,
        sidecar,
        progress_cb=None):
    """
    Streams the COMPLETE content -- an Autopsy AbstractFile or a
    DataSource, both of which expose read(byte[], long, long) --
    to the given _HasherSidecar, verifying that every expected byte
    was actually read. Missing bytes are NEVER padded with zeros: if
    fewer bytes come back than expected, streaming stops and the
    caller is told exactly how many bytes were actually read so it
    can refuse to post an artifact.

    This is the ONE code path used for both individual files and the
    complete evidence source -- both are hashed exactly the same way.

    Returns (actual_read, result_dict_or_None).
    """

    READ_BUF = 1024 * 1024

    buf = zeros(
        READ_BUF,
        'b'
    )

    offset = 0
    actual_read = 0

    sidecar.write_header(size_bytes)

    while offset < size_bytes:

        to_read = min(
            READ_BUF,
            size_bytes - offset
        )

        n_read = content.read(
            buf,
            offset,
            to_read
        )

        if n_read <= 0:
            break

        sidecar.write_chunk(buf, n_read)

        actual_read += n_read
        offset += n_read

        if progress_cb is not None:
            progress_cb(actual_read, size_bytes)

    if actual_read != size_bytes:
        return actual_read, None

    sidecar.flush()

    line_out = sidecar.read_result_line()

    if not line_out:
        return actual_read, None

    try:
        result = json.loads(str(line_out).strip())
    except Exception:
        return actual_read, None

    return actual_read, result


# ===========================================================================
# MODULE FACTORY
# ===========================================================================

class BLAKE3IngestModuleFactory(IngestModuleFactoryAdapter):

    MODULE_NAME = "Optimized BLAKE3 Hasher"
    MODULE_VERSION = "3.14"

    MODULE_DESCRIPTION = (
        "Optimized BLAKE3 hashing module for Autopsy. "
        "Creates one unified 'BLAKE3 Hash (Optimized)' artifact type. "
        "The first artifact represents the complete evidence source, "
        "followed by artifacts for individual files. "
        "Hashing validates the complete byte count and never zero-pads "
        "missing evidence bytes. Also computes MD5/SHA-1/SHA-256 "
        "baseline hashes internally (not posted as artifacts) for a "
        "performance and correctness comparison in the generated "
        "report, using the same single-pass approach as Autopsy's own "
        "Hash Lookup module. "
        "Automatically generates an HTML report when ingest finishes, "
        "and shows a pop-up telling you where it was saved."
    )

    def getModuleDisplayName(self):
        return self.MODULE_NAME

    def getModuleDescription(self):
        return self.MODULE_DESCRIPTION

    def getModuleVersionNumber(self):
        return self.MODULE_VERSION

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return BLAKE3FileIngestModule()

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return BLAKE3DataSourceIngestModule()


# ===========================================================================
# SHARED ARTIFACT HELPERS
# ===========================================================================

def get_unified_artifact_type(blackboard):

    try:
        return blackboard.getOrAddArtifactType(
            "BLAKE3_HASH_RESULT",
            "BLAKE3 Hash (Optimized)"
        )
    except Exception:
        return blackboard.getArtifactType(
            "BLAKE3_HASH_RESULT"
        )


def get_or_add_attribute_type(
        blackboard,
        type_name,
        display_name):

    try:
        return blackboard.getOrAddAttributeType(
            type_name,
            BlackboardAttribute
            .TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE
            .STRING,
            display_name
        )
    except Exception:
        return blackboard.getAttributeType(type_name)


def make_attribute(
        blackboard,
        type_name,
        display_name,
        value):

    attr_type = get_or_add_attribute_type(
        blackboard,
        type_name,
        display_name
    )

    return BlackboardAttribute(
        attr_type,
        BLAKE3IngestModuleFactory.MODULE_NAME,
        str(value)
    )


def build_common_attributes(
        blackboard,
        digest,
        simd_tier,
        threads_used,
        elapsed_s,
        throughput_mb_s,
        data_source_name,
        file_size,
        consistency_status="Not checked"):

    attrs = ArrayList()

    attrs.add(make_attribute(
        blackboard,
        "BLAKE3_DIGEST",
        "BLAKE3 Hash Digest",
        digest
    ))

    # NOTE: The hash-consistency result ("Verified (double-hashed,
    # matched)" / "Not checked ..." / evidence self-test note) is
    # intentionally NOT added as a Blackboard attribute, so it does
    # not show up as a column in the Autopsy artifact table. It is
    # still tracked internally (see consistency_status, passed in by
    # the caller) and reported in full in the HTML report instead.
    #
    # The same is true of the baseline MD5/SHA-1/SHA-256 hash
    # comparison (see compute_baseline_hashes() above) -- it is never
    # added here either, and never shows up as an Autopsy artifact
    # column.

    attrs.add(make_attribute(
        blackboard,
        "BLAKE3_SIMD",
        "SIMD Tier",
        simd_tier
    ))

    attrs.add(make_attribute(
        blackboard,
        "BLAKE3_THREADS",
        "Threads Used",
        threads_used
    ))

    attrs.add(make_attribute(
        blackboard,
        "BLAKE3_ELAPSED",
        "Execution Time (s)",
        elapsed_s
    ))

    attrs.add(make_attribute(
        blackboard,
        "BLAKE3_THROUGHPUT",
        "Throughput (MB/s)",
        throughput_mb_s
    ))

    attrs.add(make_attribute(
            blackboard,
            "BLAKE3_FILESIZE",
            "File Size (bytes)",
            file_size
        ))

    attrs.add(make_attribute(
        blackboard,
        "BLAKE3_DATASOURCE",
        "Data Source",
        data_source_name
    ))

    return attrs


# ===========================================================================
# ERROR / SKIP CLASSIFICATION
#
# Jython/Autopsy does not always surface precise OS-level error codes,
# so classification here is heuristic: it combines what Autopsy already
# knows about the file (type, size, name) with the text of any raised
# exception. It is deliberately conservative -- when nothing matches, a
# file is labeled UNKNOWN_ERROR/UNKNOWN_SKIP rather than guessed at,
# so the processing log never claims more certainty than it has.
# ===========================================================================

def _classify_skip_reason(file):
    """
    Called BEFORE hashing is attempted. Explains why a file was never
    submitted to the hasher at all.
    """

    try:

        if file.isDir():
            return "DIRECTORY"

        if not file.getName():
            return "UNNAMED_FILE"

        if file.getSize() == 0:
            return "ZERO_BYTE_FILE"

        if (
            file.getType() ==
            TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS
        ):
            return "UNALLOCATED_SPACE"

        if (
            file.getType() ==
            TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS
        ):
            return "UNUSED_BLOCKS"

        file_name = file.getName()
        if file_name and (
            file_name.startswith("$BadClus") or
            (file_name.startswith("$Bitmap") and file.getSize() == 0)
        ):
            return "SPARSE_SYSTEM_FILE"

    except Exception:
        pass

    return "UNKNOWN_SKIP"


def _classify_error(exc, actual_read, size_bytes):
    """
    Called when hashing was ATTEMPTED but did not succeed. Looks at
    the exception text (when there is one) and at how many bytes
    actually came back, and buckets the failure into one of a small
    set of forensic-relevant categories.
    """

    msg = str(exc).lower() if exc is not None else ""

    if exc is not None:

        if (
            "no such file" in msg or
            "not found" in msg or
            "does not exist" in msg or
            "file not found" in msg
        ):
            return "MISSING_FILE"

        if (
            "permission" in msg or
            "access is denied" in msg or
            "access denied" in msg or
            "eacces" in msg
        ):
            return "PERMISSION_DENIED"

        if (
            "encrypt" in msg or
            "password" in msg or
            "bitlocker" in msg
        ):
            return "ENCRYPTED_FILE"

        if (
            "unsupported" in msg or
            "not supported" in msg
        ):
            return "UNSUPPORTED_FILE"

        if (
            "corrupt" in msg or
            "malformed" in msg or
            "bad data" in msg
        ):
            return "CORRUPTED_FILE"

    if size_bytes and actual_read == 0:
        return "UNREADABLE_NO_DATA"

    if size_bytes and 0 < actual_read < size_bytes:
        return "CORRUPTED_OR_TRUNCATED"

    return "UNKNOWN_ERROR"


# ===========================================================================
# REPORTING
#
# Aggregates hashing stats per ingest job (keyed by job id) and writes an
# HTML report once the job's data source has finished ALL ingest modules
# (not just this one). Stats are updated from both the FileIngestModule
# and the DataSourceIngestModule, guarded by a lock since Autopsy runs
# multiple FileIngestModule instances concurrently on worker threads.
# ===========================================================================

_STATS_LOCK = threading.Lock()
_JOB_STATS = {}

MAX_ERROR_NAMES_IN_REPORT = 50


def _get_job_stats(job_id):

    with _STATS_LOCK:

        if job_id not in _JOB_STATS:

            _JOB_STATS[job_id] = {
                "files_hashed": 0,
                "files_error": 0,
                "files_skipped": 0,
                "files_elapsed_total": 0.0,
                "files_bytes_total": 0,
                "files_consistency_verified": 0,
                "files_consistency_not_checked": 0,
                "file_error_names": [],
                "skip_reason_counts": {},
                "error_reason_counts": {},
                "self_test_status": "Not run",
                "self_test_message": "",
                "evidence_name": None,
                "evidence_digest": None,
                "evidence_size": None,
                "evidence_elapsed": None,
                "evidence_throughput": None,
                "evidence_simd": None,
                "evidence_threads": None,
                "evidence_status": "Not completed",
                "evidence_consistency_status": None,
                "evidence_baseline_note": None,
                "evidence_baseline_status": "Not computed",
                "evidence_baseline_md5": None,
                "evidence_baseline_md5_elapsed": None,
                "evidence_baseline_sha1": None,
                "evidence_baseline_sha1_elapsed": None,
                "evidence_baseline_sha256": None,
                "evidence_baseline_sha256_elapsed": None,
                "evidence_baseline_blake3": None,
                "evidence_baseline_blake3_elapsed": None,
                "evidence_baseline_blake3_matches": None,
                "report_generated": False,
                # --- Baseline hash comparison (MD5/SHA-1/SHA-256), NEW ---
                "baseline_files_checked": 0,
                "baseline_files_skipped_too_large": 0,
                "baseline_files_error": 0,
                "baseline_bytes_total": 0,
                "baseline_md5_elapsed_total": 0.0,
                "baseline_sha1_elapsed_total": 0.0,
                "baseline_sha256_elapsed_total": 0.0,
                "baseline_optimized_blake3_elapsed_total": 0.0,
                "baseline_blake3_elapsed_total": 0.0,
                "baseline_blake3_matches": 0,
                "baseline_blake3_mismatches": 0,
            }

        return _JOB_STATS[job_id]


def _record_file_success(
        job_id,
        elapsed_s,
        size_bytes,
        consistency_status=""):

    stats = _get_job_stats(job_id)

    with _STATS_LOCK:
        stats["files_hashed"] += 1
        stats["files_elapsed_total"] += float(elapsed_s)
        stats["files_bytes_total"] += int(size_bytes)

        if str(consistency_status).startswith("Verified"):
            stats["files_consistency_verified"] += 1
        elif str(consistency_status).startswith("Not checked"):
            stats["files_consistency_not_checked"] += 1


def _record_file_error(job_id, file_name, reason="UNKNOWN_ERROR"):

    stats = _get_job_stats(job_id)

    with _STATS_LOCK:

        stats["files_error"] += 1

        stats["error_reason_counts"][reason] = (
            stats["error_reason_counts"].get(reason, 0) + 1
        )

        if len(stats["file_error_names"]) < MAX_ERROR_NAMES_IN_REPORT:
            stats["file_error_names"].append(
                file_name + " [" + reason + "]"
            )


def _record_file_skip(job_id, file_name, reason):

    stats = _get_job_stats(job_id)

    with _STATS_LOCK:

        stats["files_skipped"] += 1

        stats["skip_reason_counts"][reason] = (
            stats["skip_reason_counts"].get(reason, 0) + 1
        )


def _record_self_test(job_id, passed, message):

    stats = _get_job_stats(job_id)

    with _STATS_LOCK:

        # Once a job has a FAILED self-test, keep it FAILED even if a
        # later sidecar instance (a different worker thread) passes --
        # any failed engine instance means some files were hashed by
        # an unverified process.
        if stats["self_test_status"] != "FAILED":
            stats["self_test_status"] = "PASSED" if passed else "FAILED"
            stats["self_test_message"] = message


def _record_evidence_result(
        job_id,
        evidence_name,
        digest,
        simd_tier,
        threads_used,
        elapsed_s,
        throughput_mb_s,
        evidence_size=None,
        consistency_status=None):

    stats = _get_job_stats(job_id)

    with _STATS_LOCK:

        stats["evidence_name"] = evidence_name
        stats["evidence_digest"] = digest
        stats["evidence_simd"] = simd_tier
        stats["evidence_threads"] = threads_used
        stats["evidence_elapsed"] = elapsed_s
        stats["evidence_throughput"] = throughput_mb_s
        stats["evidence_status"] = "Completed"
        stats["evidence_size"] = evidence_size
        stats["evidence_consistency_status"] = consistency_status


def _record_baseline_result(
        job_id,
        optimized_blake3_elapsed_s,
        size_bytes,
        baseline_result):
    """
    Records the outcome of compute_baseline_hashes() for a single
    file (or the evidence source) into the job's stats, purely for
    the HTML report. baseline_result is whatever
    compute_baseline_hashes() returned: None (skipped, too large),
    {"status": "error", ...}, or {"status": "ok", ...}.
    """

    stats = _get_job_stats(job_id)

    with _STATS_LOCK:

        if baseline_result is None:
            stats["baseline_files_skipped_too_large"] += 1
            return

        if baseline_result.get("status") != "ok":
            stats["baseline_files_error"] += 1
            return

        stats["baseline_files_checked"] += 1
        stats["baseline_bytes_total"] += int(size_bytes)
        stats["baseline_md5_elapsed_total"] += float(
            baseline_result.get("md5_elapsed_s", 0.0)
        )
        stats["baseline_sha1_elapsed_total"] += float(
            baseline_result.get("sha1_elapsed_s", 0.0)
        )
        stats["baseline_sha256_elapsed_total"] += float(
            baseline_result.get("sha256_elapsed_s", 0.0)
        )
        stats["baseline_optimized_blake3_elapsed_total"] += float(
            optimized_blake3_elapsed_s
        )
        stats["baseline_blake3_elapsed_total"] += float(
            baseline_result.get("blake3_baseline_elapsed_s", 0.0)
        )

        matches = baseline_result.get(
            "blake3_baseline_matches_optimized"
        )

        if matches is True:
            stats["baseline_blake3_matches"] += 1
        elif matches is False:
            stats["baseline_blake3_mismatches"] += 1


def _record_evidence_baseline_note(job_id, note):

    stats = _get_job_stats(job_id)

    with _STATS_LOCK:
        stats["evidence_baseline_note"] = note


def _record_evidence_baseline_result(job_id, baseline_result):
    """
    Stores structured evidence-source baseline values for the HTML report.
    Reporting metadata only; never posted as Blackboard attributes.
    """
    stats = _get_job_stats(job_id)

    with _STATS_LOCK:
        if baseline_result is None:
            stats["evidence_baseline_status"] = "Skipped"
            return

        if baseline_result.get("status") != "ok":
            stats["evidence_baseline_status"] = "Error"
            return

        stats["evidence_baseline_status"] = "Computed"
        stats["evidence_baseline_md5"] = baseline_result.get("md5")
        stats["evidence_baseline_md5_elapsed"] = baseline_result.get(
            "md5_elapsed_s"
        )
        stats["evidence_baseline_sha1"] = baseline_result.get("sha1")
        stats["evidence_baseline_sha1_elapsed"] = baseline_result.get(
            "sha1_elapsed_s"
        )
        stats["evidence_baseline_sha256"] = baseline_result.get("sha256")
        stats["evidence_baseline_sha256_elapsed"] = baseline_result.get(
            "sha256_elapsed_s"
        )
        stats["evidence_baseline_blake3"] = baseline_result.get(
            "blake3_baseline"
        )
        stats["evidence_baseline_blake3_elapsed"] = baseline_result.get(
            "blake3_baseline_elapsed_s"
        )
        stats["evidence_baseline_blake3_matches"] = baseline_result.get(
            "blake3_baseline_matches_optimized"
        )


def _format_duration(seconds_value):
    """
    Turns a raw seconds figure (float or numeric string) into a
    human-readable duration like "3m 4.22s", while keeping the exact
    raw seconds alongside for anyone who needs the precise number.
    Falls back to the original value untouched if it isn't numeric.
    """

    try:
        total = float(seconds_value)
    except (TypeError, ValueError):
        return str(seconds_value)

    if total < 0:
        total = 0.0

    hours = int(total // 3600)
    minutes = int((total % 3600) // 60)
    secs = total % 60

    parts = []

    if hours > 0:
        parts.append(str(hours) + "h")

    if hours > 0 or minutes > 0:
        parts.append(str(minutes) + "m")

    parts.append("%.2fs" % secs)

    readable = " ".join(parts)

    return readable + " (%.3f s)" % total


def _format_throughput(mb_per_s_value):
    """
    Turns a raw MB/s figure (float or numeric string) into a
    human-readable rate, switching to GB/s once it's large enough
    that MB/s stops being the natural unit.
    """

    try:
        mb_s = float(mb_per_s_value)
    except (TypeError, ValueError):
        return str(mb_per_s_value)

    if mb_s < 0:
        mb_s = 0.0

    if mb_s >= 1024.0:
        return "%.2f GB/s" % (mb_s / 1024.0)

    return "%.2f MB/s" % mb_s


def _format_bytes(byte_value):
    """
    Turns a raw byte count into a human-readable size (KB/MB/GB/TB).
    """

    try:
        size = float(byte_value)
    except (TypeError, ValueError):
        return str(byte_value)

    if size < 0:
        size = 0.0

    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            if unit == "bytes":
                return "%d %s" % (int(size), unit)
            return "%.2f %s" % (size, unit)
        size /= 1024.0


def _throughput_cell_html(mb_per_s, max_mb_per_s, is_primary=False):
    """
    Renders a small "figure + horizontal bar" cell used in the
    algorithm comparison tables, so relative throughput can be read
    at a glance instead of just as numbers in a column. The bar width
    is scaled relative to the fastest algorithm in the same table
    (max_mb_per_s). Returns "N/A" (no bar) if the figure is missing.
    """

    try:
        value = float(mb_per_s)
    except (TypeError, ValueError):
        value = None

    try:
        max_value = float(max_mb_per_s)
    except (TypeError, ValueError):
        max_value = 0.0

    if value is None:
        return '<span class="throughput-figure">N/A</span>'

    if max_value > 0.0:
        pct = int(round((value / max_value) * 100.0))
    else:
        pct = 0

    if pct < 0:
        pct = 0
    if pct > 100:
        pct = 100

    fill_class = "throughput-fill is-primary" if is_primary else "throughput-fill"

    return (
        '<div class="throughput-cell">'
        '<span class="throughput-figure">' +
        _html_escape(_format_throughput(value)) +
        '</span>'
        '<div class="throughput-track">'
        '<div class="' + fill_class + '" style="width:' + str(pct) + '%;"></div>'
        '</div>'
        '</div>'
    )


def _speedup_string(baseline_time, optimized_time, label):
    """
    Returns "X.XXx faster than <label>" comparing an Optimized BLAKE3
    execution time against a reference algorithm's execution time on
    the same data, or "N/A" if either figure is missing/non-positive.
    """

    try:
        baseline_seconds = float(baseline_time)
        optimized_seconds = float(optimized_time)
    except (TypeError, ValueError):
        return "N/A"

    if baseline_seconds <= 0.0 or optimized_seconds <= 0.0:
        return "N/A"

    return "%.2fx faster than %s" % (
        baseline_seconds / optimized_seconds,
        label
    )


def _html_escape(value):

    if value is None:
        return ""

    text = str(value)

    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace('"', "&quot;")

    return text


def _get_report_directory():

    case = Case.getCurrentCase()

    try:
        report_dir = case.getReportDirectory()
    except Exception:
        report_dir = os.path.join(
            case.getCaseDirectory(),
            "Reports"
        )

    try:
        if not os.path.isdir(report_dir):
            os.makedirs(report_dir)
    except Exception:
        pass

    return report_dir


def _unique_report_path(report_dir, base_name):
    """
    Overwrite protection: never reuses a filename that already exists.
    Starts from a timestamped base name, then appends an incrementing
    counter suffix if a collision is somehow still found.
    """

    candidate = os.path.join(
        report_dir,
        base_name + ".html"
    )

    if not os.path.exists(candidate):
        return candidate

    counter = 1

    while True:

        candidate = os.path.join(
            report_dir,
            base_name + "_" + str(counter) + ".html"
        )

        if not os.path.exists(candidate):
            return candidate

        counter += 1


def _safe_case_name():

    try:
        return Case.getCurrentCase().getName()
    except Exception:
        return "Unknown Case"


def _safe_examiner():

    try:
        examiner = Case.getCurrentCase().getExaminer()
        if examiner:
            return examiner
        return "Not set"
    except Exception:
        return "Not set"


# ===========================================================================
# POP-UP NOTIFICATION
#
# Shown once the HTML report has been written to disk. Runs on the
# Swing Event Dispatch Thread (required for any UI call from a
# background ingest thread). Two buttons:
#     - "Open Report"  -> opens the HTML file with the OS default
#                          viewer via java.awt.Desktop
#     - "OK"           -> just dismisses the dialog
# ===========================================================================

def _show_report_popup(report_path):

    def _do_show():

        try:

            message = (
                "BLAKE3 Hash (Optimized) summary report saved at:\n\n" +
                report_path
            )

            options = ["Open Report", "OK"]

            choice = JOptionPane.showOptionDialog(
                None,
                message,
                "BLAKE3 Hash Report Ready",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.INFORMATION_MESSAGE,
                None,
                options,
                options[1]
            )

            if choice == 0:

                try:

                    if Desktop.isDesktopSupported():
                        Desktop.getDesktop().open(
                            JFile(report_path)
                        )
                    else:
                        JOptionPane.showMessageDialog(
                            None,
                            "Can't auto-open on this system. " +
                            "The report is saved at:\n" +
                            report_path,
                            "BLAKE3 Hash Report",
                            JOptionPane.INFORMATION_MESSAGE
                        )

                except Exception as exc:

                    JOptionPane.showMessageDialog(
                        None,
                        "Could not open the report automatically: " +
                        str(exc) +
                        "\n\nIt is saved at:\n" +
                        report_path,
                        "BLAKE3 Hash Report",
                        JOptionPane.ERROR_MESSAGE
                    )

        except Exception as exc:

            try:
                IngestServices.getInstance().postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.WARNING,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "Could not display report pop-up: " + str(exc)
                    )
                )
            except Exception:
                pass

    try:
        SwingUtilities.invokeLater(_do_show)
    except Exception:
        # Fall back to running inline if invokeLater itself is
        # unavailable for some reason -- better a slightly
        # off-thread dialog than none at all.
        _do_show()


def generate_html_report(job_id):
    """
    Builds and writes the HTML hash report for a completed ingest job.
    Safe to call more than once; caller is responsible for making sure
    it only actually happens a single time per job (see
    _BLAKE3ReportListener), but this function itself just needs a
    unique output filename so nothing is ever overwritten.

    After writing the file, it is also registered with the current
    Case (so it appears as a clickable entry under the "Reports" node
    in the Autopsy tree), a message with the full path is posted to
    the ingest inbox as a fallback, and a pop-up dialog is shown
    telling the user exactly where the report was saved, with an
    "Open Report" button and an "OK" button.
    """

    stats = _get_job_stats(job_id)

    with _STATS_LOCK:
        stats_copy = dict(stats)

    case_name = _safe_case_name()
    examiner = _safe_examiner()

    now = datetime.datetime.now()
    generated_at = now.strftime("%Y-%m-%d %H:%M:%S")
    timestamp_for_filename = now.strftime("%Y%m%d_%H%M%S")

    evidence_name = stats_copy.get("evidence_name") or "Unknown"

    safe_evidence_for_filename = "".join(
        c if (c.isalnum() or c in ("-", "_")) else "_"
        for c in evidence_name
    )

    base_name = (
        "BLAKE3_Hash_Report_" +
        safe_evidence_for_filename +
        "_" +
        timestamp_for_filename
    )

    error_rows = ""

    if stats_copy.get("file_error_names"):

        error_rows = (
            "<h3>Files That Could Not Be Hashed</h3>"
            "<ul>"
        )

        for name in stats_copy["file_error_names"]:
            error_rows += "<li>" + _html_escape(name) + "</li>"

        error_rows += "</ul>"

        if stats_copy["files_error"] > MAX_ERROR_NAMES_IN_REPORT:
            error_rows += (
                "<p><em>Showing first " +
                str(MAX_ERROR_NAMES_IN_REPORT) +
                " of " +
                str(stats_copy["files_error"]) +
                " errored files.</em></p>"
            )

    def _reason_table(title, reason_counts):

        if not reason_counts:
            return ""

        rows_html = (
            "<h3>" + _html_escape(title) + "</h3>"
            "<table><tr><th>Reason</th><th>Count</th></tr>"
        )

        for reason_key in sorted(reason_counts.keys()):
            rows_html += (
                "<tr><td>" +
                _html_escape(reason_key) +
                "</td><td>" +
                _html_escape(reason_counts[reason_key]) +
                "</td></tr>"
            )

        rows_html += "</table>"

        return rows_html

    skip_rows = _reason_table(
        "Files Skipped (never submitted for hashing)",
        stats_copy.get("skip_reason_counts", {})
    )

    error_reason_rows = _reason_table(
        "Error Breakdown by Cause",
        stats_copy.get("error_reason_counts", {})
    )

    self_test_status = stats_copy.get("self_test_status", "Not run")
    self_test_message = stats_copy.get("self_test_message", "")
    evidence_consistency_status = (
        stats_copy.get("evidence_consistency_status") or
        "Not yet available"
    )

    # -----------------------------------------------------------------------
    # BASELINE HASH COMPARISON -- aggregate figures (NEW)
    # -----------------------------------------------------------------------

    baseline_files_checked = stats_copy.get("baseline_files_checked", 0)
    baseline_bytes_total = stats_copy.get("baseline_bytes_total", 0)
    baseline_md5_elapsed_total = stats_copy.get(
        "baseline_md5_elapsed_total", 0.0
    )
    baseline_sha1_elapsed_total = stats_copy.get(
        "baseline_sha1_elapsed_total", 0.0
    )
    baseline_sha256_elapsed_total = stats_copy.get(
        "baseline_sha256_elapsed_total", 0.0
    )
    baseline_blake3_elapsed_total = stats_copy.get(
        "baseline_optimized_blake3_elapsed_total", 0.0
    )

    if baseline_files_checked > 0 and baseline_bytes_total > 0:

        baseline_mb_total = float(baseline_bytes_total) / (1024.0 * 1024.0)

        avg_blake3_throughput_subset = _format_throughput(
            baseline_mb_total / baseline_blake3_elapsed_total
            if baseline_blake3_elapsed_total > 0.0 else 0.0
        )

        avg_md5_throughput = _format_throughput(
            baseline_mb_total / baseline_md5_elapsed_total
            if baseline_md5_elapsed_total > 0.0 else 0.0
        )

        avg_sha1_throughput = _format_throughput(
            baseline_mb_total / baseline_sha1_elapsed_total
            if baseline_sha1_elapsed_total > 0.0 else 0.0
        )

        avg_sha256_throughput = _format_throughput(
            baseline_mb_total / baseline_sha256_elapsed_total
            if baseline_sha256_elapsed_total > 0.0 else 0.0
        )

        speedup_vs_md5 = (
            "%.2fx faster than MD5" % (
                baseline_md5_elapsed_total / baseline_blake3_elapsed_total
            )
            if baseline_blake3_elapsed_total > 0.0
            else "N/A"
        )

        speedup_vs_sha1 = (
            "%.2fx faster than SHA-1" % (
                baseline_sha1_elapsed_total / baseline_blake3_elapsed_total
            )
            if baseline_blake3_elapsed_total > 0.0
            else "N/A"
        )

        speedup_vs_sha256 = (
            "%.2fx faster than SHA-256" % (
                baseline_sha256_elapsed_total /
                baseline_blake3_elapsed_total
            )
            if baseline_blake3_elapsed_total > 0.0
            else "N/A"
        )

        # --- Baseline (Bouncy Castle) BLAKE3 vs Optimized BLAKE3 ---
        naive_blake3_elapsed_total = stats_copy.get(
            "baseline_blake3_elapsed_total", 0.0
        )

        avg_naive_blake3_throughput = _format_throughput(
            baseline_mb_total / naive_blake3_elapsed_total
            if naive_blake3_elapsed_total > 0.0 else 0.0
        )

        speedup_vs_naive_blake3 = (
            "%.2fx faster than Baseline BLAKE3" % (
                naive_blake3_elapsed_total / baseline_blake3_elapsed_total
            )
            if baseline_blake3_elapsed_total > 0.0
            and naive_blake3_elapsed_total > 0.0
            else "N/A"
        )

        blake3_matches = stats_copy.get("baseline_blake3_matches", 0)
        blake3_mismatches = stats_copy.get(
            "baseline_blake3_mismatches", 0
        )

        if blake3_mismatches > 0:
            blake3_correctness_summary = (
                str(blake3_matches) + " matched, " +
                str(blake3_mismatches) + " MISMATCHED -- see error "
                "log, this needs investigation"
            )
        elif blake3_matches > 0:
            blake3_correctness_summary = (
                str(blake3_matches) + " of " +
                str(blake3_matches) + " files: Baseline BLAKE3 "
                "digest matched Optimized BLAKE3 digest exactly"
            )
        else:
            blake3_correctness_summary = "Not yet available"

        # --- Raw MB/s figures + comparison bars for Section 2 ---
        _optimized_mbps = (
            baseline_mb_total / baseline_blake3_elapsed_total
            if baseline_blake3_elapsed_total > 0.0 else None
        )
        _naive_blake3_mbps = (
            baseline_mb_total / naive_blake3_elapsed_total
            if naive_blake3_elapsed_total > 0.0 else None
        )
        _sha256_mbps = (
            baseline_mb_total / baseline_sha256_elapsed_total
            if baseline_sha256_elapsed_total > 0.0 else None
        )
        _sha1_mbps = (
            baseline_mb_total / baseline_sha1_elapsed_total
            if baseline_sha1_elapsed_total > 0.0 else None
        )
        _md5_mbps = (
            baseline_mb_total / baseline_md5_elapsed_total
            if baseline_md5_elapsed_total > 0.0 else None
        )

        _max_mbps = max(
            [v for v in (
                _optimized_mbps, _naive_blake3_mbps,
                _sha256_mbps, _sha1_mbps, _md5_mbps
            ) if v is not None] or [0.0]
        )

        bar_optimized_blake3 = _throughput_cell_html(
            _optimized_mbps, _max_mbps, is_primary=True
        )
        bar_baseline_blake3 = _throughput_cell_html(
            _naive_blake3_mbps, _max_mbps
        )
        bar_sha256 = _throughput_cell_html(_sha256_mbps, _max_mbps)
        bar_sha1 = _throughput_cell_html(_sha1_mbps, _max_mbps)
        bar_md5 = _throughput_cell_html(_md5_mbps, _max_mbps)

    else:

        avg_blake3_throughput_subset = "N/A"
        avg_md5_throughput = "N/A"
        avg_sha1_throughput = "N/A"
        avg_sha256_throughput = "N/A"
        avg_naive_blake3_throughput = "N/A"
        speedup_vs_md5 = "N/A"
        speedup_vs_sha1 = "N/A"
        speedup_vs_sha256 = "N/A"
        speedup_vs_naive_blake3 = "N/A"
        blake3_correctness_summary = "Not yet available"

        bar_optimized_blake3 = '<span class="throughput-figure">N/A</span>'
        bar_baseline_blake3 = '<span class="throughput-figure">N/A</span>'
        bar_sha256 = '<span class="throughput-figure">N/A</span>'
        bar_sha1 = '<span class="throughput-figure">N/A</span>'
        bar_md5 = '<span class="throughput-figure">N/A</span>'

    evidence_baseline_note = (
        stats_copy.get("evidence_baseline_note") or "Not yet available"
    )

    # -----------------------------------------------------------------------
    # EVIDENCE-SOURCE BASELINE DETAILS
    # -----------------------------------------------------------------------
    evidence_baseline_status = (
        stats_copy.get("evidence_baseline_status") or "Not computed"
    )

    def _baseline_value(key):
        value = stats_copy.get(key)
        return value if value not in (None, "") else "N/A"

    evidence_baseline_md5 = _baseline_value("evidence_baseline_md5")
    evidence_baseline_sha1 = _baseline_value("evidence_baseline_sha1")
    evidence_baseline_sha256 = _baseline_value("evidence_baseline_sha256")
    evidence_baseline_blake3 = _baseline_value("evidence_baseline_blake3")

    evidence_baseline_md5_time = stats_copy.get(
        "evidence_baseline_md5_elapsed"
    )
    evidence_baseline_sha1_time = stats_copy.get(
        "evidence_baseline_sha1_elapsed"
    )
    evidence_baseline_sha256_time = stats_copy.get(
        "evidence_baseline_sha256_elapsed"
    )
    evidence_baseline_blake3_time = stats_copy.get(
        "evidence_baseline_blake3_elapsed"
    )

    evidence_size_mb = (
        float(stats_copy.get("evidence_size", 0)) / (1024.0 * 1024.0)
        if stats_copy.get("evidence_size") is not None else 0.0
    )

    def _evidence_baseline_throughput(elapsed):
        if evidence_size_mb > 0.0 and elapsed and float(elapsed) > 0.0:
            return _format_throughput(evidence_size_mb / float(elapsed))
        return "N/A"

    evidence_baseline_md5_time_display = (
        _format_duration(evidence_baseline_md5_time)
        if evidence_baseline_md5_time is not None else "N/A"
    )
    evidence_baseline_sha1_time_display = (
        _format_duration(evidence_baseline_sha1_time)
        if evidence_baseline_sha1_time is not None else "N/A"
    )
    evidence_baseline_sha256_time_display = (
        _format_duration(evidence_baseline_sha256_time)
        if evidence_baseline_sha256_time is not None else "N/A"
    )
    evidence_baseline_blake3_time_display = (
        _format_duration(evidence_baseline_blake3_time)
        if evidence_baseline_blake3_time is not None else "N/A"
    )

    evidence_baseline_md5_throughput = _evidence_baseline_throughput(
        evidence_baseline_md5_time
    )
    evidence_baseline_sha1_throughput = _evidence_baseline_throughput(
        evidence_baseline_sha1_time
    )
    evidence_baseline_sha256_throughput = _evidence_baseline_throughput(
        evidence_baseline_sha256_time
    )
    evidence_baseline_blake3_throughput = _evidence_baseline_throughput(
        evidence_baseline_blake3_time
    )

    optimized_evidence_time = stats_copy.get("evidence_elapsed")
    baseline_evidence_speedup = "N/A"
    if (
        optimized_evidence_time is not None
        and float(optimized_evidence_time) > 0.0
        and evidence_baseline_blake3_time is not None
        and float(evidence_baseline_blake3_time) > 0.0
    ):
        baseline_evidence_speedup = "%.2fx faster" % (
            float(evidence_baseline_blake3_time) /
            float(optimized_evidence_time)
        )

    evidence_baseline_match = stats_copy.get(
        "evidence_baseline_blake3_matches"
    )
    if evidence_baseline_match is True:
        evidence_baseline_match_display = "MATCH — same BLAKE3 digest"
        evidence_baseline_match_badge_class = "badge-green"
    elif evidence_baseline_match is False:
        evidence_baseline_match_display = "MISMATCH — investigate"
        evidence_baseline_match_badge_class = "badge-red"
    else:
        evidence_baseline_match_display = "N/A"
        evidence_baseline_match_badge_class = "badge-blue"

    # --- Evidence-source speedups, one per reference algorithm, so
    # Section 3 can show the same "vs. Optimized BLAKE3" comparison
    # that Section 2 shows for the aggregate file subset. ---
    evidence_speedup_vs_blake3_baseline = _speedup_string(
        evidence_baseline_blake3_time,
        optimized_evidence_time,
        "Baseline BLAKE3"
    )
    evidence_speedup_vs_sha256 = _speedup_string(
        evidence_baseline_sha256_time,
        optimized_evidence_time,
        "SHA-256"
    )
    evidence_speedup_vs_sha1 = _speedup_string(
        evidence_baseline_sha1_time,
        optimized_evidence_time,
        "SHA-1"
    )
    evidence_speedup_vs_md5 = _speedup_string(
        evidence_baseline_md5_time,
        optimized_evidence_time,
        "MD5"
    )


    html = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(evidence_name)s - BLAKE3 Forensic Hash Report</title>
<style>
    :root {
        --navy: #102a43;
        --blue: #1f5f8b;
        --blue2: #2f80b7;
        --ink: #243b53;
        --muted: #627d98;
        --line: #d9e2ec;
        --soft: #f5f8fb;
        --white: #ffffff;
        --green: #1f7a4d;
        --green-bg: #eaf7ef;
        --amber: #9a6700;
        --amber-bg: #fff7df;
        --red: #a61b1b;
        --red-bg: #fff0f0;
    }

    * { box-sizing: border-box; }

    body {
        margin: 0;
        background: #eef2f6;
        color: var(--ink);
        font-family: "Segoe UI", Arial, Helvetica, sans-serif;
        line-height: 1.5;
    }

    .page {
        max-width: 1180px;
        margin: 0 auto;
        padding: 34px 26px 48px;
    }

    .hero {
        background: linear-gradient(135deg, #102a43, #1f5f8b);
        color: white;
        border-radius: 16px;
        padding: 28px 30px;
        box-shadow: 0 10px 28px rgba(16, 42, 67, 0.16);
    }

    .eyebrow {
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 1.4px;
        text-transform: uppercase;
        opacity: 0.78;
    }

    h1 {
        margin: 7px 0 8px;
        font-size: 29px;
        line-height: 1.2;
    }

    .hero-subtitle {
        margin: 0;
        max-width: 900px;
        color: #d9eaf6;
        font-size: 14px;
    }

    .hero-meta {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 20px;
    }

    .hero-pill {
        background: rgba(255,255,255,0.12);
        border: 1px solid rgba(255,255,255,0.18);
        border-radius: 999px;
        padding: 6px 11px;
        font-size: 12px;
    }

    h2 {
        color: var(--navy);
        font-size: 19px;
        margin: 34px 0 12px;
    }

    h3 {
        color: var(--navy);
        font-size: 15px;
    }

    .section-note {
        color: var(--muted);
        font-size: 13px;
        margin: 8px 0 14px;
    }

    .card-grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 12px;
        margin-top: 16px;
    }

    .metric {
        background: var(--white);
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: 16px;
        box-shadow: 0 4px 14px rgba(16, 42, 67, 0.05);
    }

    .metric-label {
        color: var(--muted);
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.7px;
        font-weight: 700;
    }

    .metric-value {
        color: var(--navy);
        font-size: 18px;
        font-weight: 700;
        margin-top: 6px;
        word-break: break-word;
    }

    .panel {
        background: var(--white);
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 18px;
        margin-top: 14px;
        box-shadow: 0 4px 14px rgba(16, 42, 67, 0.04);
    }

    table {
        width: 100%%;
        border-collapse: separate;
        border-spacing: 0;
        background: var(--white);
        border: 1px solid var(--line);
        border-radius: 12px;
        overflow: hidden;
        margin-top: 12px;
    }

    th, td {
        padding: 11px 13px;
        border-bottom: 1px solid var(--line);
        vertical-align: top;
        text-align: left;
        font-size: 13px;
    }

    th {
        background: var(--navy);
        color: white;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    tr:last-child td { border-bottom: 0; }
    tbody tr:nth-child(even) td { background: var(--soft); }

    .comparison th:first-child { width: 20%%; }
    .comparison td:not(:first-child) { text-align: left; }

    .algorithm {
        font-weight: 700;
        color: var(--navy);
    }

    .role {
        display: block;
        color: var(--muted);
        font-size: 11px;
        font-weight: 400;
        margin-top: 2px;
    }

    .primary-row td {
        background: #edf6fc !important;
        border-top: 1px solid #b9d9ed;
        border-bottom: 1px solid #b9d9ed;
    }

    .baseline-row td {
        background: #f7f7fb !important;
    }

    .badge {
        display: inline-block;
        border-radius: 999px;
        padding: 4px 9px;
        font-size: 11px;
        font-weight: 700;
        white-space: nowrap;
    }

    .badge-green { color: var(--green); background: var(--green-bg); }
    .badge-amber { color: var(--amber); background: var(--amber-bg); }
    .badge-red { color: var(--red); background: var(--red-bg); }
    .badge-blue { color: var(--blue); background: #eaf3fa; }

    .digest {
        font-family: Consolas, "Courier New", monospace;
        font-size: 11px;
        word-break: break-all;
    }

    .hash-card {
        border-left: 4px solid var(--blue2);
        background: #fbfdff;
    }

    .hash-name {
        font-weight: 800;
        color: var(--navy);
        font-size: 15px;
    }

    .hash-purpose {
        color: var(--muted);
        font-size: 12px;
        margin: 3px 0 10px;
    }

    .two-col {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 14px;
    }

    .callout {
        border-radius: 11px;
        padding: 13px 15px;
        margin-top: 12px;
        font-size: 12px;
    }

    .callout-info {
        background: #edf6fc;
        border: 1px solid #c8e1f0;
        color: #24516e;
    }

    .callout-warn {
        background: var(--amber-bg);
        border: 1px solid #f0d88a;
        color: #6f5100;
    }

    .callout-danger {
        background: var(--red-bg);
        border: 1px solid #efb7b7;
        color: #7f1d1d;
    }

    .digest-block {
        background: #0f1720;
        color: #d9e2ec;
        border-radius: 10px;
        padding: 12px 14px;
        margin-top: 8px;
        font-family: Consolas, "Courier New", monospace;
        font-size: 11px;
        word-break: break-all;
    }

    .throughput-cell {
        display: flex;
        flex-direction: column;
        gap: 5px;
        min-width: 150px;
    }

    .throughput-figure {
        font-weight: 700;
        color: var(--navy);
        font-size: 13px;
    }

    .throughput-track {
        width: 100%%;
        height: 7px;
        background: #e4ecf3;
        border-radius: 999px;
        overflow: hidden;
    }

    .throughput-fill {
        height: 100%%;
        border-radius: 999px;
        background: linear-gradient(90deg, #2f80b7, #1f5f8b);
    }

    .throughput-fill.is-primary {
        background: linear-gradient(90deg, #22a35a, #1f7a4d);
    }

    .footer {
        margin-top: 34px;
        padding-top: 16px;
        border-top: 1px solid var(--line);
        color: var(--muted);
        font-size: 11px;
        text-align: center;
    }

    @media (max-width: 900px) {
        .card-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .two-col { grid-template-columns: 1fr; }
        .comparison { display: block; overflow-x: auto; }
    }

    @media (max-width: 560px) {
        .page { padding: 18px 12px 30px; }
        .hero { padding: 22px 20px; }
        .card-grid { grid-template-columns: 1fr; }
        h1 { font-size: 24px; }
    }

    @media print {
        body { background: white; }
        .page { max-width: none; padding: 0; }
        .hero { box-shadow: none; }
        .panel, .metric { box-shadow: none; }
    }
</style>
</head>
<body>
<div class="page">

<header class="hero">
    <div class="eyebrow">Digital Forensics • Autopsy Ingest Report</div>
    <h1>Optimized BLAKE3 Hash Verification Report</h1>
    <p class="hero-subtitle">
        Performance, integrity, and reference-hash comparison for the processed
        evidence source. Baseline algorithms are reporting-only and do not create
        additional Blackboard artifacts.
    </p>
    <div class="hero-meta">
        <span class="hero-pill">Case: %(case_name)s</span>
        <span class="hero-pill">Examiner: %(examiner)s</span>
        <span class="hero-pill">Evidence: %(evidence_name)s</span>
        <span class="hero-pill">Generated: %(generated_at)s</span>
    </div>
</header>

<h2>Executive Summary</h2>
<div class="card-grid">
    <div class="metric">
        <div class="metric-label">Evidence Status</div>
        <div class="metric-value">%(evidence_status)s</div>
    </div>
    <div class="metric">
        <div class="metric-label">Evidence Size</div>
        <div class="metric-value">%(evidence_size)s</div>
    </div>
    <div class="metric">
        <div class="metric-label">Optimized BLAKE3 Throughput</div>
        <div class="metric-value">%(evidence_throughput)s</div>
    </div>
    <div class="metric">
        <div class="metric-label">Engine Self-Test</div>
        <div class="metric-value">%(self_test_status)s</div>
    </div>
</div>

<h2>1. Hashing Architecture & Integrity Controls</h2>
<div class="panel">
<table>
    <thead>
        <tr><th>Control</th><th>Result</th><th>Forensic Significance</th></tr>
    </thead>
    <tbody>
        <tr>
            <td><strong>Complete byte-count verification</strong></td>
            <td><span class="badge badge-green">Required</span></td>
            <td>The module only accepts a digest after the expected number of bytes has been read; missing bytes are never zero-padded.</td>
        </tr>
        <tr>
            <td><strong>Startup engine self-test</strong></td>
            <td>%(self_test_status)s</td>
            <td>Zero-byte input is hashed twice and checked against the known BLAKE3 empty-input test vector before evidence processing.</td>
        </tr>
        <tr>
            <td><strong>Individual-file re-hash</strong></td>
            <td>%(files_consistency_verified)s verified / %(files_consistency_not_checked)s not checked</td>
            <td>Every file is hashed twice and both BLAKE3 digests are compared directly to confirm determinism.</td>
        </tr>
    </tbody>
</table>

<div class="callout callout-info">
    <strong>Self-test detail:</strong> %(self_test_message)s
</div>

<div class="callout callout-warn">
    <strong>Evidence-source consistency:</strong> %(evidence_consistency_status)s
</div>
</div>

<h2>2. Algorithm Comparison — Optimized BLAKE3 vs. Autopsy Reference Hashes</h2>
<p class="section-note">
    All five algorithms below were run against every processed file.
    MD5, SHA-1, and SHA-256 are computed the same way Autopsy's own Hash Lookup
    ingest module computes them -- one combined read pass per file, all three
    digests updated from the same bytes -- with each digest's CPU time still
    tracked individually so a per-algorithm throughput figure can be shown without
    re-reading the file three times. Baseline BLAKE3 and Optimized BLAKE3 each
    use their own dedicated read pass, since they are separate algorithms
    entirely.
</p>

<div class="panel">
<table class="comparison">
    <thead>
        <tr>
            <th>Hashing Approach</th>
            <th>Implementation</th>
            <th>Avg Throughput</th>
            <th>Relative Performance</th>
            <th>Role in Report</th>
        </tr>
    </thead>
    <tbody>
        <tr class="primary-row">
            <td class="algorithm">Optimized BLAKE3<span class="role">Production hashing path</span></td>
            <td>Optimized sidecar engine · SIMD-accelerated · multi-threaded</td>
            <td>%(bar_optimized_blake3)s</td>
            <td><span class="badge badge-green">Baseline reference · 1.00x</span></td>
            <td>Primary forensic digest, used for the Blackboard artifact</td>
        </tr>
        <tr class="baseline-row">
            <td class="algorithm">Baseline BLAKE3<span class="role">Algorithm-equivalent reference</span></td>
            <td>Bouncy Castle pure-Java Blake3Digest · single-threaded, no SIMD</td>
            <td>%(bar_baseline_blake3)s</td>
            <td><span class="badge badge-blue">%(speedup_vs_naive_blake3)s</span></td>
            <td>Isolates the real-world benefit of the optimized engine and cross-checks digest correctness</td>
        </tr>
        <tr>
            <td class="algorithm">SHA-256<span class="role">Autopsy reference hash</span></td>
            <td>java.security.MessageDigest · combined pass with MD5/SHA-1</td>
            <td>%(bar_sha256)s</td>
            <td><span class="badge badge-amber">%(speedup_vs_sha256)s</span></td>
            <td>Modern legal/interoperability reference hash</td>
        </tr>
        <tr>
            <td class="algorithm">SHA-1<span class="role">Autopsy reference hash</span></td>
            <td>java.security.MessageDigest · combined pass with MD5/SHA-256</td>
            <td>%(bar_sha1)s</td>
            <td><span class="badge badge-amber">%(speedup_vs_sha1)s</span></td>
            <td>Legacy reference hash, kept for backward compatibility</td>
        </tr>
        <tr>
            <td class="algorithm">MD5<span class="role">Autopsy reference hash</span></td>
            <td>java.security.MessageDigest · combined pass with SHA-1/SHA-256</td>
            <td>%(bar_md5)s</td>
            <td><span class="badge badge-amber">%(speedup_vs_md5)s</span></td>
            <td>Legacy reference hash, kept for backward compatibility</td>
        </tr>
    </tbody>
</table>

<div class="callout callout-info">
    <strong>How to read this table:</strong> the throughput bars are scaled
    relative to the fastest algorithm measured in this job. Relative-performance
    values compare total elapsed hashing time on the same data — e.g.
    "2.00x faster" means Optimized BLAKE3 took half the time of that algorithm
    to hash the same bytes. Because MD5/SHA-1/SHA-256 share one read pass (the
    same approach Autopsy's own Hash Lookup module uses), their individual
    figures reflect CPU time only, isolated from the (shared, one-time) I/O
    cost of reading the file.
</div>
</div>

<h2>3. Evidence Source — Complete Hash Comparison</h2>
<p class="section-note">
    The full evidence source (%(evidence_name)s, %(evidence_size)s) is hashed once
    with Optimized BLAKE3 for the Blackboard artifact. The same source is also
    independently re-hashed with Baseline BLAKE3, SHA-256, SHA-1, and MD5 (the
    latter three via one Autopsy-style combined pass) so every algorithm can be
    compared side by side, exactly like the file-level comparison in Section 2.
</p>

<div class="panel">
    <div class="callout callout-info">
        <strong>Baseline computation status:</strong> %(evidence_baseline_status)s —
        %(evidence_baseline_note)s
    </div>

    <table class="comparison">
        <thead>
            <tr>
                <th>Algorithm</th>
                <th>Role</th>
                <th>Execution Time</th>
                <th>Throughput</th>
                <th>vs. Optimized BLAKE3</th>
                <th>Digest</th>
            </tr>
        </thead>
        <tbody>
            <tr class="primary-row">
                <td class="algorithm">Optimized BLAKE3</td>
                <td>Production digest (posted as Blackboard artifact)</td>
                <td>%(evidence_elapsed)s</td>
                <td>%(evidence_throughput)s</td>
                <td><span class="badge badge-green">Reference · 1.00x</span></td>
                <td class="digest">%(evidence_digest)s</td>
            </tr>
            <tr class="baseline-row">
                <td class="algorithm">Baseline BLAKE3</td>
                <td>Algorithm-equivalent correctness check</td>
                <td>%(evidence_baseline_blake3_time)s</td>
                <td>%(evidence_baseline_blake3_throughput)s</td>
                <td><span class="badge badge-blue">%(evidence_speedup_vs_blake3_baseline)s</span></td>
                <td class="digest">%(evidence_baseline_blake3)s<br/><span class="badge %(evidence_baseline_match_badge_class)s">%(evidence_baseline_match)s</span></td>
            </tr>
            <tr>
                <td class="algorithm">SHA-256</td>
                <td>Autopsy reference hash (combined pass)</td>
                <td>%(evidence_baseline_sha256_time)s</td>
                <td>%(evidence_baseline_sha256_throughput)s</td>
                <td><span class="badge badge-amber">%(evidence_speedup_vs_sha256)s</span></td>
                <td class="digest">%(evidence_baseline_sha256)s</td>
            </tr>
            <tr>
                <td class="algorithm">SHA-1</td>
                <td>Autopsy reference hash (combined pass)</td>
                <td>%(evidence_baseline_sha1_time)s</td>
                <td>%(evidence_baseline_sha1_throughput)s</td>
                <td><span class="badge badge-amber">%(evidence_speedup_vs_sha1)s</span></td>
                <td class="digest">%(evidence_baseline_sha1)s</td>
            </tr>
            <tr>
                <td class="algorithm">MD5</td>
                <td>Autopsy reference hash (combined pass)</td>
                <td>%(evidence_baseline_md5_time)s</td>
                <td>%(evidence_baseline_md5_throughput)s</td>
                <td><span class="badge badge-amber">%(evidence_speedup_vs_md5)s</span></td>
                <td class="digest">%(evidence_baseline_md5)s</td>
            </tr>
        </tbody>
    </table>

    <div class="callout callout-warn">
        <strong>Correctness note:</strong> MD5, SHA-1, SHA-256, and BLAKE3 are
        different algorithms, so their digest values are never expected to
        match each other. The one genuine same-algorithm check available is
        Baseline BLAKE3 vs. Optimized BLAKE3, shown above.
    </div>

    <table>
        <tr><td><strong>SIMD tier</strong></td><td>%(evidence_simd)s</td></tr>
        <tr><td><strong>Threads used</strong></td><td>%(evidence_threads)s</td></tr>
        <tr><td><strong>Evidence-source hash consistency</strong></td><td>%(evidence_consistency_status)s</td></tr>
    </table>
</div>

<h2>4. Benchmark Scope & Interpretation</h2>
<div class="panel">
<table>
    <tr><th>Files included in benchmark</th><td>%(baseline_files_checked)s</td></tr>
    <tr><th>Data included</th><td>%(baseline_bytes_total)s</td></tr>
    <tr><th>Baseline errors</th><td>%(baseline_files_error)s</td></tr>
    <tr><th>Optimized BLAKE3 vs SHA-256</th><td>%(speedup_vs_sha256)s</td></tr>
    <tr><th>Optimized BLAKE3 vs SHA-1</th><td>%(speedup_vs_sha1)s</td></tr>
    <tr><th>Optimized BLAKE3 vs MD5</th><td>%(speedup_vs_md5)s</td></tr>
    <tr><th>Optimized BLAKE3 vs Baseline BLAKE3</th><td>%(speedup_vs_naive_blake3)s</td></tr>
    <tr><th>Baseline BLAKE3 correctness</th><td>%(blake3_correctness_summary)s</td></tr>
</table>

<div class="callout callout-warn">
    <strong>Important:</strong> MD5, SHA-1, SHA-256, and BLAKE3 are different
    algorithms, so their digest values are not expected to match. The meaningful
    same-algorithm correctness check is Baseline BLAKE3 versus Optimized BLAKE3.
    For the reference algorithms, correctness is instead tied to a complete,
    independently verified read of the same expected byte count.
</div>

<div class="callout callout-info">
    <strong>Reporting scope:</strong> MD5, SHA-1, SHA-256 (hashed together in one
    Autopsy-style combined pass), and Baseline BLAKE3 are computed for every
    processed file. They are internal comparison data and are not added as
    separate Blackboard artifact columns.
</div>
</div>

<h2>5. Individual File Hashing Summary</h2>
<div class="card-grid">
    <div class="metric">
        <div class="metric-label">Successfully Hashed</div>
        <div class="metric-value">%(files_hashed)s</div>
    </div>
    <div class="metric">
        <div class="metric-label">Errors</div>
        <div class="metric-value">%(files_error)s</div>
    </div>
    <div class="metric">
        <div class="metric-label">Skipped</div>
        <div class="metric-value">%(files_skipped)s</div>
    </div>
    <div class="metric">
        <div class="metric-label">Average Throughput</div>
        <div class="metric-value">%(files_avg_throughput)s</div>
    </div>
</div>

<div class="panel">
<table>
    <tr><th>Total Data Hashed</th><td>%(files_bytes_total)s</td></tr>
    <tr><th>Total Cumulative Hashing Time</th><td>%(files_elapsed_total)s</td></tr>
    <tr><th>Files Double-Hash Verified</th><td>%(files_consistency_verified)s</td></tr>
    <tr><th>Files Not Double-Hash Checked</th><td>%(files_consistency_not_checked)s</td></tr>
</table>
<p class="section-note">
    Individual files are processed concurrently by Autopsy ingest workers.
    The cumulative hashing time is therefore the sum of individual end-to-end
    file timings, not the wall-clock duration of the entire ingest job.
</p>
</div>

%(skip_rows)s
%(error_reason_rows)s
%(error_rows)s

<div class="footer">
    Generated automatically by %(module_name)s v%(module_version)s.
    This report is intended to document hashing results, verification status,
    and performance measurements produced by the ingest module.
</div>

</div>
</body>
</html>
""" % {
        "evidence_name": _html_escape(evidence_name),
        "case_name": _html_escape(case_name),
        "examiner": _html_escape(examiner),
        "generated_at": _html_escape(generated_at),
        "evidence_status": _html_escape(stats_copy.get("evidence_status")),
        "evidence_size": _html_escape(
            _format_bytes(stats_copy.get("evidence_size"))
            if stats_copy.get("evidence_size") is not None
            else "N/A"
        ),
        "evidence_digest": _html_escape(
            stats_copy.get("evidence_digest") or "N/A"
        ),
        "evidence_simd": _html_escape(
            stats_copy.get("evidence_simd") or "N/A"
        ),
        "evidence_threads": _html_escape(
            stats_copy.get("evidence_threads") or "N/A"
        ),
        "evidence_elapsed": _html_escape(
            _format_duration(stats_copy.get("evidence_elapsed"))
            if stats_copy.get("evidence_elapsed") is not None
            else "N/A"
        ),
        "evidence_throughput": _html_escape(
            _format_throughput(stats_copy.get("evidence_throughput"))
            if stats_copy.get("evidence_throughput") is not None
            else "N/A"
        ),
        "self_test_status": _html_escape(self_test_status),
        "self_test_message": _html_escape(
            self_test_message or "N/A"
        ),
        "evidence_consistency_status": _html_escape(
            evidence_consistency_status
        ),
        "files_consistency_verified": _html_escape(
            stats_copy.get("files_consistency_verified", 0)
        ),
        "files_consistency_not_checked": _html_escape(
            stats_copy.get("files_consistency_not_checked", 0)
        ),

        "baseline_files_checked": _html_escape(baseline_files_checked),
        "baseline_files_skipped_too_large": _html_escape(
            stats_copy.get("baseline_files_skipped_too_large", 0)
        ),
        "baseline_files_error": _html_escape(
            stats_copy.get("baseline_files_error", 0)
        ),
        "baseline_bytes_total": _html_escape(
            _format_bytes(baseline_bytes_total)
        ),
        "avg_blake3_throughput_subset": _html_escape(
            avg_blake3_throughput_subset
        ),
        "avg_md5_throughput": _html_escape(avg_md5_throughput),
        "avg_sha1_throughput": _html_escape(avg_sha1_throughput),
        "avg_sha256_throughput": _html_escape(avg_sha256_throughput),
        "speedup_vs_md5": _html_escape(speedup_vs_md5),
        "speedup_vs_sha1": _html_escape(speedup_vs_sha1),
        "speedup_vs_sha256": _html_escape(speedup_vs_sha256),
        "avg_naive_blake3_throughput": _html_escape(
            avg_naive_blake3_throughput
        ),
        "speedup_vs_naive_blake3": _html_escape(speedup_vs_naive_blake3),
        "bar_optimized_blake3": bar_optimized_blake3,
        "bar_baseline_blake3": bar_baseline_blake3,
        "bar_sha256": bar_sha256,
        "bar_sha1": bar_sha1,
        "bar_md5": bar_md5,
        "evidence_speedup_vs_blake3_baseline": _html_escape(
            evidence_speedup_vs_blake3_baseline
        ),
        "evidence_speedup_vs_sha256": _html_escape(
            evidence_speedup_vs_sha256
        ),
        "evidence_speedup_vs_sha1": _html_escape(
            evidence_speedup_vs_sha1
        ),
        "evidence_speedup_vs_md5": _html_escape(
            evidence_speedup_vs_md5
        ),
        "evidence_baseline_match_badge_class": evidence_baseline_match_badge_class,
        "blake3_correctness_summary": _html_escape(
            blake3_correctness_summary
        ),
        "evidence_baseline_note": _html_escape(evidence_baseline_note),
        "evidence_baseline_status": _html_escape(evidence_baseline_status),
        "evidence_baseline_md5": _html_escape(evidence_baseline_md5),
        "evidence_baseline_md5_time": _html_escape(
            evidence_baseline_md5_time_display
        ),
        "evidence_baseline_md5_throughput": _html_escape(
            evidence_baseline_md5_throughput
        ),
        "evidence_baseline_sha1": _html_escape(evidence_baseline_sha1),
        "evidence_baseline_sha1_time": _html_escape(
            evidence_baseline_sha1_time_display
        ),
        "evidence_baseline_sha1_throughput": _html_escape(
            evidence_baseline_sha1_throughput
        ),
        "evidence_baseline_sha256": _html_escape(evidence_baseline_sha256),
        "evidence_baseline_sha256_time": _html_escape(
            evidence_baseline_sha256_time_display
        ),
        "evidence_baseline_sha256_throughput": _html_escape(
            evidence_baseline_sha256_throughput
        ),
        "evidence_baseline_blake3": _html_escape(
            evidence_baseline_blake3
        ),
        "evidence_baseline_blake3_time": _html_escape(
            evidence_baseline_blake3_time_display
        ),
        "evidence_baseline_blake3_throughput": _html_escape(
            evidence_baseline_blake3_throughput
        ),
        "evidence_baseline_match": _html_escape(
            evidence_baseline_match_display
        ),
        "skip_rows": skip_rows,
        "error_reason_rows": error_reason_rows,
        "files_hashed": _html_escape(stats_copy.get("files_hashed", 0)),
        "files_error": _html_escape(stats_copy.get("files_error", 0)),
        "files_skipped": _html_escape(stats_copy.get("files_skipped", 0)),
        "files_bytes_total": _html_escape(
            _format_bytes(stats_copy.get("files_bytes_total", 0))
        ),
        "files_elapsed_total": _html_escape(
            _format_duration(stats_copy.get("files_elapsed_total", 0.0))
        ),
        "files_avg_throughput": _html_escape(
            _format_throughput(
                (
                    (
                        float(stats_copy.get("files_bytes_total", 0)) /
                        (1024.0 * 1024.0)
                    ) /
                    stats_copy["files_elapsed_total"]
                )
                if stats_copy.get("files_elapsed_total", 0.0) > 0.0
                else 0.0
            )
        ),
        "error_rows": error_rows,
        "module_name": _html_escape(BLAKE3IngestModuleFactory.MODULE_NAME),
        "module_version": _html_escape(
            BLAKE3IngestModuleFactory.MODULE_VERSION
        ),
    }

    try:

        report_dir = _get_report_directory()

        report_path = _unique_report_path(
            report_dir,
            base_name
        )

        report_file = open(report_path, "w")

        try:
            report_file.write(html)
        finally:
            report_file.close()

        # ---------------------------------------------------------------
        # REGISTER THE REPORT WITH THE CASE
        #
        # This makes the HTML file show up as a clickable entry under
        # the "Reports" node in the Autopsy tree, exactly like a
        # manually-generated report, so the user can open it from
        # inside the case without knowing the on-disk path.
        # ---------------------------------------------------------------

        try:

            Case.getCurrentCase().addReport(
                report_path,
                BLAKE3IngestModuleFactory.MODULE_NAME,
                "BLAKE3 Hash Report - " + evidence_name
            )

        except Exception as exc:

            try:
                IngestServices.getInstance().postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.WARNING,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "Report saved but could not be registered "
                        "in the Reports panel: " + str(exc)
                    )
                )
            except Exception:
                pass

        # ---------------------------------------------------------------
        # NOTIFY THE USER (INGEST INBOX)
        #
        # Posted as INFO so it lands in the ingest inbox, with the full
        # on-disk path spelled out so the user doesn't have to go
        # hunting for it even if they miss the Reports panel entry.
        # ---------------------------------------------------------------

        IngestServices.getInstance().postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                BLAKE3IngestModuleFactory.MODULE_NAME,
                "BLAKE3 hash report ready. Open it from the "
                "'Reports' panel in the tree, or directly at: " +
                report_path
            )
        )

# ---------------------------------------------------------------
        # NOTIFY THE USER (POP-UP DIALOG)
        #
        # In addition to the ingest inbox message above, show a small
        # pop-up telling the user exactly where the report was saved,
        # with an explicit "Open Report" / "OK" choice.
        # ---------------------------------------------------------------

        _show_report_popup(report_path)

    except Exception as exc:

        try:
            IngestServices.getInstance().postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    BLAKE3IngestModuleFactory.MODULE_NAME,
                    "Failed to write HTML report: " + str(exc)
                )
            )
        except Exception:
            pass


class _BLAKE3ReportListener(PropertyChangeListener):
    """
    Fires the HTML report exactly once, when the data source this
    ingest job is processing has finished ALL ingest modules (not
    just the BLAKE3 hasher). This is important: file hashing runs on
    background worker threads and may still be in flight when the
    DataSourceIngestModule.process() method itself returns, so the
    report cannot be generated there directly.
    """

    def __init__(self, job_id, data_source_id):

        self._job_id = job_id
        self._data_source_id = data_source_id

    def propertyChange(self, evt):

        try:

            if (
                evt.getPropertyName() !=
                IngestManager.IngestJobEvent
                .DATA_SOURCE_ANALYSIS_COMPLETED
                .toString()
            ):
                return

            evt_data_source = evt.getDataSource()

            if (
                evt_data_source is None or
                evt_data_source.getId() != self._data_source_id
            ):
                return

            stats = _get_job_stats(self._job_id)

            with _STATS_LOCK:

                if stats.get("report_generated"):
                    return

                stats["report_generated"] = True

            generate_html_report(self._job_id)

            try:
                IngestManager.getInstance().removeIngestJobEventListener(
                    self
                )
            except Exception:
                pass

        except Exception as exc:

            try:
                IngestServices.getInstance().postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.ERROR,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "Report listener error: " + str(exc)
                    )
                )
            except Exception:
                pass


# ===========================================================================
# FILE INGEST MODULE
# ===========================================================================

class BLAKE3FileIngestModule(FileIngestModule):

    def __init__(self):

        self._exe_path = None
        self._services = None
        self._blackboard = None
        self._case = None
        self._sidecar = None
        self._job_id = None

        self._files_done = 0
        self._files_error = 0
        self._files_skipped = 0

    # -----------------------------------------------------------------------
    # STARTUP
    # -----------------------------------------------------------------------

    def startUp(self, context):

        module_dir = os.path.dirname(
            os.path.abspath(__file__)
        )

        self._exe_path = os.path.join(
            module_dir,
            "optimized_blake3_hasher.exe"
        )

        if not os.path.isfile(self._exe_path):

            raise IngestModule.IngestModuleException(
                "optimized_blake3_hasher.exe not found in: " +
                module_dir
            )

        self._services = IngestServices.getInstance()

        self._case = Case.getCurrentCase()

        self._blackboard = (
            self._case
            .getSleuthkitCase()
            .getBlackboard()
        )

        self._job_id = context.getJobId()

        self._sidecar = _HasherSidecar(self._exe_path)

        self_test = run_engine_self_test(self._exe_path)

        _record_self_test(
            self._job_id,
            self_test["passed"],
            self_test["message"]
        )

        self._services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO
                if self_test["passed"]
                else IngestMessage.MessageType.ERROR,
                BLAKE3IngestModuleFactory.MODULE_NAME,
                "BLAKE3 file hasher started. Consistency self-test: " +
                self_test["message"]
            )
        )


    # -----------------------------------------------------------------------
    # PROCESS EACH FILE
    # -----------------------------------------------------------------------

    def process(self, file):

        file_name = file.getName()

        if (
            file.isDir() or
            file.getSize() == 0 or
            not file_name or
            file_name.startswith("$BadClus") or
            (file_name.startswith("$Bitmap") and file.getSize() == 0) or
            file.getType() ==
                TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS or
            file.getType() ==
                TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS
        ):

            # -----------------------------------------------------------
            # LOGGED SKIP, NOT A SILENT ONE
            #
            # Every skipped item is classified and counted so the
            # processing log / HTML report can account for it, instead
            # of it simply vanishing from the record.
            # -----------------------------------------------------------

            skip_reason = _classify_skip_reason(file)

            self._files_skipped += 1

            _record_file_skip(
                self._job_id,
                file.getName() or "(unnamed)",
                skip_reason
            )

            return IngestModule.ProcessResult.OK

        if (
            self._sidecar is None or
            not self._sidecar.is_alive()
        ):

            self._files_error += 1

            _record_file_error(
                self._job_id,
                file.getName(),
                "HASHER_PROCESS_UNAVAILABLE"
            )

            self._services.postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    BLAKE3IngestModuleFactory.MODULE_NAME,
                    "Hasher process is unavailable, cannot hash: " +
                    file.getName()
                )
            )

            return IngestModule.ProcessResult.OK

        size_bytes = file.getSize()

        wall_start_ns = System.nanoTime()

        try:

            # ---------------------------------------------------------------
            # STREAM COMPLETE FILE
            #
            # Same shared streaming helper used for the evidence source.
            # NEVER pads missing bytes -- verified below.
            # ---------------------------------------------------------------

            actual_read, result = stream_content_to_sidecar(
                file,
                size_bytes,
                self._sidecar
            )

            wall_elapsed_s = (
                System.nanoTime() -
                wall_start_ns
            ) * 1.0e-9

            if wall_elapsed_s < 0.0:
                wall_elapsed_s = 0.0

            # ---------------------------------------------------------------
            # ACCURACY CHECK
            #
            # NEVER pad missing bytes.
            # ---------------------------------------------------------------

            if actual_read != size_bytes:

                reason = _classify_error(None, actual_read, size_bytes)

                self._files_error += 1

                _record_file_error(self._job_id, file.getName(), reason)

                self._services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.ERROR,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "File read-size mismatch [" + reason + "]: " +
                        file.getName() +
                        " | Expected=" +
                        str(size_bytes) +
                        " | Read=" +
                        str(actual_read) +
                        " | No artifact posted."
                    )
                )

                return IngestModule.ProcessResult.OK

            # ---------------------------------------------------------------
            # GET SIDE-CAR RESULT
            # ---------------------------------------------------------------

            if result is None:

                self._files_error += 1

                _record_file_error(
                    self._job_id,
                    file.getName(),
                    "HASHER_COMMUNICATION_ERROR"
                )

                self._services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.ERROR,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "No/unparseable response from hasher for: " +
                        file.getName()
                    )
                )

                return IngestModule.ProcessResult.OK

            # ---------------------------------------------------------------
            # CHECK RESULT
            # ---------------------------------------------------------------

            if result.get("status") != "ok":

                engine_message = str(
                    result.get("message", "Unknown error")
                )

                reason = _classify_error(
                    Exception(engine_message),
                    actual_read,
                    size_bytes
                )

                self._files_error += 1

                _record_file_error(self._job_id, file.getName(), reason)

                self._services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.WARNING,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "BLAKE3 failed [" + reason + "]: " +
                        file.getName() +
                        " | " +
                        engine_message
                    )
                )

                return IngestModule.ProcessResult.OK

            digest = result.get(
                "digest",
                ""
            )

            if not _is_valid_blake3_digest(digest):

                self._files_error += 1

                _record_file_error(
                    self._job_id,
                    file.getName(),
                    "INVALID_DIGEST_FORMAT"
                )

                self._services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.ERROR,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "Hasher returned a malformed digest for: " +
                        file.getName() +
                        " | No artifact posted."
                    )
                )

                return IngestModule.ProcessResult.OK

            # ---------------------------------------------------------------
            # HASH CONSISTENCY VERIFICATION (PER-FILE RE-HASH)
            #
            # For files small enough that a second pass is cheap, hash
            # the file again through the same sidecar and confirm both
            # digests match. If they don't, the result is untrustworthy
            # and no artifact is posted -- a mismatch here means the
            # engine itself is not deterministic for this input.
            # ---------------------------------------------------------------

            # ---------------------------------------------------------------
            # HASH CONSISTENCY VERIFICATION (PER-FILE RE-HASH)
            #
            # Every file is hashed a second time through the same sidecar
            # and both digests are compared. If they don't match, the
            # result is untrustworthy and no artifact is posted.
            # ---------------------------------------------------------------

            verify_read, verify_result = stream_content_to_sidecar(
                file,
                size_bytes,
                self._sidecar
            )

            verify_digest = (
                verify_result.get("digest", "")
                if verify_result is not None
                else ""
            )

            if (
                verify_read != size_bytes or
                verify_result is None or
                verify_result.get("status") != "ok" or
                not _is_valid_blake3_digest(verify_digest) or
                verify_digest.lower() != digest.lower()
            ):

                self._files_error += 1

                _record_file_error(
                    self._job_id,
                    file.getName(),
                    "HASH_CONSISTENCY_MISMATCH"
                )

                self._services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.ERROR,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "Consistency check FAILED for " +
                        file.getName() +
                        ": re-hashing the same file produced a "
                        "different result. No artifact posted."
                    )
                )

                return IngestModule.ProcessResult.OK

            consistency_status = "Verified (double-hashed, matched)"

            # ---------------------------------------------------------------
            # REAL END-TO-END TIME
            # ---------------------------------------------------------------

            elapsed_s = "%.6f" % wall_elapsed_s

            throughput_mb_s = "%.3f" % (
                (
                    float(size_bytes) /
                    (1024.0 * 1024.0)
                ) /
                wall_elapsed_s
                if wall_elapsed_s > 0.0
                else 0.0
            )

            # ---------------------------------------------------------------
            # POST USING SAME ARTIFACT TYPE
            # ---------------------------------------------------------------

            self._post_file_artifact(
                file,
                digest,
                result.get(
                    "simd_tier",
                    ""
                ),
                result.get(
                    "threads_used",
                    ""
                ),
                elapsed_s,
                throughput_mb_s,
                size_bytes,
                consistency_status
            )

            self._files_done += 1

            _record_file_success(
                self._job_id,
                wall_elapsed_s,
                size_bytes,
                consistency_status
            )

            # ---------------------------------------------------------------
            # BASELINE HASH COMPARISON (MD5 / SHA-1 / SHA-256), NEW
            #
            # Purely additive: runs after the existing success recording
            # above, never affects whether/how the BLAKE3 artifact was
            # already posted. Internal only -- never a Blackboard
            # attribute, never a separate Autopsy data artifact. Bounded
            # by the same size threshold as the consistency check.
            # ---------------------------------------------------------------

            baseline_result = compute_baseline_hashes(
                file, size_bytes, digest
            )

            _record_baseline_result(
                self._job_id,
                wall_elapsed_s,
                size_bytes,
                baseline_result
            )

        except Exception as exc:

            reason = _classify_error(exc, 0, size_bytes)

            self._files_error += 1

            _record_file_error(self._job_id, file.getName(), reason)

            self._services.postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    BLAKE3IngestModuleFactory.MODULE_NAME,
                    "Error processing [" + reason + "] " +
                    file.getName() +
                    ": " +
                    str(exc)
                )
            )

        return IngestModule.ProcessResult.OK

    # -----------------------------------------------------------------------
    # POST FILE ARTIFACT
    # -----------------------------------------------------------------------

    def _post_file_artifact(
            self,
            file,
            digest,
            simd_tier,
            threads_used,
            elapsed_s,
            throughput_mb_s,
            file_size,
            consistency_status="Not checked"):

        try:

            art_type = get_unified_artifact_type(
                self._blackboard
            )

            attrs = build_common_attributes(
                self._blackboard,
                digest,
                simd_tier,
                threads_used,
                elapsed_s,
                throughput_mb_s,
                file.getName(),
                file_size,
                consistency_status
            )

            artifact = file.newArtifact(
                art_type.getTypeID()
            )

            artifact.addAttributes(attrs)

            self._blackboard.postArtifact(
                artifact,
                BLAKE3IngestModuleFactory.MODULE_NAME
            )

        except Exception as exc:

            self._services.postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    BLAKE3IngestModuleFactory.MODULE_NAME,
                    "Failed to post file artifact for " +
                    file.getName() +
                    ": " +
                    str(exc)
                )
            )

    # -----------------------------------------------------------------------
    # SHUTDOWN
    # -----------------------------------------------------------------------

    def shutDown(self):

        if self._sidecar is not None:
            self._sidecar.close()

        self._services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                BLAKE3IngestModuleFactory.MODULE_NAME,
                "BLAKE3 file hasher finished. " +
                "Hashed=" +
                str(self._files_done) +
                " Errors=" +
                str(self._files_error) +
                " Skipped=" +
                str(self._files_skipped)
            )
        )


# ===========================================================================
# DATA SOURCE INGEST MODULE
#
# THIS PRODUCES THE FIRST ARTIFACT:
#
#     RM#1.dd
#
# It uses the SAME artifact type as individual files:
#
#     BLAKE3 Hash (Optimized)
#
# There is NO:
#
#     BLAKE3 Hash (Optimized) - Evidence Source
#
# anymore.
# ===========================================================================

class BLAKE3DataSourceIngestModule(DataSourceIngestModule):

    def __init__(self):

        self._exe_path = None
        self._services = None
        self._case = None
        self._blackboard = None
        self._sidecar = None
        self._job_id = None

    # -----------------------------------------------------------------------
    # STARTUP
    # -----------------------------------------------------------------------

    def startUp(self, context):

        module_dir = os.path.dirname(
            os.path.abspath(__file__)
        )

        self._exe_path = os.path.join(
            module_dir,
            "optimized_blake3_hasher.exe"
        )

        if not os.path.isfile(self._exe_path):

            raise IngestModule.IngestModuleException(
                "optimized_blake3_hasher.exe not found in: " +
                module_dir
            )

        self._services = IngestServices.getInstance()

        self._case = Case.getCurrentCase()

        self._blackboard = (
            self._case
            .getSleuthkitCase()
            .getBlackboard()
        )

        self._job_id = context.getJobId()

        self._sidecar = _HasherSidecar(self._exe_path)

        self_test = run_engine_self_test(self._exe_path)

        _record_self_test(
            self._job_id,
            self_test["passed"],
            self_test["message"]
        )

        self._services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO
                if self_test["passed"]
                else IngestMessage.MessageType.ERROR,
                BLAKE3IngestModuleFactory.MODULE_NAME,
                "BLAKE3 evidence-source hasher started. Consistency "
                "self-test: " + self_test["message"]
            )
        )

    # -----------------------------------------------------------------------
    # PROGRESS
    # -----------------------------------------------------------------------

    def _switch_to_determinate(
            self,
            progressBar):

        try:

            progressBar.switchToDeterminate(
                100
            )

            return True

        except Exception:

            try:

                progressBar.switchToDeterminate()

                return True

            except Exception:

                return False

    def _set_progress(
            self,
            progressBar,
            percent):

        try:

            value = int(percent)

            if value < 0:
                value = 0

            if value > 100:
                value = 100

            progressBar.progress(
                value
            )

            return True

        except Exception:

            return False

    # -----------------------------------------------------------------------
    # PROCESS COMPLETE EVIDENCE SOURCE
    # -----------------------------------------------------------------------

    def process(
            self,
            dataSource,
            progressBar):

        evidence_name = "unknown"
        evidence_size = 0

        try:

            evidence_name = dataSource.getName()
            evidence_size = dataSource.getSize()

            # -----------------------------------------------------------
            # REGISTER THE REPORT LISTENER
            #
            # Registered here (not startUp) because we need the actual
            # dataSource object/id. Guarded so a job/data-source pair
            # only ever gets one listener and one report.
            # -----------------------------------------------------------

            try:

                stats = _get_job_stats(self._job_id)

                with _STATS_LOCK:
                    already_registered = stats.get(
                        "listener_registered",
                        False
                    )
                    stats["listener_registered"] = True

                if not already_registered:

                    IngestManager.getInstance().addIngestJobEventListener(
                        _BLAKE3ReportListener(
                            self._job_id,
                            dataSource.getId()
                        )
                    )

            except Exception as exc:

                self._services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.WARNING,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "Could not register report listener: " +
                        str(exc)
                    )
                )

            self._switch_to_determinate(
                progressBar
            )

            self._set_progress(
                progressBar,
                0
            )

            self._services.postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.INFO,
                    BLAKE3IngestModuleFactory.MODULE_NAME,
                    "Complete evidence-source hashing started: " +
                    evidence_name +
                    " | Size=" +
                    str(evidence_size) +
                    " bytes"
                )
            )

            if evidence_size <= 0:

                self._services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.WARNING,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "Evidence source has zero size: " +
                        evidence_name
                    )
                )

                self._set_progress(
                    progressBar,
                    100
                )

                return IngestModule.ProcessResult.OK

            if (
                self._sidecar is None or
                not self._sidecar.is_alive()
            ):

                self._services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.ERROR,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "Evidence-source hasher process unavailable."
                    )
                )

                return IngestModule.ProcessResult.OK

            # ---------------------------------------------------------------
            # REAL END-TO-END TIMER
            # ---------------------------------------------------------------

            wall_start_ns = System.nanoTime()

            result = self._hash_datasource(
                dataSource,
                evidence_size,
                progressBar,
                evidence_name
            )

            wall_elapsed_s = (
                System.nanoTime() -
                wall_start_ns
            ) * 1.0e-9

            if wall_elapsed_s < 0.0:
                wall_elapsed_s = 0.0

            # ---------------------------------------------------------------
            # RESULT VALIDATION
            # ---------------------------------------------------------------

            if result is None:

                return IngestModule.ProcessResult.OK
            if result.get("status") != "ok":

                engine_message = str(
                    result.get("message", "Unknown error")
                )

                reason = _classify_error(
                    Exception(engine_message),
                    result.get("bytes_read", 0) or 0,
                    evidence_size
                )

                self._services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.ERROR,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "Evidence-source hashing failed [" +
                        reason + "]: " +
                        evidence_name +
                        " | " +
                        engine_message
                    )
                )

                return IngestModule.ProcessResult.OK

            actual_read = result.get(
                "bytes_read",
                -1
            )

            if actual_read != evidence_size:

                reason = _classify_error(
                    None, actual_read, evidence_size
                )

                self._services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.ERROR,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "Evidence-source byte verification failed [" +
                        reason + "]. " +
                        "Expected=" +
                        str(evidence_size) +
                        " Read=" +
                        str(actual_read) +
                        ". No artifact posted."
                    )
                )

                return IngestModule.ProcessResult.OK

            digest = result.get(
                "digest",
                ""
            )

            if not _is_valid_blake3_digest(digest):

                self._services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.ERROR,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "Evidence-source hasher returned an empty or "
                        "malformed digest. No artifact posted."
                    )
                )

                return IngestModule.ProcessResult.OK

            simd_tier = result.get(
                "simd_tier",
                ""
            )

            threads_used = result.get(
                "threads_used",
                ""
            )

            elapsed_s = "%.6f" % wall_elapsed_s

            throughput_mb_s = "%.3f" % (
                (
                    float(evidence_size) /
                    (1024.0 * 1024.0)
                ) /
                wall_elapsed_s
                if wall_elapsed_s > 0.0
                else 0.0
            )

            # ---------------------------------------------------------------
            # HASH CONSISTENCY NOTE FOR THIS EVIDENCE SOURCE
            #
            # The evidence source is generally too large to double-hash
            # affordably, so its consistency status reflects the engine
            # self-test performed at startUp() instead of a second full
            # pass -- this is disclosed explicitly rather than implying
            # a per-source re-hash happened. This status is reported in
            # the HTML report only, never as a Blackboard/Autopsy
            # artifact attribute.
            # ---------------------------------------------------------------

            job_stats = _get_job_stats(self._job_id)

            with _STATS_LOCK:
                self_test_passed = (
                    job_stats.get("self_test_status") == "PASSED"
                )

            if self_test_passed:
                evidence_consistency_status = (
                    "Not double-hashed (evidence source size makes a "
                    "second full pass impractical); engine self-test "
                    "at startup PASSED"
                )
            else:
                evidence_consistency_status = (
                    "UNVERIFIED -- engine self-test at startup FAILED "
                    "or did not run; treat this digest with caution"
                )

            # ---------------------------------------------------------------
            # RECORD FOR THE HTML REPORT
            # ---------------------------------------------------------------

            _record_evidence_result(
                self._job_id,
                evidence_name,
                digest,
                simd_tier,
                threads_used,
                elapsed_s,
                throughput_mb_s,
                evidence_size,
                evidence_consistency_status
            )

            # ---------------------------------------------------------------
            # BASELINE HASH COMPARISON FOR THE EVIDENCE SOURCE, NEW
            #
            # In practice the evidence source almost always exceeds
            # BASELINE_HASH_MAX_BYTES, so this typically records an
            # explicit "skipped, too large" note rather than a live
            # MD5/SHA-1/SHA-256 result -- but it is attempted honestly,
            # and the outcome (whichever it is) is always disclosed in
            # the HTML report instead of being silently omitted.
            # ---------------------------------------------------------------

            evidence_baseline_result = compute_baseline_hashes(
                dataSource, evidence_size, digest
            )

            _record_evidence_baseline_result(
                self._job_id, evidence_baseline_result
            )

            if evidence_baseline_result is None:
                _record_evidence_baseline_note(
                    self._job_id,
                    "Not computed for evidence source (" +
                    _format_bytes(evidence_size) +
                    ")."
                )
            elif evidence_baseline_result.get("status") == "ok":
                _record_evidence_baseline_note(
                    self._job_id,
                    "MD5=" + evidence_baseline_result["md5"] +
                    " (" + "%.3f" % (
                        evidence_baseline_result["md5_elapsed_s"]
                    ) + "s), SHA-1=" +
                    evidence_baseline_result["sha1"] +
                    " (" + "%.3f" % (
                        evidence_baseline_result["sha1_elapsed_s"]
                    ) + "s), SHA-256=" +
                    evidence_baseline_result["sha256"] +
                    " (" + "%.3f" % (
                        evidence_baseline_result["sha256_elapsed_s"]
                    ) + "s)"
                )
            else:
                _record_evidence_baseline_note(
                    self._job_id,
                    "Error computing evidence-source baseline: " +
                    str(evidence_baseline_result.get(
                        "message", "unknown"
                    ))
                )

            artifact = self._post_evidence_artifact(
                dataSource,
                evidence_name,
                evidence_size,
                digest,
                simd_tier,
                threads_used,
                elapsed_s,
                throughput_mb_s,
                evidence_consistency_status
            )

            if artifact is None:

                return IngestModule.ProcessResult.OK

            # ---------------------------------------------------------------
            # COMPLETE
            # ---------------------------------------------------------------

            self._set_progress(
                progressBar,
                100
            )

            try:

                self._services.fireModuleDataEvent(
                    ModuleDataEvent(
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        get_unified_artifact_type(
                            self._blackboard
                        ),
                        None
                    )
                )

            except Exception:

                pass

            self._services.postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.INFO,
                    BLAKE3IngestModuleFactory.MODULE_NAME,
                    "COMPLETE EVIDENCE SOURCE: " +
                    evidence_name +
                    " | BLAKE3=" +
                    str(digest) +
                    " | Size=" +
                    str(evidence_size) +
                    " bytes" +
                    " | Time=" +
                    str(elapsed_s) +
                    " s" +
                    " | Throughput=" +
                    str(throughput_mb_s) +
                    " MB/s"
                )
            )

        except Exception as exc:

            self._services.postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    BLAKE3IngestModuleFactory.MODULE_NAME,
                    "Error hashing complete evidence source '" +
                    evidence_name +
                    "': " +
                    str(exc)
                )
            )

        return IngestModule.ProcessResult.OK

    # -----------------------------------------------------------------------
    # HASH COMPLETE DATA SOURCE
    # -----------------------------------------------------------------------

    def _hash_datasource(
            self,
            dataSource,
            size_bytes,
            progressBar,
            evidence_name):
        """
        Streams the complete evidence source to the sidecar using the
        SAME stream_content_to_sidecar() helper used for individual
        files -- one code path, one method, for both. Never zero-pads
        missing bytes.
        """

        last_percent = [-1]

        def progress_cb(actual_read, total_size):

            percent = int(
                (
                    float(actual_read) *
                    100.0
                ) /
                float(total_size)
            )

            if percent < 0:
                percent = 0

            if percent > 100:
                percent = 100

            if percent != last_percent[0]:

                self._set_progress(
                    progressBar,
                    percent
                )

                last_percent[0] = percent

        try:

            actual_read, result = stream_content_to_sidecar(
                dataSource,
                size_bytes,
                self._sidecar,
                progress_cb
            )

            # ---------------------------------------------------------------
            # NEVER ZERO-PAD
            # ---------------------------------------------------------------

            if actual_read != size_bytes or result is None:

                return {
                    "status": "error",
                    "bytes_read": actual_read,
                    "message":
                        "Evidence source read-size mismatch or no "
                        "result from hasher. " +
                        "Expected=" +
                        str(size_bytes) +
                        " Read=" +
                        str(actual_read)
                }

            result["bytes_read"] = actual_read

            if result.get("status") == "ok":

                self._set_progress(
                    progressBar,
                    100
                )

            return result

        except Exception as exc:

            return {
                "status": "error",
                "bytes_read": 0,
                "message": str(exc)
            }

    # -----------------------------------------------------------------------
    # POST EVIDENCE SOURCE AS UNIFIED ARTIFACT
    # -----------------------------------------------------------------------

    def _post_evidence_artifact(
            self,
            dataSource,
            evidence_name,
            evidence_size,
            digest,
            simd_tier,
            threads_used,
            elapsed_s,
            throughput_mb_s,
            consistency_status="Not checked"):

        try:

            # ---------------------------------------------------------------
            # SAME ARTIFACT TYPE AS FILE HASHES
            # ---------------------------------------------------------------

            art_type = get_unified_artifact_type(
                self._blackboard
            )

            attrs = build_common_attributes(
                self._blackboard,
                digest,
                simd_tier,
                threads_used,
                elapsed_s,
                throughput_mb_s,
                evidence_name,
                evidence_size,
                consistency_status
            )

            # ---------------------------------------------------------------
            # ATTACH TO DATA SOURCE
            #
            # This is what makes RM#1.dd the first/top-level evidence
            # artifact instead of an individual extracted file.
            # ---------------------------------------------------------------

            artifact = dataSource.newArtifact(
                art_type.getTypeID()
            )

            artifact.addAttributes(
                attrs
            )

            self._blackboard.postArtifact(
                artifact,
                BLAKE3IngestModuleFactory.MODULE_NAME
            )

            return artifact

        except Exception as exc:

            self._services.postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    BLAKE3IngestModuleFactory.MODULE_NAME,
                    "Failed to post unified evidence artifact: " +
                    str(exc)
                )
            )

            return None

    # -----------------------------------------------------------------------
    # SHUTDOWN
    # -----------------------------------------------------------------------

    def shutDown(self):

        if self._sidecar is not None:
            self._sidecar.close()

        self._services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                BLAKE3IngestModuleFactory.MODULE_NAME,
                "BLAKE3 evidence-source hasher stopped."
            )
        )
