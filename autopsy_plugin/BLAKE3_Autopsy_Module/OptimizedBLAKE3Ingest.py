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
# REPORTING
# ---------
# When the ingest job for a data source finishes (all modules done,
# not just this one), an HTML report is generated automatically:
#     - Case name, examiner, evidence source name
#     - Report generation date/time
#     - Hashing summary (evidence digest + aggregate file stats)
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
# 2. PER-FILE RE-HASH (exact, runs per file, bounded by size so large
#    evidence isn't hashed twice): for files at or below
#    CONSISTENCY_CHECK_MAX_BYTES, the file is streamed through the
#    sidecar a SECOND time after the first hash and the two digests
#    are compared. A mismatch means the result is untrustworthy and
#    the artifact is NOT posted.
# ===========================================================================
 
KNOWN_BLAKE3_EMPTY_DIGEST = (
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
)
 
# Files at or below this size get hashed a second time as a direct
# consistency check. 5 MB was too aggressive in practice -- the large
# majority of real-world evidence files (office documents, images,
# executables, archives) are bigger than that, so almost every file
# was falling into "Not checked" and the double-hash check was barely
# running at all. 50 MB still keeps casework speed reasonable while
# actually covering most everyday files.
CONSISTENCY_CHECK_MAX_BYTES = 50 * 1024 * 1024
 
 
def run_engine_self_test(sidecar):
    """
    Hashes a zero-byte input twice through the given sidecar process
    and compares both digests to each other and to the published
    BLAKE3 digest of empty input. Returns a dict describing the
    outcome; never raises.
    """
 
    try:
 
        sidecar.write_header(0)
        sidecar.flush()
        line1 = sidecar.read_result_line()
 
        sidecar.write_header(0)
        sidecar.flush()
        line2 = sidecar.read_result_line()
 
        if not line1 or not line2:
            return {
                "passed": False,
                "message": "Self-test got no response from hasher "
                           "engine."
            }
 
        result1 = json.loads(str(line1).strip())
        result2 = json.loads(str(line2).strip())
 
        digest1 = result1.get("digest", "")
        digest2 = result2.get("digest", "")
 
        if not digest1 or not digest2:
            return {
                "passed": False,
                "message": "Self-test hasher returned an empty "
                           "digest."
            }
 
        if digest1 != digest2:
            return {
                "passed": False,
                "message": "Self-test FAILED: hashing the same "
                            "(empty) input twice produced two "
                            "different digests -- engine is not "
                            "deterministic. " +
                            digest1 + " != " + digest2
            }
 
        if digest1.lower() != KNOWN_BLAKE3_EMPTY_DIGEST.lower():
            return {
                "passed": False,
                "message": "Self-test FAILED: digest of empty input "
                            "does not match the known BLAKE3 test "
                            "vector. Got " + digest1 + ", expected " +
                            KNOWN_BLAKE3_EMPTY_DIGEST
            }
 
        return {
            "passed": True,
            "message": "Self-test passed: engine is deterministic "
                        "and matches the known BLAKE3 test vector."
        }
 
    except Exception as exc:
 
        return {
            "passed": False,
            "message": "Self-test raised an exception: " + str(exc)
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
    MODULE_VERSION = "3.12"
 
    MODULE_DESCRIPTION = (
        "Optimized BLAKE3 hashing module for Autopsy. "
        "Creates one unified 'BLAKE3 Hash (Optimized)' artifact type. "
        "The first artifact represents the complete evidence source, "
        "followed by artifacts for individual files. "
        "Hashing validates the complete byte count and never zero-pads "
        "missing evidence bytes. Automatically generates an HTML report "
        "when ingest finishes, and shows a pop-up telling you where it "
        "was saved."
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
                "report_generated": False,
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
 
    html = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>BLAKE3 Hash Report - %(evidence_name)s</title>
<style>
    body { font-family: Arial, Helvetica, sans-serif; margin: 30px; color: #222; }
    h1 { color: #1a3c6e; border-bottom: 2px solid #1a3c6e; padding-bottom: 6px; }
    h2 { color: #1a3c6e; margin-top: 30px; }
    table { border-collapse: collapse; width: 100%%; margin-top: 10px; }
    th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }
    th { background-color: #1a3c6e; color: #fff; width: 30%%; }
    tr:nth-child(even) { background-color: #f4f6f9; }
    .digest { font-family: Consolas, monospace; word-break: break-all; }
    .footer { margin-top: 40px; font-size: 0.85em; color: #777; }
</style>
</head>
<body>
 
<h1>Optimized BLAKE3 Hasher - Hash Report</h1>
 
<h2>Case Information</h2>
<table>
    <tr><th>Case Name</th><td>%(case_name)s</td></tr>
    <tr><th>Examiner</th><td>%(examiner)s</td></tr>
    <tr><th>Evidence Source</th><td>%(evidence_name)s</td></tr>
    <tr><th>Report Generated</th><td>%(generated_at)s</td></tr>
</table>
 
<h2>Hash Consistency Verification</h2>
<table>
    <tr><th>Hashing Engine Self-Test (Startup Verification)</th><td>%(self_test_status)s</td></tr>
    <tr><th>Self-Test Result Detail</th><td>%(self_test_message)s</td></tr>
    <tr><th>Evidence Source Consistency</th><td>%(evidence_consistency_status)s</td></tr>
    <tr><th>Individual Files Double-Hash Verified</th><td>%(files_consistency_verified)s</td></tr>
    <tr><th>Individual Files Not Double-Hash Checked</th><td>%(files_consistency_not_checked)s</td></tr>
    <tr><th>Double-Hash Verification Threshold</th><td>%(consistency_threshold)s</td></tr>
</table>
<p><em>Before any evidence is touched, the hashing engine is put through
a startup self-test: it hashes a zero-byte input twice through the same
running process and confirms both results are identical to each other
and to the published, independently verifiable BLAKE3 test vector for
empty input. This catches a broken or miscompiled hasher before it can
produce a single unreliable digest. In addition, every individual file
at or below %(consistency_threshold)s is streamed through the engine a
second time after its first hash, and the two digests are compared
directly; a file is only reported as hashed once both digests match
exactly. Files above that size are not re-hashed a second time (to keep
casework speed reasonable), and are counted separately above. Any file
whose two digests failed to match would have been withheld entirely --
it is counted as an error below, not reported with an unverified
digest.</em></p>
 
<h2>Evidence Source Hash</h2>
<table>
    <tr><th>Status</th><td>%(evidence_status)s</td></tr>
    <tr><th>Evidence Size</th><td>%(evidence_size)s</td></tr>
    <tr><th>BLAKE3 Digest</th><td class="digest">%(evidence_digest)s</td></tr>
    <tr><th>SIMD Tier</th><td>%(evidence_simd)s</td></tr>
    <tr><th>Threads Used</th><td>%(evidence_threads)s</td></tr>
    <tr><th>Execution Time (s)</th><td>%(evidence_elapsed)s</td></tr>
    <tr><th>Throughput (MB/s)</th><td>%(evidence_throughput)s</td></tr>
</table>
 
<h2>Individual File Hashing Summary</h2>
<table>
    <tr><th>Files Successfully Hashed</th><td>%(files_hashed)s</td></tr>
    <tr><th>Files With Errors</th><td>%(files_error)s</td></tr>
    <tr><th>Files Skipped</th><td>%(files_skipped)s</td></tr>
    <tr><th>Total Data Hashed</th><td>%(files_bytes_total)s</td></tr>
    <tr><th>Total Hashing Time (cumulative, all files)</th><td>%(files_elapsed_total)s</td></tr>
    <tr><th>Average Throughput (all files)</th><td>%(files_avg_throughput)s</td></tr>
</table>
<p><em>Note: individual files are hashed concurrently on multiple worker
threads, so the cumulative time above is the sum of each file's own
end-to-end time, not the wall-clock duration of the whole job.</em></p>
 
%(skip_rows)s
 
%(error_reason_rows)s
 
%(error_rows)s
 
<div class="footer">
    Generated automatically by %(module_name)s v%(module_version)s
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
        "consistency_threshold": _html_escape(
            _format_bytes(CONSISTENCY_CHECK_MAX_BYTES)
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
 
        self_test = run_engine_self_test(self._sidecar)
 
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
 
        if (
            file.isDir() or
            file.getSize() == 0 or
            not file.getName() or
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
 
            consistency_status = (
                "Not checked (file exceeds " +
                _format_bytes(CONSISTENCY_CHECK_MAX_BYTES) +
                " verification threshold)"
            )
 
            if size_bytes <= CONSISTENCY_CHECK_MAX_BYTES:
 
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
 
        self_test = run_engine_self_test(self._sidecar)
 
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