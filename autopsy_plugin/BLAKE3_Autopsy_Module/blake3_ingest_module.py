# -*- coding: utf-8 -*-
"""Autopsy 4.x / Jython 2.7 ingest bridge for optimized_blake3.py.

Install this file, optimized_blake3_hasher.exe, and the README together in one
Autopsy Python module directory.  The sidecar executable must be built from the
version-controlled optimized_blake3.py source for the complete metric set.

The bridge never reconstructs Java bytes in Python.  It writes Autopsy's Java
byte[] directly to the persistent process OutputStream, validates the exact
byte count, validates the digest format, and records both engine-only and full
Autopsy-to-engine timing scopes.
"""

import datetime
import json
import os
import shutil
import threading
import time
import traceback

from java.io import BufferedReader
from java.io import File as JFile
from java.io import FileInputStream
from java.io import InputStreamReader
from java.awt import Desktop
from java.lang import ProcessBuilder
from java.lang import String as JString
from java.lang import System
from java.security import MessageDigest
from java.util import ArrayList
from java.beans import PropertyChangeListener
from jarray import zeros
from javax.swing import JOptionPane
from javax.swing import SwingUtilities

from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestManager
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData


MODULE_NAME = "Optimized BLAKE3 Hasher"
MODULE_VERSION = "4.2.1"
MODULE_BUILD = "2026-10-08-deferred-artifact-publishing-r1"
KNOWN_EMPTY = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
MAX_REPORT_ROWS = 100000


def _environment_integer(name, default_value, minimum=1):
    try:
        return max(int(minimum), int(os.environ.get(name, str(default_value))))
    except Exception:
        return max(int(minimum), int(default_value))


COMPARISON_SAMPLE_LIMIT = _environment_integer(
    "BLAKE3_COMPARISON_SAMPLE_LIMIT", 10
)
INTEGRITY_SAMPLE_LIMIT = _environment_integer(
    "BLAKE3_INTEGRITY_SAMPLE_LIMIT", 3
)
PERFORMANCE_MIN_BYTES = _environment_integer(
    "BLAKE3_PERFORMANCE_MIN_BYTES", 16 * 1024 * 1024
)
PERFORMANCE_MIN_TOTAL_BYTES = _environment_integer(
    "BLAKE3_PERFORMANCE_MIN_TOTAL_BYTES", 64 * 1024 * 1024
)
COMPARE_EVERY_FILE = (
    os.environ.get("BLAKE3_COMPARE_EVERY_FILE", "1").strip().lower()
    in ("1", "true", "yes", "on")
)
POST_ALL_FILE_ARTIFACTS = (
    os.environ.get("BLAKE3_POST_ALL_FILE_ARTIFACTS", "1").strip().lower()
    in ("1", "true", "yes", "on")
)
EVIDENCE_CACHE_WARMUP = (
    os.environ.get("BLAKE3_EVIDENCE_CACHE_WARMUP", "1").strip().lower()
    not in ("0", "false", "no", "off")
)

# ── Batch IPC tunables ───────────────────────────────────────────────────────
# Number of small files queued per ingest thread before flushing one IPC batch.
# Each ingest thread holds its own queue so total in-flight = BATCH_WINDOW × threads.
BATCH_WINDOW = _environment_integer("BLAKE3_BATCH_WINDOW", 32)
# Files at or above this size bypass the batch queue and use the single-file
# path so they can benefit from native tree parallelism in the sidecar.
# Must match BLAKE3_SMALL_FILE_LIMIT set on the sidecar process.
_SMALL_FILE_LIMIT = _environment_integer(
    "BLAKE3_SMALL_FILE_LIMIT", 32 * 1024 * 1024
)
BATCH_MAX_BYTES = _SMALL_FILE_LIMIT

_JOBS = {}
_JOBS_LOCK = threading.RLock()
_REPORT_LISTENERS = {}


def _new_job(job_id):
    return {
        "job_id": job_id,
        "active_instances": 0,
        "listener_registered": False,
        "report_written": False,
        "pending_artifacts": [],
        "finalizing_sources": [],
        "finalized_sources": [],
        "artifacts_posted": 0,
        "artifact_errors": [],
        "rows": [],
        "rows_omitted": 0,
        "hashed": 0,
        "skipped": 0,
        "errors": 0,
        "bytes": 0,
        "elapsed_ms": 0.0,
        "engine_sha256": "",
        "engine_path": "",
        "self_test": "NOT RUN",
        "module_build": MODULE_BUILD,
        "comparison_samples": {"integrity": {}, "performance": {}},
        "started_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _job(job_id):
    with _JOBS_LOCK:
        if job_id not in _JOBS:
            _JOBS[job_id] = _new_job(job_id)
        return _JOBS[job_id]


def _instance_started(job_id):
    with _JOBS_LOCK:
        _job(job_id)["active_instances"] += 1


def _record(job_id, row):
    with _JOBS_LOCK:
        stats = _job(job_id)
        if row.get("status") == "ok":
            stats["hashed"] += 1
            stats["bytes"] += int(row.get("size_bytes", 0))
            stats["elapsed_ms"] += float(row.get("end_to_end_elapsed_ms", 0.0))
        elif row.get("status") == "skipped":
            stats["skipped"] += 1
        else:
            stats["errors"] += 1
        if len(stats["rows"]) < MAX_REPORT_ROWS:
            stats["rows"].append(row)
        else:
            stats["rows_omitted"] += 1


def _claim_comparison_sample(job_id, category, size_bytes):
    """Select integrity coverage separately from performance-eligible files."""
    if COMPARE_EVERY_FILE:
        return True, int(size_bytes) >= PERFORMANCE_MIN_BYTES
    category = str(category or "Other")
    with _JOBS_LOCK:
        samples = _job(job_id)["comparison_samples"]
        integrity_counts = samples["integrity"]
        performance_counts = samples["performance"]
        integrity_count = int(integrity_counts.get(category, 0))
        performance_count = int(performance_counts.get(category, 0))
        integrity_sample = integrity_count < INTEGRITY_SAMPLE_LIMIT
        performance_sample = (
            int(size_bytes) >= PERFORMANCE_MIN_BYTES
            and performance_count < COMPARISON_SAMPLE_LIMIT
        )
        if integrity_sample:
            integrity_counts[category] = integrity_count + 1
        if performance_sample:
            performance_counts[category] = performance_count + 1
        return integrity_sample, performance_sample


def _instance_finished(job_id):
    should_report = False
    with _JOBS_LOCK:
        stats = _job(job_id)
        stats["active_instances"] = max(0, stats["active_instances"] - 1)
        # Normal data-source ingest is finalized by the Autopsy
        # DATA_SOURCE_ANALYSIS_COMPLETED listener below. This shutdown path is
        # only a fallback for file-only ingest jobs where no data-source module
        # was created.
        if (
            stats["active_instances"] == 0
            and not stats["listener_registered"]
            and not stats["report_written"]
        ):
            stats["report_written"] = True
            should_report = True
    if should_report:
        # No safe completion event was registered. Keep results in the report,
        # but never fall back to database writes from an ingest worker.
        _generate_report(job_id)


class _BLAKE3ReportListener(PropertyChangeListener):
    """Finalize artifacts and report after the matching analysis finishes."""

    def __init__(self, job_id, data_source_id):
        self.job_id = job_id
        self.data_source_id = data_source_id

    def propertyChange(self, event):
        try:
            property_name = str(event.getPropertyName())
            data_source_completed = str(
                IngestManager.IngestJobEvent.DATA_SOURCE_ANALYSIS_COMPLETED.toString()
            )
            job_completed = str(IngestManager.IngestJobEvent.COMPLETED.toString())
            if property_name not in (data_source_completed, job_completed):
                return
            if property_name == data_source_completed:
                try:
                    event_source = event.getDataSource()
                    if (
                        event.getIngestJobId() != self.job_id
                        or event_source.getId() != self.data_source_id
                    ):
                        return
                except Exception:
                    return
                # This event also represents cancellation. Import may still
                # be running in that case, so artifact writes are unsafe.
                if str(event.getResult()) != "ANALYSIS_COMPLETED":
                    return
            else:
                # COMPLETED uses oldValue for the top-level ingest job ID.
                if event.getOldValue() != self.job_id:
                    return
            with _JOBS_LOCK:
                stats = _job(self.job_id)
                if self.data_source_id in stats["finalizing_sources"]:
                    return
                stats["finalizing_sources"].append(self.data_source_id)
            # Keep Autopsy's event publisher free to deliver the blackboard
            # notifications generated by artifact posting.
            worker = threading.Thread(target=self._finalize)
            worker.daemon = True
            worker.start()
        except Exception as exc:
            try:
                IngestServices.getInstance().postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.ERROR,
                        MODULE_NAME,
                        "BLAKE3 report completion listener failed: " + str(exc),
                    )
                )
            except Exception:
                pass

    def _finalize(self):
        try:
            _flush_artifacts(self.job_id, self.data_source_id)
            with _JOBS_LOCK:
                stats = _job(self.job_id)
                stats["finalized_sources"].append(self.data_source_id)
                should_report = (
                    not stats["report_written"]
                    and not stats["pending_artifacts"]
                    and stats["active_instances"] == 0
                    and len(stats["finalized_sources"]) == len(stats["finalizing_sources"])
                )
                if should_report:
                    stats["report_written"] = True
            if should_report:
                _generate_report(self.job_id)
        finally:
            try:
                IngestManager.getInstance().removeIngestJobEventListener(self)
            except Exception:
                pass
            with _JOBS_LOCK:
                _REPORT_LISTENERS.pop((self.job_id, self.data_source_id), None)


def _register_report_listener(job_id, data_source):
    key = (job_id, data_source.getId())
    with _JOBS_LOCK:
        if key in _REPORT_LISTENERS:
            return
        listener = _BLAKE3ReportListener(job_id, data_source.getId())
        IngestManager.getInstance().addIngestJobEventListener(listener)
        _REPORT_LISTENERS[key] = listener
        _job(job_id)["listener_registered"] = True


def _adaptive_buffer(size_bytes):
    """Mirror the sidecar's adaptive_chunk_size with a smooth \u22644\u00d7 ramp.

    Adjacent tiers differ by at most 4\u00d7, eliminating the previous 8\u00d7 jump at
    the old 16 MiB boundary.  Values are kept in sync with the sidecar via the
    shared BLAKE3_SMALL_FILE_LIMIT environment variable.
    """
    if size_bytes < 512 * 1024:
        return 64 * 1024
    if size_bytes < 4 * 1024 * 1024:
        return 256 * 1024
    if size_bytes < _SMALL_FILE_LIMIT:
        return 512 * 1024
    if size_bytes < 128 * 1024 * 1024:
        return 2 * 1024 * 1024
    if size_bytes < 1024 * 1024 * 1024:
        return 8 * 1024 * 1024
    return 16 * 1024 * 1024


def _valid_digest(value, expected_length=64):
    if value is None or len(str(value)) != int(expected_length):
        return False
    try:
        int(str(value), 16)
        return True
    except Exception:
        return False


def _sha256_file(path):
    digest = MessageDigest.getInstance("SHA-256")
    stream = FileInputStream(path)
    buffer = zeros(1024 * 1024, 'b')
    try:
        while True:
            count = stream.read(buffer)
            if count < 0:
                break
            if count:
                digest.update(buffer, 0, count)
    finally:
        stream.close()
    return "".join(["%02x" % (byte_value & 0xFF) for byte_value in digest.digest()])


def _engine_path():
    module_dir = os.path.dirname(os.path.abspath(__file__))
    configured = os.environ.get("BLAKE3_ENGINE_PATH", "").strip()
    candidates = [
        configured,
        os.path.join(module_dir, "optimized_blake3_hasher.exe"),
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    raise IngestModule.IngestModuleException(
        "optimized_blake3_hasher.exe was not found next to blake3_ingest_module.py"
    )


class _Sidecar(object):
    def __init__(self, path):
        self.path = path
        self.process = None
        self.output = None
        self.input = None
        self.restart_count = 0
        self._start()

    def _start(self):
        builder = ProcessBuilder([self.path, "--server"])
        builder.redirectErrorStream(False)
        self.process = builder.start()
        self.output = self.process.getOutputStream()
        self.input = BufferedReader(InputStreamReader(self.process.getInputStream()))

    def _stop(self):
        try:
            if self.output is not None:
                self.output.close()
        except Exception:
            pass
        try:
            if self.input is not None:
                self.input.close()
        except Exception:
            pass
        try:
            if self.process is not None:
                self.process.destroy()
        except Exception:
            pass
        self.output = None
        self.input = None
        self.process = None

    def _restart_and_validate(self):
        """Reset a desynchronized request stream and re-run the known vector."""
        self._stop()
        self._start()
        self.restart_count += 1
        count, result, error = self.hash_content(
            _EmptyContent(), 0, profile="blake3_optimized", _recover=False
        )
        digest = str(result.get("digest", "")).lower() if result else ""
        if (
            error
            or result is None
            or result.get("status") != "ok"
            or digest != KNOWN_EMPTY
        ):
            self._stop()
            raise IOError(error or "restart self-test failed")

    def _failed_request(self, offset, message, recover):
        detail = str(message)
        if recover:
            try:
                self._restart_and_validate()
                detail += "; ENGINE_RESTARTED_AND_SELF_TESTED"
            except Exception as exc:
                detail += "; ENGINE_RESTART_FAILED: " + str(exc)
        return offset, None, detail

    def alive(self):
        try:
            return self.process is not None and self.process.isAlive()
        except Exception:
            return False

    def hash_content(
            self,
            content,
            size_bytes,
            context=None,
            progress=None,
            profile="blake3_optimized",
            _recover=True):
        size_bytes = int(size_bytes)
        chunk_size = _adaptive_buffer(size_bytes)
        buffer = zeros(chunk_size, 'b')
        request = json.dumps({
            "size": size_bytes,
            "profile": str(profile),
        })
        header = JString(request + "\n").getBytes("US-ASCII")
        offset = 0
        try:
            self.output.write(header)
            while offset < size_bytes:
                if context is not None:
                    try:
                        if context.isJobCancelled():
                            return self._failed_request(
                                offset, "CANCELLED", _recover
                            )
                    except Exception:
                        pass
                requested = min(chunk_size, size_bytes - offset)
                count = content.read(buffer, offset, requested)
                if count <= 0:
                    break
                self.output.write(buffer, 0, count)
                offset += count
                if progress is not None:
                    progress(offset, size_bytes)
        except Exception as exc:
            return self._failed_request(
                offset, "AUTOPSY_STREAM_IO_ERROR: " + str(exc), _recover
            )
        if offset != size_bytes:
            return self._failed_request(
                offset,
                "SHORT_READ (%d of %d bytes)" % (offset, size_bytes),
                _recover,
            )
        try:
            self.output.flush()
            line = self.input.readLine()
        except Exception as exc:
            return self._failed_request(
                offset, "ENGINE_RESPONSE_IO_ERROR: " + str(exc), _recover
            )
        if not line:
            return self._failed_request(offset, "NO_ENGINE_RESPONSE", _recover)
        try:
            return offset, json.loads(str(line)), None
        except Exception:
            return self._failed_request(offset, "INVALID_ENGINE_RESPONSE", _recover)

    def self_test(self):
        count, result, error = self.hash_content(_EmptyContent(), 0)
        if error or result is None:
            return False, error or "no result"
        digest = str(result.get("digest", "")).lower()
        if result.get("status") != "ok" or digest != KNOWN_EMPTY:
            return False, "empty-input published vector mismatch"
        return True, "published empty-input vector passed"

    def batch_self_test(self):
        """Verify the sidecar actually understands the batch wire protocol
        ({"batch": M, "requests": [...]}) before any real evidence is queued
        through it.

        A sidecar exe built from a pre-batching optimized_blake3.py doesn't
        recognize the "batch" key, raises inside its own request parser on
        the first real batch, and desyncs this persistent connection for the
        rest of the job -- corrupting every file processed afterward,
        including the evidence-source and comparison passes the HTML report
        depends on. There is no reliable way to detect that after the fact,
        so this sends one deterministic, throwaway batch request up front and
        fails loudly if the sidecar doesn't answer it correctly.
        """
        try:
            results = self.hash_batch(
                [(_EmptyContent(), 0, "blake3_optimized")],
                context=None,
                _recover=False,
            )
        except Exception as exc:
            return False, "batch protocol probe raised an exception: " + str(exc)
        if len(results) != 1:
            return False, (
                "batch protocol probe returned %d result line(s) for 1 "
                "request; the sidecar does not speak the batch protocol"
                % len(results)
            )
        actual, result, error = results[0]
        digest = str(result.get("digest", "")).lower() if result else ""
        if error or result is None or result.get("status") != "ok" or digest != KNOWN_EMPTY:
            return False, (
                "batch protocol probe failed (%s); the sidecar was likely "
                "built before batching was added to optimized_blake3.py"
                % (error or (result.get("message") if result else "no result"))
            )
        # Even a passing probe leaves no guarantee the connection is clean if
        # anything upstream partially desynced it; force a fresh, validated
        # connection before any real evidence work begins.
        try:
            self._restart_and_validate()
        except Exception as exc:
            return False, "sidecar restart after batch probe failed: " + str(exc)
        return True, "batch protocol probe passed"

    def hash_batch(self, items, context=None, _recover=True):
        """Hash multiple files in a single IPC round-trip.

        Parameters
        ----------
        items : list of (content, size_bytes, profile)
            Each ``content`` must support the Autopsy AbstractFile.read()
            interface.  ``size_bytes`` is the declared byte count.

        Returns
        -------
        list of (actual_bytes_read, result_dict_or_None, error_string_or_None)
            One tuple per input item in the same order as ``items``.
        """
        if not items:
            return []

        # ── 1. Build and send the batch header ──────────────────────────────
        requests_meta = [
            {"size": int(sz), "profile": str(prof)}
            for (_, sz, prof) in items
        ]
        batch_header = json.dumps({
            "batch": len(items),
            "requests": requests_meta,
        })
        header_bytes = JString(batch_header + "\n").getBytes("US-ASCII")
        try:
            self.output.write(header_bytes)
        except Exception as exc:
            err = "BATCH_HEADER_IO_ERROR: " + str(exc)
            if _recover:
                try:
                    self._restart_and_validate()
                    err += "; ENGINE_RESTARTED_AND_SELF_TESTED"
                except Exception as re:
                    err += "; ENGINE_RESTART_FAILED: " + str(re)
            return [(0, None, err)] * len(items)

        # ── 2. Stream all file bytes back-to-back ────────────────────────────
        offsets = []
        errors = []
        desync = False
        for (content, size_bytes, profile) in items:
            size_bytes = int(size_bytes)
            chunk_size = _adaptive_buffer(size_bytes)
            buffer = zeros(chunk_size, 'b')
            offset = 0
            item_error = None

            if desync:
                # After a mid-batch send failure the pipe is desynchronised;
                # mark all remaining items without trying to read results.
                offsets.append(0)
                errors.append("BATCH_DESYNC_BEFORE_SEND")
                continue

            try:
                while offset < size_bytes:
                    if context is not None:
                        try:
                            if context.isJobCancelled():
                                item_error = "CANCELLED"
                                desync = True
                                break
                        except Exception:
                            pass
                    requested = min(chunk_size, size_bytes - offset)
                    count = content.read(buffer, offset, requested)
                    if count <= 0:
                        break
                    self.output.write(buffer, 0, count)
                    offset += count
            except Exception as exc:
                item_error = "AUTOPSY_STREAM_IO_ERROR: " + str(exc)
                desync = True

            if item_error is None and offset != size_bytes:
                item_error = "SHORT_READ (%d of %d bytes)" % (offset, size_bytes)
                desync = True

            offsets.append(offset)
            errors.append(item_error)

        # ── 3. Flush once for the entire batch ───────────────────────────────
        try:
            self.output.flush()
        except Exception as exc:
            err = "BATCH_FLUSH_IO_ERROR: " + str(exc)
            return [
                (offsets[i] if i < len(offsets) else 0, None,
                 errors[i] if (i < len(errors) and errors[i]) else err)
                for i in range(len(items))
            ]

        # ── 4. Read N result lines (sidecar writes them all before flushing) ─
        results = []
        for i in range(len(items)):
            actual = offsets[i] if i < len(offsets) else 0
            send_error = errors[i] if i < len(errors) else "BATCH_SEND_INCOMPLETE"

            if send_error:
                # Pipe is desynchronised; restart once then mark all remaining.
                if _recover:
                    try:
                        self._restart_and_validate()
                        send_error += "; ENGINE_RESTARTED_AND_SELF_TESTED"
                    except Exception as re:
                        send_error += "; ENGINE_RESTART_FAILED: " + str(re)
                    _recover = False  # restart only once per batch
                results.append((actual, None, send_error))
                for j in range(i + 1, len(items)):
                    results.append((0, None, "BATCH_DESYNC_AFTER_ITEM_%d" % i))
                return results

            try:
                line = self.input.readLine()
            except Exception as exc:
                read_err = "ENGINE_RESPONSE_IO_ERROR: " + str(exc)
                if _recover:
                    try:
                        self._restart_and_validate()
                        read_err += "; ENGINE_RESTARTED_AND_SELF_TESTED"
                    except Exception as re:
                        read_err += "; ENGINE_RESTART_FAILED: " + str(re)
                results.append((actual, None, read_err))
                for j in range(i + 1, len(items)):
                    results.append((0, None, "BATCH_DESYNC_AFTER_ITEM_%d" % i))
                return results

            if not line:
                results.append((actual, None, "NO_ENGINE_RESPONSE"))
                for j in range(i + 1, len(items)):
                    results.append((0, None, "BATCH_DESYNC_AFTER_ITEM_%d" % i))
                return results

            try:
                results.append((actual, json.loads(str(line)), None))
            except Exception:
                results.append((actual, None, "INVALID_ENGINE_RESPONSE"))

        return results

    def close(self):
        self._stop()


class _EmptyContent(object):
    def read(self, buffer, offset, requested):
        return -1


def _baseline_hashes(file_obj):
    result = {"md5": "", "sha1": "", "sha256": ""}
    methods = {
        "md5": "getMd5Hash",
        "sha1": "getSha1Hash",
        "sha256": "getSha256Hash",
    }
    for name, method_name in methods.items():
        try:
            value = getattr(file_obj, method_name)()
            if value:
                result[name] = str(value)
        except Exception:
            pass
    return result


def _attach_autopsy_hash_checks(row, file_obj):
    """Record digest agreement with hashes already stored by Autopsy."""
    autopsy_hashes = _baseline_hashes(file_obj)
    for name in ("md5", "sha1", "sha256"):
        autopsy_digest = str(autopsy_hashes.get(name, "") or "").lower()
        measured_digest = str(row.get(name, "") or "").lower()
        row["autopsy_" + name] = autopsy_digest
        row[name + "_matches_autopsy"] = (
            measured_digest == autopsy_digest
            if measured_digest and autopsy_digest else None
        )


def _refresh_autopsy_hash_checks(rows):
    """Refresh stored-hash comparisons when the completion report is built."""
    try:
        sleuthkit_case = Case.getCurrentCase().getSleuthkitCase()
    except Exception:
        return
    for row in rows:
        if row.get("source_kind") != "File" or not row.get("object_id"):
            continue
        try:
            file_obj = sleuthkit_case.getAbstractFileById(int(row["object_id"]))
            if file_obj is not None:
                _attach_autopsy_hash_checks(row, file_obj)
        except Exception:
            pass


def _category(name):
    raw_name = str(name or "")
    basename = os.path.basename(raw_name)
    # Strip common Autopsy-appended suffixes (slack space copies, ADS
    # streams) so the underlying artifact name can still be recognized.
    metadata_stem = basename.split("-slack", 1)[0].split(":", 1)[0].strip()
    extension = os.path.splitext(raw_name)[1].lower()

    # NTFS / exFAT / FAT filesystem metadata and other synthetic
    # filesystem-internal objects (e.g. $MFT, $Bitmap, $UpCase,
    # $ALLOC_BITMAP, and their slack-space copies) carry no conventional
    # extension and would otherwise all collapse into "Other". Recognizing
    # them by name keeps that bucket meaningful.
    filesystem_metadata_names = (
        "$MFT", "$MFTMIRR", "$LOGFILE", "$VOLUME", "$ATTRDEF", "$BITMAP",
        "$BOOT", "$BADCLUS", "$SECURE", "$UPCASE", "$UPCASE_TABLE",
        "$EXTEND", "$QUOTA", "$OBJID", "$REPARSE", "$USNJRNL", "$TXF_DATA",
        "$ALLOC_BITMAP", "$UNALLOC", "$ROOT", "$FAT1", "$FAT2",
        "$ORPHANFILES", "$DIRECTORY", "$I30",
    )
    if metadata_stem.startswith("$") or metadata_stem.upper() in filesystem_metadata_names:
        return "Filesystem Metadata"

    # OS paging/hibernation files: not user documents, and worth their own
    # bucket rather than falling into "Other" or "System & Logs" noise.
    if basename.lower() in ("pagefile.sys", "hiberfil.sys", "swapfile.sys"):
        return "OS Paging & Hibernation"

    categories = [
        ("Documents", (
            ".pdf", ".docx", ".doc", ".rtf", ".odt", ".txt", ".md",
            ".xls", ".xlsx", ".ods", ".csv", ".tsv",
            ".ppt", ".pptx", ".odp", ".pages", ".numbers",
        )),
        ("Images", (
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff",
            ".webp", ".heic", ".heif", ".svg", ".ico", ".raw", ".cr2",
            ".nef", ".arw", ".psd",
        )),
        ("Audio", (
            ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a",
            ".aiff", ".opus", ".mid", ".midi",
        )),
        ("Video", (
            ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
            ".m4v", ".mpg", ".mpeg", ".3gp", ".ts",
        )),
        ("Archives", (
            ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2",
            ".xz", ".cab", ".ace", ".arj", ".z",
        )),
        ("Executables & Installers", (
            ".exe", ".elf", ".dll", ".so", ".dylib", ".bin", ".msi",
            ".bat", ".cmd", ".sh", ".app", ".apk", ".ipa", ".jar",
            ".com", ".scr",
        )),
        ("Disk & Forensic Images", (
            ".dd", ".e01", ".ex01", ".l01", ".lx01", ".vmdk", ".vhd",
            ".vhdx", ".img", ".iso", ".ad1", ".aff", ".raw",
        )),
        ("Databases", (
            ".db", ".sqlite", ".sqlite3", ".sqlitedb", ".mdb", ".accdb",
            ".dbf",
        )),
        ("Email & Messaging", (
            ".pst", ".ost", ".eml", ".msg", ".mbox", ".edb",
        )),
        ("Web, Code & Scripts", (
            ".html", ".htm", ".xml", ".json", ".js", ".css", ".py",
            ".java", ".c", ".cpp", ".h", ".php", ".rb", ".ps1",
        )),
        ("System & Logs", (
            ".log", ".ini", ".cfg", ".conf", ".reg", ".plist", ".sys",
            ".dat", ".evtx", ".evt",
        )),
        ("Fonts", (
            ".ttf", ".otf", ".woff", ".woff2",
        )),
        ("Certificates & Keys", (
            ".pem", ".crt", ".cer", ".pfx", ".p12", ".key",
        )),
    ]
    for label, extensions in categories:
        if extension in extensions:
            return label
    return "Other"


def _get_artifact_type(blackboard):
    try:
        return blackboard.getOrAddArtifactType(
            "BLAKE3_HASH_RESULT_V4", "BLAKE3 Hash (Optimized)"
        )
    except Exception:
        return blackboard.getArtifactType("BLAKE3_HASH_RESULT_V4")


def _attribute(blackboard, name, display, value):
    try:
        attribute_type = blackboard.getOrAddAttributeType(
            name,
            BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
            display,
        )
    except Exception:
        attribute_type = blackboard.getAttributeType(name)
    return BlackboardAttribute(attribute_type, MODULE_NAME, str(value))


def _post_artifact(blackboard, content, row):
    artifact_type = _get_artifact_type(blackboard)
    cpu_value = row.get("cpu_utilization_percent", "N/A")
    rss_value = row.get("peak_rss_mb", "N/A")
    values = [
        ("BLAKE3_V4_DIGEST", "BLAKE3 Hash Digest", row.get("digest", "")),
        ("BLAKE3_V4_SIZE", "File Size", _format_bytes(row.get("size_bytes", 0))),
        ("BLAKE3_V4_E2E_MS", "End-to-End Time", _format_ms(row.get("end_to_end_elapsed_ms", ""))),
        ("BLAKE3_V4_ENGINE_MS", "Engine Time", _format_ms(row.get("engine_elapsed_ms", ""))),
        ("BLAKE3_V4_MBPS", "End-to-End Throughput", _format_rate(row.get("throughput_mb_s", ""))),
        ("BLAKE3_V4_CPU", "Engine CPU Utilization", _format_percent(cpu_value) if str(cpu_value) not in ("N/A", "", "None") else "N/A"),
        ("BLAKE3_V4_RSS", "Engine Peak Memory", _format_mib(rss_value) if str(rss_value) not in ("N/A", "", "None") else "N/A"),
        ("BLAKE3_V4_SIMD", "SIMD Dispatch", row.get("simd_tier", "")),
        ("BLAKE3_V4_THREADS", "Maximum Native Cores", row.get("threads_used", "")),
        ("BLAKE3_V4_IO", "Engine I/O Strategy", row.get("io_strategy", "streamed IPC")),
        ("BLAKE3_V4_CATEGORY", "Evidence Category", row.get("category", "Other")),
    ]
    attributes = ArrayList()
    for name, display, value in values:
        attributes.add(_attribute(blackboard, name, display, value))
    artifact = content.newArtifact(artifact_type.getTypeID())
    artifact.addAttributes(attributes)
    blackboard.postArtifact(artifact, MODULE_NAME)


def _queue_artifact(job_id, data_source_id, blackboard, content, row):
    """Retain results without acquiring any Autopsy database write locks.

    In Autopsy 4.22.1, newArtifact during streaming image import can deadlock
    the case write lock against the has-children cache lock. Only the matching
    analysis-completed listener may drain this queue.
    """
    with _JOBS_LOCK:
        _job(job_id)["pending_artifacts"].append(
            (data_source_id, blackboard, content, row)
        )


def _audit_stats(stats):
    """Exclude runtime Java handles from the JSON audit representation."""
    audit = dict(stats)
    audit["pending_artifact_count"] = len(audit.pop("pending_artifacts", []))
    return audit


def _flush_artifacts(job_id, data_source_id):
    """Publish after analysis, outside both ingest workers and _JOBS_LOCK."""
    with _JOBS_LOCK:
        stats = _job(job_id)
        pending = [item for item in stats["pending_artifacts"]
                   if item[0] == data_source_id]
        stats["pending_artifacts"] = [item for item in stats["pending_artifacts"]
                                      if item[0] != data_source_id]
    for unused_source_id, blackboard, content, row in pending:
        try:
            _post_artifact(blackboard, content, row)
            with _JOBS_LOCK:
                stats["artifacts_posted"] += 1
        except Exception as exc:
            error = {"object_id": row.get("object_id"), "error": str(exc)}
            with _JOBS_LOCK:
                stats["artifact_errors"].append(error)
    if stats["artifact_errors"]:
        IngestServices.getInstance().postMessage(IngestMessage.createMessage(
            IngestMessage.MessageType.WARNING,
            MODULE_NAME,
            "%d BLAKE3 case artifact(s) could not be published. "
            "Hash results are retained in the report audit data."
            % len(stats["artifact_errors"]),
        ))


def _safe_name(content):
    try:
        return str(content.getName())
    except Exception:
        return "unknown"


def _hash_one(
        sidecar,
        content,
        size_bytes,
        context,
        source_kind,
        progress=None,
        profile="blake3_optimized"):
    started_ns = System.nanoTime()
    actual, result, bridge_error = sidecar.hash_content(
        content,
        size_bytes,
        context=context,
        progress=progress,
        profile=profile,
    )
    elapsed_ms = max(0.0, (System.nanoTime() - started_ns) / 1000000.0)
    name = _safe_name(content)
    base = {
        "name": name,
        "source_kind": source_kind,
        "category": _category(name),
        "size_bytes": int(size_bytes),
        "bytes_read": int(actual),
        "end_to_end_elapsed_ms": round(elapsed_ms, 3),
        "throughput_mb_s": round(
            (float(size_bytes) / (1024.0 * 1024.0)) / (elapsed_ms / 1000.0), 3
        ) if elapsed_ms > 0.0 else 0.0,
    }
    try:
        base["object_id"] = int(content.getId())
    except Exception:
        pass
    if bridge_error:
        if str(bridge_error).startswith("SHORT_READ"):
            base.update({
                "status": "skipped",
                "error": bridge_error,
                "reason": (
                    "Autopsy returned fewer bytes than the declared content size; "
                    "no digest was accepted"
                ),
                "digest": "",
            })
        else:
            base.update({"status": "error", "error": bridge_error, "digest": ""})
        return base
    if result is None or result.get("status") != "ok":
        base.update({
            "status": "error",
            "error": str(result.get("message", "engine error")) if result else "engine error",
            "digest": "",
        })
        return base
    digest = str(result.get("digest", ""))
    expected_lengths = {
        "md5": 32,
        "sha1": 40,
        "sha256": 64,
        "blake3_baseline": 64,
        "blake3_optimized": 64,
    }
    if (
        actual != int(size_bytes)
        or not _valid_digest(digest, expected_lengths.get(profile, 64))
    ):
        base.update({"status": "error", "error": "byte-count/digest validation failed", "digest": ""})
        return base
    base.update({
        "status": "ok",
        "error": "",
        "digest": digest.lower(),
        "engine_elapsed_ms": result.get(
            "elapsed_ms", float(result.get("elapsed_s", 0.0)) * 1000.0
        ),
        "engine_throughput_mb_s": result.get("throughput_mb_s", ""),
        "cpu_utilization_percent": result.get("cpu_utilization_percent", "N/A"),
        "process_cpu_percent": result.get("process_cpu_percent", "N/A"),
        "peak_rss_mb": result.get("peak_rss_mb", "N/A"),
        "simd_tier": result.get("simd_tier", "native runtime dispatch"),
        "threads_used": result.get("threads_used", ""),
        "io_strategy": result.get("io_strategy", "Autopsy streamed IPC"),
        "chunk_size": result.get("chunk_size", _adaptive_buffer(size_bytes)),
        "backend": result.get("backend", "packaged native sidecar"),
        "backend_version": result.get("backend_version", "legacy package metadata unavailable"),
        "algorithm": result.get("algorithm", "BLAKE3"),
        "profile": result.get("profile", profile),
    })
    return base


def _comparison_hashes(
        sidecar,
        content,
        size_bytes,
        context,
        optimized_digest,
        progress_factory=None):
    """Run independent full-pass thesis comparison profiles."""
    comparisons = {}
    profiles = (
        ("baseline_blake3", "blake3_baseline"),
        ("md5", "md5"),
        ("sha1", "sha1"),
        ("sha256", "sha256"),
    )
    for index, (prefix, profile) in enumerate(profiles):
        progress = progress_factory(index, len(profiles)) if progress_factory else None
        row = _hash_one(
            sidecar,
            content,
            size_bytes,
            context,
            "Comparison",
            progress=progress,
            profile=profile,
        )
        comparisons[prefix + "_status"] = row.get("status", "error")
        comparisons[prefix + "_error"] = row.get("error", "")
        comparisons[prefix + "_digest"] = row.get("digest", "")
        comparisons[prefix + "_elapsed_ms"] = row.get("end_to_end_elapsed_ms", "")
        comparisons[prefix + "_throughput_mb_s"] = row.get("throughput_mb_s", "")
        comparisons[prefix + "_cpu_utilization_percent"] = row.get(
            "cpu_utilization_percent", "N/A"
        )
        comparisons[prefix + "_peak_rss_mb"] = row.get("peak_rss_mb", "N/A")
        comparisons[prefix + "_bytes_read"] = row.get("bytes_read", 0)
        comparisons[prefix + "_backend"] = row.get("backend", "")
        comparisons[prefix + "_profile"] = row.get("profile", profile)
        if row.get("status") != "ok" and row.get("error") == "CANCELLED":
            break
    baseline_digest = str(comparisons.get("baseline_blake3_digest", ""))
    comparisons["baseline_blake3_matches"] = bool(
        baseline_digest
        and optimized_digest
        and baseline_digest.lower() == str(optimized_digest).lower()
    )
    return comparisons


class BLAKE3IngestModuleFactory(IngestModuleFactoryAdapter):
    def getModuleDisplayName(self):
        return MODULE_NAME

    def getModuleDescription(self):
        return (
            "Standards-compliant native BLAKE3 hashing with exact byte-count "
            "validation, adaptive Autopsy streaming, SIMD runtime dispatch, "
            "independent Baseline BLAKE3/MD5/SHA-1/SHA-256 comparison passes, "
            "precision metrics, and an automatic HTML/JSON audit report. "
            "Build: " + MODULE_BUILD
        )

    def getModuleVersionNumber(self):
        return MODULE_VERSION

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return BLAKE3FileIngestModule()

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return BLAKE3DataSourceIngestModule()


def _startup_module(module, context):
    module.context = context
    module.job_id = context.getJobId()
    module.services = IngestServices.getInstance()
    current_case = Case.getCurrentCase()
    module.blackboard = current_case.getSleuthkitCase().getBlackboard()
    module.data_source_id = context.getDataSource().getId()
    # Register before any file is processed, including file-only ingest jobs.
    _register_report_listener(module.job_id, context.getDataSource())
    module.engine_path = _engine_path()
    module.sidecar = _Sidecar(module.engine_path)
    passed, message = module.sidecar.self_test()
    if not passed:
        module.sidecar.close()
        raise IngestModule.IngestModuleException(
            "BLAKE3 engine published-vector self-test failed: " + message
        )
    batch_passed, batch_message = module.sidecar.batch_self_test()
    if not batch_passed:
        module.sidecar.close()
        raise IngestModule.IngestModuleException(
            "BLAKE3 sidecar does not support the batch IPC protocol used by "
            "this ingest module (" + batch_message + "). Rebuild "
            "optimized_blake3_hasher.exe from the current optimized_blake3.py "
            "via build_sidecar.ps1 and replace it next to "
            "blake3_ingest_module.py, then re-run ingest."
        )
    with _JOBS_LOCK:
        stats = _job(module.job_id)
        stats["engine_path"] = module.engine_path
        stats["engine_sha256"] = _sha256_file(module.engine_path)
        stats["self_test"] = "PASSED: " + message
        stats["batch_self_test"] = "PASSED: " + batch_message
    _instance_started(module.job_id)


def _shutdown_module(module):
    if getattr(module, "sidecar", None) is not None:
        module.sidecar.close()
    if getattr(module, "job_id", None) is not None:
        _instance_finished(module.job_id)


class BLAKE3FileIngestModule(FileIngestModule):
    def __init__(self):
        self.context = None
        self.sidecar = None
        self.job_id = None
        # Per-instance pending-batch queue (each Autopsy ingest thread gets its
        # own module instance, so no cross-thread sharing occurs here).
        self._batch_queue = []

    def startUp(self, context):
        _startup_module(self, context)
        self._batch_queue = []

    def process(self, file_obj):
        try:
            file_type = file_obj.getType()
            skip_reason = None
            if file_obj.isDir():
                skip_reason = (
                    "Directory entry: represents a folder in the filesystem "
                    "tree, not file content, so there are no bytes to hash."
                )
            elif file_type == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS:
                skip_reason = (
                    "Unallocated space block file: a synthetic Autopsy object "
                    "representing free/deleted space on the volume rather "
                    "than a real, recovered file."
                )
            elif file_type == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS:
                skip_reason = (
                    "Unused space block file: a synthetic Autopsy object "
                    "representing reserved-but-unused space on the volume "
                    "rather than a real, recovered file."
                )
            if skip_reason is not None:
                _record(self.job_id, {
                    "status": "skipped",
                    "name": _safe_name(file_obj),
                    "source_kind": "File",
                    "category": _category(_safe_name(file_obj)),
                    "size_bytes": int(file_obj.getSize()),
                    "reason": skip_reason,
                })
                return IngestModule.ProcessResult.OK

            size_bytes = int(file_obj.getSize())

            # Large files bypass the batch queue: they benefit from native tree
            # parallelism inside the sidecar, which works best one file at a time.
            if size_bytes >= BATCH_MAX_BYTES:
                row = _hash_one(
                    self.sidecar, file_obj, size_bytes, self.context, "File"
                )
                self._post_file_row(row, file_obj)
                return IngestModule.ProcessResult.OK

            # Accumulate small files into the batch queue.
            self._batch_queue.append(file_obj)
            if len(self._batch_queue) >= BATCH_WINDOW:
                pending = self._batch_queue
                self._batch_queue = []
                self._flush_batch(pending)

        except Exception as exc:
            _record(self.job_id, {
                "status": "error",
                "name": _safe_name(file_obj),
                "source_kind": "File",
                "category": _category(_safe_name(file_obj)),
                "size_bytes": int(file_obj.getSize()),
                "error": str(exc),
            })
        return IngestModule.ProcessResult.OK

    def _flush_batch(self, pending):
        """Send a window of small files to the sidecar in one IPC burst."""
        items = [
            (f, int(f.getSize()), "blake3_optimized")
            for f in pending
        ]
        batch_started_ns = System.nanoTime()
        batch_results = self.sidecar.hash_batch(items, context=self.context)
        batch_elapsed_ms = max(
            0.0, (System.nanoTime() - batch_started_ns) / 1000000.0
        )

        # There is only one measured round trip for the whole batch, not one
        # per file. Every total in _generate_report (the Executive Summary
        # "Hashing Speed" figure, every row of the Speed Comparison table, and
        # stats["elapsed_ms"] in _record) sums end_to_end_elapsed_ms across
        # every "ok" file and assumes that sum is meaningful. Leaving it at a
        # flat 0.0 per file didn't raise anything by itself -- every division
        # against it is already guarded -- but it silently broke that
        # invariant: files still added their full size_bytes to every total
        # while contributing 0 ms, so aggregate throughput/timing figures
        # became wrong (usually driven toward 0.00 MiB/s, or wildly inflated
        # if only a few non-batched files carried the whole job's timing) as
        # soon as batching handled any meaningful share of a job. Instead,
        # distribute the one measured round trip across the batch's files
        # proportional to bytes actually transferred, so each row -- and every
        # total derived from it -- carries a real, additive timing figure.
        total_actual_bytes = sum(
            max(0, int(batch_item[0])) for batch_item in batch_results
        )

        for file_obj, batch_item in zip(pending, batch_results):
            actual, engine_result, bridge_error = batch_item
            size_bytes = int(file_obj.getSize())
            name = _safe_name(file_obj)

            if total_actual_bytes > 0:
                item_elapsed_ms = batch_elapsed_ms * (
                    max(0, int(actual)) / float(total_actual_bytes)
                )
            elif batch_results:
                item_elapsed_ms = batch_elapsed_ms / float(len(batch_results))
            else:
                item_elapsed_ms = 0.0
            item_throughput = (
                (float(size_bytes) / (1024.0 * 1024.0)) / (item_elapsed_ms / 1000.0)
                if item_elapsed_ms > 0.0 else 0.0
            )

            base = {
                "name": name,
                "source_kind": "File",
                "category": _category(name),
                "size_bytes": size_bytes,
                "bytes_read": int(actual),
                # Distributed from one measured batch round trip, not
                # individually timed -- see batch_elapsed_ms/batch_item_count
                # on this row for the true measurement it was derived from.
                "end_to_end_elapsed_ms": round(item_elapsed_ms, 3),
                "throughput_mb_s": round(item_throughput, 3),
                "batch_mode": True,
                "batch_elapsed_ms": round(batch_elapsed_ms, 3),
                "batch_item_count": len(batch_results),
            }
            try:
                base["object_id"] = int(file_obj.getId())
            except Exception:
                pass

            if bridge_error:
                if str(bridge_error).startswith("SHORT_READ"):
                    base.update({
                        "status": "skipped",
                        "error": bridge_error,
                        "reason": (
                            "Autopsy returned fewer bytes than the declared "
                            "content size; no digest was accepted"
                        ),
                        "digest": "",
                    })
                else:
                    base.update({"status": "error", "error": bridge_error, "digest": ""})
                _record(self.job_id, base)
                continue

            if engine_result is None or engine_result.get("status") != "ok":
                base.update({
                    "status": "error",
                    "error": str(engine_result.get("message", "engine error"))
                    if engine_result else "engine error",
                    "digest": "",
                })
                _record(self.job_id, base)
                continue

            digest = str(engine_result.get("digest", ""))
            if actual != size_bytes or not _valid_digest(digest, 64):
                base.update({
                    "status": "error",
                    "error": "byte-count/digest validation failed",
                    "digest": "",
                })
                _record(self.job_id, base)
                continue

            base.update({
                "status": "ok",
                "error": "",
                "digest": digest.lower(),
                "engine_elapsed_ms": engine_result.get("elapsed_ms", 0.0),
                "engine_throughput_mb_s": engine_result.get("throughput_mb_s", ""),
                "cpu_utilization_percent": engine_result.get("cpu_utilization_percent", "N/A"),
                "process_cpu_percent": engine_result.get("process_cpu_percent", "N/A"),
                "peak_rss_mb": engine_result.get("peak_rss_mb", "N/A"),
                "simd_tier": engine_result.get("simd_tier", "native runtime dispatch"),
                "threads_used": engine_result.get("threads_used", ""),
                "io_strategy": engine_result.get("io_strategy", "Autopsy batched IPC"),
                "chunk_size": engine_result.get("chunk_size", _adaptive_buffer(size_bytes)),
                "backend": engine_result.get("backend", "packaged native sidecar"),
                "backend_version": engine_result.get("backend_version", ""),
                "algorithm": engine_result.get("algorithm", "BLAKE3"),
                "profile": engine_result.get("profile", "blake3_optimized"),
            })
            self._post_file_row(base, file_obj)

    def _post_file_row(self, row, file_obj):
        """Run comparison hashes, attach Autopsy checks, post artifact, record row.

        This is the original post-hashing logic extracted into a helper so both
        the single-file path and the batch-flush path share the same code.
        """
        if row["status"] == "ok":
            integrity_sample, performance_sample = _claim_comparison_sample(
                self.job_id,
                row.get("category", "Other"),
                row.get("size_bytes", 0),
            )
            run_comparison = integrity_sample or performance_sample
            row["comparison_integrity_sample"] = bool(integrity_sample)
            row["comparison_performance_sample"] = bool(performance_sample)
            row["comparison_scope"] = (
                "all-files" if COMPARE_EVERY_FILE else (
                    "integrity+performance" if integrity_sample and performance_sample else (
                        "performance" if performance_sample else (
                            "integrity" if integrity_sample else "optimized-only"
                        )
                    )
                )
            )
            if run_comparison:
                comparison = _comparison_hashes(
                    self.sidecar,
                    file_obj,
                    int(file_obj.getSize()),
                    self.context,
                    row.get("digest", ""),
                )
                row.update(comparison)
                row["md5"] = comparison.get("md5_digest", "")
                row["sha1"] = comparison.get("sha1_digest", "")
                row["sha256"] = comparison.get("sha256_digest", "")
            _attach_autopsy_hash_checks(row, file_obj)
            if (
                run_comparison
                and row.get("baseline_blake3_status") == "ok"
                and not row.get("baseline_blake3_matches")
            ):
                row["status"] = "error"
                row["error"] = "BASELINE_BLAKE3_DIGEST_MISMATCH"

        _record(self.job_id, row)
        if row["status"] == "ok":
            if POST_ALL_FILE_ARTIFACTS or row.get("comparison_scope") != "optimized-only":
                _queue_artifact(
                    self.job_id, self.data_source_id, self.blackboard, file_obj, row
                )
        elif row["status"] == "error":
            self.services.postMessage(IngestMessage.createMessage(
                IngestMessage.MessageType.ERROR,
                MODULE_NAME,
                "BLAKE3 failed for %s: %s" % (row["name"], row.get("error", "")),
            ))

    def shutDown(self):
        # Flush any partial batch before the sidecar process is closed.
        if self._batch_queue:
            remaining = self._batch_queue
            self._batch_queue = []
            try:
                self._flush_batch(remaining)
            except Exception:
                pass
        _shutdown_module(self)


class BLAKE3DataSourceIngestModule(DataSourceIngestModule):
    def __init__(self):
        self.context = None
        self.sidecar = None
        self.job_id = None

    def startUp(self, context):
        _startup_module(self, context)

    def process(self, data_source, progress_bar):
        try:
            try:
                _register_report_listener(self.job_id, data_source)
            except Exception as exc:
                self.services.postMessage(IngestMessage.createMessage(
                    IngestMessage.MessageType.WARNING,
                    MODULE_NAME,
                    "Could not register automatic report completion listener: " + str(exc),
                ))
            try:
                progress_bar.switchToDeterminate(100)
            except Exception:
                pass

            phase_count = 6 if EVIDENCE_CACHE_WARMUP else 5

            def phase_progress(phase_index):
                def progress(done, total):
                    if total:
                        try:
                            fraction = float(done) / float(total)
                            percent = int(
                                ((float(phase_index) + fraction) / float(phase_count))
                                * 100.0
                            )
                            progress_bar.progress(min(100, max(0, percent)))
                        except Exception:
                            pass
                return progress

            measured_phase = 0
            warmup = None
            if EVIDENCE_CACHE_WARMUP:
                warmup = _hash_one(
                    self.sidecar,
                    data_source,
                    int(data_source.getSize()),
                    self.context,
                    "Evidence source warm-up",
                    phase_progress(0),
                )
                measured_phase = 1
            if warmup is not None and warmup.get("status") != "ok":
                row = warmup
                row["source_kind"] = "Evidence source"
                row["error"] = "CACHE_WARMUP_FAILED: " + str(
                    warmup.get("error", "unknown error")
                )
            else:
                row = _hash_one(
                    self.sidecar,
                    data_source,
                    int(data_source.getSize()),
                    self.context,
                    "Evidence source",
                    phase_progress(measured_phase),
                )
                if warmup is not None:
                    row["cache_control"] = "one complete unmeasured warm-up pass"
                    row["warmup_elapsed_ms"] = warmup.get("end_to_end_elapsed_ms", "")
                    row["warmup_digest_matches"] = bool(
                        row.get("digest")
                        and warmup.get("digest")
                        and str(row.get("digest")).lower()
                        == str(warmup.get("digest")).lower()
                    )
                    if row.get("status") == "ok" and not row["warmup_digest_matches"]:
                        row["status"] = "error"
                        row["error"] = "WARMUP_BLAKE3_DIGEST_MISMATCH"
            if row["status"] == "ok":
                comparison = _comparison_hashes(
                    self.sidecar,
                    data_source,
                    int(data_source.getSize()),
                    self.context,
                    row.get("digest", ""),
                    progress_factory=lambda index, total: phase_progress(
                        index + measured_phase + 1
                    ),
                )
                row.update(comparison)
                row["md5"] = comparison.get("md5_digest", "")
                row["sha1"] = comparison.get("sha1_digest", "")
                row["sha256"] = comparison.get("sha256_digest", "")
                if (
                    comparison.get("baseline_blake3_status") == "ok"
                    and not comparison.get("baseline_blake3_matches")
                ):
                    row["status"] = "error"
                    row["error"] = "BASELINE_BLAKE3_DIGEST_MISMATCH"
            _record(self.job_id, row)
            if row["status"] == "ok":
                _queue_artifact(
                    self.job_id, self.data_source_id, self.blackboard, data_source, row
                )
        except Exception as exc:
            _record(self.job_id, {
                "status": "error",
                "name": _safe_name(data_source),
                "source_kind": "Evidence source",
                "category": _category(_safe_name(data_source)),
                "size_bytes": int(data_source.getSize()),
                "error": str(exc),
            })
        return IngestModule.ProcessResult.OK

    def shutDown(self):
        _shutdown_module(self)


def _escape(value):
    return (
        str(value if value is not None else "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _cell(row, key, fallback=""):
    value = row.get(key, fallback)
    return _escape(value if value not in (None, "") else fallback)


def _generate_report_minimal(job_id):
    with _JOBS_LOCK:
        stats = dict(_job(job_id))
        stats["rows"] = list(stats["rows"])
    try:
        case = Case.getCurrentCase()
        report_dir = str(case.getReportDirectory())
        if not os.path.isdir(report_dir):
            os.makedirs(report_dir)
        stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        stem = "BLAKE3_Forensic_Report_job_%s_%s" % (job_id, stamp)
        html_path = os.path.join(report_dir, stem + ".html")
        json_path = os.path.join(report_dir, stem + ".json")
        total_mib = float(stats["bytes"]) / (1024.0 * 1024.0)
        total_seconds = float(stats["elapsed_ms"]) / 1000.0
        aggregate = total_mib / total_seconds if total_seconds > 0.0 else 0.0

        body_rows = []
        for row in stats["rows"]:
            body_rows.append(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td class='num'>%s</td>"
                "<td class='digest'>%s</td><td class='num'>%s</td><td class='num'>%s</td>"
                "<td class='num'>%s</td><td class='num'>%s</td><td class='num'>%s</td>"
                "<td class='digest'>%s</td><td class='digest'>%s</td><td class='digest'>%s</td>"
                "<td>%s</td></tr>" % (
                    _cell(row, "source_kind"), _cell(row, "category"), _cell(row, "name"),
                    _cell(row, "size_bytes", "0"), _cell(row, "digest", "N/A"),
                    _cell(row, "end_to_end_elapsed_ms", "N/A"),
                    _cell(row, "throughput_mb_s", "N/A"),
                    _cell(row, "cpu_utilization_percent", "N/A"),
                    _cell(row, "peak_rss_mb", "N/A"), _cell(row, "threads_used", "N/A"),
                    _cell(row, "md5", "Not available from Autopsy"),
                    _cell(row, "sha1", "Not available from Autopsy"),
                    _cell(row, "sha256", "Not available from Autopsy"),
                    _cell(row, "status"),
                )
            )
        html = """<!doctype html><html><head><meta charset='utf-8'>
<title>BLAKE3 Forensic Hash Report</title><style>
body{font:14px Segoe UI,Arial,sans-serif;margin:32px;color:#18202a}h1{margin-bottom:4px}
.meta,.note{background:#f4f7fa;border:1px solid #dce3ea;padding:14px;margin:16px 0}
.cards{display:flex;gap:12px;flex-wrap:wrap}.card{border:1px solid #dce3ea;padding:12px;min-width:145px}
.card b{display:block;font-size:22px}table{border-collapse:collapse;width:100%%;font-size:12px}
th,td{border:1px solid #dce3ea;padding:6px;vertical-align:top}th{background:#23364d;color:white;position:sticky;top:0}
.num{text-align:right;white-space:nowrap}.digest{font-family:Consolas,monospace;word-break:break-all}
</style></head><body><h1>Optimized BLAKE3 Forensic Hash Report</h1>
<div class='meta'><b>Module:</b> %(module)s %(version)s<br><b>Generated (UTC):</b> %(generated)s<br>
<b>Engine path:</b> %(engine_path)s<br><b>Engine SHA-256:</b> <span class='digest'>%(engine_sha256)s</span><br>
<b>Startup validation:</b> %(self_test)s</div>
<div class='cards'><div class='card'>Hashed<b>%(hashed)s</b></div><div class='card'>Errors<b>%(errors)s</b></div>
<div class='card'>Skipped<b>%(skipped)s</b></div><div class='card'>Bytes hashed<b>%(bytes)s</b></div>
<div class='card'>Aggregate E2E MiB/s<b>%(aggregate).3f</b></div></div>
<div class='note'><b>Measurement scope.</b> End-to-end BLAKE3 timing includes Autopsy Content.read(), Java pipe transfer,
native hashing, and result parsing. Engine CPU/RSS fields require an executable rebuilt from optimized_blake3.py.
MD5/SHA-1/SHA-256 values are read from Autopsy's file metadata when another ingest module has populated them; this
module does not re-hash every file with baseline algorithms, because that would distort BLAKE3 ingest throughput.
Different algorithms are expected to have different digest text. "Not available" is not a mismatch.
No per-file double hashing is performed; exact byte-count validation and the published-vector startup test are used.
The engine executable SHA-256 above supports reproducibility and chain-of-custody documentation.</div>
<p>Detailed rows omitted because of report safety limit: %(omitted)s</p>
<table><thead><tr><th>Kind</th><th>Category</th><th>Name</th><th>Bytes</th><th>BLAKE3</th>
<th>E2E ms</th><th>E2E MiB/s</th><th>CPU %%</th><th>Peak RSS MiB</th><th>Threads</th>
<th>Autopsy MD5</th><th>Autopsy SHA-1</th><th>Autopsy SHA-256</th><th>Status</th></tr></thead>
<tbody>%(rows)s</tbody></table></body></html>""" % {
            "module": _escape(MODULE_NAME), "version": _escape(MODULE_VERSION),
            "generated": _escape(datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")),
            "engine_path": _escape(stats.get("engine_path", "")),
            "engine_sha256": _escape(stats.get("engine_sha256", "")),
            "self_test": _escape(stats.get("self_test", "")), "hashed": stats["hashed"],
            "errors": stats["errors"], "skipped": stats["skipped"], "bytes": stats["bytes"],
            "aggregate": aggregate, "omitted": stats["rows_omitted"], "rows": "".join(body_rows),
        }
        output = open(html_path, "wb")
        try:
            output.write(html)
        finally:
            output.close()
        audit = open(json_path, "w")
        try:
            audit.write(json.dumps(_audit_stats(stats), indent=2, sort_keys=True))
        finally:
            audit.close()
        try:
            case.addReport(JFile(html_path), MODULE_NAME, "BLAKE3 Forensic Hash Report")
        except Exception:
            pass
        IngestServices.getInstance().postMessage(IngestMessage.createMessage(
            IngestMessage.MessageType.INFO,
            MODULE_NAME,
            "BLAKE3 HTML and JSON reports saved: " + html_path,
        ))
        return html_path
    except Exception as exc:
        try:
            print("BLAKE3 minimal report generation failed:\n" + traceback.format_exc())
        except Exception:
            pass
        try:
            IngestServices.getInstance().postMessage(IngestMessage.createMessage(
                IngestMessage.MessageType.ERROR, MODULE_NAME, "Report generation failed: " + str(exc)
            ))
        except Exception:
            pass
        return None


def _format_bytes(byte_count):
    try:
        value = float(byte_count)
    except Exception:
        return "N/A"
    units = ["bytes", "KiB", "MiB", "GiB", "TiB"]
    unit = units[0]
    for candidate in units:
        unit = candidate
        if value < 1024.0 or candidate == units[-1]:
            break
        value /= 1024.0
    if unit == "bytes":
        return "%d bytes" % int(value)
    return "%.2f %s" % (value, unit)


def _format_ms(milliseconds):
    try:
        value = float(milliseconds)
    except Exception:
        return "N/A"
    if value >= 1000.0:
        return "%.2f s" % (value / 1000.0)
    return "%.3f ms" % value


def _format_seconds(milliseconds):
    try:
        return "%.3f s" % (float(milliseconds) / 1000.0)
    except Exception:
        return "N/A"


def _format_rate(rate):
    """Adaptive throughput formatting (MiB/s, scaling up to GiB/s or TiB/s)."""
    try:
        value = float(rate)
    except Exception:
        return "N/A"
    if value >= 1024.0 * 1024.0:
        return "%.2f TiB/s" % (value / (1024.0 * 1024.0))
    if value >= 1024.0:
        return "%.2f GiB/s" % (value / 1024.0)
    if value < 1.0 and value > 0.0:
        return "%.2f KiB/s" % (value * 1024.0)
    return "%.2f MiB/s" % value


def _format_percent(value):
    try:
        return "%.2f %%" % float(value)
    except Exception:
        return "N/A"


def _format_mib(value_mib):
    """Adaptive memory formatting. Input is always in MiB; output scales to
    KiB/MiB/GiB so small and large peak-memory readings are both legible,
    instead of always showing a fixed 'MiB' unit."""
    try:
        value = float(value_mib)
    except Exception:
        return "N/A"
    if value < 0.0:
        return "N/A"
    if value == 0.0:
        return "0 KiB"
    if value < 1.0:
        return "%.2f KiB" % (value * 1024.0)
    if value < 1024.0:
        return "%.2f MiB" % value
    return "%.2f GiB" % (value / 1024.0)


def _speedup_class(text):
    """Deterministic (non-JS) coloring for a rendered speedup label."""
    label = str(text or "").strip()
    if label == "N/A" or label.startswith("Equivalent"):
        return "speedup-equal"
    if label.startswith("Optimized"):
        return "speedup-win"
    return "speedup-loss"


def _numeric(row, key):
    try:
        return float(row.get(key))
    except Exception:
        return None


def _format_speedup(comparison_ms, optimized_ms, comparison_label="Comparison"):
    try:
        comparison = float(comparison_ms)
        optimized = float(optimized_ms)
        if comparison <= 0.0 or optimized <= 0.0:
            return "N/A"
        ratio = comparison / optimized
        if abs(ratio - 1.0) < 0.005:
            return "Equivalent (1.00x)"
        if ratio > 1.0:
            return "Optimized %.2fx faster" % ratio
        return "%s %.2fx faster" % (comparison_label, 1.0 / ratio)
    except Exception:
        return "N/A"


def _algorithm_rows(file_rows, prefix):
    """Every file row where this algorithm actually produced a digest."""
    if prefix == "optimized":
        return [row for row in file_rows if row.get("status") == "ok"]
    return [row for row in file_rows if row.get(prefix + "_status") == "ok"]


def _empty_algorithm_totals(error=None):
    """Zeroed totals shape, used whenever _algorithm_job_totals can't compute
    a real answer -- keeps every downstream consumer (Executive Summary,
    Speed Comparison row, _files_included_label, _format_speedup) working
    against the same dict shape instead of raising further down the line."""
    totals = {
        "file_count": 0,
        "includes_evidence": False,
        "bytes": 0,
        "elapsed_ms": 0.0,
        "throughput_mb_s": 0.0,
        "average_cpu": None,
        "peak_rss": None,
    }
    if error is not None:
        totals["error"] = str(error)
    return totals


def _algorithm_job_totals(file_rows, evidence, prefix):
    """Total bytes/time/CPU/RSS for one algorithm across every file it
    processed during this job, plus the evidence-source pass (when that
    algorithm also completed on the evidence source). Every algorithm is
    totaled the exact same way, so the numbers line up with each other and
    with the Executive Summary's overall hashing-speed figure.

    Never raises: any single malformed row (batch-mode or otherwise) is
    excluded from the sums rather than aborting the whole report, since this
    function's output feeds both the Executive Summary and every row of the
    Speed Comparison table.
    """
    try:
        rows_ok = _algorithm_rows(file_rows, prefix)
        if prefix == "optimized":
            elapsed_key = "end_to_end_elapsed_ms"
            cpu_key = "cpu_utilization_percent"
            rss_key = "peak_rss_mb"
            evidence_ok = evidence.get("status") == "ok"
        else:
            elapsed_key = prefix + "_elapsed_ms"
            cpu_key = prefix + "_cpu_utilization_percent"
            rss_key = prefix + "_peak_rss_mb"
            evidence_ok = evidence.get(prefix + "_status") == "ok"

        total_bytes = 0
        total_elapsed = 0.0
        cpu_values = []
        rss_values = []
        file_count = 0
        for row in rows_ok:
            try:
                total_bytes += int(row.get("size_bytes", 0))
                total_elapsed += _numeric(row, elapsed_key) or 0.0
                cpu_value = _numeric(row, cpu_key)
                if cpu_value is not None:
                    cpu_values.append(cpu_value)
                rss_value = _numeric(row, rss_key)
                if rss_value is not None:
                    rss_values.append(rss_value)
                file_count += 1
            except Exception:
                # Skip just this one malformed row; still total the rest.
                continue

        if evidence_ok:
            total_bytes += int(evidence.get("size_bytes", 0))
            total_elapsed += _numeric(evidence, elapsed_key) or 0.0
            evidence_cpu = _numeric(evidence, cpu_key)
            evidence_rss = _numeric(evidence, rss_key)
            if evidence_cpu is not None:
                cpu_values.append(evidence_cpu)
            if evidence_rss is not None:
                rss_values.append(evidence_rss)

        rate = (
            (float(total_bytes) / (1024.0 * 1024.0)) / (total_elapsed / 1000.0)
            if total_elapsed > 0.0 else 0.0
        )
        return {
            "file_count": file_count,
            "includes_evidence": evidence_ok,
            "bytes": total_bytes,
            "elapsed_ms": total_elapsed,
            "throughput_mb_s": rate,
            "average_cpu": (sum(cpu_values) / len(cpu_values)) if cpu_values else None,
            "peak_rss": max(rss_values) if rss_values else None,
        }
    except Exception as exc:
        return _empty_algorithm_totals(exc)


def _files_included_label(totals):
    label = "%d file%s" % (
        totals["file_count"], "" if totals["file_count"] == 1 else "s"
    )
    if totals["includes_evidence"]:
        label += " + evidence source"
    return label


def _local_timestamp():
    """Wall-clock timestamp on the examiner's own machine, with timezone label."""
    now = datetime.datetime.now()
    try:
        tz_name = time.tzname[time.localtime().tm_isdst > 0]
    except Exception:
        tz_name = ""
    stamp = now.strftime("%Y-%m-%d %H:%M:%S")
    return (stamp + " " + tz_name).strip()


def _local_file_stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def _safe_case_name():
    try:
        return str(Case.getCurrentCase().getName())
    except Exception:
        return "Unknown Case"


def _safe_examiner():
    try:
        value = Case.getCurrentCase().getExaminer()
        return str(value) if value else "Not set"
    except Exception:
        return "Not set"


def _status_badge(status):
    status_text = str(status or "unknown")
    badge_class = "badge-green" if status_text == "ok" else (
        "badge-amber" if status_text == "skipped" else "badge-red"
    )
    return '<span class="badge %s">%s</span>' % (
        badge_class, _escape(status_text.upper())
    )


def _show_report_popup(report_path):
    """Offer to open the completed report on Swing's UI thread."""

    def _show():
        try:
            options = ["Open Report", "OK"]
            choice = JOptionPane.showOptionDialog(
                None,
                "BLAKE3 forensic report is ready:\n\n" + report_path,
                "BLAKE3 Hash Report Ready",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.INFORMATION_MESSAGE,
                None,
                options,
                options[1],
            )
            if choice == 0:
                if Desktop.isDesktopSupported():
                    Desktop.getDesktop().open(JFile(report_path))
                else:
                    JOptionPane.showMessageDialog(
                        None,
                        "Automatic opening is not supported. Report saved at:\n" + report_path,
                        "BLAKE3 Hash Report",
                        JOptionPane.INFORMATION_MESSAGE,
                    )
        except Exception as exc:
            try:
                IngestServices.getInstance().postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.WARNING,
                        MODULE_NAME,
                        "Could not display/open the report: " + str(exc),
                    )
                )
            except Exception:
                pass

    try:
        SwingUtilities.invokeLater(_show)
    except Exception as exc:
        try:
            IngestServices.getInstance().postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.WARNING,
                    MODULE_NAME,
                    "Could not schedule the report dialog: " + str(exc),
                )
            )
        except Exception:
            pass


def _generate_report(job_id):
    """Render the full forensic report after Autopsy completes the data source."""
    with _JOBS_LOCK:
        stats = dict(_job(job_id))
        stats["rows"] = list(stats["rows"])

    try:
        rows = stats["rows"]
        _refresh_autopsy_hash_checks(rows)
        evidence_rows = [row for row in rows if row.get("source_kind") == "Evidence source"]
        evidence = evidence_rows[-1] if evidence_rows else {}
        file_rows = [row for row in rows if row.get("source_kind") == "File"]
        successful_files = [row for row in file_rows if row.get("status") == "ok"]
        error_files = [row for row in file_rows if row.get("status") == "error"]
        skipped_files = [row for row in file_rows if row.get("status") == "skipped"]

        file_bytes = sum([int(row.get("size_bytes", 0)) for row in successful_files])
        file_elapsed_ms = sum([
            _numeric(row, "end_to_end_elapsed_ms") or 0.0 for row in successful_files
        ])
        aggregate_rate = (
            (float(file_bytes) / (1024.0 * 1024.0)) / (file_elapsed_ms / 1000.0)
            if file_elapsed_ms > 0.0 else 0.0
        )

        # ------------------------------------------------------------------
        # Per-algorithm job totals: every file that algorithm hashed, plus
        # the evidence-source pass when that algorithm also completed on the
        # evidence source. Computed identically for all five algorithms so
        # "total job time" is directly comparable, and the Executive Summary
        # figure below uses the exact same numbers as the Speed Comparison
        # table (they are the same measurement, not two different ones).
        # ------------------------------------------------------------------
        optimized_totals = _algorithm_job_totals(file_rows, evidence, "optimized")
        baseline_totals = _algorithm_job_totals(file_rows, evidence, "baseline_blake3")
        sha256_totals = _algorithm_job_totals(file_rows, evidence, "sha256")
        sha1_totals = _algorithm_job_totals(file_rows, evidence, "sha1")
        md5_totals = _algorithm_job_totals(file_rows, evidence, "md5")

        cpu_values = [
            value for value in [_numeric(row, "cpu_utilization_percent") for row in successful_files]
            if value is not None
        ]
        rss_values = [
            value for value in [_numeric(row, "peak_rss_mb") for row in successful_files]
            if value is not None
        ]
        average_cpu = sum(cpu_values) / len(cpu_values) if cpu_values else None
        peak_rss = max(rss_values) if rss_values else None

        reference_counts = {}
        autopsy_check_counts = {}
        for key in ("md5", "sha1", "sha256"):
            reference_counts[key] = len([
                row for row in successful_files if row.get(key)
            ])
            available = len([
                row for row in successful_files if row.get("autopsy_" + key)
            ])
            matches = len([
                row for row in successful_files
                if row.get(key + "_matches_autopsy") is True
            ])
            mismatches = len([
                row for row in successful_files
                if row.get(key + "_matches_autopsy") is False
            ])
            autopsy_check_counts[key] = {
                "available": available,
                "matches": matches,
                "mismatches": mismatches,
            }

        short_read_skips = len([
            row for row in skipped_files
            if "fewer bytes" in str(row.get("reason", ""))
        ])
        digest_validation_errors = len([
            row for row in error_files
            if row.get("error") == "byte-count/digest validation failed"
        ])
        bytecount_issue_count = short_read_skips + digest_validation_errors
        if bytecount_issue_count == 0:
            bytecount_main = "PASS"
            bytecount_detail = "all bytes accounted for"
        else:
            bytecount_main = "FLAGGED"
            bytecount_detail = "%d file(s) failed verification" % bytecount_issue_count
        bytecount_badge = "badge-green" if bytecount_issue_count == 0 else "badge-red"
        bytecount_main_class = "is-good" if bytecount_issue_count == 0 else "is-bad"

        if not EVIDENCE_CACHE_WARMUP:
            warmup_main = "DISABLED"
            warmup_detail = "warm-up pass turned off"
            warmup_badge = "badge-amber"
            warmup_main_class = "is-warn"
        elif evidence.get("warmup_digest_matches") is True:
            warmup_main = "PASS"
            warmup_detail = "warm-up digest matched"
            warmup_badge = "badge-green"
            warmup_main_class = "is-good"
        elif evidence.get("warmup_digest_matches") is False:
            warmup_main = "FAIL"
            warmup_detail = "digest mismatch"
            warmup_badge = "badge-red"
            warmup_main_class = "is-bad"
        else:
            warmup_main = "NOT RUN"
            warmup_detail = "no warm-up pass recorded"
            warmup_badge = "badge-amber"
            warmup_main_class = "is-warn"

        baseline_matches = len([
            row for row in successful_files if row.get("baseline_blake3_matches") is True
        ])
        baseline_mismatches = len([
            row for row in file_rows if row.get("baseline_blake3_matches") is False
            and row.get("baseline_blake3_status") == "ok"
        ])
        baseline_main_class = "is-good" if baseline_mismatches == 0 else "is-bad"
        baseline_main_headline = "PASS" if baseline_mismatches == 0 else "FLAGGED"
        baseline_badge = "badge-green" if baseline_mismatches == 0 else "badge-red"
        integrity_comparisons = len([
            row for row in successful_files
            if row.get("baseline_blake3_status") == "ok"
        ])

        # -- Executive-summary "top line" stats, using the same totals that
        # -- drive the Speed Comparison table below, so the two numbers can
        # -- never disagree.
        self_test_raw = str(stats.get("self_test", "NOT RUN"))
        self_test_passed = self_test_raw.startswith("PASSED")
        self_test_class = "is-good" if self_test_passed else "is-bad"
        self_test_status = "PASSED" if self_test_passed else "FAILED / NOT RUN"
        self_test_badge = "badge-green" if self_test_passed else "badge-red"
        if ":" in self_test_raw:
            self_test_detail = self_test_raw.split(":", 1)[1].strip()
        else:
            self_test_detail = self_test_raw

        evidence_ok = evidence.get("status") == "ok"
        evidence_status = "Completed" if evidence_ok else "Not available"
        evidence_status_class = "is-good" if evidence_ok else "is-bad"
        evidence_status_detail = (
            "digest recorded to the case blackboard" if evidence_ok
            else "no evidence-source digest was recorded for this job"
        )

        hashing_speed_detail = "%s" % _escape(
            _files_included_label(optimized_totals)
        )

        error_count = len(error_files)
        skipped_count = len(skipped_files)
        if error_count == 0 and skipped_count == 0:
            issues_class = "is-good"
            issues_detail = "no issues detected during this job"
        elif error_count > 0:
            issues_class = "is-bad"
            issues_detail = "see the per-file log below"
        else:
            issues_class = "is-warn"
            issues_detail = "see the per-file log below"

        category_counts = {}
        skip_counts = {}
        for row in successful_files:
            category = str(row.get("category", "Other"))
            category_counts[category] = category_counts.get(category, 0) + 1
        for row in skipped_files:
            reason = str(row.get("reason", "OTHER"))
            skip_counts[reason] = skip_counts.get(reason, 0) + 1

        detail_rows = []

        def reference_digest_cell(row, prefix):
            digest = _cell(row, prefix, "N/A")
            state = row.get(prefix + "_matches_autopsy")
            if state is True:
                return digest + '<br><span class="badge badge-green">AUTOPSY MATCH</span>'
            if state is False:
                return digest + '<br><span class="badge badge-red">AUTOPSY MISMATCH</span>'
            return digest + '<br><span class="badge badge-amber">AUTOPSY N/A</span>'

        for row in file_rows:
            # One malformed row (batch-mode or otherwise) must drop out of
            # the audit log with a visible marker, not blank the report for
            # every other file that hashed cleanly.
            try:
                if row.get("baseline_blake3_matches") is True:
                    baseline_match = '<span class="badge badge-green">MATCH</span>'
                elif row.get("baseline_blake3_status") == "ok":
                    baseline_match = '<span class="badge badge-red">MISMATCH</span>'
                else:
                    baseline_match = '<span class="badge badge-amber">N/A</span>'
                row_rss = _numeric(row, "peak_rss_mb")
                name_cell = _cell(row, "name", "(unnamed)")
                if row.get("batch_mode"):
                    name_cell += (
                        ' <span class="badge badge-amber" '
                        'title="Timing distributed across a batched IPC round '
                        'trip, not individually measured">BATCH-EST</span>'
                    )
                detail_rows.append(
                    "<tr><td>%s</td><td>%s</td><td class='num'>%s</td>"
                    "<td class='digest'>%s</td><td class='digest'>%s</td>"
                    "<td>%s</td><td class='digest'>%s</td>"
                    "<td class='digest'>%s</td><td class='digest'>%s</td>"
                    "<td class='num'>%s</td>"
                    "<td class='num'>%s</td><td class='num'>%s</td>"
                    "<td class='num'>%s</td><td>%s</td></tr>" % (
                        name_cell,
                        _cell(row, "category", "Other"),
                        _cell(row, "size_bytes", "0"),
                        _cell(row, "digest", "N/A"),
                        _cell(row, "baseline_blake3_digest", "N/A"),
                        baseline_match,
                        reference_digest_cell(row, "md5"),
                        reference_digest_cell(row, "sha1"),
                        reference_digest_cell(row, "sha256"),
                        _cell(row, "end_to_end_elapsed_ms", "N/A"),
                        _cell(row, "throughput_mb_s", "N/A"),
                        _cell(row, "cpu_utilization_percent", "N/A"),
                        _format_mib(row_rss) if row_rss is not None else "N/A",
                        _status_badge(row.get("status")),
                    )
                )
            except Exception as exc:
                detail_rows.append(
                    "<tr><td>%s</td><td colspan='13'>Row unavailable: %s</td></tr>"
                    % (_escape(row.get("name", "(unnamed)")), _escape(str(exc)))
                )

        def _file_algorithm_total_row(label, prefix, primary=False):
            # Isolated in its own try/except: a bad or unexpected value on any
            # single row (batch-mode or otherwise) must degrade this one row
            # to an error placeholder, never abort report generation for
            # every other algorithm and the rest of the page.
            try:
                algorithm_rows = _algorithm_rows(file_rows, prefix)
                if not algorithm_rows:
                    return ""
                if prefix == "optimized":
                    elapsed_key = "end_to_end_elapsed_ms"
                    cpu_key = "cpu_utilization_percent"
                    rss_key = "peak_rss_mb"
                else:
                    elapsed_key = prefix + "_elapsed_ms"
                    cpu_key = prefix + "_cpu_utilization_percent"
                    rss_key = prefix + "_peak_rss_mb"
                total_bytes = sum([
                    int(row.get("size_bytes", 0)) for row in algorithm_rows
                ])
                total_elapsed = sum([
                    _numeric(row, elapsed_key) or 0.0 for row in algorithm_rows
                ])
                throughput = (
                    (float(total_bytes) / (1024.0 * 1024.0))
                    / (total_elapsed / 1000.0)
                    if total_elapsed > 0.0 else 0.0
                )
                cpu_values = [
                    value for value in [_numeric(row, cpu_key) for row in algorithm_rows]
                    if value is not None
                ]
                rss_values = [
                    value for value in [_numeric(row, rss_key) for row in algorithm_rows]
                    if value is not None
                ]
                batch_count = len([
                    row for row in algorithm_rows if row.get("batch_mode")
                ])
                label_html = _escape(label)
                if batch_count:
                    # Forensic transparency: these rows' timing is a
                    # proportional estimate distributed across one batched
                    # IPC round trip (see _flush_batch), not individually
                    # measured. Flag it on the total row so nobody mistakes
                    # it for a direct per-file measurement.
                    label_html += (
                        ' <span class="badge badge-amber" title="Timing for '
                        '%d of %d files is distributed across a batched IPC '
                        'round trip, not individually measured">BATCH-EST</span>'
                        % (batch_count, len(algorithm_rows))
                    )
                row_class = " class='primary-row'" if primary else ""
                return (
                    "<tr%s><td class='total-algorithm'>%s</td>"
                    "<td class='num'><strong>%d</strong></td>"
                    "<td class='num'><strong>%s</strong></td>"
                    "<td class='num'><strong>%s</strong></td>"
                    "<td class='num'><strong>%s</strong></td>"
                    "<td class='num'><strong>%s</strong></td>"
                    "<td class='num'><strong>%s</strong></td></tr>" % (
                        row_class,
                        label_html,
                        len(algorithm_rows),
                        total_bytes,
                        _escape(_format_seconds(total_elapsed)),
                        _escape(_format_rate(throughput)),
                        ("%.2f %%" % (sum(cpu_values) / len(cpu_values)))
                        if cpu_values else "N/A",
                        _format_mib(max(rss_values)) if rss_values else "N/A",
                    )
                )
            except Exception as exc:
                return (
                    "<tr><td class='total-algorithm'>%s</td>"
                    "<td class='num' colspan='5'>Totals unavailable: %s</td></tr>"
                    % (_escape(label), _escape(str(exc)))
                )

        total_rows_html = "".join([
            _file_algorithm_total_row("Optimized BLAKE3", "optimized", True),
            _file_algorithm_total_row("Baseline BLAKE3", "baseline_blake3"),
            _file_algorithm_total_row("SHA-256", "sha256"),
            _file_algorithm_total_row("SHA-1", "sha1"),
            _file_algorithm_total_row("MD5", "md5"),
        ])

        category_rows = []
        for category in sorted(category_counts.keys()):
            category_rows.append(
                "<tr><td>%s</td><td class='num'>%s</td></tr>" % (
                    _escape(category), category_counts[category]
                )
            )
        if not category_rows:
            category_rows.append("<tr><td colspan='2'>No successfully hashed files.</td></tr>")

        skip_rows = []
        for reason in sorted(skip_counts.keys()):
            skip_rows.append(
                "<tr><td>%s</td><td class='num'>%s</td></tr>" % (
                    _escape(reason), skip_counts[reason]
                )
            )
        if not skip_rows:
            skip_rows.append("<tr><td colspan='2'>No files skipped.</td></tr>")

        evidence_digest = _cell(evidence, "digest", "Not available")
        evidence_name = _cell(evidence, "name", "Data source")
        evidence_rss_numeric = _numeric(evidence, "peak_rss_mb")
        evidence_reference_rows = []
        baseline_match_text = (
            '<br><span class="badge badge-green">MATCH</span>'
            if evidence.get("baseline_blake3_matches") is True
            else '<br><span class="badge badge-red">MISMATCH / UNAVAILABLE</span>'
        )
        evidence_reference_rows.append(
            "<tr><td class='algorithm'>Baseline BLAKE3</td>"
            "<td>Reference BLAKE3 implementation (fixed 1&nbsp;MiB buffer, single thread)</td>"
            "<td>%s</td><td>%s</td><td class='digest'>%s%s</td></tr>" % (
                _escape(_format_ms(evidence.get("baseline_blake3_elapsed_ms"))),
                _escape(_format_rate(evidence.get("baseline_blake3_throughput_mb_s"))),
                _cell(evidence, "baseline_blake3_digest", "Not available"),
                baseline_match_text,
            )
        )
        for label, prefix in (("MD5", "md5"), ("SHA-1", "sha1"), ("SHA-256", "sha256")):
            evidence_reference_rows.append(
                "<tr><td class='algorithm'>%s</td><td>Independent reference hash for cross-validation</td>"
                "<td>%s</td><td>%s</td><td class='digest'>%s</td></tr>" % (
                    label,
                    _escape(_format_ms(evidence.get(prefix + "_elapsed_ms"))),
                    _escape(_format_rate(evidence.get(prefix + "_throughput_mb_s"))),
                    _cell(evidence, prefix + "_digest", "Not available"),
                )
            )

        if COMPARE_EVERY_FILE:
            integrity_scope_text = (
                "Confirms the optimized digest matches an independently computed "
                "BLAKE3 digest for every file that was hashed, and cross-checks it "
                "against MD5, SHA-1, and SHA-256 as well."
            )
            speed_comparison_note = (
                "Every algorithm processed every successfully hashed file (including the "
                "evidence source) under identical conditions."
            )
            per_file_log_note = (
                "Optimized BLAKE3 and every comparison algorithm (Baseline "
                "BLAKE3, MD5, SHA-1, SHA-256) cover every readable file."
            )
        else:
            integrity_scope_text = (
                "Confirms the optimized digest matches an independently computed "
                "BLAKE3 digest, sampled across up to %s files per evidence "
                "category. Performance is measured separately on up to %s files "
                "per category, restricted to files &ge; %s, so small-file overhead "
                "doesn't distort the speed comparison." % (
                    INTEGRITY_SAMPLE_LIMIT,
                    COMPARISON_SAMPLE_LIMIT,
                    _escape(_format_bytes(PERFORMANCE_MIN_BYTES)),
                )
            )
            speed_comparison_note = (
                "Each algorithm's \"Total Time\" and \"Throughput\" below cover every "
                "file that algorithm actually processed (plus the evidence source, "
                "where completed) &mdash; the same measurement basis used for "
                "\"Hashing Speed\" in the Executive Summary above. The \"Files\" "
                "column shows how many items went into each total; algorithms may "
                "cover different file counts when sampling is enabled, so it's shown "
                "explicitly rather than assumed."
            )
            per_file_log_note = (
                "Optimized BLAKE3 covers every readable file. Comparison "
                "algorithms use independent full passes over the recorded "
                "stratified sample."
            )

        def _comparison_row(label, profile_text, totals, role_text):
            time_text = _format_ms(totals["elapsed_ms"])
            rate_text = _format_rate(totals["throughput_mb_s"])
            cpu_text = (
                "%.2f %%" % totals["average_cpu"]
                if totals["average_cpu"] is not None else "N/A"
            )
            rss_text = (
                _format_mib(totals["peak_rss"])
                if totals["peak_rss"] is not None else "N/A"
            )
            speedup_text = _format_speedup(
                totals["elapsed_ms"], optimized_totals["elapsed_ms"], label
            )
            return (
                "<tr><td class='algorithm'>%s</td><td>%s</td>"
                "<td>%s</td><td>%s</td><td><strong>%s</strong></td>"
                "<td>%s</td><td>%s</td>"
                "<td><span class=\"speedup %s\">%s</span></td><td>%s</td></tr>" % (
                    _escape(label),
                    profile_text,
                    _escape(_files_included_label(totals)),
                    _escape(time_text),
                    _escape(rate_text),
                    _escape(cpu_text),
                    _escape(rss_text),
                    _speedup_class(speedup_text),
                    _escape(speedup_text),
                    role_text,
                )
            )

        optimized_row_html = (
            "<tr class=\"primary-row\"><td class=\"algorithm\">Optimized BLAKE3"
            "<span class=\"role\">Production profile</span></td>"
            "<td>Adaptive I/O buffering with native, multi-threaded tree hashing (%s)</td>"
            "<td>%s</td><td>%s</td><td><strong>%s</strong></td>"
            "<td>%s</td><td>%s</td>"
            "<td><span class=\"badge badge-blue\">Reference baseline</span></td>"
            "<td>Digest posted to the case blackboard as the primary result</td></tr>" % (
                _cell(evidence, "simd_tier", "Native runtime dispatch"),
                _escape(_files_included_label(optimized_totals)),
                _escape(_format_ms(optimized_totals["elapsed_ms"])),
                _escape(_format_rate(optimized_totals["throughput_mb_s"])),
                (
                    "%.2f %%" % optimized_totals["average_cpu"]
                    if optimized_totals["average_cpu"] is not None else "N/A"
                ),
                (
                    _format_mib(optimized_totals["peak_rss"])
                    if optimized_totals["peak_rss"] is not None else "N/A"
                ),
            )
        )
        comparison_rows_html = (
            optimized_row_html
            + _comparison_row(
                "Baseline BLAKE3",
                "Reference configuration: fixed 1&nbsp;MiB buffer, single-threaded, "
                "same underlying BLAKE3 implementation",
                baseline_totals,
                "Isolates the optimization's contribution from the algorithm itself",
            )
            + _comparison_row(
                "SHA-256",
                "Independent full-file pass using a fixed I/O buffer",
                sha256_totals,
                "Industry-standard comparison; also checked against Autopsy's stored digest",
            )
            + _comparison_row(
                "SHA-1",
                "Independent full-file pass using a fixed I/O buffer",
                sha1_totals,
                "Industry-standard comparison; also checked against Autopsy's stored digest",
            )
            + _comparison_row(
                "MD5",
                "Independent full-file pass using a fixed I/O buffer",
                md5_totals,
                "Industry-standard comparison; also checked against Autopsy's stored digest",
            )
        )

        case_name = _safe_case_name()
        examiner = _safe_examiner()
        generated = _local_timestamp()
        report_dir = str(Case.getCurrentCase().getReportDirectory())
        if not os.path.isdir(report_dir):
            os.makedirs(report_dir)
        logo_source = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "autopsy-logo.png"
        )
        logo_path = os.path.join(report_dir, "autopsy-logo.png")
        if os.path.isfile(logo_source):
            try:
                shutil.copyfile(logo_source, logo_path)
            except Exception:
                pass
        safe_stem = "".join([
            character if character.isalnum() else "_" for character in evidence_name
        ]).strip("_") or "Data_Source"
        stamp = _local_file_stamp()
        html_path = os.path.join(
            report_dir, "BLAKE3_Hash_Report_%s_%s.html" % (safe_stem, stamp)
        )
        json_path = os.path.join(
            report_dir, "BLAKE3_Hash_Report_%s_%s.json" % (safe_stem, stamp)
        )

        html = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(evidence_name)s - BLAKE3 Forensic Hash Report</title>
<style>
:root{--navy:#13293d;--navy-deep:#0c1c29;--ink:#1e2b33;--muted:#5c6b74;--line:#dde3e7;--bg:#f6f7f9;--panel:#ffffff;--accent:#2f6690;--green:#1f7a4d;--green-bg:#eaf5ee;--amber:#8a6100;--amber-bg:#fbf3df;--red:#a32020;--red-bg:#faeaea;--blue:#2f6690;--blue-bg:#eaf2f7;--sidebar-w:272px}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font-family:"Segoe UI",Arial,Helvetica,sans-serif;line-height:1.55;font-size:14px}
.skip-link{position:absolute;left:-999px;top:0;background:var(--navy);color:#fff;padding:10px 16px;z-index:200;border-radius:0 0 6px 0}
.skip-link:focus{left:0}
.layout{display:flex;align-items:flex-start;min-height:100vh}
.sidebar{width:var(--sidebar-w);flex:0 0 var(--sidebar-w);background:var(--navy-deep);color:#c7d6e0;position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column;border-right:1px solid #06121c}
.sidebar-header{padding:20px 20px 16px;border-bottom:1px solid rgba(255,255,255,.08)}
.brand-row{display:flex;align-items:center;gap:8px}
.brand-icon{width:42px;height:42px;flex:0 0 auto;object-fit:contain}
.brand-name{color:#fff;font-size:25px;font-weight:800;letter-spacing:.6px;text-transform:uppercase}
.sidebar-title{color:#fff;font-size:15px;font-weight:700;line-height:1.3}
.sidebar-sub{color:#8fa5b3;font-size:12px;margin-left:12px}
.sidebar-meta{margin:0;padding:16px 20px;border-bottom:1px solid rgba(255,255,255,.08);font-size:12px}
.sidebar-meta>div{display:flex;justify-content:space-between;gap:10px;padding:4px 0}
.sidebar-meta dt{color:#7f97a6;flex:0 0 auto}
.sidebar-meta dd{margin:0;color:#e7eef2;text-align:right;overflow-wrap:anywhere}
.sidebar-scroll{padding:16px 12px;flex:1 1 auto}
.sidebar-label{margin:0 8px 8px;color:#7f97a6;font-size:11px;text-transform:uppercase;letter-spacing:.8px;font-weight:700}
.toc{list-style:none;margin:0;padding:0}
.toc li+li{margin-top:2px}
.toc a{display:block;padding:8px 12px;border-radius:5px;color:#c7d6e0;text-decoration:none;font-size:12.5px;border-left:2px solid transparent}
.toc a:hover{background:rgba(255,255,255,.06);color:#fff}
.toc a:focus-visible{outline:2px solid #6fb3d9;outline-offset:-2px}
.toc a.active{background:rgba(111,179,217,.14);border-left-color:#6fb3d9;color:#fff;font-weight:600}
.sidebar-footer{padding:14px 20px 20px;border-top:1px solid rgba(255,255,255,.08);display:flex;flex-direction:column;gap:8px}
.print-btn{background:transparent;border:1px solid rgba(255,255,255,.28);color:#e7eef2;padding:8px 10px;border-radius:5px;font-size:12px;cursor:pointer}
.print-btn:hover{background:rgba(255,255,255,.08)}
.print-btn:active{background:rgba(255,255,255,.14)}
.print-btn:focus-visible{outline:2px solid #6fb3d9;outline-offset:1px}
.top-link{color:#8fa5b3;font-size:11px;text-decoration:none}
.top-link:hover{color:#fff;text-decoration:underline}
.nav-toggle-input{display:none}
.nav-toggle-label{display:none}
.main{flex:1 1 auto;min-width:0;max-width:1080px;margin:0 auto;padding:32px 34px 56px}
.hero{background:var(--navy);color:#fff;padding:22px 26px;border-left:4px solid var(--accent)}
.eyebrow{font-size:11px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:#9fc3d8}
h1{margin:6px 0 8px;font-size:24px;line-height:1.25;font-weight:700}
.hero-subtitle{margin:0;max-width:760px;color:#cfe0ea;font-size:13px}
section{margin-top:36px;scroll-margin-top:18px}
h2{color:var(--navy);font-size:17px;margin:0 0 12px;padding-bottom:8px;border-bottom:2px solid var(--line);font-weight:700}
h3{color:var(--navy);font-size:13.5px;margin:18px 0 8px;font-weight:700}
.section-note{color:var(--muted);font-size:12.5px;margin:-4px 0 14px}
.stat-strip{display:flex;flex-wrap:wrap;border:1px solid var(--line);border-top:none;background:var(--panel)}
.stat{flex:1 1 180px;padding:14px 18px;border-right:1px solid var(--line);border-bottom:1px solid var(--line)}
.stat:last-child{border-right:none}
.stat-label{color:var(--muted);font-size:10.5px;text-transform:uppercase;letter-spacing:.6px;font-weight:700}
.stat-value{color:var(--navy);font-size:17px;font-weight:700;margin-top:5px;word-break:break-word}
.total-summary{border:1px solid var(--line);background:var(--panel);padding:14px 16px 0;margin-top:14px}
.total-summary-heading{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin:0 0 12px;color:var(--navy);font-size:13px;font-weight:700}
.total-summary-heading span{color:var(--muted);font-size:11px;font-weight:400}
.total-summary .stat-strip{border:0;border-top:1px solid var(--line);margin:0 -16px}
.total-summary .stat{flex:1 1 150px;padding:12px 16px}
.total-summary .stat-value{font-size:16px}
.total-summary .stat-value.emphasis{color:var(--green)}
.status-line{display:flex;flex-direction:column;gap:3px;margin-top:5px}
.status-line .status-main{font-size:17px;font-weight:800;letter-spacing:.2px;color:var(--navy)}
.status-line .status-main.is-good{color:var(--green)}
.status-line .status-main.is-bad{color:var(--red)}
.status-line .status-main.is-warn{color:var(--amber)}
.status-line .status-detail{font-size:10.5px;font-weight:600;letter-spacing:.15px;color:var(--muted);text-transform:none}
.badge .status-detail{display:inline;font-size:9px;font-weight:600;opacity:.82;margin-left:4px}
table.table-kv{table-layout:fixed}
table.table-kv th{width:44%%;white-space:normal}
table.table-kv td{width:56%%;white-space:normal}
.panel{background:var(--panel);border:1px solid var(--line);padding:0;margin-top:14px;overflow-x:auto}
.panel>table{margin-top:0}
table{width:100%%;border-collapse:collapse;background:var(--panel);font-size:12.5px}
th,td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}
th{background:var(--navy);color:#fff;font-size:10.5px;text-transform:uppercase;letter-spacing:.4px;font-weight:600;position:sticky;top:0}
tbody tr:hover td{background:#f1f6f9}
tbody tr:nth-child(even) td{background:#fafbfc}
tbody tr:nth-child(even):hover td{background:#f1f6f9}
.algorithm{font-weight:700;color:var(--navy)}
.total-algorithm{font-weight:400;color:var(--navy);white-space:nowrap}
.role{display:block;color:var(--muted);font-size:11px;font-weight:400;margin-top:2px}
.primary-row td{background:#eef5f9!important}
.primary-row:hover td{background:#e6f0f6!important}
.badge{display:inline-block;border-radius:3px;padding:3px 8px;font-size:10.5px;font-weight:700;white-space:nowrap;letter-spacing:.2px}
.badge-green{color:var(--green);background:var(--green-bg)}
.badge-amber{color:var(--amber);background:var(--amber-bg)}
.badge-red{color:var(--red);background:var(--red-bg)}
.badge-blue{color:var(--blue);background:var(--blue-bg)}
.speedup{display:inline-block;border-radius:3px;padding:3px 8px;font-size:11px;font-weight:700;white-space:nowrap;letter-spacing:.2px;background:#eef1f3;color:var(--muted)}
.speedup-win{background:var(--green-bg);color:var(--green)}
.speedup-loss{background:var(--red-bg);color:var(--red)}
.speedup-equal{background:#eef1f3;color:var(--muted)}
.legend{display:flex;flex-wrap:wrap;gap:16px;padding:10px 14px;font-size:11.5px;color:var(--muted);background:#fafbfc;border:1px solid var(--line);border-top:none}
.legend span{display:inline-flex;align-items:center;gap:6px}
.legend i{width:9px;height:9px;border-radius:50%%;display:inline-block}
.legend .dot-green{background:var(--green)}
.legend .dot-gray{background:#9aa7ae}
.legend .dot-red{background:var(--red)}
.digest{font-family:Consolas,"Courier New",monospace;font-size:11px;word-break:break-all;color:#33474f}
.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:11px}
td[colspan]{color:var(--muted);font-style:italic;text-align:center;padding:18px}
@media(max-width:960px){
.sidebar{position:fixed;left:0;top:0;transform:translateX(-100%%);z-index:150;box-shadow:2px 0 18px rgba(0,0,0,.25);transition:transform .18s ease}
.nav-toggle-input:checked~.sidebar{transform:translateX(0)}
.nav-toggle-label{display:flex;position:fixed;top:14px;left:14px;z-index:160;width:38px;height:38px;background:var(--navy);border-radius:5px;flex-direction:column;justify-content:center;align-items:center;gap:4px;cursor:pointer}
.nav-toggle-label span{width:18px;height:2px;background:#fff;display:block}
.main{padding:70px 20px 40px;max-width:none}
.stat{flex:1 1 45%%}
}
@media(max-width:600px){
.stat{flex:1 1 100%%}
h1{font-size:20px}
.hero{padding:18px}
}
@media print{
.sidebar,.nav-toggle-label,.skip-link{display:none}
.layout{display:block}
.main{max-width:none;padding:0;margin:0}
body{background:#fff}
section{margin-top:22px}
.panel{overflow-x:visible}
}
</style></head><body>
<a class="skip-link" href="#main-content">Skip to report content</a>
<div class="layout">
<input type="checkbox" id="nav-toggle" class="nav-toggle-input">
<label for="nav-toggle" class="nav-toggle-label" aria-label="Toggle contents menu"><span></span><span></span><span></span></label>
<nav class="sidebar" aria-label="Report contents">
<div class="sidebar-header">
<div class="brand-row">
<img class="brand-icon" src="autopsy-logo.png" alt="Autopsy logo">
<span class="brand-name">Autopsy</span>
</div>
<div class="sidebar-sub">Optimized Blake3 Hash Report</div></div>
<dl class="sidebar-meta">
<div><dt>Case</dt><dd>%(case_name)s</dd></div>
<div><dt>Examiner</dt><dd>%(examiner)s</dd></div>
<div><dt>Evidence</dt><dd>%(evidence_name)s</dd></div>
<div><dt>Generated</dt><dd>%(generated)s</dd></div>
</dl>
<div class="sidebar-scroll">
<p class="sidebar-label">Contents</p>
<ol class="toc">
<li><a href="#executive-summary">Summary</a></li>
<li><a href="#architecture">Integrity &amp; Verification</a></li>
<li><a href="#algorithm-comparison">Speed Comparison</a></li>
<li><a href="#evidence-source">Evidence Source Result</a></li>
<li><a href="#benchmark-scope">Benchmark Details</a></li>
<li><a href="#file-summary">File-by-File Summary</a></li>
<li><a href="#performance-log">Full Per-File Log</a></li>
</ol>
</div>
<div class="sidebar-footer"><button type="button" class="print-btn" onclick="window.print()">Print / Save as PDF</button><a class="top-link" href="#top">Back to top &uarr;</a></div>
</nav>
<main class="main" id="main-content"><a id="top"></a>
<header class="hero"><div class="eyebrow">Autopsy Ingest Report</div><h1>Optimized BLAKE3 Hash Verification Report</h1><p class="hero-subtitle">Hash verification and comparative performance analysis for the evidence source processed during this ingest job.</p></header>
<section id="executive-summary"><h2>Executive Summary</h2>
<div class="stat-strip">
<div class="stat"><div class="stat-label">Evidence Status</div><div class="status-line"><span class="status-main %(evidence_status_class)s">%(evidence_status)s</span><span class="status-detail">%(evidence_status_detail)s</span></div></div>
<div class="stat"><div class="stat-label">Self-Test</div><div class="status-line"><span class="status-main %(self_test_class)s">%(self_test_status)s</span><span class="status-detail">%(self_test_detail)s</span></div></div>
<div class="stat"><div class="stat-label">Hashing Speed</div><div class="status-line"><span class="status-main">%(total_time_display)s</span><span class="status-detail">%(hashing_speed_detail)s</span></div></div>
<div class="stat"><div class="stat-label">Errors / Skipped Files</div><div class="status-line"><span class="status-main %(issues_class)s">%(error_count)s errors, %(skipped_count)s skipped</span><span class="status-detail">%(issues_detail)s</span></div></div>
</div>
</section>
<section id="architecture"><h2>Integrity &amp; Verification</h2>
<div class="stat-strip">
<div class="stat"><div class="stat-label">Engine Startup Self-Test</div><div class="status-line"><span class="status-main %(self_test_class)s">%(self_test_status)s</span><span class="status-detail">%(self_test_detail)s</span></div></div>
<div class="stat"><div class="stat-label">Baseline BLAKE3 Cross-Check</div><div class="status-line"><span class="status-main %(baseline_main_class)s">%(baseline_match_headline)s</span><span class="status-detail">%(baseline_match_summary)s</span></div></div>
<div class="stat"><div class="stat-label">Evidence Cache Warm-Up</div><div class="status-line"><span class="status-main %(warmup_main_class)s">%(warmup_main)s</span><span class="status-detail">%(warmup_detail)s</span></div></div>
</div>
<div class="panel"><table><thead><tr><th>Check</th><th>Status</th><th>What it confirms</th></tr></thead><tbody>
<tr><td><strong>Published-vector startup test</strong></td><td><span class="badge %(self_test_badge)s">%(self_test_status)s</span></td><td>Confirms the correct BLAKE3 engine is actually running, by checking it against a known, official test value before any evidence is touched.</td></tr>
<tr><td><strong>Baseline BLAKE3 cross-check</strong></td><td><span class="badge %(baseline_badge)s">%(baseline_match_headline)s<span class="status-detail">%(baseline_match_summary)s</span></span></td><td>%(integrity_scope_text)s</td></tr>
<tr><td><strong>Evidence cache warm-up consistency</strong></td><td><span class="badge %(warmup_badge)s">%(warmup_main)s<span class="status-detail">%(warmup_detail)s</span></span></td><td>Makes sure the timing numbers aren't skewed by disk caching. The evidence is read once to warm the cache, then read again for the timed digest, and the two digests must match.</td></tr>
</tbody></table></div>
<h3>Engine Configuration</h3>
<p class="section-note">Describes how the optimized profile was run.</p>
<div class="panel"><table class="table-kv"><tr><th>SIMD dispatch</th><td>%(simd)s</td></tr><tr><th>Maximum native threads</th><td>%(threads)s</td></tr></table></div>
</section>
<section id="algorithm-comparison"><h2>Speed Comparison</h2><p class="section-note">%(speed_comparison_note)s</p><div class="panel"><table><thead><tr><th>Algorithm</th><th>Profile</th><th>Files</th><th>Total Time</th><th>Throughput</th><th>Avg CPU</th><th>Peak Memory</th><th>Relative Performance</th><th>Role</th></tr></thead><tbody>%(comparison_rows)s</tbody></table><div class="legend"><span><i class="dot-green"></i>Optimized BLAKE3 faster</span><span><i class="dot-gray"></i>Equivalent performance</span><span><i class="dot-red"></i>Comparison algorithm faster</span></div></div></section>
<section id="evidence-source"><h2>Evidence Source Result</h2><p class="section-note">Full-source digest for the complete evidence source, alongside the same independently computed reference algorithms.</p><div class="panel"><table><thead><tr><th>Algorithm</th><th>Role</th><th>Execution Time</th><th>Throughput</th><th>Digest</th></tr></thead><tbody><tr class="primary-row"><td class="algorithm">Optimized BLAKE3</td><td>Primary digest recorded to the case blackboard</td><td>%(evidence_time)s</td><td>%(evidence_rate)s</td><td class="digest">%(evidence_digest)s</td></tr>%(evidence_reference_rows)s</tbody></table><table class="table-kv"><tr><th>SIMD dispatch</th><td>%(simd)s</td></tr><tr><th>Maximum native threads</th><td>%(threads)s</td></tr><tr><th>Engine CPU utilization</th><td>%(evidence_cpu)s</td></tr><tr><th>Engine peak memory</th><td>%(evidence_rss)s</td></tr></table></div></section>
<section id="benchmark-scope"><h2>Benchmark Details</h2><p class="section-note">Raw counts and cumulative figures underlying the summary and speed comparison above.</p>
<h3>Coverage</h3>
<div class="panel"><table class="table-kv"><tr><th>Successfully hashed files</th><td>%(success_count)s</td></tr><tr><th>Data included</th><td>%(file_bytes)s</td></tr><tr><th>Errors</th><td>%(error_count)s</td></tr><tr><th>Detailed rows omitted by safety limit</th><td>%(omitted)s</td></tr></table></div>
<h3>Cross-Algorithm Verification</h3>
<p class="section-note">How many files each independent algorithm actually reprocessed, and whether Baseline BLAKE3 agreed with the optimized digest.</p>
<div class="panel"><table class="table-kv"><tr><th>Baseline BLAKE3 completed</th><td>%(baseline_count)s files</td></tr><tr><th>Baseline digest verification</th><td>%(baseline_match_summary)s</td></tr><tr><th>SHA-256 completed</th><td>%(sha256_count)s files</td></tr><tr><th>SHA-1 completed</th><td>%(sha1_count)s files</td></tr><tr><th>MD5 completed</th><td>%(md5_count)s files</td></tr></table></div>
<h3>Autopsy Stored-Hash Reconciliation</h3>
<p class="section-note">Comparison against hashes Autopsy already had on file, where another ingest module had populated them.</p>
<div class="panel"><table class="table-kv"><tr><th>Stored Autopsy SHA-256 checks</th><td>%(autopsy_sha256_summary)s</td></tr><tr><th>Stored Autopsy SHA-1 checks</th><td>%(autopsy_sha1_summary)s</td></tr><tr><th>Stored Autopsy MD5 checks</th><td>%(autopsy_md5_summary)s</td></tr></table></div>
<h3>Optimized BLAKE3 Performance (files only)</h3>
<p class="section-note">Files only, excluding the evidence source.</p>
<div class="panel"><table class="table-kv"><tr><th>Optimized cumulative time</th><td>%(file_time)s</td></tr><tr><th>Optimized aggregate throughput</th><td>%(aggregate_rate)s</td></tr><tr><th>Average optimized normalized CPU</th><td>%(average_cpu)s</td></tr><tr><th>Maximum optimized peak memory</th><td>%(peak_rss)s</td></tr></table></div>
</section>
<section id="file-summary"><h2>File-by-File Summary</h2><p class="section-note">Breakdown of hashed evidence by category, and any files that were skipped.</p><div class="stat-strip">
<div class="stat"><div class="stat-label">Successfully Hashed</div><div class="stat-value">%(success_count)s</div></div>
<div class="stat"><div class="stat-label">Errors</div><div class="stat-value">%(error_count)s</div></div>
<div class="stat"><div class="stat-label">Skipped</div><div class="stat-value">%(skipped_count)s</div></div>
<div class="stat"><div class="stat-label">Aggregate Throughput</div><div class="stat-value">%(aggregate_rate)s</div></div>
</div><div class="panel"><h3>Evidence Categories</h3><table><thead><tr><th>Category</th><th>Successfully Hashed</th></tr></thead><tbody>%(category_rows)s</tbody></table><h3>Files Skipped</h3><table><thead><tr><th>Reason</th><th>Count</th></tr></thead><tbody>%(skip_rows)s</tbody></table></div></section>
<section id="performance-log"><h2>Full Per-File Log</h2><p class="section-note">%(per_file_log_note)s</p><div class="total-summary"><div class="total-summary-heading">Successfully Hashed Files <span>Optimized BLAKE3 Hash</span></div><div class="stat-strip"><div class="stat"><div class="stat-label">Files Hashed</div><div class="stat-value">%(success_count)s</div></div><div class="stat"><div class="stat-label">Data Processed</div><div class="stat-value">%(file_bytes)s</div></div><div class="stat"><div class="stat-label">End-to-End Time</div><div class="stat-value emphasis">%(file_time_seconds)s</div></div><div class="stat"><div class="stat-label">Throughput</div><div class="stat-value emphasis">%(aggregate_rate)s</div></div><div class="stat"><div class="stat-label">Average CPU</div><div class="stat-value">%(average_cpu)s</div></div><div class="stat"><div class="stat-label">Peak Memory</div><div class="stat-value">%(peak_rss)s</div></div></div></div><h3>Individual File Results</h3><div class="panel"><table><thead><tr><th>File</th><th>Category</th><th>Bytes</th><th>Optimized BLAKE3</th><th>Baseline BLAKE3</th><th>Match</th><th>MD5</th><th>SHA-1</th><th>SHA-256</th><th>Optimized End-to-End ms</th><th>Optimized MiB/s</th><th>CPU %%</th><th>Peak Memory</th><th>Status</th></tr></thead><tbody>%(detail_rows)s</tbody></table></div></section>
<div class="footer">This report documents hashing results, integrity controls, and performance measurements produced during Autopsy ingest.</div>
</main>
</div>
<script>
(function () {
  var sections = Array.prototype.slice.call(document.querySelectorAll('main section[id]'));
  var links = Array.prototype.slice.call(document.querySelectorAll('.toc a'));
  function setActive() {
    var pos = window.scrollY + 130;
    var current = sections.length ? sections[0].id : null;
    for (var i = 0; i < sections.length; i++) {
      if (sections[i].offsetTop <= pos) { current = sections[i].id; }
    }
    for (var j = 0; j < links.length; j++) {
      var isActive = current && links[j].getAttribute('href') === '#' + current;
      links[j].classList.toggle('active', !!isActive);
    }
  }
  window.addEventListener('scroll', setActive, { passive: true });
  window.addEventListener('resize', setActive);
  setActive();
  var toggle = document.getElementById('nav-toggle');
  if (toggle) {
    links.forEach(function (a) {
      a.addEventListener('click', function () { toggle.checked = false; });
    });
  }
})();
</script>
</body></html>""" % {
            "evidence_name": _escape(evidence_name),
            "case_name": _escape(case_name),
            "examiner": _escape(examiner),
            "generated": _escape(generated),
            "build": _escape(MODULE_BUILD),
            "integrity_scope_text": integrity_scope_text,
            "speed_comparison_note": speed_comparison_note,
            "per_file_log_note": per_file_log_note,
            "evidence_status": _escape(evidence_status),
            "evidence_status_class": evidence_status_class,
            "evidence_status_detail": _escape(evidence_status_detail),
            "display_rate": _escape(_format_rate(optimized_totals["throughput_mb_s"])),
            "total_time_display": _escape(_format_ms(optimized_totals["elapsed_ms"])),
            "hashing_speed_detail": hashing_speed_detail,
            "self_test_status": self_test_status,
            "self_test_class": self_test_class,
            "self_test_detail": _escape(self_test_detail),
            "self_test_badge": self_test_badge,
            "issues_class": issues_class,
            "issues_detail": _escape(issues_detail),
            "bytecount_main": bytecount_main,
            "bytecount_detail": bytecount_detail,
            "bytecount_badge": bytecount_badge,
            "bytecount_main_class": bytecount_main_class,
            "warmup_main": warmup_main,
            "warmup_detail": warmup_detail,
            "warmup_badge": warmup_badge,
            "warmup_main_class": warmup_main_class,
            "baseline_badge": baseline_badge,
            "baseline_match_headline": baseline_main_headline,
            "baseline_main_class": baseline_main_class,
            "baseline_match_summary": (
                "%d matched / %d mismatched" % (baseline_matches, baseline_mismatches)
            ),
            "baseline_count": integrity_comparisons,
            "threads": _cell(evidence, "threads_used", "N/A"),
            "engine_sha256": _escape(stats.get("engine_sha256", "")),
            "simd": _cell(evidence, "simd_tier", "Native runtime dispatch"),
            "aggregate_rate": _escape(_format_rate(aggregate_rate)),
            "comparison_rows": comparison_rows_html,
            "success_count": len(successful_files),
            "sha256_count": reference_counts["sha256"],
            "sha1_count": reference_counts["sha1"],
            "md5_count": reference_counts["md5"],
            "autopsy_sha256_summary": "%d available; %d matched; %d mismatched" % (
                autopsy_check_counts["sha256"]["available"],
                autopsy_check_counts["sha256"]["matches"],
                autopsy_check_counts["sha256"]["mismatches"],
            ),
            "autopsy_sha1_summary": "%d available; %d matched; %d mismatched" % (
                autopsy_check_counts["sha1"]["available"],
                autopsy_check_counts["sha1"]["matches"],
                autopsy_check_counts["sha1"]["mismatches"],
            ),
            "autopsy_md5_summary": "%d available; %d matched; %d mismatched" % (
                autopsy_check_counts["md5"]["available"],
                autopsy_check_counts["md5"]["matches"],
                autopsy_check_counts["md5"]["mismatches"],
            ),
            "evidence_time": _escape(_format_ms(evidence.get("end_to_end_elapsed_ms"))),
            "evidence_rate": _escape(_format_rate(_numeric(evidence, "throughput_mb_s"))),
            "evidence_digest": evidence_digest,
            "evidence_reference_rows": "".join(evidence_reference_rows),
            "evidence_cpu": _escape(_format_percent(
                evidence.get("cpu_utilization_percent")
            )),
            "evidence_rss": (
                _format_mib(evidence_rss_numeric)
                if evidence_rss_numeric is not None else "N/A"
            ),
            "evidence_bytes_read": _cell(evidence, "bytes_read", "N/A"),
            "evidence_bytes_expected": _cell(evidence, "size_bytes", "N/A"),
            "file_bytes": _escape(_format_bytes(file_bytes)),
            "file_time": _escape(_format_ms(file_elapsed_ms)),
            "file_time_seconds": _escape(_format_seconds(file_elapsed_ms)),
            "average_cpu": ("%.2f %%" % average_cpu) if average_cpu is not None else "N/A",
            "peak_rss": _format_mib(peak_rss) if peak_rss is not None else "N/A",
            "error_count": len(error_files),
            "skipped_count": len(skipped_files),
            "omitted": stats.get("rows_omitted", 0),
            "category_rows": "".join(category_rows),
            "skip_rows": "".join(skip_rows),
            "detail_rows": "".join(detail_rows) if detail_rows else "<tr><td colspan='14'>No file rows recorded.</td></tr>",
            "total_rows": total_rows_html,
            "module": _escape(MODULE_NAME),
            "version": _escape(MODULE_VERSION),
        }

        stats["optimized_job_totals"] = optimized_totals
        stats["baseline_blake3_job_totals"] = baseline_totals
        stats["sha256_job_totals"] = sha256_totals
        stats["sha1_job_totals"] = sha1_totals
        stats["md5_job_totals"] = md5_totals

        output = open(html_path, "wb")
        try:
            output.write(html)
        finally:
            output.close()
        audit = open(json_path, "w")
        try:
            audit.write(json.dumps(_audit_stats(stats), indent=2, sort_keys=True))
        finally:
            audit.close()

        try:
            Case.getCurrentCase().addReport(
                JFile(html_path), MODULE_NAME, "BLAKE3 Hash Report - " + evidence_name
            )
        except Exception as exc:
            IngestServices.getInstance().postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.WARNING,
                    MODULE_NAME,
                    "Report was written but could not be registered in Autopsy: " + str(exc),
                )
            )
        IngestServices.getInstance().postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                MODULE_NAME,
                "BLAKE3 HTML and JSON reports saved: " + html_path,
            )
        )
        _show_report_popup(html_path)
        return html_path
    except Exception as exc:
        # str(exc) alone is often just a bare key/attribute name and doesn't
        # say where in the ~700-line report body it happened. Log the full
        # traceback so a future failure is diagnosable from Autopsy's own
        # logs (Help -> Open Log Folder) instead of guessing again.
        trace_text = traceback.format_exc()
        try:
            print("BLAKE3 styled report generation failed:\n" + trace_text)
        except Exception:
            pass
        try:
            IngestServices.getInstance().postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    MODULE_NAME,
                    "Failed to generate styled BLAKE3 report: " + str(exc)
                    + " -- full traceback written to the Autopsy log. "
                    "Falling back to the minimal report.",
                )
            )
        except Exception:
            pass
        # Guaranteed fallback: the styled report has many moving parts (HTML
        # template, per-algorithm totals, per-file table). The minimal report
        # below only depends on the same flat "rows" list already recorded
        # during ingest, so it succeeds independently of whatever broke above
        # -- the job should never end with zero reports on disk.
        try:
            return _generate_report_minimal(job_id)
        except Exception as fallback_exc:
            try:
                IngestServices.getInstance().postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.ERROR,
                        MODULE_NAME,
                        "Minimal fallback report also failed: " + str(fallback_exc),
                    )
                )
            except Exception:
                pass
            return None
