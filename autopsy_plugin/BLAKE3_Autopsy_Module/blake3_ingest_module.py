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
import threading

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
MODULE_VERSION = "4.2.0"
MODULE_BUILD = "2026-08-27-balanced-benchmark-r2"
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
    os.environ.get("BLAKE3_COMPARE_EVERY_FILE", "0").strip().lower()
    in ("1", "true", "yes", "on")
)
POST_ALL_FILE_ARTIFACTS = (
    os.environ.get("BLAKE3_POST_ALL_FILE_ARTIFACTS", "0").strip().lower()
    in ("1", "true", "yes", "on")
)
EVIDENCE_CACHE_WARMUP = (
    os.environ.get("BLAKE3_EVIDENCE_CACHE_WARMUP", "1").strip().lower()
    not in ("0", "false", "no", "off")
)

_JOBS = {}
_JOBS_LOCK = threading.RLock()
_REPORT_LISTENERS = {}


def _new_job(job_id):
    return {
        "job_id": job_id,
        "active_instances": 0,
        "listener_registered": False,
        "report_written": False,
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
        _generate_report(job_id)


class _BLAKE3ReportListener(PropertyChangeListener):
    """Generate exactly once after all ingest modules finish a data source."""

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
                event_source = None
                try:
                    event_source = event.getNewValue()
                except Exception:
                    try:
                        event_source = event.getDataSource()
                    except Exception:
                        pass
                try:
                    if event_source is None or event_source.getId() != self.data_source_id:
                        return
                except Exception:
                    return
            with _JOBS_LOCK:
                stats = _job(self.job_id)
                if stats["report_written"]:
                    return
                stats["report_written"] = True
            _generate_report(self.job_id)
            try:
                IngestManager.getInstance().removeIngestJobEventListener(self)
            except Exception:
                pass
            with _JOBS_LOCK:
                _REPORT_LISTENERS.pop((self.job_id, self.data_source_id), None)
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
    if size_bytes < 1024 * 1024:
        return 64 * 1024
    if size_bytes < 16 * 1024 * 1024:
        return 256 * 1024
    if size_bytes < 64 * 1024 * 1024:
        return 2 * 1024 * 1024
    if size_bytes < 256 * 1024 * 1024:
        return 8 * 1024 * 1024
    if size_bytes < 2 * 1024 * 1024 * 1024:
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
    extension = os.path.splitext(str(name or ""))[1].lower()
    categories = [
        ("Documents", (".pdf", ".docx", ".txt")),
        ("Images", (".jpg", ".jpeg", ".png")),
        ("Audio", (".mp3", ".wav")),
        ("Video", (".mp4", ".avi")),
        ("Executables", (".exe", ".elf")),
        ("Disk Images", (".dd", ".e01", ".vmdk")),
    ]
    for label, extensions in categories:
        if extension in extensions:
            return label
    return "Other"


def _get_artifact_type(blackboard):
    try:
        return blackboard.getOrAddArtifactType(
            "BLAKE3_HASH_RESULT_V4", "BLAKE3 Hash (Optimized v4)"
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
    values = [
        ("BLAKE3_V4_DIGEST", "BLAKE3-256 Digest", row.get("digest", "")),
        ("BLAKE3_V4_SIZE", "File Size (bytes)", row.get("size_bytes", 0)),
        ("BLAKE3_V4_E2E_MS", "End-to-End Time (ms)", row.get("end_to_end_elapsed_ms", "")),
        ("BLAKE3_V4_ENGINE_MS", "Engine Time (ms)", row.get("engine_elapsed_ms", "")),
        ("BLAKE3_V4_MBPS", "End-to-End Throughput (MiB/s)", row.get("throughput_mb_s", "")),
        ("BLAKE3_V4_CPU", "Engine CPU Utilization (%)", row.get("cpu_utilization_percent", "N/A")),
        ("BLAKE3_V4_RSS", "Engine Peak RSS (MiB)", row.get("peak_rss_mb", "N/A")),
        ("BLAKE3_V4_SIMD", "SIMD Dispatch", row.get("simd_tier", "")),
        ("BLAKE3_V4_THREADS", "Maximum Native Threads", row.get("threads_used", "")),
        ("BLAKE3_V4_IO", "Engine I/O Strategy", row.get("io_strategy", "streamed IPC")),
        ("BLAKE3_V4_CATEGORY", "Evidence Category", row.get("category", "Other")),
    ]
    attributes = ArrayList()
    for name, display, value in values:
        attributes.add(_attribute(blackboard, name, display, value))
    artifact = content.newArtifact(artifact_type.getTypeID())
    artifact.addAttributes(attributes)
    blackboard.postArtifact(artifact, MODULE_NAME)


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
    module.engine_path = _engine_path()
    module.sidecar = _Sidecar(module.engine_path)
    passed, message = module.sidecar.self_test()
    if not passed:
        module.sidecar.close()
        raise IngestModule.IngestModuleException(
            "BLAKE3 engine published-vector self-test failed: " + message
        )
    with _JOBS_LOCK:
        stats = _job(module.job_id)
        stats["engine_path"] = module.engine_path
        stats["engine_sha256"] = _sha256_file(module.engine_path)
        stats["self_test"] = "PASSED: " + message
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

    def startUp(self, context):
        _startup_module(self, context)

    def process(self, file_obj):
        try:
            file_type = file_obj.getType()
            if file_obj.isDir() or file_type in (
                TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS,
                TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS,
            ):
                _record(self.job_id, {
                    "status": "skipped",
                    "name": _safe_name(file_obj),
                    "source_kind": "File",
                    "category": _category(_safe_name(file_obj)),
                    "size_bytes": int(file_obj.getSize()),
                    "reason": "directory or non-file block range",
                })
                return IngestModule.ProcessResult.OK
            row = _hash_one(
                self.sidecar,
                file_obj,
                int(file_obj.getSize()),
                self.context,
                "File",
            )
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
                    _post_artifact(self.blackboard, file_obj, row)
            elif row["status"] == "error":
                self.services.postMessage(IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    MODULE_NAME,
                    "BLAKE3 failed for %s: %s" % (row["name"], row.get("error", "")),
                ))
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

    def shutDown(self):
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
                _post_artifact(self.blackboard, data_source, row)
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
            audit.write(json.dumps(stats, indent=2, sort_keys=True))
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
    except Exception as exc:
        try:
            IngestServices.getInstance().postMessage(IngestMessage.createMessage(
                IngestMessage.MessageType.ERROR, MODULE_NAME, "Report generation failed: " + str(exc)
            ))
        except Exception:
            pass


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


def _format_rate(rate):
    try:
        value = float(rate)
    except Exception:
        return "N/A"
    if value >= 1024.0:
        return "%.2f GiB/s" % (value / 1024.0)
    return "%.2f MiB/s" % value


def _format_percent(value):
    try:
        return "%.2f %%" % float(value)
    except Exception:
        return "N/A"


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
        evidence_rate = _numeric(evidence, "throughput_mb_s")
        display_rate = evidence_rate if evidence_rate is not None else aggregate_rate

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

        performance_file_rows = [
            row for row in successful_files
            if row.get("comparison_performance_sample") is True
        ]
        performance_file_bytes = sum([
            int(row.get("size_bytes", 0)) for row in performance_file_rows
        ])
        if (
            performance_file_bytes >= PERFORMANCE_MIN_TOTAL_BYTES
            or evidence.get("status") != "ok"
        ):
            performance_rows = performance_file_rows
            performance_scope = "large-file cohort"
        else:
            performance_rows = [evidence]
            performance_scope = "complete evidence source (cohort fallback)"

        def comparison_metrics(prefix):
            measured = [
                row for row in performance_rows
                if row.get(prefix + "_status") == "ok"
            ]
            elapsed_values = [
                _numeric(row, prefix + "_elapsed_ms") or 0.0 for row in measured
            ]
            total_elapsed = sum(elapsed_values)
            total_bytes = sum([int(row.get("size_bytes", 0)) for row in measured])
            optimized_elapsed = sum([
                _numeric(row, "end_to_end_elapsed_ms") or 0.0 for row in measured
            ])
            optimized_rate = (
                (float(total_bytes) / (1024.0 * 1024.0)) / (optimized_elapsed / 1000.0)
                if optimized_elapsed > 0.0 else 0.0
            )
            optimized_cpu = [
                value for value in [
                    _numeric(row, "cpu_utilization_percent") for row in measured
                ] if value is not None
            ]
            optimized_rss = [
                value for value in [
                    _numeric(row, "peak_rss_mb") for row in measured
                ] if value is not None
            ]
            rate = (
                (float(total_bytes) / (1024.0 * 1024.0)) / (total_elapsed / 1000.0)
                if total_elapsed > 0.0 else 0.0
            )
            cpu = [
                value for value in [
                    _numeric(row, prefix + "_cpu_utilization_percent") for row in measured
                ] if value is not None
            ]
            rss = [
                value for value in [
                    _numeric(row, prefix + "_peak_rss_mb") for row in measured
                ] if value is not None
            ]
            return {
                "count": len(measured),
                "bytes": total_bytes,
                "elapsed_ms": total_elapsed,
                "optimized_elapsed_ms": optimized_elapsed,
                "optimized_throughput_mb_s": optimized_rate,
                "optimized_average_cpu": (
                    sum(optimized_cpu) / len(optimized_cpu) if optimized_cpu else None
                ),
                "optimized_peak_rss": max(optimized_rss) if optimized_rss else None,
                "throughput_mb_s": rate,
                "average_cpu": (sum(cpu) / len(cpu)) if cpu else None,
                "peak_rss": max(rss) if rss else None,
            }

        baseline_metrics = comparison_metrics("baseline_blake3")
        md5_metrics = comparison_metrics("md5")
        sha1_metrics = comparison_metrics("sha1")
        sha256_metrics = comparison_metrics("sha256")
        baseline_matches = len([
            row for row in successful_files if row.get("baseline_blake3_matches") is True
        ])
        baseline_mismatches = len([
            row for row in file_rows if row.get("baseline_blake3_matches") is False
            and row.get("baseline_blake3_status") == "ok"
        ])
        integrity_comparisons = len([
            row for row in successful_files
            if row.get("baseline_blake3_status") == "ok"
        ])

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
            if row.get("baseline_blake3_matches") is True:
                baseline_match = '<span class="badge badge-green">MATCH</span>'
            elif row.get("baseline_blake3_status") == "ok":
                baseline_match = '<span class="badge badge-red">MISMATCH</span>'
            else:
                baseline_match = '<span class="badge badge-amber">N/A</span>'
            detail_rows.append(
                "<tr><td>%s</td><td>%s</td><td class='num'>%s</td>"
                "<td class='digest'>%s</td><td class='digest'>%s</td>"
                "<td>%s</td><td class='digest'>%s</td>"
                "<td class='digest'>%s</td><td class='digest'>%s</td>"
                "<td class='num'>%s</td>"
                "<td class='num'>%s</td><td class='num'>%s</td>"
                "<td class='num'>%s</td><td>%s</td></tr>" % (
                    _cell(row, "name", "(unnamed)"),
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
                    _cell(row, "peak_rss_mb", "N/A"),
                    _status_badge(row.get("status")),
                )
            )

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
        evidence_status = "Completed" if evidence.get("status") == "ok" else "Not available"
        self_test_passed = str(stats.get("self_test", "")).startswith("PASSED")
        evidence_reference_rows = []
        baseline_match_text = (
            '<br><span class="badge badge-green">MATCH</span>'
            if evidence.get("baseline_blake3_matches") is True
            else '<br><span class="badge badge-red">MISMATCH / UNAVAILABLE</span>'
        )
        evidence_reference_rows.append(
            "<tr><td class='algorithm'>Baseline BLAKE3</td>"
            "<td>Official BLAKE3 &bull; fixed 1 MiB buffer &bull; single thread</td>"
            "<td>%s</td><td>%s</td><td class='digest'>%s%s</td></tr>" % (
                _escape(_format_ms(evidence.get("baseline_blake3_elapsed_ms"))),
                _escape(_format_rate(evidence.get("baseline_blake3_throughput_mb_s"))),
                _cell(evidence, "baseline_blake3_digest", "Not available"),
                baseline_match_text,
            )
        )
        for label, prefix in (("MD5", "md5"), ("SHA-1", "sha1"), ("SHA-256", "sha256")):
            evidence_reference_rows.append(
                "<tr><td class='algorithm'>%s</td><td>Independent full reference pass</td>"
                "<td>%s</td><td>%s</td><td class='digest'>%s</td></tr>" % (
                    label,
                    _escape(_format_ms(evidence.get(prefix + "_elapsed_ms"))),
                    _escape(_format_rate(evidence.get(prefix + "_throughput_mb_s"))),
                    _cell(evidence, prefix + "_digest", "Not available"),
                )
            )

        case_name = _safe_case_name()
        examiner = _safe_examiner()
        generated = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        report_dir = str(Case.getCurrentCase().getReportDirectory())
        if not os.path.isdir(report_dir):
            os.makedirs(report_dir)
        safe_stem = "".join([
            character if character.isalnum() else "_" for character in evidence_name
        ]).strip("_") or "Data_Source"
        stamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
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
:root{--navy:#102a43;--blue:#1f5f8b;--blue2:#2f80b7;--ink:#243b53;--muted:#627d98;--line:#d9e2ec;--soft:#f5f8fb;--white:#fff;--green:#1f7a4d;--green-bg:#eaf7ef;--amber:#9a6700;--amber-bg:#fff7df;--red:#a61b1b;--red-bg:#fff0f0}
*{box-sizing:border-box}body{margin:0;background:#eef2f6;color:var(--ink);font-family:"Segoe UI",Arial,Helvetica,sans-serif;line-height:1.5}.page{max-width:1180px;margin:0 auto;padding:34px 26px 48px}.hero{background:linear-gradient(135deg,#102a43,#1f5f8b);color:white;border-radius:16px;padding:28px 30px;box-shadow:0 10px 28px rgba(16,42,67,.16)}.eyebrow{font-size:12px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;opacity:.78}h1{margin:7px 0 8px;font-size:29px;line-height:1.2}.hero-subtitle{margin:0;max-width:900px;color:#d9eaf6;font-size:14px}.hero-meta{display:flex;flex-wrap:wrap;gap:10px;margin-top:20px}.hero-pill{background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.18);border-radius:999px;padding:6px 11px;font-size:12px}h2{color:var(--navy);font-size:19px;margin:34px 0 12px}h3{color:var(--navy);font-size:15px}.section-note{color:var(--muted);font-size:13px;margin:8px 0 14px}.card-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:16px}.metric{background:var(--white);border:1px solid var(--line);border-radius:12px;padding:16px;box-shadow:0 4px 14px rgba(16,42,67,.05)}.metric-label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.7px;font-weight:700}.metric-value{color:var(--navy);font-size:18px;font-weight:700;margin-top:6px;word-break:break-word}.panel{background:var(--white);border:1px solid var(--line);border-radius:14px;padding:18px;margin-top:14px;box-shadow:0 4px 14px rgba(16,42,67,.04);overflow-x:auto}table{width:100%%;border-collapse:separate;border-spacing:0;background:var(--white);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-top:12px}th,td{padding:11px 13px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left;font-size:13px}th{background:var(--navy);color:white;font-size:11px;text-transform:uppercase;letter-spacing:.5px}tr:last-child td{border-bottom:0}tbody tr:nth-child(even) td{background:var(--soft)}.algorithm{font-weight:700;color:var(--navy)}.role{display:block;color:var(--muted);font-size:11px;font-weight:400;margin-top:2px}.primary-row td{background:#edf6fc!important;border-top:1px solid #b9d9ed;border-bottom:1px solid #b9d9ed}.badge{display:inline-block;border-radius:999px;padding:4px 9px;font-size:11px;font-weight:700;white-space:nowrap}.badge-green{color:var(--green);background:var(--green-bg)}.badge-amber{color:var(--amber);background:var(--amber-bg)}.badge-red{color:var(--red);background:var(--red-bg)}.badge-blue{color:var(--blue);background:#eaf3fa}.digest{font-family:Consolas,"Courier New",monospace;font-size:11px;word-break:break-all}.num{text-align:right;white-space:nowrap}.callout{border-radius:11px;padding:13px 15px;margin-top:12px;font-size:12px}.callout-info{background:#edf6fc;border:1px solid #c8e1f0;color:#24516e}.callout-warn{background:var(--amber-bg);border:1px solid #f0d88a;color:#6f5100}.digest-block{background:#0f1720;color:#d9e2ec;border-radius:10px;padding:12px 14px;margin-top:8px;font-family:Consolas,"Courier New",monospace;font-size:11px;word-break:break-all}.footer{margin-top:34px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:11px;text-align:center}@media(max-width:900px){.card-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:560px){.page{padding:18px 12px 30px}.hero{padding:22px 20px}.card-grid{grid-template-columns:1fr}h1{font-size:24px}}@media print{body{background:white}.page{max-width:none;padding:0}.hero,.panel,.metric{box-shadow:none}}
</style></head><body><div class="page">
<header class="hero"><div class="eyebrow">Digital Forensics &bull; Autopsy Ingest Report</div><h1>Optimized BLAKE3 Hash Verification Report</h1><p class="hero-subtitle">Performance, integrity controls, resource measurements, independently timed reference algorithms, and comparison with hashes stored by Autopsy.</p><div class="hero-meta"><span class="hero-pill">Case: %(case_name)s</span><span class="hero-pill">Examiner: %(examiner)s</span><span class="hero-pill">Evidence: %(evidence_name)s</span><span class="hero-pill">Build: %(build)s</span><span class="hero-pill">Generated: %(generated)s</span></div></header>
<h2>Executive Summary</h2><div class="card-grid"><div class="metric"><div class="metric-label">Evidence Status</div><div class="metric-value">%(evidence_status)s</div></div><div class="metric"><div class="metric-label">Evidence Size</div><div class="metric-value">%(evidence_size)s</div></div><div class="metric"><div class="metric-label">Optimized BLAKE3 Throughput</div><div class="metric-value">%(display_rate)s</div></div><div class="metric"><div class="metric-label">Engine Self-Test</div><div class="metric-value">%(self_test_status)s</div></div></div>
<h2>1. Hashing Architecture &amp; Integrity Controls</h2><div class="panel"><table><thead><tr><th>Control</th><th>Result</th><th>Forensic Significance</th></tr></thead><tbody><tr><td><strong>Complete byte-count verification</strong></td><td><span class="badge badge-green">REQUIRED</span></td><td>A digest is accepted only after the declared byte count is read. Missing bytes are never zero-padded. An incomplete request resets and self-tests the native engine before processing continues.</td></tr><tr><td><strong>Published-vector startup test</strong></td><td><span class="badge %(self_test_badge)s">%(self_test_status)s</span></td><td>The packaged engine is checked against the standard BLAKE3 empty-input vector before evidence processing.</td></tr><tr><td><strong>Optimized native profile</strong></td><td>%(threads)s maximum threads</td><td>Adaptive buffers and standards-compliant native Merkle-tree parallelism are used for every readable file.</td></tr><tr><td><strong>Baseline BLAKE3 cross-check</strong></td><td><span class="badge %(baseline_match_badge)s">%(baseline_match_summary)s</span></td><td>Correctness coverage uses up to %(integrity_limit)s files per category. Performance aggregation separately includes up to %(comparison_limit)s files per category that are at least %(performance_min)s, so tiny-file request overhead is not misreported as hashing throughput.</td></tr><tr><td><strong>Evidence cache control</strong></td><td>%(evidence_cache_control)s</td><td>A complete unmeasured pass precedes the evidence-source timing, placing every measured algorithm under a warmed Autopsy/libewf/OS cache condition. The warm-up and measured BLAKE3 digests must agree.</td></tr></tbody></table><div class="callout callout-info"><strong>Engine identity:</strong> %(engine_path)s<br><span class="digest">SHA-256: %(engine_sha256)s</span></div><div class="callout callout-warn"><strong>Controlled SIMD factor:</strong> the official Python BLAKE3 API does not expose a runtime switch that disables SIMD. Native SIMD dispatch is therefore held constant in both BLAKE3 profiles; the measured treatment factors are adaptive buffering and multithreaded tree execution.</div></div>
<h2>2. Algorithm Comparison &mdash; Optimized BLAKE3, Baseline BLAKE3, and Autopsy-Compatible References</h2><p class="section-note">Each algorithm independently re-reads the same sampled Autopsy content objects. Execution time and throughput therefore use an aligned end-to-end measurement scope.</p><div class="panel"><table><thead><tr><th>Hashing Approach</th><th>Experimental Profile</th><th>Cumulative Time</th><th>Aggregate Throughput</th><th>Avg CPU</th><th>Peak RSS</th><th>vs Optimized</th><th>Role</th></tr></thead><tbody><tr class="primary-row"><td class="algorithm">Optimized BLAKE3<span class="role">Production profile</span></td><td>Adaptive buffer &bull; native tree parallelism &bull; %(simd)s</td><td>%(comparison_optimized_time)s</td><td><strong>%(comparison_optimized_rate)s</strong></td><td>%(optimized_cpu)s</td><td>%(optimized_rss)s</td><td><span class="badge badge-green">Reference 1.00x</span></td><td>Blackboard artifact and optimized treatment</td></tr><tr><td class="algorithm">Baseline BLAKE3<span class="role">Non-optimized application profile</span></td><td>Fixed 1 MiB buffer &bull; one native thread &bull; same official backend</td><td>%(baseline_total_time)s</td><td>%(baseline_rate)s</td><td>%(baseline_cpu)s</td><td>%(baseline_rss)s</td><td><span class="badge badge-blue">%(baseline_speedup)s</span></td><td>Same-algorithm performance and digest control</td></tr><tr><td class="algorithm">SHA-256</td><td>Independent fixed-buffer full pass</td><td>%(sha256_total_time)s</td><td>%(sha256_rate)s</td><td>%(sha256_cpu)s</td><td>%(sha256_rss)s</td><td><span class="badge badge-amber">%(sha256_speedup)s</span></td><td>Autopsy-compatible algorithm; stored digest checked separately</td></tr><tr><td class="algorithm">SHA-1</td><td>Independent fixed-buffer full pass</td><td>%(sha1_total_time)s</td><td>%(sha1_rate)s</td><td>%(sha1_cpu)s</td><td>%(sha1_rss)s</td><td><span class="badge badge-amber">%(sha1_speedup)s</span></td><td>Autopsy-compatible algorithm; stored digest checked separately</td></tr><tr><td class="algorithm">MD5</td><td>Independent fixed-buffer full pass</td><td>%(md5_total_time)s</td><td>%(md5_rate)s</td><td>%(md5_cpu)s</td><td>%(md5_rss)s</td><td><span class="badge badge-amber">%(md5_speedup)s</span></td><td>Autopsy-compatible algorithm; stored digest checked separately</td></tr></tbody></table><div class="callout callout-info"><strong>Interpretation:</strong> a value such as 2.00x faster means the comparison profile took twice as long as Optimized BLAKE3 on exactly the same sampled bytes. MD5, SHA-1, SHA-256, and BLAKE3 produce different digest values; only Baseline BLAKE3 and Optimized BLAKE3 are expected to match.</div><div class="callout callout-warn"><strong>Measurement boundary:</strong> MD5, SHA-1, and SHA-256 performance values are produced by independent sidecar passes, not exported timing values from Autopsy's built-in hashing module. When Autopsy has stored its own digest, the per-file log verifies equality and labels it AUTOPSY MATCH or AUTOPSY MISMATCH.</div></div>
<h2>3. Evidence Source &mdash; Complete Hash Result</h2><div class="panel"><table><thead><tr><th>Algorithm</th><th>Role</th><th>Execution Time</th><th>Throughput</th><th>Digest</th></tr></thead><tbody><tr class="primary-row"><td class="algorithm">Optimized BLAKE3</td><td>Production digest posted to Blackboard</td><td>%(evidence_time)s</td><td>%(evidence_rate)s</td><td class="digest">%(evidence_digest)s</td></tr>%(evidence_reference_rows)s</tbody></table><table><tr><th>SIMD dispatch</th><td>%(simd)s</td></tr><tr><th>Maximum native threads</th><td>%(threads)s</td></tr><tr><th>Engine CPU utilization</th><td>%(evidence_cpu)s</td></tr><tr><th>Engine peak RSS</th><td>%(evidence_rss)s</td></tr><tr><th>Byte-count verification</th><td>%(evidence_bytes_read)s of %(evidence_bytes_expected)s bytes read</td></tr></table></div>
<h2>4. Benchmark Scope &amp; Resource Interpretation</h2><div class="panel"><table><tr><th>Successfully hashed files</th><td>%(success_count)s</td></tr><tr><th>Data included</th><td>%(file_bytes)s</td></tr><tr><th>Baseline BLAKE3 completed</th><td>%(baseline_count)s files</td></tr><tr><th>Baseline digest verification</th><td>%(baseline_match_summary)s</td></tr><tr><th>SHA-256 / SHA-1 / MD5 completed</th><td>%(sha256_count)s / %(sha1_count)s / %(md5_count)s files</td></tr><tr><th>Stored Autopsy SHA-256 checks</th><td>%(autopsy_sha256_summary)s</td></tr><tr><th>Stored Autopsy SHA-1 checks</th><td>%(autopsy_sha1_summary)s</td></tr><tr><th>Stored Autopsy MD5 checks</th><td>%(autopsy_md5_summary)s</td></tr><tr><th>Optimized cumulative time</th><td>%(file_time)s</td></tr><tr><th>Optimized aggregate throughput</th><td>%(aggregate_rate)s</td></tr><tr><th>Average optimized normalized CPU</th><td>%(average_cpu)s</td></tr><tr><th>Maximum optimized peak RSS</th><td>%(peak_rss)s</td></tr><tr><th>Errors</th><td>%(error_count)s</td></tr><tr><th>Detailed rows omitted by safety limit</th><td>%(omitted)s</td></tr></table><div class="callout callout-info"><strong>Timing scope:</strong> every algorithm uses its own complete Autopsy Content.read(), Java bulk pipe transfer, hash computation, digest finalization, and result parsing pass. Cumulative times are sums across file measurements, not whole-job wall time.</div></div>
<h2>5. Individual File Hashing Summary</h2><div class="card-grid"><div class="metric"><div class="metric-label">Successfully Hashed</div><div class="metric-value">%(success_count)s</div></div><div class="metric"><div class="metric-label">Errors</div><div class="metric-value">%(error_count)s</div></div><div class="metric"><div class="metric-label">Skipped</div><div class="metric-value">%(skipped_count)s</div></div><div class="metric"><div class="metric-label">Aggregate Throughput</div><div class="metric-value">%(aggregate_rate)s</div></div></div><div class="panel"><h3>Evidence Categories</h3><table><thead><tr><th>Category</th><th>Successfully Hashed</th></tr></thead><tbody>%(category_rows)s</tbody></table><h3>Files Skipped</h3><table><thead><tr><th>Reason</th><th>Count</th></tr></thead><tbody>%(skip_rows)s</tbody></table></div>
<h2>6. Per-File Performance Log</h2><p class="section-note">Optimized BLAKE3 covers every readable file. Comparison algorithms use independent full passes for the recorded stratified sample. End-to-end throughput uses MiB/s (2^20 bytes per second). AUTOPSY N/A means the built-in hash was not stored or available when the completion report was created.</p><div class="panel"><table><thead><tr><th>File</th><th>Category</th><th>Bytes</th><th>Optimized BLAKE3</th><th>Baseline BLAKE3</th><th>Match</th><th>MD5</th><th>SHA-1</th><th>SHA-256</th><th>Optimized E2E ms</th><th>Optimized MiB/s</th><th>CPU %%</th><th>Peak RSS MiB</th><th>Status</th></tr></thead><tbody>%(detail_rows)s</tbody></table></div>
<div class="footer">Generated automatically by %(module)s v%(version)s, build %(build)s.<br>This report documents hashing results, integrity controls, and performance measurements produced during Autopsy ingest.</div></div></body></html>""" % {
            "evidence_name": _escape(evidence_name),
            "case_name": _escape(case_name),
            "examiner": _escape(examiner),
            "generated": _escape(generated),
            "build": _escape(MODULE_BUILD),
            "comparison_limit": COMPARISON_SAMPLE_LIMIT,
            "integrity_limit": INTEGRITY_SAMPLE_LIMIT,
            "performance_min": _escape(_format_bytes(PERFORMANCE_MIN_BYTES)),
            "evidence_cache_control": _escape(
                evidence.get("cache_control", "disabled")
            ),
            "evidence_status": _escape(evidence_status),
            "evidence_size": _escape(_format_bytes(evidence.get("size_bytes", 0))),
            "display_rate": _escape(_format_rate(display_rate)),
            "self_test_status": "PASSED" if self_test_passed else "FAILED / NOT RUN",
            "self_test_badge": "badge-green" if self_test_passed else "badge-red",
            "baseline_match_badge": "badge-green" if baseline_mismatches == 0 else "badge-red",
            "baseline_match_summary": (
                "%d matched / %d mismatched" % (baseline_matches, baseline_mismatches)
            ),
            "baseline_count": integrity_comparisons,
            "threads": _cell(evidence, "threads_used", "N/A"),
            "engine_path": _escape(stats.get("engine_path", "")),
            "engine_sha256": _escape(stats.get("engine_sha256", "")),
            "simd": _cell(evidence, "simd_tier", "Native runtime dispatch"),
            "aggregate_rate": _escape(_format_rate(aggregate_rate)),
            "optimized_total_time": _escape(_format_ms(file_elapsed_ms)),
            "comparison_optimized_time": _escape(_format_ms(
                baseline_metrics["optimized_elapsed_ms"]
            )),
            "comparison_optimized_rate": _escape(_format_rate(
                baseline_metrics["optimized_throughput_mb_s"]
            )),
            "optimized_cpu": (
                "%.2f %%" % baseline_metrics["optimized_average_cpu"]
                if baseline_metrics["optimized_average_cpu"] is not None else "N/A"
            ),
            "optimized_rss": (
                "%.2f MiB" % baseline_metrics["optimized_peak_rss"]
                if baseline_metrics["optimized_peak_rss"] is not None else "N/A"
            ),
            "baseline_total_time": _escape(_format_ms(baseline_metrics["elapsed_ms"])),
            "baseline_rate": _escape(_format_rate(baseline_metrics["throughput_mb_s"])),
            "baseline_cpu": (
                "%.2f %%" % baseline_metrics["average_cpu"]
                if baseline_metrics["average_cpu"] is not None else "N/A"
            ),
            "baseline_rss": (
                "%.2f MiB" % baseline_metrics["peak_rss"]
                if baseline_metrics["peak_rss"] is not None else "N/A"
            ),
            "baseline_speedup": _escape(_format_speedup(
                baseline_metrics["elapsed_ms"],
                baseline_metrics["optimized_elapsed_ms"],
                "Baseline BLAKE3",
            )),
            "sha256_total_time": _escape(_format_ms(sha256_metrics["elapsed_ms"])),
            "sha256_rate": _escape(_format_rate(sha256_metrics["throughput_mb_s"])),
            "sha256_cpu": (
                "%.2f %%" % sha256_metrics["average_cpu"]
                if sha256_metrics["average_cpu"] is not None else "N/A"
            ),
            "sha256_rss": (
                "%.2f MiB" % sha256_metrics["peak_rss"]
                if sha256_metrics["peak_rss"] is not None else "N/A"
            ),
            "sha256_speedup": _escape(_format_speedup(
                sha256_metrics["elapsed_ms"],
                sha256_metrics["optimized_elapsed_ms"],
                "SHA-256",
            )),
            "sha1_total_time": _escape(_format_ms(sha1_metrics["elapsed_ms"])),
            "sha1_rate": _escape(_format_rate(sha1_metrics["throughput_mb_s"])),
            "sha1_cpu": (
                "%.2f %%" % sha1_metrics["average_cpu"]
                if sha1_metrics["average_cpu"] is not None else "N/A"
            ),
            "sha1_rss": (
                "%.2f MiB" % sha1_metrics["peak_rss"]
                if sha1_metrics["peak_rss"] is not None else "N/A"
            ),
            "sha1_speedup": _escape(_format_speedup(
                sha1_metrics["elapsed_ms"],
                sha1_metrics["optimized_elapsed_ms"],
                "SHA-1",
            )),
            "md5_total_time": _escape(_format_ms(md5_metrics["elapsed_ms"])),
            "md5_rate": _escape(_format_rate(md5_metrics["throughput_mb_s"])),
            "md5_cpu": (
                "%.2f %%" % md5_metrics["average_cpu"]
                if md5_metrics["average_cpu"] is not None else "N/A"
            ),
            "md5_rss": (
                "%.2f MiB" % md5_metrics["peak_rss"]
                if md5_metrics["peak_rss"] is not None else "N/A"
            ),
            "md5_speedup": _escape(_format_speedup(
                md5_metrics["elapsed_ms"],
                md5_metrics["optimized_elapsed_ms"],
                "MD5",
            )),
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
            "evidence_rate": _escape(_format_rate(evidence_rate)),
            "evidence_digest": evidence_digest,
            "evidence_reference_rows": "".join(evidence_reference_rows),
            "evidence_cpu": _escape(_format_percent(
                evidence.get("cpu_utilization_percent")
            )),
            "evidence_rss": _cell(evidence, "peak_rss_mb", "N/A"),
            "evidence_bytes_read": _cell(evidence, "bytes_read", "N/A"),
            "evidence_bytes_expected": _cell(evidence, "size_bytes", "N/A"),
            "file_bytes": _escape(_format_bytes(file_bytes)),
            "file_time": _escape(_format_ms(file_elapsed_ms)),
            "average_cpu": ("%.2f %%" % average_cpu) if average_cpu is not None else "N/A",
            "peak_rss": ("%.2f MiB" % peak_rss) if peak_rss is not None else "N/A",
            "error_count": len(error_files),
            "skipped_count": len(skipped_files),
            "omitted": stats.get("rows_omitted", 0),
            "category_rows": "".join(category_rows),
            "skip_rows": "".join(skip_rows),
            "detail_rows": "".join(detail_rows) or "<tr><td colspan='14'>No file rows recorded.</td></tr>",
            "module": _escape(MODULE_NAME),
            "version": _escape(MODULE_VERSION),
        }

        performance_bytes = baseline_metrics["bytes"]
        html = html.replace(
            "Each algorithm independently re-reads the same sampled Autopsy content objects.",
            "Performance scope: %s; %s. Each algorithm independently re-reads "
            "that exact cohort." % (
                _escape(performance_scope),
                _escape(_format_bytes(performance_bytes)),
            ),
        )
        stats["report_performance_scope"] = performance_scope
        stats["report_performance_bytes"] = performance_bytes

        output = open(html_path, "wb")
        try:
            output.write(html)
        finally:
            output.close()
        audit = open(json_path, "w")
        try:
            audit.write(json.dumps(stats, indent=2, sort_keys=True))
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
        try:
            IngestServices.getInstance().postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    MODULE_NAME,
                    "Failed to generate styled BLAKE3 report: " + str(exc),
                )
            )
        except Exception:
            pass
        return None
