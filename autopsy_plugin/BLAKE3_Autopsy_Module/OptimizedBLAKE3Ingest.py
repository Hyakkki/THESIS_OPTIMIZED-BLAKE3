# -*- coding: utf-8 -*-
# AutopsyBLAKE3Ingest.py
#
# Autopsy File Ingest Module: Optimized BLAKE3 Hasher
# -----------------------------------------------------
# Thesis: "Performance Optimization of BLAKE3 for Multi-Format File
#          Hashing in Digital Forensic Investigations"
#
# Architecture: Sidecar-Executable Bridge
#   The bundled optimized_blake3_hasher.exe is launched ONCE at ingest
#   startup in --server mode.  For each evidence file, the Jython module
#   sends the temp-file path over stdin and reads one JSON result from
#   stdout.  This eliminates the ~100-300 ms per-file process-startup
#   overhead that the old single-shot approach suffered from.
#
# Installation:
#   1. Copy the entire BLAKE3_Autopsy_Module/ folder to:
#      %AppData%\autopsy\python_modules\
#      (Open Autopsy > Tools > Python Plugins to find this folder)
#   2. Make sure optimized_blake3_hasher.exe is in the same folder.
#   3. Restart Autopsy.
#   4. Run Ingest > enable "Optimized BLAKE3 Hasher".
#
# Python 2.7 / Jython compatible. Tested on Autopsy 4.22.

import json
import os
import subprocess

from jarray import zeros

from java.lang import System
from java.util import ArrayList
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData


# ---------------------------------------------------------------------------
# Module factory - Autopsy discovers and names the module from here
# ---------------------------------------------------------------------------

class BLAKE3IngestModuleFactory(IngestModuleFactoryAdapter):
    """Factory that Autopsy uses to register and instantiate the module."""

    MODULE_NAME = "Optimized BLAKE3 Hasher"
    MODULE_VERSION = "2.01"
    MODULE_DESCRIPTION = (
        "Hashes each evidence file using an optimized BLAKE3 implementation "
        "with adaptive chunk/buffer handling, multithreaded parallel processing, "
        "and SIMD-aware execution. The hashing engine runs as a persistent "
        "sidecar process to eliminate per-file startup overhead. "
        "Results are stored as Blackboard artifacts."
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


# ---------------------------------------------------------------------------
# Ingest module - runs for every file in the case
# ---------------------------------------------------------------------------

class BLAKE3FileIngestModule(FileIngestModule):
    """File-level ingest module that computes an optimized BLAKE3 hash."""

    def __init__(self):
        self._exe_path = None
        self._services = None
        self._blackboard = None
        self._case = None
        self._proc = None       # persistent server process
        self._files_done = 0
        self._files_error = 0

    def startUp(self, context):
        """Called once before processing begins. Starts the persistent exe server."""

        module_dir = os.path.dirname(os.path.abspath(__file__))
        self._exe_path = os.path.join(module_dir, "optimized_blake3_hasher.exe")

        if not os.path.isfile(self._exe_path):
            raise IngestModule.IngestModuleException(
                "optimized_blake3_hasher.exe not found in: " + module_dir
            )

        self._services = IngestServices.getInstance()
        self._case = Case.getCurrentCase()
        self._blackboard = self._case.getSleuthkitCase().getBlackboard()

        # Start the exe once in server mode -- it will stay running for the
        # entire ingest session, reading file paths from stdin.
        self._proc = subprocess.Popen(
            [self._exe_path, "--server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self._services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                BLAKE3IngestModuleFactory.MODULE_NAME,
                "BLAKE3 Hasher started (server mode). Executable: " + self._exe_path,
            )
        )

    def process(self, file):
        """Called for every file. Sends path to the server, reads JSON result."""

        # Skip directories, unallocated space, and zero-byte files
        if (file.isDir() or
                file.getSize() == 0 or
                not file.getName() or
                file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS or
                file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS):
            return IngestModule.ProcessResult.OK

        # If server process died, skip gracefully
        if self._proc is None or self._proc.poll() is not None:
            self._files_error += 1
            return IngestModule.ProcessResult.OK

        tmp_dir = System.getProperty("java.io.tmpdir")
        tmp_file = os.path.join(tmp_dir, "blake3_tmp_" + str(file.getId()))

        try:
            # Extract file bytes from the case image using file.read().
            # Apply & 0xFF to convert Java signed bytes (-128..127) to
            # Python unsigned bytes (0..255).
            READ_BUF = 65536
            size_bytes = file.getSize()
            buf = zeros(READ_BUF, 'b')
            offset = 0
            out_f = open(tmp_file, 'wb')
            try:
                while offset < size_bytes:
                    to_read = min(READ_BUF, size_bytes - offset)
                    n_read = file.read(buf, offset, to_read)
                    if n_read <= 0:
                        break
                    out_f.write(bytearray([(b & 0xFF) for b in buf[:n_read]]))
                    offset += n_read
            finally:
                out_f.close()

            # Send the temp file path to the persistent server process
            result = self._run_hasher_server(tmp_file)

            if result is None or result.get("status") != "ok":
                error_msg = result.get("message", "Unknown error") if result else "No output from server"
                self._services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.WARNING,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "Failed to hash: " + file.getName() + " - " + error_msg,
                    )
                )
                self._files_error += 1
                return IngestModule.ProcessResult.OK

            # Post artifact to Blackboard
            self._post_artifact(file, result)
            self._files_done += 1

        except Exception as exc:
            self._files_error += 1
            self._services.postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    BLAKE3IngestModuleFactory.MODULE_NAME,
                    "Error processing " + file.getName() + ": " + str(exc),
                )
            )
        finally:
            try:
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)
            except Exception:
                pass

        return IngestModule.ProcessResult.OK

    def shutDown(self):
        """Called once after all files are processed. Shuts down the server."""
        if self._proc is not None:
            try:
                self._proc.stdin.close()
                self._proc.wait()
            except Exception:
                try:
                    self._proc.terminate()
                except Exception:
                    pass

        summary = (
            "BLAKE3 Hasher finished. "
            "Hashed: " + str(self._files_done) +
            "  Errors: " + str(self._files_error)
        )
        self._services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                BLAKE3IngestModuleFactory.MODULE_NAME,
                summary,
            )
        )

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _run_hasher_server(self, file_path):
        """
        Send a file path to the persistent server process and read one JSON result.
        Falls back to None on any I/O error.
        """
        try:
            line_in = (file_path + "\n").encode("utf-8")
            self._proc.stdin.write(line_in)
            self._proc.stdin.flush()
            line_out = self._proc.stdout.readline()
            if not line_out:
                return None
            return json.loads(line_out.strip())
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    def _post_artifact(self, file, result):
        """Create a custom Blackboard artifact for the BLAKE3 hash result."""
        try:
            skCase = self._case.getSleuthkitCase()
            blackboard = skCase.getBlackboard()

            try:
                art_type = blackboard.getOrAddArtifactType(
                    "BLAKE3_HASH_RESULT",
                    "BLAKE3 Hash (Optimized)"
                )
            except Exception:
                art_type = blackboard.getArtifactType("BLAKE3_HASH_RESULT")

            attrs = ArrayList()

            def make_attr(type_name, display_name, value):
                try:
                    attr_type = blackboard.getOrAddAttributeType(
                        type_name,
                        BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                        display_name
                    )
                except Exception:
                    attr_type = blackboard.getAttributeType(type_name)
                return BlackboardAttribute(
                    attr_type,
                    BLAKE3IngestModuleFactory.MODULE_NAME,
                    str(value)
                )

            attrs.add(make_attr("BLAKE3_DIGEST",     "BLAKE3 Hash Digest",  result.get("digest", "")))
            attrs.add(make_attr("BLAKE3_SIMD",       "SIMD Tier",           result.get("simd_tier", "")))
            attrs.add(make_attr("BLAKE3_THREADS",    "Threads Used",        str(result.get("threads_used", ""))))
            attrs.add(make_attr("BLAKE3_ELAPSED",    "Execution Time (s)",  str(result.get("elapsed_s", ""))))
            attrs.add(make_attr("BLAKE3_THROUGHPUT", "Throughput (MB/s)",   str(result.get("throughput_mb_s", ""))))
            attrs.add(make_attr("BLAKE3_FILESIZE",   "File Size (bytes)",   str(result.get("file_size_bytes", ""))))

            artifact = file.newArtifact(art_type.getTypeID())
            artifact.addAttributes(attrs)
            blackboard.postArtifact(artifact, BLAKE3IngestModuleFactory.MODULE_NAME)

        except Exception as exc:
            self._services.postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    BLAKE3IngestModuleFactory.MODULE_NAME,
                    "Failed to post artifact for " + file.getName() + ": " + str(exc),
                )
            )
