# -*- coding: utf-8 -*-
# AutopsyBLAKE3Ingest.py
#
# Autopsy File Ingest Module: Optimized BLAKE3 Hasher
# -----------------------------------------------------
# Thesis: "Performance Optimization of BLAKE3 for Multi-Format File
#          Hashing in Digital Forensic Investigations"
#
# This Jython module calls the bundled optimized_blake3_hasher.exe for
# every file in an Autopsy case and posts the resulting BLAKE3 hash and
# performance metrics as a custom Blackboard artifact.
#
# Installation:
#   1. Copy the entire BLAKE3_Autopsy_Module/ folder to:
#      %AppData%\autopsy\python_modules\
#      (Open Autopsy > Tools > Python Plugins to find this folder)
#   2. Make sure optimized_blake3_hasher.exe is in the same folder
#      as this script.
#   3. Restart Autopsy.
#   4. Run Ingest > enable "Optimized BLAKE3 Hasher".
#
# Python 2.7 / Jython compatible. Tested on Autopsy 4.22.

import json
import os
import subprocess

import jarray

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
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import Score
from org.sleuthkit.datamodel import TskData


# ---------------------------------------------------------------------------
# Module factory - Autopsy discovers and names the module from here
# ---------------------------------------------------------------------------

class BLAKE3IngestModuleFactory(IngestModuleFactoryAdapter):
    """Factory that Autopsy uses to register and instantiate the module."""

    MODULE_NAME = "Optimized BLAKE3 Hasher"
    MODULE_VERSION = "1.01"
    MODULE_DESCRIPTION = (
        "Hashes each evidence file using an optimized BLAKE3 implementation "
        "with adaptive chunk/buffer handling, multithreaded parallel processing, "
        "and SIMD-aware execution. Results are stored as Blackboard artifacts."
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

    _ARTIFACT_TYPE_NAME = "TSK_INTERESTING_FILE_HIT"

    def __init__(self):
        self._exe_path = None
        self._services = None
        self._blackboard = None
        self._case = None

    def startUp(self, context):
        """Called once before processing begins. Locates the .exe."""

        # Locate the .exe bundled alongside this script
        module_dir = os.path.dirname(os.path.abspath(__file__))
        self._exe_path = os.path.join(module_dir, "optimized_blake3_hasher.exe")

        if not os.path.isfile(self._exe_path):
            raise IngestModule.IngestModuleException(
                "optimized_blake3_hasher.exe not found in: " + module_dir +
                "\nPlease make sure the exe is in the same folder as AutopsyBLAKE3Ingest.py"
            )

        self._services = IngestServices.getInstance()
        self._case = Case.getCurrentCase()
        self._blackboard = self._case.getSleuthkitCase().getBlackboard()

        self._services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                BLAKE3IngestModuleFactory.MODULE_NAME,
                "BLAKE3 Hasher started. Executable: " + self._exe_path,
            )
        )

    def process(self, file):
        """Called for every file. Runs the .exe and posts a Blackboard artifact."""

        # Skip directories, unallocated space, and zero-byte files
        if (file.isDir() or
                file.getSize() == 0 or
                not file.getName() or
                file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS or
                file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS):
            return IngestModule.ProcessResult.OK

        tmp_dir = System.getProperty("java.io.tmpdir")
        tmp_file = os.path.join(tmp_dir, "blake3_tmp_" + str(file.getId()))

        try:
            # Extract file bytes from the case image to a temp file
            input_stream = ReadContentInputStream(file)
            buf = jarray.zeros(4096, "b")
            out_f = open(tmp_file, "wb")
            try:
                while True:
                    read_len = input_stream.read(buf)
                    if read_len == -1:
                        break
                    out_f.write(bytearray(buf[:read_len]))
            finally:
                out_f.close()

            # Run the optimized BLAKE3 exe
            result = self._run_hasher(tmp_file)

            if result is None or result.get("status") != "ok":
                error_msg = result.get("message", "Unknown error") if result else "No output from exe"
                self._services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.WARNING,
                        BLAKE3IngestModuleFactory.MODULE_NAME,
                        "Failed to hash: " + file.getName() + " - " + error_msg,
                    )
                )
                return IngestModule.ProcessResult.OK

            # Post artifact to Blackboard
            self._post_artifact(file, result)

        except Exception as exc:
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
        """Called once after all files are processed."""
        self._services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                BLAKE3IngestModuleFactory.MODULE_NAME,
                "BLAKE3 Hasher finished.",
            )
        )

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _run_hasher(self, file_path):
        """Run optimized_blake3_hasher.exe and return the parsed JSON result."""
        try:
            proc = subprocess.Popen(
                [self._exe_path, file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = proc.communicate()
            output = stdout.strip()
            if not output:
                return None
            return json.loads(output)
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    def _post_artifact(self, file, result):
        """Create a Blackboard artifact using the Autopsy 4.x API."""
        try:
            skCase = self._case.getSleuthkitCase()
            blackboard = skCase.getBlackboard()

            # Use a custom artifact type via the new Blackboard API
            try:
                art_type = blackboard.getOrAddArtifactType(
                    "BLAKE3_HASH_RESULT",
                    "BLAKE3 Hash (Optimized)"
                )
            except Exception:
                art_type = blackboard.getArtifactType("BLAKE3_HASH_RESULT")

            # Build the list of attributes
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
                return BlackboardAttribute(attr_type, BLAKE3IngestModuleFactory.MODULE_NAME, str(value))

            attrs.add(make_attr("BLAKE3_DIGEST",     "BLAKE3 Hash Digest",  result.get("digest", "")))
            attrs.add(make_attr("BLAKE3_SIMD",       "SIMD Tier",           result.get("simd_tier", "")))
            attrs.add(make_attr("BLAKE3_THREADS",    "Threads Used",        str(result.get("threads_used", ""))))
            attrs.add(make_attr("BLAKE3_ELAPSED",    "Execution Time (s)",  str(result.get("elapsed_s", ""))))
            attrs.add(make_attr("BLAKE3_THROUGHPUT", "Throughput (MB/s)",   str(result.get("throughput_mb_s", ""))))
            attrs.add(make_attr("BLAKE3_FILESIZE",   "File Size (bytes)",   str(result.get("file_size_bytes", ""))))

            # Create artifact and post to blackboard
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
