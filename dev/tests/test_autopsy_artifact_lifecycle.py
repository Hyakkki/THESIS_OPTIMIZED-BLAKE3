"""Test bridge lifecycle code without requiring a live Autopsy/Jython process."""
import ast
import datetime
import json
from pathlib import Path
import threading
import types
import unittest


class ArtifactLifecycleTests(unittest.TestCase):
    def setUp(self):
        path = (Path(__file__).resolve().parents[2] / "autopsy_plugin" /
                "BLAKE3_Autopsy_Module" / "blake3_ingest_module.py")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {"_new_job", "_job", "_queue_artifact", "_flush_artifacts",
                 "_audit_stats", "_BLAKE3ReportListener"}
        selected = ast.Module(body=[node for node in tree.body
                                   if getattr(node, "name", None) in names],
                              type_ignores=[])
        self.posted = []
        self.reports = []
        self.workers = []
        self.removed = []
        self.messages = []
        manager = types.SimpleNamespace(
            removeIngestJobEventListener=self.removed.append)
        events = types.SimpleNamespace(**{
            key: types.SimpleNamespace(toString=lambda value=key: value)
            for key in ("DATA_SOURCE_ANALYSIS_COMPLETED", "COMPLETED")})
        owner = self

        class Worker:
            def __init__(self, target):
                self.target = target

            def start(self):
                owner.workers.append(self)

        self.env = dict(
            datetime=datetime, MODULE_BUILD="test", MODULE_NAME="test",
            _JOBS={}, _JOBS_LOCK=threading.RLock(), _REPORT_LISTENERS={},
            PropertyChangeListener=object,
            threading=types.SimpleNamespace(Thread=Worker),
            IngestManager=types.SimpleNamespace(
                IngestJobEvent=events, getInstance=lambda: manager),
            IngestServices=types.SimpleNamespace(getInstance=lambda:
                types.SimpleNamespace(postMessage=self.messages.append)),
            IngestMessage=types.SimpleNamespace(
                MessageType=types.SimpleNamespace(WARNING="warning", ERROR="error"),
                createMessage=lambda *args: args),
            _generate_report=self.reports.append,
        )

        def post(blackboard, content, row):
            self.assertFalse(self.env["_JOBS_LOCK"]._is_owned())
            self.posted.append((content, row["digest"]))

        self.env["_post_artifact"] = post
        exec(compile(selected, str(path), "exec"), self.env)
        self.listener = self.env["_BLAKE3ReportListener"](7, 10)

    def queue(self, source=10):
        self.env["_queue_artifact"](7, source, object(), object(),
                                    {"object_id": 42, "digest": "abc"})

    def event(self, job=7, source=10, result="ANALYSIS_COMPLETED"):
        # In Autopsy 4.22.1 newValue is null for this typed event.
        return types.SimpleNamespace(
            getPropertyName=lambda: "DATA_SOURCE_ANALYSIS_COMPLETED",
            getNewValue=lambda: None, getIngestJobId=lambda: job,
            getDataSource=lambda: types.SimpleNamespace(getId=lambda: source),
            getResult=lambda: result)

    def test_queue_does_not_write_during_ingest(self):
        self.queue()
        self.assertEqual(self.posted, [])
        self.assertEqual(len(self.env["_job"](7)["pending_artifacts"]), 1)

    def test_matching_completion_posts_once_and_then_reports(self):
        self.queue()
        self.listener.propertyChange(self.event())
        self.listener.propertyChange(self.event())
        self.assertEqual(len(self.workers), 1)
        self.assertEqual(self.posted, [])
        self.workers[0].target()
        self.assertEqual(len(self.posted), 1)
        self.assertEqual(self.reports, [7])
        self.assertEqual(self.env["_job"](7)["artifacts_posted"], 1)
        self.assertEqual(self.removed, [self.listener])

    def test_other_job_or_source_cannot_finalize(self):
        self.queue()
        self.listener.propertyChange(self.event(job=8))
        self.listener.propertyChange(self.event(source=11))
        self.listener.propertyChange(types.SimpleNamespace(
            getPropertyName=lambda: "COMPLETED", getOldValue=lambda: 8))
        self.assertEqual(self.workers, [])

    def test_two_sources_each_publish_before_one_combined_report(self):
        self.queue()
        self.queue(source=11)
        other = self.env["_BLAKE3ReportListener"](7, 11)
        self.listener.propertyChange(self.event())
        other.propertyChange(self.event(source=11))
        self.workers[0].target()
        self.assertEqual(self.reports, [])
        self.workers[1].target()
        self.assertEqual(len(self.posted), 2)
        self.assertEqual(self.reports, [7])

    def test_cancelled_analysis_does_not_publish(self):
        self.queue()
        self.listener.propertyChange(self.event(result="ANALYSIS_CANCELLED"))
        self.assertEqual(self.workers, [])
        self.assertEqual(self.posted, [])

    def test_flush_only_drains_matching_source(self):
        self.queue()
        self.queue(source=11)
        self.env["_flush_artifacts"](7, 10)
        self.assertEqual(len(self.posted), 1)
        self.assertEqual(self.env["_job"](7)["pending_artifacts"][0][0], 11)

    def test_publication_failure_keeps_hash_results_and_reports_error(self):
        self.queue()
        self.queue()
        original = self.env["_post_artifact"]
        attempts = []

        def post(*args):
            attempts.append(1)
            if len(attempts) == 1:
                raise RuntimeError("database unavailable")
            original(*args)

        self.env["_post_artifact"] = post
        self.env["_flush_artifacts"](7, 10)
        stats = self.env["_job"](7)
        self.assertEqual(stats["artifacts_posted"], 1)
        self.assertEqual(len(stats["artifact_errors"]), 1)
        self.assertEqual(len(self.messages), 1)
        self.assertEqual(stats["errors"], 0)

    def test_audit_contains_no_runtime_handles(self):
        self.queue()
        audit = self.env["_audit_stats"](self.env["_job"](7))
        json.dumps(audit)
        self.assertEqual(audit["pending_artifact_count"], 1)
        self.assertNotIn("pending_artifacts", audit)


if __name__ == "__main__":
    unittest.main()
