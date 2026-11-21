"""Requests only a running app can answer use what the RVSec exploration executed.

exp_final_20261019 declined 302 of 584 evidence requests as "requires
observing a running program", for findings a running program had produced.
"""
import json
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.integrations.rvsec import attach_coverage, runtime_coverage  # noqa: E402
from cognalys.llm.evidence_requests import resolve_evidence_requests  # noqa: E402

APK = "org.example.app_1.apk"
COVERAGE = {APK: {"monkey:fast": ["org.example.Crypto::digest", "org.example.Crypto::<init>",
                                  "org.example.Login::submit"],
                  "ape:sata": ["org.example.Crypto::digest"]}}


class RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_coverage_is_written_beside_the_findings_and_referenced(self):
        findings = self.root / "findings.jsonl"
        findings.write_text(json.dumps({"apk": APK, "class": "org.example.Crypto"}) + "\n")
        target = attach_coverage(findings, COVERAGE)
        record = json.loads(findings.read_text().splitlines()[0])
        self.assertEqual(record["detector_runtime_coverage_file"], str(target.resolve()))
        self.assertIn(("org.example.Crypto", "digest"), runtime_coverage(str(target), APK)["monkey:fast"])

    def _target(self):
        coverage = self.root / "findings.coverage.json"
        coverage.write_text(json.dumps(COVERAGE))
        return {"apk_name": APK, "csv_class": "org.example.Crypto",
                "detector_context": {"runtime_coverage_file": str(coverage)}}

    def test_a_runtime_request_is_answered_from_the_coverage(self):
        request = {"kind": "runtime_execution_path",
                   "symbol": "Login.submit() and Settings.export()",
                   "reason": "whether the digest runs when the user logs in at runtime"}
        result = resolve_evidence_requests(self.root, [request], set(), target=self._target())
        self.assertEqual(result["declined"], [])
        content = result["entries"][0]["data"]["content"]
        self.assertEqual(result["entries"][0]["trust_level"], "runtime_trace")
        self.assertIn("in org.example.Crypto: <init>, digest", content)
        self.assertIn("submit: org.example.Login.submit", content)
        self.assertIn("export: not executed", content)

    def test_without_coverage_a_runtime_request_is_still_declined(self):
        request = {"kind": "runtime_execution_path", "symbol": "Login.submit()",
                   "reason": "at runtime"}
        result = resolve_evidence_requests(self.root, [request], set(), target={"apk_name": APK})
        self.assertEqual(result["entries"], [])
        self.assertIn("running program", result["declined"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
