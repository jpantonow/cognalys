"""The findings runs left without a fix, written back as a findings file."""
import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.models import FindingResult, RunResult  # noqa: E402
from cognalys.reporting.unpatched import write_unpatched  # noqa: E402

COLUMNS = ["apk", "rep", "class", "method", "spec", "message"]


def result(method, outcome):
    return FindingResult(apk="a.apk", csv_class="a.C", method=method, spec="MessageDigestSpec",
                         outcome=outcome)


class UnpatchedTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        findings = self.root / "findings.csv"
        with findings.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=COLUMNS)
            writer.writeheader()
            for method in ("fixed", "refused", "contract", "failed_build"):
                writer.writerow({"apk": "a.apk", "rep": "1", "class": "a.C", "method": method,
                                 "spec": "MessageDigestSpec", "message": "found SHA-1"})
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()
        (self.run_dir / "run_inputs.json").write_text(
            json.dumps({"findings_csv": str(findings)}), encoding="utf-8")
        outcomes = RunResult(runs=(self.run_dir,), findings=(
            result("fixed", "PR pronto"),
            result("refused", "violação confirmada sem correção segura"),
            result("contract", "contrato externo impede a correção"),
            result("failed_build", "correção gerada, sem PR"),
            result("not_in_inputs", "evidência insuficiente"),
        ))
        patcher = mock.patch("cognalys.api.load_results", return_value=outcomes)
        patcher.start()
        self.addCleanup(patcher.stop)

    def written(self, include=()):
        output = self.root / "out" / "unpatched.csv"
        report = write_unpatched([self.run_dir], output, include)
        with output.open(newline="", encoding="utf-8") as handle:
            return report, list(csv.DictReader(handle))

    def test_only_unsettled_findings_are_written_with_their_original_row(self):
        report, rows = self.written()
        self.assertEqual([row["method"] for row in rows], ["failed_build", "refused"])
        self.assertEqual(rows[0]["message"], "found SHA-1")
        self.assertEqual([f.method for f in report["missing"]], ["not_in_inputs"])

    def test_an_issue_over_an_external_contract_stays_settled(self):
        contract_issue = FindingResult(
            apk="a.apk", csv_class="a.C", method="contract", spec="MessageDigestSpec",
            outcome="issue para o mantenedor do app",
            decision="EXTERNAL_DIGEST_CONTRACT_NO_CLIENT_ONLY_FIX")
        with mock.patch("cognalys.api.load_results",
                        return_value=RunResult(runs=(self.run_dir,), findings=(contract_issue,))):
            report = write_unpatched([self.run_dir], self.root / "c.csv")
        self.assertEqual(report["kept"], [])

    def test_a_pull_request_opened_in_any_run_settles_the_finding(self):
        prs = self.run_dir / "pull_requests"
        prs.mkdir()
        (prs / "a.apk_refused_MessageDigestSpec_pr.json").write_text(
            json.dumps({"method_name": "refused", "spec": "MessageDigestSpec"}), encoding="utf-8")
        (prs / "a.apk_refused_MessageDigestSpec_pr_created.json").write_text(
            json.dumps({"number": 2}), encoding="utf-8")
        _, rows = self.written()
        self.assertEqual([row["method"] for row in rows], ["failed_build"])

    def test_a_settled_outcome_can_be_included(self):
        _, rows = self.written(include=["contrato externo impede a correção"])
        self.assertIn("contract", [row["method"] for row in rows])


if __name__ == "__main__":
    unittest.main()
