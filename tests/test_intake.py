import contextlib
import csv
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import cli, intake  # noqa: E402
from cognalys.orchestration import run_pipeline  # noqa: E402
from cognalys.sources import SOURCE_PROBLEM, read_rows  # noqa: E402
from cognalys.utils.corpus_rows import row_problems  # noqa: E402

SOURCE = "app/src/main/java/org/app/crypto/Hasher.java"
JAVA = """package org.app.crypto;

import java.security.MessageDigest;

public class Hasher {
    private static final String NAME = "x";

    public byte[] digest(byte[] input) throws Exception {
        return MessageDigest.getInstance("MD5").digest(input);
    }
}
"""


def _checkout(directory: Path) -> Path:
    repo = directory / "myapp"
    (repo / SOURCE).parent.mkdir(parents=True)
    (repo / SOURCE).write_text(JAVA, encoding="utf-8")
    for arguments in (["init", "-q", "-b", "main"], ["config", "user.email", "t@x.invalid"],
                      ["config", "user.name", "T"], ["add", "-A"], ["commit", "-qm", "app"]):
        subprocess.run(["git", *arguments], cwd=repo, check=True, capture_output=True)
    return repo


def _csv(path: Path, rows) -> Path:
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return path


SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "CodeQL"}},
        "results": [{
            "ruleId": "java/weak-cryptographic-algorithm",
            "level": "error",
            "message": {"text": "MD5 is broken"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": SOURCE}, "region": {"startLine": 9}}}],
        }, {
            "ruleId": "java/constant",
            "message": {"text": "a field"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": SOURCE}, "region": {"startLine": 6}}}],
        }],
    }],
}

SEMGREP = {"results": [{
    "check_id": "rules.message-digest-non-allowlisted-literal-algorithm",
    "path": f"/home/someone/scan/myapp/{SOURCE}",
    "start": {"line": 9}, "extra": {"message": "MD5", "severity": "WARNING"},
}], "errors": []}


class IntakeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.repo = _checkout(self.root)

    def tearDown(self):
        self.directory.cleanup()

    def test_a_sarif_report_is_resolved_against_the_checkout(self):
        report = self.root / "codeql.sarif"
        report.write_text(json.dumps(SARIF), encoding="utf-8")
        taken = intake.read_findings([report], self.repo)
        [row] = taken.rows
        self.assertEqual((row["apk"], row["class"], row["method"]),
                         ("myapp.apk", "org.app.crypto.Hasher", "digest"))
        self.assertEqual(row["spec"], "java_weak-cryptographic-algorithm")
        self.assertEqual(row["detector_code"], "java/weak-cryptographic-algorithm")
        self.assertEqual(row["tool"], "static:codeql")
        self.assertEqual(row["findings_source"], "codeql.sarif:1")
        self.assertEqual(len(row["commit"]), 40)
        self.assertEqual(row_problems(row), [])
        # Line 6 is a field: no method to repair, said rather than guessed.
        [problem] = taken.problems
        self.assertIn("not inside a method", problem["problem"])

    def test_a_semgrep_report_names_files_from_where_it_ran(self):
        report = self.root / "semgrep.json"
        report.write_text(json.dumps(SEMGREP), encoding="utf-8")
        [row] = intake.read_findings([report], self.repo).rows
        # One of cognalys's own rules: read back as its specification.
        self.assertEqual(row["spec"], "MessageDigestSpec")
        self.assertEqual(row["source_file"], SOURCE)
        self.assertEqual(row["method"], "digest")

    def test_other_column_names_are_read_as_the_corpus_ones(self):
        sheet = _csv(self.root / "export.csv", [{
            "apk_name": "myapp", "className": "org.app.crypto.Hasher",
            "method_name": "digest", "rule_id": "MessageDigestSpec",
            "description": "MD5", "repository": "https://github.com/o/myapp",
            "sha": "0123456789abcdef0123456789abcdef01234567"}])
        taken = intake.read_findings([sheet])
        [row] = taken.rows
        self.assertEqual(row["class"], "org.app.crypto.Hasher")
        self.assertEqual(row["spec"], "MessageDigestSpec")
        self.assertEqual(row["repo_url"], "https://github.com/o/myapp")
        self.assertEqual(row["apk"], "myapp.apk")
        self.assertEqual(taken.renamed["className"], "class")

    def test_reports_in_one_method_are_one_finding(self):
        sarif = self.root / "semgrep.sarif"
        sarif.write_text(json.dumps({"runs": [{
            "tool": {"driver": {"name": "Semgrep OSS"}},
            "results": [{"ruleId": "home.me.rules.weak-digest", "message": {"text": "MD5"},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": SOURCE},
                             "region": {"startLine": line}}}]} for line in (8, 9)]}]}),
            encoding="utf-8")
        semgrep = self.root / "semgrep.json"
        semgrep.write_text(json.dumps({"results": [{
            "check_id": "home.me.rules.weak-digest", "path": SOURCE,
            "start": {"line": 9}, "extra": {"message": "MD5"}}]}), encoding="utf-8")
        [row] = intake.read_findings([sarif, semgrep], self.repo).rows
        self.assertEqual(row["spec"], "weak-digest")
        self.assertEqual(row["line"], "8; 9")
        self.assertEqual(row["findings_source"], "semgrep.sarif:1; semgrep.sarif:2; semgrep.json:1")

    def test_a_corpus_column_wins_over_an_alias_of_it(self):
        row = intake.apply_aliases({"class": "a.B", "className": "c.D"})
        self.assertEqual(row["class"], "a.B")
        self.assertEqual(row["className"], "c.D")

    def test_a_location_without_a_checkout_is_a_problem(self):
        sheet = _csv(self.root / "lines.csv", [{
            "apk": "myapp.apk", "spec": "S", "file": SOURCE, "line": "9"}])
        taken = intake.read_findings([sheet])
        self.assertEqual(taken.rows, [])
        self.assertIn("--repo", taken.problems[0]["problem"])

    def test_several_files_keep_where_each_row_came_from(self):
        first = _csv(self.root / "a.csv", [{
            "apk": "x.apk", "class": "a.B", "method": "m", "spec": "S"}])
        second = self.root / "b.jsonl"
        second.write_text(json.dumps({"apk": "y.apk", "class": "c.D", "method": "n",
                                      "spec": "T"}) + "\n{not json\n", encoding="utf-8")
        taken = intake.read_findings([first, second])
        self.assertEqual([row["findings_source"] for row in taken.rows], ["a.csv:2", "b.jsonl:1"])
        self.assertEqual([problem["source"] for problem in taken.problems], ["b.jsonl:2"])

    def test_check_names_the_closest_column(self):
        sheet = _csv(self.root / "odd.csv", [{
            "apk": "x.apk", "klass": "a.B", "method": "m", "spec": "S"}])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["check", str(sheet)])
        self.assertEqual(code, 2)
        self.assertIn("missing class", out.getvalue())
        self.assertIn("is 'klass' it?", out.getvalue())

    def test_the_template_passes_check_with_its_checkout(self):
        path = self.root / "t.csv"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["template", "-o", str(path)]), 0)
        rows = read_rows(path)
        self.assertEqual({row["spec"] for row in rows}, {"MessageDigestSpec", "CipherSpec"})
        taken = intake.read_findings([path])
        self.assertEqual(len(taken.rows), 1)


class PipelineIntakeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def _args(self, *argv):
        return run_pipeline.parse_args(["--llm-provider", "openai", 
            *argv, "--extracted-methods-dir", str(self.root / "run" / "error_methods")])

    def test_findings_is_repeatable(self):
        args = self._args("--findings", "a.csv", "--findings", "b.sarif")
        self.assertEqual(args.csv_file, "a.csv")
        self.assertEqual(args.findings_files, ["a.csv", "b.sarif"])

    def test_a_file_in_the_corpus_columns_is_read_where_it_is(self):
        sheet = _csv(self.root / "a.csv", [{
            "apk": "x.apk", "class": "a.B", "method": "m", "spec": "S"}])
        self.assertFalse(run_pipeline.needs_intake(self._args("--findings", str(sheet)), self.root))

    def test_several_files_become_one_with_the_problems_kept(self):
        first = _csv(self.root / "a.csv", [{
            "apk": "x.apk", "class": "a.B", "method": "m", "spec": "S"}])
        second = _csv(self.root / "b.csv", [{"apk": "y.apk", "spec": "T"}])
        args = self._args("--findings", str(first), "--findings", str(second))
        self.assertTrue(run_pipeline.needs_intake(args, self.root))
        with contextlib.redirect_stderr(io.StringIO()):
            path = run_pipeline.materialize_intake(args, self.root)
        rows = read_rows(path)
        self.assertEqual(path, self.root / "run" / "findings.jsonl")
        self.assertEqual(rows[0]["class"], "a.B")
        self.assertIn("missing class, method", rows[1][SOURCE_PROBLEM])
        self.assertEqual(row_problems(rows[1]), [rows[1][SOURCE_PROBLEM]])


if __name__ == "__main__":
    unittest.main()
