"""Rules the model proposes are kept only when real code agrees with them.

And once kept, a rule does not change between runs without a reason: the
second half of these tests pins when a specification is asked again.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.validation import rule_proposal  # noqa: E402
from cognalys.validation import semgrep_rules  # noqa: E402
from cognalys.validation.rule_proposal import FIRES, SILENT, Case  # noqa: E402


VULNERABLE = """package app;
class Loader {
    void onCreate() {
        android.webkit.WebView.setWebContentsDebuggingEnabled(true);
    }
}
"""
FIXED = """package app;
class Loader {
    void onCreate() {
        if (BuildConfig.DEBUG) {
            android.webkit.WebView.setWebContentsDebuggingEnabled(true);
        }
    }
}
"""
RULE = """rules:
  - id: debugging-enabled
    languages: [java, kotlin]
    severity: WARNING
    message: debugging enabled without a debug guard
    patterns:
      - pattern: android.webkit.WebView.setWebContentsDebuggingEnabled(true)
      - pattern-not-inside: |
          if (<... BuildConfig.DEBUG ...>) { ... }
"""


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def advisory_extraction(root: Path) -> Path:
    """A finding pinned at its vulnerable commit, fixed later on `main`."""
    repo = root / "clone"
    source = repo / "app" / "Loader.java"
    source.parent.mkdir(parents=True)
    git(repo.parent, "init", "-q", "-b", "main", str(repo))
    source.write_text(VULNERABLE, encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "vulnerable")
    pinned = git(repo, "rev-parse", "HEAD")
    source.write_text(FIXED, encoding="utf-8")
    git(repo, "commit", "-q", "-am", "fix")
    record = root / "run_1" / "error_methods" / "app.apk" / "0_onCreate.json"
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps({
        "extraction_metadata": {
            "apk_name": "app.apk", "extraction_status": "success",
            "repository_path": str(repo), "pinned_revision": pinned,
            "contribution_base": {"base_ref": "main"},
        },
        "error": {"spec": "DebugSpec", "csv_class": "app.Loader",
                  "csv_method": "onCreate", "tool": "external_advisory",
                  "error_message": "External finding (CVE-2024-12345): debugging"},
        "class_info": {"source_file_path": "app/Loader.java"},
        "method_info": {"source_name": "onCreate"},
    }), encoding="utf-8")
    return record


class FindingCaseTests(unittest.TestCase):
    def test_an_advisory_gives_its_vulnerable_and_its_fixed_method(self):
        with tempfile.TemporaryDirectory() as directory:
            record = advisory_extraction(Path(directory))
            cases = rule_proposal.finding_cases("DebugSpec", [record])
        self.assertEqual([(case.origin, case.expected, case.required) for case in cases],
                         [("finding", FIRES, True), ("fixed_revision", SILENT, False)])
        self.assertIn("setWebContentsDebuggingEnabled(true);\n    }", cases[0].content)
        self.assertIn("BuildConfig.DEBUG", cases[1].content)

    def test_another_specification_contributes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            record = advisory_extraction(Path(directory))
            self.assertEqual(rule_proposal.finding_cases("OtherSpec", [record]), [])


def result(origin, expected, got, required=True):
    return {"label": origin, "origin": origin, "expected": expected, "got": got,
            "required": required, "detail": ""}


EXAMPLES = [result("example", FIRES, FIRES), result("example", FIRES, FIRES),
            result("example", SILENT, SILENT), result("example", SILENT, SILENT)]


class VerdictTests(unittest.TestCase):
    def test_agreement_on_every_case_accepts(self):
        accepted, problems = rule_proposal.verdict(
            [result("finding", FIRES, FIRES), *EXAMPLES])
        self.assertTrue(accepted, problems)

    def test_firing_on_a_required_silent_case_rejects(self):
        accepted, problems = rule_proposal.verdict([
            result("finding", FIRES, FIRES),
            result("example", SILENT, FIRES), *EXAMPLES])
        self.assertFalse(accepted)
        self.assertIn("stay silent", problems[0])

    def test_a_later_revision_that_still_fires_does_not_reject(self):
        # Omni-Notes' method changed after CVE-2023-33188 only in how it
        # spelled a Toast constant; the fix went elsewhere.
        accepted, _ = rule_proposal.verdict([
            result("finding", FIRES, FIRES),
            result("fixed_revision", SILENT, FIRES, required=False), *EXAMPLES])
        self.assertTrue(accepted)

    def test_an_unvouched_finding_may_be_missed_but_not_all_of_them(self):
        accepted, _ = rule_proposal.verdict([
            result("finding", FIRES, SILENT, required=False),
            result("finding", FIRES, FIRES, required=False), *EXAMPLES])
        self.assertTrue(accepted)
        accepted, problems = rule_proposal.verdict([
            result("finding", FIRES, SILENT, required=False), *EXAMPLES])
        self.assertFalse(accepted)
        self.assertIn("fires on none of the reported findings", problems[0])

    def test_too_few_examples_reject(self):
        accepted, problems = rule_proposal.verdict([result("finding", FIRES, FIRES)])
        self.assertFalse(accepted)

    def test_a_semgrep_error_always_rejects(self):
        accepted, _ = rule_proposal.verdict([
            result("finding", FIRES, FIRES),
            result("example", SILENT, "error", required=False), *EXAMPLES])
        self.assertFalse(accepted)


class ShapeTests(unittest.TestCase):
    def test_a_rule_for_another_language_is_refused(self):
        self.assertTrue(rule_proposal.rule_shape_issues(
            RULE.replace("[java, kotlin]", "[python]")))
        self.assertEqual(rule_proposal.rule_shape_issues(RULE), [])


class ProposalLoopTests(unittest.TestCase):
    CASES = [Case("finding", "finding", FIRES, "Loader.java", VULNERABLE, "onCreate")]

    def test_a_failing_rule_is_retried_with_the_failures(self):
        prompts = []

        def generate(prompt, _schema):
            prompts.append(prompt)
            return {"decision": "rule", "reason": "local", "rule_yaml": RULE, "examples": []}

        def evaluate(_rule, _spec, cases):
            ok = len(prompts) > 1
            return [result(case.origin, case.expected,
                           case.expected if ok else SILENT) for case in cases] + EXAMPLES

        outcome = rule_proposal.propose_rule("DebugSpec", {}, self.CASES, generate, {},
                                             evaluate_rule=evaluate)
        self.assertEqual((outcome["status"], outcome["attempts"]), ("accepted", 2))
        self.assertIn("previous_attempt_failed", prompts[1])

    def test_not_local_ends_without_a_rule(self):
        outcome = rule_proposal.propose_rule(
            "DebugSpec", {}, self.CASES,
            lambda *_: {"decision": "not_local", "reason": "repair is in gradle",
                        "rule_yaml": "", "examples": []}, {})
        self.assertEqual(outcome["status"], "not_local")

    def test_exhausted_attempts_are_rejected(self):
        outcome = rule_proposal.propose_rule(
            "DebugSpec", {}, self.CASES,
            lambda *_: {"decision": "rule", "reason": "", "rule_yaml": "nonsense",
                        "examples": []}, {}, attempts=2)
        self.assertEqual((outcome["status"], outcome["attempts"]), ("rejected", 2))


class ConsistencyTests(unittest.TestCase):
    def provenance(self, **entry):
        return {"rules": {"DebugSpec": {"specification_sha256": "s1",
                                         "case_fingerprints": ["f1", "f2"], **entry}}}

    def test_a_hand_written_rule_is_never_touched(self):
        self.assertTrue(rule_proposal.skip_reason(
            "DebugSpec", "s1", ["f1"], {"rules": {}}, rule_exists=True, replace=True))

    def test_an_accepted_rule_changes_only_when_asked(self):
        provenance = self.provenance(status="accepted")
        self.assertTrue(rule_proposal.skip_reason("DebugSpec", "s2", ["f3"], provenance, True))
        self.assertEqual(rule_proposal.skip_reason(
            "DebugSpec", "s1", ["f1"], provenance, True, replace=True), "")

    def test_not_local_is_asked_again_only_for_a_changed_specification(self):
        provenance = self.provenance(status="not_local")
        self.assertTrue(rule_proposal.skip_reason("DebugSpec", "s1", ["f3"], provenance, False))
        self.assertEqual(rule_proposal.skip_reason("DebugSpec", "s2", ["f1"], provenance, False), "")

    def test_rejected_is_asked_again_only_with_new_evidence(self):
        provenance = self.provenance(status="rejected")
        # Fewer cases than before (a clone was pruned) is not new evidence.
        self.assertTrue(rule_proposal.skip_reason("DebugSpec", "s2", ["f1"], provenance, False))
        self.assertEqual(rule_proposal.skip_reason(
            "DebugSpec", "s1", ["f1", "f3"], provenance, False), "")

    def test_an_accepted_rule_is_written_with_its_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provenance = {"rules": {}}
            entry = rule_proposal.record_outcome(
                "DebugSpec",
                {"status": "accepted", "rule_text": RULE, "reason": "local repair",
                 "results": [result("finding", FIRES, FIRES)], "attempts": 1},
                provenance, "s1", ["f1"], "model-x",
                rules_directory=root, provenance_path=root / "generated_rules.json",
            )
            text = (root / "DebugSpec.yml").read_text(encoding="utf-8")
            stored = json.loads((root / "generated_rules.json").read_text(encoding="utf-8"))
        self.assertTrue(text.startswith("# Generated by scripts/propose_detector_rules.py"))
        self.assertIn(RULE.strip(), text)
        self.assertEqual(stored["rules"]["DebugSpec"]["rule_sha256"], entry["rule_sha256"])

    def test_a_changed_specification_marks_its_rule_stale(self):
        provenance = self.provenance(status="accepted")
        self.assertEqual(rule_proposal.stale_rules(provenance, {"DebugSpec": "s2"}),
                         ["DebugSpec"])
        self.assertEqual(rule_proposal.stale_rules(provenance, {"DebugSpec": "s1"}), [])


@unittest.skipUnless(semgrep_rules.find_semgrep(), "semgrep is not installed")
class RealSemgrepTests(unittest.TestCase):
    def test_a_candidate_rule_is_evaluated_without_being_installed(self):
        cases = [
            Case("vulnerable", "finding", FIRES, "Loader.java", VULNERABLE, "onCreate"),
            Case("fixed", "fixed_revision", SILENT, "Loader.java", FIXED, "onCreate"),
        ]
        results = rule_proposal.evaluate(RULE, "NoSuchInstalledSpec", cases)
        self.assertEqual([item["got"] for item in results], [FIRES, SILENT])
        self.assertIsNone(semgrep_rules.rule_file("NoSuchInstalledSpec"))


if __name__ == "__main__":
    unittest.main()
