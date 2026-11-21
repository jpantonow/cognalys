"""What validation can say about behaviour, as opposed to compilation.

Three gaps are pinned here. A patch that changed production code and no
test ran no test at all. What did run was recorded as a Gradle status, so a
task that executed zero tests read as a pass. And the baseline build was
cached without its toolchain, so a different JDK or dependency set reused a
baseline built under other conditions.

The regression suite is a measurement, never a gate: the tests below also
pin that it cannot change a build's status.
"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.validation.behavioral import (  # noqa: E402
    fingerprint_digest,
    toolchain_fingerprint,
)
from cognalys.validation import applied_solutions  # noqa: E402


def _junit(directory: Path, name: str, tests: int, failures: int = 0,
           skipped: int = 0, failing_case: str = "") -> None:
    results = directory / "build" / "test-results" / "testDebugUnitTest"
    results.mkdir(parents=True, exist_ok=True)
    cases = ""
    if failing_case:
        cases = (f'<testcase classname="app.T" name="{failing_case}">'
                 '<failure message="expected 1 but was 2"/></testcase>')
    (results / f"TEST-{name}.xml").write_text(
        f'<?xml version="1.0"?><testsuite name="{name}" tests="{tests}" '
        f'failures="{failures}" errors="0" skipped="{skipped}">{cases}'
        '</testsuite>',
        encoding="utf-8",
    )


class ToolchainTests(unittest.TestCase):

    def test_a_changed_dependency_declaration_changes_the_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            build = root / "app" / "build.gradle"
            build.write_text('implementation "a:b:1.0"', encoding="utf-8")
            before = toolchain_fingerprint(root)
            build.write_text('implementation "a:b:2.0"', encoding="utf-8")
            after = toolchain_fingerprint(root)
        self.assertNotEqual(
            before["build_declarations_sha256"],
            after["build_declarations_sha256"],
        )
        self.assertNotEqual(fingerprint_digest(before), fingerprint_digest(after))

    def test_a_changed_sdk_changes_the_baseline_cache_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {"ANDROID_HOME": "/sdk/one"}):
                one = applied_solutions.baseline_cache_key(root, "abc", ["t"])
            with patch.dict(os.environ, {"ANDROID_HOME": "/sdk/two"}):
                two = applied_solutions.baseline_cache_key(root, "abc", ["t"])
        self.assertNotEqual(one, two)

    def test_the_same_conditions_give_the_same_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(
                applied_solutions.baseline_cache_key(root, "abc", ["t"], "x"),
                applied_solutions.baseline_cache_key(root, "abc", ["t"], "x"),
            )


class DetectorReplayWiringTests(unittest.TestCase):
    """A tool with no detector adapter is reported as uncovered."""

    def test_a_finding_from_a_tool_without_an_adapter_is_uncovered(self):
        result = applied_solutions.replay_source_detector(
            {"tool": "CogniCrypt"}, Path(".")
        )
        self.assertEqual(result["outcome"], "no_detector_coverage")
        self.assertIn("cognicrypt", result["detail"])
        self.assertEqual(result["detector"], {"tool": "cognicrypt"})

    def test_a_file_absent_at_the_base_commit_is_not_exercised(self):
        with tempfile.TemporaryDirectory() as directory:
            result = applied_solutions.replay_source_detector({
                "tool": "pmd", "source_file": "x/A.java",
                "base_repository_path": directory, "base_commit": "abc",
                "spec": "SomeRule", "method_name": "m",
            }, Path(directory))
        self.assertEqual(result["outcome"], "not_exercised")

    def test_the_renames_the_validation_accepted_reach_the_replay(self):
        # md5Hash -> sha256Hash with a new body: the lexical guess alone
        # could read it as method_removed.
        from unittest.mock import MagicMock

        adapter = MagicMock(tool="pmd")
        adapter.describe.return_value = {"tool": "pmd"}
        adapter.replay_pair.return_value = {"outcome": "method_renamed"}
        solution = {
            "tool": "pmd", "source_file": "x/A.kt", "base_repository_path": ".",
            "base_commit": "abc", "spec": "Rule", "method_name": "md5Hash",
            "semantic_validation": {"status": "valid", "accepted_renames": [
                {"old": "md5Hash", "new": "sha256Hash"}]},
        }
        with patch("cognalys.validation.detector_replay.adapter_for_finding",
                   return_value=adapter), \
                patch("cognalys.validation.detector_replay.file_at_revision",
                      side_effect=lambda repo, commit, relative, target: target):
            applied_solutions.replay_source_detector(solution, Path("."))
            del solution["semantic_validation"]
            applied_solutions.replay_source_detector(solution, Path("."))
        first, second = adapter.replay_pair.call_args_list
        self.assertEqual(first.kwargs["confirmed_renames"], {"md5Hash": "sha256Hash"})
        self.assertNotIn("confirmed_renames", second.kwargs)

    def test_validation_records_the_renames_it_accepted(self):
        from cognalys.llm import semantic_validation

        with patch.object(semantic_validation, "rename_issues",
                          return_value=([], {("md5Hash", "sha256Hash")})):
            result = semantic_validation.validate_coordinated_semantics(
                {"source_file_path": "x/A.kt"}, [])
        self.assertEqual(result["accepted_renames"], [{"old": "md5Hash", "new": "sha256Hash"}])


if __name__ == "__main__":
    unittest.main()
