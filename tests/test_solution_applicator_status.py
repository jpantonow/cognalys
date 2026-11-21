import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from unittest.mock import patch  # noqa: E402

from cognalys.config.apply_solutions_config import ApplySolutionsConfig  # noqa: E402
from cognalys.solutions import solution_applicator as MODULE  # noqa: E402
from cognalys.solutions.solution_applicator import SolutionApplicator  # noqa: E402
from cognalys.solutions.solution_mapper import SolutionMapper  # noqa: E402


class ExecutionReportWorkflowStatusTests(unittest.TestCase):
    """A run that discovers/attempts nothing must not report "SUCCESS".

    A prior run produced zero mapped APKs, zero solutions and zero patches,
    yet execution_report.json still read workflow_status: SUCCESS, because
    the status expression only checked "failed == 0" -- true of an empty
    list -- without first asking whether any solution was ever attempted.
    That made "the workflow ran without an exception" indistinguishable
    from "the workflow actually did something".
    """

    def _applicator(self):
        return SolutionApplicator(ApplySolutionsConfig())

    def test_no_attempted_solutions_is_not_reported_as_success(self):
        applicator = self._applicator()
        applicator.results = []
        report = applicator._generate_execution_report()
        self.assertEqual(report["workflow_status"], "SUCCESS_WITH_NO_ACTION")
        self.assertNotEqual(report["workflow_status"], "SUCCESS")

    def test_all_successful_solutions_are_still_reported_as_success(self):
        applicator = self._applicator()
        applicator.results = [
            {"status": "SUCCESS", "finding_id": "f1"},
            {"status": "SUCCESS", "finding_id": "f2"},
        ]
        report = applicator._generate_execution_report()
        self.assertEqual(report["workflow_status"], "SUCCESS")

    def test_mixed_outcomes_are_reported_as_partial(self):
        applicator = self._applicator()
        applicator.results = [
            {"status": "SUCCESS", "finding_id": "f1"},
            {"status": "FAILED"},
        ]
        report = applicator._generate_execution_report()
        self.assertEqual(report["workflow_status"], "PARTIAL")

    def test_a_finding_absent_from_the_base_branch_is_not_a_failure(self):
        """It was never appliable there, and no rerun changes that.

        Counting it as a failure reported run_20260909_125353 as FAILED for a
        finding whose file the upstream project had removed years earlier.
        """
        applicator = self._applicator()
        applicator.results = [{
            "status": "NOT_APPLICABLE_TO_BASE",
            "error": "SOURCE_FILE_ABSENT_FROM_BASE_BRANCH",
        }]
        report = applicator._generate_execution_report()
        self.assertEqual(report["results"]["failed"], 0)
        self.assertEqual(
            report["results"]["not_applicable_to_base_branch"], 1,
        )
        self.assertEqual(report["workflow_status"], "SUCCESS_WITH_NO_ACTION")

    def test_a_body_the_base_changed_is_reclassified_not_failed(self):
        """Element Android's MainActivity.kt is on develop, so the file check
        passed, but develop has carried the fix for CVE-2024-26131 since
        1.6.12. The patch had nothing left to apply to."""
        applicator = self._applicator()
        result = {"status": "FAILED", "error": "ORIGINAL_CODE_NOT_FOUND:a.kt",
                  "base_branch": "develop"}
        with patch.object(
            MODULE, "code_exists_at",
            side_effect=lambda repo, ref, path, code: ref != "base-sha",
        ):
            applicator._classify_base_drift(
                result, Path("."), "base-sha", "a.kt", "fun old() {}",
                "app.apk", "old",
            )
        self.assertEqual(result["status"], "NOT_APPLICABLE_TO_BASE")
        self.assertEqual(
            result["error"], "ORIGINAL_CODE_ABSENT_FROM_BASE_BRANCH",
        )
        self.assertFalse(result["contribution_base"]["analyzed_code_present"])

    def test_a_body_absent_from_both_stays_a_failure(self):
        """Present at neither revision means the solution's original code was
        never in this repository, which is a real failure and not drift."""
        applicator = self._applicator()
        result = {"status": "FAILED", "error": "ORIGINAL_CODE_NOT_FOUND:a.kt"}
        with patch.object(
            MODULE, "code_exists_at", return_value=False,
        ):
            applicator._classify_base_drift(
                result, Path("."), "base-sha", "a.kt", "fun old() {}",
                "app.apk", "old",
            )
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["error"], "ORIGINAL_CODE_NOT_FOUND:a.kt")

    def test_an_unknown_answer_does_not_reclassify(self):
        applicator = self._applicator()
        result = {"status": "FAILED", "error": "PATCH_FAILED"}
        with patch.object(MODULE, "code_exists_at", return_value=None):
            applicator._classify_base_drift(
                result, Path("."), "base-sha", "a.kt", "fun old() {}",
                "app.apk", "old",
            )
        self.assertEqual(result["status"], "FAILED")

    def test_it_does_not_mask_a_real_failure_beside_it(self):
        applicator = self._applicator()
        applicator.results = [
            {"status": "NOT_APPLICABLE_TO_BASE"},
            {"status": "FAILED"},
        ]
        report = applicator._generate_execution_report()
        self.assertEqual(report["results"]["failed"], 1)
        self.assertEqual(report["workflow_status"], "FAILED")

    def test_it_does_not_downgrade_a_run_that_applied_something(self):
        applicator = self._applicator()
        applicator.results = [
            {"status": "SUCCESS"},
            {"status": "NOT_APPLICABLE_TO_BASE"},
        ]
        report = applicator._generate_execution_report()
        self.assertEqual(report["workflow_status"], "SUCCESS")

    def test_all_dry_run_is_still_reported_as_dry_run(self):
        applicator = self._applicator()
        applicator.results = [
            {"status": "DRY_RUN"}, {"status": "DRY_RUN"},
        ]
        report = applicator._generate_execution_report()
        self.assertEqual(report["workflow_status"], "DRY_RUN")


class CoordinatedSolutionDiscoveryTests(unittest.TestCase):
    """A coordinated patch must survive discovery without a single method body.

    net.gaast.giggity generated a valid three-edit patch -- delete an import,
    rewrite hashCode(), create a dedicated test -- whose corrected method_body
    was empty. discover_solutions required that body, so the mapping report
    read 0 apks, the applicator reported SUCCESS_WITH_NO_ACTION, and the run
    produced no pull request even though the fix was complete and valid.
    """

    def _write(self, root: Path, body, edits) -> Path:
        directory = root / "error_solutions" / "app.apk"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "1_hashCode_solution.json"
        path.write_text(json.dumps({
            "solution_metadata": {
                "apk_name": "app.apk",
                "error_index": 1,
                "method_name": "hashCode",
                "csv_class": "p.Item",
                "relative_method_file": "app.apk/app/src/main/java/p/Item.java",
                "source_file_path": "app/src/main/java/p/Item.java",
                "spec": "MessageDigestSpec",
                "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                "fix_scope": "review_only",
                "auto_apply": False,
                "code_quality_metrics": {"quality_score": 100},
            },
            "original_error": {"method_body": "int hashCode() { return md5(); }"},
            "corrected_implementation": {
                "method_body": body,
                "explanation": "Replace the digest with Objects.hash.",
                "coordinated_edits": edits,
            },
        }), encoding="utf-8")
        return path

    def _discover(self, body, edits):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write(root, body, edits)
            mapper = SolutionMapper(
                root / "error_solutions", root / "cloned"
            )
            return mapper.discover_solutions()

    EDITS = [
        {"source_file_path": "app/src/main/java/p/Item.java",
         "edit_kind": "delete", "original_code": "import x;",
         "corrected_code": "", "symbol": "import", "reason": "unused"},
        {"source_file_path": "app/src/test/java/p/ItemTest.java",
         "edit_kind": "create", "original_code": "",
         "corrected_code": "class ItemTest {}", "symbol": "ItemTest",
         "reason": "coverage"},
    ]

    def test_coordinated_patch_without_a_method_body_is_discovered(self):
        found = self._discover("", self.EDITS)
        self.assertEqual(len(found), 1)
        self.assertEqual(len(found[0]["coordinated_edits"]), 2)
        self.assertEqual(found[0]["fix_scope"], "review_only")

    def test_single_method_solution_still_requires_its_body(self):
        """Without coordinated edits there is nothing else to apply."""
        self.assertEqual(self._discover("", []), [])

    def test_a_body_only_solution_is_still_discovered(self):
        found = self._discover("int hashCode() { return 1; }", [])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["coordinated_edits"], [])


class ReviewContractVersionRowTests(unittest.TestCase):
    """The execution-report row carries the review contract, as it does
    fix_scope, so the PR metadata does not depend on finding the solution
    file from the report's place in a run directory."""

    class _NoSourceMapper:
        @staticmethod
        def locate_source_file(_relative):
            return None

    def _row(self, solution):
        applicator = SolutionApplicator(ApplySolutionsConfig())
        return applicator._apply_single_solution({
            "apk_name": "app.apk", "method_name": "m", "csv_class": "p.C",
            "relative_method_file": "app.apk/C.java", **solution,
        }, self._NoSourceMapper())

    def test_the_solution_file_s_version_reaches_the_row(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "1_m_solution.json"
            path.write_text(json.dumps({
                "solution_metadata": {"review_contract_version": 3},
            }), encoding="utf-8")
            row = self._row({"solution_file": str(path)})
        self.assertEqual(row["error"], "SOURCE_FILE_NOT_FOUND")
        self.assertEqual(row["review_contract_version"], 3)

    def test_the_solution_s_own_field_wins_and_none_means_unreviewed(self):
        self.assertEqual(self._row({"review_contract_version": 5})
                         ["review_contract_version"], 5)
        self.assertIsNone(self._row({"review_contract_version": None})
                          ["review_contract_version"])
        self.assertIsNone(self._row({"solution_file": ""})["review_contract_version"])


class PublicationBlockedIsStillAppliedTests(unittest.TestCase):
    """A publication block must not stop the patch reaching a worktree.

    solution_applicator derives review_only from manual_review_required and
    auto_apply, deliberately NOT from publication_allowed, so that a solution
    whose publication the adjudication blocked is still applied and built --
    pr_generator is what refuses to turn it into a pull request. This pins the
    asymmetry, because marking such a solution as manual review instead sent
    it down the skip path, and the escape hatch that would re-admit it needs a
    semantic_validation status the single-method path never writes.
    """

    @staticmethod
    def _review_only(solution, approve_for_validation=False):
        review_only = (
            solution.get("manual_review_required") is True
            or solution.get("auto_apply") is False
        )
        validation_approved = (
            review_only
            and approve_for_validation
            and solution.get("publication_allowed") is False
            and solution.get("semantic_validation", {}).get("status") == "valid"
        )
        return review_only and not validation_approved

    def test_publication_blocked_alone_does_not_skip_application(self):
        solution = {
            "manual_review_required": False,
            "auto_apply": True,
            "publication_allowed": False,
        }
        self.assertFalse(self._review_only(solution))

    def test_manual_review_without_semantic_validation_is_skipped(self):
        """Why marking a publication block as manual review broke the run."""
        solution = {
            "manual_review_required": True,
            "auto_apply": True,
            "publication_allowed": False,
        }
        self.assertTrue(
            self._review_only(solution, approve_for_validation=True)
        )

    def test_manual_review_with_valid_semantic_validation_is_admitted(self):
        solution = {
            "manual_review_required": True,
            "auto_apply": True,
            "publication_allowed": False,
            "semantic_validation": {"status": "valid"},
        }
        self.assertFalse(
            self._review_only(solution, approve_for_validation=True)
        )


from cognalys.solutions.solution_mapper import MethodReplacer  # noqa: E402


class TrailingWhitespacePreservationTests(unittest.TestCase):
    """A two-line change must not arrive as a hundred-line diff.

    A generated method is rewritten whole, so the model's whitespace habits
    land on every line it left alone. gtalksms's HelpCmd constructor
    (run_20260911_125911) gained a synchronized block -- two lines -- and
    produced a 104-line diff. Of the 51 rewritten lines, 41 were the loop
    body legitimately indenting into the new block and 10 were blank lines
    whose trailing spaces had been stripped. Only the ten are noise, and
    only the ten are undone here: flattening the other 41 back would be
    wrong.
    """

    ORIGINAL = (
        "    void run() {\n"
        "        int a = 1;\n"
        "        \n"
        "        call(a);\n"
        "    }\n"
    )

    def test_trailing_whitespace_on_an_unchanged_line_is_restored(self):
        generated = self.ORIGINAL.replace("        \n", "\n")
        self.assertEqual(
            MethodReplacer.preserve_unchanged_trailing_whitespace(
                self.ORIGINAL, generated
            ),
            self.ORIGINAL,
        )

    def test_an_intentional_reindentation_is_kept(self):
        # The body moved one level deeper into a new block: that is a real
        # change to those lines, not churn.
        generated = (
            "    void run() {\n"
            "        synchronized (lock) {\n"
            "            int a = 1;\n"
            "\n"
            "            call(a);\n"
            "        }\n"
            "    }\n"
        )
        result = MethodReplacer.preserve_unchanged_trailing_whitespace(
            self.ORIGINAL, generated
        )
        self.assertIn("            int a = 1;", result)
        self.assertIn("        synchronized (lock) {", result)

    def test_inserted_and_removed_lines_are_untouched(self):
        generated = (
            "    void run() {\n"
            "        int a = 2;\n"
            "        \n"
            "        call(a);\n"
            "        log(a);\n"
            "    }\n"
        )
        self.assertEqual(
            MethodReplacer.preserve_unchanged_trailing_whitespace(
                self.ORIGINAL, generated
            ),
            generated,
        )

    def test_a_content_line_losing_trailing_spaces_is_restored(self):
        original = "    void run() {\n        int a = 1;   \n    }\n"
        generated = "    void run() {\n        int a = 1;\n    }\n"
        self.assertEqual(
            MethodReplacer.preserve_unchanged_trailing_whitespace(
                original, generated
            ),
            original,
        )

    def test_an_identical_body_is_returned_unchanged(self):
        self.assertEqual(
            MethodReplacer.preserve_unchanged_trailing_whitespace(
                self.ORIGINAL, self.ORIGINAL
            ),
            self.ORIGINAL,
        )


class ProjectScopedExecutionReportTests(unittest.TestCase):
    """Resuming a run one project at a time must not erase the others.

    run_20260927_175748 applied TagMo with `--project`, and the report that
    invocation wrote held TagMo alone: the Signal finding generated earlier
    in the same run left no trace in any later step.
    """

    def _applicator(self, root: Path, project: str):
        solutions = root / "error_solutions"
        return SolutionApplicator(ApplySolutionsConfig(
            error_solutions_dir=str(solutions / project if project else solutions),
            output_dir=str(root / "application_results"),
        ))

    def _earlier(self, root: Path, details):
        path = root / "application_results" / "execution_report.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"per_solution_details": details}),
                        encoding="utf-8")

    def test_a_project_scoped_run_keeps_other_projects_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._earlier(root, [
                {"apk_name": "signal.apk", "status": "SUCCESS", "finding_id": "a"},
                {"apk_name": "tagmo.apk", "status": "FAILED", "finding_id": "b"},
            ])
            applicator = self._applicator(root, "tagmo.apk")
            applicator.results = [
                {"apk_name": "tagmo.apk", "status": "SUCCESS", "finding_id": "c"},
            ]
            report = applicator._generate_execution_report()
        self.assertEqual(
            [(item["apk_name"], item["finding_id"])
             for item in report["per_solution_details"]],
            [("signal.apk", "a"), ("tagmo.apk", "c")],
        )
        self.assertEqual(report["total_solutions"], 2)
        self.assertEqual(report["results"]["successfully_applied"], 2)

    def test_the_status_describes_only_this_invocation(self):
        # The exit code is read from workflow_status; an earlier project's
        # success must not turn this invocation's failure into PARTIAL.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._earlier(root, [
                {"apk_name": "signal.apk", "status": "SUCCESS", "finding_id": "a"},
            ])
            applicator = self._applicator(root, "tagmo.apk")
            applicator.results = [{"apk_name": "tagmo.apk", "status": "FAILED"}]
            report = applicator._generate_execution_report()
        self.assertEqual(report["workflow_status"], "FAILED")
        self.assertEqual(report["results"]["failed"], 1)

    def test_a_scoped_project_with_no_results_drops_its_stale_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._earlier(root, [
                {"apk_name": "tagmo.apk", "status": "FAILED", "finding_id": "b"},
            ])
            applicator = self._applicator(root, "tagmo.apk")
            applicator.results = []
            report = applicator._generate_execution_report()
        self.assertEqual(report["per_solution_details"], [])

    def test_a_whole_run_replaces_the_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._earlier(root, [
                {"apk_name": "signal.apk", "status": "SUCCESS", "finding_id": "a"},
            ])
            applicator = self._applicator(root, "")
            applicator.results = [
                {"apk_name": "tagmo.apk", "status": "SUCCESS", "finding_id": "c"},
            ]
            report = applicator._generate_execution_report()
        self.assertEqual(
            [item["apk_name"] for item in report["per_solution_details"]],
            ["tagmo.apk"],
        )


class SingleOccurrenceReplacementTests(unittest.TestCase):
    """The single-method path asks what the coordinated path asks (A5).

    It replaced the first of several copies of the reviewed body, and called
    a corrected body already in the file a success that changed nothing.
    """

    BODY = '    void run() {\n        digest("MD5");\n    }\n'
    FIXED = '    void run() {\n        digest("SHA-256");\n    }\n'

    def _replace(self, content: str):
        import logging

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "A.java"
            source.write_text(content, encoding="utf-8")
            replacer = MethodReplacer(logging.getLogger("single-occurrence"))
            status = replacer.replace_method_status(source, self.BODY, self.FIXED)
            applied = MethodReplacer(logging.getLogger("single-occurrence")).replace_method(
                source, self.BODY, self.FIXED) if status != "APPLIED" else True
            return status, applied, source.read_text(encoding="utf-8")

    def test_a_body_present_twice_is_ambiguous_and_nothing_changes(self):
        content = "class A {\n" + self.BODY + "}\nclass B {\n" + self.BODY + "}\n"
        status, applied, after = self._replace(content)
        self.assertEqual(status, "ORIGINAL_CODE_NOT_UNIQUE")
        self.assertFalse(applied)
        self.assertEqual(after, content)

    def test_a_corrected_body_already_present_is_not_an_application(self):
        content = "class A {\n" + self.FIXED + "}\n"
        status, applied, after = self._replace(content)
        self.assertEqual(status, "ALREADY_APPLIED")
        self.assertFalse(applied)
        self.assertEqual(after, content)

    def test_one_occurrence_is_replaced_and_an_absent_body_is_not_found(self):
        status, _, after = self._replace("class A {\n" + self.BODY + "}\n")
        self.assertEqual(status, "APPLIED")
        self.assertIn("SHA-256", after)
        self.assertEqual(self._replace("class A {}\n")[0], "ORIGINAL_CODE_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
