import json
import logging
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.config.apply_solutions_config import ApplySolutionsConfig  # noqa: E402
from cognalys.solutions.solution_applicator import SolutionApplicator  # noqa: E402
from cognalys.solutions.solution_mapper import SolutionMapper  # noqa: E402


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    )


class SolutionWorktreeIntegrationTests(unittest.TestCase):
    def test_coordinated_create_adds_new_test_file_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Source.kt"
            source.write_text("class Source\n", encoding="utf-8")
            new_test = root / "app/src/test/kotlin/example/SourceTest.kt"
            applicator = SolutionApplicator(ApplySolutionsConfig(
                error_solutions_dir=str(root / "solutions"),
                cloned_projects_dir=str(root), output_dir=str(root / "results"),
                worktrees_dir=str(root / "worktrees"), save_backups=False,
            ))
            solution = {"coordinated_edits": [{
                "source_file_path": "Source.kt", "symbol": "Source",
                "edit_kind": "declaration", "original_code": "class Source",
                "corrected_code": "internal class Source", "reason": "scope",
            }, {
                "source_file_path": "app/src/test/kotlin/example/SourceTest.kt",
                "symbol": "SourceTest", "edit_kind": "create",
                "original_code": "", "corrected_code": "class SourceTest\n",
                "reason": "dedicated regression test",
            }]}
            ok, changes, error = applicator._apply_coordinated_edits(
                solution, SolutionMapper(str(root / "solutions"), str(root)), root
            )
            self.assertTrue(ok, error)
            self.assertTrue(new_test.is_file())
            self.assertEqual(new_test.read_text(encoding="utf-8"), "class SourceTest\n")
            self.assertEqual([item["edit_kind"] for item in changes], [
                "declaration", "create",
            ])

    def test_declaration_anchored_inside_class_but_called_unqualified_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Source.kt"
            original_source = (
                "class Outer {\n"
                "    private object Marker {\n"
                "        val x = 1\n"
                "    }\n"
                "}\n"
            )
            source.write_text(original_source, encoding="utf-8")
            applicator = SolutionApplicator(ApplySolutionsConfig(
                error_solutions_dir=str(root / "solutions"),
                cloned_projects_dir=str(root), output_dir=str(root / "results"),
                worktrees_dir=str(root / "worktrees"), save_backups=False,
            ))
            solution = {"coordinated_edits": [{
                "source_file_path": "Source.kt", "symbol": "helper",
                "edit_kind": "declaration",
                "original_code": (
                    "    private object Marker {\n"
                    "        val x = 1\n"
                    "    }"
                ),
                "corrected_code": (
                    "    internal fun helper(): Int = 1\n\n"
                    "    private object Marker {\n"
                    "        val x = 1\n"
                    "    }"
                ),
                "reason": "add helper used by a new test",
            }, {
                "source_file_path": "SourceTest.kt", "symbol": "SourceTest",
                "edit_kind": "create", "original_code": "",
                "corrected_code": (
                    "class SourceTest {\n"
                    "    fun test() { helper() }\n"
                    "}\n"
                ),
                "reason": "regression test",
            }]}
            ok, changes, error = applicator._apply_coordinated_edits(
                solution, SolutionMapper(str(root / "solutions"), str(root)), root
            )
            self.assertFalse(ok)
            self.assertTrue(error.startswith("DECLARATION_SCOPE_MISMATCH:"), error)
            self.assertEqual(source.read_text(encoding="utf-8"), original_source)

    def test_coordinated_delete_removes_exact_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Source.kt"
            source.write_text(
                "import java.security.MessageDigest\n\nclass Source\n",
                encoding="utf-8",
            )
            applicator = SolutionApplicator(ApplySolutionsConfig(
                error_solutions_dir=str(root / "solutions"),
                cloned_projects_dir=str(root),
                output_dir=str(root / "results"),
                worktrees_dir=str(root / "worktrees"),
                save_backups=False,
            ))
            solution = {"coordinated_edits": [{
                "source_file_path": "Source.kt",
                "symbol": "MessageDigest import", "edit_kind": "delete",
                "original_code": "import java.security.MessageDigest\n",
                "corrected_code": "", "reason": "unused",
            }, {
                "source_file_path": "Source.kt",
                "symbol": "Source", "edit_kind": "declaration",
                "original_code": "class Source",
                "corrected_code": "internal class Source", "reason": "scope",
            }]}
            # Dependency-scoped count permits a one-edit unit fixture; the same
            # deletion logic is used by ordinary multi-file coordinated fixes.
            solution["fix_scope"] = "dependency"
            ok, changes, error = applicator._apply_coordinated_edits(
                solution, SolutionMapper(str(root / "solutions"), str(root)), root
            )
            self.assertTrue(ok, error)
            self.assertEqual(
                [item["edit_kind"] for item in changes],
                ["delete", "declaration"],
            )
            # The import's blank separator goes with it: no blank first line.
            self.assertEqual(
                source.read_text(encoding="utf-8"), "internal class Source\n"
            )

    def test_review_only_solution_is_never_applied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clones = root / "clones"
            repo = clones / "app.apk"
            repo.mkdir(parents=True)
            git(repo, "init", "-b", "main")
            git(repo, "config", "user.name", "Test")
            git(repo, "config", "user.email", "test@example.com")
            original = "class Source { int value() { return 1; } }\n"
            (repo / "Source.java").write_text(original, encoding="utf-8")
            git(repo, "add", "Source.java")
            git(repo, "commit", "-m", "initial")

            solutions = root / "solutions" / "app.apk"
            solutions.mkdir(parents=True)
            payload = {
                "solution_metadata": {
                    "apk_name": "app.apk", "method_name": "value",
                    "csv_class": "Source",
                    "relative_method_file": "app.apk/Source.java",
                    "source_file_path": "Source.java", "spec": "ExampleSpec",
                    "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                    "fix_scope": "review_only",
                    "manual_review_required": True, "auto_apply": False,
                    "publication_allowed": False,
                    "code_quality_metrics": {"quality_score": 70},
                },
                "original_error": {
                    "method_body": "int value() { return 1; }",
                    "unique_error_id": "review-only",
                },
                "corrected_implementation": {
                    "method_body": "int value() { return 2; }",
                    "explanation": "candidate only",
                },
            }
            (solutions / "0_value_solution.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )

            logging.disable(logging.CRITICAL)
            try:
                report = SolutionApplicator(ApplySolutionsConfig(
                    error_solutions_dir=str(root / "solutions"),
                    cloned_projects_dir=str(clones),
                    output_dir=str(root / "results"),
                    worktrees_dir=str(root / "worktrees"),
                    save_backups=False,
                )).apply_solutions()
            finally:
                logging.disable(logging.NOTSET)

            self.assertEqual(
                report["per_solution_details"][0]["status"], "REVIEW_ONLY"
            )
            self.assertEqual(
                report["results"]["review_only_not_applied"], 1
            )
            detail = report["per_solution_details"][0]
            self.assertTrue(detail["manual_review_required"])
            self.assertFalse(detail["auto_apply"])
            self.assertFalse(detail["publication_allowed"])
            self.assertEqual(
                (repo / "Source.java").read_text(encoding="utf-8"), original
            )
            self.assertEqual(list((root / "worktrees").iterdir()), [])

    def test_applies_two_findings_from_same_project_independently(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clones = root / "clones"
            repo = clones / "app.apk"
            repo.mkdir(parents=True)
            git(repo, "init", "-b", "main")
            git(repo, "config", "user.name", "Test")
            git(repo, "config", "user.email", "test@example.com")
            original = (
                "class Source {\n"
                "    int first() { return 1; }\n"
                "    int second() { return 2; }\n"
                "}\n"
            )
            (repo / "Source.java").write_text(original, encoding="utf-8")
            git(repo, "add", "Source.java")
            git(repo, "commit", "-m", "initial")

            solutions = root / "solutions" / "app.apk"
            solutions.mkdir(parents=True)
            cases = [
                ("first", "int first() { return 1; }", "int first() { return 10; }"),
                ("second", "int second() { return 2; }", "int second() { return 20; }"),
            ]
            for index, (method, before, after) in enumerate(cases):
                payload = {
                    "solution_metadata": {
                        "apk_name": "app.apk",
                        "method_name": method,
                        "csv_class": "Source",
                        "relative_method_file": "app.apk/Source.java",
                        "source_file_path": "Source.java",
                        "spec": "ExampleSpec",
                        "code_quality_metrics": {"quality_score": 80},
                    },
                    "original_error": {
                        "method_body": before,
                        "unique_error_id": f"finding-{method}",
                    },
                    "corrected_implementation": {
                        "method_body": after,
                        "explanation": "test correction",
                    },
                }
                (solutions / f"{index}_{method}_solution.json").write_text(
                    json.dumps(payload), encoding="utf-8"
                )

            logging.disable(logging.CRITICAL)
            try:
                report = SolutionApplicator(ApplySolutionsConfig(
                    error_solutions_dir=str(root / "solutions"),
                    cloned_projects_dir=str(clones),
                    output_dir=str(root / "results"),
                    worktrees_dir=str(root / "worktrees"),
                    save_backups=False,
                )).apply_solutions()
            finally:
                logging.disable(logging.NOTSET)

            successful = [
                item for item in report["per_solution_details"]
                if item["status"] == "SUCCESS"
            ]
            self.assertEqual(len(successful), 2)
            by_method = {item["method_name"]: item for item in successful}
            self.assertNotEqual(
                by_method["first"]["worktree_path"],
                by_method["second"]["worktree_path"],
            )
            first_source = Path(by_method["first"]["worktree_path"]) / "Source.java"
            second_source = Path(by_method["second"]["worktree_path"]) / "Source.java"
            self.assertIn("return 10", first_source.read_text(encoding="utf-8"))
            self.assertNotIn("return 20", first_source.read_text(encoding="utf-8"))
            self.assertIn("return 20", second_source.read_text(encoding="utf-8"))
            self.assertNotIn("return 10", second_source.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
