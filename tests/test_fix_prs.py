import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

# Bound to the module that owns the stage, not to the scripts/ entry point
# that re-exports it: patching a re-exported name is a silent no-op, and the
# alias keeps every fix_prs.X usage below unchanged.
from cognalys.prs import pr_feedback as fix_prs  # noqa: E402
# Patch collaborators where they actually execute. pr_feedback re-exports
# these functions, but a moved function resolves its own dependencies in its
# own module, so patching the re-exported name would be a silent no-op.
from cognalys.solutions import coordinated_edits  # noqa: E402
from cognalys.prs import pr_github, pr_validation  # noqa: E402


class GatherCandidateFilesTests(unittest.TestCase):
    def test_collects_primary_and_feedback_referenced_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            primary = root / "app/src/main/java/example/A.java"
            other = root / "app/src/main/java/example/B.java"
            primary.parent.mkdir(parents=True)
            primary.write_text("class A {}", encoding="utf-8")
            other.write_text("class B {}", encoding="utf-8")
            feedback = [
                {"path": "app/src/main/java/example/B.java", "body": "fix B too"},
                {"path": "", "body": "general comment"},
            ]

            files = fix_prs.gather_candidate_files(root, primary, feedback)

            self.assertEqual(
                files,
                {
                    "app/src/main/java/example/A.java": "class A {}",
                    "app/src/main/java/example/B.java": "class B {}",
                },
            )

    def test_ignores_a_feedback_path_that_does_not_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            primary = root / "A.java"
            primary.write_text("class A {}", encoding="utf-8")
            feedback = [{"path": "Missing.java", "body": "x"}]

            files = fix_prs.gather_candidate_files(root, primary, feedback)

            self.assertEqual(files, {"A.java": "class A {}"})

    def test_primary_source_is_included_even_past_the_size_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            primary = root / "Big.java"
            huge = "x" * (fix_prs.MAX_CANDIDATE_FILE_CHARS + 1)
            primary.write_text(huge, encoding="utf-8")

            files = fix_prs.gather_candidate_files(root, primary, [])

            self.assertIn("Big.java", files)

    def test_a_secondary_file_past_the_size_cap_is_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            primary = root / "A.java"
            other = root / "B.java"
            primary.write_text("class A {}", encoding="utf-8")
            other.write_text("x" * (fix_prs.MAX_CANDIDATE_FILE_CHARS + 1), encoding="utf-8")
            feedback = [{"path": "B.java", "body": "fix"}]

            files = fix_prs.gather_candidate_files(root, primary, feedback)

            self.assertNotIn("B.java", files)


class DiscoverReferencedClassFilesTests(unittest.TestCase):
    def test_finds_the_file_declaring_a_class_named_in_a_review_body(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Helper.java").write_text(
                "class Helper {\n  void configureSocket() {}\n}\n", encoding="utf-8",
            )
            feedback = [{
                "kind": "review",
                "body": "Helper.configureSocket(...) should throw SSLException.",
            }]

            found = fix_prs.discover_referenced_class_files(root, feedback, set())

            self.assertEqual(found, ["Helper.java"])

    def test_a_bare_mention_without_a_method_call_shape_is_not_matched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Helper.java").write_text("class Helper {}\n", encoding="utf-8")
            feedback = [{"kind": "review", "body": "Helper looks fine overall."}]

            found = fix_prs.discover_referenced_class_files(root, feedback, set())

            self.assertEqual(found, [])

    def test_already_covered_files_are_not_returned_again(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Helper.java").write_text(
                "class Helper {\n  void m() {}\n}\n", encoding="utf-8",
            )
            feedback = [{"kind": "review", "body": "Helper.m(...) needs work."}]

            found = fix_prs.discover_referenced_class_files(
                root, feedback, {"Helper.java"},
            )

            self.assertEqual(found, [])


class DiscoverTypeUsageFilesTests(unittest.TestCase):
    def _project(self, root: Path) -> dict[str, str]:
        files = {
            "src/pkg/Helper.java": "public class Helper extends Base {}\n",
            "src/pkg/Caller.java": "class Caller { Helper h = new Helper(); }\n",
            "src/pkg/Other.java": "class Other { HelperFactory f; }\n",
            "notes.txt": "Helper is used here too\n",
        }
        for relative, text in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text, encoding="utf-8")
        return {"src/pkg/Helper.java": files["src/pkg/Helper.java"]}

    def test_a_type_named_in_prose_pulls_in_the_files_that_use_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            covered = self._project(root)
            feedback = [{"body": "Please remove `Helper` and its usage."}]

            found = fix_prs.discover_type_usage_files(root, feedback, covered)

        self.assertEqual(found, ["src/pkg/Caller.java"])

    def test_a_type_the_feedback_does_not_name_adds_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            covered = self._project(root)
            feedback = [{"body": "Please clean up the description."}]

            found = fix_prs.discover_type_usage_files(root, feedback, covered)

        self.assertEqual(found, [])

    def test_a_named_type_not_declared_in_covered_files_adds_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._project(root)
            feedback = [{"body": "Please remove Helper."}]

            found = fix_prs.discover_type_usage_files(root, feedback, {})

        self.assertEqual(found, [])


class PrMetadataUpdateTests(unittest.TestCase):
    PR = {"title": "Fix <init>", "body": "old body"}

    def test_keeps_only_fields_that_change(self):
        update, issues = fix_prs.pr_metadata_update(
            {"pr_title": "Remove obsolete TLS socket factory", "pr_body": "old body"},
            self.PR,
        )
        self.assertEqual(update, {"title": "Remove obsolete TLS socket factory"})
        self.assertEqual(issues, [])

    def test_empty_fields_keep_the_current_metadata(self):
        self.assertEqual(
            fix_prs.pr_metadata_update({"pr_title": "", "pr_body": ""}, self.PR),
            ({}, []),
        )

    def test_rejects_text_presenting_the_contribution_as_automated(self):
        update, issues = fix_prs.pr_metadata_update(
            {"pr_title": "", "pr_body": "This patch was generated by an LLM."},
            self.PR,
        )
        self.assertEqual(update, {})
        self.assertEqual(len(issues), 1)
        self.assertIn("pr_body rejected", issues[0])

    def test_naming_the_analysis_tool_is_allowed(self):
        body = "The dynamic-analysis tool `ape` reported the issue."
        update, issues = fix_prs.pr_metadata_update(
            {"pr_title": "", "pr_body": body}, self.PR,
        )
        self.assertEqual(update, {"body": body})
        self.assertEqual(issues, [])

    def test_rejects_a_multi_line_title(self):
        update, issues = fix_prs.pr_metadata_update(
            {"pr_title": "one\ntwo", "pr_body": ""}, self.PR,
        )
        self.assertEqual(update, {})
        self.assertIn("pr_title rejected", issues[0])


class ApplyCoordinatedEditsTests(unittest.TestCase):
    def _files(self):
        return {
            "A.java": "class A {\n  void m() { int a = 1; }\n}\n",
            "B.java": "class B {\n  void n() { int b = 1; }\n}\n",
        }

    def _edit(self, **overrides):
        edit = {
            "source_file_path": "A.java",
            "symbol": "m",
            "edit_kind": "method",
            "original_code": "void m() { int a = 1; }",
            "corrected_code": "void m() { int a = 2; }",
            "reason": "fix a",
            "required_imports": [],
        }
        edit.update(overrides)
        return edit

    def _delete_file(self, **overrides):
        return self._edit(**{
            "source_file_path": "B.java", "symbol": "B",
            "edit_kind": "delete_file",
            "original_code": "class B {\n  void n() { int b = 1; }\n}\n",
            "corrected_code": "", **overrides,
        })

    def test_delete_file_removes_the_whole_file(self):
        updated, issues = fix_prs.apply_coordinated_edits(
            self._files(), [self._edit(), self._delete_file()]
        )
        self.assertEqual(issues, [])
        self.assertNotIn("B.java", updated)
        self.assertIn("int a = 2", updated["A.java"])

    def test_delete_file_tolerates_indentation_drift_in_the_copy(self):
        updated, issues = fix_prs.apply_coordinated_edits(
            self._files(),
            [self._delete_file(original_code="class B {\nvoid n() { int b = 1; }\n}")],
        )
        self.assertEqual(issues, [])
        self.assertNotIn("B.java", updated)

    def test_delete_file_rejects_a_partial_copy(self):
        updated, issues = fix_prs.apply_coordinated_edits(
            self._files(),
            [self._delete_file(original_code="void n() { int b = 1; }")],
        )
        self.assertIsNone(updated)
        self.assertIn("entire current content", issues[0])

    def test_delete_file_and_an_edit_to_the_same_file_conflict(self):
        edit_b = self._edit(
            source_file_path="B.java", symbol="n",
            original_code="void n() { int b = 1; }",
            corrected_code="void n() { int b = 2; }",
        )
        updated, issues = fix_prs.apply_coordinated_edits(
            self._files(), [self._delete_file(), edit_b]
        )
        self.assertIsNone(updated)
        self.assertIn("a file this revision deletes", issues[0])
        # Edited first, the file no longer matches the copy being deleted.
        updated, _ = fix_prs.apply_coordinated_edits(
            self._files(), [edit_b, self._delete_file()]
        )
        self.assertIsNone(updated)

    def test_applies_a_single_valid_edit(self):
        updated, issues = fix_prs.apply_coordinated_edits(
            self._files(), [self._edit()]
        )
        self.assertEqual(issues, [])
        self.assertIn("int a = 2", updated["A.java"])
        self.assertEqual(updated["B.java"], self._files()["B.java"])

    def test_applies_edits_across_multiple_files_in_one_pass(self):
        edits = [
            self._edit(),
            self._edit(
                source_file_path="B.java", symbol="n",
                original_code="void n() { int b = 1; }",
                corrected_code="void n() { int b = 2; }",
            ),
        ]
        updated, issues = fix_prs.apply_coordinated_edits(self._files(), edits)
        self.assertEqual(issues, [])
        self.assertIn("int a = 2", updated["A.java"])
        self.assertIn("int b = 2", updated["B.java"])

    def test_rejects_the_whole_revision_when_one_edit_is_invalid(self):
        edits = [
            self._edit(),
            self._edit(
                source_file_path="B.java", symbol="n",
                original_code="this text does not appear in B.java",
                corrected_code="void n() { int b = 2; }",
            ),
        ]
        updated, issues = fix_prs.apply_coordinated_edits(self._files(), edits)
        self.assertIsNone(updated)
        self.assertTrue(any("B.java" in issue for issue in issues))

    def test_rejects_a_file_outside_the_supplied_candidates(self):
        edit = self._edit(source_file_path="Outside.java")
        updated, issues = fix_prs.apply_coordinated_edits(self._files(), [edit])
        self.assertIsNone(updated)
        self.assertTrue(any("Outside.java" in issue for issue in issues))

    def test_accepts_create_for_a_path_outside_the_candidates(self):
        """create is the one edit allowed to name an unsupplied path.

        This previously asserted the opposite. Rejecting create meant a
        revision could only delete misplaced code, never relocate it, so a
        request to move misplaced tests into their own file came back as a
        proposal that deleted the coverage instead.
        """
        edit = self._edit(
            source_file_path="New.java", edit_kind="create",
            original_code="", corrected_code="class New {}",
        )
        updated, issues = fix_prs.apply_coordinated_edits(self._files(), [edit])
        self.assertEqual(issues, [])
        self.assertEqual(updated["New.java"], "class New {}")

    def test_still_rejects_a_non_create_edit_outside_the_candidates(self):
        edit = self._edit(source_file_path="Outside.java", edit_kind="method")
        updated, issues = fix_prs.apply_coordinated_edits(self._files(), [edit])
        self.assertIsNone(updated)
        self.assertTrue(any("Outside.java" in issue for issue in issues))

    def test_rejects_non_unique_original_code_match(self):
        files = {"A.java": "x();\nx();\n"}
        edit = self._edit(
            source_file_path="A.java", original_code="x();", corrected_code="y();",
        )
        updated, issues = fix_prs.apply_coordinated_edits(files, [edit])
        self.assertIsNone(updated)
        self.assertIn("matched 2 times exactly", issues[0])

    def test_applies_unique_edit_with_leading_indentation_drift(self):
        files = {
            "A.java": (
                "class A {\n"
                "    \t\tpublic Object[] values() {\n"
                "    \t\t\treturn null;\n"
                "    \t\t}\n"
                "}\n"
            )
        }
        edit = self._edit(
            source_file_path="A.java",
            original_code=(
                "public Object[] values() {\n"
                "\t\t\treturn null;\n"
                "\t\t}"
            ),
            corrected_code=(
                "public Object[] values() {\n"
                "\t\t\treturn new Object[0];\n"
                "\t\t}"
            ),
        )

        updated, issues = fix_prs.apply_coordinated_edits(files, [edit])

        self.assertEqual(issues, [])
        self.assertIn("    \t\t\treturn new Object[0];", updated["A.java"])
        self.assertIn("    \t\tpublic Object[] values()", updated["A.java"])

    def test_rejects_non_unique_indentation_only_match(self):
        files = {
            "A.java": (
                "  void m() {\n    run();\n  }\n"
                "\tvoid m() {\n\t\trun();\n\t}\n"
            )
        }
        edit = self._edit(
            source_file_path="A.java",
            original_code="void m() {\n run();\n}",
            corrected_code="void m() {\n fixed();\n}",
        )

        updated, issues = fix_prs.apply_coordinated_edits(files, [edit])

        self.assertIsNone(updated)
        self.assertIn("matched 2 blocks", issues[0])

    def test_indentation_fallback_rejects_a_line_count_change(self):
        files = {"A.java": "  void m() {\n    run();\n  }\n"}
        edit = self._edit(
            source_file_path="A.java",
            original_code="void m() {\n run();\n}",
            corrected_code="void m() {\n prepare();\n run();\n}",
        )

        updated, issues = fix_prs.apply_coordinated_edits(files, [edit])

        self.assertIsNone(updated)
        self.assertIn("same number of lines", issues[0])

    def test_indentation_fallback_applies_a_line_count_change_with_a_constant_shift(
        self,
    ):
        """A real fix_prs run against github.paroj/DSub2000 PR #160: the file
        mixes a fixed 4-space prefix with tab-depth indentation on every
        line, the model's original_code dropped that constant prefix, and
        its corrected_code also extracted a helper method -- adding lines.
        Rejecting this (the old behavior) discarded five other, unrelated,
        correctly-matched edits in the same coordinated revision, because
        apply_coordinated_edits is all-or-nothing.
        """
        files = {"A.java": (
            "class A {\n"
            "    \t\tprivate Socket configureSocket(Socket socket) {\n"
            "    \t\t\ttry {\n"
            "    \t\t\t\treturn socket;\n"
            "    \t\t\t} catch (RuntimeException e) {\n"
            "    \t\t\t\tsocket.close();\n"
            "    \t\t\t\tthrow e;\n"
            "    \t\t\t}\n"
            "    \t\t}\n"
            "}\n"
        )}
        edit = self._edit(
            original_code=(
                "\t\tprivate Socket configureSocket(Socket socket) {\n"
                "\t\t\ttry {\n"
                "\t\t\t\treturn socket;\n"
                "\t\t\t} catch (RuntimeException e) {\n"
                "\t\t\t\tsocket.close();\n"
                "\t\t\t\tthrow e;\n"
                "\t\t\t}\n"
                "\t\t}"
            ),
            corrected_code=(
                "\t\tprivate Socket configureSocket(Socket socket) {\n"
                "\t\t\ttry {\n"
                "\t\t\t\treturn socket;\n"
                "\t\t\t} catch (RuntimeException e) {\n"
                "\t\t\t\tcloseSocket(socket);\n"
                "\t\t\t\tthrow e;\n"
                "\t\t\t}\n"
                "\t\t}\n"
                "\n"
                "\t\tprivate void closeSocket(Socket socket) {\n"
                "\t\t\tsocket.close();\n"
                "\t\t}"
            ),
        )

        updated, issues = fix_prs.apply_coordinated_edits(files, [edit])

        self.assertEqual(issues, [])
        self.assertIn("    \t\t\t\tcloseSocket(socket);", updated["A.java"])
        self.assertIn(
            "    \t\tprivate void closeSocket(Socket socket) {", updated["A.java"],
        )

    def test_line_count_change_rebases_an_isolated_signature_indent_drift(self):
        """Regression for the second DSub2000 PR #160 fix_prs revision.

        The model omitted one tab only on configureSocket's declaration; all
        other original lines retained their exact mixed space/tab indentation.
        Its correction added an exception branch, so neither the line-by-line
        path nor the constant-shift path could apply the otherwise unique edit.
        """
        files = {"A.java": (
            "class A {\n"
            "    \t\tprivate Socket configureSocket(Socket socket) {\n"
            "    \t\t\ttry {\n"
            "    \t\t\t\treturn socket;\n"
            "    \t\t\t} catch (RuntimeException e) {\n"
            "    \t\t\t\tthrow e;\n"
            "    \t\t\t}\n"
            "    \t\t}\n"
            "}\n"
        )}
        edit = self._edit(
            original_code=(
                "    \tprivate Socket configureSocket(Socket socket) {\n"
                "    \t\t\ttry {\n"
                "    \t\t\t\treturn socket;\n"
                "    \t\t\t} catch (RuntimeException e) {\n"
                "    \t\t\t\tthrow e;\n"
                "    \t\t\t}\n"
                "    \t\t}"
            ),
            corrected_code=(
                "    \tprivate Socket configureSocket(Socket socket) {\n"
                "    \t\t\ttry {\n"
                "    \t\t\t\treturn socket;\n"
                "    \t\t\t} catch (IllegalStateException e) {\n"
                "    \t\t\t\tthrow new IOException(e);\n"
                "    \t\t\t} catch (RuntimeException e) {\n"
                "    \t\t\t\tthrow e;\n"
                "    \t\t\t}\n"
                "    \t\t}"
            ),
        )

        updated, issues = fix_prs.apply_coordinated_edits(files, [edit])

        self.assertEqual(issues, [])
        self.assertIn(
            "    \t\tprivate Socket configureSocket(Socket socket)",
            updated["A.java"],
        )
        self.assertIn(
            "    \t\t\t} catch (IllegalStateException e) {", updated["A.java"],
        )

    def test_line_count_change_rejects_a_conflicting_indent_level_mapping(self):
        files = {"A.java": (
            "class A {\n"
            "  void first() {\n"
            "    run();\n"
            "   stop();\n"
            "  }\n"
            "}\n"
        )}
        edit = self._edit(
            original_code=(
                "void first() {\n"
                " run();\n"
                " stop();\n"
                "}"
            ),
            corrected_code=(
                "void first() {\n"
                " prepare();\n"
                " run();\n"
                " stop();\n"
                "}"
            ),
        )

        updated, issues = fix_prs.apply_coordinated_edits(files, [edit])

        self.assertIsNone(updated)
        self.assertIn("unambiguous mapping", issues[0])

    def test_applies_required_imports_only_to_the_edited_file(self):
        files = {
            "A.java": (
                "import java.util.List;\n"
                "class A {\n  void m() { int a = 1; }\n}\n"
            ),
            "B.java": "import java.util.List;\nclass B {\n  void n() {}\n}\n",
        }
        edit = self._edit(required_imports=["com.example.Thing"])
        updated, issues = fix_prs.apply_coordinated_edits(files, [edit])
        self.assertEqual(issues, [])
        self.assertIn("import com.example.Thing;", updated["A.java"])
        self.assertNotIn("com.example.Thing", updated["B.java"])

    def test_existing_java_import_with_semicolon_is_not_duplicated(self):
        source = (
            "package example;\n\n"
            "import example.service.Service;\n\n"
            "import junit.framework.TestCase;\n"
        )

        updated, added = coordinated_edits.apply_required_imports(
            source, ["example.service.Service"],
        )

        self.assertEqual(added, [])
        self.assertEqual(updated, source)


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def make_origin_and_clone(root: Path) -> tuple[Path, Path]:
    """A bare 'origin' with a main branch and a pushed feature branch, plus
    a clone of it (standing in for --projects-dir's shared checkout)."""
    origin = root / "origin.git"
    origin.mkdir()
    git(origin, "init", "--bare", "-b", "main")

    seed = root / "seed"
    seed.mkdir()
    git(seed, "init", "-b", "main")
    git(seed, "config", "user.name", "Test")
    git(seed, "config", "user.email", "test@example.com")
    (seed / "File.java").write_text(
        "class File { void m() { int a = 1; } }", encoding="utf-8"
    )
    git(seed, "add", ".")
    git(seed, "commit", "-m", "initial")
    git(seed, "remote", "add", "origin", str(origin))
    git(seed, "push", "origin", "main")

    git(seed, "checkout", "-b", "fix/branch")
    (seed / "File.java").write_text(
        "class File { void m() { int a = 2; } }", encoding="utf-8"
    )
    git(seed, "commit", "-am", "fix commit")
    git(seed, "push", "origin", "fix/branch")
    git(seed, "checkout", "main")

    shared = root / "shared"
    subprocess.run(
        ["git", "clone", str(origin), str(shared)],
        check=True, capture_output=True,
    )
    git(shared, "config", "user.name", "Test")
    git(shared, "config", "user.email", "test@example.com")
    return origin, shared


class PreparePrCheckoutTests(unittest.TestCase):
    def test_creates_a_worktree_when_none_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _origin, shared = make_origin_and_clone(root)

            project_root, error = fix_prs.prepare_pr_checkout(
                {"repository": "", "finding_id": "f1"},
                "fix/branch", shared, root / "worktrees",
            )

            self.assertIsNone(error)
            self.assertEqual(git(project_root, "branch", "--show-current"), "fix/branch")
            self.assertIn("a = 2", (project_root / "File.java").read_text())
            # The shared clone must stay untouched on its own branch.
            self.assertEqual(git(shared, "branch", "--show-current"), "main")

    def test_a_request_for_a_setting_brings_the_settings_screen_and_a_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app/src/main/res/xml").mkdir(parents=True)
            (root / "app/src/main/res/xml/pref_general.xml").write_text(
                "<PreferenceScreen><SwitchPreference app:key=\"a\"/></PreferenceScreen>")
            (root / "app/src/main/res/xml/backup_descriptor.xml").write_text("<full-backup-content/>")
            for name in ("pref_about.xml", "pref_about_list.xml", "pref_a_more.xml"):
                (root / "app/src/main/res/xml" / name).write_text("<PreferenceScreen><Preference/></PreferenceScreen>")
            (root / "app/src/main/java").mkdir(parents=True)
            (root / "app/src/main/java/Global.kt").write_text(
                "val on = PreferenceManager.getDefaultSharedPreferences(c).getBoolean(\"a\", true)")
            asked = [{"body": "If you need this feature you can put it behind a toggle in the settings."}]
            found = fix_prs.settings_files(root, asked, set())
            self.assertEqual(found[0], "app/src/main/res/xml/pref_general.xml")
            self.assertEqual(found[-1], "app/src/main/java/Global.kt")
            self.assertEqual(len(found), 4)
            self.assertEqual(fix_prs.settings_files(root, [{"body": "Please rename this."}], set()), [])

    def test_a_removed_project_clone_is_cloned_back_from_the_head_repository(self):
        # HomeApp #114: cleanup had removed the shared clone before the
        # maintainer's feedback was addressed.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            origin, _shared = make_origin_and_clone(root)
            gone = root / "projects" / "app.apk"

            project_root, error = fix_prs.prepare_pr_checkout(
                {"repository": "", "finding_id": "f1"},
                "fix/branch", gone, root / "worktrees", str(origin),
            )

            self.assertIsNone(error)
            self.assertIn("a = 2", (project_root / "File.java").read_text())
            _project_root, error = fix_prs.prepare_pr_checkout(
                {"repository": "", "finding_id": "f2"},
                "fix/branch", root / "projects" / "other.apk", root / "worktrees",
            )
            self.assertIn("no head repository", error)

    def test_reuses_and_syncs_an_existing_worktree_on_the_right_branch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            origin, shared = make_origin_and_clone(root)
            existing = root / "existing_worktree"
            git(
                shared, "worktree", "add", str(existing),
                "-B", "fix/branch", "origin/fix/branch",
            )

            # A maintainer pushes another commit to the PR branch after our
            # worktree was created; prepare_pr_checkout must pick it up.
            git(shared, "fetch", "origin", "fix/branch")
            later = root / "later_push"
            subprocess.run(
                ["git", "clone", str(origin), str(later)],
                check=True, capture_output=True,
            )
            git(later, "config", "user.name", "Test")
            git(later, "config", "user.email", "test@example.com")
            git(later, "checkout", "fix/branch")
            (later / "File.java").write_text(
                "class File { void m() { int a = 3; } }", encoding="utf-8"
            )
            git(later, "commit", "-am", "later push")
            git(later, "push", "origin", "fix/branch")

            project_root, error = fix_prs.prepare_pr_checkout(
                {"repository": str(existing), "finding_id": "f1"},
                "fix/branch", shared, root / "worktrees",
            )

            self.assertIsNone(error)
            self.assertEqual(project_root, existing)
            self.assertIn("a = 3", (project_root / "File.java").read_text())

    def test_discards_an_uncommitted_unpublished_patch_from_a_prior_run(self):
        # A previous fix_prs run wrote a revision straight to the worktree
        # (see run_revision) but was never revalidated/published, so it was
        # never committed. A later run must not build on top of that stale,
        # unpublished patch -- it must start from what is actually on the
        # PR (the branch's last real commit), exactly as if that leftover
        # local edit had never happened.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _origin, shared = make_origin_and_clone(root)
            existing = root / "existing_worktree"
            git(
                shared, "worktree", "add", str(existing),
                "-B", "fix/branch", "origin/fix/branch",
            )
            original_content = (existing / "File.java").read_text()
            (existing / "File.java").write_text(
                "class File { void m() { int a = 999; /* unpublished patch */ } }",
                encoding="utf-8",
            )

            project_root, error = fix_prs.prepare_pr_checkout(
                {"repository": str(existing), "finding_id": "f1"},
                "fix/branch", shared, root / "worktrees",
            )

            self.assertIsNone(error)
            self.assertEqual(project_root, existing)
            self.assertEqual(
                (project_root / "File.java").read_text(), original_content,
            )
            self.assertEqual(git(project_root, "status", "--porcelain"), "")

    def test_falls_back_to_a_new_worktree_when_the_recorded_one_is_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _origin, shared = make_origin_and_clone(root)
            stale = root / "stale_worktree"
            git(shared, "worktree", "add", str(stale), "-B", "other-branch", "main")

            project_root, error = fix_prs.prepare_pr_checkout(
                {"repository": str(stale), "finding_id": "f1"},
                "fix/branch", shared, root / "worktrees",
            )

            self.assertIsNone(error)
            self.assertNotEqual(project_root, stale)
            self.assertEqual(git(project_root, "branch", "--show-current"), "fix/branch")

    def test_no_branch_and_no_recorded_worktree_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _origin, shared = make_origin_and_clone(root)

            project_root, error = fix_prs.prepare_pr_checkout(
                {"repository": "", "finding_id": "f1"},
                "", shared, root / "worktrees",
            )

            self.assertIsNotNone(error)


class ResolveSourceMethodNameTests(unittest.TestCase):
    def test_non_constructor_method_name_is_unchanged(self):
        self.assertEqual(
            fix_prs.resolve_source_method_name(
                "deleteKey", "com.sshborg.data.KeystoreManager",
                Path("KeystoreManager.kt"),
            ),
            "deleteKey",
        )

    def test_constructor_resolves_to_the_simple_class_name(self):
        self.assertEqual(
            fix_prs.resolve_source_method_name(
                "<init>", "github.paroj.dsub2000.service.RESTMusicService",
                Path("RESTMusicService.java"),
            ),
            "RESTMusicService",
        )

    def test_constructor_of_a_nested_class_uses_the_inner_simple_name(self):
        self.assertEqual(
            fix_prs.resolve_source_method_name(
                "<init>", "com.example.Outer$Inner", Path("Outer.java"),
            ),
            "Inner",
        )

    def test_kotlin_top_level_wrapper_class_falls_back_to_the_file_name(self):
        self.assertEqual(
            fix_prs.resolve_source_method_name(
                "<init>", "example.GettersKt", Path("Getters.kt"),
            ),
            "Getters",
        )


class ProjectNameFromMetadataTests(unittest.TestCase):
    def test_extracts_project_from_worktree_path_not_its_last_segment(self):
        metadata = {
            "repository": (
                "outputs/finding_worktrees/github.paroj.dsub2000_217.apk/"
                "42e63cf76e71/f480a9f320"
            ),
            "finding_id": "42e63cf76e71",
            "solution_revision": "f480a9f320",
        }
        self.assertEqual(
            fix_prs.project_name_from_metadata(metadata),
            "github.paroj.dsub2000_217.apk",
        )

    def test_handles_a_retried_revision_directory_suffix(self):
        metadata = {
            "repository": (
                "outputs/finding_worktrees/app.apk/abc123/rev0001-2"
            ),
            "finding_id": "abc123",
            "solution_revision": "rev0001",
        }
        self.assertEqual(fix_prs.project_name_from_metadata(metadata), "app.apk")

    def test_falls_back_to_last_segment_without_a_finding_id(self):
        metadata = {"repository": "outputs/cloned_projects/app.apk"}
        self.assertEqual(fix_prs.project_name_from_metadata(metadata), "app.apk")


class CompileValidationTaskTests(unittest.TestCase):
    def _write_flavors(self, module: Path) -> None:
        module.mkdir(parents=True, exist_ok=True)
        (module / "build.gradle").write_text(
            "android {\n"
            "  productFlavors {\n"
            "    floss {\n      dimension \"version\"\n    }\n"
            "    google {\n      dimension \"version\"\n    }\n"
            "  }\n"
            "}\n",
            encoding="utf-8",
        )

    def test_androidtest_source_selects_flavor_qualified_assemble_task(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_flavors(root / "app")
            source = root / "app/src/androidTest/java/example/FooTest.java"
            source.parent.mkdir(parents=True)
            source.write_text("class FooTest {}", encoding="utf-8")

            task = pr_validation.compile_validation_task(root, source)
            self.assertEqual(task, ":app:assembleFlossDebugAndroidTest")

    def test_unit_test_source_selects_flavor_qualified_test_task(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_flavors(root / "app")
            source = root / "app/src/test/java/example/FooTest.java"
            source.parent.mkdir(parents=True)
            source.write_text("class FooTest {}", encoding="utf-8")

            task = pr_validation.compile_validation_task(root, source)
            self.assertEqual(task, ":app:testFlossDebugUnitTest")

    def test_production_source_selects_flavor_qualified_assemble_debug(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_flavors(root / "app")
            source = root / "app/src/main/java/example/Foo.java"
            source.parent.mkdir(parents=True)
            source.write_text("class Foo {}", encoding="utf-8")

            task = pr_validation.compile_validation_task(root, source)
            self.assertEqual(task, ":app:assembleFlossDebug")

    def test_unflavored_module_keeps_plain_task_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / "app"
            module.mkdir(parents=True)
            (module / "build.gradle").write_text("android {}\n", encoding="utf-8")
            source = module / "src/main/java/example/Foo.java"
            source.parent.mkdir(parents=True)
            source.write_text("class Foo {}", encoding="utf-8")

            task = pr_validation.compile_validation_task(root, source)
            self.assertEqual(task, ":app:assembleDebug")

    def test_single_module_project_with_sources_at_the_root_is_unqualified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build.gradle").write_text("android {}\n", encoding="utf-8")
            source = root / "src/se/example/Foo.java"
            source.parent.mkdir(parents=True)
            source.write_text("class Foo {}", encoding="utf-8")

            task = pr_validation.compile_validation_task(root, source)
            self.assertEqual(task, "assembleDebug")

    def test_nested_module_uses_its_gradle_project_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / "libs/core"
            module.mkdir(parents=True)
            (module / "build.gradle.kts").write_text("", encoding="utf-8")
            source = module / "src/main/java/Foo.java"
            source.parent.mkdir(parents=True)

            task = pr_validation.compile_validation_task(root, source)
            self.assertEqual(task, ":libs:core:assembleDebug")

    def _nested_gradle_root(self, root: Path) -> Path:
        """BWT's layout: settings file, wrapper and modules under one subdirectory."""
        gradle = root / "comencryptbwt"
        (gradle / "app").mkdir(parents=True)
        (gradle / "settings.gradle").write_text("include ':app'\n", encoding="utf-8")
        (gradle / "app" / "build.gradle").write_text("android {}\n", encoding="utf-8")
        (gradle / "gradlew").write_text("", encoding="utf-8")
        return gradle

    def test_task_paths_are_relative_to_the_gradle_root_not_the_checkout(self):
        # The same rule as applied_solutions.invoked_gradle_root: a task named
        # from the checkout (":comencryptbwt:app:...") is refused by Gradle.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gradle = self._nested_gradle_root(root)
            source = gradle / "app/src/test/java/FooTest.java"
            source.parent.mkdir(parents=True)

            self.assertEqual(pr_validation.gradle_root(root), gradle.resolve())
            self.assertEqual(pr_validation.gradle_module_path(root, source), "app")
            self.assertEqual(pr_validation.compile_validation_task(root, source),
                             ":app:testDebugUnitTest")

    def test_a_source_outside_the_gradle_root_has_no_task(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._nested_gradle_root(root)
            source = root / "src/test/java/FooTest.java"
            source.parent.mkdir(parents=True)

            self.assertIsNone(pr_validation.gradle_module_path(root, source))
            self.assertIsNone(pr_validation.compile_validation_task(root, source))


class RunCompileValidationTests(unittest.TestCase):
    def test_missing_gradle_wrapper_is_not_configured(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app/src/main/java/example/Foo.java"
            source.parent.mkdir(parents=True)
            source.write_text("class Foo {}", encoding="utf-8")

            result = pr_validation.run_compile_validation(
                root, [source], Path("build_script.py"), root / "out",
                "debug", 60,
            )

            self.assertEqual(result["status"], "NOT_CONFIGURED")

    def test_no_changed_sources_is_not_configured(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "gradlew").write_text("", encoding="utf-8")

            result = pr_validation.run_compile_validation(
                root, [], Path("build_script.py"), root / "out", "debug", 60,
            )

            self.assertEqual(result["status"], "NOT_CONFIGURED")

    def test_the_wrapper_is_found_at_the_gradle_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gradle = root / "sub"
            (gradle / "app").mkdir(parents=True)
            (gradle / "settings.gradle.kts").write_text("", encoding="utf-8")
            (gradle / "app" / "build.gradle.kts").write_text("", encoding="utf-8")
            (gradle / ("gradlew.bat" if os.name == "nt" else "gradlew")).write_text(
                "", encoding="utf-8")
            source = gradle / "app/src/main/java/Foo.java"
            source.parent.mkdir(parents=True)
            source.write_text("class Foo {}", encoding="utf-8")

            completed = subprocess.CompletedProcess([], 0, "", "")
            with mock.patch.object(
                pr_validation.subprocess, "run", return_value=completed,
            ) as run, mock.patch.object(
                pr_validation, "_load_build_result", return_value={"status": "success"},
            ):
                result = pr_validation.run_compile_validation(
                    root, [source], Path("scripts/build.py"), root / "out", "debug", 60,
                )

            self.assertEqual(result["status"], "SUCCESS")
            self.assertEqual(result["tasks"], [":app:assembleDebug"])
            command = run.call_args.args[0]
            self.assertEqual(command[command.index("--task") + 1], ":app:assembleDebug")

    def test_a_changed_source_no_task_compiles_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gradle = root / "sub"
            gradle.mkdir()
            (gradle / "settings.gradle").write_text("", encoding="utf-8")
            (gradle / ("gradlew.bat" if os.name == "nt" else "gradlew")).write_text(
                "", encoding="utf-8")
            outside = root / "src/test/java/FooTest.java"
            outside.parent.mkdir(parents=True)
            outside.write_text("class FooTest {}", encoding="utf-8")

            with mock.patch.object(pr_validation.subprocess, "run") as run:
                result = pr_validation.run_compile_validation(
                    root, [outside], Path("scripts/build.py"), root / "out", "debug", 60,
                )

            self.assertEqual(result["status"], "NOT_CONFIGURED")
            self.assertIn("outside the Gradle root", result["reason"])
            run.assert_not_called()

    def test_style_steps_without_a_source_in_the_gradle_root_run_nothing(self):
        """A bare gradlew runs the default task; its success is no ktlint pass."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gradle = root / "sub"
            gradle.mkdir()
            (gradle / "settings.gradle").write_text("", encoding="utf-8")
            (gradle / "build.gradle").write_text(
                "plugins { id 'org.jlleitschuh.gradle.ktlint' }", encoding="utf-8")
            (gradle / ("gradlew.bat" if os.name == "nt" else "gradlew")).write_text(
                "", encoding="utf-8")
            outside = root / "src/main/java/Foo.kt"
            outside.parent.mkdir(parents=True)
            outside.write_text("class Foo", encoding="utf-8")

            with mock.patch.object(pr_validation.subprocess, "run") as run:
                check = pr_validation.run_style_validation(root, [outside], 60)
                repair = pr_validation.repair_style_violations(root, [outside], 60)

            for result in (check, repair):
                self.assertEqual(result["status"], "NOT_CONFIGURED")
                self.assertIn("inside the Gradle root", result["reason"])
            run.assert_not_called()

    def test_relative_checkout_is_forwarded_to_builder_as_absolute_paths(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            absolute_root = Path(directory)
            (absolute_root / "gradlew").write_text("", encoding="utf-8")
            source = absolute_root / "app/src/main/java/example/Foo.java"
            source.parent.mkdir(parents=True)
            source.write_text("class Foo {}", encoding="utf-8")
            relative_root = absolute_root.relative_to(Path.cwd())
            relative_source = relative_root / source.relative_to(absolute_root)

            completed = subprocess.CompletedProcess([], 0, "", "")
            with mock.patch.object(
                pr_validation.subprocess, "run", return_value=completed,
            ) as run, mock.patch.object(
                pr_validation, "_load_build_result", return_value={"status": "success"},
            ):
                result = pr_validation.run_compile_validation(
                    relative_root, [relative_source], Path("scripts/build.py"),
                    relative_root / "out", "debug", 60,
                )

            self.assertEqual(result["status"], "SUCCESS")
            command = run.call_args.args[0]
            projects_dir = Path(command[command.index("--projects-dir") + 1])
            output_dir = Path(command[command.index("--output-dir") + 1])
            self.assertTrue(projects_dir.is_absolute())
            self.assertTrue(output_dir.is_absolute())
            self.assertTrue(run.call_args.kwargs["cwd"].is_absolute())


class FeedbackFromPrTests(unittest.TestCase):
    def _pr(self):
        return {
            "comments_url": "https://api/issues/1/comments",
            "review_comments_url": "https://api/pulls/1/comments",
            "url": "https://api/pulls/1",
        }

    def test_review_with_empty_body_and_changes_requested_is_kept(self):
        by_url = {
            "https://api/issues/1/comments": [],
            "https://api/pulls/1/comments": [],
            "https://api/pulls/1/reviews": [
                {"body": "", "state": "CHANGES_REQUESTED", "user": {"login": "m"}},
            ],
        }
        with mock.patch.object(
            pr_github, "fetch_all", side_effect=lambda url: by_url[url]
        ):
            feedback = pr_github.feedback_from_pr(self._pr())
        self.assertEqual(len(feedback), 1)
        self.assertEqual(feedback[0]["review_state"], "CHANGES_REQUESTED")

    def test_review_with_empty_body_and_only_a_comment_state_is_dropped(self):
        by_url = {
            "https://api/issues/1/comments": [],
            "https://api/pulls/1/comments": [],
            "https://api/pulls/1/reviews": [
                {"body": "", "state": "COMMENTED", "user": {"login": "m"}},
            ],
        }
        with mock.patch.object(
            pr_github, "fetch_all", side_effect=lambda url: by_url[url]
        ):
            feedback = pr_github.feedback_from_pr(self._pr())
        self.assertEqual(feedback, [])

    def test_inline_comment_without_a_live_position_is_marked_outdated(self):
        by_url = {
            "https://api/issues/1/comments": [],
            "https://api/pulls/1/comments": [
                {
                    "body": "please fix this",
                    "position": None,
                    "user": {"login": "m"},
                },
            ],
            "https://api/pulls/1/reviews": [],
        }
        with mock.patch.object(
            pr_github, "fetch_all", side_effect=lambda url: by_url[url]
        ):
            feedback = pr_github.feedback_from_pr(self._pr())
        self.assertEqual(len(feedback), 1)
        self.assertTrue(feedback[0]["outdated"])

    def test_a_review_bots_comments_are_not_maintainer_feedback(self):
        # NotallyX#1167 (2026-10-30): coderabbitai[bot]'s review, with its
        # "Prompt for AI Agents" block, was read as maintainer feedback.
        # Bots are read by pr_followup, as untrusted data.
        by_url = {
            "https://api/issues/1/comments": [
                {"body": "Walkthrough", "user": {"login": "coderabbitai[bot]", "type": "Bot"}},
                {"body": "Thanks, please rename it", "user": {"login": "m", "type": "User"}},
            ],
            "https://api/pulls/1/comments": [
                {"body": "Prompt for AI Agents: do X", "position": 3,
                 "user": {"login": "gemini-code-assist", "type": "User"}},
            ],
            "https://api/pulls/1/reviews": [
                {"body": "Nitpick", "state": "COMMENTED",
                 "user": {"login": "sourcery-ai[bot]", "type": "Bot"}},
            ],
        }
        with mock.patch.object(
            pr_github, "fetch_all", side_effect=lambda url: by_url[url]
        ):
            feedback = pr_github.feedback_from_pr(self._pr())
        self.assertEqual([item["author"] for item in feedback], ["m"])

    def test_inline_comment_with_a_live_position_is_not_outdated(self):
        by_url = {
            "https://api/issues/1/comments": [],
            "https://api/pulls/1/comments": [
                {"body": "please fix this", "position": 4, "user": {"login": "m"}},
            ],
            "https://api/pulls/1/reviews": [],
        }
        with mock.patch.object(
            pr_github, "fetch_all", side_effect=lambda url: by_url[url]
        ):
            feedback = pr_github.feedback_from_pr(self._pr())
        self.assertFalse(feedback[0]["outdated"])


class FetchCurrentPrStateTests(unittest.TestCase):
    def _mock_response(self, status_code: int, payload: dict):
        response = mock.Mock()
        response.status_code = status_code
        response.json.return_value = payload
        response.raise_for_status.side_effect = (
            None if status_code < 400 else Exception("http error")
        )
        return response

    def test_open_pr_reports_open(self):
        with mock.patch.object(
            pr_github.requests, "get",
            return_value=self._mock_response(200, {"state": "open"}),
        ):
            state = fix_prs.fetch_current_pr_state({"url": "https://api/pulls/1"})
        self.assertEqual(state["status"], "open")

    def test_merged_pr_is_reported_as_merged_not_closed(self):
        with mock.patch.object(
            pr_github.requests, "get",
            return_value=self._mock_response(
                200, {"state": "closed", "merged": True}
            ),
        ):
            state = fix_prs.fetch_current_pr_state({"url": "https://api/pulls/1"})
        self.assertEqual(state["status"], "merged")

    def test_closed_unmerged_pr_is_reported_as_closed(self):
        with mock.patch.object(
            pr_github.requests, "get",
            return_value=self._mock_response(
                200, {"state": "closed", "merged": False}
            ),
        ):
            state = fix_prs.fetch_current_pr_state({"url": "https://api/pulls/1"})
        self.assertEqual(state["status"], "closed")

    def test_deleted_pr_is_reported_as_not_found(self):
        with mock.patch.object(
            pr_github.requests, "get",
            return_value=self._mock_response(404, {}),
        ):
            state = fix_prs.fetch_current_pr_state({"url": "https://api/pulls/1"})
        self.assertEqual(state["status"], "not_found")

    def test_missing_api_url_is_unknown_without_a_request(self):
        with mock.patch.object(pr_github.requests, "get") as get:
            state = fix_prs.fetch_current_pr_state({})
        get.assert_not_called()
        self.assertEqual(state["status"], "unknown")


class PathFromLogExcerptTests(unittest.TestCase):
    def test_finds_a_kotlin_file_named_in_a_lint_error(self):
        log = (
            "> Task :app:ktlintCheck\n"
            "app/src/main/java/com/example/Foo.kt:15:1: Unused import\n"
        )
        self.assertEqual(
            pr_github.path_from_log_excerpt(log),
            "app/src/main/java/com/example/Foo.kt",
        )

    def test_returns_empty_string_when_no_file_is_named(self):
        log = (
            "Could not resolve com.pinterest.ktlint:ktlint-cli:1.5.0.\n"
            "> Could not GET 'https://repo.maven.apache.org/...': "
            "Received status code 403 from server"
        )
        self.assertEqual(pr_github.path_from_log_excerpt(log), "")


class BuildFileCandidatesTests(unittest.TestCase):
    def test_offers_only_build_files_that_actually_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            (root / "app" / "build.gradle.kts").write_text("", encoding="utf-8")
            ci_failures = [{"path": ""}]

            candidates = fix_prs.build_file_candidates(root, ci_failures, set())

            self.assertEqual(candidates, ["app/build.gradle.kts"])

    def test_offers_nothing_when_every_ci_failure_already_names_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build.gradle.kts").write_text("", encoding="utf-8")
            ci_failures = [{"path": "app/src/main/Foo.kt"}]

            candidates = fix_prs.build_file_candidates(root, ci_failures, set())

            self.assertEqual(candidates, [])

    def test_skips_paths_already_covered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build.gradle.kts").write_text("", encoding="utf-8")
            ci_failures = [{"path": ""}]

            candidates = fix_prs.build_file_candidates(
                root, ci_failures, {"build.gradle.kts"},
            )

            self.assertEqual(candidates, [])


class FetchCheckRunsTests(unittest.TestCase):
    def _mock_response(self, payload: dict, links: dict | None = None):
        response = mock.Mock()
        response.json.return_value = payload
        response.raise_for_status.side_effect = None
        response.links = links or {}
        return response

    def test_returns_the_check_runs_list(self):
        response = self._mock_response({"check_runs": [{"id": 1}, {"id": 2}]})
        with mock.patch.object(pr_github.requests, "get", return_value=response):
            runs = pr_github.fetch_check_runs("owner/repo", "abc123")
        self.assertEqual([run["id"] for run in runs], [1, 2])

    def test_follows_pagination_via_link_header(self):
        first = self._mock_response(
            {"check_runs": [{"id": 1}]},
            links={"next": {"url": "https://api.github.com/next"}},
        )
        second = self._mock_response({"check_runs": [{"id": 2}]})
        with mock.patch.object(
            pr_github.requests, "get", side_effect=[first, second]
        ):
            runs = pr_github.fetch_check_runs("owner/repo", "abc123")
        self.assertEqual([run["id"] for run in runs], [1, 2])


class FetchJobLogExcerptTests(unittest.TestCase):
    def test_returns_only_the_tail_of_a_long_log(self):
        response = mock.Mock()
        response.text = "x" * 100 + "IMPORTANT ERROR"
        response.raise_for_status.side_effect = None
        with mock.patch.object(pr_github.requests, "get", return_value=response):
            excerpt = pr_github.fetch_job_log_excerpt("owner/repo", 123, max_chars=15)
        self.assertEqual(excerpt, "IMPORTANT ERROR")
        self.assertEqual(len(excerpt), 15)


class JobReproducesOnBaseTests(unittest.TestCase):
    def _responses(self, runs_payload, jobs_payload):
        def fake_get(url, headers=None, params=None, timeout=None):
            response = mock.Mock()
            response.raise_for_status.side_effect = None
            if "actions/runs" in url and "jobs" not in url:
                response.json.return_value = runs_payload
            else:
                response.json.return_value = jobs_payload
            return response
        return fake_get

    def test_true_when_the_same_job_also_failed_on_base(self):
        runs = {"workflow_runs": [{"jobs_url": "https://api/runs/1/jobs"}]}
        jobs = {"jobs": [{"name": "ktlint", "conclusion": "failure"}]}
        with mock.patch.object(
            pr_github.requests, "get", side_effect=self._responses(runs, jobs)
        ):
            result = pr_github.job_reproduces_on_base("owner/repo", "ktlint", "master")
        self.assertTrue(result)

    def test_false_when_the_same_job_passed_on_base(self):
        runs = {"workflow_runs": [{"jobs_url": "https://api/runs/1/jobs"}]}
        jobs = {"jobs": [{"name": "ktlint", "conclusion": "success"}]}
        with mock.patch.object(
            pr_github.requests, "get", side_effect=self._responses(runs, jobs)
        ):
            result = pr_github.job_reproduces_on_base("owner/repo", "ktlint", "master")
        self.assertFalse(result)

    def test_none_when_no_matching_job_is_found(self):
        runs = {"workflow_runs": [{"jobs_url": "https://api/runs/1/jobs"}]}
        jobs = {"jobs": [{"name": "unit-tests", "conclusion": "success"}]}
        with mock.patch.object(
            pr_github.requests, "get", side_effect=self._responses(runs, jobs)
        ):
            result = pr_github.job_reproduces_on_base("owner/repo", "ktlint", "master")
        self.assertIsNone(result)

    def test_none_when_there_is_no_completed_run_on_base(self):
        runs = {"workflow_runs": []}
        with mock.patch.object(
            pr_github.requests, "get", side_effect=self._responses(runs, {})
        ):
            result = pr_github.job_reproduces_on_base("owner/repo", "ktlint", "master")
        self.assertIsNone(result)


class CiFailuresFromPrTests(unittest.TestCase):
    def _pr(self):
        return {
            "base": {"ref": "master", "repo": {"full_name": "owner/repo"}},
            "head": {"sha": "abc123"},
        }

    def test_returns_empty_list_when_repo_or_sha_is_missing(self):
        self.assertEqual(pr_github.ci_failures_from_pr({}), [])

    def test_skips_checks_that_did_not_fail(self):
        with mock.patch.object(
            pr_github, "fetch_check_runs",
            return_value=[{"name": "unit-tests", "conclusion": "success"}],
        ):
            self.assertEqual(pr_github.ci_failures_from_pr(self._pr()), [])

    def test_builds_a_feedback_shaped_entry_for_a_failed_check(self):
        with mock.patch.object(
            pr_github, "fetch_check_runs",
            return_value=[{
                "name": "ktlint", "id": 999, "conclusion": "failure",
                "html_url": "https://github.com/owner/repo/actions/runs/1/job/999",
            }],
        ), mock.patch.object(
            pr_github, "fetch_job_log_excerpt",
            return_value="Could not resolve ktlint-cli:1.5.0",
        ), mock.patch.object(
            pr_github, "job_reproduces_on_base", return_value=True,
        ):
            entries = pr_github.ci_failures_from_pr(self._pr())

        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["kind"], "ci_failure")
        self.assertEqual(entry["check_name"], "ktlint")
        self.assertTrue(entry["reproduces_on_base"])
        self.assertIn("pre-existing", entry["body"])
        self.assertIn("ktlint-cli:1.5.0", entry["body"])

    def test_degrades_to_empty_list_on_network_failure(self):
        with mock.patch.object(
            pr_github, "fetch_check_runs", side_effect=RuntimeError("network down"),
        ):
            self.assertEqual(pr_github.ci_failures_from_pr(self._pr()), [])


class CiFailureCommentBodyTests(unittest.TestCase):
    def test_summarizes_each_check_and_includes_the_explanation(self):
        record = {
            "ci_failures": [
                {"check_name": "ktlint", "reproduces_on_base": True},
            ],
            "llm_revision": {"explanation": "Bumped the ktlint version."},
        }
        body = pr_github.ci_failure_comment_body(record)
        self.assertIn("ktlint", body)
        self.assertIn("pre-existing", body)
        self.assertIn("Bumped the ktlint version.", body)


class PostPrCommentTests(unittest.TestCase):
    def test_does_nothing_without_a_comments_url(self):
        with mock.patch.object(pr_github.requests, "post") as post:
            fix_prs.post_pr_comment("", "body")
        post.assert_not_called()

    def test_posts_the_body_to_the_comments_url(self):
        response = mock.Mock()
        response.raise_for_status.side_effect = None
        with mock.patch.object(
            pr_github.requests, "post", return_value=response
        ) as post:
            fix_prs.post_pr_comment("https://api/issues/1/comments", "hello")
        post.assert_called_once()
        self.assertEqual(
            post.call_args.kwargs["json"], {"body": "hello"},
        )


class RunRevalidationTests(unittest.TestCase):
    def _args(self, output: Path, **overrides) -> argparse.Namespace:
        base = dict(
            output=str(output), project="", skip_compile_validation=True,
            skip_validation=True, build_script=Path("build_script.py"),
            build_variant="debug", build_timeout=1800, timeout=60,
            publish=False, dry_run=False, commit_message="msg {method_name}",
            # Every record _write_report writes is finding f1, approved here;
            # RevisionApprovalTests covers a finding that is not.
            approve_revision=["f1"], pull_requests_dir="",
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    def _write_report(self, path: Path, results: list) -> None:
        path.write_text(
            json.dumps({"results": [{"finding_id": "f1", **item} for item in results]}),
            encoding="utf-8",
        )

    def test_non_applied_entries_are_left_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            self._write_report(output, [{"status": "NO_SAFE_FIX", "project": "a"}])

            code = fix_prs.run_revalidation(self._args(output))

            self.assertEqual(code, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["results"][0]["status"], "NO_SAFE_FIX")

    def test_applied_entry_missing_checkout_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            self._write_report(output, [{"status": "APPLIED", "project": "a"}])

            code = fix_prs.run_revalidation(self._args(output))

            self.assertEqual(code, 1)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["results"][0]["status"], "FAILED")

    def test_applied_entry_with_both_checks_skipped_is_revalidated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.java").write_text("class A {}", encoding="utf-8")
            output = root / "report.json"
            self._write_report(output, [{
                "status": "APPLIED", "project": "a", "checkout": str(root),
                "changed_files": ["A.java"], "branch": "fix/x",
                "method_name": "m",
            }])

            code = fix_prs.run_revalidation(self._args(output))

            self.assertEqual(code, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["results"][0]["status"], "REVALIDATED")

    def test_failed_compile_entry_can_be_retried_from_revalidation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.java").write_text("class A {}", encoding="utf-8")
            output = root / "report.json"
            self._write_report(output, [{
                "status": "FAILED", "project": "a", "checkout": str(root),
                "changed_files": ["A.java"], "branch": "fix/x",
                "method_name": "m", "error": "revised project did not compile",
                "compile_validation": {"status": "FAILED"},
            }])

            code = fix_prs.run_revalidation(self._args(output))

            self.assertEqual(code, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["results"][0]["status"], "REVALIDATED")
            self.assertNotIn("error", report["results"][0])

    def test_project_filter_skips_non_matching_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.java").write_text("class A {}", encoding="utf-8")
            output = root / "report.json"
            self._write_report(output, [{
                "status": "APPLIED", "project": "other", "checkout": str(root),
                "changed_files": ["A.java"], "branch": "fix/x",
            }])

            code = fix_prs.run_revalidation(self._args(output, project="a"))

            self.assertEqual(code, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["results"][0]["status"], "APPLIED")

    def test_publish_is_called_with_the_stored_branch_and_changed_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.java").write_text("class A {}", encoding="utf-8")
            output = root / "report.json"
            self._write_report(output, [{
                "status": "APPLIED", "project": "a", "checkout": str(root),
                "changed_files": ["A.java"], "branch": "fix/x",
                "method_name": "m",
            }])

            with mock.patch.object(
                fix_prs, "publish_revision", return_value="abc123",
            ) as publish:
                code = fix_prs.run_revalidation(self._args(output, publish=True))

            self.assertEqual(code, 0)
            publish.assert_called_once()
            call_args = publish.call_args[0]
            self.assertEqual(call_args[0], root)
            self.assertEqual(call_args[1], [root / "A.java"])
            self.assertEqual(call_args[2], "fix/x")
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["results"][0]["status"], "PUBLISHED")
            self.assertEqual(report["results"][0]["commit"], "abc123")

    def test_publish_posts_a_ci_failure_explanation_comment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.java").write_text("class A {}", encoding="utf-8")
            output = root / "report.json"
            self._write_report(output, [{
                "status": "APPLIED", "project": "a", "checkout": str(root),
                "changed_files": ["A.java"], "branch": "fix/x",
                "method_name": "m",
                "comments_url": "https://api/issues/1/comments",
                "ci_failures": [
                    {"check_name": "ktlint", "reproduces_on_base": True,
                     "url": "https://example/checks/1"},
                ],
                "llm_revision": {"explanation": "Bumped the ktlint version."},
            }])

            with mock.patch.object(
                fix_prs, "publish_revision", return_value="abc123",
            ), mock.patch.object(fix_prs, "post_pr_comment") as comment:
                code = fix_prs.run_revalidation(self._args(output, publish=True))

            self.assertEqual(code, 0)
            comment.assert_called_once()
            call_args = comment.call_args[0]
            self.assertEqual(call_args[0], "https://api/issues/1/comments")
            self.assertIn("ktlint", call_args[1])
            self.assertIn("Bumped the ktlint version.", call_args[1])

    def test_publish_does_not_post_a_comment_without_ci_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.java").write_text("class A {}", encoding="utf-8")
            output = root / "report.json"
            self._write_report(output, [{
                "status": "APPLIED", "project": "a", "checkout": str(root),
                "changed_files": ["A.java"], "branch": "fix/x",
                "method_name": "m",
                "comments_url": "https://api/issues/1/comments",
            }])

            with mock.patch.object(
                fix_prs, "publish_revision", return_value="abc123",
            ), mock.patch.object(fix_prs, "post_pr_comment") as comment:
                code = fix_prs.run_revalidation(self._args(output, publish=True))

            self.assertEqual(code, 0)
            comment.assert_not_called()

    def test_comment_posting_failure_does_not_undo_a_successful_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.java").write_text("class A {}", encoding="utf-8")
            output = root / "report.json"
            self._write_report(output, [{
                "status": "APPLIED", "project": "a", "checkout": str(root),
                "changed_files": ["A.java"], "branch": "fix/x",
                "method_name": "m",
                "comments_url": "https://api/issues/1/comments",
                "ci_failures": [{"check_name": "ktlint",
                                  "reproduces_on_base": True, "url": ""}],
            }])

            with mock.patch.object(
                fix_prs, "publish_revision", return_value="abc123",
            ), mock.patch.object(
                fix_prs, "post_pr_comment", side_effect=RuntimeError("boom"),
            ):
                code = fix_prs.run_revalidation(self._args(output, publish=True))

            self.assertEqual(code, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["results"][0]["status"], "PUBLISHED")

    def test_publish_reuses_an_existing_successful_revalidation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.java").write_text("class A {}", encoding="utf-8")
            output = root / "report.json"
            self._write_report(output, [{
                "status": "REVALIDATED", "project": "a",
                "checkout": str(root), "changed_files": ["A.java"],
                "branch": "fix/x", "method_name": "m",
                "compile_validation": {"status": "SUCCESS"},
            }])

            with mock.patch.object(
                fix_prs, "run_compile_validation",
            ) as compile_validation, mock.patch.object(
                fix_prs, "run_style_validation",
            ) as style_validation, mock.patch.object(
                fix_prs, "publish_revision", return_value="abc123",
            ) as publish:
                code = fix_prs.run_revalidation(
                    self._args(
                        output, publish=True, skip_compile_validation=False,
                        skip_validation=False,
                    )
                )

            self.assertEqual(code, 0)
            compile_validation.assert_not_called()
            style_validation.assert_not_called()
            publish.assert_called_once_with(root, [root / "A.java"], "fix/x", "msg m")
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["results"][0]["status"], "PUBLISHED")
            self.assertEqual(report["results"][0]["commit"], "abc123")


class RevisionApprovalTests(unittest.TestCase):
    """A revalidated revision reaches GitHub only for a finding named by
    --approve-revision. --publish alone pushed every revision of the report,
    rewrote its pull request's text and posted its reply (batch6 audit,
    2026-10-30)."""

    def _args(self, output: Path, pr_dir: Path, approve: list) -> argparse.Namespace:
        return argparse.Namespace(
            output=str(output), project="", skip_compile_validation=True,
            skip_validation=True, build_script=Path("build_script.py"),
            build_variant="debug", build_timeout=1800, timeout=60,
            publish=True, dry_run=False, commit_message="msg {method_name}",
            approve_revision=approve, pull_requests_dir=str(pr_dir),
        )

    def _report(self, root: Path, **extra) -> Path:
        (root / "A.java").write_text("class A {}", encoding="utf-8")
        output = root / "report.json"
        output.write_text(json.dumps({"results": [{
            "status": "APPLIED", "project": "a", "checkout": str(root),
            "changed_files": ["A.java"], "branch": "fix/x", "method_name": "m",
            "pull_request": "https://github.com/o/r/pull/7",
            "pull_request_api_url": "https://api.github.com/repos/o/r/pulls/7",
            "comments_url": "https://api.github.com/repos/o/r/issues/7/comments",
            "pr_metadata_update": {"body": "new text"},
            "maintainer_reply": "Thanks, done.", **extra,
        }]}), encoding="utf-8")
        return output

    def _run(self, output: Path, args: argparse.Namespace):
        with mock.patch.object(fix_prs, "publish_revision", return_value="abc123") as push, \
                mock.patch.object(fix_prs, "update_pr_metadata") as update, \
                mock.patch.object(fix_prs, "post_pr_comment") as comment:
            code = fix_prs.run_revalidation(args)
        return code, push, update, comment, json.loads(output.read_text(encoding="utf-8"))

    def test_nothing_is_sent_for_a_finding_not_named(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = self._report(root, finding_id="f1")
            code, push, update, comment, report = self._run(
                output, self._args(output, root, ["another"]))
        self.assertEqual(code, 0)
        push.assert_not_called()
        update.assert_not_called()
        comment.assert_not_called()
        record = report["results"][0]
        self.assertEqual(record["status"], "REVALIDATED")
        self.assertEqual(record["publish"]["status"], "NOT_APPROVED")
        self.assertIn("--approve-revision f1", record["publish"]["reason"])
        self.assertEqual(record["publish"]["would_update"], {"body": "new text"})
        self.assertEqual(record["publish"]["would_reply"], "Thanks, done.")

    def test_the_named_finding_is_pushed_text_updated_and_replied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = self._report(root, finding_id="f1")
            code, push, update, comment, report = self._run(
                output, self._args(output, root, ["f1"]))
        self.assertEqual(code, 0)
        push.assert_called_once()
        update.assert_called_once_with("https://api.github.com/repos/o/r/pulls/7",
                                       {"body": "new text"})
        comment.assert_called_once()
        self.assertEqual(report["results"][0]["status"], "PUBLISHED")
        self.assertNotIn("publish", report["results"][0])

    def test_a_record_written_before_finding_id_is_named_through_its_pr_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pr_dir = root / "pull_requests"
            pr_dir.mkdir()
            (pr_dir / "a_m_pr.json").write_text(json.dumps({"finding_id": "f9"}),
                                               encoding="utf-8")
            (pr_dir / "a_m_pr_created.json").write_text(json.dumps(
                {"html_url": "https://github.com/o/r/pull/7"}), encoding="utf-8")
            output = self._report(root)
            self.assertEqual(fix_prs.revision_finding_id(
                json.loads(output.read_text(encoding="utf-8"))["results"][0], pr_dir), "f9")
            code, push, _, _, report = self._run(output, self._args(output, pr_dir, ["f9"]))
        push.assert_called_once()
        self.assertEqual(report["results"][0]["status"], "PUBLISHED")


class RunRevisionPreservesPriorReportTests(unittest.TestCase):
    """A plain (non --revalidate) run re-fetches live PR comments and used to
    rebuild the whole report from scratch every time, so re-running it
    silently discarded whatever revalidation_fix_prs had already recorded
    (REVALIDATED/PUBLISHED, compile/style results) whenever the maintainer
    feedback had not actually changed, and dropped every other project's
    record outright when run with --project. These tests pin the fix.
    """

    def _write_pr_files(self, pr_dir: Path, stem: str, repository: str) -> None:
        (pr_dir / f"{stem}_pr_created.json").write_text(
            json.dumps({"html_url": f"https://example/pull/{stem}"}),
            encoding="utf-8",
        )
        (pr_dir / f"{stem}_pr.json").write_text(
            json.dumps({"repository": repository}), encoding="utf-8",
        )

    def _args(self, pr_dir: Path, output: Path, **overrides) -> argparse.Namespace:
        base = dict(
            pull_requests_dir=str(pr_dir), projects_dir=str(pr_dir),
            worktrees_dir=str(pr_dir), output=str(output), project="",
            model="m", endpoint="https://x", timeout=60, max_output_tokens=100,
            reasoning_effort="high", prompt_log_dir=None,
            skip_pr_state_check=True, dry_run=False, fix_ci_failures=False,
            self_audit=False,
        )
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_skips_re_revision_when_feedback_is_unchanged_since_revalidation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_pr_files(root, "a", repository="a")
            feedback = [{"kind": "review", "body": "please fix", "url": "c1"}]
            signature = hashlib.sha256(
                json.dumps(feedback, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()
            output = root / "report.json"
            output.write_text(json.dumps({"results": [{
                "project": "a", "status": "REVALIDATED",
                "feedback_signature": signature,
            }]}), encoding="utf-8")

            with mock.patch.object(
                fix_prs, "feedback_from_pr", return_value=feedback,
            ), mock.patch.object(fix_prs, "OpenAIProvider") as provider_cls:
                provider_cls.return_value.get_token_usage.return_value = {}
                code = fix_prs.run_revision(self._args(root, output))

            provider_cls.return_value.generate.assert_not_called()
            self.assertEqual(code, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(report["results"]), 1)
            self.assertEqual(report["results"][0]["status"], "REVALIDATED")

    def test_fix_ci_failures_disabled_never_looks_up_ci_and_reports_no_feedback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_pr_files(root, "a", repository="a")
            output = root / "report.json"

            with mock.patch.object(
                fix_prs, "feedback_from_pr", return_value=[],
            ), mock.patch.object(
                fix_prs, "ci_failures_from_pr",
            ) as ci_lookup, mock.patch.object(
                fix_prs, "OpenAIProvider"
            ) as provider_cls:
                provider_cls.return_value.get_token_usage.return_value = {}
                code = fix_prs.run_revision(
                    self._args(root, output, fix_ci_failures=False)
                )

            ci_lookup.assert_not_called()
            self.assertEqual(code, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["results"][0]["status"], "NO_FEEDBACK")

    def test_fix_ci_failures_enabled_but_no_failures_still_reports_no_feedback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_pr_files(root, "a", repository="a")
            output = root / "report.json"

            with mock.patch.object(
                fix_prs, "feedback_from_pr", return_value=[],
            ), mock.patch.object(
                fix_prs, "ci_failures_from_pr", return_value=[],
            ) as ci_lookup, mock.patch.object(
                fix_prs, "OpenAIProvider"
            ) as provider_cls:
                provider_cls.return_value.get_token_usage.return_value = {}
                code = fix_prs.run_revision(
                    self._args(root, output, fix_ci_failures=True)
                )

            ci_lookup.assert_called_once()
            self.assertEqual(code, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["results"][0]["status"], "NO_FEEDBACK")

    def test_fix_ci_failures_enabled_with_failures_proceeds_past_no_feedback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_pr_files(root, "a", repository="a")
            output = root / "report.json"
            ci_failure = {
                "kind": "ci_failure", "author": "github-actions",
                "body": "ktlint failed", "path": "", "line": None,
                "diff_hunk": "", "url": "https://example/checks/1",
                "check_name": "ktlint", "reproduces_on_base": True,
            }

            with mock.patch.object(
                fix_prs, "feedback_from_pr", return_value=[],
            ), mock.patch.object(
                fix_prs, "ci_failures_from_pr", return_value=[ci_failure],
            ), mock.patch.object(
                fix_prs, "OpenAIProvider"
            ) as provider_cls:
                provider_cls.return_value.get_token_usage.return_value = {}
                code = fix_prs.run_revision(
                    self._args(root, output, fix_ci_failures=True)
                )

            self.assertEqual(code, 1)
            report = json.loads(output.read_text(encoding="utf-8"))
            result = report["results"][0]
            # No real project checkout exists at this path, so this fails
            # later at checkout -- proof the NO_FEEDBACK gate was passed.
            self.assertNotEqual(result["status"], "NO_FEEDBACK")
            self.assertEqual(
                [item["check_name"] for item in result["ci_failures"]],
                ["ktlint"],
            )

    def test_preserves_previous_result_for_a_project_without_a_current_pr_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_pr_files(root, "a", repository="a")
            output = root / "report.json"
            output.write_text(json.dumps({"results": [
                {"project": "a", "status": "NO_FEEDBACK"},
                {"project": "b", "status": "PUBLISHED", "commit": "abc123"},
            ]}), encoding="utf-8")

            with mock.patch.object(
                fix_prs, "feedback_from_pr", return_value=[],
            ), mock.patch.object(fix_prs, "OpenAIProvider") as provider_cls:
                provider_cls.return_value.get_token_usage.return_value = {}
                code = fix_prs.run_revision(self._args(root, output))

            provider_cls.return_value.generate.assert_not_called()
            self.assertEqual(code, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            by_project = {row["project"]: row for row in report["results"]}
            self.assertEqual(by_project["a"]["status"], "NO_FEEDBACK")
            self.assertEqual(by_project["b"]["status"], "PUBLISHED")
            self.assertEqual(by_project["b"]["commit"], "abc123")


class CreateEditSupportTests(unittest.TestCase):
    """A revision must be able to relocate code, not only delete it.

    Asked to move misplaced TLS tests out of DateFormattingTest.kt, the model
    could only emit deletions because edit_kind=create was rejected, so the
    proposal removed the coverage instead of rehoming it.
    """

    def _edit(self, **overrides):
        edit = {
            "source_file_path": ("app/src/androidTest/java/com/nononsenseapps/"
                                 "jsonfeed/OkHttpBuilderExtensionsTlsProtocolTest.kt"),
            "symbol": "OkHttpBuilderExtensionsTlsProtocolTest",
            "edit_kind": "create",
            "original_code": "",
            "corrected_code": "package com.nononsenseapps.jsonfeed\n\nclass T\n",
            "reason": "Rehome the misplaced TLS assertions",
        }
        edit.update(overrides)
        return edit

    def test_creates_a_file_absent_from_current_files(self):
        updated, issues = fix_prs.apply_coordinated_edits(
            {"app/src/main/A.kt": "class A\n"}, [self._edit()]
        )
        self.assertEqual(issues, [])
        self.assertIn(self._edit()["source_file_path"], updated)
        self.assertIn("class T", updated[self._edit()["source_file_path"]])

    def test_relocation_pairs_create_with_delete(self):
        existing = "app/src/androidTest/java/com/nononsenseapps/feeder/DateFormattingTest.kt"
        updated, issues = fix_prs.apply_coordinated_edits(
            {existing: "class D {\n  fun tls() { assert(true) }\n}\n"},
            [
                self._edit(),
                {
                    "source_file_path": existing,
                    "symbol": "tls", "edit_kind": "delete",
                    "original_code": "  fun tls() { assert(true) }\n",
                    "corrected_code": "",
                    "reason": "Remove the misplaced TLS assertions",
                },
            ],
        )
        self.assertEqual(issues, [])
        self.assertNotIn("fun tls", updated[existing])
        self.assertIn("class T", updated[self._edit()["source_file_path"]])

    def test_create_must_not_clobber_an_existing_file(self):
        path = self._edit()["source_file_path"]
        _updated, issues = fix_prs.apply_coordinated_edits(
            {path: "class Existing\n"}, [self._edit()]
        )
        self.assertTrue(any("already exists" in issue for issue in issues))

    def test_create_still_requires_content_and_empty_original(self):
        for override, expected in (
            ({"corrected_code": "   "}, "non-empty file content"),
            ({"original_code": "something"}, "exactly empty original_code"),
        ):
            with self.subTest(override=override):
                _updated, issues = fix_prs.apply_coordinated_edits(
                    {}, [self._edit(**override)]
                )
                self.assertTrue(
                    any(expected in issue for issue in issues), issues
                )


class PublishStagingTests(unittest.TestCase):
    """Publishing must tolerate a revised file that ends with no net change.

    repair_style_violations runs the project's own ktlintFormat, which undid a
    reformatting the model had proposed for OkHttpBuilderExtensions.kt and
    restored it byte-for-byte. That file stayed in changed_files, so requiring
    every listed file to be staged aborted the publish -- even though the real
    change, relocating the misplaced TLS tests, was staged and correct.
    """

    def _repo(self, directory: str) -> Path:
        root = Path(directory)
        for command in (
            ["git", "init", "-q", "-b", "fix/x", str(root)],
            ["git", "-C", str(root), "config", "user.email", "t@t"],
            ["git", "-C", str(root), "config", "user.name", "t"],
        ):
            subprocess.run(command, check=True, capture_output=True)
        (root / "Untouched.kt").write_text("class Untouched\n", encoding="utf-8")
        (root / "Moved.kt").write_text("class Moved\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "-A"],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "base"],
                       check=True, capture_output=True)
        return root

    def test_commits_the_files_that_actually_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory)
            # Only one of the two "revised" files really differs.
            (root / "Moved.kt").write_text("class Moved { fun tls() {} }\n",
                                           encoding="utf-8")
            sources = [root / "Untouched.kt", root / "Moved.kt"]

            pushes = []
            original_run_git = fix_prs.run_git

            def without_pushing(project_root, *args, **kwargs):
                if args and args[0] == "push":
                    pushes.append(args)
                    return ""
                return original_run_git(project_root, *args, **kwargs)

            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "t"}), \
                 mock.patch.object(pr_github, "run_git", without_pushing):
                commit = pr_github.publish_revision(root, sources, "fix/x", "revise")

            self.assertTrue(commit)
            self.assertEqual(len(pushes), 1)
            committed = subprocess.run(
                ["git", "-C", str(root), "show", "--name-only", "--format=", "HEAD"],
                capture_output=True, text=True,
            ).stdout.split()
            self.assertEqual(committed, ["Moved.kt"])

    def test_still_refuses_when_nothing_changed_at_all(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory)
            sources = [root / "Untouched.kt", root / "Moved.kt"]
            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "t"}):
                with self.assertRaises(RuntimeError) as caught:
                    pr_github.publish_revision(root, sources, "fix/x", "revise")
            self.assertIn("any of", str(caught.exception))


class ShapeRetryPromptTests(unittest.TestCase):
    """The revision prompt must make the delete/empty pairing unmissable.

    The real failure was a complete four-edit relocation discarded because one
    removal was labelled "test" while carrying empty corrected_code.
    """

    def test_prompt_states_that_a_removal_is_always_delete(self):
        _system, user = fix_prs.coordinated_prompts({
            "pull_request": "", "method_name": "m", "source_file": "A.kt",
            "original_finding": {}, "current_method": "", "method_lines": [1, 2],
            "maintainer_feedback": [], "current_files": {},
            "repository_style_context": "", "repository_symbol_evidence": "",
        })
        combined = _system + user
        self.assertIn("edit_kind must be exactly \"delete\"", combined)
        self.assertIn("not \"test\"", combined)

    def test_retry_feedback_is_carried_into_the_prompt(self):
        _system, user = fix_prs.coordinated_prompts({
            "pull_request": "", "method_name": "m", "source_file": "A.kt",
            "original_finding": {}, "current_method": "", "method_lines": [1, 2],
            "maintainer_feedback": [], "current_files": {},
            "repository_style_context": "", "repository_symbol_evidence": "",
            "rejected_edits_feedback": {
                "instruction": "fix the shape",
                "issues": ["X.kt: replacement edit requires non-empty corrected_code"],
                "previous_edits": [],
            },
        })
        self.assertIn("replacement edit requires non-empty corrected_code", user)


class RepairStyleViolationsTests(unittest.TestCase):
    """ktlint formatting failures are fixed by the project's own formatter.

    PR #1210's revision compiled but failed :app:ktlintCheck on
    "Newline expected after opening parenthesis" -- a pure formatting rule that
    ktlintFormat rewrites exactly, so the revision should not be abandoned over
    it. ktlintFormat touches the whole source set, so unrelated files it
    reformats must be restored before they reach someone else's pull request.
    """

    def _project(self, directory: str) -> Path:
        root = Path(directory)
        (root / "app" / "src").mkdir(parents=True)
        (root / "app" / "build.gradle.kts").write_text("", encoding="utf-8")
        (root / "gradlew").write_text("#!/bin/sh\n", encoding="utf-8")
        return root

    def test_reverts_files_the_formatter_touched_outside_the_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._project(directory)
            patched = root / "app" / "src" / "Patched.kt"
            unrelated = "app/src/Unrelated.kt"
            patched.write_text("class Patched\n", encoding="utf-8")

            calls = []

            def fake_run(command, **kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, "formatted", "")

            def fake_git(project_root, *args):
                if args[0] == "status":
                    return f" M app/src/Patched.kt\n M {unrelated}\n"
                calls.append(("git",) + args)
                return ""

            with mock.patch.object(pr_validation.subprocess, "run", fake_run), \
                 mock.patch.object(pr_validation, "run_git", fake_git):
                result = pr_validation.repair_style_violations(root, [patched], 60)

            self.assertEqual(result["status"], "SUCCESS")
            self.assertEqual(result["reverted_unrelated_files"], [unrelated])
            self.assertIn(":app:ktlintFormat", result["tasks"])
            checkouts = [c for c in calls if c[:2] == ("git", "checkout")]
            self.assertEqual(len(checkouts), 1)
            self.assertIn(unrelated, checkouts[0])

    def test_the_first_status_line_stripped_by_run_git_keeps_its_path(self):
        # run_git strips its output: " M app/src/Patched.kt" arrives as
        # "M app/src/Patched.kt", and line[3:] read "pp/src/Patched.kt",
        # a file outside the patch that could not be checked out (2026-10-30).
        with tempfile.TemporaryDirectory() as directory:
            root = self._project(directory)
            patched = root / "app" / "src" / "Patched.kt"
            patched.write_text("class Patched\n", encoding="utf-8")
            checkouts = []

            def fake_git(project_root, *args):
                if args[0] == "status":
                    return "M app/src/Patched.kt\n M app/src/Unrelated.kt"
                checkouts.append(args)
                return ""

            with mock.patch.object(pr_validation.subprocess, "run", return_value=(
                    subprocess.CompletedProcess([], 0, "", ""))), \
                 mock.patch.object(pr_validation, "run_git", fake_git):
                result = pr_validation.repair_style_violations(root, [patched], 60)

        self.assertEqual(result["status"], "SUCCESS")
        self.assertEqual(checkouts, [("checkout", "--", "app/src/Unrelated.kt")])

    def test_reports_not_configured_without_a_gradle_wrapper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            source = root / "app" / "A.kt"
            source.write_text("class A\n", encoding="utf-8")
            result = pr_validation.repair_style_violations(root, [source], 60)
            self.assertEqual(result["status"], "NOT_CONFIGURED")


class SelfAuditFindingsTests(unittest.TestCase):
    """Detect a defect in a published PR that nobody reported.

    PR #1210 on spacecowboy/Feeder shipped TLS assertions inside
    DateFormattingTest.kt and received no maintainer comment, so the revision
    flow -- which only runs when feedback exists -- never engaged. Replaying the
    pipeline's own gates over the published edit set supplies that feedback.
    """

    TARGET = "app/src/main/java/com/nononsenseapps/jsonfeed/OkHttpBuilderExtensions.kt"

    def _metadata(self, edits):
        return {
            "source_file": self.TARGET,
            "method_name": "trustAllCerts",
            "coordinated_edits": edits,
        }

    def test_reports_the_unrelated_test_placement(self):
        findings = fix_prs.self_audit_findings(self._metadata([
            {"source_file": self.TARGET, "edit_kind": "method"},
            {
                "source_file": ("app/src/androidTest/java/com/nononsenseapps/"
                                "feeder/DateFormattingTest.kt"),
                "edit_kind": "test",
                "original_code": "class DateFormattingTest",
            },
        ]))
        self.assertEqual(len(findings), 1)
        entry = findings[0]
        self.assertEqual(entry["kind"], "self_audit")
        self.assertEqual(entry["audit_code"], "TEST_PLACED_IN_UNRELATED_FILE")
        self.assertIn("DateFormattingTest.kt", entry["path"])
        self.assertIn("OkHttpBuilderExtensions", entry["body"])

    def test_is_silent_on_a_correctly_placed_patch(self):
        self.assertEqual(fix_prs.self_audit_findings(self._metadata([
            {"source_file": self.TARGET, "edit_kind": "method"},
            {
                "source_file": ("app/src/androidTest/java/com/nononsenseapps/"
                                "jsonfeed/OkHttpBuilderExtensionsTlsProtocolTest.kt"),
                "edit_kind": "create",
            },
        ])), [])

    def test_is_silent_without_recorded_edits(self):
        self.assertEqual(fix_prs.self_audit_findings({}), [])
        self.assertEqual(
            fix_prs.self_audit_findings(self._metadata([])), []
        )

    def test_audit_is_not_suppressed_by_unrelated_maintainer_feedback(self):
        """A gate finding must survive alongside human comments.

        On the real PR #1210 the maintainer had left three comments, so a
        self-audit gated on "no feedback" never ran and the revision changed
        only the production file, leaving the misplaced tests in place.
        """
        metadata = self._metadata([{
            "source_file": ("app/src/androidTest/java/com/nononsenseapps/"
                            "feeder/DateFormattingTest.kt"),
            "edit_kind": "test",
            "original_code": "class DateFormattingTest",
        }])
        human = [{"kind": "conversation", "author": "maintainer",
                  "body": "please rename the helper", "path": "", "line": None,
                  "diff_hunk": "", "url": ""}]
        combined = human + fix_prs.self_audit_findings(metadata)
        self.assertEqual(len(combined), 2)
        self.assertEqual(
            {item["kind"] for item in combined}, {"conversation", "self_audit"}
        )

    def test_findings_carry_the_shape_the_revision_flow_consumes(self):
        findings = fix_prs.self_audit_findings(self._metadata([{
            "source_file": ("app/src/androidTest/java/com/nononsenseapps/"
                            "feeder/DateFormattingTest.kt"),
            "edit_kind": "test",
            "original_code": "class DateFormattingTest",
        }]))
        for key in ("kind", "author", "body", "path", "line", "diff_hunk", "url"):
            self.assertIn(key, findings[0])


class RevisionCommitMessageTests(unittest.TestCase):
    """The follow-up commit names the method as the source does: SMSecure
    #89's read "Address pull request feedback for <init>" (2026-11-02)."""

    template = "Address pull request feedback for {method_name}"

    def test_a_constructor_is_named_by_its_class(self):
        message = fix_prs.revision_commit_message(self.template, {
            "method_name": "<init>", "class_name": "org.smssecure.crypto.MasterCipher"})
        self.assertEqual(message, "Address pull request feedback for the MasterCipher constructor")

    def test_an_old_record_without_class_falls_back_to_the_source_file(self):
        message = fix_prs.revision_commit_message(self.template, {
            "method_name": "<init>", "source_file": "src/a/MasterCipher.java"})
        self.assertNotIn("<init>", message)
        self.assertIn("MasterCipher constructor", message)

    def test_a_kotlin_file_function_and_a_lambda_class(self):
        self.assertEqual(fix_prs.revision_commit_message("{method_name}", {
            "method_name": "hash", "class_name": "a.b.CryptoUtilsKt"}), "hash")
        self.assertEqual(fix_prs.revision_commit_message("{method_name}", {
            "method_name": "invokeSuspend", "class_name": "a.Main$onCreate$1"}), "Main.onCreate")

    def test_a_synthetic_lambda_class_names_its_enclosing_method_or_the_lambda(self):
        # Review of batch 17 (2026-11-02): Foo$$ExternalSyntheticLambda0.run read "Foo.run".
        self.assertEqual(fix_prs.revision_commit_message("{method_name}", {
            "method_name": "run", "class_name": "a.Foo$$ExternalSyntheticLambda0"}),
            "a lambda in Foo")
        self.assertEqual(fix_prs.revision_commit_message("{method_name}", {
            "method_name": "run", "class_name": "a.Foo$$ExternalSyntheticLambda0",
            "source_method_name": "save"}), "Foo.save")
        self.assertEqual(fix_prs.revision_commit_message("{method_name}", {
            "method_name": "accept", "class_name": "a.Foo$$Lambda$12"}), "a lambda in Foo")


class UnchangedFeedbackPublishTests(unittest.TestCase):
    """--publish --approve-revision on a plain run whose feedback is unchanged
    since a REVALIDATED revision pushed nothing: it logged "keeping the
    existing result" (SMSecure #89, 2026-11-02)."""

    def _setup(self, root: Path, approve: list) -> tuple[Path, argparse.Namespace]:
        (root / "A.java").write_text("class A {}", encoding="utf-8")
        (root / "a_pr_created.json").write_text(
            json.dumps({"html_url": "https://github.com/o/r/pull/7"}), encoding="utf-8")
        (root / "a_pr.json").write_text(json.dumps({"repository": "a"}), encoding="utf-8")
        feedback = [{"kind": "review", "body": "please fix", "url": "c1"}]
        signature = hashlib.sha256(
            json.dumps(feedback, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        output = root / "report.json"
        output.write_text(json.dumps({"results": [{
            "project": "a", "status": "REVALIDATED", "feedback_signature": signature,
            "finding_id": "f1", "checkout": str(root), "changed_files": ["A.java"],
            "branch": "fix/x", "method_name": "<init>", "class_name": "p.A",
            "pull_request": "https://github.com/o/r/pull/7",
        }]}), encoding="utf-8")
        args = argparse.Namespace(
            pull_requests_dir=str(root), projects_dir=str(root), worktrees_dir=str(root),
            output=str(output), project="", model="m", endpoint="https://x", timeout=60,
            max_output_tokens=100, reasoning_effort="high", prompt_log_dir=None,
            skip_pr_state_check=True, dry_run=False, fix_ci_failures=False,
            self_audit=False, publish=True, approve_revision=approve,
            commit_message="Address pull request feedback for {method_name}")
        return output, args, feedback

    def _run(self, approve: list):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, args, feedback = self._setup(root, approve)
            with mock.patch.object(fix_prs, "feedback_from_pr", return_value=feedback),                     mock.patch.object(fix_prs, "OpenAIProvider") as provider_cls,                     mock.patch.object(fix_prs, "publish_revision", return_value="abc") as push:
                provider_cls.return_value.get_token_usage.return_value = {}
                fix_prs.run_revision(args)
            provider_cls.return_value.generate.assert_not_called()
            return push, json.loads(output.read_text(encoding="utf-8"))["results"][0], root

    def test_the_approved_revision_is_pushed(self):
        push, record, root = self._run(["f1"])
        push.assert_called_once()
        self.assertEqual(push.call_args[0][3],
                         "Address pull request feedback for the A constructor")
        self.assertEqual(record["status"], "PUBLISHED")

    def test_an_unapproved_revision_records_what_it_would_send(self):
        push, record, _ = self._run(["other"])
        push.assert_not_called()
        self.assertEqual(record["status"], "REVALIDATED")
        self.assertEqual(record["publish"]["status"], "NOT_APPROVED")


if __name__ == "__main__":
    unittest.main()
