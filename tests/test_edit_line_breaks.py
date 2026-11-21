import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.config.apply_solutions_config import ApplySolutionsConfig  # noqa: E402
from cognalys.solutions.coordinated_edits import apply_edits_to_sources  # noqa: E402
from cognalys.solutions.solution_applicator import SolutionApplicator  # noqa: E402
from cognalys.solutions.solution_mapper import SolutionMapper  # noqa: E402
from cognalys.utils.edit_text import (  # noqa: E402
    file_line_ending, match_trailing_line_break, read_source, with_endings_of, with_line_ending,
    write_source,
)


SOURCE = (
    "val client = object : WebViewClient() {\n"
    "    @SuppressLint(\"X\")\n"
    "    override fun onReceivedSslError(handler: SslErrorHandler) {\n"
    "        handler.proceed()\n"
    "    }\n"
    "}\n"
    "\n"
    "loadUrl(serverUrl)\n"
)
ORIGINAL = (
    "    @SuppressLint(\"X\")\n"
    "    override fun onReceivedSslError(handler: SslErrorHandler) {\n"
    "        handler.proceed()\n"
    "    }\n"
)
CORRECTED_WITHOUT_BREAK = (
    "    override fun onReceivedSslError(handler: SslErrorHandler) {\n"
    "        handler.cancel()\n"
    "    }"
)
EXPECTED = (
    "val client = object : WebViewClient() {\n"
    "    override fun onReceivedSslError(handler: SslErrorHandler) {\n"
    "        handler.cancel()\n"
    "    }\n"
    "}\n"
    "\n"
    "loadUrl(serverUrl)\n"
)


class MatchTrailingLineBreakTests(unittest.TestCase):
    def test_a_dropped_closing_break_is_restored(self):
        self.assertEqual(match_trailing_line_break("a\n", "b"), "b\n")

    def test_the_break_style_of_the_original_is_kept(self):
        self.assertEqual(match_trailing_line_break("a\r\n", "b"), "b\r\n")
        self.assertEqual(match_trailing_line_break("a\n", "b\r\n"), "b\n")

    def test_an_extra_closing_break_is_removed(self):
        self.assertEqual(match_trailing_line_break("a", "b\n"), "b")

    def test_matching_and_empty_replacements_are_untouched(self):
        self.assertEqual(match_trailing_line_break("a\n", "b\n"), "b\n")
        self.assertEqual(match_trailing_line_break("a", "b"), "b")
        self.assertEqual(match_trailing_line_break("a\n", ""), "")


class EditApplicationKeepsLinesApartTests(unittest.TestCase):
    """The next line of the file must never be glued onto a replacement."""

    def test_in_memory_application(self):
        updated, issues = apply_edits_to_sources(
            {"Screen.kt": SOURCE},
            [{
                "source_file_path": "Screen.kt", "symbol": "onReceivedSslError",
                "edit_kind": "method", "original_code": ORIGINAL,
                "corrected_code": CORRECTED_WITHOUT_BREAK,
                "reason": "cancel instead of proceeding",
            }],
        )
        self.assertEqual(issues, [])
        self.assertEqual(updated["Screen.kt"], EXPECTED)

    def test_worktree_application_writes_and_records_the_same_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Screen.kt"
            source.write_text(SOURCE, encoding="utf-8")
            applicator = SolutionApplicator(ApplySolutionsConfig(
                error_solutions_dir=str(root / "solutions"),
                cloned_projects_dir=str(root), output_dir=str(root / "results"),
                worktrees_dir=str(root / "worktrees"), save_backups=False,
            ))
            solution = {"fix_scope": "dependency", "coordinated_edits": [{
                "source_file_path": "Screen.kt", "symbol": "onReceivedSslError",
                "edit_kind": "method", "original_code": ORIGINAL,
                "corrected_code": CORRECTED_WITHOUT_BREAK,
                "reason": "cancel instead of proceeding",
            }]}
            ok, changes, error = applicator._apply_coordinated_edits(
                solution, SolutionMapper(str(root / "solutions"), str(root)), root
            )
            self.assertTrue(ok, error)
            self.assertEqual(source.read_text(encoding="utf-8"), EXPECTED)
            self.assertTrue(changes[0]["corrected_code"].endswith("}\n"))


# The same file as SOURCE, as a repository that commits CRLF holds it.
CRLF_SOURCE = SOURCE.replace("\n", "\r\n")
CRLF_EXPECTED = EXPECTED.replace("\n", "\r\n")


def lines_changed(before: bytes, after: bytes) -> int:
    """How many lines a diff of the two files would touch."""
    import difflib

    return sum(1 for line in difflib.ndiff(before.decode().splitlines(keepends=True),
                                           after.decode().splitlines(keepends=True))
               if line[:1] in "+-")


class CrlfSourceTests(unittest.TestCase):
    """A generated edit on a CRLF file changes only its own lines.

    Read with read_text and written back, a CRLF file came out all LF: a
    diff touching every line (the batch4 format review of pr_followup,
    2026-10-30). Six of 82 local clones hold such Java/Kotlin/Gradle files
    (quad9-connect, Cryptomator, AntennaPod, Olvid, ...).
    """

    def applicator(self, root: Path) -> SolutionApplicator:
        return SolutionApplicator(ApplySolutionsConfig(
            error_solutions_dir=str(root / "solutions"),
            cloned_projects_dir=str(root), output_dir=str(root / "results"),
            worktrees_dir=str(root / "worktrees"), save_backups=False,
        ))

    def solution(self) -> dict:
        return {"fix_scope": "dependency", "coordinated_edits": [{
            "source_file_path": "Screen.kt", "symbol": "onReceivedSslError",
            "edit_kind": "method", "original_code": ORIGINAL,
            "corrected_code": CORRECTED_WITHOUT_BREAK,
            "reason": "cancel instead of proceeding",
        }]}

    def test_the_line_ending_of_a_file_is_kept_and_a_mixed_one_has_none(self):
        self.assertEqual(file_line_ending(CRLF_SOURCE), "\r\n")
        self.assertEqual(file_line_ending(SOURCE), "\n")
        self.assertEqual(file_line_ending("a\r\nb\n"), "\n")
        self.assertEqual(file_line_ending("no break"), "\n")
        self.assertEqual(with_line_ending("a\nb\r\n", "\r\n"), "a\r\nb\r\n")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "A.kt"
            path.write_bytes(CRLF_SOURCE.encode("utf-8"))
            self.assertEqual(read_source(path), SOURCE)
            write_source(path, EXPECTED)
            self.assertEqual(path.read_bytes(), CRLF_EXPECTED.encode("utf-8"))
            created = Path(directory) / "New.kt"
            write_source(created, "class New\n")
            self.assertEqual(created.read_bytes(), b"class New\n")

    def test_worktree_application_keeps_a_crlf_file_crlf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Screen.kt"
            source.write_bytes(CRLF_SOURCE.encode("utf-8"))
            ok, changes, error = self.applicator(root)._apply_coordinated_edits(
                self.solution(), SolutionMapper(str(root / "solutions"), str(root)), root)
            self.assertTrue(ok, error)
            self.assertEqual(source.read_bytes(), CRLF_EXPECTED.encode("utf-8"))
            self.assertEqual(lines_changed(CRLF_SOURCE.encode(), source.read_bytes()), 3)

    def test_single_method_replacement_keeps_a_crlf_file_crlf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Screen.kt"
            source.write_bytes(CRLF_SOURCE.encode("utf-8"))
            mapper = SolutionMapper(str(root / "solutions"), str(root))
            self.assertTrue(mapper.replacer.replace_method(
                source, ORIGINAL, CORRECTED_WITHOUT_BREAK + "\n"))
            self.assertEqual(source.read_bytes().count(b"\r\n"),
                             source.read_bytes().count(b"\n"))
            self.assertIn(b"handler.cancel()\r\n", source.read_bytes())

    def test_a_validation_repair_keeps_a_crlf_file_crlf(self):
        from cognalys.validation.repair import validate_and_apply

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Screen.kt"
            source.write_bytes(CRLF_SOURCE.encode("utf-8"))
            ok, _, error = validate_and_apply(root, {"decision": "REPAIR", "edits": [{
                "source_file_path": "Screen.kt", "original_code": "loadUrl(serverUrl)\n",
                "corrected_code": "loadUrl(serverUrl.trim())\n", "reason": "compile",
            }]}, {"Screen.kt"}, dry_run=False)
            self.assertTrue(ok, error)
            self.assertEqual(source.read_bytes(), CRLF_SOURCE.replace(
                "loadUrl(serverUrl)", "loadUrl(serverUrl.trim())").encode("utf-8"))

    def test_a_revision_of_a_published_pull_request_keeps_a_crlf_file_crlf(self):
        from cognalys.prs.pr_feedback import (
            apply_coordinated_edits, gather_candidate_files, write_revision_files)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Screen.kt"
            source.write_bytes(CRLF_SOURCE.encode("utf-8"))
            files = gather_candidate_files(root, source, [])
            updated, issues = apply_coordinated_edits(files, self.solution()["coordinated_edits"])
            self.assertEqual(issues, [])
            write_revision_files(root, updated, ["Screen.kt"], [])
            self.assertEqual(source.read_bytes(), CRLF_EXPECTED.encode("utf-8"))

    def test_an_edit_rebased_onto_a_crlf_base_keeps_it_crlf(self):
        def git(where: Path, *args: str) -> str:
            return subprocess.run(["git", "-C", str(where), *args], check=True,
                                  capture_output=True, text=True).stdout.strip()

        moved = CRLF_SOURCE.replace("loadUrl(serverUrl)", "loadUrl(server.url)")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clone = root / "clone"
            clone.mkdir()
            git(clone, "init", "-q")
            git(clone, "config", "core.autocrlf", "false")
            git(clone, "config", "user.email", "t@example.com")
            git(clone, "config", "user.name", "t")
            (clone / "Screen.kt").write_bytes(CRLF_SOURCE.encode("utf-8"))
            git(clone, "add", "-A")
            git(clone, "commit", "-q", "-m", "analysed")
            worktree = root / "worktree"
            worktree.mkdir()
            (worktree / "Screen.kt").write_bytes(moved.encode("utf-8"))
            solution = self.solution()
            # Written against the analysed revision: its last line moved on the base.
            solution["coordinated_edits"][0]["original_code"] = ORIGINAL + "}\n\nloadUrl(serverUrl)\n"
            solution["coordinated_edits"][0]["corrected_code"] = (
                CORRECTED_WITHOUT_BREAK + "\n}\n\nloadUrl(serverUrl)\n")
            rebased = self.applicator(root)._apply_rebased_coordinated_edits(
                solution, SolutionMapper(str(root / "s"), str(root)), worktree, clone)
            self.assertIsNotNone(rebased)
            self.assertEqual((worktree / "Screen.kt").read_bytes(),
                             CRLF_EXPECTED.replace("loadUrl(serverUrl)", "loadUrl(server.url)")
                             .encode("utf-8"))

    def test_a_mixed_file_changes_only_the_lines_the_edit_wrote(self):
        # Written all LF, a file whose licence header was CRLF had those
        # lines in the diff too (2026-10-30 review).
        mixed = "// licence\r\n// header\r\n" + SOURCE
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Screen.kt"
            source.write_bytes(mixed.encode("utf-8"))
            write_source(source, read_source(source).replace("handler.proceed()",
                                                             "handler.cancel()"))
            self.assertEqual(source.read_bytes(), mixed.replace(
                "handler.proceed()", "handler.cancel()").encode("utf-8"))
            self.assertEqual(lines_changed(mixed.encode(), source.read_bytes()), 2)
            # A line the edit writes in place of a CRLF line, or after one,
            # takes its ending.
            write_source(source, read_source(source).replace(
                "// header\n", "// header, edited\n// added\n"))
            self.assertTrue(source.read_bytes().startswith(
                b"// licence\r\n// header, edited\r\n// added\r\nval client"))
        self.assertEqual(with_endings_of("a\r\nb\n", "a\nb\nc"), "a\r\nb\nc")

    def test_an_edit_rebased_onto_an_eol_crlf_checkout_is_merged(self):
        # .gitattributes eol=crlf: git show gives the LF blob, the checkout
        # holds CRLF. Merged byte for byte, every line conflicted and the
        # rebase was refused; the merged file keeps the checkout's CRLF
        # (2026-10-30 review).
        def git(where: Path, *args: str) -> str:
            return subprocess.run(["git", "-C", str(where), *args], check=True,
                                  capture_output=True, text=True).stdout.strip()

        moved = CRLF_SOURCE.replace("loadUrl(serverUrl)", "loadUrl(server.url)")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clone = root / "clone"
            clone.mkdir()
            git(clone, "init", "-q")
            git(clone, "config", "core.autocrlf", "false")
            git(clone, "config", "user.email", "t@example.com")
            git(clone, "config", "user.name", "t")
            (clone / ".gitattributes").write_text("*.kt text eol=crlf\n", encoding="utf-8")
            (clone / "Screen.kt").write_bytes(CRLF_SOURCE.encode("utf-8"))
            git(clone, "add", "-A")
            git(clone, "commit", "-q", "-m", "analysed")
            self.assertNotIn(b"\r", subprocess.run(
                ["git", "-C", str(clone), "show", "HEAD:Screen.kt"],
                check=True, capture_output=True).stdout)
            worktree = root / "worktree"
            worktree.mkdir()
            (worktree / "Screen.kt").write_bytes(moved.encode("utf-8"))
            solution = self.solution()
            solution["coordinated_edits"][0]["original_code"] = ORIGINAL + "}\n\nloadUrl(serverUrl)\n"
            solution["coordinated_edits"][0]["corrected_code"] = (
                CORRECTED_WITHOUT_BREAK + "\n}\n\nloadUrl(serverUrl)\n")
            rebased = self.applicator(root)._apply_rebased_coordinated_edits(
                solution, SolutionMapper(str(root / "s"), str(root)), worktree, clone)
            self.assertIsNotNone(rebased)
            self.assertEqual((worktree / "Screen.kt").read_bytes(),
                             CRLF_EXPECTED.replace("loadUrl(serverUrl)", "loadUrl(server.url)")
                             .encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
