import subprocess
import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.config.apply_solutions_config import ApplySolutionsConfig  # noqa: E402
from cognalys.solutions.solution_applicator import SolutionApplicator  # noqa: E402
from cognalys.utils.contribution_base import (  # noqa: E402
    contribution_base_status,
    relocated_path,
    renamed_paths,
)

BODY = (
    "fun cacheKey(name: String): String {\n"
    "    val md = MessageDigest.getInstance(\"MD5\")\n"
    "    return md.digest(name.toByteArray()).joinToString(\"\")\n"
    "}"
)
OLD = "app/src/main/java/org/example/cache/DiskCache.kt"
NEW = "core/data/src/main/kotlin/org/example/core/cache/DiskCache.kt"
OLD_TEST = "app/src/test/java/org/example/cache/DiskCacheTest.kt"
NEW_TEST = "core/data/src/test/kotlin/org/example/core/cache/DiskCacheTest.kt"


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=repo, capture_output=True, text=True,
        check=True,
    ).stdout.strip()


def _write(repo: Path, relative: str, text: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class RelocatedSourceTests(unittest.TestCase):
    """A file the project moved since the analysed artifact was built.

    BetterUntis moved data/cache/DiskCache.kt into a core/data module and
    OpenBible moved logic/Getters.kt into a Kotlin Multiplatform shared
    module, both keeping the reviewed method byte for byte. Both fixes were
    recorded as SOURCE_FILE_ABSENT_FROM_BASE_BRANCH and no pull request was
    attempted.
    """

    def _clone(self, directory: str, moved_body: str = BODY) -> Path:
        """A clone detached at the analysed revision; dev has moved the files."""
        upstream = Path(directory) / "upstream"
        upstream.mkdir()
        _git(upstream, "init", "-q", "-b", "dev")
        _git(upstream, "config", "user.email", "t@example.invalid")
        _git(upstream, "config", "user.name", "Test")
        source = f"package org.example.cache\n\nclass DiskCache {{\n{BODY}\n}}\n"
        test = "package org.example.cache\n\nclass DiskCacheTest { fun keeps() {} }\n"
        _write(upstream, OLD, source)
        _write(upstream, OLD_TEST, test)
        _git(upstream, "add", "-A")
        _git(upstream, "commit", "-qm", "analysed revision")
        analysed = _git(upstream, "rev-parse", "HEAD")
        for target in (NEW, NEW_TEST):
            (upstream / target).parent.mkdir(parents=True, exist_ok=True)
        _git(upstream, "mv", OLD, NEW)
        _git(upstream, "mv", OLD_TEST, NEW_TEST)
        _write(upstream, NEW, source.replace("org.example.cache",
                                             "org.example.core.cache")
               .replace(BODY, moved_body))
        _git(upstream, "add", "-A")
        _git(upstream, "commit", "-qm", "move cache into core/data")

        repo = Path(directory) / "repo"
        subprocess.run(["git", "clone", "-q", str(upstream), str(repo)],
                       capture_output=True, text=True, check=True)
        _git(repo, "checkout", "-q", "--detach", analysed)
        return repo

    def test_a_moved_file_with_the_reviewed_body_is_found_at_its_new_path(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._clone(directory)

            self.assertEqual(renamed_paths(repo, "HEAD", "origin/dev")[OLD], NEW)
            self.assertEqual(
                relocated_path(repo, "HEAD", "origin/dev", OLD, BODY), NEW,
            )
            status = contribution_base_status(repo, OLD, method_body=BODY)
            self.assertTrue(status["target_present"])
            self.assertTrue(status["analyzed_code_present"])
            self.assertEqual(status["relocated_path"], NEW)

    def test_a_moved_file_whose_body_changed_is_not_a_place_to_patch(self):
        """git calls a file renamed at 50% similarity; the reviewed code
        being gone means the move is not where the fix belongs."""
        changed = BODY.replace('"MD5"', '"SHA-256"')
        with tempfile.TemporaryDirectory() as directory:
            repo = self._clone(directory, moved_body=changed)

            self.assertEqual(
                relocated_path(repo, "HEAD", "origin/dev", OLD, BODY), "",
            )
            status = contribution_base_status(repo, OLD, method_body=BODY)
            self.assertFalse(status["target_present"])
            self.assertNotIn("relocated_path", status)

    def test_an_unreadable_revision_relocates_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._clone(directory)

            self.assertEqual(renamed_paths(repo, "HEAD", "no-such-ref"), {})
            self.assertEqual(renamed_paths(repo, "", "origin/dev"), {})

    def test_the_solution_follows_every_rename_including_its_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._clone(directory)
            solution = {
                "source_file_path": OLD,
                "coordinated_edits": [
                    {"source_file_path": OLD, "original_code": BODY},
                    {"source_file_path": OLD_TEST, "original_code": "fun keeps() {}"},
                    {"source_file_path": "README.md", "original_code": "x"},
                ],
                "authorized_patch_plan": {"required_edits": [
                    {"source_file_path": OLD}, {"source_file_path": OLD_TEST},
                    {"source_file_path": "README.md"},
                ]},
            }
            applicator = SolutionApplicator(ApplySolutionsConfig())

            relocated = applicator._relocate_moved_sources(
                solution, repo, "origin/dev", OLD, BODY,
            )

            self.assertEqual(relocated, NEW)
            self.assertEqual(solution["source_file_path"], NEW)
            self.assertEqual(
                [edit["source_file_path"] for edit in solution["coordinated_edits"]],
                [NEW, NEW_TEST, "README.md"],
            )
            self.assertEqual(
                [item["source_file_path"]
                 for item in solution["authorized_patch_plan"]["required_edits"]],
                [NEW, NEW_TEST, "README.md"],
            )

    def test_a_file_the_patch_creates_follows_the_module_and_package(self):
        """A created test is in no rename list; it must still move, or it is
        written where it cannot see the class it tests."""
        created_path = "app/src/test/java/org/example/cache/CacheKeyTest.kt"
        test_code = (
            "package org.example.cache\n\n"
            "import org.example.cache.DiskCache\n"
            "import org.junit.Test\n\n"
            "class CacheKeyTest { @Test fun hashesWithSha256() {} }\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            repo = self._clone(directory)
            solution = {
                "source_file_path": OLD,
                "coordinated_edits": [
                    {"source_file_path": OLD, "original_code": BODY},
                    {"source_file_path": created_path, "edit_kind": "create",
                     "original_code": "", "corrected_code": test_code},
                    {"source_file_path": "app/src/test/java/other/Unrelated.kt",
                     "edit_kind": "create", "original_code": "",
                     "corrected_code": "package other\n"},
                ],
                "authorized_patch_plan": {"required_edits": [
                    {"source_file_path": created_path, "create_new_file": True},
                ]},
            }
            applicator = SolutionApplicator(ApplySolutionsConfig())

            applicator._relocate_moved_sources(
                solution, repo, "origin/dev", OLD, BODY,
            )

            created = solution["coordinated_edits"][1]
            # The test source set already exists on the base under kotlin/.
            expected = NEW_TEST.rsplit("/", 1)[0] + "/CacheKeyTest.kt"
            self.assertEqual(created["source_file_path"], expected)
            self.assertIn("package org.example.core.cache\n",
                          created["corrected_code"])
            self.assertIn("import org.example.core.cache.DiskCache\n",
                          created["corrected_code"])
            self.assertIn("import org.junit.Test\n", created["corrected_code"])
            self.assertEqual(
                solution["authorized_patch_plan"]["required_edits"][0]
                ["source_file_path"], expected,
            )
            # A file created elsewhere is not the moved module's business.
            self.assertEqual(solution["coordinated_edits"][2]["source_file_path"],
                             "app/src/test/java/other/Unrelated.kt")

    def test_a_solution_that_cannot_be_relocated_is_left_untouched(self):
        changed = BODY.replace('"MD5"', '"SHA-256"')
        with tempfile.TemporaryDirectory() as directory:
            repo = self._clone(directory, moved_body=changed)
            solution = {
                "source_file_path": OLD,
                "coordinated_edits": [{"source_file_path": OLD_TEST}],
            }
            applicator = SolutionApplicator(ApplySolutionsConfig())

            self.assertEqual(applicator._relocate_moved_sources(
                solution, repo, "origin/dev", OLD, BODY,
            ), "")
            self.assertEqual(solution["source_file_path"], OLD)
            self.assertEqual(
                solution["coordinated_edits"][0]["source_file_path"], OLD_TEST,
            )


if __name__ == "__main__":
    unittest.main()
