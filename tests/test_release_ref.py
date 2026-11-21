"""Tell a relocated class, a stale finding and a bad one apart.

`extraction_status=application_class_not_in_checkout` is the largest single
block in the failure ledger (16 occurrences), and it covered three unrelated
situations at once. These tests pin the separation, and pin the refusals
that keep it honest: no branch is ever used as a stand-in for the release
tag, and an ambiguous relocation is left unresolved rather than guessed.
"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.release_ref import (  # noqa: E402
    apk_version, candidate_tags, file_at_ref, historical_class_lookup,
    path_of_class_at_ref, relocated_path, resolve_release_ref,
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args],
                   check=True, capture_output=True, text=True)


class VersionParsingTests(unittest.TestCase):

    def test_a_version_name_is_read(self):
        self.assertEqual(
            apk_version("net.gsantner.markor_v2.11.0.apk"),
            {"kind": "version_name", "value": "2.11.0"},
        )

    def test_a_version_code_is_recognised_but_not_treated_as_a_version(self):
        self.assertEqual(
            apk_version("com.hmdm.launcher_15390.apk"),
            {"kind": "version_code", "value": "15390"},
        )

    def test_an_unparsable_name_is_unknown(self):
        self.assertEqual(apk_version("app-universal-release.apk")["kind"],
                         "unknown")

    def test_tag_spellings_start_with_the_literal_version(self):
        candidates = candidate_tags("2.11.0")
        self.assertEqual(candidates[0], "2.11.0")
        self.assertIn("v2.11.0", candidates)


class ReleaseRefTests(unittest.TestCase):

    CLASS = "net.gsantner.markor.format.Highlighter"
    PATH = "app/src/main/java/net/gsantner/markor/format/Highlighter.java"

    def _repository(self, directory: str, *, tag: str = "v2.11.0") -> Path:
        repo = Path(directory) / "repo"
        source = repo / self.PATH
        source.parent.mkdir(parents=True)
        source.write_text("class Highlighter {}", encoding="utf-8")
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "t@example.com")
        _git(repo, "config", "user.name", "Test")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "release")
        if tag:
            _git(repo, "tag", tag)
        return repo

    def test_a_matching_tag_is_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory)
            reference = resolve_release_ref(repo, "net.gsantner.markor_v2.11.0.apk")
        self.assertEqual(reference["status"], "resolved")
        self.assertEqual(reference["tag"], "v2.11.0")

    def test_a_version_code_no_tag_declares_is_not_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory, tag="v1.0")
            reference = resolve_release_ref(repo, "com.hmdm.launcher_15390.apk")
        self.assertEqual(reference["status"], "version_code_not_found")
        self.assertEqual(reference["ref"], "")
        self.assertTrue(reference["search_complete"])

    def _release(self, repo: Path, code: int, *tags: str) -> None:
        build = repo / "app" / "build.gradle"
        build.write_text(
            "android {\n  defaultConfig {\n    versionCode %d\n"
            "    versionName \"x\"\n  }\n}\n" % code, encoding="utf-8",
        )
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", f"release {code}")
        for tag in tags:
            _git(repo, "tag", tag)

    def test_a_version_code_is_matched_through_the_build_file_at_the_tag(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory, tag="")
            self._release(repo, 15389, "v1.0")
            self._release(repo, 15390, "v1.1")
            self._release(repo, 15391, "v1.2")
            reference = resolve_release_ref(repo, "com.hmdm.launcher_15390.apk")
        self.assertEqual(reference["status"], "resolved")
        self.assertEqual(reference["tag"], "v1.1")
        self.assertEqual(reference["resolution_method"], "build_version_code")
        # A tag match names the declared sources, not the binary's.
        self.assertEqual(reference["binary_equivalence"], "not_established")

    def test_tags_on_one_commit_resolve_together(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory, tag="")
            self._release(repo, 15390, "v1.1", "1.1")
            reference = resolve_release_ref(repo, "com.hmdm.launcher_15390.apk")
        self.assertEqual(reference["status"], "resolved")

    def test_one_code_on_two_commits_is_ambiguous_not_guessed(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory, tag="")
            self._release(repo, 15390, "v1.1")
            (repo / "app" / "Other.java").write_text("class Other {}", encoding="utf-8")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "-m", "unbumped release")
            _git(repo, "tag", "v1.1.1")
            reference = resolve_release_ref(repo, "com.hmdm.launcher_15390.apk")
        self.assertEqual(reference["status"], "version_code_ambiguous")
        self.assertEqual(reference["ref"], "")
        self.assertEqual(sorted(reference["candidates"]), ["v1.1", "v1.1.1"])

    def test_no_tag_means_no_ref_rather_than_a_branch(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory, tag="")
            reference = resolve_release_ref(repo, "net.gsantner.markor_v2.11.0.apk")
        self.assertEqual(reference["status"], "tag_not_found")
        self.assertEqual(reference["ref"], "")

    def test_the_class_is_located_and_read_at_the_tag(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory)
            path = path_of_class_at_ref(repo, "refs/tags/v2.11.0", self.CLASS)
            self.assertEqual(path, self.PATH)
            self.assertIn(
                "Highlighter", file_at_ref(repo, "refs/tags/v2.11.0", path)
            )

    def test_a_class_moved_to_another_module_is_relocated(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory)
            moved = repo / "core/src/main/java/net/other/pkg/Highlighter.java"
            moved.parent.mkdir(parents=True)
            _git(repo, "mv", self.PATH, str(moved.relative_to(repo)))
            _git(repo, "commit", "-q", "-m", "move")
            lookup = historical_class_lookup(
                repo, "net.gsantner.markor_v2.11.0.apk", self.CLASS
            )
        self.assertEqual(lookup["status"], "relocated")
        self.assertEqual(
            lookup["current_path"],
            "core/src/main/java/net/other/pkg/Highlighter.java",
        )

    def test_a_deleted_class_is_stale_not_unanalysable(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory)
            _git(repo, "rm", "-q", self.PATH)
            _git(repo, "commit", "-q", "-m", "remove")
            lookup = historical_class_lookup(
                repo, "net.gsantner.markor_v2.11.0.apk", self.CLASS
            )
        self.assertEqual(lookup["status"], "removed_since_release")
        self.assertEqual(lookup["historical_path"], self.PATH)

    def test_a_class_that_was_never_there_is_reported_as_such(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory)
            lookup = historical_class_lookup(
                repo, "net.gsantner.markor_v2.11.0.apk", "com.other.Absent"
            )
        self.assertEqual(lookup["status"], "absent_at_release")

    def test_without_a_resolvable_release_nothing_is_concluded(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory, tag="")
            lookup = historical_class_lookup(
                repo, "net.gsantner.markor_v2.11.0.apk", self.CLASS
            )
        self.assertEqual(lookup["status"], "release_unresolved")

    def test_an_ambiguous_relocation_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repository(directory)
            twin = repo / "other/src/main/java/x/Highlighter.java"
            twin.parent.mkdir(parents=True)
            twin.write_text("class Highlighter {}", encoding="utf-8")
            self.assertEqual(relocated_path(repo, self.PATH), "")


if __name__ == "__main__":
    unittest.main()
