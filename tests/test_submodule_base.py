import subprocess
import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.issue_candidates import IssueCandidates  # noqa: E402
from cognalys.utils.contribution_base import (  # noqa: E402
    contribution_base_status,
    submodule_containing,
    submodule_of,
)

INNER = "cert4android/src/main/java/at/bitfire/cert4android/CustomCertService.kt"


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-c", "protocol.file.allow=always", *arguments], cwd=repo,
        capture_output=True, text=True, check=True,
    ).stdout.strip()


class SubmoduleBaseTests(unittest.TestCase):
    """EteSync's CustomCertService.kt lives in the cert4android submodule; the
    superproject's tree holds a commit pointer there, and the finding was
    recorded as SOURCE_FILE_ABSENT_FROM_BASE_BRANCH."""

    def _superproject(self, directory: str, url: str = "") -> Path:
        library = Path(directory) / "cert4android"
        (library / "src/main/java/at/bitfire/cert4android").mkdir(parents=True)
        _git(library, "init", "-q", "-b", "main")
        _git(library, "config", "user.email", "t@example.invalid")
        _git(library, "config", "user.name", "Test")
        (library / "src/main/java/at/bitfire/cert4android/CustomCertService.kt"
         ).write_text("class CustomCertService", encoding="utf-8")
        _git(library, "add", "-A")
        _git(library, "commit", "-qm", "library")

        app = Path(directory) / "app"
        app.mkdir()
        _git(app, "init", "-q", "-b", "main")
        _git(app, "config", "user.email", "t@example.invalid")
        _git(app, "config", "user.name", "Test")
        _git(app, "submodule", "add", "-q", str(library), "cert4android")
        if url:
            _git(app, "config", "-f", ".gitmodules",
                 "submodule.cert4android.url", url)
        _git(app, "add", "-A")
        _git(app, "commit", "-qm", "vendor cert4android")
        return app

    def test_a_path_inside_a_submodule_names_the_submodule(self):
        with tempfile.TemporaryDirectory() as directory:
            app = self._superproject(
                directory, "https://github.com/bitfireAT/cert4android.git")

            submodule = submodule_containing(app, "HEAD", INNER)

            self.assertEqual(submodule["path"], "cert4android")
            self.assertEqual(submodule["url"],
                             "https://github.com/bitfireAT/cert4android.git")
            self.assertEqual(len(submodule["commit"]), 40)

    def test_the_contribution_base_reports_the_submodule(self):
        with tempfile.TemporaryDirectory() as directory:
            app = self._superproject(directory)

            status = contribution_base_status(app, INNER)

            self.assertFalse(status["target_present"])
            self.assertEqual(status["submodule"]["path"], "cert4android")

    def test_a_checked_out_submodule_names_itself(self):
        """The applicator walks up to the nearest .git, which for a file in
        cert4android/ is the submodule's own checkout, not the superproject."""
        with tempfile.TemporaryDirectory() as directory:
            app = self._superproject(directory)
            checkout = app / "cert4android"

            submodule = submodule_of(checkout, INNER)

            self.assertEqual(submodule["path"], "cert4android")
            self.assertTrue(submodule["url"].endswith("cert4android"))
            self.assertEqual(len(submodule["commit"]), 40)
            self.assertEqual(submodule_of(app), {})
            self.assertEqual(submodule_of(checkout, "other/File.kt"), {})

    def test_an_ordinary_missing_path_is_no_submodule(self):
        with tempfile.TemporaryDirectory() as directory:
            app = self._superproject(directory)

            self.assertEqual(submodule_containing(app, "HEAD", "gone/File.kt"), {})
            self.assertEqual(submodule_containing(app, "HEAD", ".gitmodules"), {})
            self.assertNotIn("submodule", contribution_base_status(app, "gone/A.kt"))

    def test_an_issue_goes_to_the_submodule_repository_when_on_github(self):
        error = {
            "repository_url": "https://github.com/etesync/android",
            "extraction_status": "success",
            "contribution_base": {"submodule": {
                "path": "cert4android",
                "url": "https://github.com/bitfireAT/cert4android.git",
            }},
        }
        match, target, withheld = IssueCandidates.issue_repository(error, "")
        self.assertEqual(target, "upstream_library")
        self.assertEqual(match.group(1, 2), ("bitfireAT", "cert4android"))
        self.assertEqual(withheld, "")

    def test_an_issue_is_withheld_when_the_submodule_is_not_on_github(self):
        error = {
            "repository_url": "https://github.com/etesync/android",
            "extraction_status": "success",
            "contribution_base": {"submodule": {
                "path": "cert4android",
                "url": "https://gitlab.com/tasn/cert4android.git",
            }},
        }
        match, target, withheld = IssueCandidates.issue_repository(error, "")
        self.assertIsNone(match)
        self.assertIn("gitlab.com/tasn/cert4android", withheld)


if __name__ == "__main__":
    unittest.main()
