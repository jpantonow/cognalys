"""A research workspace kept apart from the library (COGNALYS_WORKSPACE=legado).

It holds its own runs, inputs and learned state; the specifications, detector
rules and policies come from the library unless the workspace has its own.
"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import workspace  # noqa: E402

CHECKOUT = Path(__file__).resolve().parents[1]


class SeparateWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.legacy = Path(self.directory.name) / "legado"
        (self.legacy / "data" / "processed").mkdir(parents=True)

    def tearDown(self):
        self.directory.cleanup()

    def environment(self):
        return patch.dict(os.environ, {workspace.ENVIRONMENT_VARIABLE: str(self.legacy)})

    def test_runs_and_inputs_are_the_workspaces(self):
        with self.environment():
            self.assertEqual(workspace.workspace_root(), self.legacy.resolve())
            self.assertEqual(workspace.data_path("pr_outcomes"),
                             self.legacy.resolve() / "data" / "pr_outcomes")

    def test_library_data_comes_from_the_library_when_the_workspace_has_none(self):
        with self.environment():
            self.assertEqual(workspace.library_data("specifications"), CHECKOUT / "data" / "specifications")
            self.assertTrue(workspace.library_data("detector_rules", "semgrep").is_dir())

    def test_the_workspaces_own_copy_wins(self):
        own = self.legacy / "data" / "specifications"
        own.mkdir(parents=True)
        with self.environment():
            self.assertEqual(workspace.library_data("specifications"), own.resolve())

    def test_without_a_separate_workspace_nothing_moves(self):
        with patch.dict(os.environ, {workspace.ENVIRONMENT_VARIABLE: ""}):
            self.assertEqual(workspace.workspace_root(), CHECKOUT)
            self.assertEqual(workspace.library_data("specifications"), CHECKOUT / "data" / "specifications")
            self.assertEqual(workspace.credential_directories(), [CHECKOUT])

    def test_credentials_are_read_from_the_workspace_then_the_library(self):
        from cognalys import cli

        (self.legacy / ".env.github").write_text("GITHUB_TOKEN=from-workspace\n", encoding="utf-8")
        with self.environment():
            self.assertEqual(workspace.credential_directories(), [self.legacy.resolve(), CHECKOUT])
        with tempfile.TemporaryDirectory() as library:
            library = Path(library)
            (library / ".env.github").write_text(
                "GITHUB_TOKEN=from-library\nGIT_AUTHOR_NAME=someone\n", encoding="utf-8")
            with patch.dict(os.environ, {"GITHUB_TOKEN": "", "GIT_AUTHOR_NAME": ""}):
                os.environ.pop("GITHUB_TOKEN")
                os.environ.pop("GIT_AUTHOR_NAME")
                for directory in (self.legacy, library):
                    cli.load_env_file(directory / ".env.github")
                self.assertEqual(os.environ["GITHUB_TOKEN"], "from-workspace")
                self.assertEqual(os.environ["GIT_AUTHOR_NAME"], "someone")


if __name__ == "__main__":
    unittest.main()
