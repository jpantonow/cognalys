import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import workspace  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class WorkspaceTests(unittest.TestCase):
    """Where data/ is, once the package can be installed anywhere.

    The package found data/ by walking up from its own file, which is right
    in a checkout and wrong in site-packages.
    """

    def test_a_checkout_is_its_own_workspace(self):
        with patch.dict(os.environ, {workspace.ENVIRONMENT_VARIABLE: ""}):
            self.assertEqual(workspace.workspace_root(), ROOT)
            self.assertEqual(workspace.data_path("specifications"),
                             ROOT / "data" / "specifications")

    def test_the_environment_variable_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {workspace.ENVIRONMENT_VARIABLE: directory}):
                self.assertEqual(workspace.workspace_root(), Path(directory).resolve())
                self.assertEqual(workspace.data_path("llm_policies"),
                                 Path(directory).resolve() / "data" / "llm_policies")

    def test_an_installed_package_falls_back_to_the_current_directory(self):
        """Installed, the package sits in site-packages, two levels below no
        data/ or pyproject.toml; the directory the run starts in is used."""
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory) / "site-packages" / "cognalys"
            site.mkdir(parents=True)
            run_from = Path(directory) / "project"
            run_from.mkdir()
            with patch.dict(os.environ, {workspace.ENVIRONMENT_VARIABLE: ""}), \
                    patch.object(workspace, "__file__", str(site / "workspace.py")):
                previous = Path.cwd()
                os.chdir(run_from)
                try:
                    self.assertEqual(workspace.workspace_root(), run_from.resolve())
                finally:
                    os.chdir(previous)


class StepEnvironmentTests(unittest.TestCase):

    def test_steps_import_the_package_the_orchestrator_runs(self):
        """Not <workspace>/src: an installed package with a checkout as its
        workspace would otherwise run the checkout's code in every step."""
        import cognalys
        from cognalys.orchestration import run_pipeline

        with tempfile.TemporaryDirectory() as directory:
            env = run_pipeline.build_environment(Path(directory))
        first = env["PYTHONPATH"].split(os.pathsep)[0]
        self.assertEqual(Path(first), Path(cognalys.__file__).resolve().parents[1])
        self.assertNotIn(str(Path(directory) / "src"), env["PYTHONPATH"])


if __name__ == "__main__":
    unittest.main()
