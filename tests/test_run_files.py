import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import cli  # noqa: E402
from cognalys.orchestration import run_pipeline  # noqa: E402


class RunDirTests(unittest.TestCase):
    """--run-dir replaces the six per-run directory options."""

    def test_every_per_run_directory_goes_inside_it(self):
        args = run_pipeline.parse_args(["--llm-provider", "openai", "--run-dir", "outputs/minha"])
        self.assertEqual(args.extracted_methods_dir, "outputs/minha/error_methods")
        self.assertEqual(args.error_solutions_dir, "outputs/minha/error_solutions")
        self.assertEqual(args.application_results_dir, "outputs/minha/application_results")
        self.assertEqual(args.pull_requests_dir, "outputs/minha/pull_requests")
        self.assertEqual(args.issues_dir, "outputs/minha/issues")
        self.assertEqual(args.previews_dir, "outputs/minha/previews")
        # Shared across runs, as before.
        self.assertEqual(args.cloned_projects_dir, "outputs/cloned_projects")

    def test_an_explicit_directory_wins(self):
        args = run_pipeline.parse_args(["--llm-provider", "openai", "--run-dir", "outputs/minha",
                                        "--previews-dir", "elsewhere"])
        self.assertEqual(args.previews_dir, "elsewhere")

    def test_without_it_nothing_changes(self):
        args = run_pipeline.parse_args(["--llm-provider", "openai"])
        self.assertEqual(args.extracted_methods_dir, "outputs/error_methods_tracked")


class RunFileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def _config(self, *argv):
        with patch("cognalys.workspace.workspace_root", return_value=self.root):
            return cli._config(list(argv)).namespace()

    def test_the_template_is_a_valid_run(self):
        path = self.root / "minha_run.toml"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["init", "-o", str(path)]), 0)
        args = self._config(str(path))
        self.assertEqual(args.llm_provider, "openai")
        self.assertEqual(args.max_cost, 10.0)
        self.assertTrue(args.validate_build)
        self.assertEqual(args.extracted_methods_dir, "outputs/minha_run/error_methods")
        self.assertEqual(args.findings_files, ["data/processed/rv_import_findings.csv"])

    def test_init_does_not_overwrite(self):
        path = self.root / "minha_run.toml"
        path.write_text("mine", encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["init", "-o", str(path)]), 2)
        self.assertEqual(path.read_text(encoding="utf-8"), "mine")

    def test_the_command_line_wins_over_the_file(self):
        path = self.root / "run.toml"
        path.write_text('llm-provider = "openai"\nllm-model = "a"\nrun-dir = "outputs/x"\n'
                        'skip = ["build"]\n',
                        encoding="utf-8")
        args = self._config(str(path), "--llm-model", "b")
        self.assertEqual(args.llm_model, "b")
        self.assertEqual(args.skip, ["build"])
        self.assertEqual(args.pull_requests_dir, "outputs/x/pull_requests")

    def test_the_file_wins_over_the_workspace_config(self):
        (self.root / "cognalys.toml").write_text(
            '[pipeline]\nllm-provider = "openai"\nllm-model = "workspace"\n',
                                                 encoding="utf-8")
        path = self.root / "run.toml"
        path.write_text('llm-model = "run"\n', encoding="utf-8")
        self.assertEqual(self._config(str(path)).llm_model, "run")
        self.assertEqual(self._config().llm_model, "workspace")

    def test_a_missing_run_file_is_an_error(self):
        with self.assertRaises(ValueError):
            self._config(str(self.root / "nope.toml"))


class PublishTests(unittest.TestCase):
    def test_publish_approves_each_finding_it_is_given(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run / "pull_requests").mkdir()
            with patch("subprocess.run") as run_process:
                run_process.return_value.returncode = 0
                code = cli.main(["publish", str(run), "--finding", "abc", "--finding", "def",
                                 "--without-build-validation", "--dry-run"])
        self.assertEqual(code, 0)
        command = run_process.call_args.args[0]
        self.assertEqual(command[1:3], ["-m", "cognalys.prs.pr_creator"])
        self.assertEqual(command[command.index("--pull-requests-dir") + 1],
                         str((run / "pull_requests").resolve()))
        self.assertEqual(command.count("--approve-reviewed-finding"), 2)
        self.assertEqual(command.count("--publish-without-build-validation"), 2)
        self.assertIn("--dry-run", command)

    def test_nothing_is_approved_without_a_finding(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch("subprocess.run") as run_process:
            run_process.return_value.returncode = 0
            cli.main(["publish", directory])
        self.assertNotIn("--approve-reviewed-finding", run_process.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
