import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import api  # noqa: E402
from cognalys.models import RunConfig  # noqa: E402
from cognalys.orchestration import run_pipeline  # noqa: E402
from cognalys.workspace import ENVIRONMENT_VARIABLE  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "golden_commands"
from _run_fixtures import KEY, run_directory as _run_directory  # noqa: E402


class LoadResultsTests(unittest.TestCase):

    def test_a_run_is_read_back_finding_by_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            run = _run_directory(Path(directory))

            result = api.load_results(run)

            [finding] = result.findings
            self.assertEqual(finding.key, KEY)
            self.assertEqual(finding.outcome, "PR pronto")
            self.assertTrue(finding.analysed)
            self.assertEqual(finding.decision, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
            self.assertEqual(finding.pr_title, "Use SHA-256")
            self.assertEqual(result.ready_pull_requests(), (finding,))
            self.assertEqual(result.outcomes()["PR pronto"], 1)

    def test_at_least_one_run_is_needed(self):
        with self.assertRaises(ValueError):
            api.load_results()


class RunConfigTests(unittest.TestCase):

    def test_invalid_arguments_raise_instead_of_exiting(self):
        with self.assertRaises(ValueError) as caught:
            RunConfig.from_legacy_args(["--only", "no-such-step"])
        self.assertIn("--only", str(caught.exception))

    def test_valid_arguments_are_kept_as_given(self):
        config = RunConfig.from_legacy_args(["--llm-provider", "openai", "--csv-file", "x.csv",
                                             "--validate-build"])
        self.assertEqual(config.arguments,
                         ("--llm-provider", "openai", "--csv-file", "x.csv", "--validate-build"))
        self.assertTrue(config.namespace().validate_build)


class PlanTests(unittest.TestCase):

    def test_the_plan_of_a_real_run_lists_the_steps_it_executed(self):
        """run_melhorias_20261011_203822 ran these fifteen steps."""
        recorded = json.loads((FIXTURES / "melhorias_20261011.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            steps = api.plan(RunConfig.from_legacy_args(recorded["argv"]), workspace=Path(directory))
        self.assertEqual([step.name for step in steps], [
            "spec_generation", "cloning", "repository_setup", "extraction", "spec_context",
            "detector_rules", "llm", "solutions", "validation", "validation_fix",
            "revalidation", "prs", "preview", "fix_prs", "revalidation_fix_prs",
        ])
        llm = next(step for step in steps if step.name == "llm")
        self.assertEqual(llm.command[1:3], ("-m", "cognalys.llm.generate_error_fixes"))

    def test_planning_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api.plan(RunConfig.from_legacy_args(
                ["--llm-provider", "openai", "--csv-file", "findings.csv", "--extracted-methods-dir", "outputs/r/error_methods"]),
                workspace=root)
            self.assertEqual(list(root.iterdir()), [])


class RunTests(unittest.TestCase):

    def test_run_calls_the_orchestrator_and_reads_its_run_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _run_directory(root)
            seen = {}

            def fake_main(argv):
                seen["argv"] = argv
                seen["workspace"] = os.environ.get(ENVIRONMENT_VARIABLE)
                return 0

            config = RunConfig.from_legacy_args(["--llm-provider", "openai", 
                "--csv-file", "findings.csv",
                "--extracted-methods-dir", "outputs/run_x/error_methods",
            ])
            with patch.object(run_pipeline, "main", side_effect=fake_main):
                result = api.run(config, workspace=root)

            self.assertEqual(seen["argv"], list(config.arguments))
            self.assertEqual(seen["workspace"], str(root))
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.runs, (root / "outputs" / "run_x",))
            self.assertEqual([f.outcome for f in result.findings], ["PR pronto"])
            self.assertNotEqual(os.environ.get(ENVIRONMENT_VARIABLE), str(root))


if __name__ == "__main__":
    unittest.main()
