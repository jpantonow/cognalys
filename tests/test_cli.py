import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import cli  # noqa: E402
from cognalys.validation import semgrep_rules  # noqa: E402
from cognalys.workspace import ENVIRONMENT_VARIABLE  # noqa: E402

from _run_fixtures import run_directory  # noqa: E402
import test_detectors  # noqa: E402


def _run(argv) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class ConfigFileTests(unittest.TestCase):

    def test_the_pipeline_table_becomes_arguments_before_the_command_line(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cognalys.toml").write_text(
                '[pipeline]\nllm-provider = "ollama"\nvalidate-build = true\n'
                'generate-previews = false\nskip = ["publish", "issues"]\n',
                encoding="utf-8")
            self.assertEqual(cli.config_arguments(root), [
                "--llm-provider", "ollama", "--validate-build",
                "--skip", "publish", "--skip", "issues"])
            with patch.dict(os.environ, {ENVIRONMENT_VARIABLE: str(root)}):
                config = cli._config(["--llm-provider", "openai"])
            # The command line comes last, so it wins.
            self.assertEqual(config.namespace().llm_provider, "openai")
            self.assertTrue(config.namespace().validate_build)

    def test_no_file_means_no_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(cli.config_arguments(Path(directory)), [])


class CredentialFileTests(unittest.TestCase):
    """The launchers source .env.openai before a run; the command reads it
    the same way, and what the caller already set wins."""

    def test_variables_are_set_without_overriding_the_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.openai"
            path.write_text("# comment\nexport COGNALYS_TEST_A='one'\n"
                            "COGNALYS_TEST_B=two\nnot a line\n", encoding="utf-8")
            with patch.dict(os.environ, {"COGNALYS_TEST_B": "kept"}):
                loaded = cli.load_env_file(path)
                self.assertEqual(os.environ["COGNALYS_TEST_A"], "one")
                self.assertEqual(os.environ["COGNALYS_TEST_B"], "kept")
            os.environ.pop("COGNALYS_TEST_A", None)
        self.assertEqual(loaded, ["COGNALYS_TEST_A"])

    def test_a_missing_file_sets_nothing(self):
        self.assertEqual(cli.load_env_file(Path("/no/such/.env.openai")), [])

    def test_references_to_earlier_variables_are_expanded(self):
        """.env.github: GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" reached a commit literally."""
        names = ("COGNALYS_T_AUTHOR", "COGNALYS_T_COMMITTER", "COGNALYS_T_BRACED",
                 "COGNALYS_T_SINGLE")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env.github"
            path.write_text(
                "export COGNALYS_T_AUTHOR=jpantonow\n"
                'export COGNALYS_T_COMMITTER="$COGNALYS_T_AUTHOR"\n'
                "export COGNALYS_T_BRACED=${COGNALYS_T_AUTHOR}-bot\n"
                "export COGNALYS_T_SINGLE='$COGNALYS_T_AUTHOR'\n", encoding="utf-8")
            try:
                cli.load_env_file(path)
                self.assertEqual(os.environ["COGNALYS_T_COMMITTER"], "jpantonow")
                self.assertEqual(os.environ["COGNALYS_T_BRACED"], "jpantonow-bot")
                self.assertEqual(os.environ["COGNALYS_T_SINGLE"], "$COGNALYS_T_AUTHOR")
            finally:
                for name in names:
                    os.environ.pop(name, None)


class CommandTests(unittest.TestCase):

    def test_plan_prints_steps_and_runs_nothing(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {ENVIRONMENT_VARIABLE: directory}):
            code, out, _ = _run(["plan", "--llm-provider", "openai", "--findings", "f.jsonl", "--only", "llm"])
            self.assertEqual(list(Path(directory).iterdir()), [])
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("llm "))
        self.assertIn("-m cognalys.llm.generate_error_fixes", out)

    def test_invalid_pipeline_options_are_an_error_message(self):
        code, _, err = _run(["plan", "--only", "nope"])
        self.assertEqual(code, 2)
        self.assertIn("--only", err)

    def test_results_reads_a_run(self):
        with tempfile.TemporaryDirectory() as directory:
            run = run_directory(Path(directory))
            code, out, _ = _run(["results", str(run), "--json"])
        self.assertEqual(code, 0)
        [finding] = json.loads(out)["findings"]
        self.assertEqual(finding["outcome"], "PR pronto")

    def test_results_say_which_ready_drafts_need_a_rerun(self):
        """The fixture's draft records no behaviour-review contract, like the
        drafts that predate the review (Orgzly, Syncthing-Lite, 2026-10-25)."""
        with tempfile.TemporaryDirectory() as directory:
            run = run_directory(Path(directory))
            code, out, _ = _run(["results", str(run)])
        self.assertEqual(code, 0)
        self.assertIn("-> Use SHA-256 [revisão anterior: reexecutar]", out)

    def test_results_group_runs_by_the_library_version_they_recorded(self):
        """Each run counts its own outcomes: combined, the latest run would
        take the shared finding and leave the older versions empty."""
        identities = {"one": {"commit": "a" * 40, "dirty": False, "src_tree_sha256": "1" * 64},
                      "two": {"commit": "b" * 40, "dirty": True, "src_tree_sha256": "2" * 64},
                      "three": {"commit": "a" * 40, "dirty": False, "src_tree_sha256": "1" * 64},
                      "four": {"commit": "", "dirty": None, "src_tree_sha256": "4" * 64}}
        with tempfile.TemporaryDirectory() as directory:
            runs = []
            for name, identity in identities.items():
                run = run_directory(Path(directory) / name)
                (run / "run_inputs.json").write_text(
                    json.dumps({"library": identity}), encoding="utf-8")
                runs.append(str(run))
            code, out, _ = _run(["results", *runs, "--by-version", "--json"])
            _, text, _ = _run(["results", *runs, "--by-version"])
        self.assertEqual(code, 0)
        groups = json.loads(out)["by_version"]
        self.assertEqual(list(groups), ["aaaaaaaaaa", "bbbbbbbbbb dirty", "src 444444444444"])
        self.assertEqual(groups["aaaaaaaaaa"]["runs"], [runs[0], runs[2]])
        self.assertEqual(groups["aaaaaaaaaa"]["outcomes"], {"PR pronto": 2})
        self.assertEqual(groups["bbbbbbbbbb dirty"]["findings"], 1)
        self.assertIn("aaaaaaaaaa: 2 run(s), 2 findings. PR pronto: 2", text)

    def test_results_name_each_runs_library_once(self):
        with tempfile.TemporaryDirectory() as directory:
            recorded = run_directory(Path(directory) / "recorded")
            (recorded / "run_inputs.json").write_text(json.dumps({"library": {
                "commit": "c" * 40, "dirty": True, "src_tree_sha256": "3" * 64}}),
                encoding="utf-8")
            older = run_directory(Path(directory) / "older")
            code, out, _ = _run(["results", str(recorded), str(older)])
            _, as_json, _ = _run(["results", str(recorded), "--json"])
        self.assertEqual(code, 0)
        self.assertIn(f"Library of {recorded}: cccccccccc dirty\n", out)
        self.assertIn(f"Library of {older}: unrecorded\n", out)
        self.assertEqual(out.count("Library of "), 2)
        self.assertEqual(json.loads(as_json)["library_versions"],
                         {str(recorded): "cccccccccc dirty"})

    def test_results_keep_a_mixed_run_out_of_its_first_versions_group(self):
        """A run resumed under an edited src/ is not the clean commit's
        result; an older run without a library in run_inputs.json reads the
        one run_status.json recorded."""
        clean = {"commit": "a" * 40, "dirty": False, "src_tree_sha256": "1" * 64}
        edited = {"commit": "a" * 40, "dirty": True, "src_tree_sha256": "2" * 64}
        with tempfile.TemporaryDirectory() as directory:
            plain = run_directory(Path(directory) / "plain")
            (plain / "run_inputs.json").write_text(json.dumps({"library": clean}),
                                                   encoding="utf-8")
            mixed = run_directory(Path(directory) / "mixed")
            (mixed / "run_inputs.json").write_text(json.dumps({"library": clean}),
                                                   encoding="utf-8")
            (mixed / "run_status.json").write_text(json.dumps(
                {"passes": [clean, edited], "library": clean, "mixed_pipeline": True}),
                encoding="utf-8")
            older = run_directory(Path(directory) / "older")
            (older / "run_inputs.json").write_text(json.dumps({"config": {}}),
                                                   encoding="utf-8")
            (older / "run_status.json").write_text(json.dumps(
                {"passes": [clean], "library": clean, "mixed_pipeline": False}),
                encoding="utf-8")
            code, out, _ = _run(["results", str(plain), str(mixed), str(older),
                                 "--by-version", "--json"])
        self.assertEqual(code, 0)
        groups = json.loads(out)["by_version"]
        self.assertEqual(groups["aaaaaaaaaa"]["runs"], [str(plain), str(older)])
        self.assertEqual(groups["aaaaaaaaaa -> aaaaaaaaaa dirty (mixed)"]["runs"], [str(mixed)])

    def test_run_and_propose_prs_print_results_without_versions(self):
        from cognalys import api

        with tempfile.TemporaryDirectory() as directory:
            run = run_directory(Path(directory) / "run")
            (run / "run_inputs.json").write_text(json.dumps({"library": {
                "commit": "c" * 40, "dirty": False}}), encoding="utf-8")
            result = api.load_results(run)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli._print_results(result, False)
                cli._print_results(result, True)
        self.assertNotIn("Library of", out.getvalue())
        self.assertNotIn("library_versions", out.getvalue())

    def test_doctor_reports_each_capability(self):
        code, out, _ = _run(["doctor"])
        self.assertIn("semgrep", out)
        self.assertIn("workspace", out)
        self.assertIn(code, (0, 1))

    def test_propose_prs_refuses_a_changed_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = test_detectors._repository(directory)
            (repo / test_detectors.SOURCE).write_text("// edited\n", encoding="utf-8")
            code, _, err = _run(["propose-prs", "--repo", str(repo), "--llm-provider", "openai"])
        self.assertEqual(code, 2)
        self.assertIn("uncommitted changes", err)

    @unittest.skipUnless(semgrep_rules.find_semgrep(), "semgrep is not installed")
    def test_scan_lists_what_the_rules_find(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = test_detectors._repository(directory)
            code, out, _ = _run(["scan", "--repo", str(repo), "--spec",
                                 "MessageDigestSpec", "--json"])
        self.assertEqual(code, 0)
        [row] = json.loads(out)["findings"]
        self.assertEqual((row["class"], row["method"]), ("org.example.Hasher", "digest"))

    def test_the_package_runs_as_a_module(self):
        completed = subprocess.run(
            [os.sys.executable, "-m", "cognalys.cli", "plan", "--llm-provider", "openai", "--only", "llm"],
            capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(Path(_paths.ROOT) / "src")})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("llm", completed.stdout)


if __name__ == "__main__":
    unittest.main()
