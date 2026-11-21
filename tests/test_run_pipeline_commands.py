import argparse
import contextlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (scripts/ and src/ on sys.path)


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "cognalys" / "orchestration" / "run_pipeline.py"
SPEC = importlib.util.spec_from_file_location("run_pipeline", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _step_name(command) -> str:
    """The step a command runs, named as its script in scripts/ is.

    Steps run as `python -m cognalys.<area>.<module>`. Scripts moved into the
    package kept their names; the four that were already facades name the
    module they front differently, so they are mapped back.
    """
    if len(command) > 2 and command[1] == "-m":
        module = str(command[2]).rsplit(".", 1)[-1]
        return _FACADE_SCRIPTS.get(module, module)
    return Path(str(command[1])).stem


_FACADE_SCRIPTS = {
    "applied_solutions": "validate_applied_solutions",
    "repair": "repair_validation_failures",
    "pr_feedback": "fix_prs",
    "apk_build": "build_apks_no_proguard",
}


def _paths() -> "MODULE.PipelinePaths":
    root = Path("/repo")
    return MODULE.PipelinePaths(
        root=root,
        input_csv_file=root / "in.csv",
        csv_file=root / "out.csv",
        cloned_projects_dir=root / "cloned",
        extracted_methods_dir=root / "extracted",
        build_output_dir=root / "build",
        error_solutions_dir=root / "solutions",
        application_results_dir=root / "results",
        worktrees_dir=root / "worktrees",
        pull_requests_dir=root / "prs",
        issues_dir=root / "issues",
        previews_dir=root / "previews",
    )


def _args(**overrides) -> argparse.Namespace:
    base = dict(
        limit=0, project="", dry_run=False, reprocess_existing=False,
        approve_reviewed_finding=[], publish_without_build_validation=[],
        approve_revision=[], approve_cleanup=[],
        allow_duplicate_pr=False, allow_stale_review=False,
        pr_issue_style="v1",
        issue_title="title", issue_body="body",
        overwrite_specifications=False, spec_model="test-model",
        llm_model="test-model", llm_endpoint="https://example.com/v1",
        llm_timeout=60, llm_max_output_tokens=1000, llm_reasoning_effort="low",
        openai_prompt_log_dir="",
        build_variant="debug", build_timeout=1800, publish_fix_prs=False,
        skip_fix_prs_compile_validation=False,
        skip_fix_prs_pr_state_check=False, fix_ci_failures=False,
        self_audit_prs=False,
        # Read by the "llm" step.
        approve_review_only_for_validation=False, no_llm_resume=False,
        no_llm_cache=False, llm_cache_dir="", allow_cache_invalidation=False,
        disable_llm_web_search=True, migration_policies_file="policies.json",
        llm_provider="openai", ollama_context_length=16384,
        llm_validation_mode="strict",
        repository_context_budget=100000,
        llm_web_search_cache_ttl_hours=168.0, llm_web_search_retries=1,
        llm_workers=1, llm_retries=2,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class WholeCsvScopingTests(unittest.TestCase):
    """Without --project, the clone-walking steps take the CSV's projects.

    repository_setup and build iterate outputs/cloned_projects. A five-row
    CSV run passed them nothing, and repository_setup checked out and fetched
    every one of sixty clones left behind by earlier runs.
    """

    HEADER = "apk,repo_url,class,method,message,apk_url\n"

    def _paths(self, directory: str, body: str):
        import dataclasses
        csv_file = Path(directory) / "findings.csv"
        csv_file.write_text(self.HEADER + body, encoding="utf-8")
        return dataclasses.replace(_paths(), csv_file=csv_file)

    def _projects(self, command):
        return [command[i + 1] for i, part in enumerate(command) if part == "--project"]

    def test_the_csv_projects_scope_setup_and_build(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self._paths(
                directory,
                "a.one_1.apk,https://github.com/a/one,C,m,msg,\n"
                "b.two_2.apk,https://github.com/b/two,C,m,msg,\n"
                "a.one_1.apk,https://github.com/a/one,D,n,msg,\n",
            )
            for step in ("repository_setup", "build"):
                with self.subTest(step=step):
                    command = MODULE.command_for_step(step, _args(), paths)
                    self.assertEqual(
                        self._projects(command), ["a.one_1.apk", "b.two_2.apk"],
                    )

    def test_an_explicit_project_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self._paths(directory, "a.one_1.apk,u,C,m,msg,\n")
            command = MODULE.command_for_step(
                "repository_setup", _args(project="x.y_9.apk"), paths,
            )
            self.assertEqual(self._projects(command), ["x.y_9.apk"])

    def test_the_apk_url_names_a_row_without_an_apk_column_value(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self._paths(
                directory, ",u,C,m,msg,https://f-droid.org/repo/c.three_3.apk\n",
            )
            command = MODULE.command_for_step("repository_setup", _args(), paths)
            self.assertEqual(self._projects(command), ["c.three_3.apk"])

    def test_an_unnamed_row_leaves_the_step_unscoped(self):
        """A partial list would silently skip the project it could not name."""
        with tempfile.TemporaryDirectory() as directory:
            paths = self._paths(
                directory, "a.one_1.apk,u,C,m,msg,\n,u,C,m,msg,\n",
            )
            command = MODULE.command_for_step("repository_setup", _args(), paths)
            self.assertEqual(self._projects(command), [])


class PublishWithoutValidationWiringTests(unittest.TestCase):
    """The approval has to survive the hop into each subprocess.

    It is read by two different steps -- prs, which decides whether to
    commit, and publish, which decides whether to push -- and a flag that
    reaches only one of them is a flag that does nothing.
    """

    def test_every_step_that_reads_it_forwards_the_approval(self):
        # validation is in the list because without it the run stops on the
        # infrastructure failure and never reaches the other two.
        for step in ("validation", "prs", "publish"):
            with self.subTest(step=step):
                command = MODULE.command_for_step(
                    step,
                    _args(publish_without_build_validation=["abc123"]),
                    _paths(),
                )
                self.assertIn("--publish-without-build-validation", command)
                self.assertIn("abc123", command)

    def test_no_step_forwards_it_by_default(self):
        for step in ("validation", "prs", "publish"):
            with self.subTest(step=step):
                command = MODULE.command_for_step(step, _args(), _paths())
                self.assertNotIn(
                    "--publish-without-build-validation", command
                )


class RevalidationScopeWiringTests(unittest.TestCase):
    def test_revalidation_rebuilds_only_repaired_or_failing_findings_by_default(self):
        command = MODULE.command_for_step("revalidation", _args(), _paths())
        self.assertIn("--revalidate-repaired-in", command)
        self.assertEqual(
            command[command.index("--revalidate-repaired-in") + 1],
            str(_paths().application_results_dir / "validation_fixes"),
        )

    def test_full_revalidation_and_the_first_validation_are_unchanged(self):
        self.assertNotIn(
            "--revalidate-repaired-in",
            MODULE.command_for_step(
                "revalidation", _args(full_revalidation=True), _paths()),
        )
        self.assertNotIn(
            "--revalidate-repaired-in",
            MODULE.command_for_step("validation", _args(), _paths()),
        )


class RevalidationDoesNotAbortTheRunTests(unittest.TestCase):
    """One finding that still fails must not stop the prs step for the rest."""

    def test_no_validation_step_fails_the_run_on_a_patch_failure(self):
        for step in ("validation", "revalidation"):
            with self.subTest(step=step):
                self.assertNotIn(
                    "--fail-on-validation-error",
                    MODULE.command_for_step(step, _args(), _paths()),
                )


class StatisticsPreviousRunTests(unittest.TestCase):
    """The stability table compares with the latest run on the same findings."""

    HEADER = "apk,class,method,spec\n"

    def _layout(self, directory):
        base = Path(directory)
        csv_file = base / "findings.csv"
        csv_file.write_text(self.HEADER + "a.apk,C,m,S\nb.apk,D,n,T\n", encoding="utf-8")
        return base, csv_file

    @staticmethod
    def _run(base, name, keys=(), inputs=None, llm_finished=True):
        run = base / name
        run.mkdir()
        steps = [{"step": "extraction", "exit_code": 0}]
        if llm_finished:
            steps.append({"step": "llm", "exit_code": 0})
        (run / "step_timings.json").write_text(json.dumps({"steps": steps}), encoding="utf-8")
        for index, (apk, cls, method, spec) in enumerate(keys):
            path = run / "error_methods" / apk / f"{index}_{method}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({
                "extraction_metadata": {"apk_name": apk},
                "error": {"csv_class": cls, "csv_method": method, "spec": spec},
            }), encoding="utf-8")
        if inputs is not None:
            (run / MODULE.RUN_INPUTS_FILE).write_text(json.dumps(inputs), encoding="utf-8")
        return run

    def test_a_recorded_hash_identifies_the_previous_run(self):
        with tempfile.TemporaryDirectory() as directory:
            base, csv_file = self._layout(directory)
            digest = MODULE._file_sha256(csv_file)
            previous = self._run(base, "run_1", inputs={"findings_csv_sha256": digest})
            current = self._run(base, "run_2")
            self.assertEqual(
                MODULE.previous_run_on_same_input(current, csv_file, digest), previous)

    def test_an_unrecorded_run_matches_by_its_extracted_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            base, csv_file = self._layout(directory)
            previous = self._run(base, "run_1", keys=[("a.apk", "C", "m", "S"),
                                                     ("b.apk", "D", "n", "T")])
            current = self._run(base, "run_2")
            self.assertEqual(
                MODULE.previous_run_on_same_input(current, csv_file, "x"), previous)

    def test_a_run_on_other_findings_is_not_compared(self):
        with tempfile.TemporaryDirectory() as directory:
            base, csv_file = self._layout(directory)
            self._run(base, "run_1", keys=[("z.apk", "Z", "z", "Z")])
            self._run(base, "run_0", inputs={"findings_csv_sha256": "other"})
            current = self._run(base, "run_2")
            self.assertIsNone(MODULE.previous_run_on_same_input(current, csv_file, "x"))

    def test_a_run_interrupted_before_its_analysis_finished_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            base, csv_file = self._layout(directory)
            digest = MODULE._file_sha256(csv_file)
            complete = self._run(base, "run_1", inputs={"findings_csv_sha256": digest})
            self._run(base, "run_2", inputs={"findings_csv_sha256": digest},
                      llm_finished=False)
            current = self._run(base, "run_3")
            self.assertEqual(
                MODULE.previous_run_on_same_input(current, csv_file, digest), complete)

    def test_the_statistics_can_be_turned_off(self):
        with patch.object(MODULE.subprocess, "run") as run:
            MODULE.run_statistics_safely(
                _paths(), argparse.Namespace(no_statistics=True), ["llm"])
        run.assert_not_called()


class GradleBuildCacheWiringTests(unittest.TestCase):
    def test_validation_forwards_the_cache_only_when_asked(self):
        for step in ("validation", "revalidation"):
            with self.subTest(step=step):
                self.assertNotIn(
                    "--gradle-build-cache",
                    MODULE.command_for_step(step, _args(), _paths()),
                )
                self.assertIn(
                    "--gradle-build-cache",
                    MODULE.command_for_step(
                        step, _args(gradle_build_cache=True), _paths(),
                    ),
                )


class ReprocessExistingWiringTests(unittest.TestCase):
    def test_spec_generation_includes_selected_project(self):
        command = MODULE.command_for_step(
            "spec_generation", _args(project="target.apk"), _paths()
        )
        self.assertEqual(command[-2:], ["--project", "target.apk"])

    def test_publish_command_omits_flag_by_default(self):
        command = MODULE.command_for_step("publish", _args(), _paths())
        self.assertNotIn("--reprocess-existing", command)

    def test_publish_command_includes_flag_when_requested(self):
        command = MODULE.command_for_step(
            "publish", _args(reprocess_existing=True), _paths()
        )
        self.assertIn("--reprocess-existing", command)

    def test_publish_forwards_allow_stale_review_only_when_requested(self):
        # The override reaches pr_creator, which withholds a draft that did
        # not pass the current behaviour review unless it is passed.
        self.assertNotIn(
            "--allow-stale-review",
            MODULE.command_for_step("publish", _args(), _paths()),
        )
        self.assertIn(
            "--allow-stale-review",
            MODULE.command_for_step(
                "publish", _args(allow_stale_review=True), _paths()
            ),
        )
        self.assertNotIn(
            "--allow-stale-review",
            MODULE.command_for_step(
                "prs", _args(allow_stale_review=True), _paths()
            ),
        )

    def test_issues_command_omits_flag_by_default(self):
        command = MODULE.command_for_step("issues", _args(), _paths())
        self.assertNotIn("--reprocess-existing", command)

    def test_issues_command_includes_flag_when_requested(self):
        command = MODULE.command_for_step(
            "issues", _args(reprocess_existing=True), _paths()
        )
        self.assertIn("--reprocess-existing", command)

    def test_fix_prs_command_never_compiles_or_publishes(self):
        # fix_prs is revision-only: compiling and publishing are the
        # separate, explicit revalidation_fix_prs step below.
        command = MODULE.command_for_step("fix_prs", _args(), _paths())
        self.assertNotIn("--build-script", command)
        self.assertNotIn("--publish", command)
        self.assertNotIn("--revalidate", command)
        self.assertNotIn("--skip-pr-state-check", command)

    def test_fix_prs_command_includes_pr_state_skip_flag_when_requested(self):
        command = MODULE.command_for_step(
            "fix_prs", _args(skip_fix_prs_pr_state_check=True), _paths(),
        )
        self.assertIn("--skip-pr-state-check", command)

    def test_fix_prs_command_omits_fix_ci_failures_by_default(self):
        command = MODULE.command_for_step("fix_prs", _args(), _paths())
        self.assertNotIn("--fix-ci-failures", command)

    def test_fix_prs_command_includes_fix_ci_failures_when_requested(self):
        command = MODULE.command_for_step(
            "fix_prs", _args(fix_ci_failures=True), _paths(),
        )
        self.assertIn("--fix-ci-failures", command)

    def test_fix_prs_command_omits_self_audit_by_default(self):
        command = MODULE.command_for_step("fix_prs", _args(), _paths())
        self.assertNotIn("--self-audit", command)

    def test_fix_prs_command_includes_self_audit_when_requested(self):
        command = MODULE.command_for_step(
            "fix_prs", _args(self_audit_prs=True), _paths(),
        )
        self.assertIn("--self-audit", command)

    def test_revalidation_fix_prs_command_forwards_build_settings_by_default(self):
        command = MODULE.command_for_step("revalidation_fix_prs", _args(), _paths())
        self.assertIn("--revalidate", command)
        # The package's own build stage: no script path is handed over.
        self.assertNotIn("--build-script", command)
        self.assertIn("--build-variant", command)
        self.assertEqual(
            command[command.index("--build-variant") + 1], "debug"
        )
        self.assertIn("--build-timeout", command)
        self.assertEqual(
            command[command.index("--build-timeout") + 1], "1800"
        )
        self.assertNotIn("--skip-compile-validation", command)
        self.assertNotIn("--publish", command)

    def test_revalidation_fix_prs_command_includes_skip_and_publish_flags(self):
        command = MODULE.command_for_step(
            "revalidation_fix_prs",
            _args(skip_fix_prs_compile_validation=True, publish_fix_prs=True),
            _paths(),
        )
        self.assertIn("--skip-compile-validation", command)
        self.assertIn("--publish", command)


class LlmCacheWiringTests(unittest.TestCase):
    """The LLM cache must be anchored outside the per-run output directory.

    Its previous default resolved to ERROR_SOLUTIONS_DIR/.llm_cache, which is
    recreated empty for every run, so paid responses were written once and
    never read back (observed as "0 hit(s), 4 miss(es)" on every run while
    238 entries sat in ~40 orphaned per-run directories).
    """

    def _cache_dir(self, **overrides) -> str:
        command = MODULE.command_for_step(
            "llm", _args(**overrides), _paths()
        )
        return command[command.index("--cache-dir") + 1]

    def test_default_cache_is_shared_across_runs(self):
        self.assertEqual(self._cache_dir(), str(Path("/repo/outputs/.llm_cache")))

    def test_default_cache_is_outside_the_run_output_directory(self):
        self.assertNotIn("solutions", Path(self._cache_dir()).parts)

    def test_explicit_cache_dir_is_honoured(self):
        self.assertEqual(
            self._cache_dir(llm_cache_dir="custom/cache"),
            str(Path("/repo/custom/cache")),
        )

    def test_disabling_the_cache_passes_no_cache_dir(self):
        command = MODULE.command_for_step(
            "llm", _args(no_llm_cache=True), _paths()
        )
        self.assertIn("--no-cache", command)
        self.assertNotIn("--cache-dir", command)

    def test_llm_script_own_default_is_not_under_the_output_dir(self):
        """Defence in depth for a direct invocation of the LLM script.

        run_pipeline.py now always passes --cache-dir, which masks the script's
        own default. That default must still be run-independent so invoking the
        script directly does not silently reintroduce a never-hitting cache.
        """
        source = (ROOT / "src" / "cognalys" / "llm" / "generate_error_fixes.py")
        text = source.read_text(encoding="utf-8")
        start = text.index("cache_dir = None if args.no_cache")
        expression = text[start:start + 200]
        self.assertNotIn('output_dir / ".llm_cache"', expression)
        self.assertIn('"outputs" / ".llm_cache"', expression)


class ValidationFullyPassedTests(unittest.TestCase):
    def test_true_when_every_entry_succeeded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "execution_report.json"
            path.write_text(json.dumps({
                "per_solution_details": [
                    {"build_validation": {"status": "success"}},
                    {"build_validation": {"status": "success"}},
                ],
            }))
            self.assertTrue(MODULE.validation_fully_passed(path))

    def test_an_app_module_only_success_counts_as_passing(self):
        # run_20260913_180317: TowerCollector compiled its app module while an
        # unrelated module could not build, validation reported "2 passed",
        # and validation_fix plus a full revalidation still ran.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "execution_report.json"
            path.write_text(json.dumps({
                "per_solution_details": [
                    {"build_validation": {"status": "success_app_module_only"}},
                    {"build_validation": {"status": "success"}},
                ],
            }))
            self.assertTrue(MODULE.validation_fully_passed(path))

    def test_false_when_one_entry_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "execution_report.json"
            path.write_text(json.dumps({
                "per_solution_details": [
                    {"build_validation": {"status": "success"}},
                    {"build_validation": {"status": "failed"}},
                ],
            }))
            self.assertFalse(MODULE.validation_fully_passed(path))

    def test_false_when_no_build_validation_entries_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "execution_report.json"
            path.write_text(json.dumps({"per_solution_details": []}))
            self.assertFalse(MODULE.validation_fully_passed(path))

    def test_false_when_the_report_is_missing_or_malformed(self):
        missing = Path(tempfile.mkdtemp()) / "does_not_exist.json"
        self.assertFalse(MODULE.validation_fully_passed(missing))


def _no_repository_lock(_root):
    # These tests exercise step orchestration. The real lock lives under the
    # project's own outputs/, so a pipeline running on this machine made
    # them fail with "Repository use is locked" -- a property of the
    # machine, not of the code under test.
    return contextlib.nullcontext()


class RevalidationSkipIntegrationTests(unittest.TestCase):
    def _run(self, report_entries, extra_args=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app_results = root / "results"
            app_results.mkdir()
            (app_results / "execution_report.json").write_text(json.dumps({
                "per_solution_details": report_entries,
            }))
            invoked = []

            def fake_run(command, cwd=None, env=None, timeout_seconds=None):
                invoked.append(_step_name(command))
                return {"returncode": 0, "timed_out": False}

            argv = [
                "run_pipeline.py", "--llm-provider", "openai",
                # These tests exercise step orchestration, not the pre-run
                # checks, and pyflakes over the whole of src and scripts
                # would dominate their runtime for nothing.
                "--skip-preflight",
                "--no-retrospective",
                "--csv-file", str(root / "in.csv"),
                "--cloned-projects-dir", str(root / "cloned"),
                "--extracted-methods-dir", str(root / "extracted"),
                "--build-output-dir", str(root / "build"),
                "--error-solutions-dir", str(root / "solutions"),
                "--application-results-dir", str(app_results),
                "--worktrees-dir", str(root / "worktrees"),
                "--pull-requests-dir", str(root / "prs"),
                "--issues-dir", str(root / "issues"),
                "--previews-dir", str(root / "previews"),
                "--start-from", "validation",
                "--skip", "prs",
                "--skip", "fix_prs",
                *extra_args,
            ]
            with patch.object(sys, "argv", argv), \
                 patch.object(MODULE, "run_with_deadline", fake_run),                  patch("cognalys.utils.repository_lock.RepositoryUsageLock",
                       _no_repository_lock):
                exit_code = MODULE.main()
            return exit_code, invoked

    def test_skips_validation_fix_and_revalidation_when_validation_passes(self):
        exit_code, invoked = self._run(
            [{"finding_id": "a", "build_validation": {"status": "success"}}]
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(invoked.count("validate_applied_solutions"), 1)
        self.assertNotIn("repair_validation_failures", invoked)

    def test_skips_both_when_validation_passes_on_the_app_module_only(self):
        exit_code, invoked = self._run([
            {"finding_id": "a", "build_validation": {"status": "success_app_module_only"}},
            {"finding_id": "b", "build_validation": {"status": "success"}},
        ])
        self.assertEqual(exit_code, 0)
        self.assertEqual(invoked.count("validate_applied_solutions"), 1)
        self.assertNotIn("repair_validation_failures", invoked)

    def test_runs_validation_fix_and_revalidation_when_a_repair_was_applied(self):
        exit_code, invoked = self._run([{
            "finding_id": "a", "build_validation": {"status": "failed"},
            "validation_fix": {"status": "success"},
        }])
        self.assertEqual(exit_code, 0)
        self.assertEqual(invoked.count("validate_applied_solutions"), 2)
        self.assertIn("repair_validation_failures", invoked)

    def test_skips_revalidation_when_validation_fix_repaired_nothing(self):
        # Revalidating unchanged worktrees only reproduces the failure
        # validation already recorded.
        exit_code, invoked = self._run(
            [{"finding_id": "a", "build_validation": {"status": "failed"}}]
        )
        self.assertEqual(exit_code, 0)
        self.assertIn("repair_validation_failures", invoked)
        self.assertEqual(invoked.count("validate_applied_solutions"), 1)

    def test_force_revalidation_always_runs_them(self):
        exit_code, invoked = self._run(
            [{"finding_id": "a", "build_validation": {"status": "success"}}],
            extra_args=["--force-revalidation"],
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(invoked.count("validate_applied_solutions"), 2)
        self.assertIn("repair_validation_failures", invoked)


class SolutionsReportIsEmptyTests(unittest.TestCase):
    def test_true_when_total_solutions_is_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "execution_report.json"
            path.write_text(json.dumps({"total_solutions": 0}))
            self.assertTrue(MODULE.solutions_report_is_empty(path))

    def test_false_when_total_solutions_is_positive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "execution_report.json"
            path.write_text(json.dumps({"total_solutions": 3}))
            self.assertFalse(MODULE.solutions_report_is_empty(path))

    def test_false_when_the_report_is_missing_or_malformed(self):
        missing = Path(tempfile.mkdtemp()) / "does_not_exist.json"
        self.assertFalse(MODULE.solutions_report_is_empty(missing))


class HasIssueCandidatesTests(unittest.TestCase):
    def test_false_when_directory_is_missing(self):
        missing = Path(tempfile.mkdtemp()) / "issue_candidates"
        self.assertFalse(MODULE.has_issue_candidates(missing))

    def test_false_when_directory_has_no_issue_files(self):
        with tempfile.TemporaryDirectory() as directory:
            candidates = Path(directory) / "issue_candidates"
            candidates.mkdir()
            (candidates / "notes.txt").write_text("x")
            self.assertFalse(MODULE.has_issue_candidates(candidates))

    def test_true_when_an_issue_file_exists_in_a_subdirectory(self):
        with tempfile.TemporaryDirectory() as directory:
            candidates = Path(directory) / "issue_candidates" / "app.apk"
            candidates.mkdir(parents=True)
            (candidates / "1_method_issue.json").write_text("{}")
            self.assertTrue(
                MODULE.has_issue_candidates(candidates.parent)
            )


class DownstreamSkipIntegrationTests(unittest.TestCase):
    def _run(self, total_solutions, issue_candidate_files=(), extra_args=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app_results = root / "results"
            app_results.mkdir()
            (app_results / "execution_report.json").write_text(json.dumps({
                "total_solutions": total_solutions,
            }))
            solutions_dir = root / "solutions"
            candidates_dir = solutions_dir / "issue_candidates"
            candidates_dir.mkdir(parents=True)
            for name in issue_candidate_files:
                (candidates_dir / name).write_text("{}")

            invoked = []

            def fake_run(command, cwd=None, env=None, timeout_seconds=None):
                invoked.append(_step_name(command))
                return {"returncode": 0, "timed_out": False}

            argv = [
                "run_pipeline.py", "--llm-provider", "openai",
                # These tests exercise step orchestration, not the pre-run
                # checks, and pyflakes over the whole of src and scripts
                # would dominate their runtime for nothing.
                "--skip-preflight",
                "--no-retrospective",
                "--csv-file", str(root / "in.csv"),
                "--cloned-projects-dir", str(root / "cloned"),
                "--extracted-methods-dir", str(root / "extracted"),
                "--build-output-dir", str(root / "build"),
                "--error-solutions-dir", str(solutions_dir),
                "--application-results-dir", str(app_results),
                "--worktrees-dir", str(root / "worktrees"),
                "--pull-requests-dir", str(root / "prs"),
                "--issues-dir", str(root / "issues"),
                "--previews-dir", str(root / "previews"),
                "--start-from", "solutions",
                "--validate-build",
                "--generate-previews",
                "--publish-prs",
                "--publish-issues",
                *extra_args,
            ]
            with patch.object(sys, "argv", argv), \
                 patch.object(MODULE, "run_with_deadline", fake_run),                  patch("cognalys.utils.repository_lock.RepositoryUsageLock",
                       _no_repository_lock):
                exit_code = MODULE.main()
            return exit_code, invoked

    def test_skips_downstream_steps_when_nothing_applied_or_candidate(self):
        exit_code, invoked = self._run(total_solutions=0)
        self.assertEqual(exit_code, 0)
        self.assertIn("run_apply", invoked)
        self.assertNotIn("validate_applied_solutions", invoked)
        self.assertNotIn("repair_validation_failures", invoked)
        self.assertNotIn("run_prs", invoked)
        self.assertNotIn("pr_creator", invoked)
        self.assertNotIn("fix_prs", invoked)
        self.assertNotIn("issue_creator", invoked)
        self.assertIn("generate_github_previews", invoked)

    def test_runs_downstream_steps_when_solutions_exist(self):
        exit_code, invoked = self._run(total_solutions=2)
        self.assertEqual(exit_code, 0)
        self.assertIn("validate_applied_solutions", invoked)
        self.assertIn("run_prs", invoked)
        self.assertIn("pr_creator", invoked)
        self.assertEqual(invoked.count("fix_prs"), 2)
        self.assertIn("generate_github_previews", invoked)

    def test_still_runs_issues_when_candidates_exist_without_solutions(self):
        exit_code, invoked = self._run(
            total_solutions=0, issue_candidate_files=["1_x_issue.json"],
        )
        self.assertEqual(exit_code, 0)
        self.assertNotIn("validate_applied_solutions", invoked)
        self.assertNotIn("pr_creator", invoked)
        self.assertIn("issue_creator", invoked)

    def test_force_downstream_steps_always_runs_them(self):
        exit_code, invoked = self._run(
            total_solutions=0, extra_args=["--force-downstream-steps"],
        )
        self.assertEqual(exit_code, 0)
        self.assertIn("validate_applied_solutions", invoked)
        self.assertIn("run_prs", invoked)
        self.assertIn("pr_creator", invoked)
        self.assertIn("issue_creator", invoked)


class PreviewAfterFailedValidationTests(unittest.TestCase):
    """A failed validation step is a result, and the preview still shows it.

    Six runs (bluegate run, run_v5 and run_v6, lite run_v2, tasks run_v2,
    tokn run_v4; 2026-10-31 audit) ended with an empty previews/ because
    validation_fix exited 1 when its repair failed, and the run returned
    before preview, which publishes nothing.
    """

    def _run(self, failing_step):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app_results = root / "results"
            app_results.mkdir()
            (app_results / "execution_report.json").write_text(json.dumps({
                "total_solutions": 1,
                "per_solution_details": [
                    {"finding_id": "a", "build_validation": {"status": "failed"}}],
            }))
            invoked = []

            def fake_run(command, cwd=None, env=None, timeout_seconds=None, **_watch):
                invoked.append(_step_name(command))
                return {"returncode": 1 if invoked[-1] == failing_step else 0,
                        "timed_out": False}

            argv = [
                "run_pipeline.py", "--llm-provider", "openai", "--skip-preflight", "--no-retrospective",
                "--no-statistics",
                "--csv-file", str(root / "in.csv"),
                "--cloned-projects-dir", str(root / "cloned"),
                "--extracted-methods-dir", str(root / "extracted"),
                "--build-output-dir", str(root / "build"),
                "--error-solutions-dir", str(root / "run" / "error_solutions"),
                "--application-results-dir", str(app_results),
                "--worktrees-dir", str(root / "worktrees"),
                "--pull-requests-dir", str(root / "prs"),
                "--issues-dir", str(root / "issues"),
                "--previews-dir", str(root / "previews"),
                "--start-from", "solutions", "--validate-build", "--generate-previews",
            ]
            with patch.object(sys, "argv", argv), \
                 patch.object(MODULE, "run_with_deadline", fake_run), \
                 patch("cognalys.utils.repository_lock.RepositoryUsageLock",
                       _no_repository_lock):
                exit_code = MODULE.main()
            status = json.loads((root / "run" / "run_status.json").read_text())
            inputs = json.loads((root / "run" / "run_inputs.json").read_text())
            return exit_code, invoked, status, inputs

    def test_a_failed_validation_fix_still_runs_the_preview(self):
        exit_code, invoked, status, inputs = self._run("repair_validation_failures")

        self.assertEqual(exit_code, 1)
        self.assertEqual(invoked[-1], "generate_github_previews")
        self.assertNotIn("run_prs", invoked)
        # The run is complete: the failed repair is its result, not a stop.
        self.assertEqual(status["status"], "complete")
        self.assertEqual(status["failed_steps"],
                         [{"step": "validation_fix", "exit_code": 1}])
        self.assertEqual(inputs["library"]["src_tree_sha256"], "test-suite")

    def test_a_failed_apply_still_stops_the_run(self):
        exit_code, invoked, _, _ = self._run("run_apply")

        self.assertEqual(exit_code, 1)
        self.assertNotIn("generate_github_previews", invoked)


class StepRegistryTests(unittest.TestCase):
    """One home per step, and a check that the tables agree.

    command_for_step was a 452-line chain of `if step == ...`, and the step
    vocabulary lived in six independent places in run_pipeline.py: the
    ordered tuple, that chain, five flag filters, and three more sets used
    for skip and reporting logic. Adding or renaming a step meant finding
    all six, and nothing verified they agreed. These assertions are what
    "nothing verified" is replaced with.
    """

    def test_every_pipeline_step_has_a_command_builder(self):
        missing = sorted(set(MODULE.PIPELINE_STEPS) - set(MODULE.STEP_COMMAND_BUILDERS))
        self.assertEqual(missing, [])

    def test_every_builder_names_a_real_step(self):
        # Maintenance modes use explicit flags instead of the ordered tuple.
        extra = sorted(
            set(MODULE.STEP_COMMAND_BUILDERS) - set(MODULE.PIPELINE_STEPS)
        )
        self.assertEqual(extra, ["cleanup", "prune_unused_repos"])

    def test_every_optional_step_is_a_real_step(self):
        unknown = sorted(set(MODULE.OPTIONAL_STEPS) - set(MODULE.PIPELINE_STEPS))
        self.assertEqual(unknown, [])

    def test_every_optional_step_names_a_real_argparse_flag(self):
        # A gate naming a flag argparse does not define would read as False
        # forever, silently removing the step from every run.
        argv = [
            "run_pipeline.py", "--llm-provider", "openai",
            "--csv-file", "data/x.csv",
            "--cloned-projects-dir", "outputs/cloned",
            "--extracted-methods-dir", "outputs/m",
            "--error-solutions-dir", "outputs/s",
            "--application-results-dir", "outputs/a",
            "--pull-requests-dir", "outputs/p",
            "--issues-dir", "outputs/i",
            "--previews-dir", "outputs/v",
        ]
        with patch.object(sys, "argv", argv):
            args = MODULE.parse_args()
        for step, gate in MODULE.OPTIONAL_STEPS.items():
            if gate["flag"]:
                self.assertTrue(hasattr(args, gate["flag"]), step)

    def test_every_gate_start_from_is_a_real_step(self):
        for step, gate in MODULE.OPTIONAL_STEPS.items():
            self.assertIn(gate["start_from"], MODULE.PIPELINE_STEPS, step)

    def test_an_unknown_step_is_refused(self):
        with self.assertRaises(ValueError):
            MODULE.command_for_step("not_a_step", argparse.Namespace(), None)

    def test_a_gated_step_is_dropped_without_its_flag(self):
        args = argparse.Namespace(
            publish_prs=False, start_from="llm", validate_build=False,
            build_no_proguard=False, publish_issues=False,
            generate_previews=False,
        )
        self.assertFalse(MODULE._step_enabled("publish", args))

    def test_a_gated_step_is_kept_with_its_flag(self):
        args = argparse.Namespace(
            publish_prs=True, start_from="llm", validate_build=False,
            build_no_proguard=False, publish_issues=False,
            generate_previews=False,
        )
        self.assertTrue(MODULE._step_enabled("publish", args))

    def test_starting_at_validation_admits_the_whole_validation_trio(self):
        # The escape hatch is not always the step's own name: asking to
        # start at "validation" must also admit validation_fix and
        # revalidation, which is why the table stores start_from separately.
        args = argparse.Namespace(
            validate_build=False, start_from="validation", publish_prs=False,
            build_no_proguard=False, publish_issues=False,
            generate_previews=False,
        )
        for step in ("validation", "validation_fix", "revalidation"):
            self.assertTrue(MODULE._step_enabled(step, args), step)

    def test_issues_cleanup_is_reachable_only_by_starting_there(self):
        args = argparse.Namespace(start_from="llm")
        self.assertFalse(MODULE._step_enabled("issues_cleanup", args))
        args = argparse.Namespace(start_from="issues_cleanup")
        self.assertTrue(MODULE._step_enabled("issues_cleanup", args))


class LlmPerformanceWiringTests(unittest.TestCase):
    """The analysis step's cost controls must reach the child process.

    Web research was 64% of the pipeline's LLM wall time in the runs of
    2026-09-07, and every finding was analysed one at a time. Both are now
    tunable, and a flag that never reaches the command line tunes nothing.
    """

    def _command(self, **overrides) -> list:
        return MODULE.command_for_step("llm", _args(**overrides), _paths())

    def test_defaults_pass_a_week_long_research_ttl_and_one_worker(self):
        command = self._command()
        self.assertEqual(
            command[command.index("--web-search-cache-ttl-hours") + 1], "168.0"
        )
        self.assertEqual(command[command.index("--web-search-retries") + 1], "1")
        self.assertEqual(command[command.index("--workers") + 1], "1")
        self.assertEqual(command[command.index("--retries") + 1], "2")

    def test_overrides_are_forwarded(self):
        command = self._command(
            llm_web_search_cache_ttl_hours=0.0, llm_web_search_retries=3,
            llm_workers=4, llm_retries=0,
        )
        self.assertEqual(
            command[command.index("--web-search-cache-ttl-hours") + 1], "0.0"
        )
        self.assertEqual(command[command.index("--web-search-retries") + 1], "3")
        self.assertEqual(command[command.index("--workers") + 1], "4")
        self.assertEqual(command[command.index("--retries") + 1], "0")


class CacheBypassPerFindingTests(unittest.TestCase):
    def test_repeated_patterns_reach_the_steps_environment(self):
        argv = ["run_pipeline.py", "--llm-provider", "openai", "--csv-file", "data/x.csv",
                "--llm-cache-bypass-finding", "appModule$lambda$0$3",
                "--llm-cache-bypass-finding", " other.apk "]
        with patch.object(sys, "argv", argv):
            args = MODULE.parse_args()
        with patch.dict("os.environ", {}, clear=False) as environment:
            environment.pop("TCC_LLM_CACHE_BYPASS_FINDINGS", None)
            self.assertEqual(MODULE.export_cache_bypass_patterns(args),
                             ["appModule$lambda$0$3", "other.apk"])
            self.assertEqual(environment["TCC_LLM_CACHE_BYPASS_FINDINGS"],
                             "appModule$lambda$0$3\nother.apk")

    def test_without_patterns_nothing_is_exported(self):
        with patch.dict("os.environ", {}, clear=False) as environment:
            environment.pop("TCC_LLM_CACHE_BYPASS_FINDINGS", None)
            MODULE.export_cache_bypass_patterns(argparse.Namespace(llm_cache_bypass_finding=[]))
            self.assertNotIn("TCC_LLM_CACHE_BYPASS_FINDINGS", environment)


class LearningStoreWiringTests(unittest.TestCase):
    """--learning-dir decides where the steps read the store, not only where
    the retrospective writes it (2026-11-10: every benchmark execution that
    planned read sibling executions' attempts from the shared store)."""

    def _run(self, extra_args=(), environment=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "results").mkdir()
            (root / "results" / "execution_report.json").write_text(json.dumps({
                "per_solution_details": [{"finding_id": "a", "build_validation": {"status": "success"}}],
            }))
            seen = []

            def fake_run(command, cwd=None, env=None, timeout_seconds=None):
                seen.append((env or {}).get("TCC_LEARNING_DIR")
                            or __import__("os").environ.get("TCC_LEARNING_DIR"))
                return {"returncode": 0, "timed_out": False}

            argv = [
                "run_pipeline.py", "--llm-provider", "openai", "--skip-preflight", "--no-retrospective",
                "--csv-file", str(root / "in.csv"),
                "--cloned-projects-dir", str(root / "cloned"),
                "--extracted-methods-dir", str(root / "run" / "extracted"),
                "--build-output-dir", str(root / "build"),
                "--error-solutions-dir", str(root / "solutions"),
                "--application-results-dir", str(root / "results"),
                "--worktrees-dir", str(root / "worktrees"),
                "--pull-requests-dir", str(root / "prs"),
                "--issues-dir", str(root / "issues"),
                "--previews-dir", str(root / "previews"),
                "--start-from", "validation", "--skip", "prs", "--skip", "fix_prs",
                *extra_args,
            ]
            with patch.dict("os.environ", environment or {}, clear=False) as env:
                if environment is None:
                    env.pop("TCC_LEARNING_DIR", None)
                with patch.object(sys, "argv", argv), \
                     patch.object(MODULE, "run_with_deadline", fake_run), \
                     patch("cognalys.utils.repository_lock.RepositoryUsageLock",
                           _no_repository_lock):
                    exit_code = MODULE.main()
                self.after_run = env.get("TCC_LEARNING_DIR")
            try:
                inputs = json.loads((root / MODULE.RUN_INPUTS_FILE).read_text(encoding="utf-8"))
            except OSError:
                inputs = {}
            return exit_code, seen, inputs

    def test_the_environment_is_restored_when_the_run_ends(self):
        """Review of 2026-11-10: a second run in the same process (api.run) read
        and wrote the first run's store through the exported variable."""
        with tempfile.TemporaryDirectory() as store:
            _, seen, _ = self._run(["--learning-dir", store],
                                   environment={"TCC_LEARNING_DIR": "/before/store"})
            self.assertEqual(set(seen), {str(Path(store).resolve())})
            self.assertEqual(self.after_run, "/before/store")
            self._run(["--learning-dir", store])
        self.assertIsNone(self.after_run)

    def test_the_steps_read_the_learning_store_the_run_writes(self):
        with tempfile.TemporaryDirectory() as store:
            exit_code, seen, _ = self._run(["--learning-dir", store])
        self.assertEqual(exit_code, 0)
        self.assertTrue(seen)
        self.assertEqual(set(seen), {str(Path(store).resolve())})

    def test_without_the_option_the_environment_then_the_default_is_used(self):
        root = Path("/workspace")
        with patch.dict("os.environ", {"TCC_LEARNING_DIR": "/elsewhere/store"}):
            self.assertEqual(MODULE.resolved_learning_dir(argparse.Namespace(learning_dir=None), root),
                             Path("/elsewhere/store").resolve())
            self.assertEqual(
                MODULE.resolved_learning_dir(argparse.Namespace(learning_dir="mine"), root),
                (root / "mine").resolve())
        with patch.dict("os.environ", {}, clear=False) as environment:
            environment.pop("TCC_LEARNING_DIR", None)
            self.assertEqual(MODULE.resolved_learning_dir(argparse.Namespace(learning_dir=None), root),
                             (root / "data/pipeline_learning").resolve())
        with patch.object(sys, "argv", ["run_pipeline.py", "--llm-provider", "openai", "--csv-file", "x.csv"]):
            self.assertIsNone(MODULE.parse_args().learning_dir)

    def test_run_inputs_record_the_learning_store_and_history_rules(self):
        from cognalys.learning.knowledge import HISTORY_RULES_VERSION

        with tempfile.TemporaryDirectory() as store:
            _, _, inputs = self._run(["--learning-dir", store])
        self.assertEqual(inputs["learning_dir"], str(Path(store).resolve()))
        self.assertEqual(inputs["learning_history_rules_version"], HISTORY_RULES_VERSION)


class ContactIssueTitleWiringTests(unittest.TestCase):
    def test_the_neutral_contact_title_is_passed_to_previews_and_issues(self):
        neutral = "Question about {api} in {location}?"
        for step in ("preview", "issues"):
            command = MODULE.command_for_step(
                step, _args(issue_title_without_security_impact=neutral), _paths())
            option = command.index("--issue-title-without-security-impact")
            self.assertEqual(command[option + 1], neutral)
        with patch.object(sys, "argv", ["run_pipeline.py", "--llm-provider", "openai", "--csv-file", "x.csv"]):
            default = MODULE.parse_args().issue_title_without_security_impact
        self.assertIn("{api}", default)
        self.assertIn("{location}", default)


if __name__ == "__main__":
    unittest.main()
