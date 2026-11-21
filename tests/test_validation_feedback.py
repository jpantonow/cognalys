import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (scripts/ and src/ on sys.path)


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "cognalys" / "validation" / "applied_solutions.py"
SPEC = importlib.util.spec_from_file_location("validation.applied_solutions", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ValidationFeedbackTests(unittest.TestCase):
    def test_diagnostic_signature_ignores_worktree_prefix(self):
        first = {
            "path": "/worktrees/revision/app/src/androidTest/ClientTest.java",
            "message": "cannot find symbol",
            "source_line": "client = Client.create(null);",
        }
        baseline = {
            "path": "/clones/project/app/src/androidTest/ClientTest.java",
            "message": "cannot find symbol",
            "source_line": "client = Client.create(null);",
        }
        self.assertEqual(
            MODULE.diagnostic_signature(first),
            MODULE.diagnostic_signature(baseline),
        )

    def test_attributes_unchanged_broken_test_line_to_preexisting_code(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text(
                "/repo/app/src/androidTest/ClientTest.java:54: error: cannot find symbol\n"
                "        client = Client.create(null);\n",
                encoding="utf-8",
            )
            diagnostics = MODULE.compiler_diagnostics(log, [{
                "corrected_code": "assertTrue(filterProtocols());"
            }])
            self.assertEqual(
                diagnostics[0]["attribution"],
                "preexisting_code_outside_generated_edits",
            )

    def test_attributes_generated_failing_line_to_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text(
                "/repo/app/src/test/ClientTest.java:20: error: cannot find symbol\n"
                "        assertTrue(filterProtocols());\n",
                encoding="utf-8",
            )
            diagnostics = MODULE.compiler_diagnostics(log, [{
                "corrected_code": "assertTrue(filterProtocols());"
            }])
            self.assertEqual(
                diagnostics[0]["attribution"], "generated_or_replaced_code"
            )

    def test_parses_kotlinc_diagnostic_with_no_source_excerpt_in_log(self):
        # kotlinc's `e: file://<path>:<line>:<col> <message>` diagnostics are
        # not followed by a source excerpt in the Gradle log (unlike javac),
        # so the offending line must be read from the file itself.
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "HttpClient.kt"
            filler = "\n".join(f"// line {i}" for i in range(1, 286))
            offending = (
                "            sslSocket.enabledProtocols = "
                "filterLegacyTlsProtocols(sslSocket.enabledProtocols)"
            )
            source.write_text(filler + "\n" + offending + "\n", encoding="utf-8")
            log = Path(directory) / "build.log"
            log.write_text(
                "> Task :app:compileDebugKotlin\n"
                f"e: file://{source.as_posix()}:286:42 "
                "Unresolved reference: filterLegacyTlsProtocols\n"
                "\n> Task :app:compileDebugKotlin FAILED\n",
                encoding="utf-8",
            )
            diagnostics = MODULE.compiler_diagnostics(log, [{
                "corrected_code": offending.strip()
            }])
            self.assertEqual(len(diagnostics), 1)
            item = diagnostics[0]
            self.assertEqual(item["line"], 286)
            self.assertEqual(
                item["message"], "Unresolved reference: filterLegacyTlsProtocols"
            )
            self.assertTrue(item["path"].endswith("HttpClient.kt"))
            self.assertEqual(item["attribution"], "generated_or_replaced_code")

    def test_kotlinc_diagnostic_without_matching_edit_is_preexisting(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Other.kt"
            source.write_text("class Other {\n    val x = 1\n}\n", encoding="utf-8")
            log = Path(directory) / "build.log"
            log.write_text(
                f"e: file://{source.as_posix()}:2:5 Unresolved reference: y\n",
                encoding="utf-8",
            )
            diagnostics = MODULE.compiler_diagnostics(log, [{
                "corrected_code": "val z = 2"
            }])
            self.assertEqual(len(diagnostics), 1)
            self.assertEqual(
                diagnostics[0]["attribution"],
                "preexisting_code_outside_generated_edits",
            )


class BaselineBuildCacheTests(unittest.TestCase):
    def _fake_run_build_phase(self, calls, status="success"):
        def fake(args, project, output_dir, tasks=None, clean_first=False,
                 keep_going=False):
            calls.append(project)
            output_dir.mkdir(parents=True, exist_ok=True)
            report = [{
                "project_name": project.name, "status": status, "log_file": "",
            }]
            (output_dir / "build_report.json").write_text(json.dumps(report))
            return dict(report[0])
        return fake

    def test_cache_key_is_stable_regardless_of_task_order(self):
        first = MODULE.baseline_cache_key(Path("/repo"), "abc", ["b", "a"])
        second = MODULE.baseline_cache_key(Path("/repo"), "abc", ["a", "b"])
        self.assertEqual(first, second)

    def test_cache_key_differs_for_a_different_commit(self):
        first = MODULE.baseline_cache_key(Path("/repo"), "abc", ["a"])
        second = MODULE.baseline_cache_key(Path("/repo"), "def", ["a"])
        self.assertNotEqual(first, second)

    def test_second_call_reuses_the_cached_successful_build(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_dir = Path(directory) / "cache"
            repo = Path(directory) / "repo"
            repo.mkdir()
            calls: list[Path] = []
            with patch.object(
                MODULE, "run_build_phase",
                self._fake_run_build_phase(calls, "success"),
            ):
                _, first_from_cache = MODULE.run_baseline_build(
                    None, repo, "abc123", ["assembleDebugAndroidTest"], cache_dir,
                )
                _, second_from_cache = MODULE.run_baseline_build(
                    None, repo, "abc123", ["assembleDebugAndroidTest"], cache_dir,
                )
            self.assertFalse(first_from_cache)
            self.assertTrue(second_from_cache)
            self.assertEqual(len(calls), 1)

    def test_infrastructure_failures_are_never_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_dir = Path(directory) / "cache"
            repo = Path(directory) / "repo"
            repo.mkdir()
            calls: list[Path] = []
            with patch.object(
                MODULE, "run_build_phase",
                self._fake_run_build_phase(calls, "infrastructure_failure"),
            ):
                MODULE.run_baseline_build(None, repo, "abc123", ["t"], cache_dir)
                _, from_cache = MODULE.run_baseline_build(
                    None, repo, "abc123", ["t"], cache_dir
                )
            self.assertFalse(from_cache)
            self.assertEqual(len(calls), 2)

    def test_result_merged_with_from_cache_flag_stays_a_plain_dict(self):
        # Regression guard: `phases["baseline_tests_from_cache"] = from_cache`
        # once put a bare bool as a sibling value in the `phases` dict that
        # main() iterates with `phase.get("status")`, crashing with
        # `AttributeError: 'bool' object has no attribute 'get'`. The flag
        # must be merged into the baseline result dict instead.
        with tempfile.TemporaryDirectory() as directory:
            cache_dir = Path(directory) / "cache"
            repo = Path(directory) / "repo"
            repo.mkdir()
            with patch.object(
                MODULE, "run_build_phase",
                self._fake_run_build_phase([], "failed"),
            ):
                baseline, from_cache = MODULE.run_baseline_build(
                    None, repo, "abc123", ["t"], cache_dir
                )
            merged = dict(baseline, from_cache=from_cache)
            phases = {"production": {"status": "success"}, "baseline_tests": merged}
            self.assertFalse(any(
                phase.get("status") == "infrastructure_failure"
                for phase in phases.values()
            ))
            self.assertEqual(merged.get("status"), "failed")

    def test_different_task_sets_get_different_cache_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            cache_dir = Path(directory) / "cache"
            repo = Path(directory) / "repo"
            repo.mkdir()
            calls: list[Path] = []
            with patch.object(
                MODULE, "run_build_phase",
                self._fake_run_build_phase(calls, "success"),
            ):
                MODULE.run_baseline_build(None, repo, "abc123", ["taskA"], cache_dir)
                _, from_cache = MODULE.run_baseline_build(
                    None, repo, "abc123", ["taskB"], cache_dir
                )
            self.assertFalse(from_cache)
            self.assertEqual(len(calls), 2)


class IncrementalRevalidationTests(unittest.TestCase):
    """A repaired worktree is rebuilt from what its failed build left behind."""

    def report(self, directory: Path, status: str, project_dir: str) -> Path:
        output = directory / "production"
        output.mkdir()
        (output / "build_report.json").write_text(
            json.dumps([{"status": status, "project_dir": project_dir}]),
            encoding="utf-8",
        )
        return output

    def test_a_failed_compile_in_this_worktree_is_rebuilt_incrementally(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self.report(Path(directory), "failed", "/w/finding/rev")
            self.assertTrue(MODULE.previous_build_failed_in_place(output, Path("/w/finding/rev")))

    def test_a_success_another_worktree_or_no_report_keeps_the_clean_build(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.assertFalse(MODULE.previous_build_failed_in_place(base / "none", Path("/w/x")))
            success = self.report(base, "success", "/w/finding/rev")
            self.assertFalse(MODULE.previous_build_failed_in_place(success, Path("/w/finding/rev")))
        with tempfile.TemporaryDirectory() as directory:
            other = self.report(Path(directory), "failed", "/w/finding/other")
            self.assertFalse(MODULE.previous_build_failed_in_place(other, Path("/w/finding/rev")))


class TestOnlyRepairTests(unittest.TestCase):
    """The last run rebuilt a passing production build for a repaired test file."""

    def repair(self, path: str) -> dict:
        return {"edit_kind": "validation_repair", "source_file": path}

    def test_only_test_source_sets_count_as_test_only(self):
        self.assertTrue(MODULE.is_test_source("app/src/androidTest/java/A.kt"))
        self.assertTrue(MODULE.is_test_source("src/test/java/A.kt"))
        self.assertFalse(MODULE.is_test_source("app/src/main/java/A.kt"))
        self.assertFalse(MODULE.is_test_source("app/src/testFixtures/A.kt"))

    def test_a_repair_that_touched_production_or_nothing_is_not_test_only(self):
        self.assertTrue(MODULE.repair_touched_only_tests(
            [self.repair("app/src/androidTest/A.kt"), {"edit_kind": "method", "source_file": "x/main/B.kt"}]))
        self.assertFalse(MODULE.repair_touched_only_tests(
            [self.repair("app/src/androidTest/A.kt"), self.repair("app/src/main/B.kt")]))
        self.assertFalse(MODULE.repair_touched_only_tests([{"edit_kind": "method", "source_file": "a/src/test/A.kt"}]))
        self.assertFalse(MODULE.repair_touched_only_tests([]))

    def test_a_previous_success_in_this_worktree_is_found(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "production"
            output.mkdir()
            (output / "build_report.json").write_text(
                json.dumps([{"status": "success", "project_dir": "/w/f/r"}]), encoding="utf-8")
            self.assertTrue(MODULE.previous_build_succeeded_in_place(output, Path("/w/f/r")))
            self.assertFalse(MODULE.previous_build_succeeded_in_place(output, Path("/w/f/other")))
            self.assertFalse(MODULE.previous_build_succeeded_in_place(base / "none", Path("/w/f/r")))

    def test_repaired_findings_are_read_from_the_fix_records(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "a_validation_fix.json").write_text(
                json.dumps({"finding_id": "a", "status": "success"}), encoding="utf-8")
            (base / "b_validation_fix.json").write_text(
                json.dumps({"finding_id": "b", "status": "failed"}), encoding="utf-8")
            (base / "broken_validation_fix.json").write_text("{", encoding="utf-8")
            self.assertEqual(MODULE.repaired_finding_ids(base), {"a"})
            self.assertEqual(MODULE.repaired_finding_ids(base / "missing"), set())
            self.assertEqual(MODULE.repaired_finding_ids(None), set())


class CallerOfChangedSymbolTests(unittest.TestCase):
    """hfut-schedule: the patch removed a default; the caller it did not write broke."""

    EDITS = [{
        "source_file": "network/GiteeService.kt", "symbol": "GiteeService.getUpdate",
        "edit_kind": "method",
        "original_code": "    fun getUpdate(@Query(\"t\") token : String = Constant.TOKEN) : Call<R>\n",
        "corrected_code": "    fun getUpdate(@Query(\"t\") token : String) : Call<R>\n",
    }]

    def diagnostics(self, source_line: str):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "GithubRepository.kt"
            source.write_text("class A {\n" + source_line + "\n}\n", encoding="utf-8")
            log = Path(directory) / "build.log"
            log.write_text(
                f"e: file://{source}:2:36 No value passed for parameter 'token'.\n",
                encoding="utf-8",
            )
            return MODULE.compiler_diagnostics(log, self.EDITS)

    def test_a_caller_of_the_changed_function_is_blamed_on_the_patch(self):
        [item] = self.diagnostics("        request = { gitee.getUpdate() },")
        self.assertEqual(item["attribution"], "caller_of_changed_symbol")
        self.assertIn("caller_of_changed_symbol", MODULE.PATCH_CAUSED_ATTRIBUTIONS)

    def test_an_unrelated_broken_line_is_still_preexisting(self):
        [item] = self.diagnostics("        request = { gitee.download(name) },")
        self.assertEqual(item["attribution"], "preexisting_code_outside_generated_edits")

    def test_a_longer_identifier_is_not_a_match(self):
        [item] = self.diagnostics("        request = { gitee.getUpdateContents() },")
        self.assertEqual(item["attribution"], "preexisting_code_outside_generated_edits")


def _git(repo: Path, *arguments: str) -> str:
    import subprocess

    return subprocess.run(["git", "-C", str(repo), *arguments],
                          check=True, capture_output=True, text=True).stdout.strip()


class TestBuildFailingOnBaseTests(unittest.TestCase):
    """A test build that fails before any test compiles, with and without the patch.

    KeyPass's :common:assembleDebugAndroidTest failed at
    checkDebugAndroidTestAarMetadata on both sides (rvsec_keypass_20261025);
    no diagnostic meant no attribution, and a production fix that built was
    blocked by a test that never compiled.
    """

    PRODUCTION = "common/src/main/java/app/CryptoManager.kt"
    EXISTING_TEST = "common/src/androidTest/java/app/SharedPreferenceUtilsTest.kt"
    CREATED_TEST = "common/src/androidTest/java/app/CryptoManagerMigrationTest.kt"
    FAILURE = (
        "> Task :common:checkDebugAndroidTestAarMetadata FAILED\n"
        "Execution failed for task ':common:checkDebugAndroidTestAarMetadata'.\n"
    )

    def _fixture(self, directory: str, commit_created_test: bool = False):
        root = Path(directory)
        base = root / "base"
        base.mkdir()
        _git(base, "init", "-q")
        _git(base, "config", "user.email", "t@example.com")
        _git(base, "config", "user.name", "Test")
        for path, text in ((self.PRODUCTION, "class CryptoManager\n"),
                           (self.EXISTING_TEST, "class SharedPreferenceUtilsTest\n"),
                           ("settings.gradle", "include ':common'\n")):
            (base / path).parent.mkdir(parents=True, exist_ok=True)
            (base / path).write_text(text, encoding="utf-8")
        _git(base, "add", "-A")
        _git(base, "commit", "-q", "-m", "base")
        commit = _git(base, "rev-parse", "HEAD")
        worktree = root / "worktree"
        _git(root, "clone", "-q", str(base), str(worktree))
        _git(worktree, "config", "user.email", "t@example.com")
        _git(worktree, "config", "user.name", "Test")
        (worktree / self.PRODUCTION).write_text("class CryptoManager { }\n", encoding="utf-8")
        (worktree / self.CREATED_TEST).write_text("class CryptoManagerMigrationTest\n",
                                                  encoding="utf-8")
        if commit_created_test:
            _git(worktree, "add", "-A")
            _git(worktree, "commit", "-q", "-m", "patch")
        patched_log = root / "patched.log"
        patched_log.write_text(self.FAILURE, encoding="utf-8")
        baseline_log = root / "baseline.log"
        baseline_log.write_text(self.FAILURE, encoding="utf-8")
        return root, base, commit, worktree, patched_log, baseline_log

    def _settle(self, worktree, base, commit, patched_log, baseline_log,
                edited_tests, baseline_status="failed"):
        solution = {
            "finding_id": "f405", "source_file": self.PRODUCTION,
            "coordinated_edits": [{"source_file": self.PRODUCTION},
                                  *({"source_file": path, "edit_kind": "test"}
                                    for path in edited_tests)],
            "changed_files": [self.PRODUCTION, *edited_tests],
            "required_tests": ["legacy ciphertext still decrypts"],
        }
        production = {"status": "success", "task": "assembleDebug",
                      "log_file": "production.log", "apk_count": 2}
        patched = {"status": "failed", "task": ":common:assembleDebugAndroidTest",
                   "log_file": str(patched_log)}
        baseline = {"status": baseline_status, "log_file": str(baseline_log)}
        settled = MODULE.settle_test_build_failing_on_base(
            solution, worktree, worktree, production, patched, baseline,
            base, commit, list(edited_tests), dry_run=False,
        )
        return settled, solution

    def test_a_created_test_is_dropped_and_the_production_build_stands(self):
        with tempfile.TemporaryDirectory() as directory:
            _, base, commit, worktree, patched_log, baseline_log = self._fixture(directory)
            settled, solution = self._settle(
                worktree, base, commit, patched_log, baseline_log, [self.CREATED_TEST],
            )
            self.assertEqual(settled["status"], MODULE.PRODUCTION_ONLY_TEST_BUILD_PREEXISTING)
            self.assertIn(settled["status"], MODULE.PASSING_STATUSES)
            self.assertEqual(settled["failure_attribution"], "verified_preexisting_test_debt")
            # What the record names as built is the production build.
            self.assertEqual((settled["task"], settled["apk_count"]), ("assembleDebug", 2))
            self.assertEqual(settled["failed_test_tasks"],
                             [":common:checkDebugAndroidTestAarMetadata"])
            self.assertFalse((worktree / self.CREATED_TEST).exists())
            self.assertTrue((worktree / self.PRODUCTION).is_file())
            # The PR text reads its tests from coordinated_edits.
            self.assertEqual([item["source_file"] for item in solution["coordinated_edits"]],
                             [self.PRODUCTION])
            self.assertEqual(solution["changed_files"], [self.PRODUCTION])
            self.assertEqual(solution["required_tests"], [])
            self.assertEqual(solution["removed_generated_tests"], [self.CREATED_TEST])
            self.assertTrue(solution["manual_review_required"])
            # The summary was written with the test among the edits.
            self.assertIs(solution["summary_stale"], True)
            note = solution["review_assumptions"][-1]
            self.assertIn("legacy ciphertext still decrypts", note)
            self.assertNotIn("Before merging", note)
            # An untracked test leaves nothing to commit.
            self.assertNotIn("commit_hash", solution)

    def test_a_committed_created_test_is_removed_in_a_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            _, base, commit, worktree, patched_log, baseline_log = self._fixture(
                directory, commit_created_test=True)
            before = _git(worktree, "rev-parse", "HEAD")
            settled, solution = self._settle(
                worktree, base, commit, patched_log, baseline_log, [self.CREATED_TEST],
            )
            self.assertEqual(settled["status"], MODULE.PRODUCTION_ONLY_TEST_BUILD_PREEXISTING)
            self.assertNotEqual(solution["commit_hash"], before)
            self.assertEqual(solution["commit_hash"], _git(worktree, "rev-parse", "HEAD"))
            self.assertEqual(_git(worktree, "ls-files", self.CREATED_TEST), "")

    def test_an_edited_existing_test_is_kept_and_the_build_stays_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            _, base, commit, worktree, patched_log, baseline_log = self._fixture(directory)
            settled, solution = self._settle(
                worktree, base, commit, patched_log, baseline_log,
                [self.CREATED_TEST, self.EXISTING_TEST],
            )
            self.assertEqual(settled["status"], "failed")
            self.assertEqual(settled["failure_attribution"], "verified_preexisting_test_debt")
            self.assertEqual(settled["reason"], "test_build_fails_on_base_without_patch")
            self.assertFalse(MODULE.failure_is_the_patch(settled))
            self.assertTrue((worktree / self.CREATED_TEST).is_file())
            self.assertNotIn("removed_generated_tests", solution)

    def test_a_different_failure_on_base_or_a_passing_base_settles_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            _, base, commit, worktree, patched_log, baseline_log = self._fixture(directory)
            baseline_log.write_text(
                "Execution failed for task ':common:mergeDebugAndroidTestResources'.\n",
                encoding="utf-8",
            )
            settled, _ = self._settle(
                worktree, base, commit, patched_log, baseline_log, [self.CREATED_TEST],
            )
            self.assertIsNone(settled)
            baseline_log.write_text(self.FAILURE, encoding="utf-8")
            settled, _ = self._settle(
                worktree, base, commit, patched_log, baseline_log, [self.CREATED_TEST],
                baseline_status="success",
            )
            self.assertIsNone(settled)
            self.assertTrue((worktree / self.CREATED_TEST).is_file())

    def test_a_test_that_ran_and_failed_is_never_removed(self):
        # The created test throws from a platform frame, so failing_tests
        # parses nothing; the base already had failing tests in that module.
        with tempfile.TemporaryDirectory() as directory:
            _, base, commit, worktree, patched_log, baseline_log = self._fixture(directory)
            ran = (
                "> Task :common:compileDebugAndroidTestKotlin\n"
                "CryptoManagerMigrationTest > decrypts FAILED\n"
                "    javax.crypto.AEADBadTagException at CipherCore.java:1\n"
                "> Task :common:testDebugUnitTest FAILED\n"
                "Execution failed for task ':common:testDebugUnitTest'.\n"
                "> There were failing tests. See the report.\n"
            )
            patched_log.write_text(ran, encoding="utf-8")
            baseline_log.write_text(ran, encoding="utf-8")
            settled, solution = self._settle(
                worktree, base, commit, patched_log, baseline_log, [self.CREATED_TEST],
            )
            self.assertIsNone(settled)
            self.assertTrue((worktree / self.CREATED_TEST).is_file())
            self.assertNotIn("removed_generated_tests", solution)
            # The failed task alone is enough, whatever the log says around it.
            only_task = ("Execution failed for task ':common:connectedDebugAndroidTest'.\n")
            patched_log.write_text(only_task, encoding="utf-8")
            baseline_log.write_text(only_task, encoding="utf-8")
            settled, _ = self._settle(
                worktree, base, commit, patched_log, baseline_log, [self.CREATED_TEST],
            )
            self.assertIsNone(settled)

    def test_a_created_test_whose_compile_task_never_ran_is_removed_too(self):
        # Under --continue a test task that depends on the failed module is
        # skipped silently, so a module with no failed task proves nothing.
        with tempfile.TemporaryDirectory() as directory:
            _, base, commit, worktree, patched_log, baseline_log = self._fixture(directory)
            app_test = "app/src/test/java/app/AppTest.kt"
            (worktree / app_test).parent.mkdir(parents=True)
            (worktree / app_test).write_text("class AppTest\n", encoding="utf-8")
            settled, solution = self._settle(
                worktree, base, commit, patched_log, baseline_log,
                [self.CREATED_TEST, app_test],
            )
            self.assertEqual(settled["status"], MODULE.PRODUCTION_ONLY_TEST_BUILD_PREEXISTING)
            self.assertFalse((worktree / app_test).exists())
            self.assertEqual(solution["removed_generated_tests"],
                             sorted([self.CREATED_TEST, app_test]))
            self.assertEqual(solution["required_tests"], [])

    @staticmethod
    def _refused_task_log(checkout: str) -> str:
        # NotallyX run_v4: Gradle refused the task during validation, so
        # there is no "Execution failed for task" line.
        return (
            "> Task :common:installLocalGitHooks FAILED\n\n"
            "FAILURE: Build failed with an exception.\n\n"
            "* What went wrong:\n"
            "Some problems were found with the configuration of task "
            "':common:installLocalGitHooks' (type 'Copy').\n"
            f"  property 'destinationDir' is not writable because '{checkout}/.git/hooks'"
            f" ancestor '{checkout}/.git' is not a directory\n\n"
            "* Try:\n> Run with --scan.\n\nBUILD FAILED in 12s\n"
        )

    def test_a_task_refused_before_it_ran_settles_like_a_failed_one(self):
        with tempfile.TemporaryDirectory() as directory:
            _, base, commit, worktree, patched_log, baseline_log = self._fixture(directory)
            patched_log.write_text(self._refused_task_log(str(worktree)), encoding="utf-8")
            baseline_log.write_text(self._refused_task_log("/elsewhere/baseline_b45b"),
                                    encoding="utf-8")
            self.assertEqual(MODULE.failed_task_paths(patched_log),
                             {":common:installLocalGitHooks"})
            settled, solution = self._settle(
                worktree, base, commit, patched_log, baseline_log, [self.CREATED_TEST],
            )
            self.assertEqual(settled["status"], MODULE.PRODUCTION_ONLY_TEST_BUILD_PREEXISTING)
            self.assertEqual(settled["failed_test_tasks"], [":common:installLocalGitHooks"])
            self.assertEqual(solution["removed_generated_tests"], [self.CREATED_TEST])

    def _settle_without_task(self, worktree, base, commit, patched_log, baseline_log,
                             baseline_checkout):
        solution = {"finding_id": "f405", "source_file": self.PRODUCTION,
                    "coordinated_edits": [{"source_file": self.PRODUCTION},
                                          {"source_file": self.CREATED_TEST}],
                    "changed_files": [self.PRODUCTION, self.CREATED_TEST]}
        production = {"status": "success", "task": "assembleDebug", "apk_count": 1}
        patched = {"status": "failed", "log_file": str(patched_log),
                   "project_dir": str(worktree)}
        baseline = {"status": "failed", "log_file": str(baseline_log),
                    "project_dir": baseline_checkout}
        return MODULE.settle_test_build_failing_on_base(
            solution, worktree, worktree, production, patched, baseline,
            base, commit, [self.CREATED_TEST], dry_run=False,
        )

    def test_a_failure_naming_no_task_settles_when_the_base_reports_the_same(self):
        def log(checkout, name):
            return ("FAILURE: Build failed with an exception.\n\n* What went wrong:\n"
                    "A problem occurred configuring project ':common'.\n"
                    f"> Could not read file '{checkout}/common/{name}'\n\n"
                    "* Try:\n> Run with --stacktrace.\n\nBUILD FAILED in 3s\n")

        with tempfile.TemporaryDirectory() as directory:
            _, base, commit, worktree, patched_log, baseline_log = self._fixture(directory)
            patched_log.write_text(log(worktree, "version.txt"), encoding="utf-8")
            baseline_log.write_text(log("/cache/baseline_1", "other.txt"), encoding="utf-8")
            self.assertIsNone(self._settle_without_task(
                worktree, base, commit, patched_log, baseline_log, "/cache/baseline_1"))
            self.assertTrue((worktree / self.CREATED_TEST).is_file())

            baseline_log.write_text(log("/cache/baseline_1", "version.txt"), encoding="utf-8")
            settled = self._settle_without_task(
                worktree, base, commit, patched_log, baseline_log, "/cache/baseline_1")
            self.assertEqual(settled["status"], MODULE.PRODUCTION_ONLY_TEST_BUILD_PREEXISTING)
            self.assertEqual(settled["failed_test_tasks"], [])
            self.assertEqual(len(settled["failure_reports_shared_with_base"]), 1)
            self.assertIn("<checkout>/common/version.txt",
                          settled["failure_reports_shared_with_base"][0])
            self.assertFalse((worktree / self.CREATED_TEST).exists())

    def test_a_test_in_a_module_whose_build_did_not_fail_is_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            _, base, commit, worktree, patched_log, baseline_log = self._fixture(directory)
            app_test = "app/src/test/java/app/AppTest.kt"
            (worktree / app_test).parent.mkdir(parents=True)
            (worktree / app_test).write_text("class AppTest\n", encoding="utf-8")
            patched_log.write_text(
                "> Task :app:compileDebugUnitTestKotlin\n" + self.FAILURE, encoding="utf-8",
            )
            settled, solution = self._settle(
                worktree, base, commit, patched_log, baseline_log,
                [self.CREATED_TEST, app_test],
            )
            self.assertEqual(settled["status"], MODULE.PRODUCTION_ONLY_TEST_BUILD_PREEXISTING)
            self.assertFalse((worktree / self.CREATED_TEST).exists())
            self.assertTrue((worktree / app_test).is_file())
            self.assertIn(app_test, [item["source_file"]
                                     for item in solution["coordinated_edits"]])
            # A test of the patch is left, so its required tests stay.
            self.assertEqual(solution["required_tests"], ["legacy ciphertext still decrypts"])

    def test_main_records_the_production_only_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root, base, commit, worktree, patched_log, baseline_log = self._fixture(directory)
            solution = {
                "status": "SUCCESS", "finding_id": "f405", "apk_name": "keypass.apk",
                "worktree_path": str(worktree), "source_file": self.PRODUCTION,
                "base_repository_path": str(base), "base_commit": commit,
                "coordinated_edits": [{"source_file": self.PRODUCTION},
                                      {"source_file": self.CREATED_TEST, "edit_kind": "test"}],
            }
            report = root / "execution_report.json"
            report.write_text(json.dumps({"per_solution_details": [solution]}), encoding="utf-8")
            output = root / "build_validation"
            calls = []

            def fake_build(args, project, output_dir, tasks=None, clean_first=False,
                           keep_going=False):
                calls.append(tasks)
                if tasks and any("AndroidTest" in task for task in tasks):
                    return {"status": "failed", "task": tasks[0], "log_file": str(patched_log)}
                return {"status": "success", "task": "assembleDebug", "log_file": "",
                        "project_dir": str(project)}

            argv = ["x", "--build-script", "b.py", "--projects-dir", str(root),
                    "--output-dir", str(output), "--execution-report", str(report)]
            with patch.object(sys, "argv", argv), \
                    patch.object(MODULE, "run_build_phase", fake_build), \
                    patch.object(MODULE, "build_reads_git_directory", return_value=[]), \
                    patch.object(MODULE, "production_modules_for", return_value=set()), \
                    patch.object(MODULE, "rescue_unrelated_module_failure", return_value=None), \
                    patch.object(MODULE, "replay_source_detector", return_value={}), \
                    patch.object(MODULE, "checkout_matches_base", return_value=True), \
                    patch.object(MODULE, "run_baseline_build", return_value=(
                        {"status": "failed", "log_file": str(baseline_log)}, False)):
                MODULE.main()
            self.assertIn([":common:assembleDebugAndroidTest"], calls)
            written = json.loads(report.read_text(encoding="utf-8"))["per_solution_details"][0]
            self.assertEqual(written["build_validation"]["status"],
                             MODULE.PRODUCTION_ONLY_TEST_BUILD_PREEXISTING)
            self.assertEqual(written["build_validation"]["task"], "assembleDebug")
            self.assertEqual(written["removed_generated_tests"], [self.CREATED_TEST])
            # Later stages read these from the record, not the build report.
            self.assertEqual(written["build_validation"]["failed_test_tasks"],
                             [":common:checkDebugAndroidTestAarMetadata"])
            self.assertEqual(written["build_validation"]["removed_generated_tests"],
                             [self.CREATED_TEST])
            feedback = json.loads(
                (output / "f405" / "validation_feedback.json").read_text(encoding="utf-8"))
            self.assertEqual(feedback["regeneration_guidance"], "")


class TestsOutsideGradleRootTests(unittest.TestCase):
    """A patch test in a directory the Gradle root does not contain.

    No task can name it, so it was never compiled; it must not ship under
    the production build's plain success.
    """

    PRODUCTION = "android/app/src/main/java/app/Crypto.java"
    CREATED_TEST = "src/test/java/app/CryptoTest.java"
    EXISTING_TEST = "src/test/java/app/OldTest.java"

    def _fixture(self, directory: str, settings: str = "include ':app'\n"):
        root = Path(directory)
        base = root / "base"
        base.mkdir()
        _git(base, "init", "-q")
        _git(base, "config", "user.email", "t@example.com")
        _git(base, "config", "user.name", "Test")
        for path, text in ((self.PRODUCTION, "class Crypto {}\n"),
                           (self.EXISTING_TEST, "class OldTest {}\n"),
                           ("android/settings.gradle", settings)):
            (base / path).parent.mkdir(parents=True, exist_ok=True)
            (base / path).write_text(text, encoding="utf-8")
        _git(base, "add", "-A")
        _git(base, "commit", "-q", "-m", "base")
        commit = _git(base, "rev-parse", "HEAD")
        worktree = root / "worktree"
        _git(root, "clone", "-q", str(base), str(worktree))
        (worktree / self.PRODUCTION).write_text("class Crypto { }\n", encoding="utf-8")
        (worktree / self.CREATED_TEST).write_text("class CryptoTest {}\n", encoding="utf-8")
        return root, base, commit, worktree

    def _main(self, root, base, commit, worktree, tests):
        solution = {
            "status": "SUCCESS", "finding_id": "bwt1", "apk_name": "bwt.apk",
            "worktree_path": str(worktree), "source_file": self.PRODUCTION,
            "base_repository_path": str(base), "base_commit": commit,
            "coordinated_edits": [{"source_file": self.PRODUCTION},
                                  *({"source_file": path, "edit_kind": "test"}
                                    for path in tests)],
        }
        report = root / "execution_report.json"
        report.write_text(json.dumps({"per_solution_details": [solution]}), encoding="utf-8")
        calls = []

        def fake_build(args, project, output_dir, tasks=None, clean_first=False,
                       keep_going=False):
            calls.append(tasks)
            return {"status": "success", "task": "assembleDebug", "log_file": "",
                    "project_dir": str(project)}

        argv = ["x", "--build-script", "b.py", "--projects-dir", str(root),
                "--output-dir", str(root / "build_validation"),
                "--execution-report", str(report)]
        with patch.object(sys, "argv", argv), \
                patch.object(MODULE, "run_build_phase", fake_build), \
                patch.object(MODULE, "build_reads_git_directory", return_value=[]), \
                patch.object(MODULE, "production_modules_for", return_value=set()), \
                patch.object(MODULE, "rescue_unrelated_module_failure", return_value=None), \
                patch.object(MODULE, "replay_source_detector", return_value={}):
            MODULE.main()
        written = json.loads(report.read_text(encoding="utf-8"))["per_solution_details"][0]
        return written, calls

    def test_a_created_test_outside_the_root_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root, base, commit, worktree = self._fixture(directory)
            written, calls = self._main(root, base, commit, worktree, [self.CREATED_TEST])
            # No test task was requested for a module no build contains.
            self.assertTrue(all(not any("Test" in task for task in tasks or [])
                                for tasks in calls))
            self.assertEqual(written["build_validation"]["status"], "success")
            self.assertFalse((worktree / self.CREATED_TEST).exists())
            self.assertEqual(written["removed_generated_tests"], [self.CREATED_TEST])
            self.assertEqual([item["source_file"] for item in written["coordinated_edits"]],
                             [self.PRODUCTION])
            # The PR step rewrites the summary without the removed test.
            self.assertIs(written["summary_stale"], True)
            self.assertEqual(written["build_validation"]["test_modules_outside_gradle_root"],
                             [""])

    def test_an_existing_test_outside_the_root_keeps_the_build_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            root, base, commit, worktree = self._fixture(directory)
            written, _ = self._main(root, base, commit, worktree,
                                    [self.CREATED_TEST, self.EXISTING_TEST])
            validation = written["build_validation"]
            self.assertNotIn(validation["status"], MODULE.PASSING_STATUSES)
            self.assertEqual(validation["reason"], "validation_test_module_outside_gradle_root")
            self.assertEqual(validation["failure_attribution"], "validation_task_unresolved")
            self.assertTrue((worktree / self.CREATED_TEST).is_file())
            self.assertNotIn("removed_generated_tests", written)

    def test_a_settings_file_that_relocates_projects_removes_nothing(self):
        # projectDir can put a project outside the root, so the test may be compiled.
        with tempfile.TemporaryDirectory() as directory:
            root, base, commit, worktree = self._fixture(
                directory, settings="include ':app', ':core'\n"
                                    "project(':core').projectDir = file('../core')\n")
            written, _ = self._main(root, base, commit, worktree, [self.CREATED_TEST])
            self.assertEqual(written["build_validation"]["status"], "failed")
            self.assertTrue((worktree / self.CREATED_TEST).is_file())


if __name__ == "__main__":
    unittest.main()
