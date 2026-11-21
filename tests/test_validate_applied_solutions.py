import argparse
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

# Imported from the module that owns these names, not from the
# scripts/ entry point that re-exports them: patching a re-exported
# name leaves the code under test reading its own module global.
from cognalys.validation import applied_solutions as vas  # noqa: E402
from cognalys.validation.applied_solutions import (  # noqa: E402
    _declared_product_flavors,
    _flavor_qualified_task,
    _selected_product_flavors,
    build_failure_phase,
    build_reads_git_directory,
    edits_touch_build_files,
    failing_task_module,
)


class KeepGoingBuildPhaseTests(unittest.TestCase):
    """Test builds ask Gradle to continue past the first failing task."""

    def _command(self, **kwargs) -> list:
        args = argparse.Namespace(
            build_script=Path("build.py"), variant="debug", timeout=10,
            dry_run=False,
        )
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(vas.subprocess, "run") as run, \
                patch.object(vas, "_load_build_result",
                             return_value={"status": "success"}):
            run.return_value.returncode = 0
            vas.run_build_phase(
                args, Path(directory) / "project", Path(directory) / "out",
                tasks=[":app:assembleDebugAndroidTest"], **kwargs,
            )
            # The build is one call among the git reads that bracket it.
            return next(call[0][0] for call in run.call_args_list
                        if "--projects-dir" in call[0][0])

    def test_a_keep_going_phase_passes_the_continue_option(self):
        self.assertIn(
            "--continue-after-task-failure", self._command(keep_going=True))

    def test_other_phases_keep_the_default(self):
        self.assertNotIn("--continue-after-task-failure", self._command())


class CreatedFileBaselineTests(unittest.TestCase):
    """A file the patch created cannot carry an error that predates it."""

    def test_files_the_patch_created_are_absent_from_the_base_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "src").mkdir()
            (repo / "src" / "Old.java").write_text("class Old {}\n", encoding="utf-8")
            for argv in (
                ["init", "-q"],
                ["config", "user.email", "test@example.invalid"],
                ["config", "user.name", "Test"],
                ["add", "-A"],
                ["commit", "-q", "-m", "base"],
            ):
                subprocess.run(["git", "-C", str(repo), *argv], check=True,
                               capture_output=True, text=True)
            commit = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()

            self.assertTrue(vas.paths_absent_from_commit(
                repo, commit, ["src/New.java"]))
            self.assertFalse(vas.paths_absent_from_commit(
                repo, commit, ["src/New.java", "src/Old.java"]))
            self.assertFalse(vas.paths_absent_from_commit(repo, commit, []))


class FlavorQualifiedTaskTests(unittest.TestCase):
    def test_flavored_module_qualifies_assemble_and_test_tasks(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "app"
            module.mkdir()
            (module / "build.gradle").write_text(
                "android {\n"
                "  productFlavors {\n"
                "    floss {\n"
                "      dimension \"version\"\n"
                "    }\n"
                "    google {\n"
                "      dimension \"version\"\n"
                "    }\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )

            self.assertEqual(
                _declared_product_flavors(module), ["floss", "google"]
            )
            self.assertEqual(_selected_product_flavors(module), ["floss"])
            self.assertEqual(
                _flavor_qualified_task(module, "assembleDebugAndroidTest"),
                "assembleFlossDebugAndroidTest",
            )
            self.assertEqual(
                _flavor_qualified_task(module, "testDebugUnitTest"),
                "testFlossDebugUnitTest",
            )

    def test_unflavored_module_leaves_task_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "app"
            module.mkdir()
            (module / "build.gradle").write_text(
                "android {\n  compileSdk 34\n}\n", encoding="utf-8",
            )

            self.assertEqual(_declared_product_flavors(module), [])
            self.assertEqual(
                _flavor_qualified_task(module, "assembleDebugAndroidTest"),
                "assembleDebugAndroidTest",
            )

    def test_combines_one_flavor_from_each_dimension_in_declared_order(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "mobile"
            module.mkdir()
            (module / "build.gradle").write_text(
                "android {\n"
                "  flavorDimensions \"license\", \"release\"\n"
                "  productFlavors {\n"
                "    full {\n"
                "      dimension \"license\"\n"
                "      firebaseAppDistribution { artifactType = \"APK\" }\n"
                "    }\n"
                "    foss { dimension \"license\" }\n"
                "    stable { dimension \"release\" }\n"
                "    beta {\n"
                "      dimension \"release\"\n"
                "    }\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )

            self.assertEqual(
                _declared_product_flavors(module),
                ["beta", "foss", "full", "stable"],
            )
            self.assertEqual(
                _selected_product_flavors(module), ["foss", "beta"],
            )
            self.assertEqual(
                _flavor_qualified_task(module, "assembleDebugAndroidTest"),
                "assembleFossBetaDebugAndroidTest",
            )
            self.assertEqual(
                _flavor_qualified_task(module, "testDebugUnitTest"),
                "testFossBetaDebugUnitTest",
            )

    def test_supports_kotlin_dsl_create_flavors(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "app"
            module.mkdir()
            (module / "build.gradle.kts").write_text(
                "android {\n"
                "  flavorDimensions += listOf(\"market\", \"api\")\n"
                "  productFlavors {\n"
                "    create(\"google\") { dimension = \"market\" }\n"
                "    create(\"foss\") { dimension = \"market\" }\n"
                "    create(\"modern\") { dimension = \"api\" }\n"
                "    create(\"legacy\") { dimension = \"api\" }\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )

            self.assertEqual(
                _selected_product_flavors(module), ["foss", "legacy"],
            )
            self.assertEqual(
                _flavor_qualified_task(module, "assembleDebugAndroidTest"),
                "assembleFossLegacyDebugAndroidTest",
            )

    def test_flavors_without_dimension_belong_to_the_only_declared_one(self):
        # NetworkSurvey's layout: one declared dimension, and flavors that
        # name none, which Gradle assigns to it.
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "networksurvey"
            module.mkdir()
            (module / "build.gradle").write_text(
                "android {\n"
                "    flavorDimensions = [\"version\"]\n"
                "    productFlavors {\n"
                "        // Regular is for Google Play\n"
                "        regular {\n"
                "            versionNameSuffix \"\"\n"
                "        }\n"
                "        cdr {\n"
                "            versionNameSuffix \"\"\n"
                "        }\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )

            self.assertEqual(_selected_product_flavors(module), ["cdr"])
            self.assertEqual(
                _flavor_qualified_task(module, "assembleDebugAndroidTest"),
                "assembleCdrDebugAndroidTest",
            )
            self.assertEqual(
                _flavor_qualified_task(module, "testDebugUnitTest"),
                "testCdrDebugUnitTest",
            )

    def test_an_undeclared_dimension_among_several_stays_unqualified(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "app"
            module.mkdir()
            (module / "build.gradle").write_text(
                "android {\n"
                "  flavorDimensions \"license\", \"release\"\n"
                "  productFlavors {\n"
                "    foss { dimension \"license\" }\n"
                "    beta { }\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )

            self.assertEqual(_selected_product_flavors(module), [])

    def test_missing_build_file_leaves_task_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "app"
            module.mkdir()

            self.assertEqual(
                _flavor_qualified_task(module, "testDebugUnitTest"),
                "testDebugUnitTest",
            )


class RescueUnrelatedModuleFailureTests(unittest.TestCase):
    """Regression tests for a real run: com.ivanovsky.passnotes_11700.apk.

    Its assembleDebug fails at ':keepass-rs-android:buildDebugRustJni'
    because the validation machine has no cargo/cargo-ndk/Android NDK --
    a module the patch (in HttpClientFactory.kt, under app/) never
    touched, and the log has no compiler diagnostic anywhere. A scoped
    recompile of just the patched module confirmed it compiles cleanly
    (BUILD SUCCESSFUL for :app:compileAutomationDebugKotlin), so this
    should be reported as "success_app_module_only", not a bare "failed".
    """

    RUST_FAILURE_LOG = (
        "> Task :keepass-rs-android:buildDebugRustJni FAILED\n"
        "Required command is not installed: cargo\n"
        "\n"
        "FAILURE: Build failed with an exception.\n"
        "* What went wrong:\n"
        "Execution failed for task ':keepass-rs-android:buildDebugRustJni'.\n"
        "> Process 'command '.../build-native-libraries.sh'' finished with "
        "non-zero exit value 1\n"
    )

    def _write_log(self, directory: Path, text: str) -> Path:
        log_file = directory / "build.log"
        log_file.write_text(text, encoding="utf-8")
        return log_file

    def test_failing_task_module_is_extracted_from_gradle_log(self):
        with tempfile.TemporaryDirectory() as directory:
            log_file = self._write_log(Path(directory), self.RUST_FAILURE_LOG)
            self.assertEqual(
                failing_task_module(log_file), ":keepass-rs-android"
            )

    def test_failing_task_module_is_none_without_a_task_failure_line(self):
        with tempfile.TemporaryDirectory() as directory:
            log_file = self._write_log(Path(directory), "some unrelated log\n")
            self.assertIsNone(failing_task_module(log_file))

    def test_rescues_when_failure_is_outside_the_patched_module(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            (worktree / "app").mkdir()
            log_file = self._write_log(worktree, self.RUST_FAILURE_LOG)
            production = {"status": "failed", "log_file": str(log_file)}

            with patch.object(
                vas, "run_build_phase"
            ) as mock_build:
                mock_build.return_value = {
                    "status": "success", "task": "compileDebugKotlin",
                    "return_code": 0, "log_file": str(log_file),
                }
                rescue = vas.rescue_unrelated_module_failure(
                    argparse.Namespace(), worktree, worktree / "out",
                    production, {"app"},
                )

            self.assertIsNotNone(rescue)
            self.assertEqual(rescue["status"], "success_app_module_only")
            self.assertEqual(
                rescue["unrelated_module_failure_task"], ":keepass-rs-android"
            )
            mock_build.assert_called_once()
            self.assertEqual(
                mock_build.call_args.kwargs["tasks"],
                [":app:compileDebugSources"],
            )

    def test_a_full_build_that_timed_out_recompiles_the_patched_module(self):
        """MyExpenses' patch changed one class in the PlayLicensingOrig
        library; :myExpenses:assembleExternDebug was still compiling the
        app's Kotlin when the limit ran out, which says nothing about it."""
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            (worktree / "PlayLicensingOrig").mkdir()
            log_file = self._write_log(
                worktree, "> Task :myExpenses:compileExternDebugKotlin\n"
                "Timed out after 1800 seconds.\n",
            )
            production = {"status": "timeout", "log_file": str(log_file)}

            with patch.object(vas, "run_build_phase") as mock_build:
                mock_build.return_value = {
                    "status": "failed", "return_code": 0,
                    "task": ":PlayLicensingOrig:compileDebugSources",
                    "log_file": str(log_file),
                }
                rescue = vas.rescue_unrelated_module_failure(
                    argparse.Namespace(), worktree, worktree / "out",
                    production, {"PlayLicensingOrig"},
                )

            self.assertEqual(rescue["status"], "success_app_module_only")
            self.assertEqual(rescue["reason"],
                             "full_build_timeout_patched_module_recompiled")
            self.assertEqual(mock_build.call_args.kwargs["tasks"],
                             [":PlayLicensingOrig:compileDebugSources"])

    def test_a_single_module_project_is_not_labelled_app_module_only(self):
        """Salty (2026-10-29): :app is the only module, so the recheck compiled
        the whole project; "the changed module builds" misdescribed it."""
        for settings, expected in (
                ('rootProject.name = "Salty"\ninclude(":app")\n', "success_compile_only"),
                ("include ':app', ':lib'\n", "success_app_module_only"),
                ('file("libs").listFiles().forEach { include(":${it.name}") }\n'
                 'include(":app")\n', "success_app_module_only")):
            with tempfile.TemporaryDirectory() as directory:
                worktree = Path(directory)
                (worktree / "app").mkdir()
                (worktree / "settings.gradle.kts").write_text(settings, encoding="utf-8")
                log_file = self._write_log(worktree, "Timed out after 3600 seconds.\n")
                with patch.object(vas, "run_build_phase") as mock_build:
                    mock_build.return_value = {
                        "status": "failed", "return_code": 0,
                        "task": ":app:compileDebugSources", "log_file": str(log_file),
                    }
                    rescue = vas.rescue_unrelated_module_failure(
                        argparse.Namespace(), worktree, worktree / "out",
                        {"status": "timeout", "log_file": str(log_file)}, {"app"},
                    )
            self.assertEqual(rescue["status"], expected, settings)
            self.assertIn(rescue["status"], vas.PASSING_STATUSES)
        # A settings file one level down names its modules from there (BWT).
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            (worktree / "bwt" / "app").mkdir(parents=True)
            (worktree / "bwt" / "settings.gradle").write_text("include ':app'\n")
            self.assertTrue(vas.patched_modules_are_the_whole_project(worktree, {"bwt/app"}))
            self.assertFalse(vas.patched_modules_are_the_whole_project(worktree, set()))

    def test_a_timed_out_build_whose_module_compile_fails_is_not_rescued(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            (worktree / "lib").mkdir()
            log_file = self._write_log(worktree, "Timed out after 1800 seconds.\n")
            with patch.object(vas, "run_build_phase") as mock_build:
                mock_build.return_value = {"status": "failed", "return_code": 1,
                                           "log_file": str(log_file)}
                self.assertIsNone(vas.rescue_unrelated_module_failure(
                    argparse.Namespace(), worktree, worktree / "out",
                    {"status": "timeout", "log_file": str(log_file)}, {"lib"},
                ))

    def test_rescues_even_when_the_scoped_recompile_reports_failed_for_missing_apk(
        self,
    ):
        # The real bug this guards against: run_build_phase shells out to
        # build_apks_no_proguard.py, which is written for assembleDebug-style
        # tasks and marks ANY run with no copied APK as status "failed" --
        # reason "no_apk_found_after_successful_build" -- even when Gradle's
        # own return_code was 0. A plain compileDebugKotlin task never
        # produces an APK, so on a real passnotes run this made the rescue
        # always report None and validation_fix always see "no repairable
        # compiler diagnostics" (correctly -- there wasn't one -- while the
        # finding stayed stuck on a bare "failed").
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            (worktree / "app").mkdir()
            log_file = self._write_log(worktree, self.RUST_FAILURE_LOG)
            production = {"status": "failed", "log_file": str(log_file)}

            with patch.object(
                vas, "run_build_phase"
            ) as mock_build:
                mock_build.return_value = {
                    "status": "failed",
                    "reason": "no_apk_found_after_successful_build",
                    "return_code": 0,
                    "task": "compileDebugKotlin",
                    "log_file": str(log_file),
                }
                rescue = vas.rescue_unrelated_module_failure(
                    argparse.Namespace(), worktree, worktree / "out",
                    production, {"app"},
                )

            self.assertIsNotNone(rescue)
            self.assertEqual(rescue["status"], "success_app_module_only")

    def test_does_not_rescue_a_real_compiler_error(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            (worktree / "app").mkdir()
            log_file = self._write_log(
                worktree,
                "e: file:///app/src/main/kotlin/A.kt:3:1 unresolved reference\n"
                + self.RUST_FAILURE_LOG,
            )
            production = {"status": "failed", "log_file": str(log_file)}

            with patch.object(
                vas, "run_build_phase"
            ) as mock_build:
                rescue = vas.rescue_unrelated_module_failure(
                    argparse.Namespace(), worktree, worktree / "out",
                    production, {"app"},
                )

            self.assertIsNone(rescue)
            mock_build.assert_not_called()

    def test_does_not_rescue_a_failure_inside_the_patched_module(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            (worktree / "app").mkdir()
            log_file = self._write_log(
                worktree,
                "Execution failed for task ':app:someOtherTask'.\n",
            )
            production = {"status": "failed", "log_file": str(log_file)}

            with patch.object(
                vas, "run_build_phase"
            ) as mock_build:
                rescue = vas.rescue_unrelated_module_failure(
                    argparse.Namespace(), worktree, worktree / "out",
                    production, {"app"},
                )

            self.assertIsNone(rescue)
            mock_build.assert_not_called()

    def test_does_not_rescue_a_successful_production_build(self):
        rescue = vas.rescue_unrelated_module_failure(
            argparse.Namespace(), Path("."), Path("out"),
            {"status": "success"}, {"app"},
        )
        self.assertIsNone(rescue)

    def test_scoped_recompile_failing_does_not_count_as_a_rescue(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            (worktree / "app").mkdir()
            log_file = self._write_log(worktree, self.RUST_FAILURE_LOG)
            production = {"status": "failed", "log_file": str(log_file)}

            with patch.object(
                vas, "run_build_phase"
            ) as mock_build:
                mock_build.return_value = {
                    "status": "failed", "return_code": 1,
                }
                rescue = vas.rescue_unrelated_module_failure(
                    argparse.Namespace(), worktree, worktree / "out",
                    production, {"app"},
                )

            self.assertIsNone(rescue)


class BuildFailurePhaseTests(unittest.TestCase):
    """Classify build failures that produce no compiler diagnostics at all.

    Modelled on run_20260903_010736, where orgzly's app/build.gradle reads
    `.git/HEAD` to derive GIT_COMMIT. In a git worktree `.git` is a regular
    file, so Gradle failed while evaluating the project, produced zero
    javac/kotlinc lines, and the failure was recorded with an empty
    failure_attribution -- indistinguishable from a broken patch.
    """

    def _log(self, directory: str, text: str) -> Path:
        path = Path(directory) / "build.log"
        path.write_text(text, encoding="utf-8")
        return path

    def test_detects_the_real_worktree_git_layout_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            log = self._log(directory, (
                "* What went wrong:\n"
                "A problem occurred evaluating project ':app'.\n"
                "> /w/app/../.git/HEAD (Not a directory)\n"
                "\nBUILD FAILED in 10s\n"
            ))
            self.assertEqual(build_failure_phase(log), "configuration")

    def test_detects_an_execution_phase_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            log = self._log(directory, (
                "> Task :app:compileDebugJavaWithJavac FAILED\n"
                "Execution failed for task ':app:compileDebugJavaWithJavac'.\n"
            ))
            self.assertEqual(build_failure_phase(log), "execution")

    def test_detects_a_task_gradle_refused_to_select(self):
        with tempfile.TemporaryDirectory() as directory:
            log = self._log(directory, (
                "> Configure project :networksurvey\n"
                "WARNING: The option setting 'android.newDsl=false' is "
                "deprecated.\n"
                "* What went wrong:\n"
                "Cannot locate tasks that match "
                "':networksurvey:assembleDebugAndroidTest' as task "
                "'assembleDebugAndroidTest' is ambiguous in project "
                "':networksurvey'. Candidates are: "
                "'assembleCdrDebugAndroidTest', "
                "'assembleRegularDebugAndroidTest'.\n"
                "\nBUILD FAILED in 9s\n"
            ))
            self.assertEqual(build_failure_phase(log), "task_selection")

    def test_detects_a_wrapper_that_could_not_install_gradle(self):
        # edziennik, run_20260929_104044: a truncated distribution zip.
        with tempfile.TemporaryDirectory() as directory:
            log = self._log(directory, (
                "Unzipping /home/u/.gradle/wrapper/dists/gradle-8.7-bin/abc/"
                "gradle-8.7-bin.zip to /home/u/.gradle/wrapper/dists/"
                "gradle-8.7-bin/abc\n"
                'Exception in thread "main" java.util.zip.ZipException: '
                "zip END header not found\n"
                "\tat org.gradle.wrapper.Install.unzip(Install.java:215)\n"
                "A problem occurred evaluating project ':app'.\n"
            ))
            self.assertEqual(build_failure_phase(log), "toolchain")
            self.assertEqual(
                vas.wrapper_distribution_dirs(log),
                ["/home/u/.gradle/wrapper/dists/gradle-8.7-bin/abc"],
            )

    def test_only_a_wrapper_cache_entry_is_discarded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cached = root / "gradle_home/wrapper/dists/gradle-8.7-bin/abc"
            cached.mkdir(parents=True)
            (cached / "gradle-8.7-bin.zip").write_bytes(b"truncated")
            elsewhere = root / "project/build"
            elsewhere.mkdir(parents=True)
            log = self._log(directory, (
                f"Unzipping {cached}/gradle-8.7-bin.zip to {cached}\n"
                f"Unzipping {elsewhere}/x.zip to {elsewhere}\n"
                "\tat org.gradle.wrapper.Install.unzip(Install.java:215)\n"
            ))
            removed = vas.discard_broken_wrapper_distributions(log)
            self.assertEqual(removed, [str(cached)])
            self.assertFalse(cached.exists())
            self.assertTrue(elsewhere.exists())

    def test_unknown_when_the_log_names_no_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                build_failure_phase(self._log(directory, "BUILD FAILED\n")),
                "unknown",
            )

    def test_unknown_for_an_unreadable_log(self):
        self.assertEqual(
            build_failure_phase(Path("/does/not/exist.log")), "unknown"
        )


class EditsTouchBuildFilesTests(unittest.TestCase):
    """A configuration failure is only the patch's fault if it edited a build file."""

    def test_source_only_patch_touches_no_build_file(self):
        self.assertEqual(edits_touch_build_files([
            {"source_file_path": "app/src/main/java/com/orgzly/android/util/MiscUtils.java"},
            {"source_file_path": "app/src/androidTest/java/com/orgzly/Test.kt"},
        ]), [])

    def test_detects_gradle_and_properties_edits(self):
        self.assertEqual(edits_touch_build_files([
            {"source_file_path": "app/build.gradle"},
            {"source_file_path": "buildSrc/deps.gradle.kts"},
            {"source_file_path": "gradle.properties"},
            {"source_file_path": "app/src/main/java/A.java"},
        ]), ["app/build.gradle", "buildSrc/deps.gradle.kts", "gradle.properties"])

    def test_detects_version_catalog_by_name(self):
        self.assertEqual(
            edits_touch_build_files(
                [{"source_file_path": "gradle/libs.versions.toml"}]
            ),
            ["gradle/libs.versions.toml"],
        )

    def test_ignores_malformed_entries(self):
        self.assertEqual(
            edits_touch_build_files([{}, {"source_file_path": ""}, "nonsense"]),
            [],
        )

    def test_reads_the_persisted_source_file_key(self):
        """The execution report renames source_file_path to source_file.

        Honouring only one key made every patch look source-only, which would
        exonerate a patch that really did edit a build file.
        """
        self.assertEqual(
            edits_touch_build_files([{"source_file": "app/build.gradle"}]),
            ["app/build.gradle"],
        )

    def test_folds_in_the_flat_changed_files_list(self):
        self.assertEqual(
            edits_touch_build_files(
                [{"source_file": "app/src/main/java/A.java"}],
                ["app/src/main/java/A.java", "settings.gradle"],
            ),
            ["settings.gradle"],
        )


class WorktreeBaselineTests(unittest.TestCase):
    def test_baseline_key_separates_worktree_from_clone_layout(self):
        """The two baselines must never share a cache entry.

        A clone baseline can succeed exactly where every worktree fails, so
        reusing one for the other would reintroduce the misattribution.
        """
        repo = Path("/repo")
        self.assertNotEqual(
            vas.baseline_cache_key(repo, "abc123", ["assembleDebug"]),
            vas.baseline_cache_key(repo, "abc123", ["assembleDebug", "@worktree"]),
        )

    def test_missing_base_repository_is_reported_as_infrastructure(self):
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(
                build_script="build.py", variant="debug", timeout=60,
                dry_run=True,
            )
            result, from_cache = vas.run_worktree_baseline_build(
                args, Path(directory) / "absent", "abc123", None,
                Path(directory) / "cache",
            )
            self.assertFalse(from_cache)
            self.assertEqual(result["status"], "infrastructure_failure")
            self.assertIn("baseline_worktree_unavailable", result["reason"])


class GitDirectoryShimTests(unittest.TestCase):
    """Let worktree builds read .git/HEAD, as a clone build always could.

    orgzly's app/build.gradle derives GIT_COMMIT with
        def gitFolder = "$projectDir/../.git/"
        def head = new File(gitFolder + "HEAD").text.split(":")
        def refHead = new File(gitFolder + head[1].trim())
    which needs .git to be a directory holding HEAD and refs/heads/<branch>.
    """

    def _repo_with_worktree(self, directory: str) -> tuple[Path, Path]:
        root = Path(directory)
        main = root / "main"
        main.mkdir()
        for command in (
            ["git", "init", "-q", "-b", "main", str(main)],
            ["git", "-C", str(main), "config", "user.email", "t@t"],
            ["git", "-C", str(main), "config", "user.name", "t"],
        ):
            subprocess.run(command, check=True, capture_output=True)
        (main / "f.txt").write_text("x\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(main), "add", "-A"],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", str(main), "commit", "-qm", "init"],
                       check=True, capture_output=True)
        worktree = root / "wt"
        subprocess.run(
            ["git", "-C", str(main), "worktree", "add", "-q", str(worktree),
             "-b", "fix/spec-abc"],
            check=True, capture_output=True,
        )
        return main, worktree

    def _orgzly_pattern(self, worktree: Path) -> str:
        git_folder = worktree / ".git"
        head = (git_folder / "HEAD").read_text(encoding="utf-8")
        return (git_folder / head.split(":", 1)[1].strip()).read_text(
            encoding="utf-8"
        ).strip()

    def _git_ok(self, worktree: Path) -> bool:
        return subprocess.run(
            ["git", "-C", str(worktree), "status", "--porcelain"],
            capture_output=True,
        ).returncode == 0

    def test_shim_resolves_the_commit_and_restores_the_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            _, worktree = self._repo_with_worktree(directory)
            expected = subprocess.run(
                ["git", "-C", str(worktree), "rev-parse", "HEAD"],
                capture_output=True, text=True,
            ).stdout.strip()
            (worktree / "patch.txt").write_text("uncommitted\n", encoding="utf-8")

            with self.assertRaises(NotADirectoryError):
                self._orgzly_pattern(worktree)

            with vas.readable_git_directory(worktree) as applied:
                self.assertTrue(applied)
                self.assertEqual(self._orgzly_pattern(worktree), expected)

            self.assertTrue((worktree / ".git").is_file())
            self.assertTrue(self._git_ok(worktree))
            self.assertTrue((worktree / "patch.txt").exists())

    def test_shim_restores_even_when_the_build_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            _, worktree = self._repo_with_worktree(directory)
            with self.assertRaises(RuntimeError):
                with vas.readable_git_directory(worktree):
                    raise RuntimeError("gradle exploded")
            self.assertTrue((worktree / ".git").is_file())
            self.assertTrue(self._git_ok(worktree))

    def test_shim_self_heals_after_an_interrupted_run(self):
        with tempfile.TemporaryDirectory() as directory:
            _, worktree = self._repo_with_worktree(directory)
            # Simulate a process killed inside the window: shim left in place.
            pointer = (worktree / ".git").read_text(encoding="utf-8")
            (worktree / ".git.worktree-pointer.bak").write_text(
                pointer, encoding="utf-8"
            )
            (worktree / ".git").unlink()
            (worktree / ".git").mkdir()
            self.assertFalse(self._git_ok(worktree))

            with vas.readable_git_directory(worktree):
                pass
            self.assertTrue((worktree / ".git").is_file())
            self.assertTrue(self._git_ok(worktree))

    def test_shim_is_a_no_op_for_a_plain_clone(self):
        with tempfile.TemporaryDirectory() as directory:
            main, _ = self._repo_with_worktree(directory)
            with vas.readable_git_directory(main) as applied:
                self.assertFalse(applied)
            self.assertTrue((main / ".git").is_dir())
            self.assertTrue(self._git_ok(main))

    def test_detects_build_scripts_that_read_the_git_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "app").mkdir()
            (project / "app" / "build.gradle").write_text(
                'def gitFolder = "$projectDir/../.git/"\n'
                'def head = new File(gitFolder + "HEAD").text\n',
                encoding="utf-8",
            )
            self.assertEqual(
                build_reads_git_directory(project), ["app/build.gradle"]
            )

    def test_ordinary_project_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "app").mkdir()
            (project / "app" / "build.gradle").write_text(
                "android {\n  compileSdk 34\n}\n", encoding="utf-8"
            )
            self.assertEqual(build_reads_git_directory(project), [])



class AlgorithmPredicateParsingTests(unittest.TestCase):
    """Every message shape the detector actually emits, from data/raw/errors.csv.

    The predicate used to accept only MessageDigestSpec with a braced
    allowlist, which covered 11,071 of the 142,580 recorded findings. The
    other specifications carry the same "expecting one of X but found Y"
    predicate in three further spellings, and each one had to be read from
    the data rather than assumed.
    """

    def test_braced_allowlist(self):
        parsed = vas.parse_algorithm_predicate(
            "MessageDigestSpec",
            "expecting one of {SHA-256, SHA-384, SHA-512} but found MD5.")
        self.assertTrue(parsed["supported"])
        self.assertEqual(parsed["factory_type"], "MessageDigest")
        self.assertEqual(parsed["forbidden"], "MD5")
        self.assertEqual(parsed["allowed"], ["SHA-256", "SHA-384", "SHA-512"])

    def test_bare_comma_allowlist(self):
        parsed = vas.parse_algorithm_predicate(
            "TrustManagerFactorySpec",
            "expecting one of PKIX,SunX509 but found X509.")
        self.assertTrue(parsed["supported"])
        self.assertEqual(parsed["factory_type"], "TrustManagerFactory")
        self.assertEqual(parsed["forbidden"], "X509")
        self.assertEqual(parsed["allowed"], ["PKIX", "SunX509"])

    def test_allowlist_with_no_space_after_of(self):
        # KeyStoreSpec really emits "expecting one ofJCEKS,...".
        parsed = vas.parse_algorithm_predicate(
            "KeyStoreSpec",
            "expecting one ofJCEKS,JKS,DKS,PKCS11,PKCS12 "
            "but found AndroidKeyStore.")
        self.assertTrue(parsed["supported"])
        self.assertEqual(parsed["forbidden"], "AndroidKeyStore")
        self.assertIn("PKCS12", parsed["allowed"])

    def test_a_transformation_string_keeps_its_slashes(self):
        parsed = vas.parse_algorithm_predicate(
            "CipherSpec",
            "expecting one of {AES/CBC/PKCS5Padding, AES/PCBC/ISO10126Padding, "
            "...} but found RSA/ECB/OAEPWithSHA1AndMGF1Padding.")
        self.assertTrue(parsed["supported"])
        self.assertEqual(
            parsed["forbidden"], "RSA/ECB/OAEPWithSHA1AndMGF1Padding")
        self.assertTrue(parsed["allowlist_truncated"])

    def test_an_unresolved_literal_is_not_supported(self):
        # "but found ." is the majority shape for TrustManagerFactorySpec.
        parsed = vas.parse_algorithm_predicate(
            "TrustManagerFactorySpec",
            "expecting one of PKIX,SunX509 but found .")
        self.assertFalse(parsed["supported"])
        self.assertIn("no concrete literal", parsed["reason"])

    def test_an_unknown_message_is_not_supported(self):
        parsed = vas.parse_algorithm_predicate("SecureRandomSpec", "unknown")
        self.assertFalse(parsed["supported"])

    def test_a_specification_without_an_adapter_is_not_supported(self):
        # The adapter now comes from the specification's data; an invalid key
        # size is still no allowlist predicate, so it stays unsupported.
        parsed = vas.parse_algorithm_predicate(
            "KeyPairGeneratorSpec", "invalid key size for algorithm RSA.")
        self.assertFalse(parsed["supported"])
        self.assertIn("no literal found/allowlist predicate", parsed["reason"])
        self.assertFalse(vas.parse_algorithm_predicate(
            "NoSuchSpecification", "expecting one of AES but found DES")["supported"])

    def test_the_factory_type_comes_from_the_specification_data(self):
        self.assertEqual(vas.algorithm_factory_type("KeyGeneratorSpec"), "KeyGenerator")
        self.assertEqual(vas.algorithm_factory_type("SignatureSpec"), "Signature")
        # CookieManager.getInstance() takes no algorithm: not a factory adapter.
        self.assertEqual(vas.algorithm_factory_type("WebViewMixedContentSpec"), "")
        parsed = vas.parse_algorithm_predicate(
            "KeyGeneratorSpec", "expecting one of AES,HmacSHA256 but found HmacSHA1")
        self.assertEqual((parsed["supported"], parsed["factory_type"], parsed["forbidden"]),
                         (True, "KeyGenerator", "HmacSHA1"))

    def test_a_forbidden_literal_that_is_also_allowed_is_undecidable(self):
        # SignatureSpec reports "found SHA256WITHRSA" against an allowlist
        # containing "SHA256withRSA": the same source occurrence would be
        # both the violation and the fix.
        parsed = vas.parse_algorithm_predicate(
            "SignatureSpec",
            "expecting one of SHA256withRSA,SHA256withECDSA but found "
            "SHA256WITHRSA.")
        self.assertFalse(parsed["supported"])
        self.assertIn("allowlist contains the reported literal",
                      parsed["reason"])


_GRADLE_TEST_LOG = """> Task :app:compileDebugUnitTestJavaWithJavac
3 warnings

> Task :app:testDebugUnitTest

ScheduleHashCodeTest > equalItemsHaveEqualHashCodes FAILED
    java.lang.AssertionError at ScheduleHashCodeTest.java:2

38 tests completed, 1 failed

> Task :app:testDebugUnitTest FAILED
"""


class FailingTestExtractionTests(unittest.TestCase):
    """A failing assertion produces no compiler diagnostic.

    That is why run_20260906_080507 looped: the patched test compiled and
    then failed its assertion, so validation recorded no
    failure_attribution and the repair stage reported "no repairable
    compiler diagnostics" and did nothing, run after run.
    """

    def _worktree(self, directory):
        root = Path(directory)
        test_file = root / "app/src/test/java/ScheduleHashCodeTest.java"
        test_file.parent.mkdir(parents=True)
        test_file.write_text(
            "class ScheduleHashCodeTest {\n"
            "assertEquals(first, second);\n"
            "}\n",
            encoding="utf-8",
        )
        log = root / "build.log"
        log.write_text(_GRADLE_TEST_LOG, encoding="utf-8")
        return root, log

    def test_extracts_the_failing_test_with_its_source_line(self):
        with tempfile.TemporaryDirectory() as directory:
            root, log = self._worktree(directory)
            found = vas.failing_test_diagnostics(log, root, [])
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["test_suite"], "ScheduleHashCodeTest")
            self.assertEqual(found[0]["test_name"],
                             "equalItemsHaveEqualHashCodes")
            self.assertEqual(found[0]["line"], 2)
            self.assertEqual(found[0]["source_line"],
                             "assertEquals(first, second);")
            self.assertIn("AssertionError", found[0]["message"])

    def test_attributes_a_line_the_patch_wrote_to_the_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            root, log = self._worktree(directory)
            found = vas.failing_test_diagnostics(log, root, [
                {"corrected_code": "assertEquals(first, second);"},
            ])
            self.assertEqual(found[0]["attribution"],
                             "generated_or_replaced_code")

    def test_attributes_an_untouched_line_to_preexisting_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root, log = self._worktree(directory)
            found = vas.failing_test_diagnostics(log, root, [
                {"corrected_code": "return getUrl().hashCode();"},
            ])
            self.assertEqual(found[0]["attribution"],
                             "preexisting_code_outside_generated_edits")

    def test_a_throwable_without_an_error_or_exception_suffix_is_read(self):
        """Mockito's verification failures, as wifianalyzer's tests raised them."""
        with tempfile.TemporaryDirectory() as directory:
            root, log = self._worktree(directory)
            log.write_text(
                "ScheduleHashCodeTest > equalItemsHaveEqualHashCodes FAILED\n"
                "    org.mockito.exceptions.verification.junit.ArgumentsAreDifferent"
                " at ScheduleHashCodeTest.java:2\n",
                encoding="utf-8",
            )
            found = vas.failing_test_diagnostics(log, root, [])
            self.assertEqual(len(found), 1)
            self.assertIn("ArgumentsAreDifferent", found[0]["message"])

    def test_a_passing_log_yields_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "build.log"
            log.write_text("BUILD SUCCESSFUL in 2s\n", encoding="utf-8")
            self.assertEqual(vas.failing_test_diagnostics(log, root, []), [])

    def test_a_cause_outside_the_repository_points_at_the_failing_test(self):
        """NotallyX: the generated tests failed inside Robolectric's own file.

        Gradle printed "RuntimeException at AndroidInterceptors.java:88", a
        file the checkout does not have, so no failing test was recorded and
        the repair step had nothing to repair.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            test_file = root / "app/src/test/kotlin/x/ExportDigestTest.kt"
            test_file.parent.mkdir(parents=True)
            test_file.write_text(
                "class ExportDigestTest {\n"
                "    @Test\n"
                "    fun matchingCopyHasSameDigest() {\n"
                "        assertEquals(a, b)\n"
                "    }\n"
                "    @Test\n"
                "    fun `empty stream has full digest`() {}\n"
                "}\n",
                encoding="utf-8",
            )
            log = root / "build.log"
            log.write_text(
                "x.ExportDigestTest > matchingCopyHasSameDigest FAILED\n"
                "    java.lang.RuntimeException at AndroidInterceptors.java:88\n"
                "        Caused by: java.lang.IllegalAccessException at Reflection.java:394\n"
                "\n"
                "ExportDigestTest > empty stream has full digest FAILED\n"
                "    java.lang.RuntimeException at AndroidInterceptors.java:88\n",
                encoding="utf-8",
            )
            found = vas.failing_test_diagnostics(log, root, [
                {"corrected_code": "fun matchingCopyHasSameDigest() {"},
            ])
            self.assertEqual(len(found), 2)
            self.assertTrue(found[0]["path"].endswith("ExportDigestTest.kt"))
            self.assertEqual(found[0]["line"], 3)
            self.assertEqual(found[0]["attribution"], "generated_or_replaced_code")
            self.assertIn("AndroidInterceptors.java:88, outside the repository",
                          found[0]["message"])
            self.assertIn("IllegalAccessException", found[0]["message"])
            self.assertEqual(found[1]["line"], 7)

    def test_a_cause_outside_the_repository_in_a_missing_suite_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "build.log"
            log.write_text(
                "x.MissingTest > anything FAILED\n"
                "    java.lang.RuntimeException at AndroidInterceptors.java:88\n",
                encoding="utf-8",
            )
            self.assertEqual(vas.failing_test_diagnostics(log, root, []), [])

    def test_a_failure_whose_file_is_absent_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "build.log"
            log.write_text(_GRADLE_TEST_LOG, encoding="utf-8")
            self.assertEqual(vas.failing_test_diagnostics(log, root, []), [])


class BaselineCacheVersionTests(unittest.TestCase):
    """A cache that stores a verdict must be keyed by the verdict's logic.

    The giggity baseline was cached as status="failed" with return_code=0
    and reason="no_apk_found_after_successful_build" -- the old rule that
    demanded an APK from a unit-test task. Fixing the rule did not touch
    the cached entry, and from_cache=true meant it was never recomputed.
    """

    def test_the_key_changes_with_the_verdict_logic_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tasks = [":app:testDebugUnitTest"]
            first = vas.baseline_cache_key(root, "abc123", tasks)
            with patch.object(vas, "BASELINE_VERDICT_LOGIC_VERSION",
                              vas.BASELINE_VERDICT_LOGIC_VERSION + 1):
                second = vas.baseline_cache_key(root, "abc123", tasks)
            self.assertNotEqual(first, second)

    def test_the_key_is_stable_for_the_same_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tasks = [":app:testDebugUnitTest"]
            self.assertEqual(
                vas.baseline_cache_key(root, "abc123", tasks),
                vas.baseline_cache_key(root, "abc123", tasks),
            )



class BuildValidationRecordTests(unittest.TestCase):
    """Everything a later stage reads must survive this record.

    The record is an explicit whitelist, so a field computed during
    validation but absent from it is silently dropped on write. That is what
    made the failing-test extraction look like it had never run: its
    attribution was persisted, because that key was listed, while the
    records the attribution came from were not -- and the repair stage,
    which reads the persisted report rather than the in-memory result,
    still found nothing to repair.
    """

    def _record(self, **extra):
        result = {
            "status": "failed", "task": ":app:testDebugUnitTest",
            "return_code": 1, "reason": "gradle_return_code_1",
            "log_file": "/tmp/build.log", "phases": {"production": {}},
        }
        result.update(extra)
        with tempfile.TemporaryDirectory() as directory:
            return vas.build_validation_record(
                result, "0638946f7e4a", Path(directory),
            )

    def test_failing_tests_reach_the_persisted_record(self):
        failures = [{"test_suite": "ScheduleHashCodeTest",
                     "test_name": "equalItemsHaveEqualHashCodes"}]
        record = self._record(
            failing_tests=failures, failure_attribution="generated_patch")
        self.assertEqual(record["failing_tests"], failures)
        self.assertEqual(record["failure_attribution"], "generated_patch")

    def test_every_diagnostic_field_defaults_to_an_empty_list(self):
        record = self._record()
        for field in vas.BUILD_VALIDATION_DIAGNOSTIC_FIELDS:
            self.assertEqual(record[field], [], field)

    def test_the_record_carries_every_field_the_repair_stage_reads(self):
        # The repair stage selects candidates on these keys; if the record
        # cannot carry one, a repairable finding is invisible to it.
        record = self._record()
        for field in ("status", "failure_attribution", "compiler_diagnostics",
                      "failing_tests", "worktree_path"):
            self.assertIn(field, record)


if __name__ == "__main__":
    unittest.main()


class PreexistingBuildFailureTests(unittest.TestCase):
    """A failure the patch did not cause must not be blamed on the finding.

    The validation already proves this: it rebuilds the unmodified base commit
    in an identical worktree layout and records
    failure_attribution="verified_preexisting_build_failure" when the base
    fails the same way. That determination was then ignored by the summary and
    by --fail-on-validation-error, so hanjoongcho/aaf-easydiary -- whose
    app/build.gradle.kts reads a local.properties the README asks each
    developer to create, making both the patched worktree and the baseline
    fail to configure -- aborted run_20260908_163511 with a correct, applied
    Zip Slip fix already in hand.
    """

    @staticmethod
    def _result(status, attribution=None):
        result = {"status": status}
        if attribution is not None:
            result["failure_attribution"] = attribution
        return result

    def test_a_preexisting_failure_is_not_the_patch(self):
        for attribution in (
            "verified_preexisting_build_failure",
            "verified_preexisting_test_debt",
            "preexisting_build_configuration",
            "validation_task_unresolved",
            "build_environment",
        ):
            with self.subTest(attribution=attribution):
                self.assertFalse(vas.failure_is_the_patch(
                    self._result("failed", attribution)
                ))

    def test_a_patch_attributed_failure_still_is(self):
        self.assertTrue(vas.failure_is_the_patch(
            self._result("failed", "generated_patch")
        ))

    def test_an_unattributed_failure_is_still_blamed_on_the_patch(self):
        """No attribution means nothing ruled the patch out."""
        self.assertTrue(vas.failure_is_the_patch(self._result("failed")))

    def test_a_passing_build_is_never_a_failure(self):
        for status in ("success", "success_app_module_only"):
            with self.subTest(status=status):
                self.assertFalse(vas.failure_is_the_patch(
                    self._result(status)
                ))

    def test_a_preexisting_failure_is_still_not_a_pass(self):
        """It must stay unpublishable: the patch was never compiled."""
        result = self._result("failed", "verified_preexisting_build_failure")
        self.assertNotIn(result["status"], vas.PASSING_STATUSES)


class UnselectedFlavorFailureTests(unittest.TestCase):
    """One unbuildable product flavor must not fail the whole validation.

    A plain assembleDebug fans out to EVERY product flavor and Gradle
    interleaves their tasks, so an unbuildable flavor aborts the run before the
    flavor validation actually targets has compiled anything. Measured on
    hanjoongcho/aaf-easydiary: assembleDebug died in
    :app:processGmsDevDebugResources on the ten Flaticon drawables its README
    tells each developer to import by hand, with 36 foss tasks run and
    compileFossDebugKotlin never reached -- while assembleFossDebug on the same
    patched worktree finished BUILD SUCCESSFUL and packaged an APK.
    """

    EASYDIARY = """
    android {
        productFlavors {
            create("foss") { dimension = "version" }
            create("gmsDev") { dimension = "version" }
            create("gms") { dimension = "version" }
        }
    }
    """

    def _module(self, directory, text=None):
        module = Path(directory) / "app"
        module.mkdir()
        (module / "build.gradle.kts").write_text(
            self.EASYDIARY if text is None else text
        )
        return module

    def test_a_task_for_an_unbuilt_flavor_is_recognised(self):
        with tempfile.TemporaryDirectory() as directory:
            module = self._module(directory)
            self.assertEqual(
                vas.unselected_flavor_failure(
                    module, "processGmsDevDebugResources"
                ),
                "gmsDev",
            )

    def test_a_task_for_the_selected_flavor_is_not_excused(self):
        with tempfile.TemporaryDirectory() as directory:
            module = self._module(directory)
            # foss is the alphabetically first flavor, so it is the one
            # validation builds: a failure there is the patch's problem.
            self.assertIsNone(vas.unselected_flavor_failure(
                module, "compileFossDebugKotlin"
            ))

    def test_a_flavourless_module_never_excuses_anything(self):
        with tempfile.TemporaryDirectory() as directory:
            module = self._module(directory, "android { }")
            self.assertIsNone(vas.unselected_flavor_failure(
                module, "processDebugResources"
            ))

    def test_a_flavor_name_must_match_at_a_task_word_boundary(self):
        """Gradle capitalises the flavor in a variant task name."""
        with tempfile.TemporaryDirectory() as directory:
            module = self._module(
                directory,
                'android { productFlavors { create("res") '
                '{ dimension = "d" }\ncreate("aaa") { dimension = "d" } } }',
            )
            # "res" appears inside "Resources" but never as "Res".
            self.assertIsNone(vas.unselected_flavor_failure(
                module, "processAaaDebugResources"
            ))

    def test_an_empty_task_name_is_not_a_flavor_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertIsNone(
                vas.unselected_flavor_failure(self._module(directory), "")
            )

    def test_the_failing_task_name_is_read_from_the_log(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text(
                "Execution failed for task "
                "':app:processGmsDevDebugResources'.\n"
            )
            self.assertEqual(
                vas.failing_task_name(log), "processGmsDevDebugResources"
            )
            self.assertEqual(vas.failing_task_module(log), ":app")

    def test_a_log_naming_no_task_yields_no_name(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text("A problem occurred evaluating project ':app'.\n")
            self.assertIsNone(vas.failing_task_name(log))


class SingleMethodFixRescueTests(unittest.TestCase):
    """The rescue path must not be dead for single-method fixes.

    changed_paths was built only from coordinated_edits, which a single-method
    solution does not have -- it records its one file in source_file. So
    production_modules came out empty, rescue_unrelated_module_failure returned
    on its first guard, and neither the unrelated-module branch nor the
    unselected-flavor one could ever run for that whole class of fix.
    run_20260908_203221 is the case: easydiary's Zip Slip fix built its foss
    APK (apk_count=1) and was still recorded as failed, because the rescue that
    would have recognised a gmsDev-only failure never ran.
    """

    SOURCE = "app/src/main/java/me/blog/korn123/easydiary/helper/ZipHelper.kt"

    @staticmethod
    def _changed_paths(solution):
        """Mirrors the construction in validate_applied_solutions.main()."""
        paths = {
            str(item.get("source_file", "")).replace("\\", "/").lower()
            for item in (solution.get("coordinated_edits") or [])
            if isinstance(item, dict)
        }
        primary = str(solution.get("source_file", "")).replace("\\", "/").lower()
        if primary:
            paths.add(primary)
        return paths

    @staticmethod
    def _production_modules(changed_paths):
        return vas.production_modules_for(Path("."), changed_paths)

    def test_a_single_method_fix_yields_a_production_module(self):
        solution = {"fix_scope": "single_method", "source_file": self.SOURCE,
                    "coordinated_edits": None}
        modules = self._production_modules(self._changed_paths(solution))
        self.assertEqual(modules, {"app"})

    def test_a_coordinated_fix_still_yields_all_its_modules(self):
        solution = {
            "fix_scope": "coordinated",
            "source_file": self.SOURCE,
            "coordinated_edits": [
                {"source_file": self.SOURCE},
                {"source_file": "lib/src/main/java/p/Other.kt"},
            ],
        }
        modules = self._production_modules(self._changed_paths(solution))
        self.assertEqual(modules, {"app", "lib"})

    def test_a_solution_with_no_source_file_stays_empty(self):
        solution = {"coordinated_edits": None, "source_file": ""}
        self.assertEqual(self._changed_paths(solution), set())

    def test_the_rescue_bails_when_there_is_no_production_module(self):
        self.assertIsNone(vas.rescue_unrelated_module_failure(
            argparse.Namespace(), Path("."), Path("."),
            {"status": "failed"}, set(),
        ))


class ProductionModuleLayoutTests(unittest.TestCase):
    """Modules are found in any source-set layout, not only src/main.

    nelenkov/wwwjdic keeps its :wwwjdic library sources in wwwjdic/src/. The
    patched module set came out empty, so a build that failed only in
    :wwwjdic-app (google-services.json missing) was recorded as failed
    without the patched library ever being recompiled (run_20260915_175048).
    """

    def _legacy_worktree(self, directory):
        worktree = Path(directory)
        (worktree / "build.gradle").write_text("", encoding="utf-8")
        (worktree / "wwwjdic").mkdir()
        (worktree / "wwwjdic" / "build.gradle").write_text(
            "apply plugin: 'com.android.library'\n", encoding="utf-8",
        )
        return worktree

    def test_a_module_outside_the_conventional_layout_is_found(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = self._legacy_worktree(directory)
            self.assertEqual(vas.production_modules_for(worktree, {
                "wwwjdic/src/org/nick/wwwjdic/ocr/OcrFormEntity.java",
                "wwwjdic-android/src/test/java/org/nick/wwwjdic/ocr/"
                "OcrFormEntityCloseRegressionTest.java",
            }), {"wwwjdic"})

    def test_a_root_project_file_names_no_module(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            (worktree / "build.gradle").write_text("", encoding="utf-8")
            self.assertEqual(vas.production_modules_for(
                worktree, {"src/org/tvheadend/tvhguide/TVHGuideApplication.java"},
            ), set())

    def test_the_conventional_layout_needs_no_build_file(self):
        self.assertEqual(vas.production_modules_for(Path("missing"), {
            "app/src/main/java/p/A.kt", "app/src/test/java/p/ATest.kt",
        }), {"app"})

    def test_the_unrelated_module_failure_is_rescued_for_a_java_library(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = self._legacy_worktree(directory)
            log_file = worktree / "build.log"
            log_file.write_text(
                "* What went wrong:\n"
                "Execution failed for task "
                "':wwwjdic-app:processDonateDebugGoogleServices'.\n"
                "> File google-services.json is missing.\n",
                encoding="utf-8",
            )
            modules = vas.production_modules_for(
                worktree, {"wwwjdic/src/org/nick/wwwjdic/ocr/OcrFormEntity.java"},
            )
            with patch.object(vas, "run_build_phase") as mock_build:
                mock_build.return_value = {"status": "failed", "return_code": 0}
                rescue = vas.rescue_unrelated_module_failure(
                    argparse.Namespace(), worktree, worktree / "out",
                    {"status": "failed", "log_file": str(log_file)}, modules,
                )
            self.assertEqual(rescue["status"], "success_app_module_only")
            self.assertEqual(rescue["unrelated_module_failure_task"], ":wwwjdic-app")
            # A Java-only module has no compileDebugKotlin task.
            self.assertEqual(
                mock_build.call_args.kwargs["tasks"], [":wwwjdic:compileDebugSources"],
            )


class BaselineCacheInvalidationTests(unittest.TestCase):
    """A cached baseline must not outlive a change to what a build does.

    The key covers repo, commit, task set and a verdict-logic version. Adding
    local.properties provisioning changed what a baseline build *does* without
    changing any of those, so run_20260908_203221 compared a patched build that
    reached resource linking against a baseline cached at 16:38 that had died
    on "local.properties (No such file or directory)". Here the verdict was
    still right; a stale "success" would have blamed the patch instead.
    """

    def test_the_version_is_part_of_the_key(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            first = vas.baseline_cache_key(repo, "abc123", ["assembleDebug"])
            with patch.object(vas, "BASELINE_VERDICT_LOGIC_VERSION", 999):
                second = vas.baseline_cache_key(repo, "abc123", ["assembleDebug"])
        self.assertNotEqual(first, second)

    def test_the_local_properties_change_bumped_the_version(self):
        """Pins the bump, so the same omission cannot recur silently."""
        self.assertGreaterEqual(vas.BASELINE_VERDICT_LOGIC_VERSION, 3)

    def test_the_same_inputs_still_hit_the_same_key(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            self.assertEqual(
                vas.baseline_cache_key(repo, "abc123", ["assembleDebug"]),
                vas.baseline_cache_key(repo, "abc123", ["assembleDebug"]),
            )


class RevalidationScopeTests(unittest.TestCase):
    """The revalidation rebuilds what a repair changed, not what already passed."""

    def run_main(self, solutions, fixes, previous_report=None, previous_production=None):
        import json

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report = base / "execution_report.json"
            report.write_text(json.dumps({"per_solution_details": solutions}), encoding="utf-8")
            output = base / "build_validation"
            output.mkdir()
            if previous_report is not None:
                (output / "build_report.json").write_text(json.dumps(previous_report), encoding="utf-8")
            for finding_id, record in (previous_production or {}).items():
                production = output / finding_id / "production"
                production.mkdir(parents=True)
                (production / "build_report.json").write_text(json.dumps([record]), encoding="utf-8")
            fixes_dir = base / "validation_fixes"
            fixes_dir.mkdir()
            for finding_id, status in fixes.items():
                (fixes_dir / f"{finding_id}_validation_fix.json").write_text(
                    json.dumps({"finding_id": finding_id, "status": status}), encoding="utf-8")
            calls = []

            def fake_build(args, project, output_dir, tasks=None, clean_first=False, keep_going=False):
                calls.append({"project": project.name, "clean_first": clean_first, "tasks": tasks})
                return {"status": "success", "project_dir": str(project), "log_file": ""}

            argv = ["x", "--build-script", "b.py", "--projects-dir", str(base),
                    "--output-dir", str(output), "--execution-report", str(report),
                    "--revalidate-repaired-in", str(fixes_dir)]
            with patch.object(sys, "argv", argv), \
                    patch.object(vas, "run_build_phase", fake_build), \
                    patch.object(vas, "build_reads_git_directory", return_value=[]), \
                    patch.object(vas, "production_modules_for", return_value=set()), \
                    patch.object(vas, "rescue_unrelated_module_failure", return_value=None), \
                    patch.object(vas, "replay_source_detector", return_value={}):
                vas.main()
            merged = json.loads((output / "build_report.json").read_text(encoding="utf-8"))
            return calls, merged

    def solution(self, name, status, edits=()):
        worktree = f"/w/{name}"
        return {
            "status": "SUCCESS", "finding_id": name, "apk_name": f"{name}.apk",
            "worktree_path": worktree, "source_file": "app/src/main/A.kt",
            "coordinated_edits": list(edits), "build_validation": {"status": status},
        }

    def test_a_finding_that_passed_and_was_not_repaired_is_not_rebuilt(self):
        calls, merged = self.run_main(
            [self.solution("kept", "success"), self.solution("fixed", "failed")],
            {"fixed": "success"},
            previous_report=[{"finding_id": "kept", "status": "success"}],
        )
        self.assertEqual([call["project"] for call in calls], ["fixed"])
        self.assertEqual(
            sorted(item["finding_id"] for item in merged), ["fixed", "kept"])

    def test_a_finding_that_still_fails_is_rebuilt_even_if_no_repair_succeeded(self):
        calls, _ = self.run_main([self.solution("broken", "failed")], {"broken": "failed"})
        self.assertEqual([call["project"] for call in calls], ["broken"])

    def test_a_passed_finding_that_was_repaired_is_rebuilt(self):
        calls, _ = self.run_main([self.solution("again", "success")], {"again": "success"})
        self.assertEqual([call["project"] for call in calls], ["again"])

    def test_a_test_only_repair_after_a_passing_build_reuses_that_build(self):
        edits = [{"edit_kind": "validation_repair", "source_file": "app/src/androidTest/T.kt"}]
        calls, merged = self.run_main(
            [self.solution("t", "failed", edits)], {"t": "success"},
            previous_production={"t": {
                "status": "success", "project_dir": "/w/t", "apk_count": 3,
                "copied_apks": ["a.apk"],
            }},
        )
        # The production build is not repeated (with every task up to date its APKs
        # are older than the build's start and would be refused as stale); only
        # the test tasks the repair changed are built.
        self.assertTrue(all(call["tasks"] for call in calls), calls)
        self.assertTrue(calls)
        [record] = [item for item in merged if item.get("finding_id") == "t"]
        production = record["phases"]["production"]
        self.assertEqual(production["status"], "success")
        self.assertEqual(production["apk_count"], 3)
        self.assertEqual(production["copied_apks"], ["a.apk"])
        self.assertTrue(production["reused_after_test_only_repair"])

    def test_a_production_repair_keeps_the_clean_build(self):
        edits = [{"edit_kind": "validation_repair", "source_file": "app/src/main/A.kt"}]
        calls, _ = self.run_main(
            [self.solution("p", "failed", edits)], {"p": "success"},
            previous_production={"p": {"status": "success", "project_dir": "/w/p"}},
        )
        self.assertTrue(calls[0]["clean_first"])


class ProblemReportDiagnosticTests(unittest.TestCase):
    """Kotlin errors reported through Gradle's problems API, with no `e:` line."""

    def _diagnostics(self, log: str, source: str = "", edits=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            test_file = root / "app" / "src" / "test" / "DigestTest.kt"
            test_file.parent.mkdir(parents=True)
            test_file.write_text(source, encoding="utf-8")
            log_file = root / "build.log"
            log_file.write_text(log.replace("{path}", str(test_file)), encoding="utf-8")
            return vas.compiler_diagnostics(log_file, edits or [])

    LOG = (
        "> Task :app:compileDebugUnitTestKotlin\n"
        "Problem found: Kotlin compiler: INVISIBLE_REFERENCE "
        "(id: kotlin:compiler:error:INVISIBLE_REFERENCE)\n"
        "  Kotlin compiler error\n"
        "    Cannot access 'fun childType(): Int': it is private in 'A'.\n"
        "    Location: {path} line 2\n"
        "Problem found: Kotlin compiler: DEPRECATION "
        "(id: kotlin:compiler:warning:DEPRECATION)\n"
        "  Kotlin compiler warning\n"
        "    'fun startScan(): Boolean' is deprecated.\n"
        "    Location: {path} line 1\n"
        "> Task :app:compileDebugUnitTestKotlin FAILED\n"
    )
    SOURCE = "class DigestTest {\n    val t = A().childType()\n}\n"

    def test_an_error_report_becomes_a_diagnostic_and_a_warning_does_not(self):
        diagnostics = self._diagnostics(self.LOG, self.SOURCE)
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0]["line"], 2)
        self.assertIn("it is private", diagnostics[0]["message"])
        self.assertEqual(diagnostics[0]["source_line"], "val t = A().childType()")

    def test_the_line_the_patch_wrote_is_attributed_to_it(self):
        diagnostics = self._diagnostics(
            self.LOG, self.SOURCE,
            edits=[{"corrected_code": "    val t = A().childType()"}],
        )
        self.assertEqual(diagnostics[0]["attribution"], "generated_or_replaced_code")

    def test_an_error_printed_in_both_formats_is_reported_once(self):
        log = self.LOG + "e: file://{path}:2:17 Cannot access 'fun childType(): Int': it is private in 'A'.\n"
        self.assertEqual(len(self._diagnostics(log, self.SOURCE)), 1)


class TestBaselineOffBaseCloneTests(unittest.TestCase):
    """The test baseline runs even when the clone is not at the base commit.

    A clone pinned to the commit the analysed APK was built from sits behind
    the branch tip a finding worktree starts from. The baseline used to be
    skipped then, every patched test failure stayed unattributed, and
    validation_fix had nothing it was allowed to repair.
    """

    LOG = (
        "AppTest > roundtrip FAILED\n"
        "    java.lang.AssertionError at AppTest.kt:3\n"
    )

    def run_main(self, baseline_status="success", created_by_patch=False):
        import json

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            worktree = base / "w" / "finding"
            test_file = worktree / "app" / "src" / "test" / "AppTest.kt"
            test_file.parent.mkdir(parents=True)
            test_file.write_text("class AppTest {\n\n    fun roundtrip() = check(false)\n}\n",
                                 encoding="utf-8")
            clone = base / "clone"
            clone.mkdir()
            log_file = base / "patched_tests.log"
            log_file.write_text(self.LOG, encoding="utf-8")
            solution = {
                "status": "SUCCESS", "finding_id": "finding", "apk_name": "a.apk",
                "worktree_path": str(worktree), "source_file": "app/src/main/A.kt",
                "base_repository_path": str(clone), "base_commit": "abc123",
                "coordinated_edits": [{"source_file": "app/src/test/AppTest.kt",
                                       "corrected_code": "fun roundtrip() = check(false)"}],
            }
            report = base / "execution_report.json"
            report.write_text(json.dumps({"per_solution_details": [solution]}), encoding="utf-8")
            output = base / "build_validation"
            output.mkdir()

            def fake_build(args, project, output_dir, tasks=None, clean_first=False, keep_going=False):
                if tasks and any("Test" in task for task in tasks):
                    return {"status": "failed", "project_dir": str(project),
                            "log_file": str(log_file)}
                return {"status": "success", "project_dir": str(project), "log_file": ""}

            worktree_baseline = patch.object(
                vas, "run_worktree_baseline_build",
                return_value=({"status": baseline_status, "log_file": ""}, False),
            )
            argv = ["x", "--build-script", "b.py", "--projects-dir", str(base),
                    "--output-dir", str(output), "--execution-report", str(report)]
            with patch.object(sys, "argv", argv), \
                    patch.object(vas, "run_build_phase", fake_build), \
                    patch.object(vas, "build_reads_git_directory", return_value=[]), \
                    patch.object(vas, "production_modules_for", return_value=set()), \
                    patch.object(vas, "rescue_unrelated_module_failure", return_value=None), \
                    patch.object(vas, "replay_source_detector", return_value={}), \
                    patch.object(vas, "checkout_matches_base", return_value=False), \
                    patch.object(vas, "paths_absent_from_commit",
                                 return_value=created_by_patch), \
                    patch.object(vas, "run_baseline_build") as clone_baseline, \
                    worktree_baseline as worktree_build:
                vas.main()
            merged = json.loads((output / "build_report.json").read_text(encoding="utf-8"))
            return merged[0], clone_baseline, worktree_build

    def test_a_new_failure_is_attributed_through_a_worktree_baseline(self):
        result, clone_baseline, worktree_build = self.run_main()
        clone_baseline.assert_not_called()
        worktree_build.assert_called_once()
        self.assertEqual(result["failure_attribution"], "generated_patch")
        self.assertEqual(len(result["new_failing_tests"]), 1)

    def test_a_baseline_that_never_built_attributes_nothing(self):
        result, _, _ = self.run_main(baseline_status="infrastructure_failure")
        self.assertNotIn("new_failing_tests", result)
        self.assertNotEqual(result.get("failure_attribution"), "generated_patch")

    def test_a_failing_test_the_patch_created_needs_no_baseline(self):
        result, clone_baseline, worktree_build = self.run_main(created_by_patch=True)
        clone_baseline.assert_not_called()
        worktree_build.assert_not_called()
        self.assertEqual(result["failure_attribution"], "generated_patch")
        self.assertEqual(result["phases"]["baseline_tests"]["status"], "skipped")
