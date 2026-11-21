"""The repository's own formatter, run on the lines a patch wrote.

Crustack/NotallyX#1167 (2026-10-30): the repository formats Kotlin with
ktfmt (kotlinLangStyle, 100 columns) through a pre-commit hook a Gradle task
installs, and the pipeline only knew ktlintFormat. The published test and the
follow-up commit had lines over 100 columns.
"""
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs import repository_formatter as rf  # noqa: E402
from cognalys.prs.pr_generator import PrGenerator  # noqa: E402


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, text=True).stdout


def _project(directory: str, app_build: str = "", catalog: str = "",
             files: dict | None = None) -> Path:
    """A Gradle checkout with one :app module, committed."""
    root = Path(directory) / "Proj"
    (root / "app").mkdir(parents=True)
    (root / "settings.gradle.kts").write_text('include(":app")\n', encoding="utf-8")
    (root / "build.gradle.kts").write_text("", encoding="utf-8")
    (root / "gradlew").write_text("#!/bin/sh\n", encoding="utf-8")
    (root / "gradlew").chmod(0o755)
    (root / "app/build.gradle.kts").write_text(app_build, encoding="utf-8")
    if catalog:
        (root / "gradle").mkdir()
        (root / "gradle/libs.versions.toml").write_text(catalog, encoding="utf-8")
    for path, text in (files or {}).items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text, encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True,
                   capture_output=True)
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    return root


KTFMT_BUILD = ('plugins { alias(libs.plugins.ktfmt) }\n'
               'ktfmt { kotlinLangStyle() }\n')
KTFMT_CATALOG = ('[plugins]\nktfmt = { id = "com.ncorti.ktfmt.gradle", '
                 'version.ref = "ktfmt" }\n')
TEST = "app/src/test/kotlin/HashTest.kt"
OTHER = "app/src/main/kotlin/Other.kt"
LONG = ("        val originalDigest = ByteArrayInputStream(\"original export content\""
        ".toByteArray()).sha256Hash()\n")
WRAPPED = ("        val originalDigest =\n"
           "            ByteArrayInputStream(\"original export content\""
           ".toByteArray()).sha256Hash()\n")


class DetectionTests(unittest.TestCase):

    def test_ktfmt_is_read_from_the_catalog_plugin_and_the_hook_that_runs_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, KTFMT_BUILD, KTFMT_CATALOG, {
                ".scripts/pre-commit": "./gradlew ktfmtPrecommit --include-only=$f\n"})
            detection = rf.detect_formatter(root)
        self.assertEqual(detection.formatter.name, "ktfmt")
        self.assertIn(".scripts/pre-commit", detection.evidence)
        self.assertIn("gradle/libs.versions.toml", detection.evidence)

    def test_a_tool_name_in_the_catalog_alone_is_not_a_formatter_plugin(self):
        # Spotless's ktlint step names "ktlint" in a catalog as readily as
        # the ktlint plugin does; only Spotless is configured here.
        with tempfile.TemporaryDirectory() as directory:
            root = _project(
                directory, 'plugins { id("com.diffplug.spotless") }\n'
                           'spotless { kotlin { ktlint(libs.versions.ktlint.get()) } }\n',
                '[versions]\nktlint = "1.3.0"\n')
            self.assertEqual(rf.detect_formatter(root).formatter.name, "spotless")

    def test_the_formatter_a_hook_runs_wins_over_another_configured_one(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, 'plugins { id("com.diffplug.spotless") '
                                       'id("org.jlleitschuh.gradle.ktlint") }\n', files={
                                           ".githooks/pre-commit": "./gradlew ktlintFormat\n"})
            self.assertEqual(rf.detect_formatter(root).formatter.name, "ktlint")

    def test_a_formatter_of_another_gradle_build_in_the_checkout_is_not_this_ones(self):
        # Intertune's innertubex submodule (intertune_v5, 2026-10-30) has its
        # own settings and applies ktlint to itself; the root build applies
        # no formatter, so ":app:ktlintFormat" did not exist. An included
        # build of convention plugins is still read.
        ktlint = 'plugins { id("org.jlleitschuh.gradle.ktlint") }\n'
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, files={"innertubex/settings.gradle.kts": "",
                                              "innertubex/build.gradle.kts": ktlint})
            self.assertIsNone(rf.detect_formatter(root).formatter)
            (root / "build-logic").mkdir()
            (root / "build-logic/settings.gradle.kts").write_text("", encoding="utf-8")
            (root / "build-logic/build.gradle.kts").write_text(ktlint, encoding="utf-8")
            self.assertIsNone(rf.detect_formatter(root).formatter)
            (root / "settings.gradle.kts").write_text(
                'pluginManagement { includeBuild("build-logic") }\ninclude(":app")\n',
                encoding="utf-8")
            detection = rf.detect_formatter(root)
        self.assertEqual(detection.formatter.name, "ktlint")
        self.assertEqual(detection.evidence, ["build-logic/build.gradle.kts"])

    def test_nothing_configured_is_none(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, 'plugins { id("com.android.application") }\n')
            detection = rf.detect_formatter(root)
        self.assertIsNone(detection.formatter)
        self.assertFalse(detection.pre_commit_config)


class LineLimitTests(unittest.TestCase):

    def test_ktfmt_formats_to_100_columns_unless_max_width_says_otherwise(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, KTFMT_BUILD, KTFMT_CATALOG)
            self.assertEqual(rf.line_limit(root, TEST), 100)
            (root / "app/build.gradle.kts").write_text(
                KTFMT_BUILD + "ktfmt { maxWidth.set(120) }\n", encoding="utf-8")
            self.assertEqual(rf.line_limit(root, TEST), 120)
            # ktfmt does not format Java.
            self.assertIsNone(rf.line_limit(root, "app/src/main/java/A.java"))

    def test_editorconfig_max_line_length_applies_to_its_own_sections(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, files={".editorconfig": (
                "root = true\n[*]\nmax_line_length = 120\n"
                "[*.{kt,kts}]\nmax_line_length = 140\n[*.md]\nmax_line_length = off\n")})
            self.assertEqual(rf.line_limit(root, TEST), 140)
            self.assertEqual(rf.line_limit(root, "app/src/main/java/A.java"), 120)
            self.assertIsNone(rf.line_limit(root, "README.md"))

    def test_a_convention_plugin_in_an_included_build_sets_the_formatters_style(self):
        # AGrahn configures Spotless's ktfmt (googleStyle, 100 columns) in
        # build-logic's SpotlessPlugin.kt (2026-10-30); a source file of a
        # module is still not read as configuration.
        convention = ("build-logic/src/main/kotlin/SpotlessPlugin.kt",
                      "kotlin { ktfmt(\"0.64\").googleStyle() }\n")
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, 'plugins { id("com.diffplug.spotless") }\n',
                            files={convention[0]: convention[1],
                                   "build-logic/build.gradle.kts": ""})
            self.assertIsNone(rf.line_limit(root, TEST))
            (root / "settings.gradle.kts").write_text(
                'pluginManagement { includeBuild("build-logic") }\ninclude(":app")\n',
                encoding="utf-8")
            self.assertEqual(rf.line_limit(root, TEST), 100)
            (root / "app/src/main/kotlin").mkdir(parents=True)
            (root / "app/src/main/kotlin/Spotless.kt").write_text(
                "val x = ktfmt(1)\n", encoding="utf-8")
            (root / "settings.gradle.kts").write_text('include(":app")\n', encoding="utf-8")
            self.assertIsNone(rf.line_limit(root, TEST))

    def test_overlong_lines_are_counted_on_the_patch_lines_only(self):
        text = "short\n" + "x" * 101 + "\n" + "y" * 101 + "\n"
        self.assertEqual(rf.overlong_lines(text, 100, {1}), [2])
        self.assertEqual(rf.overlong_lines(text, None), [])


class MergeTests(unittest.TestCase):
    """Only the formatter's hunks on the patch's own lines are kept."""

    BEFORE = "class A {\n    fun   untouched() = 1\n}\n"

    def test_a_hunk_on_the_patch_lines_is_kept_and_one_elsewhere_dropped(self):
        patched = "class A {\n    fun   untouched() = 1\n" + LONG + "}\n"
        formatted = "class A {\n    fun untouched() = 1\n" + WRAPPED + "}\n"
        merged, kept, dropped = rf.merge_formatting(self.BEFORE, patched, formatted, False)
        self.assertEqual(merged, "class A {\n    fun   untouched() = 1\n" + WRAPPED + "}\n")
        self.assertEqual(kept, 1)
        self.assertEqual([hunk["reason"] for hunk in dropped],
                         ["lines the patch did not write"])

    def test_a_new_file_is_formatted_whole(self):
        merged, _, dropped = rf.merge_formatting(None, LONG, WRAPPED, True)
        self.assertEqual(merged, WRAPPED)
        self.assertEqual(dropped, [])

    def test_with_only_layout_a_change_beyond_layout_is_dropped(self):
        # The build validated the patch before the PR step formats it: a
        # formatter that removes an import or adds braces changes code the
        # build never compiled.
        before = "import a.B\n\nfun f() = 1\n"
        patched = "import a.B\nimport a.C\n\nfun f() = 1\n"
        formatted = "import a.B\n\nfun f() = 1\n"
        merged, _, dropped = rf.merge_formatting(before, patched, formatted, True)
        self.assertEqual(merged, patched)
        self.assertEqual(dropped[0]["reason"], "more than layout")
        merged, _, _ = rf.merge_formatting(before, patched, formatted, False)
        self.assertEqual(merged, formatted)

    def test_trailing_commas_and_line_breaks_are_layout(self):
        self.assertTrue(rf.layout_only(["f(a, b)\n"], ["f(\n", "    a,\n", "    b,\n", ")\n"]))
        self.assertFalse(rf.layout_only(["f(a, b)\n"], ["f(b, a)\n"]))

    def test_the_patchs_import_moved_into_sorted_order_is_kept(self):
        # NotallyX's ExportExtensions.kt (2026-10-30): ktfmt moved
        # "import ...sha256Hash" below "resolveAttachmentFile"; the insertion
        # judged alone sits beside lines the patch did not write.
        before = "import u.log\nimport u.md5Hash\nimport u.resolve\nimport u.verify\n"
        patched = "import u.log\nimport u.sha256Hash\nimport u.resolve\nimport u.verify\n"
        formatted = "import u.log\nimport u.resolve\nimport u.sha256Hash\nimport u.verify\n"
        merged, _, dropped = rf.merge_formatting(before, patched, formatted, True)
        self.assertEqual(merged, formatted)
        self.assertEqual(dropped, [])

    def test_a_repository_whose_own_imports_are_unsorted_keeps_them(self):
        before = "import z.Z\nimport a.A\n"
        patched = "import z.Z\nimport a.A\nimport m.M\n"
        formatted = "import a.A\nimport m.M\nimport z.Z\n"
        merged, _, _ = rf.merge_formatting(before, patched, formatted, True)
        self.assertEqual(merged, patched)


class CommandTests(unittest.TestCase):

    def test_ktfmt_runs_the_source_set_task_on_the_patch_files_only(self):
        # The paths are relative to the module, as NotallyX's own hook
        # passes them to --include-only.
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, KTFMT_BUILD, KTFMT_CATALOG)
            spec = rf.detect_formatter(root).formatter
            commands = rf.formatter_commands(spec, root, [TEST, OTHER])
        self.assertEqual(commands, [(
            [":app:ktfmtFormatMain", "--include-only=src/main/kotlin/Other.kt",
             ":app:ktfmtFormatTest", "--include-only=src/test/kotlin/HashTest.kt"],
            [":app:ktfmtFormat"], ["ktfmtFormat"])])

    def test_spotless_formats_one_file_through_its_ide_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, 'plugins { id("com.diffplug.spotless") }\n')
            spec = rf.detect_formatter(root).formatter
            (precise, broad, _from_root), = rf.formatter_commands(spec, root, [TEST])
        self.assertEqual(precise[0], ":app:spotlessApply")
        self.assertTrue(precise[1].startswith("-PspotlessIdeHook=")
                        and precise[1].endswith("HashTest.kt"))
        self.assertEqual(broad, [":app:spotlessApply"])

    def test_a_formatter_applied_to_the_root_project_alone_is_run_from_the_root(self):
        # AGrahn (agrahn_v3, 2026-10-30) applies Spotless to its root project
        # only, with target("**/*.kt"): ":app:spotlessApply" does not exist,
        # and the module task was the last thing tried.
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, files={TEST: "class HashTest {\n}\n"})
            (root / "build.gradle.kts").write_text(
                'plugins { id("com.diffplug.spotless") }\n'
                'spotless { kotlin { target("**/*.kt"); ktfmt("0.64").googleStyle() } }\n',
                encoding="utf-8")
            _git(root, "commit", "-qam", "spotless")
            (root / TEST).write_text("class HashTest {\n" + LONG + "}\n", encoding="utf-8")
            calls: list = []

            def gradle(command, cwd, env, timeout):
                calls.append(command)
                task = next(part for part in command[1:] if not part.startswith("-"))
                if task.startswith(":app:"):
                    return subprocess.CompletedProcess(
                        command, 1, "", "Task 'spotlessApply' not found in project ':app'.")
                (root / TEST).write_text("class HashTest {\n" + WRAPPED + "}\n",
                                         encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "BUILD SUCCESSFUL", "")

            record = rf.format_patch(root, [TEST], rf.texts_at(root, "HEAD", [TEST]),
                                     runner=gradle)
            self.assertEqual(record["status"], "FORMATTED", record.get("note"))
            self.assertEqual((root / TEST).read_text(encoding="utf-8"),
                             "class HashTest {\n" + WRAPPED + "}\n")
        self.assertEqual(calls[-1][1], "spotlessApply")
        self.assertTrue(calls[-1][2].startswith("-PspotlessIdeHook="))


class FormatPatchTests(unittest.TestCase):

    def _patched(self, directory: str) -> Path:
        root = _project(directory, KTFMT_BUILD, KTFMT_CATALOG, {
            TEST: "class HashTest {\n}\n", OTHER: "fun   other() = 1\n"})
        (root / TEST).write_text("class HashTest {\n" + LONG + "}\n", encoding="utf-8")
        return root

    def _formatter(self, root: Path, calls: list, outcomes: list | None = None):
        """A fake Gradle: wraps the long line and reformats an unrelated file."""
        outcomes = list(outcomes or [])

        def run(command, cwd, env, timeout):
            calls.append(command)
            if outcomes:
                returncode, output = outcomes.pop(0)
                if returncode:
                    return subprocess.CompletedProcess(command, returncode, output, "")
            (root / TEST).write_text("class HashTest {\n" + WRAPPED + "}\n", encoding="utf-8")
            (root / OTHER).write_text("fun other() = 1\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "BUILD SUCCESSFUL", "")
        return run

    def test_the_patch_lines_are_wrapped_and_other_files_put_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._patched(directory)
            calls: list = []
            record = rf.format_patch(root, [TEST], rf.texts_at(root, "HEAD", [TEST]),
                                     runner=self._formatter(root, calls))
            self.assertEqual(record["status"], "FORMATTED")
            self.assertEqual((root / TEST).read_text(encoding="utf-8"),
                             "class HashTest {\n" + WRAPPED + "}\n")
            self.assertEqual((root / OTHER).read_text(encoding="utf-8"), "fun   other() = 1\n")
            self.assertEqual(record["reverted_outside_patch"], [OTHER])
        self.assertIn(":app:ktfmtFormatTest", calls[0])
        self.assertNotIn("overlong_patch_lines", record)

    def test_release_signing_properties_get_the_build_steps_placeholders(self):
        # NotallyX's app/build.gradle.kts reads RELEASE_STORE_FILE while it
        # configures, so its formatting task stopped there (2026-10-30).
        failure = ("Build file '{}' line: 1\n* What went wrong:\nCannot query the value of "
                   "Gradle property 'RELEASE_STORE_FILE' because it has no value available.")
        with tempfile.TemporaryDirectory() as directory:
            root = self._patched(directory)
            build = root / "app/build.gradle.kts"
            build.write_text('storeFile = file(providers.gradleProperty("RELEASE_STORE_FILE")'
                             '.get())\n' + KTFMT_BUILD, encoding="utf-8")
            calls: list = []
            record = rf.format_patch(
                root, [TEST], rf.texts_at(root, "HEAD", [TEST]),
                runner=self._formatter(root, calls, [(1, failure.format(build))]))
        self.assertEqual(record["status"], "FORMATTED")
        self.assertIn("-PRELEASE_STORE_FILE=cognalys-unused", calls[1])

    def test_a_missing_source_set_task_falls_back_to_the_module_task(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._patched(directory)
            calls: list = []
            record = rf.format_patch(
                root, [TEST], rf.texts_at(root, "HEAD", [TEST]),
                runner=self._formatter(root, calls, [
                    (1, "Task 'ktfmtFormatTest' not found in project ':app'.")]))
        self.assertEqual(record["status"], "FORMATTED")
        self.assertIn(":app:ktfmtFormat", calls[1])
        self.assertNotIn("--include-only", " ".join(calls[1]))

    def test_a_failing_formatter_leaves_the_patch_as_it_was(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._patched(directory)

            def half_written(command, cwd, env, timeout):
                (root / TEST).write_text("garbage", encoding="utf-8")
                (root / OTHER).write_text("garbage", encoding="utf-8")
                return subprocess.CompletedProcess(command, 1, "Compilation error", "")

            record = rf.format_patch(root, [TEST], rf.texts_at(root, "HEAD", [TEST]),
                                     runner=half_written)
            self.assertEqual(record["status"], "FAILED")
            self.assertIn("Compilation error", record["note"])
            self.assertEqual((root / TEST).read_text(encoding="utf-8"),
                             "class HashTest {\n" + LONG + "}\n")
            self.assertEqual((root / OTHER).read_text(encoding="utf-8"), "fun   other() = 1\n")

    def test_a_timeout_leaves_the_patch_as_it_was(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._patched(directory)

            def slow(command, cwd, env, timeout):
                raise subprocess.TimeoutExpired(command, timeout)

            record = rf.format_patch(root, [TEST], rf.texts_at(root, "HEAD", [TEST]),
                                     timeout=5, runner=slow)
        self.assertEqual(record["status"], "FAILED")
        self.assertIn("timed out after 5s", record["note"])

    def test_a_crlf_file_keeps_its_line_endings_and_only_the_patch_lines_change(self):
        # Reading with universal newlines turned every CRLF line into a line
        # "the patch wrote" (the base keeps its \r) and wrote the file back
        # with LF: the whole file changed in the diff, failed formatter or not.
        crlf_before = b"class HashTest {\r\n    fun   other() = 1\r\n}\r\n"
        crlf_patched = (b"class HashTest {\r\n    fun   other() = 1\r\n"
                        + LONG.replace("\n", "\r\n").encode() + b"}\r\n")
        for returncode in (0, 1):
            with tempfile.TemporaryDirectory() as directory:
                root = _project(directory, KTFMT_BUILD, KTFMT_CATALOG)
                (root / TEST).parent.mkdir(parents=True)
                (root / TEST).write_bytes(crlf_before)
                _git(root, "add", "-A")
                _git(root, "commit", "-qm", "crlf")
                (root / TEST).write_bytes(crlf_patched)

                def ktfmt(command, cwd, env, timeout, returncode=returncode):
                    # ktfmt keeps the file's line separator and reformats all of it.
                    (root / TEST).write_bytes(
                        b"class HashTest {\r\n    fun other() = 1\r\n"
                        + WRAPPED.replace("\n", "\r\n").encode() + b"}\r\n")
                    return subprocess.CompletedProcess(command, returncode, "", "error")

                record = rf.format_patch(root, [TEST], rf.texts_at(root, "HEAD", [TEST]),
                                         runner=ktfmt)
                result = (root / TEST).read_bytes()
            if returncode:
                self.assertEqual(record["status"], "FAILED")
                self.assertEqual(result, crlf_patched)
            else:
                self.assertEqual(record["status"], "FORMATTED")
                self.assertEqual(result, b"class HashTest {\r\n    fun   other() = 1\r\n"
                                 + WRAPPED.replace("\n", "\r\n").encode() + b"}\r\n")

    def test_an_eol_crlf_repository_formats_only_the_patch_lines(self):
        # .gitattributes eol=crlf: the blob is LF and the checkout CRLF. Read
        # with git show, the base differed from the file on every line, all
        # of them counted as written by the patch, and the formatter's change
        # to an unrelated line was kept (2026-10-30 review).
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, KTFMT_BUILD, KTFMT_CATALOG,
                            {".gitattributes": "*.kt text eol=crlf\n"})
            (root / TEST).parent.mkdir(parents=True)
            (root / TEST).write_bytes(b"class HashTest {\r\n    fun   other() = 1\r\n}\r\n")
            _git(root, "add", "-A")
            _git(root, "commit", "-qm", "crlf")
            self.assertNotIn(b"\r", subprocess.run(
                ["git", "-C", str(root), "show", f"HEAD:{TEST}"],
                check=True, capture_output=True).stdout)
            (root / TEST).write_bytes(b"class HashTest {\r\n    fun   other() = 1\r\n"
                                      + LONG.replace("\n", "\r\n").encode() + b"}\r\n")
            before = rf.texts_at(root, "HEAD", [TEST])
            self.assertEqual(before[TEST], "class HashTest {\r\n    fun   other() = 1\r\n}\r\n")

            def ktfmt(command, cwd, env, timeout):
                (root / TEST).write_bytes(
                    b"class HashTest {\r\n    fun other() = 1\r\n"
                    + WRAPPED.replace("\n", "\r\n").encode() + b"}\r\n")
                return subprocess.CompletedProcess(command, 0, "", "")

            record = rf.format_patch(root, [TEST], before, runner=ktfmt)
            self.assertEqual(record["status"], "FORMATTED")
            self.assertEqual((root / TEST).read_bytes(),
                             b"class HashTest {\r\n    fun   other() = 1\r\n"
                             + WRAPPED.replace("\n", "\r\n").encode() + b"}\r\n")

    def _wrapper(self, root: Path, script: str) -> None:
        (root / "gradlew").write_text("#!/bin/sh\n" + script, encoding="utf-8")
        (root / "gradlew").chmod(0o755)
        _git(root, "commit", "-qm", "wrapper", "--", "gradlew")

    @unittest.skipIf(os.name == "nt", "process groups are POSIX")
    def test_a_timeout_stops_every_process_the_formatter_started(self):
        # Killing the Gradle client alone leaves its daemon and workers
        # running (apk_build.kill_process_group); a worker that outlived the
        # timeout rewrote a file outside the patch after it was put back.
        with tempfile.TemporaryDirectory() as directory:
            root = self._patched(directory)
            self._wrapper(root, f"(sleep 2; echo late > {OTHER}) &\nsleep 30\n")
            record = rf.format_patch(root, [TEST], rf.texts_at(root, "HEAD", [TEST]),
                                     timeout=1)
            time.sleep(3)
            self.assertEqual(record["status"], "FAILED")
            self.assertEqual((root / OTHER).read_text(encoding="utf-8"), "fun   other() = 1\n")

    @unittest.skipIf(os.name == "nt", "process groups are POSIX")
    def test_a_client_that_never_exits_after_build_successful_still_formats(self):
        # Salty's Gradle client printed BUILD SUCCESSFUL and never exited
        # (2026-10-29); apk_build.run_gradle takes the outcome from that line
        # instead of waiting for the timeout and discarding the formatting.
        with tempfile.TemporaryDirectory() as directory:
            root = self._patched(directory)
            (root / "wrapped.txt").write_text("class HashTest {\n" + WRAPPED + "}\n",
                                              encoding="utf-8")
            self._wrapper(root, f"cp wrapped.txt {TEST}\necho 'BUILD SUCCESSFUL in 1s'\n"
                                "sleep 60\n")
            started = time.monotonic()
            with mock.patch("cognalys.builds.apk_build.HUNG_CLIENT_GRACE_SECONDS", 2):
                record = rf.format_patch(root, [TEST], rf.texts_at(root, "HEAD", [TEST]),
                                         timeout=45)
            self.assertLess(time.monotonic() - started, 30)
            self.assertEqual(record["status"], "FORMATTED", record.get("note"))

    def test_without_a_formatter_nothing_runs_and_wide_lines_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, files={TEST: "class HashTest {\n}\n",
                                              ".editorconfig": "[*.kt]\nmax_line_length=100\n"})
            (root / TEST).write_text("class HashTest {\n" + LONG + "}\n", encoding="utf-8")
            runner = mock.Mock()
            record = rf.format_patch(root, [TEST], rf.texts_at(root, "HEAD", [TEST]),
                                     runner=runner)
        runner.assert_not_called()
        self.assertEqual(record["status"], "NOT_CONFIGURED")
        self.assertEqual(record["overlong_patch_lines"], {TEST: {"limit": 100, "lines": [2]}})

    def test_a_dirty_file_outside_the_patch_keeps_its_own_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._patched(directory)
            (root / OTHER).write_text("fun   other() = 2\n", encoding="utf-8")
            rf.format_patch(root, [TEST], rf.texts_at(root, "HEAD", [TEST]),
                            runner=self._formatter(root, []))
            self.assertEqual((root / OTHER).read_text(encoding="utf-8"), "fun   other() = 2\n")


class PullRequestStepTests(unittest.TestCase):
    """The PR step formats the patch before its commit (NotallyX#1167)."""

    def _generator(self, root: Path) -> PrGenerator:
        report = root / "execution.json"
        report.write_text("{}", encoding="utf-8")
        return PrGenerator(str(report), str(root / "prs"))

    def test_an_already_committed_patch_is_not_reformatted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, KTFMT_BUILD, KTFMT_CATALOG, {TEST: LONG})
            with mock.patch("cognalys.prs.repository_formatter.format_patch") as step:
                record = self._generator(Path(directory)).format_with_repository_formatter(
                    root, {}, [TEST])
        step.assert_not_called()
        self.assertEqual(record["status"], "NOT_RUN")

    def test_an_uncommitted_patch_is_formatted_against_its_base(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, KTFMT_BUILD, KTFMT_CATALOG, {TEST: "class T\n"})
            base = _git(root, "rev-parse", "HEAD").strip()
            (root / TEST).write_text("class T\n" + LONG, encoding="utf-8")
            with mock.patch("cognalys.prs.repository_formatter.format_patch",
                            return_value={"status": "FORMATTED"}) as step:
                self._generator(Path(directory)).format_with_repository_formatter(
                    root, {"base_commit": base}, [TEST])
        arguments, options = step.call_args
        self.assertEqual(arguments[2], {TEST: "class T\n"})
        self.assertTrue(options["only_layout"])

    def test_what_is_staged_on_a_repair_commit_joins_it_under_the_pr_message(self):
        # NotallyX#1167 went out with "Repair validation compilation for
        # fff072cb8953" under the pull request's own commit; formatting the
        # repaired file would add the same split to any repaired patch.
        from cognalys.validation.repair import commit_repair
        with tempfile.TemporaryDirectory() as directory:
            root = _project(directory, files={TEST: "class T\n"})
            (root / TEST).write_text("class T2\n", encoding="utf-8")
            commit_repair(root, [TEST], "f167efd80107")
            (root / TEST).write_text("class T2 // formatted\n", encoding="utf-8")
            self._generator(Path(directory)).commit_changes(
                root, "Use SHA-256", changed_files=[TEST])
            subjects = _git(root, "log", "--format=%s").split("\n")
            self.assertEqual(subjects[:2], ["Use SHA-256", "base"])
            self.assertEqual(_git(root, "status", "--porcelain"), "")


if __name__ == "__main__":
    unittest.main()
