import os
import sys
import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.builds.command import build_invocation  # noqa: E402


class BuildInvocationTests(unittest.TestCase):
    """Validation starts the APK build from scripts/ in a checkout, and from
    the package module where there is no scripts/ (an installed package)."""

    def test_an_existing_build_script_is_run_as_given(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "build_apks_no_proguard.py"
            script.write_text("", encoding="utf-8")
            self.assertEqual(build_invocation(script), [sys.executable, str(script)])

    def test_a_missing_or_unset_script_runs_the_package_module(self):
        module = [sys.executable, "-m", "cognalys.builds.apk_build"]
        self.assertEqual(build_invocation(None), module)
        self.assertEqual(build_invocation(Path("/no/such/build_apks.py")), module)


@unittest.skipIf(sys.platform.startswith("win"), "the executable bit is a POSIX matter")
class GradleWrapperTests(unittest.TestCase):
    """PaperCript commits gradlew without its executable bit."""

    def test_a_wrapper_without_the_executable_bit_runs_through_sh(self):
        from cognalys.builds.apk_build import gradle_command

        with tempfile.TemporaryDirectory() as directory:
            wrapper = Path(directory) / "gradlew"
            wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
            wrapper.chmod(0o644)
            self.assertEqual(gradle_command(Path(directory)), ["sh", str(wrapper)])
            wrapper.chmod(0o755)
            self.assertEqual(gradle_command(Path(directory)), [str(wrapper)])

    def test_a_missing_debug_variant_falls_back_to_the_build_type_task(self):
        """N-Zik's `gradle: [foss]` is a build type: assembleFossDebug does not exist."""
        from types import SimpleNamespace
        from cognalys.builds.apk_build import build_type_task

        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text("Cannot locate tasks that match ':ComposeN-Zik:assembleFossDebug' as "
                           "task 'assembleFossDebug' not found in project ':ComposeN-Zik'.")
            failed = SimpleNamespace(status="failed", log_file=str(log))
            self.assertEqual(build_type_task(":ComposeN-Zik:assembleFossDebug", failed),
                             ":ComposeN-Zik:assembleFoss")
            self.assertEqual(build_type_task(":app:assembleDebug", failed), "")
            log.write_text("e: some compile error")
            self.assertEqual(build_type_task(":ComposeN-Zik:assembleFossDebug", failed), "")

    def test_an_ambiguous_retry_resolves_to_its_one_assemble_candidate(self):
        """moshinda: :mastodon:assembleFdroid was ambiguous with a UnitTest task."""
        from types import SimpleNamespace
        from cognalys.builds.apk_build import ambiguous_task, fallback_task

        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            failed = SimpleNamespace(status="failed", log_file=str(log))
            log.write_text("Cannot locate tasks that match ':mastodon:assembleFdroid' as task "
                           "'assembleFdroid' is ambiguous in project ':mastodon'. Candidates are: "
                           "'assembleFdroidRelease', 'assembleFdroidReleaseUnitTest'.\n")
            self.assertEqual(ambiguous_task(":mastodon:assembleFdroid", failed),
                             ":mastodon:assembleFdroidRelease")
            self.assertEqual(fallback_task(":mastodon:assembleFdroid", failed,
                                           ":mastodon:assembleFdroidDebug",
                                           [":mastodon:assembleFdroidDebug",
                                            ":mastodon:assembleFdroid"]),
                             ":mastodon:assembleFdroidRelease")
            # Two real variants stay ambiguous.
            log.write_text("Cannot locate tasks that match 'assembleFree' as task 'assembleFree' "
                           "is ambiguous in root project 'g'. Candidates are: "
                           "'assembleFreeActive', 'assembleFreeLegacy'.\n")
            self.assertEqual(ambiguous_task("assembleFree", failed), "")

    def test_the_release_task_is_the_last_fallback(self):
        """The build-type retry comes first: N-Zik's and Keryx's builds rely on it."""
        from types import SimpleNamespace
        from cognalys.builds.apk_build import fallback_task

        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            failed = SimpleNamespace(status="failed", log_file=str(log))
            log.write_text("Cannot locate tasks that match ':app:assembleFossDebug' as task "
                           "'assembleFossDebug' not found in project ':app'.")
            requested = ":app:assembleFossDebug"
            self.assertEqual(fallback_task(requested, failed, requested, [requested]),
                             ":app:assembleFoss")
            log.write_text("Cannot locate tasks that match ':app:assembleFoss' as task "
                           "'assembleFoss' not found in project ':app'.")
            self.assertEqual(fallback_task(":app:assembleFoss", failed, requested,
                                           [requested, ":app:assembleFoss"]),
                             ":app:assembleFossRelease")
            self.assertEqual(fallback_task(":app:assembleFossRelease", failed, requested,
                                           [requested, ":app:assembleFoss",
                                            ":app:assembleFossRelease"]), "")
            # A compile error is no reason to try another task.
            log.write_text("e: Unresolved reference 'Libcore'")
            self.assertEqual(fallback_task(requested, failed, requested, [requested]), "")

    def test_an_undefined_signing_property_is_named_for_a_placeholder_retry(self):
        """Librera reads RELEASE_STORE_FILE from the author's gradle.properties."""
        from types import SimpleNamespace
        from cognalys.builds.apk_build import missing_signing_property

        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text("> Could not get unknown property 'RELEASE_STORE_FILE' for "
                           "SigningConfig$AgpDecorated_Decorated{name=release}")
            failed = SimpleNamespace(status="failed", log_file=str(log))
            self.assertEqual(missing_signing_property(failed), "RELEASE_STORE_FILE")
            self.assertEqual(missing_signing_property(SimpleNamespace(status="success", log_file=str(log))), "")
            log.write_text("> Could not get unknown property 'foo' for project ':app'")
            self.assertEqual(missing_signing_property(failed), "")

    def test_a_signing_provider_property_without_value_is_named(self):
        """NotallyX reads RELEASE_STORE_FILE with providers.gradleProperty(...).get()."""
        from types import SimpleNamespace
        from cognalys.builds.apk_build import missing_signing_property

        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "build.gradle.kts"
            script.write_text('signingConfigs {\n  create("release") {\n'
                              '    storeFile = file(providers.gradleProperty("RELEASE_STORE_FILE").get())\n'
                              '  }\n}\nval v = providers.gradleProperty("APP_VERSION").get()\n')
            log = Path(directory) / "build.log"
            failed = SimpleNamespace(status="failed", log_file=str(log))
            message = ("* Where:\nBuild file '{}' line: {}\n\n* What went wrong:\n"
                       "Cannot query the value of Gradle property '{}' because it has no value available.")
            log.write_text(message.format(script, 3, "RELEASE_STORE_FILE"))
            self.assertEqual(missing_signing_property(failed), "RELEASE_STORE_FILE")
            # A property outside the signing fields gets no placeholder.
            log.write_text(message.format(script, 6, "APP_VERSION"))
            self.assertEqual(missing_signing_property(failed), "")

    def test_the_minification_init_script_respects_isolated_projects(self):
        """Kahon: allprojects { plugins } is rejected under isolated projects."""
        from cognalys.builds import apk_build

        script = next(value for name, value in vars(apk_build).items()
                      if isinstance(value, str) and "disableAndroidMinification" in value)
        self.assertIn("gradle.lifecycle.beforeProject", script)

    def test_a_debug_build_whose_keystore_is_missing_is_signed_with_the_debug_key(self):
        """Input Leaf's debug build used the release config and its absent input-leaf.jks."""
        from cognalys.builds import apk_build

        script = apk_build.INIT_GRADLE
        # Defined before the closure that calls it: a Groovy script-level
        # closure sees only the locals declared above it.
        self.assertLess(script.index("def signDebugWithTheDebugKey"),
                        script.index("signDebugWithTheDebugKey(project, androidExt)"))
        self.assertIn("!config.storeFile.exists()", script)
        self.assertIn('signingConfigs.findByName("debug")', script)
        # In afterEvaluate the change came too late: AGP 7+ had locked the DSL.
        self.assertIn("components.finalizeDsl", script)

    def test_a_bash_wrapper_without_the_executable_bit_runs_through_bash(self):
        """J2ME Loader's `#!/usr/bin/env bash` gradlew failed under dash."""
        from cognalys.builds.apk_build import gradle_command

        with tempfile.TemporaryDirectory() as directory:
            wrapper = Path(directory) / "gradlew"
            wrapper.write_text("#!/usr/bin/env bash\nARGS=(a b)\n", encoding="utf-8")
            wrapper.chmod(0o644)
            self.assertEqual(gradle_command(Path(directory)), ["bash", str(wrapper)])

    def test_a_gradlew_without_line_breaks_falls_back_to_the_distribution(self):
        """Vetro's gradlew is one line; a CRLF one asks for /bin/sh\\r."""
        from cognalys.builds import apk_build

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "gradle" / "wrapper").mkdir(parents=True)
            (root / "gradle" / "wrapper" / "gradle-wrapper.properties").write_text(
                "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.5.1-bin.zip\n")
            wrapper = root / "gradlew"
            wrapper.write_bytes(b"#!/bin/sh## Copyright 2015 the original authors.# exec java")
            wrapper.chmod(0o755)
            fallback = root / "dist" / "gradle"
            original = apk_build.wrapper_distribution
            apk_build.wrapper_distribution = lambda gradle_root: fallback
            try:
                self.assertEqual(apk_build.gradle_command(root), [str(fallback)])
                wrapper.write_bytes(b"#!/bin/sh\r\nexec java\r\n")
                self.assertEqual(apk_build.gradle_command(root), [str(fallback)])
                wrapper.write_bytes(b"#!/bin/sh\nexec java\n")
                # A sound script still needs its jar (AnonymousMessenger has none).
                self.assertEqual(apk_build.gradle_command(root), [str(fallback)])
                (root / "gradle" / "wrapper" / "gradle-wrapper.jar").write_bytes(b"PK")
                self.assertEqual(apk_build.gradle_command(root), [str(wrapper)])
            finally:
                apk_build.wrapper_distribution = original

    def test_properties_without_gradlew_run_the_distribution_they_name(self):
        """rssreader keeps gradle-wrapper.properties but not gradlew."""
        import zipfile
        from cognalys.builds.apk_build import wrapper_distribution

        with tempfile.TemporaryDirectory() as directory:
            root, home = Path(directory) / "app", Path(directory) / "gradle_home"
            (root / "gradle" / "wrapper").mkdir(parents=True)
            (root / "gradle" / "wrapper" / "gradle-wrapper.properties").write_text(
                "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.5.1-bin.zip\n")
            fetched = []

            def download(url, destination):
                fetched.append(url)
                with zipfile.ZipFile(destination, "w") as bundle:
                    bundle.writestr("gradle-9.5.1/bin/gradle", "#!/bin/sh\n")

            script = wrapper_distribution(root, home, download)
            self.assertEqual(fetched, ["https://services.gradle.org/distributions/gradle-9.5.1-bin.zip"])
            self.assertEqual(script.parts[-3:], ("gradle-9.5.1", "bin", "gradle"))
            self.assertTrue(os.access(script, os.X_OK))
            # Unpacked once; the next build reuses it.
            self.assertEqual(wrapper_distribution(root, home, download), script)
            self.assertEqual(len(fetched), 1)

    def test_a_truncated_distribution_url_fetches_nothing(self):
        """Rena-w4b's properties end at "distributionUrl=https\\:" (2026-11-07)."""
        from cognalys.builds.apk_build import wrapper_distribution

        with tempfile.TemporaryDirectory() as directory:
            root, home = Path(directory) / "app", Path(directory) / "gradle_home"
            (root / "gradle" / "wrapper").mkdir(parents=True)
            (root / "gradle" / "wrapper" / "gradle-wrapper.properties").write_text(
                "distributionUrl=https\\:\n")
            fetched = []
            self.assertIsNone(wrapper_distribution(root, home, lambda url, _: fetched.append(url)))
            self.assertEqual(fetched, [])
            self.assertFalse((home / "wrapper").exists())

    def test_inconsistent_jvm_targets_retry_on_the_java_target_jdk(self):
        """P4OC (2026-11-07): javac 17, Kotlin 21 from the JDK it ran on."""
        from unittest import mock
        from cognalys.builds import apk_build

        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text("> Inconsistent JVM Target Compatibility Between Java and Kotlin Tasks\n"
                           "  Inconsistent JVM-target compatibility detected for tasks "
                           "'compileDebugJavaWithJavac' (17) and 'compileDebugKotlin' (21).\n")
            reason = apk_build.classify_gradle_failure(log)
            self.assertEqual(reason, "inconsistent_jvm_target_of_build_jdk")
            result = mock.Mock(reason=reason, log_file=str(log))
            self.assertEqual(apk_build.jdk_to_retry_on(result), 17)
            self.assertEqual(apk_build.jdk_to_retry_on(
                mock.Mock(reason="incompatible_build_jdk_for_kotlin_plugin", log_file="")), 17)
            self.assertIsNone(apk_build.jdk_to_retry_on(mock.Mock(reason="", log_file="")))



class FindApksTests(unittest.TestCase):
    def test_an_up_to_date_rebuild_still_yields_its_apk(self):
        """AmaRadio's second build: every task UP-TO-DATE, nothing rewritten."""
        import time
        from cognalys.builds.apk_build import find_apks

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "app" / "build" / "outputs" / "apk" / "foss" / "debug" / "a_foss.apk"
            apk.parent.mkdir(parents=True)
            apk.write_bytes(b"PK")
            old = time.time() - 3600
            os.utime(apk, (old, old))
            started = time.time()
            self.assertEqual(find_apks(root, started), [])
            self.assertEqual(find_apks(root, started, succeeded=True), [apk])

    def test_a_rebuild_replaces_the_previous_copy_instead_of_adding_one(self):
        from cognalys.builds.apk_build import copy_apks

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "src" / "debug" / "app-debug.apk"
            other = root / "src" / "release" / "app-debug.apk"
            for path in (apk, other):
                path.parent.mkdir(parents=True)
                path.write_bytes(b"PK")
            out = root / "out"
            copy_apks("app", [apk], out)
            copy_apks("app", [apk], out)
            self.assertEqual(sorted(p.name for p in (out / "apks" / "app").iterdir()),
                             ["app-debug.apk"])
            # Two of one build sharing a name are still both kept.
            copied = copy_apks("app", [apk, other], out)
            self.assertEqual(len(set(copied)), 2)

class R8AndMinificationTests(unittest.TestCase):
    """Password Store (2026-10-25): a fallback built an R8 release APK, its
    convention plugin computing isMinifyEnabled where the override never looked."""

    def test_the_dex_marker_tells_r8_release_from_d8(self):
        import zipfile
        from cognalys.builds.apk_build import r8_optimized_apk

        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "app.apk"
            with zipfile.ZipFile(apk, "w") as bundle:
                bundle.writestr("classes.dex", b'~~D8{"backend":"dex","compilation-mode":"debug"}')
                bundle.writestr("classes2.dex", b'~~D8{"compilation-mode":"release"}')
            self.assertFalse(r8_optimized_apk(apk))
            with zipfile.ZipFile(apk, "w") as bundle:
                bundle.writestr("classes.dex", b'~~R8{"backend":"dex","compilation-mode":"release",'
                                               b'"r8-mode":"full"}')
                bundle.writestr("classes2.dex", b"no marker")
            self.assertTrue(r8_optimized_apk(apk))
            self.assertFalse(r8_optimized_apk(Path(directory) / "missing.apk"))

    def test_a_librarys_r8_marker_in_a_d8_build_is_not_r8(self):
        """Inure's debug APK: D8 dexed a library that carries its own R8 marker."""
        import zipfile
        from cognalys.builds.apk_build import r8_optimized_apk

        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "app.apk"
            with zipfile.ZipFile(apk, "w") as bundle:
                bundle.writestr("classes.dex", b'~~R8{"compilation-mode":"release"}'
                                               b'~~D8{"compilation-mode":"debug"}')
            self.assertFalse(r8_optimized_apk(apk))
            with zipfile.ZipFile(apk, "w") as bundle:
                bundle.writestr("classes.dex", b'~~R8{"compilation-mode":"release"}')
                bundle.writestr("classes2.dex", b'~~D8{"compilation-mode":"release"}')
            self.assertFalse(r8_optimized_apk(apk))
            with zipfile.ZipFile(apk, "w") as bundle:
                bundle.writestr("classes.dex", b'~~R8{"compilation-mode":"release"}'
                                               b'~~L8{"compilation-mode":"release"}')
            self.assertTrue(r8_optimized_apk(apk), "L8's desugar library goes with R8")

    def test_computed_flags_in_kotlin_convention_plugins_are_turned_off_and_restored(self):
        import io
        from cognalys.builds.apk_build import disabled_minification_in_build_files

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin = root / "build-logic" / "src" / "main" / "kotlin" / "ApplicationPlugin.kt"
            plugin.parent.mkdir(parents=True)
            original = ("release {\n"
                        "    isMinifyEnabled = !minifySwitch.isPresent\n"
                        "    isShrinkResources = providers.gradleProperty(\"shrink\").isPresent // why\n"
                        "    if (isMinifyEnabled == true) println(\"minifyEnabled ${x}\")\n"
                        "    isMinifyEnabled = minify &&\n        other\n"
                        "}\n")
            plugin.write_text(original)
            groovy = root / "app" / "build.gradle"
            groovy.parent.mkdir()
            groovy.write_text("release {\n    minifyEnabled project.hasProperty('minify')\n}\n")
            with disabled_minification_in_build_files(root, True, io.StringIO()):
                patched = plugin.read_text()
                self.assertIn("isMinifyEnabled = false\n    isShrinkResources = false\n", patched)
                self.assertIn("isMinifyEnabled == true", patched, "a comparison is left alone")
                self.assertIn("isMinifyEnabled = minify &&\n", patched,
                              "a value continued on the next line is left alone")
                self.assertIn("minifyEnabled false", groovy.read_text())
            self.assertEqual(plugin.read_text(), original)

    def test_a_flag_that_is_only_read_is_left_alone(self):
        import io
        from cognalys.builds.apk_build import disabled_minification_in_build_files

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin = root / "buildSrc" / "src" / "main" / "kotlin" / "Release.kt"
            plugin.parent.mkdir(parents=True)
            reads = ("    val changed = isMinifyEnabled != other\n"
                     "    val m = isMinifyEnabled as Boolean\n"
                     "    val both = isMinifyEnabled and isShrinkResources\n"
                     "    println \"minifyEnabled is \" + minify\n"
                     "    isMinifyEnabled != other\n"
                     "    isMinifyEnabled as Boolean\n")
            assigned = ("    buildType.isMinifyEnabled = minify.get()\n"
                        "    applied = true; minifyEnabled hasMinify\n")
            plugin.write_text("fun f() {\n" + reads + assigned + "}\n")
            with disabled_minification_in_build_files(root, True, io.StringIO()):
                patched = plugin.read_text()
                self.assertIn(reads, patched)
                self.assertIn("    buildType.isMinifyEnabled = false\n"
                              "    applied = true; minifyEnabled false\n", patched)


class FallbackChainTests(unittest.TestCase):
    """apk_build.main's retries: moshinda's ambiguous build type, then the
    release signing properties a release variant reads (NotallyX, Librera)."""

    def _main(self, outcomes):
        from unittest import mock
        from cognalys.builds import apk_build

        calls = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "projects" / "mastodon"
            project.mkdir(parents=True)
            (project / "settings.gradle").write_text("")

            def run_build(project_dir, gradle_root, task, init_script, output_dir, args):
                calls.append((task, list(args.gradle_property)))
                log = root / f"log{len(calls)}.txt"
                status, text, apks = outcomes(task, list(args.gradle_property))
                log.write_text(text)
                copied = []
                for name, dex in apks:
                    import zipfile
                    target = root / "copied" / name
                    target.parent.mkdir(exist_ok=True)
                    with zipfile.ZipFile(target, "w") as bundle:
                        bundle.writestr("classes.dex", dex)
                    copied.append(str(target))
                return apk_build.BuildResult("mastodon", str(project_dir), str(gradle_root), task,
                                             status, 0, 1.0, len(copied), copied, str(log))

            argv = ["apk_build", "--projects-dir", str(root / "projects"), "--output-dir",
                    str(root / "out"), "--task", ":mastodon:assembleFdroidDebug"]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(apk_build, "detect_android_sdk", return_value=root), \
                    mock.patch.object(apk_build, "run_build", side_effect=run_build):
                apk_build.main()
            report = __import__("json").loads((root / "out" / "build_report.json").read_text())
            remaining = sorted(path.name for path in (root / "copied").glob("*.apk")) \
                if (root / "copied").is_dir() else []
        return calls, report[0], remaining

    def test_an_ambiguous_build_type_resolves_and_reruns_the_signing_loop(self):
        not_found = ("Cannot locate tasks that match ':mastodon:assembleFdroidDebug' as task "
                     "'assembleFdroidDebug' not found in project ':mastodon'.")
        ambiguous = ("Cannot locate tasks that match ':mastodon:assembleFdroid' as task "
                     "'assembleFdroid' is ambiguous in project ':mastodon'. Candidates are: "
                     "'assembleFdroidRelease', 'assembleFdroidReleaseUnitTest'.")
        signing = "> Could not get unknown property 'RELEASE_KEY' for SigningConfig{name=release}"

        def outcomes(task, properties):
            if task.endswith("Debug"):
                return "failed", not_found, []
            if task.endswith("assembleFdroid"):
                return "failed", ambiguous, []
            if not properties:
                return "failed", signing, []
            return "success", "", [("app-fdroidRelease.apk", b'~~D8{"compilation-mode":"release"}')]

        calls, result, _ = self._main(outcomes)
        self.assertEqual([task for task, _ in calls],
                         [":mastodon:assembleFdroidDebug", ":mastodon:assembleFdroid",
                          ":mastodon:assembleFdroidRelease", ":mastodon:assembleFdroidRelease"])
        self.assertEqual(calls[-1][1], ["RELEASE_KEY=cognalys-unused"])
        self.assertEqual(result["status"], "success")
        self.assertFalse(result["r8_optimized"], "D8 release keeps the names")

    def test_an_r8_apk_from_a_fallback_is_replaced_by_the_debug_build(self):
        not_found = ("Cannot locate tasks that match ':mastodon:assembleFdroidDebug' as task "
                     "'assembleFdroidDebug' not found in project ':mastodon'.")
        r8 = b'~~R8{"compilation-mode":"release","r8-mode":"full"}'

        def outcomes(task, properties, debug_builds=True):
            if task.endswith("FdroidDebug"):
                return "failed", not_found, []
            if task.endswith("assembleFdroid"):
                return "success", "", [("app-release.apk", r8)]
            if debug_builds:
                return "success", "", [("app-debug.apk", b'~~D8{"compilation-mode":"debug"}')]
            return "failed", "e: error", []

        calls, result, remaining = self._main(outcomes)
        self.assertEqual(calls[-1][0], ":mastodon:assembleDebug")
        self.assertFalse(result["r8_optimized"])
        self.assertEqual(remaining, ["app-debug.apk"])
        calls, result, remaining = self._main(
            lambda task, properties: outcomes(task, properties, debug_builds=False))
        self.assertTrue(result["r8_optimized"], "kept, and flagged")
        self.assertEqual(result["task"], ":mastodon:assembleFdroid")
        self.assertEqual(remaining, ["app-release.apk"])

    def test_a_debug_apk_built_beside_an_r8_one_is_kept_without_a_retry(self):
        """Keryx's flavour retry builds both build types of the flavour."""
        not_found = ("Cannot locate tasks that match ':mastodon:assembleFdroidDebug' as task "
                     "'assembleFdroidDebug' not found in project ':mastodon'.")

        def outcomes(task, properties):
            if task.endswith("FdroidDebug"):
                return "failed", not_found, []
            if task.endswith("assembleFdroid"):
                return "success", "", [("app-fdroid-debug.apk", b'~~D8{"compilation-mode":"debug"}'),
                                       ("app-fdroid-release.apk", b'~~R8{"compilation-mode":"release"}')]
            return "failed", "e: another flavour lacks google-services.json", []

        calls, result, remaining = self._main(outcomes)
        self.assertEqual([task for task, _ in calls],
                         [":mastodon:assembleFdroidDebug", ":mastodon:assembleFdroid"])
        self.assertFalse(result["r8_optimized"])
        self.assertEqual(result["apk_count"], 1)
        self.assertEqual(remaining, ["app-fdroid-debug.apk"])


def _alive(pid: int) -> bool:
    """Whether a process exists and is not a zombie waiting to be reaped."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as handle:
            return handle.read().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


@unittest.skipIf(sys.platform.startswith("win"), "process groups are a POSIX matter")
class HungGradleClientTests(unittest.TestCase):
    """Salty (2026-10-29): BUILD SUCCESSFUL in 4m 56s, then a client that never
    exited, recorded as an hour-long timeout. Each fake gradlew leaves a
    background child behind, which must not outlive the build."""

    def _build(self, script: str, timeout: int = 20):
        from types import SimpleNamespace
        from unittest import mock
        from cognalys.builds import apk_build

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "projects" / "salty"
            project.mkdir(parents=True)
            gradlew = project / "gradlew"
            gradlew.write_text("#!/bin/sh\n" + script, encoding="utf-8")
            gradlew.chmod(0o755)
            args = SimpleNamespace(
                clean_first=False, additional_task=[], gradle_property=[],
                refresh_dependencies=False, android_sdk="", java_home="/usr",
                skip_submodules=True, timeout=timeout, hung_client_grace=1,
                projects_dir=str(root / "projects"),
            )
            with mock.patch.object(apk_build, "ensure_validation_keystore", return_value=None):
                result = apk_build.run_build(
                    project, project, "assembleDebug", None, root / "out", args)
            child = int((project / "child.pid").read_text().strip())
            log = Path(result.log_file).read_text(encoding="utf-8")
        return result, child, log

    def test_build_successful_then_a_hang_is_a_success_and_the_group_is_killed(self):
        result, child, log = self._build(
            "mkdir -p app/build/outputs/apk/debug\n"
            "echo PK > app/build/outputs/apk/debug/app-debug.apk\n"
            "sleep 300 &\necho $! > child.pid\n"
            'echo "BUILD SUCCESSFUL in 4m 56s"\n'
            'echo "38 actionable tasks: 37 executed, 1 up-to-date"\n'
            "sleep 300\n")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.reason, "gradle_client_hung_after_build_successful")
        self.assertEqual(result.return_code, 0)
        self.assertEqual(result.apk_count, 1)
        self.assertLess(result.duration_seconds, 15)
        self.assertIn("did not exit", log)
        self.assertFalse(_alive(child))

    def test_a_silent_sleeper_times_out_and_leaves_no_child(self):
        result, child, log = self._build(
            "sleep 300 &\necho $! > child.pid\nsleep 300\n", timeout=2)
        self.assertEqual(result.status, "timeout")
        self.assertIn("Timed out after 2 seconds.", log)
        self.assertFalse(_alive(child))

    def test_build_failed_then_a_hang_is_a_classified_failure(self):
        failed = ("sleep 300 &\necho $! > child.pid\n"
                  'echo "e: Unknown Kotlin JVM target: 21"\n'
                  'echo "BUILD FAILED in 9s"\nsleep 300\n')
        result, child, _log = self._build(failed)
        self.assertEqual((result.status, result.reason),
                         ("infrastructure_failure", "incompatible_build_jdk_for_kotlin_plugin"))
        self.assertFalse(_alive(child))
        result, child, _log = self._build(failed.replace("Unknown Kotlin JVM target: 21", "boom"))
        self.assertEqual((result.status, result.reason),
                         ("failed", "gradle_client_hung_after_build_failed"))
        self.assertFalse(_alive(child))

    def test_a_step_deadline_stops_the_client_and_everything_it_started(self):
        # The client runs in its own session; the step's group kill reaches
        # only apk_build, whose SIGTERM handler must stop the client's group.
        import os
        import time
        from cognalys.utils.process_tree import run_with_deadline

        inner = (
            "import os, sys\n"
            "from pathlib import Path\n"
            "from cognalys.builds import apk_build\n"
            "apk_build.install_termination_handler()\n"
            "root = Path(sys.argv[1])\n"
            "with open(root / 'build.log', 'w') as log:\n"
            "    apk_build.run_gradle([str(root / 'gradlew')], root, dict(os.environ), log,\n"
            "                         root / 'build.log', timeout=300)\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gradlew = root / "gradlew"
            gradlew.write_text("#!/bin/sh\necho $$ > client.pid\n"
                               "sleep 300 &\necho $! > child.pid\nsleep 300\n",
                               encoding="utf-8")
            gradlew.chmod(0o755)
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
            outcome = run_with_deadline([sys.executable, "-c", inner, str(root)],
                                        env=env, timeout_seconds=6)
            pids = [int((root / name).read_text().strip()) for name in ("client.pid", "child.pid")]
            deadline = time.monotonic() + 20
            while any(_alive(pid) for pid in pids) and time.monotonic() < deadline:
                time.sleep(0.2)
        self.assertTrue(outcome["timed_out"])
        self.assertEqual([pid for pid in pids if _alive(pid)], [])

    def test_only_a_last_end_of_build_line_counts(self):
        from cognalys.builds.apk_build import finished_build_outcome

        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text("> Task :app:assembleDebug\nBUILD SUCCESSFUL in 1s\n"
                           "2 actionable tasks: 2 executed\n\n")
            self.assertEqual(finished_build_outcome(log), "SUCCESSFUL")
            # An included build still printing after the outer line.
            log.write_text("BUILD SUCCESSFUL in 1s\n> Task :build-logic:compileKotlin\n")
            self.assertIsNone(finished_build_outcome(log))
            log.write_text("> Task :app:compileDebugKotlin\n")
            self.assertIsNone(finished_build_outcome(log))

    def test_gradles_own_lines_after_the_summary_still_count(self):
        # Tails of stored build logs (exp_final_20261019 and others): 77 of
        # 251 had one of these after the end-of-build line.
        from cognalys.builds.apk_build import finished_build_outcome

        tails = (
            "37 actionable tasks: 37 executed\nConfiguration cache entry stored.\n",
            "2 actionable tasks: 2 up-to-date\nConfiguration cache entry reused.\n",
            "40 actionable tasks: 40 executed\nConsider enabling configuration cache to "
            "speed up this build: https://docs.gradle.org/9.0/userguide/"
            "configuration_cache_enabling.html\n",
            "Publishing build scan...\nhttps://gradle.com/s/abcdef123\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            for tail in tails:
                with self.subTest(tail=tail.splitlines()[-1]):
                    log.write_text("BUILD SUCCESSFUL in 2m 10s\n" + tail)
                    self.assertEqual(finished_build_outcome(log), "SUCCESSFUL")

    def test_a_hang_after_the_configuration_cache_line_is_judged(self):
        result, child, _log = self._build(
            "mkdir -p app/build/outputs/apk/debug\n"
            "echo PK > app/build/outputs/apk/debug/app-debug.apk\n"
            "sleep 300 &\necho $! > child.pid\n"
            'echo "BUILD SUCCESSFUL in 2m 10s"\n'
            'echo "37 actionable tasks: 37 executed"\n'
            'echo "Configuration cache entry stored."\n'
            "sleep 300\n")
        self.assertEqual(result.reason, "gradle_client_hung_after_build_successful")
        self.assertLess(result.duration_seconds, 15)
        self.assertFalse(_alive(child))


class SubmoduleCommandTests(unittest.TestCase):
    """Element X (2026-10-27): a private submodule sat on a credential
    prompt until the hour-long timeout instead of failing."""

    def test_git_never_waits_for_credentials(self):
        from unittest import mock
        from cognalys.builds import apk_build
        calls = []
        with mock.patch.object(apk_build.subprocess, "run",
                               side_effect=lambda *a, **k: calls.append(k)
                               or mock.Mock(returncode=0)):
            self.assertIsNone(apk_build.run_submodule_commands(
                Path("."), None, 60, {"PATH": "/bin"}))
        for kwargs in calls:
            self.assertEqual(kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")
            self.assertEqual(kwargs["env"]["PATH"], "/bin")
            self.assertIs(kwargs["stdin"], apk_build.subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
