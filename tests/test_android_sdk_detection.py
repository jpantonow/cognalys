import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (scripts/ and src/ on sys.path)


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "cognalys" / "builds" / "apk_build.py"
SPEC = importlib.util.spec_from_file_location("builds.apk_build", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class AndroidSdkDetectionTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "host compatibility rule applies on Linux")
    def test_rejects_windows_only_sdk_on_linux(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk = Path(directory)
            tools = sdk / "build-tools" / "37.0.0"
            tools.mkdir(parents=True)
            (tools / "aapt.exe").write_bytes(b"windows")

            self.assertFalse(MODULE.sdk_matches_host(sdk))

    @unittest.skipIf(os.name == "nt", "host compatibility rule applies on Linux")
    def test_accepts_linux_sdk_on_linux(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk = Path(directory)
            tools = sdk / "build-tools" / "37.0.0"
            tools.mkdir(parents=True)
            (tools / "aapt").write_bytes(b"linux")

            self.assertTrue(MODULE.sdk_matches_host(sdk))

    def test_prefers_native_home_sdk_before_inferred_windows_sdk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / "home" / "Android" / "Sdk"
            native.mkdir(parents=True)
            windows = root / "windows-sdk"
            windows.mkdir()

            with patch.object(MODULE.Path, "home", return_value=root / "home"), \
                    patch.object(MODULE, "infer_windows_user_from_cwd",
                                 return_value="Antonow"), \
                    patch.object(MODULE, "existing_path_from") as existing:
                existing.side_effect = lambda value: (
                    native if value == str(native)
                    else windows if value and str(value).startswith("/mnt/c/")
                    else None
                )
                with patch.dict(os.environ, {}, clear=True):
                    detected = MODULE.detect_android_sdk(None)

            self.assertEqual(detected, native)

    def test_classifies_unsupported_kotlin_target_as_infrastructure(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text(
                "Failed to calculate jvmTarget\nUnknown Kotlin JVM target: 21\n",
                encoding="utf-8",
            )

            self.assertEqual(
                MODULE.classify_gradle_failure(log),
                "incompatible_build_jdk_for_kotlin_plugin",
            )

    def test_classifies_a_jlink_failure_on_a_newer_jdk_but_not_on_17(self):
        failure = ("> Execution failed for JdkImageTransform: /sdk/platforms/android-34/"
                   "core-for-system-modules.jar.\n   > Error while executing process "
                   "{jdk}/bin/jlink with arguments {{--module-path x}}\n")
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text(failure.format(jdk="/usr/lib/jvm/java-21-openjdk-amd64"), encoding="utf-8")
            self.assertEqual(MODULE.classify_gradle_failure(log),
                             "incompatible_build_jdk_for_android_jdk_image")
            log.write_text(failure.format(jdk="/usr/lib/jvm/java-17-openjdk-amd64"), encoding="utf-8")
            self.assertIsNone(MODULE.classify_gradle_failure(log))

    def test_does_not_classify_source_compilation_error_as_infrastructure(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text("error: unresolved reference: enabledProtocols\n")

            self.assertIsNone(MODULE.classify_gradle_failure(log))


class BuildOutcomeTests(unittest.TestCase):
    """A task that never promised an APK must not be failed for lacking one."""

    def test_test_only_task_without_apk_is_a_success(self):
        self.assertEqual(
            MODULE.build_outcome("compileDebugUnitTestJavaWithJavac", 0, 0, None),
            ("success", ""),
        )

    def test_assemble_task_without_apk_still_fails(self):
        self.assertEqual(
            MODULE.build_outcome("assembleDebug", 0, 0, None),
            ("failed", "no_apk_found_after_successful_build"),
        )

    def test_assemble_task_with_apk_is_a_success(self):
        self.assertEqual(
            MODULE.build_outcome("assembleDebug", 0, 2, None),
            ("success", ""),
        )

    def test_a_mixed_task_line_stops_requiring_an_apk(self):
        # Deliberately lenient: the APK requirement exists only to catch a
        # silent assemble failure, so any test/compile task in the line
        # waives it rather than risk failing a build that did its job.
        self.assertEqual(
            MODULE.build_outcome("assembleDebug testDebugUnitTest", 0, 0, None),
            ("success", ""),
        )

    def test_a_nonzero_return_code_reports_the_gradle_code(self):
        self.assertEqual(
            MODULE.build_outcome("assembleDebug", 1, 0, None),
            ("failed", "gradle_return_code_1"),
        )

    def test_an_infrastructure_reason_outranks_every_other_verdict(self):
        self.assertEqual(
            MODULE.build_outcome("assembleDebug", 1, 0, "android_sdk_missing"),
            ("infrastructure_failure", "android_sdk_missing"),
        )



class JdkSelectionTests(unittest.TestCase):
    """An old Gradle wrapper fails on a newer JDK before reading the build."""

    def _wrapper(self, root, version):
        properties = root / "gradle" / "wrapper" / "gradle-wrapper.properties"
        properties.parent.mkdir(parents=True)
        properties.write_text(
            "distributionUrl=https\\://services.gradle.org/distributions/"
            f"gradle-{version}-bin.zip\n", encoding="utf-8")

    def test_gradle_7_6_gets_the_newest_jdk_it_runs_on(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._wrapper(root, "7.6.4")
            jdks = {17: Path("/jdk17"), 21: Path("/jdk21")}
            self.assertEqual(MODULE.compatible_java_home(root, jdks), Path("/jdk17"))

    def test_a_recent_gradle_keeps_the_newest_jdk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._wrapper(root, "8.9")
            jdks = {17: Path("/jdk17"), 21: Path("/jdk21")}
            self.assertEqual(MODULE.compatible_java_home(root, jdks), Path("/jdk21"))

    def test_no_choice_without_a_wrapper_or_a_compatible_jdk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNone(MODULE.compatible_java_home(root, {21: Path("/jdk21")}))
            self._wrapper(root, "6.1.1")
            self.assertIsNone(MODULE.compatible_java_home(root, {21: Path("/jdk21")}))

    def test_a_declared_newer_java_selects_the_smallest_jdk_at_or_above_it(self):
        """keyholm: Gradle 9.8 with JavaVersion.VERSION_25 cannot compile on 21."""
        jdks = {17: Path("/jdk17"), 21: Path("/jdk21"), 25: Path("/jdk25")}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._wrapper(root, "9.8.2")
            # Nothing declared: a Gradle 9 project stays on 21.
            self.assertEqual(MODULE.compatible_java_home(root, jdks), Path("/jdk21"))
            (root / "app").mkdir()
            (root / "app" / "build.gradle.kts").write_text(
                "compileOptions {\n  sourceCompatibility = JavaVersion.VERSION_25\n}\n")
            self.assertEqual(MODULE.compatible_java_home(root, jdks), Path("/jdk25"))
            # Never above what the wrapper runs on: Gradle 8.9 runs on 22 at most.
            self._wrapper_version(root, "8.9")
            self.assertEqual(MODULE.compatible_java_home(root, jdks), Path("/jdk21"))

    def test_a_declared_older_java_never_lowers_the_choice(self):
        """Android Gradle Plugin 8 needs JDK 17 to run, whatever target the app has."""
        jdks = {11: Path("/jdk11"), 17: Path("/jdk17"), 21: Path("/jdk21")}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._wrapper(root, "8.9")
            (root / "build-logic" / "src").mkdir(parents=True)
            (root / "build-logic" / "src" / "Android.kt").write_text("jvmToolchain(11)\n")
            self.assertEqual(MODULE.declared_java_version(root), 11)
            self.assertEqual(MODULE.compatible_java_home(root, jdks), Path("/jdk21"))

    def test_an_old_gradle_gets_jdk_11_once_installed(self):
        """ech_apps: Gradle 7.2 runs on JDK 16 at most."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._wrapper(root, "7.2")
            jdks = {11: Path("/jdk11"), 17: Path("/jdk17"), 21: Path("/jdk21")}
            self.assertEqual(MODULE.compatible_java_home(root, jdks), Path("/jdk11"))

    def test_the_table_follows_gradles_compatibility_matrix(self):
        self.assertEqual(MODULE.newest_supported_jdk((9, 1)), 25)
        self.assertEqual(MODULE.newest_supported_jdk((8, 14)), 24)
        self.assertEqual(MODULE.newest_supported_jdk((8, 10)), 23)
        self.assertEqual(MODULE.newest_supported_jdk((8, 9)), 22)

    def _wrapper_version(self, root, version):
        (root / "gradle" / "wrapper" / "gradle-wrapper.properties").write_text(
            "distributionUrl=https\\://services.gradle.org/distributions/"
            f"gradle-{version}-bin.zip\n", encoding="utf-8")

    @unittest.skipIf(os.name == "nt", "a JDK home holds bin/java on POSIX")
    def test_installed_jdks_are_read_from_their_directory_names(self):
        with tempfile.TemporaryDirectory() as directory:
            jvm = Path(directory)
            for name in ("java-17-openjdk-amd64", "java-1.8.0-openjdk", "default-java"):
                (jvm / name / "bin").mkdir(parents=True)
                (jvm / name / "bin" / "java").write_text("", encoding="utf-8")
            self.assertEqual(sorted(MODULE.installed_jdks([jvm])), [8, 17])


if __name__ == "__main__":
    unittest.main()


class LocalPropertiesProvisioningTests(unittest.TestCase):
    """A gitignored local.properties must not stop a patch being validated.

    local.properties is per-developer and gitignored, so no clone or worktree
    ever has one. An Android build script that reads it fails during Gradle
    configuration -- before compiling anything -- so the generated patch is
    never validated at all. hanjoongcho/aaf-easydiary's app/build.gradle.kts
    loads it unconditionally and casts storePassword/storeFile to String, and
    run_20260908_163511 died there with a correct, applied Zip Slip fix in
    hand. Nothing signed with the generated keystore is ever distributed; it
    exists so such a project can configure.
    """

    class _Log:
        def __init__(self):
            self.text = ""

        def write(self, value):
            self.text += value

    def test_writes_the_sdk_path_and_signing_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keystore = root / "validation.jks"
            keystore.write_bytes(b"")
            MODULE.ensure_local_properties(
                root, "/opt/android-sdk", keystore, self._Log()
            )
            written = (root / "local.properties").read_text()
        self.assertIn("sdk.dir=/opt/android-sdk", written)
        self.assertIn("storeFile=", written)
        self.assertIn("storePassword=", written)
        self.assertIn("keyAlias=", written)
        self.assertIn("keyPassword=", written)

    def test_an_existing_file_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "local.properties").write_text("sdk.dir=/mine\n")
            MODULE.ensure_local_properties(
                root, "/opt/android-sdk", root / "k.jks", self._Log()
            )
            self.assertEqual(
                (root / "local.properties").read_text(), "sdk.dir=/mine\n"
            )

    def test_a_windows_sdk_path_is_written_with_forward_slashes(self):
        """Backslash is an escape character in a .properties file."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            MODULE.ensure_local_properties(
                root, r"C:\Android\Sdk", None, self._Log()
            )
            written = (root / "local.properties").read_text()
        self.assertNotIn("\\", written)

    def test_without_a_keystore_only_the_sdk_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            MODULE.ensure_local_properties(
                root, "/opt/android-sdk", None, self._Log()
            )
            written = (root / "local.properties").read_text()
        self.assertIn("sdk.dir=", written)
        self.assertNotIn("storeFile", written)

    def test_nothing_is_written_when_there_is_nothing_to_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            MODULE.ensure_local_properties(root, "", None, self._Log())
            self.assertFalse((root / "local.properties").exists())

    def test_a_missing_keytool_degrades_instead_of_failing(self):
        with tempfile.TemporaryDirectory() as directory:
            log = self._Log()
            with patch.object(MODULE.shutil, "which", return_value=None):
                self.assertIsNone(MODULE.ensure_validation_keystore(
                    Path(directory) / "signing", {}, log
                ))
            self.assertIn("keytool", log.text)

    def test_an_existing_keystore_is_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            (cache / "validation.jks").write_bytes(b"existing")
            with patch.object(MODULE.subprocess, "run") as run:
                keystore = MODULE.ensure_validation_keystore(
                    cache, {}, self._Log()
                )
            run.assert_not_called()
            self.assertEqual(keystore.read_bytes(), b"existing")
