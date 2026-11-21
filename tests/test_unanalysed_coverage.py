import logging
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "src", ROOT / "src" / "cognalys" / "extraction", ROOT / "src" / "cognalys" / "config"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from cognalys.extraction import apk_evidence  # noqa: E402
from cognalys.extraction import dependency_context  # noqa: E402
from cognalys.extraction import extract_methods_single_csv as extraction  # noqa: E402

EXTRACTOR = extraction.MethodExtractor(logging.getLogger("test"))
TREE = (
    "debugRuntimeClasspath\n"
    "+--- com.google.crypto.tink:tink-android:1.7.0\n"
    "\\--- com.squareup.okio:okio:3.9.0\n"
)


def _write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class DependencyTreeTests(unittest.TestCase):
    def _project(self, root: Path) -> Path:
        _write(root, "gradlew", "#!/bin/sh\n").chmod(0o755)
        _write(root, "build.gradle.kts",
               'plugins { id("com.android.application") version "8" apply false }\n')
        _write(root, "app/build.gradle.kts", 'plugins { id("com.android.application") }\n')
        _write(root, "lib/build.gradle.kts", 'plugins { id("com.android.library") }\n')
        return root

    def test_the_application_module_is_asked_for_its_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._project(Path(directory))
            self.assertEqual(dependency_context.application_dependency_tasks(root),
                             [":app:dependencies"])

    def _resolve(self, root, online, offline_output, online_output=TREE):
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            output = offline_output if "--offline" in command else online_output
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

        dependency_context._GRAPH_CACHE.clear()
        environ = {dependency_context.ONLINE_RESOLUTION_ENV: "1"} if online else {}
        with patch.object(dependency_context.subprocess, "run", fake_run), \
                patch.dict(dependency_context.os.environ, environ, clear=False):
            if not online:
                dependency_context.os.environ.pop(dependency_context.ONLINE_RESOLUTION_ENV, None)
            graph = dependency_context.resolve_dependency_graph(root)
        return graph, calls

    def test_offline_failure_is_followed_by_one_online_resolution_when_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._project(Path(directory))
            graph, calls = self._resolve(root, True, "BUILD FAILED")
            self.assertEqual(graph["status"], "available")
            self.assertEqual(graph["resolution"], "online")
            self.assertEqual(len(calls), 2)
            self.assertNotIn("--offline", calls[1])
            self.assertIn(":app:dependencies", calls[1])

    def test_without_the_option_the_network_is_never_used(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._project(Path(directory))
            graph, calls = self._resolve(root, False, "BUILD FAILED")
            self.assertEqual(graph["status"], "unavailable")
            self.assertEqual(len(calls), 1)
            self.assertIn("--offline", calls[0])

    def test_an_offline_tree_needs_no_online_call(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._project(Path(directory))
            graph, calls = self._resolve(root, True, TREE)
            self.assertEqual(graph["resolution"], "offline")
            self.assertEqual(len(calls), 1)


class ApplicationModuleDetectionTests(unittest.TestCase):
    def test_a_catalog_alias_with_any_name_is_found_by_its_application_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(root, "build.gradle.kts", "plugins { alias(libs.plugins.androidApplication) apply false }\n")
            _write(root, "composeApp/build.gradle.kts",
                   "plugins { alias(libs.plugins.androidApplication) }\n"
                   "android { defaultConfig { applicationId = \"com.example\" } }\n")
            _write(root, "shared/build.gradle.kts", "plugins { alias(libs.plugins.androidLibrary) }\n")
            self.assertEqual(dependency_context.application_dependency_tasks(root),
                             [":composeApp:dependencies"])


class OwnerByNameTests(unittest.TestCase):
    def test_jitpack_and_platform_artifacts_rank_by_their_names(self):
        score = dependency_context.owner_name_similarity
        self.assertGreater(score("at.bitfire.cert4android.CustomCertService",
                                 "com.github.bitfireAT", "cert4android"), 0)
        self.assertGreater(score("com.absinthe.rulesbundle.utils.HashUtils",
                                 "com.github.LibChecker", "LibChecker-Rules-Bundle"), 0)
        self.assertEqual(score("io.ktor.network.tls.KeysKt", "com.squareup.okio", "okio"), 0)

    def test_the_plainest_artifact_of_a_family_ranks_first(self):
        owners = dependency_context.name_similar_owners(
            "io.ktor.network.tls.KeysKt",
            [{"group": "io.ktor", "artifact": "ktor-client-android", "version_expression": "3.4.1"},
             {"group": "io.ktor", "artifact": "ktor-network-tls-jvm", "version_expression": "3.4.1"}],
            set(),
        )
        self.assertEqual(owners[0]["artifact"], "ktor-network-tls-jvm")

    def test_a_family_proposes_its_plain_artifact(self):
        owners = dependency_context.name_similar_owners(
            "io.sentry.util.StringUtils",
            [{"group": "io.sentry", "artifact": "sentry-android", "version_expression": "8.14.0"}],
            set(),
        )
        self.assertEqual((owners[0]["artifact"], owners[0]["version"]), ("sentry", "8.14.0"))

    def test_rich_version_constraints_are_read_as_their_version(self):
        nodes = dependency_context.parse_dependency_tree(
            "+--- io.ktor:ktor-network-tls:{strictly 3.4.1} -> 3.4.1\n")
        self.assertEqual(nodes[0]["version_expression"], "3.4.1")


class RepositoryBinaryTests(unittest.TestCase):
    def test_a_class_in_an_aar_the_repository_carries_is_found(self):
        import io
        from cognalys.extraction import artifact_cache

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inner = io.BytesIO()
            with zipfile.ZipFile(inner, "w") as jar:
                jar.writestr("org/flyve/inventory/CryptoUtil.class", b"\xca\xfe\xba\xbe")
            (root / "app" / "libs").mkdir(parents=True)
            with zipfile.ZipFile(root / "app" / "libs" / "inventory-release.aar", "w") as aar:
                aar.writestr("classes.jar", inner.getvalue())
            with patch.object(artifact_cache, "disassemble_method",
                              return_value={"status": "available"}):
                found = artifact_cache.locate_repository_binary_method(
                    root, "org.flyve.inventory.CryptoUtil", "encrypt", javap="javap")
            self.assertEqual(found["status"], "available")
            self.assertEqual(found["source"], "repository_binary")
            self.assertEqual(found["artifact"], "app/libs/inventory-release.aar")


class SubmoduleTests(unittest.TestCase):
    def test_a_repository_without_submodules_is_left_alone(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                extraction.populate_empty_submodules(Path(directory), logging.getLogger("t")), [])


class LibraryDownloadTests(unittest.TestCase):
    def test_nothing_is_downloaded_without_online_resolution(self):
        from cognalys.extraction import artifact_cache

        with patch("urllib.request.urlopen") as urlopen:
            self.assertIsNone(artifact_cache.fetch_library_binary(
                "com.google.crypto.tink", "tink-android", "1.19.0", environ={}))
        urlopen.assert_not_called()

    def test_a_metadata_only_version_is_completed_with_the_downloaded_binary(self):
        from cognalys.extraction import artifact_cache

        class_name = "com.example.Lib"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "files-2.1"
            _write(root, "com.example/lib/1.0/abc/lib-1.0.pom", "<project/>")
            jar = Path(directory) / "lib-1.0.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("com/example/Lib.class", b"\xca\xfe\xba\xbe")
            cache = artifact_cache.ArtifactCache([root])
            with patch.object(artifact_cache, "fetch_library_binary", return_value=jar) as fetch, \
                    patch.object(artifact_cache, "disassemble_method",
                                 return_value={"status": "available"}):
                found = artifact_cache.locate_method_bytecode(
                    [{"group": "com.example", "artifact": "lib", "version": "1.0"}],
                    class_name, "run", cache, javap="javap",
                )
            fetch.assert_called_once_with("com.example", "lib", "1.0")
            self.assertEqual(found["status"], "available")
            self.assertEqual(found["binary"], "lib-1.0.jar")


class ReportedLineTests(unittest.TestCase):
    SOURCE = (
        "package a\n\n"
        "val appModule =\n"
        "    module {\n"
        "        single { Store(get()) }\n"
        "        single { MessageDigest.getInstance(\"SHA-1\") }\n"
        "    }\n"
    )

    def test_the_line_names_the_resolved_file_only(self):
        path = Path("/x/AppModule.kt")
        self.assertEqual(extraction.reported_source_line(
            {"detector_source_location": "AppModule.kt:6"}, path), 6)
        self.assertIsNone(extraction.reported_source_line(
            {"detector_source_location": "Other.kt:6"}, path))
        self.assertIsNone(extraction.reported_source_line({}, path))

    def test_a_property_whose_block_starts_on_the_next_line_contains_the_line(self):
        found = EXTRACTOR._extract_declaration_containing_line(self.SOURCE, 6)
        self.assertIsNotNone(found)
        self.assertTrue(found[0].startswith("val appModule ="))
        self.assertIn('MessageDigest.getInstance("SHA-1")', found[0])
        self.assertEqual((found[1], found[2]), (3, 7))


class LocalApkTests(unittest.TestCase):
    def test_a_local_apk_is_used_where_it_is(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "app_1.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", b"dex")
            for reference in (str(apk), f"file://{apk}"):
                self.assertEqual(
                    apk_evidence.fetch_apk(reference, Path(directory) / "cache", "app_1.apk"),
                    apk,
                )

    def test_a_missing_local_apk_is_an_error_not_a_download(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                apk_evidence.fetch_apk(str(Path(directory) / "none.apk"),
                                       Path(directory), "none.apk")


if __name__ == "__main__":
    unittest.main()
