import io
import tempfile
import unittest
import unittest.mock
import zipfile
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction import apk_evidence  # noqa: E402
from cognalys.extraction.artifact_cache import (  # noqa: E402
    ArtifactCache,
    fetch_library_dependencies,
    locate_method_bytecode,
)
from cognalys.extraction.dependency_context import (  # noqa: E402
    collect_declarations,
    resolve_property_versions,
)
from test_artifact_cache import TINK_CLASS, TINK_SOURCE, _compiled_jar, _pom, _publish  # noqa: E402

GROUP = "com.google.crypto.tink"


def versions_of(repo: Path) -> dict:
    return {item["artifact"]: item["version_expression"]
            for item in collect_declarations(repo)["declarations"]}


def _empty_jar() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    return buffer.getvalue()


class PropertyVersionTests(unittest.TestCase):
    def test_versions_named_by_build_properties_are_resolved(self):
        """retrowars: ext { ktor_version = '1.6.0' } and "io.ktor:...:$ktor_version"."""
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "build.gradle").write_text(
                "buildscript {\n    ext {\n        ktor_version = '1.6.0'\n    }\n}\n"
                "ext.okhttpVersion = \"4.12.0\"\n", encoding="utf-8")
            (repo / "gradle.properties").write_text("coroutines=1.4.2\n", encoding="utf-8")
            (repo / "app").mkdir()
            (repo / "app" / "build.gradle").write_text(
                "dependencies {\n"
                "    implementation \"io.ktor:ktor-client-core:$ktor_version\"\n"
                "    implementation \"com.squareup.okhttp3:okhttp:${rootProject.ext.okhttpVersion}\"\n"
                "    implementation \"org.jetbrains.kotlinx:kotlinx-coroutines-core:${coroutines}\"\n"
                "    implementation \"org.example:unknown:$nowhere\"\n"
                "}\n", encoding="utf-8")
            (repo / "lib").mkdir()
            (repo / "lib" / "build.gradle.kts").write_text(
                'extra["roomVersion"] = "2.6.1"\n'
                'dependencies {\n    implementation("androidx.room:room-runtime:$roomVersion")\n}\n',
                encoding="utf-8")
            versions = versions_of(repo)
        self.assertEqual(versions["ktor-client-core"], "1.6.0")
        self.assertEqual(versions["okhttp"], "4.12.0")
        self.assertEqual(versions["kotlinx-coroutines-core"], "1.4.2")
        self.assertEqual(versions["room-runtime"], "2.6.1")
        # Nothing defines it: left as written, so the record says it is unsettled.
        self.assertEqual(versions["unknown"], "$nowhere")

    def test_a_kotlin_constant_object_is_used_for_qualified_references(self):
        declarations = [{"group": "g", "artifact": "a", "version_expression": "${Versions.okhttp}"}]
        constants = {"Versions.okhttp": {"value": "5.0.0", "source_file_path": "buildSrc/V.kt",
                                         "line": 3}}
        resolve_property_versions(declarations, {}, constants)
        self.assertEqual(declarations[0]["version_expression"], "5.0.0")
        self.assertEqual(declarations[0]["version_resolved_from"], "buildSrc/V.kt:3")


class TransitiveBytecodeTests(unittest.TestCase):
    @staticmethod
    def _publish_core(root: Path) -> None:
        _publish(root, GROUP, "tink-core", "1.0", "tink-core-1.0.pom", _pom(
            GROUP, "tink-core", "1.0", [
                ("com.google.protobuf", "protobuf-java", "3.0", ""),
                (GROUP, "tink-common", "1.0", ""),
                (GROUP, "tink-integration", "1.0", ""),
            ]))

    def test_a_class_a_dependency_down_is_found_in_the_owners_group(self):
        """retrowars' io.ktor.util.CryptoKt is in ktor-utils, under the declared ktor-client-core."""
        with tempfile.TemporaryDirectory() as directory:
            workdir = Path(directory)
            jar = _compiled_jar(workdir, TINK_CLASS, TINK_SOURCE)
            root = workdir / "cache"
            self._publish_core(root)
            _publish(root, GROUP, "tink-core", "1.0", "tink-core-1.0.jar", _empty_jar())
            _publish(root, GROUP, "tink-common", "1.0", "tink-common-1.0.jar", _empty_jar())
            _publish(root, GROUP, "tink-integration", "1.0", "tink-integration-1.0.jar", jar)
            result = locate_method_bytecode(
                [{"group": GROUP, "artifact": "tink-core", "version": "1.0"}],
                TINK_CLASS, "encryptInternal", ArtifactCache([root]),
            )
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["artifact"], f"{GROUP}:tink-integration")
        self.assertEqual(result["transitive_of"], f"{GROUP}:tink-core:1.0")

    def test_other_groups_are_not_followed_and_package_names_go_first(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._publish_core(root)
            result = locate_method_bytecode(
                [{"group": GROUP, "artifact": "tink-core", "version": "1.0"}],
                TINK_CLASS, "encryptInternal", ArtifactCache([root]), javap="javap",
            )
        searched = [entry["coordinate"] for entry in result["searched"]]
        self.assertEqual(searched, [f"{GROUP}:tink-core", f"{GROUP}:tink-integration",
                                    f"{GROUP}:tink-common"])

    def test_metadata_is_not_fetched_offline(self):
        self.assertEqual(fetch_library_dependencies("io.ktor", "ktor-utils", "1.6.0", environ={}), [])


class StoreApkTests(unittest.TestCase):
    ONLINE = {"TCC_ONLINE_DEPENDENCY_RESOLUTION": "1"}

    def test_an_fdroid_name_gives_the_release_and_archive_urls_when_online(self):
        self.assertEqual(apk_evidence.store_apk_urls("com.serwylo.retrowars_70.apk", self.ONLINE),
                         ["https://f-droid.org/repo/com.serwylo.retrowars_70.apk",
                          "https://f-droid.org/archive/com.serwylo.retrowars_70.apk"])
        self.assertEqual(apk_evidence.store_apk_urls("com.serwylo.retrowars_70.apk", {}), [])
        self.assertEqual(apk_evidence.store_apk_urls("app-debug.apk", self.ONLINE), [])

    def test_an_old_release_comes_from_the_archive(self):
        tried = []

        def fetch(url, cache_dir, name):
            tried.append(url)
            if "/repo/" in url:
                raise OSError("HTTP Error 404: Not Found")
            return Path("/cache") / name

        with unittest.mock.patch.dict("os.environ", self.ONLINE):
            path, url, failure = apk_evidence.obtain_apk("a.b_3.apk", "", Path("/cache"), fetch)
        self.assertEqual((path, failure), (Path("/cache/a.b_3.apk"), ""))
        self.assertEqual(url, "https://f-droid.org/archive/a.b_3.apk")
        self.assertEqual(len(tried), 2)

    def test_a_given_apk_is_never_replaced_by_the_store_release(self):
        def fetch(url, cache_dir, name):
            raise ValueError("local APK not found")

        with unittest.mock.patch.dict("os.environ", self.ONLINE):
            path, _, failure = apk_evidence.obtain_apk("a.b_3.apk", "/apks/a.b_3.apk", Path("/c"), fetch)
        self.assertIsNone(path)
        self.assertIn("local APK not found", failure)

    def test_bindings_for_a_method_in_the_checkout_do_not_download_by_name(self):
        def fetch(url, cache_dir, name):
            raise AssertionError("no download expected")

        with unittest.mock.patch.dict("os.environ", self.ONLINE):
            record = apk_evidence.collect_method_bytecode_bindings(
                "a.b_3.apk", "", "a.b.C", "m", Path("/c"), fetch=fetch)
        self.assertEqual(record["reason"], "no_apk_url")


if __name__ == "__main__":
    unittest.main()
