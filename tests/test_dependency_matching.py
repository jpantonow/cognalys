import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.dependency_context import collect_dependency_context  # noqa: E402


class VersionCatalogSplitFormTests(unittest.TestCase):
    """The catalog form that keeps group and name in separate keys.

    dev.dettmer.simplenotes declares androidx-security-crypto that way and
    its dependency_context came back with zero declared dependencies: there
    is no `group:artifact` string anywhere in the file for a coordinate
    pattern to find.
    """

    CATALOG = (
        "[versions]\n"
        "securityCrypto = \"1.1.0\"\n"
        "\n"
        "[libraries]\n"
        "androidx-security-crypto = { group = \"androidx.security\", "
        "name = \"security-crypto\", version.ref = \"securityCrypto\" }\n"
        "inline-version = { group = \"com.example\", name = \"thing\", "
        "version = \"2.0.0\" }\n"
    )

    def _context(self, class_name: str) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "gradle").mkdir()
            (root / "gradle" / "libs.versions.toml").write_text(
                self.CATALOG, encoding="utf-8",
            )
            return collect_dependency_context(root, class_name, "some.apk")

    def test_the_split_form_is_read_with_its_referenced_version(self):
        found = {
            (item["group"], item["artifact"], item["version_expression"])
            for item in self._context(
                "androidx.security.crypto.EncryptedSharedPreferences"
            )["declared_dependencies"]
        }
        self.assertIn(("androidx.security", "security-crypto", "1.1.0"), found)

    def test_an_inline_version_is_read_too(self):
        found = {
            (item["group"], item["artifact"], item["version_expression"])
            for item in self._context("com.example.thing.Thing")[
                "declared_dependencies"
            ]
        }
        self.assertIn(("com.example", "thing", "2.0.0"), found)


class DependencyTreeTests(unittest.TestCase):
    """A class shipped transitively is named nowhere in the build files.

    dev.dettmer.simplenotes declares androidx.security:security-crypto and
    the finding is in com.google.crypto.tink...: Tink arrives through
    security-crypto and shares not one token with it, so no scan of the
    build files can ever identify it.
    """

    TREE = (
        "releaseRuntimeClasspath - Runtime classpath of release.\n"
        "+--- androidx.security:security-crypto:1.1.0\n"
        "|    +--- com.google.crypto.tink:tink-android:1.5.0\n"
        "|    \\--- androidx.annotation:annotation:1.1.0 -> 1.9.1\n"
        "\\--- com.squareup.okhttp3:okhttp:4.12.0\n"
    )

    def _nodes(self) -> dict:
        from cognalys.extraction.dependency_context import parse_dependency_tree
        return {
            (node["group"], node["artifact"]): node
            for node in parse_dependency_tree(self.TREE)
        }

    def test_a_direct_dependency_is_marked_direct(self):
        node = self._nodes()[("androidx.security", "security-crypto")]
        self.assertTrue(node["direct"])
        self.assertEqual(node["reached_through"], "")
        self.assertEqual(node["version_expression"], "1.1.0")

    def test_a_transitive_dependency_names_the_parent_that_pulls_it(self):
        node = self._nodes()[("com.google.crypto.tink", "tink-android")]
        self.assertFalse(node["direct"])
        self.assertEqual(
            node["reached_through"], "androidx.security:security-crypto"
        )
        self.assertEqual(
            node["dependency_path"],
            ["androidx.security:security-crypto",
             "com.google.crypto.tink:tink-android"],
        )

    def test_the_resolved_version_wins_over_the_requested_one(self):
        node = self._nodes()[("androidx.annotation", "annotation")]
        self.assertEqual(node["version_expression"], "1.9.1")


class ThirdPartyAttributionTests(unittest.TestCase):
    """Naming the library even when the artifact cannot be resolved.

    Resolving the real dependency tree needs a warm Gradle cache, and a
    finding that never reaches the build stage never has one:
    dev.dettmer.simplenotes fails `gradlew dependencies --offline` because
    the Android plugin itself was never downloaded. The package still names
    the library, and whether the project declares it is the transitive
    signal.
    """

    def test_the_package_prefix_identifies_the_library(self):
        from cognalys.extraction.dependency_context import owning_package_prefix
        for class_name, expected in (
            ("com.google.crypto.tink.integration.android.AndroidKeystoreAesGcm",
             "com.google.crypto"),
            # Not okhttp3.internal: that names a directory inside OkHttp.
            ("okhttp3.internal.platform.Platform", "okhttp3"),
            ("kotlin.uuid.Uuid", "kotlin.uuid"),
            ("androidx.security.crypto.EncryptedSharedPreferences",
             "androidx.security"),
        ):
            with self.subTest(class_name=class_name):
                self.assertEqual(owning_package_prefix(class_name), expected)

    def test_a_declared_library_is_reported_as_declared(self):
        from cognalys.extraction.dependency_context import third_party_attribution
        attribution = third_party_attribution(
            "okhttp3.internal.platform.Platform",
            [{"group": "com.squareup.okhttp3", "artifact": "okhttp",
              "version_expression": "5.3.2", "source_file_path": "b.gradle"}],
        )
        self.assertTrue(attribution["declared_directly"])
        self.assertEqual(
            attribution["matching_declarations"][0]["artifact"], "okhttp"
        )

    def test_an_undeclared_library_is_the_transitive_signal(self):
        from cognalys.extraction.dependency_context import third_party_attribution
        attribution = third_party_attribution(
            "com.google.crypto.tink.integration.android.AndroidKeystoreAesGcm",
            [{"group": "androidx.security", "artifact": "security-crypto",
              "version_expression": "1.1.0", "source_file_path": "libs.toml"}],
        )
        self.assertEqual(attribution["owning_package"], "com.google.crypto")
        self.assertFalse(attribution["declared_directly"])

    def test_it_states_that_it_names_no_artifact_or_version(self):
        from cognalys.extraction.dependency_context import third_party_attribution
        attribution = third_party_attribution("kotlin.uuid.Uuid", [])
        self.assertIn("not the exact artifact", attribution["bound"])


class CoordinateAnchoringTests(unittest.TestCase):
    """A Maven coordinate is a string literal, not any word:word.

    at.linuxtage.Eventfahrplan's dependency_context came back listing
    "-Xlint:unchecked" and "-Xlint:deprecation" off a compilerArgs line, and
    "HH:mm" out of the date format "yyyy-MM-dd'T'HH:mm'Z'", as candidate
    artifacts -- while the OkHttp declaration the finding was actually about
    went unfound and the run recorded "no dependency artifact was identified
    for it".
    """

    def _context(self, build_gradle: str, class_name: str) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            (root / "app" / "build.gradle").write_text(
                build_gradle, encoding="utf-8",
            )
            return collect_dependency_context(root, class_name, "some.apk")

    def test_compiler_arguments_are_not_dependency_coordinates(self):
        context = self._context(
            'options.compilerArgs << "-Xlint:unchecked" << "-Xlint:deprecation"\n',
            "okhttp3.internal.platform.Platform",
        )
        found = {
            (item["group"], item["artifact"])
            for item in context["declared_dependencies"]
        }
        self.assertNotIn(("-Xlint", "unchecked"), found)
        self.assertNotIn(("-Xlint", "deprecation"), found)

    def test_a_time_format_is_not_a_dependency_coordinate(self):
        context = self._context(
            'return date.format("yyyy-MM-dd\'T\'HH:mm\'Z\'", TimeZone.getDefault())\n',
            "okhttp3.internal.platform.Platform",
        )
        found = {
            (item["group"], item["artifact"])
            for item in context["declared_dependencies"]
        }
        self.assertNotIn(("HH", "mm"), found)

    def test_a_real_quoted_coordinate_is_still_read(self):
        context = self._context(
            '    implementation "com.squareup.okhttp3:okhttp:4.12.0"\n',
            "okhttp3.internal.platform.Platform",
        )
        found = {
            (item["group"], item["artifact"], item["version_expression"])
            for item in context["declared_dependencies"]
        }
        self.assertIn(("com.squareup.okhttp3", "okhttp", "4.12.0"), found)


class ConstantDeclaredDependencyTests(unittest.TestCase):
    """`implementation Libs.okhttp` is how a modern Android project declares
    a dependency, and a scanner that only reads literal coordinates finds
    nothing in one.

    Eventfahrplan names the coordinate in a buildSrc object that nests
    `object Versions` inside `object Libs`, so both the coordinate and the
    version are constants called `okhttp`. Keyed by bare name the version
    wins, `Libs.okhttp` resolves to "5.3.2", and the dependency disappears --
    while its siblings okhttpZstd and okhttpLoggingInterceptor, which collide
    with nothing, resolve fine.
    """

    DEPENDENCIES = (
        "object Libs {\n"
        "    object Versions {\n"
        "        const val okhttp = \"5.3.2\"\n"
        "    }\n"
        "    const val okhttp = "
        "\"com.squareup.okhttp3:okhttp:${Versions.okhttp}\"\n"
        "    const val okhttpZstd = "
        "\"com.squareup.okhttp3:okhttp-zstd:${Versions.okhttp}\"\n"
        "}\n"
    )

    def _context(self, modules: dict, class_name: str) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "buildSrc" / "src" / "main" / "kotlin"
            source.mkdir(parents=True)
            (source / "Dependencies.kt").write_text(
                self.DEPENDENCIES, encoding="utf-8",
            )
            for name, content in modules.items():
                module = root / name
                module.mkdir(parents=True, exist_ok=True)
                (module / "build.gradle").write_text(content, encoding="utf-8")
            return collect_dependency_context(root, class_name, "some.apk")

    def test_the_coordinate_and_version_are_resolved_through_the_constant(self):
        context = self._context(
            {"app": "dependencies {\n    implementation Libs.okhttp\n}\n"},
            "okhttp3.internal.platform.Platform",
        )
        likely = context["likely_dependency"]
        self.assertEqual(context["status"], "identified")
        self.assertEqual(likely["group"], "com.squareup.okhttp3")
        self.assertEqual(likely["artifact"], "okhttp")
        self.assertEqual(likely["version_expression"], "5.3.2")
        self.assertEqual(likely["resolved_through_constant"], "okhttp")

    def test_the_nested_version_constant_does_not_shadow_the_coordinate(self):
        # Both are called okhttp; the qualified reference decides which.
        context = self._context(
            {"app": "dependencies {\n    implementation Libs.okhttp\n}\n"},
            "okhttp3.internal.platform.Platform",
        )
        self.assertNotEqual(
            context["likely_dependency"].get("version_expression"), ""
        )
        self.assertNotIn(
            "$", context["likely_dependency"]["version_expression"]
        )

    def test_one_dependency_declared_by_two_modules_is_not_ambiguous(self):
        declaration = "dependencies {\n    implementation Libs.okhttp\n}\n"
        context = self._context(
            {"app": declaration, "network": declaration},
            "okhttp3.internal.platform.Platform",
        )
        self.assertEqual(context["status"], "identified")

    def test_the_artifact_naming_the_class_root_package_wins(self):
        # okhttp3.* ships in okhttp, not in okhttp-zstd beside it.
        context = self._context(
            {"app": (
                "dependencies {\n"
                "    implementation Libs.okhttp\n"
                "    implementation Libs.okhttpZstd\n"
                "}\n"
            )},
            "okhttp3.internal.platform.Platform",
        )
        self.assertEqual(context["status"], "identified")
        self.assertEqual(context["likely_dependency"]["artifact"], "okhttp")
        self.assertIn(
            "artifact name matches the class root package",
            context["likely_dependency"]["match_reasons"],
        )


class DependencyCandidateMatchingTests(unittest.TestCase):
    """run_20260909_100446 offered org.jetbrains.compose.runtime:runtime and
    three androidx.lifecycle artifacts as the dependency behind
    org.mifos.mobilebanking.api.SelfServiceOkHttpClient. The whole basis was
    the segment "org", which almost every Java package begins with."""

    def _context(self, declarations: str, class_name: str) -> dict:
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        (root / "gradle").mkdir()
        (root / "gradle" / "libs.versions.toml").write_text(
            declarations, encoding="utf-8",
        )
        try:
            return collect_dependency_context(root, class_name, "some.apk")
        finally:
            directory.cleanup()

    def test_a_shared_top_level_segment_scores_nothing(self):
        context = self._context(
            'jb = { module = "org.jetbrains.compose.runtime:runtime", '
            'version.ref = "composeJB" }\n',
            "org.mifos.mobilebanking.api.SelfServiceOkHttpClient",
        )
        scored = [
            item for item in context["dependency_candidates"]
            if item["match_score"] > 0
        ]
        self.assertEqual(scored, [])

    def test_a_real_group_segment_still_scores(self):
        context = self._context(
            'lib = { module = "com.squareup.okhttp3:okhttp", '
            'version = "4.12.0" }\n',
            "com.squareup.okhttp3.OkHttpClient",
        )
        top = context["dependency_candidates"][0]
        self.assertGreaterEqual(top["match_score"], 3)
        self.assertIn(
            "group segments occur in class package", top["match_reasons"],
        )
        self.assertEqual(context["status"], "identified")

    def test_a_segment_is_matched_whole_and_not_as_a_substring(self):
        # "ui" inside "gui", "compose" inside "composer": a substring test
        # scored a group against a class it only happened to spell part of.
        context = self._context(
            'lib = { module = "org.composer.tools:runtime", '
            'version = "1.0" }\n',
            "org.composerly.gui.Widget",
        )
        scored = [
            item for item in context["dependency_candidates"]
            if item["match_score"] > 0
        ]
        self.assertEqual(scored, [])


if __name__ == "__main__":
    unittest.main()
