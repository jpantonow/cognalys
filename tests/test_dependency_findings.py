import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.dependency_context import (  # noqa: E402
    collect_declarations,
    collect_refresh_versions,
)
from cognalys.extraction.dependency_finding import (  # noqa: E402
    change_scale,
    collect_dependency_finding,
    module_build_files,
    parse_finding_message,
    version_satisfies,
)
from cognalys.llm.pipeline_architecture import (  # noqa: E402
    classify_spec_family,
    dependency_declaration_sources,
)
from cognalys.llm.generate_error_fixes import FixGenerator  # noqa: E402


# The messages of data/processed/bibliotecas_deprecadas_pr.csv, verbatim.
OKHTTP = "Using okhttp3 v3.12.0. Update to v4.10.0 or higher."
SUPPORT = ("Found android.support.v4.app.Fragment. Migrate to "
           "androidx.fragment.app.Fragment.")
ASYNCTASK = ("android.os.AsyncTask is deprecated. Use java.util.concurrent or "
             "Kotlin Coroutines.")
JODA = "joda-time library is deprecated. Migrate to java.time (Desugared)."
RXJAVA = "Using rx.Observable (RxJava 1.x) which is EOL. Update to RxJava 3.x."
BROADCAST = ("androidx.localbroadcastmanager.content.LocalBroadcastManager is "
             "deprecated. Use LiveData or Flow.")
GCM = ("com.google.android.gms:play-services-gcm is deprecated. Migrate to "
       "Firebase Cloud Messaging (FCM).")
PICASSO = "Using Picasso 2.5.2. Consider updating to 2.8 or migrating to Coil/Glide."
PREFERENCE = ("android.preference.PreferenceManager is deprecated. Use "
              "androidx.preference.PreferenceManager.")
RETROFIT = "Using Retrofit 1.9.0. Update to Retrofit 2.x for modern features and support."


def _repository(files: dict) -> Path:
    directory = Path(tempfile.mkdtemp())
    for relative, content in files.items():
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return directory


class MessageParsingTests(unittest.TestCase):
    """What each row of the sample names, read without per-library rules."""

    def test_an_outdated_version_with_a_target(self):
        parsed = parse_finding_message(OKHTTP)
        self.assertEqual(parsed["kind"], "dependency_version")
        self.assertEqual(parsed["subjects"][0]["name"], "okhttp3")
        self.assertEqual(parsed["reported_version"], "3.12.0")
        self.assertEqual(parsed["target"]["version"], "4.10.0")
        self.assertEqual(parsed["change_scale"], "major")

    def test_a_major_version_family_is_read_as_a_major_change(self):
        for message, name in ((RXJAVA, "RxJava"), (RETROFIT, "Retrofit")):
            with self.subTest(message=message):
                parsed = parse_finding_message(message)
                self.assertEqual(parsed["kind"], "dependency_version")
                self.assertEqual(parsed["subjects"][0]["name"], name)
                self.assertEqual(parsed["target"]["name"], name)
                self.assertEqual(parsed["change_scale"], "major")
        self.assertEqual(parse_finding_message(RXJAVA)["deprecated_types"], ["rx.Observable"])

    def test_a_minor_update_without_a_named_target(self):
        parsed = parse_finding_message(PICASSO)
        self.assertEqual(parsed["kind"], "dependency_version")
        self.assertEqual(parsed["target"]["version"], "2.8")
        self.assertEqual(parsed["change_scale"], "minor")

    def test_deprecated_types_and_their_replacements(self):
        cases = (
            (SUPPORT, "android.support.v4.app.Fragment", ["androidx.fragment.app.Fragment"]),
            (PREFERENCE, "android.preference.PreferenceManager",
             ["androidx.preference.PreferenceManager"]),
            (BROADCAST,
             "androidx.localbroadcastmanager.content.LocalBroadcastManager", []),
        )
        for message, deprecated, replacements in cases:
            with self.subTest(message=message):
                parsed = parse_finding_message(message)
                self.assertEqual(parsed["kind"], "api_migration")
                self.assertEqual(parsed["deprecated_types"], [deprecated])
                self.assertEqual(parsed["target"]["types"], replacements)

    def test_a_replacement_package_is_recorded(self):
        self.assertIn("java.util.concurrent",
                      parse_finding_message(ASYNCTASK)["target"]["packages"])
        self.assertIn("java.time", parse_finding_message(JODA)["target"]["packages"])

    def test_a_library_named_without_a_version(self):
        parsed = parse_finding_message(JODA)
        self.assertEqual(parsed["kind"], "api_migration")
        self.assertEqual(parsed["subjects"][0]["name"], "joda-time")

    def test_a_maven_coordinate(self):
        parsed = parse_finding_message(GCM)
        self.assertEqual(parsed["kind"], "api_migration")
        self.assertEqual(
            parsed["subjects"][0]["coordinate"], "com.google.android.gms:play-services-gcm",
        )

    def test_crypto_and_other_messages_are_left_alone(self):
        for message in (
            "expecting one of PKIX,SunX509 but found .",
            "unknown",
            "expecting an authenticated or non-ECB transformation but found AES/ECB/NoPadding.",
            "URLEncoder_EncodeUTF8 The used encoding 'ISO-8859-15' may introduce incompatibilites.",
            "",
        ):
            with self.subTest(message=message):
                self.assertEqual(parse_finding_message(message), {})


class VersionTests(unittest.TestCase):
    def test_a_version_meets_a_target(self):
        self.assertTrue(version_satisfies("4.12.0", "4.10.0"))
        self.assertFalse(version_satisfies("3.12.0", "4.10.0"))
        self.assertTrue(version_satisfies("2.9.0", "2.x"))
        self.assertFalse(version_satisfies("1.9.0", "2.x"))

    def test_the_scale_of_a_change(self):
        self.assertEqual(change_scale("3.12.0", "4.10.0"), "major")
        self.assertEqual(change_scale("2.5.2", "2.8"), "minor")
        self.assertEqual(change_scale("", "2.8"), "unknown")


class RefreshVersionsTests(unittest.TestCase):
    """DuckDuckGo keeps every version in versions.properties."""

    def test_alias_and_coordinate_keys_are_read(self):
        entries = collect_refresh_versions(
            "version.okhttp3=4.12.0\n"
            "version.com.github.bumptech.glide..okhttp3-integration=4.16.0\n"
            "# comment\n",
            "versions.properties",
        )
        self.assertEqual(
            [(e["group"], e["artifact"], e["version_expression"]) for e in entries],
            [("", "okhttp3", "4.12.0"),
             ("com.github.bumptech.glide", "okhttp3-integration", "4.16.0")],
        )

    def test_the_placeholder_resolves_through_the_group_alias(self):
        root = _repository({
            "versions.properties": "version.okhttp3=4.12.0\n",
            "app/build.gradle": 'dependencies {\n  implementation "com.squareup.okhttp3:okhttp:_"\n}\n',
        })
        declarations = collect_declarations(root)["declarations"]
        [okhttp] = [item for item in declarations if item["artifact"] == "okhttp"]
        self.assertEqual(okhttp["version_expression"], "4.12.0")
        self.assertEqual(okhttp["version_resolved_from"], "versions.properties:1")


class GroundingTests(unittest.TestCase):
    """Whether the checkout still has what the message names."""

    SOURCE = {"app/src/main/java/a/Api.java": "package a;\nimport okhttp3.OkHttpClient;\nclass Api {}\n"}

    def test_a_version_already_meeting_the_target_is_already_satisfied(self):
        """DuckDuckGo: 3.12.0 reported, versions.properties pins 4.12.0."""
        root = _repository({
            "versions.properties": "version.okhttp3=4.12.0\n",
            "app/build.gradle": "dependencies {\n  implementation Square.okHttp3.okHttp\n}\n",
            **self.SOURCE,
        })
        finding = collect_dependency_finding(root, OKHTTP)
        self.assertEqual(finding["status"], "already_satisfied")
        self.assertEqual(finding["declaration_files"], ["versions.properties"])

    def test_a_version_below_the_target_is_confirmed(self):
        root = _repository({
            "gradle/libs.versions.toml":
                '[libraries]\nokhttp = { module = "com.squareup.okhttp3:okhttp", version = "3.12.0" }\n',
            **self.SOURCE,
        })
        finding = collect_dependency_finding(root, OKHTTP)
        self.assertEqual(finding["status"], "confirmed")
        self.assertEqual(finding["declaration_files"], ["gradle/libs.versions.toml"])

    def test_a_library_neither_declared_nor_imported_is_not_found(self):
        """Fenix: Retrofit 1.9.0 reported, no Retrofit anywhere."""
        root = _repository({
            "app/build.gradle": 'dependencies { implementation "androidx.core:core:1.9.0" }\n',
            "app/src/main/java/a/Sync.kt": "package a\nimport mozilla.components.Foo\n",
        })
        self.assertEqual(collect_dependency_finding(root, RETROFIT)["status"], "not_found")

    def test_an_imported_library_with_no_declaration_is_not_dismissed(self):
        root = _repository(dict(self.SOURCE))
        finding = collect_dependency_finding(root, OKHTTP)
        self.assertEqual(finding["status"], "used_but_not_declared")
        self.assertEqual(finding["usages"][0]["source_file_path"], "app/src/main/java/a/Api.java")

    def test_an_unreadable_version_is_left_to_the_analysis(self):
        root = _repository({
            "app/build.gradle": 'dependencies { implementation "com.squareup.okhttp3:okhttp:$okhttpVersion" }\n',
            **self.SOURCE,
        })
        self.assertEqual(
            collect_dependency_finding(root, OKHTTP)["status"], "declared_version_unresolved",
        )

    def test_a_deprecated_api_in_use_is_confirmed_with_its_module_build_file(self):
        root = _repository({
            "app/build.gradle": "android {}\n",
            "gradle/libs.versions.toml": "[versions]\n",
            "app/src/main/java/a/Loader.java":
                "package a;\nimport android.os.AsyncTask;\nclass Loader {}\n",
        })
        finding = collect_dependency_finding(
            root, ASYNCTASK, "app/src/main/java/a/Loader.java",
        )
        self.assertEqual(finding["kind"], "api_migration")
        self.assertEqual(finding["status"], "confirmed")
        self.assertEqual(
            finding["module_build_files"], ["app/build.gradle", "gradle/libs.versions.toml"],
        )

    def test_a_longer_name_or_its_androidx_successor_is_not_a_use(self):
        """NewPipe imports androidx.preference.PreferenceManager everywhere."""
        root = _repository({
            "app/src/main/java/a/S.java":
                "package a;\nimport androidx.preference.PreferenceManager;\n"
                "import android.os.AsyncTaskLoader;\nclass S {}\n",
        })
        self.assertEqual(collect_dependency_finding(root, PREFERENCE)["status"], "not_found")
        self.assertEqual(collect_dependency_finding(root, ASYNCTASK)["status"], "not_found")

    def test_a_deprecated_api_nowhere_in_the_source_is_not_found(self):
        root = _repository({"app/src/main/java/a/B.java": "package a;\nclass B {}\n"})
        self.assertEqual(collect_dependency_finding(root, ASYNCTASK)["status"], "not_found")

    def test_a_crypto_message_produces_no_record(self):
        root = _repository(dict(self.SOURCE))
        self.assertEqual(
            collect_dependency_finding(root, "expecting one of PKIX,SunX509 but found ."), {},
        )


class ModuleBuildFileTests(unittest.TestCase):
    def test_the_nearest_build_script_up_the_tree(self):
        root = _repository({
            "build.gradle": "",
            "feature/login/build.gradle.kts": "",
            "feature/login/src/main/kotlin/a/Login.kt": "",
        })
        self.assertEqual(
            module_build_files(root, "feature/login/src/main/kotlin/a/Login.kt"),
            ["feature/login/build.gradle.kts"],
        )


class FamilyTests(unittest.TestCase):
    def test_the_message_decides_the_family(self):
        self.assertEqual(classify_spec_family(
            "OutdatedDependencySpec", {}, {"kind": "dependency_version"},
        ), "dependency")
        self.assertEqual(classify_spec_family(
            "DeprecatedApiSpec", {}, {"kind": "api_migration"},
        ), "api_migration")

    def test_existing_families_are_unchanged(self):
        self.assertEqual(classify_spec_family("CipherSpec", {}, {}), "cipher")
        self.assertEqual(classify_spec_family("CipherSpec", {"status": "ambiguous"}), "dependency")


class DeclarationSourceTests(unittest.TestCase):
    """A dependency plan can only edit a build file supplied as exact source."""

    def test_the_declaring_file_is_supplied(self):
        root = _repository({"versions.properties": "version.okhttp3=3.12.0\n"})
        [source] = dependency_declaration_sources(str(root), {
            "kind": "dependency_version", "declaration_files": ["versions.properties"],
        }, set())
        self.assertEqual(source["source_file_path"], "versions.properties")
        self.assertIn("version.okhttp3=3.12.0", source["content"])

    def test_an_api_migration_also_supplies_the_module_build_file(self):
        root = _repository({"app/build.gradle": "android {}\n"})
        sources = dependency_declaration_sources(str(root), {
            "kind": "api_migration", "declaration_files": [],
            "module_build_files": ["app/build.gradle"],
        }, set())
        self.assertEqual([s["source_file_path"] for s in sources], ["app/build.gradle"])

    def test_a_file_already_supplied_or_outside_the_repository_is_skipped(self):
        root = _repository({"versions.properties": "x\n"})
        self.assertEqual(dependency_declaration_sources(str(root), {
            "kind": "dependency_version",
            "declaration_files": ["versions.properties", "../outside.gradle"],
        }, {"versions.properties"}), [])

    def test_no_finding_supplies_nothing(self):
        self.assertEqual(dependency_declaration_sources("/tmp", {}, set()), [])


class SkipBeforeModelTests(unittest.TestCase):
    BASE = {"method_body": "", "source_file_path": "", "surrounding_context": ""}

    def test_an_already_satisfied_finding_says_what_the_checkout_declares(self):
        reason = FixGenerator.not_applicable_reason({"dependency_finding": {
            "status": "already_satisfied",
            "subjects": [{"name": "okhttp3", "version": "3.12.0"}],
            "target": {"version": "4.10.0"},
            "matched_declarations": [{"version_expression": "4.12.0",
                                      "source_file_path": "versions.properties", "line": 156}],
        }})
        self.assertIn("already declares okhttp3", reason)
        self.assertIn("4.10.0", reason)
        self.assertIn("versions.properties:156", reason)

    def test_a_finding_the_checkout_does_not_contain_says_so(self):
        reason = FixGenerator.not_applicable_reason({"dependency_finding": {
            "status": "not_found", "subjects": [{"name": "Retrofit"}],
        }})
        self.assertIn("neither declares it", reason)

    def test_a_confirmed_finding_is_analysed_even_without_source(self):
        error = dict(self.BASE, dependency_finding={"status": "confirmed"},
                     extraction_status="application_class_not_in_checkout")
        self.assertEqual(FixGenerator.not_applicable_reason(error), "")
        self.assertEqual(FixGenerator.unanalysable_reason(error), "")

    def test_no_finding_changes_nothing(self):
        self.assertEqual(FixGenerator.not_applicable_reason({}), "")


if __name__ == "__main__":
    unittest.main()
