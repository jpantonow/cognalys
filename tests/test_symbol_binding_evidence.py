"""What a call binds to, and what a generated test may import.

Two gates that ended findings in run_20260917_230558 and before it:

  * an extractor asking "does this expression resolve to
    android.webkit.WebView.setWebContentsDebuggingEnabled(boolean)?" was
    always declined with "no matching file in the repository" -- true and
    useless, because the type is declared in the platform, not the
    checkout. The predicate stayed unknown and the cause stayed
    unconfirmed, in four runs (`adjudication:cause_unknown`);

  * a generated unit test imported Robolectric and androidx.test in a
    module that declares neither, so Gradle failed with five unresolved
    references and the correct production fix died with its test.

Both are now answered from the repository's own files, and both refuse to
answer when the files do not settle it -- which is the property these tests
pin hardest.
"""
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.symbol_binding import (  # noqa: E402
    called_names_in, qualified_type_names, resolve_call_bindings,
)
from cognalys.extraction.test_classpath import (  # noqa: E402
    declared_coordinates, unsupported_test_imports,
)
from cognalys.llm import evidence_requests  # noqa: E402
from cognalys.llm.evidence_requests import (  # noqa: E402
    classify_evidence_request, resolve_evidence_requests,
)


class CallBindingTests(unittest.TestCase):

    KOTLIN = (
        "package uk.org.retallack.slimbook\n\n"
        "import android.webkit.*\n"
        "import androidx.work.*\n\n"
        "class MainActivity {\n"
        "    fun setupWebView() {\n"
        "        WebView.setWebContentsDebuggingEnabled(true)\n"
        "    }\n"
        "}\n"
    )

    def test_an_explicit_import_resolves_the_receiver_type(self):
        source = (
            "import android.webkit.WebView;\n"
            "class A { void f(WebView view) { view.loadUrl(\"x\"); } }\n"
        )
        binding = resolve_call_bindings(
            source, ["loadUrl"], declares=lambda name: False
        )[0]
        self.assertEqual(binding["resolution"], "unique_external")
        self.assertEqual(binding["qualified_type"], "android.webkit.WebView")

    def test_a_wildcard_import_matching_the_reported_api_is_reported_as_such(self):
        binding = resolve_call_bindings(
            self.KOTLIN, ["setWebContentsDebuggingEnabled"],
            declares=lambda name: False,
            expected_types=["android.webkit.WebView"],
        )[0]
        self.assertEqual(binding["resolution"], "consistent_with_reported_api")
        self.assertEqual(binding["qualified_type"], "android.webkit.WebView")
        self.assertEqual(binding["arguments"], ["true"])

    def test_without_a_reported_api_several_wildcards_stay_ambiguous(self):
        binding = resolve_call_bindings(
            self.KOTLIN, ["setWebContentsDebuggingEnabled"],
            declares=lambda name: False,
        )[0]
        self.assertEqual(binding["resolution"], "ambiguous")
        self.assertEqual(binding["qualified_type"], "")

    def test_a_type_the_checkout_declares_is_not_an_external_binding(self):
        source = (
            "package app;\n"
            "class A { void f() { Helper.run(); } }\n"
        )
        binding = resolve_call_bindings(
            source, ["run"], declares=lambda name: name == "Helper"
        )[0]
        self.assertEqual(binding["resolution"], "repository_type")
        self.assertEqual(binding["qualified_type"], "app.Helper")

    def test_an_aliased_import_is_refused_rather_than_resolved(self):
        source = (
            "import android.webkit.WebView as Browser\n"
            "class A { fun f() { Browser.setWebContentsDebuggingEnabled(true) } }\n"
        )
        binding = resolve_call_bindings(
            source, ["setWebContentsDebuggingEnabled"],
            declares=lambda name: False,
            expected_types=["android.webkit.WebView"],
        )[0]
        self.assertEqual(binding["resolution"], "aliased_import_not_resolved")

    def test_a_receiverless_call_is_not_claimed_to_resolve(self):
        binding = resolve_call_bindings(
            "class A { void f() { helper(1); } }", ["helper"],
            declares=lambda name: False,
        )[0]
        self.assertEqual(binding["receiver_kind"], "implicit")
        self.assertEqual(binding["resolution"], "unresolved")

    def test_a_receiverless_call_named_like_an_imported_type_is_its_constructor(self):
        # BlueGate run_v6/run_v7 (2026-10-31): KeyPair(entry.certificate.publicKey,
        # entry.privateKey) under `import java.security.KeyPair` was read as a
        # call on the enclosing type, and the adjudication blocked on it.
        kotlin = (
            "package org.cleverfox.bluegate\n\n"
            "import java.security.KeyPair\n"
            "import java.security.KeyStore\n\n"
            "class KeyManager(private val keyStore: KeyStore) {\n"
            "    fun getOrCreateKeyPair(): KeyPair {\n"
            "        val entry = keyStore.getEntry(\"a\", null) as KeyStore.PrivateKeyEntry\n"
            "        return KeyPair(entry.certificate.publicKey, entry.privateKey)\n"
            "    }\n"
            "}\n"
        )
        java = ("import java.security.KeyPair;\n"
                "class A { KeyPair f(PublicKey p, PrivateKey k) { return new KeyPair(p, k); } }\n")
        for source in (kotlin, java):
            with self.subTest(source=source[:30]):
                [binding] = resolve_call_bindings(
                    source, ["KeyPair"], declares=lambda name: False,
                    expected_types=["java.security.KeyPair"])
                self.assertEqual(binding["receiver_kind"], "constructor")
                self.assertEqual(binding["resolution"], "unique_external")
                self.assertEqual(binding["qualified_type"], "java.security.KeyPair")
                self.assertEqual(binding["arity"], 2)
        # A type of the checkout's own is that type, and a name nothing
        # imports or declares stays unresolved.
        [own] = resolve_call_bindings(
            "package app\nclass A { fun f() = Holder(1) }\n", ["Holder"],
            declares=lambda name: name == "Holder")
        self.assertEqual((own["resolution"], own["qualified_type"]),
                         ("repository_type", "app.Holder"))
        [unknown] = resolve_call_bindings(
            "class A { fun f() = Holder(1) }\n", ["Holder"], declares=lambda name: False)
        self.assertEqual((unknown["receiver_kind"], unknown["resolution"]),
                         ("constructor", "unresolved"))

    def test_a_capitalised_function_is_not_read_as_a_constructor(self):
        # Review of 2026-10-31: a Kotlin Composable, a Java static method and
        # a statically imported one are spelled like constructors.
        for name, source in (
                ("BrowserAuthScreen", "@Composable\nfun BrowserAuthScreen(url: String) {}\n"
                                      "fun host() { BrowserAuthScreen(\"u\") }\n"),
                ("SHA1", "class U {\n  static String SHA1(String s) {\n    return s;\n  }\n"
                         "  String id(String s) { return SHA1(s); }\n}\n"),
                ("Hash", "import static a.Util.Hash;\nclass B { int f(int x) "
                         "{ return Hash(x); } }\n")):
            with self.subTest(name):
                bindings = resolve_call_bindings(source, [name], declares=lambda simple: False)
                self.assertTrue(bindings)
                self.assertEqual({item["receiver_kind"] for item in bindings}, {"implicit"})
        # A caller that knows the name is a method asks for no constructor.
        [method] = resolve_call_bindings(
            "import java.security.KeyPair\nfun f() = KeyPair(a, b)\n", ["KeyPair"],
            declares=lambda simple: False, constructors=False)
        self.assertEqual(method["receiver_kind"], "implicit")

    def test_names_and_types_are_read_out_of_the_request_text(self):
        asked = (
            "Establish whether the reviewed expression resolves specifically "
            "to android.webkit.WebView.setWebContentsDebuggingEnabled(boolean)."
        )
        self.assertIn("setWebContentsDebuggingEnabled", called_names_in(asked))
        self.assertIn("android.webkit.WebView", qualified_type_names(asked))


class BindingRequestRoutingTests(unittest.TestCase):

    REQUEST = {
        "kind": "symbol_resolution",
        "reason": "Establish whether the reviewed expression resolves "
                  "specifically to android.webkit.WebView."
                  "setWebContentsDebuggingEnabled(boolean).",
        "symbol": "uk.org.retallack.slimbook.MainActivity#setupWebView",
    }

    def test_a_resolution_request_is_its_own_family(self):
        self.assertEqual(
            classify_evidence_request(self.REQUEST),
            evidence_requests.SYMBOL_BINDING,
        )

    def test_a_dependency_request_is_still_build_configuration(self):
        self.assertEqual(
            classify_evidence_request({
                "kind": "resolved_dependency_graph_or_lockfile",
                "symbol": "OkHttp version"}),
            evidence_requests.BUILD_CONFIGURATION,
        )

    def test_a_runtime_request_is_still_runtime_only(self):
        self.assertEqual(
            classify_evidence_request({
                "kind": "runtime_resolution_of_the_negotiated_protocol",
                "symbol": "SSLSession.getProtocol()"}),
            evidence_requests.RUNTIME_ONLY,
        )

    def test_the_request_is_answered_with_a_binding_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = "app/src/main/java/uk/org/retallack/slimbook/MainActivity.kt"
            path = root / relative
            path.parent.mkdir(parents=True)
            path.write_text(CallBindingTests.KOTLIN, encoding="utf-8")
            resolution = resolve_evidence_requests(
                root, [self.REQUEST], set(),
                target={
                    "source_file_path": relative,
                    "method_name": "setupWebView",
                    "error_message": "WebView.setWebContentsDebuggingEnabled"
                                     "(true) is called in release builds.",
                },
            )
        self.assertEqual(resolution["declined"], [])
        entry = resolution["entries"][0]
        self.assertEqual(entry["kind"], "resolved_symbol_binding")
        binding = entry["data"]["bindings"][0]
        self.assertEqual(binding["qualified_type"], "android.webkit.WebView")
        self.assertEqual(binding["arguments"], ["true"])

    def test_without_a_target_file_the_request_is_declined_not_invented(self):
        with tempfile.TemporaryDirectory() as directory:
            resolution = resolve_evidence_requests(
                Path(directory), [self.REQUEST], set(),
            )
        self.assertEqual(resolution["entries"], [])
        self.assertTrue(resolution["declined"])


class TestClasspathTests(unittest.TestCase):

    BUILD = (
        "dependencies {\n"
        "    implementation(libs.androidx.core.ktx)\n"
        "    testImplementation(libs.junit)\n"
        "    testImplementation(\"com.squareup.okhttp3:mockwebserver:4.12.0\")\n"
        "}\n"
    )
    CATALOG = (
        "[libraries]\n"
        "androidx-core-ktx = { module = \"androidx.core:core-ktx\", version.ref = \"c\" }\n"
        "junit = { module = \"junit:junit\", version.ref = \"j\" }\n"
    )

    def _module(self, directory: str) -> Path:
        root = Path(directory)
        (root / "app").mkdir(parents=True)
        (root / "app" / "build.gradle.kts").write_text(self.BUILD, encoding="utf-8")
        (root / "gradle").mkdir()
        (root / "gradle" / "libs.versions.toml").write_text(
            self.CATALOG, encoding="utf-8"
        )
        return root

    def test_catalog_references_and_literals_are_both_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._module(directory)
            coordinates = declared_coordinates(
                root, "app/src/test/java/app/AnyTest.kt"
            )
        self.assertIn("junit:junit", coordinates)
        self.assertIn("androidx.core:core-ktx", coordinates)
        self.assertIn("com.squareup.okhttp3:mockwebserver", coordinates)

    def test_an_undeclared_test_runner_is_flagged(self):
        code = (
            "package app\n"
            "import org.junit.Test\n"
            "import org.robolectric.RobolectricTestRunner\n"
            "import androidx.test.core.app.ApplicationProvider\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self._module(directory)
            missing = unsupported_test_imports(
                root, "app/src/test/java/app/AnyTest.kt", code,
                package_roots={"app"},
            )
        self.assertEqual(
            missing,
            ["androidx.test.core.app.ApplicationProvider",
             "org.robolectric.RobolectricTestRunner"],
        )

    def test_declared_libraries_the_platform_and_the_repository_pass(self):
        code = (
            "package app\n"
            "import android.content.Context\n"
            "import java.io.File\n"
            "import org.junit.Test\n"
            "import okhttp3.mockwebserver.MockWebServer\n"
            "import app.internal.Helper\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self._module(directory)
            missing = unsupported_test_imports(
                root, "app/src/test/java/app/AnyTest.kt", code,
                package_roots={"app", "app.internal"},
            )
        self.assertEqual(missing, [])

    def _literal_module(self, directory: str, build: str) -> Path:
        root = Path(directory)
        (root / "app").mkdir(parents=True)
        (root / "app" / "build.gradle.kts").write_text(build, encoding="utf-8")
        return root

    def test_a_dotless_versioned_literal_is_a_coordinate(self):
        # HomeApp declares junit as a literal, not through a catalog.
        with tempfile.TemporaryDirectory() as directory:
            root = self._literal_module(
                directory,
                'dependencies {\n'
                '    testImplementation("junit:junit:4.13.2")\n'
                '    testImplementation("org.robolectric:robolectric:4.17")\n'
                '}\n',
            )
            missing = unsupported_test_imports(
                root, "app/src/test/java/app/AnyTest.kt",
                "import org.junit.Test\nimport kotlin.test.Test\n",
                package_roots=set(),
            )
        self.assertEqual(missing, ["kotlin.test.Test"])

    def test_kotlin_test_passes_once_its_artifact_is_declared(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._literal_module(
                directory,
                'dependencies {\n'
                '    testImplementation("junit:junit:4.13.2")\n'
                '    testImplementation(kotlin("test"))\n'
                '}\n',
            )
            missing = unsupported_test_imports(
                root, "app/src/test/java/app/AnyTest.kt",
                "import kotlin.test.Test\nimport kotlin.collections.List\n",
                package_roots=set(),
            )
        self.assertEqual(missing, [])

    def test_a_module_without_readable_declarations_is_not_judged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            missing = unsupported_test_imports(
                root, "app/src/test/java/app/AnyTest.kt",
                "import org.robolectric.RobolectricTestRunner\n",
                package_roots=set(),
            )
        self.assertEqual(missing, [])

    def test_a_package_below_a_long_license_header_is_the_repositorys_own(self):
        # RedReader (2026-11-03): its GPL header put `package` past the
        # first 600 characters, and its own common.General was refused.
        from cognalys.extraction.test_classpath import repository_packages

        with tempfile.TemporaryDirectory() as directory:
            root = self._literal_module(
                directory, 'dependencies {\n    testImplementation("junit:junit:4.13.2")\n}\n')
            source = root / "app/src/main/java/org/example/common/General.kt"
            source.parent.mkdir(parents=True)
            source.write_text("/*\n" + " * licence text\n" * 200 + " */\n\n"
                              "package org.example.common\n\nobject General\n", encoding="utf-8")
            missing = unsupported_test_imports(
                root, "app/src/test/java/org/example/GeneralTest.java",
                "import org.example.common.General;\nimport org.junit.Test;\n",
                package_roots=repository_packages(root),
            )
        self.assertEqual(missing, [])

    def test_the_generator_is_told_the_import_prefixes_the_check_accepts(self):
        from cognalys.extraction.test_classpath import test_classpath_summary

        with tempfile.TemporaryDirectory() as directory:
            root = self._literal_module(
                directory,
                'dependencies {\n'
                '    testImplementation("junit:junit:4.13.2")\n'
                '    androidTestImplementation("androidx.test.ext:junit:1.2.1")\n'
                '}\n',
            )
            summary = test_classpath_summary(
                root, "app/src/test/java/app/AnyTest.kt",
                package_roots={"org.example", "org.example.common", "com.other"})
        self.assertEqual(summary["declared_group_prefixes"], ["androidx.test.ext", "junit"])
        self.assertEqual(summary["repository_package_prefixes"], ["com.other", "org.example"])
        self.assertIn("use only those", summary["rule"])


if __name__ == "__main__":
    unittest.main()
