import subprocess
import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import detectors  # noqa: E402
from cognalys.extraction.extract_methods_single_csv import hosted_remote_of  # noqa: E402
from cognalys.llm import contract_gates as gates  # noqa: E402
from cognalys.validation import semgrep_rules  # noqa: E402


def _git(path, *arguments):
    return subprocess.run(["git", "-C", str(path), *arguments], check=True,
                          capture_output=True, text=True).stdout.strip()


def _commit(path: Path) -> None:
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "t@x.invalid")
    _git(path, "config", "user.name", "T")
    _git(path, "add", "-A")
    _git(path, "commit", "-qm", "app")


class HostedUpstreamTests(unittest.TestCase):
    """A clone of a local checkout keeps the checkout's hosted repository."""

    def test_the_checkouts_origin_is_found(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "aihub"
            repo.mkdir()
            (repo / "README").write_text("x", encoding="utf-8")
            _commit(repo)
            self.assertEqual(hosted_remote_of(str(repo)), "")
            _git(repo, "remote", "add", "origin", "https://github.com/silentcoderhere/aihub")
            self.assertEqual(hosted_remote_of(str(repo)), "https://github.com/silentcoderhere/aihub")

    def test_a_url_is_not_a_local_checkout(self):
        self.assertEqual(hosted_remote_of("https://github.com/o/r"), "")
        self.assertEqual(hosted_remote_of("/nonexistent/path"), "")


KOTLIN_USE = '''package org.app

class Picker {
    fun pick(context: Context, uri: Uri) {
        val cursor = context.contentResolver.query(uri, null, null, null, null)
        name = cursor?.use { c -> c.getString(0) }
    }
}
'''
KOTLIN_LEAK = '''package org.app

class Counter {
    fun count(db: Db): Int {
        val cursor = db.query("t")
        return cursor.count
    }
}
'''


@unittest.skipUnless(semgrep_rules.find_semgrep(), "semgrep is not installed")
class DiscoveryExclusionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.repo = Path(self.directory.name) / "app"
        main = self.repo / "app/src/main/java/org/app"
        # androidTest, as nerdcalci's DatabaseMigrationTest: Semgrep's own
        # default ignore already skips test/ directories, not androidTest/.
        test = self.repo / "app/src/androidTest/java/org/app"
        main.mkdir(parents=True)
        test.mkdir(parents=True)
        (main / "Picker.kt").write_text(KOTLIN_USE, encoding="utf-8")
        (main / "Counter.kt").write_text(KOTLIN_LEAK, encoding="utf-8")
        (test / "MigrationTest.kt").write_text(KOTLIN_LEAK.replace("Counter", "MigrationTest"),
                                               encoding="utf-8")
        _commit(self.repo)

    def tearDown(self):
        self.directory.cleanup()

    def test_only_the_real_leak_in_app_code_is_a_finding(self):
        result = detectors.discover_semgrep(detectors.RepositoryTarget(local_path=self.repo),
                                            ["CursorLeakSpec"])
        self.assertEqual([(f.class_name, f.method) for f in result.findings],
                         [("org.app.Counter", "count")])
        reasons = sorted(item["reason"].split(":")[0] for item in result.excluded)
        self.assertEqual(reasons, ["test code", "the method matches method_excludes_any"])
        self.assertTrue(result.complete)


class LocateTests(unittest.TestCase):
    """AI Hub: a top-level function after a closed object is not its member."""

    SOURCE = '''package com.foss.aihub.ui.webview

object WebViewProxyHelper {
    fun apply(webView: WebView) {
        val brace = "{"
    }
}

@SuppressLint("SetJavaScriptEnabled")
fun updateWebViewSettings(webView: WebView) {
    webView.settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
}

class Holder {
    fun member() {
        work()
    }
}
'''

    def _locate(self, needle):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "WebViewUtils.kt"
            path.write_text(self.SOURCE, encoding="utf-8")
            line = self.SOURCE.splitlines().index(needle) + 1
            return detectors.locate(path, line)

    def test_a_top_level_function_belongs_to_the_files_class(self):
        self.assertEqual(
            self._locate("    webView.settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW"),
            ("com.foss.aihub.ui.webview.WebViewUtilsKt", "updateWebViewSettings"))

    def test_a_member_still_belongs_to_its_class(self):
        self.assertEqual(self._locate("        work()"),
                         ("com.foss.aihub.ui.webview.Holder", "member"))
        self.assertEqual(self._locate('        val brace = "{"'),
                         ("com.foss.aihub.ui.webview.WebViewProxyHelper", "apply"))


class SourceTextTestTests(unittest.TestCase):
    def test_a_test_reading_the_source_file_is_rejected(self):
        """AI Hub's first patch: it grepped WebViewUtils.kt for the constant."""
        code = '''
    private fun readWebViewUtilsSource(): String {
        val sourceFile = listOf(
            File("src/main/java/com/foss/aihub/ui/webview/WebViewUtils.kt"),
        ).firstOrNull(File::isFile) ?: throw AssertionError("missing")
        return sourceFile.readText()
    }'''
        [issue] = gates.source_text_tests([{
            "source_file_path": "app/src/test/java/WebViewUtilsMixedContentPolicyTest.kt",
            "edit_kind": "test", "original_code": "", "corrected_code": code}])
        self.assertEqual(issue["code"], "TEST_READS_PRODUCTION_SOURCE")

    def test_any_way_of_opening_a_production_source_is_rejected(self):
        """AI Hub's second attempt read the file through a FileInputStream."""
        code = '''
        val sourceFile = arrayOf(File("src/main/java/com/foss/aihub/ui/webview/WebChromeClient.kt"))
            .firstOrNull { it.isFile }
        val input = FileInputStream(sourceFile)'''
        [issue] = gates.source_text_tests([{
            "source_file_path": "app/src/test/java/WebViewMixedContentPolicyTest.kt",
            "edit_kind": "test", "corrected_code": code}])
        self.assertEqual(issue["code"], "TEST_READS_PRODUCTION_SOURCE")

    def test_an_assertion_between_constants_is_rejected(self):
        """AI Hub: asserting NEVER_ALLOW differs from ALWAYS_ALLOW tests nothing."""
        code = '''
        assertFalse(
            "MIXED_CONTENT_NEVER_ALLOW must remain distinct from the permissive mode",
            WebSettings.MIXED_CONTENT_NEVER_ALLOW == WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
        )'''
        [issue] = gates.source_text_tests([{
            "source_file_path": "app/src/test/java/WebViewUtilsMixedContentConfigurationTest.kt",
            "edit_kind": "test", "corrected_code": code}])
        self.assertEqual(issue["code"], "TEST_ASSERTS_ONLY_CONSTANTS")

    def test_an_assertion_on_produced_values_is_not(self):
        code = 'assertEquals(WebSettings.MIXED_CONTENT_NEVER_ALLOW, view.settings.mixedContentMode)'
        self.assertEqual(gates.source_text_tests([{
            "source_file_path": "app/src/test/java/T.kt", "edit_kind": "test",
            "corrected_code": code}]), [])

    def test_a_test_reading_a_fixture_is_not(self):
        code = 'val json = File("src/test/resources/sample.json").readText()'
        self.assertEqual(gates.source_text_tests([{
            "source_file_path": "app/src/test/java/ParserTest.kt", "edit_kind": "test",
            "corrected_code": code}]), [])

    def test_production_code_is_not_checked(self):
        code = 'val text = File("Main.kt").readText()'
        self.assertEqual(gates.source_text_tests([{
            "source_file_path": "app/src/main/java/Tool.kt", "corrected_code": code}]), [])


if __name__ == "__main__":
    unittest.main()
