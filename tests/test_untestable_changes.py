import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.test_classpath import android_runtime_source, untestable_reason  # noqa: E402

WEBVIEW_SOURCE = '''package com.foss.aihub.ui.webview

import android.webkit.WebSettings
import android.webkit.WebView

fun updateWebViewSettings(webView: WebView) {
    webView.settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
}
'''
PLAIN_SOURCE = '''package org.app.crypto

import java.security.MessageDigest

object Hasher {
    fun digest(input: ByteArray) = MessageDigest.getInstance("SHA-256").digest(input)
}
'''


class TestCannotExerciseTests(unittest.TestCase):
    """Decided in the plan, before the model spends its attempts on a test."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.repo = Path(self.directory.name)
        app = self.repo / "app"
        (app / "src/main/java/org/app").mkdir(parents=True)
        (app / "src/main/java/org/app/WebViewUtils.kt").write_text(WEBVIEW_SOURCE, encoding="utf-8")
        (app / "src/main/java/org/app/Hasher.kt").write_text(PLAIN_SOURCE, encoding="utf-8")
        (app / "build.gradle.kts").write_text(
            'dependencies {\n    testImplementation("junit:junit:4.13.2")\n}\n', encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    WEBVIEW = "app/src/main/java/org/app/WebViewUtils.kt"
    HASHER = "app/src/main/java/org/app/Hasher.kt"
    JVM_TEST = "app/src/test/java/org/app/PolicyTest.kt"
    DEVICE_TEST = "app/src/androidTest/java/org/app/PolicyTest.kt"

    def test_a_webview_change_cannot_be_checked_by_a_jvm_test_without_robolectric(self):
        self.assertTrue(android_runtime_source(self.repo, self.WEBVIEW))
        self.assertIn("no Robolectric", untestable_reason(self.repo, self.JVM_TEST, [self.WEBVIEW]))

    def test_an_instrumented_test_is_never_run(self):
        self.assertIn("never run", untestable_reason(self.repo, self.DEVICE_TEST, [self.WEBVIEW]))

    def test_robolectric_makes_a_jvm_test_possible(self):
        (self.repo / "app/build.gradle.kts").write_text(
            'dependencies {\n    testImplementation("org.robolectric:robolectric:4.13")\n}\n',
            encoding="utf-8")
        self.assertEqual(untestable_reason(self.repo, self.JVM_TEST, [self.WEBVIEW]), "")

    def test_plain_jvm_code_keeps_its_test(self):
        self.assertFalse(android_runtime_source(self.repo, self.HASHER))
        self.assertEqual(untestable_reason(self.repo, self.JVM_TEST, [self.HASHER]), "")
        self.assertEqual(untestable_reason(self.repo, self.DEVICE_TEST, [self.HASHER]), "")


if __name__ == "__main__":
    unittest.main()
