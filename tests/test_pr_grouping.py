import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs import pr_creator  # noqa: E402
from cognalys.prs.pr_grouping import diff_changes, relate  # noqa: E402

UTILS = '''diff --git a/app/WebViewUtils.kt b/app/WebViewUtils.kt
--- a/app/WebViewUtils.kt
+++ b/app/WebViewUtils.kt
@@ -262,7 +262,7 @@ fun updateWebViewSettings(
         allowContentAccess = true
-        mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
+        mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
         cacheMode = WebSettings.LOAD_DEFAULT
'''
CHROME = '''diff --git a/app/WebChromeClient.kt b/app/WebChromeClient.kt
--- a/app/WebChromeClient.kt
+++ b/app/WebChromeClient.kt
@@ -68,7 +68,7 @@ open class CustomWebChromeClient(
-                    mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
+                    mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
'''


def _pr(finding, diff, method, source="app/X.kt", repo="aihub"):
    return {"finding_id": finding, "diff": diff, "method_name": method, "source_file": source,
            "repo_owner": "SilentCoderHere", "repo_name": repo}


class RelateTests(unittest.TestCase):
    def test_a_pull_request_inside_another_is_superseded(self):
        """AI Hub: updateWebViewSettings' change was all inside onCreateWindow's."""
        relations = relate([_pr("utils", UTILS, "updateWebViewSettings", "app/WebViewUtils.kt"),
                            _pr("chrome", CHROME + UTILS, "onCreateWindow", "app/WebChromeClient.kt")])
        self.assertEqual(relations, {"utils": {"superseded_by": "chrome"}})

    def test_two_rewrites_of_one_method_overlap(self):
        """BitBanana: two specs, two different rewrites of encodePbkdf2."""
        first = UTILS.replace("NEVER_ALLOW", "COMPATIBILITY_MODE")
        relations = relate([_pr("a", UTILS, "update", "app/WebViewUtils.kt"),
                            _pr("b", first, "update", "app/WebViewUtils.kt")])
        self.assertEqual(relations["a"], {"overlaps_with": ["b"]})
        self.assertEqual(relations["b"], {"overlaps_with": ["a"]})

    def test_unrelated_changes_and_other_repositories_stay_apart(self):
        self.assertEqual(relate([_pr("utils", UTILS, "update", "app/WebViewUtils.kt"),
                                 _pr("chrome", CHROME, "onCreateWindow", "app/WebChromeClient.kt")]), {})
        self.assertEqual(relate([_pr("a", UTILS, "update", repo="one"),
                                 _pr("b", UTILS + CHROME, "other", repo="two")]), {})

    def test_of_two_identical_changes_one_is_kept(self):
        relations = relate([_pr("b", UTILS, "update"), _pr("a", UTILS, "update")])
        self.assertEqual(relations, {"b": {"superseded_by": "a"}})

    def test_whitespace_does_not_make_a_change_different(self):
        self.assertEqual(diff_changes(UTILS), diff_changes(UTILS.replace("        mixed", "  mixed")))


KSU_RSA = '''diff --git a/app/KeyStoreUtils.java b/app/KeyStoreUtils.java
--- a/app/KeyStoreUtils.java
+++ b/app/KeyStoreUtils.java
@@ -40,7 +40,7 @@ public class KeyStoreUtils {
-        java.security.KeyPair generateKeyPair = keyPairGenerator.generateKeyPair();
+        java.security.KeyPair keyPair = keyPairGenerator.genKeyPair();
@@ -60,7 +60,7 @@ public class KeyStoreUtils {
-        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", new BouncyCastleProvider());
+        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
-        java.security.KeyPair generateKeyPair = keyPairGenerator.generateKeyPair();
+        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();
'''
KSU_ECC = '''diff --git a/app/KeyStoreUtils.java b/app/KeyStoreUtils.java
--- a/app/KeyStoreUtils.java
+++ b/app/KeyStoreUtils.java
@@ -60,7 +60,7 @@ public class KeyStoreUtils {
-        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", new BouncyCastleProvider());
+        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
'''


class ResolvedWithTests(unittest.TestCase):
    """App Manager (2026-11-01): generateRSAKeyPair's draft also made
    generateECCKeyPair's "ECDH" -> "EC", and both counted as PR pronto."""

    def _prs(self):
        rsa = _pr("a5", KSU_RSA, "generateRSAKeyPair", "app/KeyStoreUtils.java")
        rsa["original_method_body"] = (
            "java.security.KeyPair generateKeyPair = keyPairGenerator.generateKeyPair();\n"
            "KeyPairGenerator.getInstance(\"RSA\");")
        ecc = _pr("bc", KSU_ECC, "generateECCKeyPair", "app/KeyStoreUtils.java")
        ecc["original_method_body"] = (
            "KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(\"ECDH\", "
            "new BouncyCastleProvider());")
        return rsa, ecc

    def test_the_draft_whose_own_change_the_other_makes_is_resolved_with_it(self):
        relations = relate(self._prs())
        self.assertEqual(relations["bc"]["resolved_with"], "a5")
        self.assertEqual(relations["bc"]["resolved_with_method"], "generateRSAKeyPair")
        self.assertNotIn("overlaps_with", relations.get("a5", {}))

    def test_two_rewrites_that_differ_both_stay(self):
        first = UTILS.replace("NEVER_ALLOW", "COMPATIBILITY_MODE")
        a, b = _pr("a", UTILS, "update", "app/WebViewUtils.kt"), _pr("b", first, "update", "app/WebViewUtils.kt")
        for pr in (a, b):
            pr["original_method_body"] = "mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW"
        relations = relate([a, b])
        self.assertNotIn("resolved_with", relations["a"])
        self.assertNotIn("resolved_with", relations["b"])

    def test_statistics_count_the_resolved_draft_once(self):
        from cognalys.reporting.finding_statistics import final_outcome

        outcome, detail = final_outcome({
            "solution": "s.json", "pr": True, "pr_committed": True, "build_status": "success",
            "pr_held": "resolved with a5", "joined_into": "generateRSAKeyPair"})
        self.assertNotEqual(outcome, "PR pronto")
        self.assertIn("resolvido junto com generateRSAKeyPair", detail)


class PublicationTests(unittest.TestCase):
    def _metadata(self, directory, **extra):
        path = Path(directory) / "app_update_pr.json"
        path.write_text(json.dumps({
            "finding_id": "utils", "publishable": True, "title": "Keep the login on HTTPS",
            "body": "## Summary\n\nPlain text.", "build_validation": {"status": "success"},
            "repository": directory, "branch": "fix/update-spec-utils-abc", **extra,
        }), encoding="utf-8")
        return path

    def test_a_superseded_pull_request_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._metadata(directory, superseded_by="chrome")
            creator = pr_creator.AutomatedPRCreator(pull_requests_dir=directory, dry_run=True)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(creator.process_pr_file(path), "blocked")
            self.assertIn("finding chrome", out.getvalue())

    def test_a_pull_request_resolved_with_another_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._metadata(directory, resolved_with="a5")
            creator = pr_creator.AutomatedPRCreator(pull_requests_dir=directory, dry_run=True)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(creator.process_pr_file(path), "blocked")
            self.assertIn("finding a5", out.getvalue())

    def test_the_second_of_two_overlapping_pull_requests_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._metadata(directory, overlaps_with=["other"])
            (Path(directory) / "app_other_pr_created.json").write_text(json.dumps(
                {"branch": "fix/update-spec-other-123", "pr_url": "https://github.com/o/r/pull/1"}),
                encoding="utf-8")
            creator = pr_creator.AutomatedPRCreator(pull_requests_dir=directory, dry_run=True)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(creator.process_pr_file(path), "blocked")
            self.assertIn("combine", out.getvalue())

    def test_an_overlap_with_nothing_published_does_not_block(self):
        with tempfile.TemporaryDirectory() as directory:
            creator = pr_creator.AutomatedPRCreator(pull_requests_dir=directory, dry_run=True)
            self.assertFalse(creator.published_in_directory("other"))


class PublishableSurvivorTests(unittest.TestCase):
    """2026-11-01 review: a finding never yields to a draft that cannot be published."""

    def _prs(self):
        return ResolvedWithTests._prs(self)

    def test_a_held_draft_resolves_nothing(self):
        rsa, ecc = self._prs()
        rsa.update(publishable=False, preview_status="HELD_BEHAVIOUR_REVIEW")
        self.assertNotIn("resolved_with", relate([rsa, ecc]).get("bc", {}))

    def test_a_held_draft_supersedes_nothing(self):
        held = _pr("chrome", CHROME + UTILS, "onCreateWindow", "app/WebChromeClient.kt")
        held["publishable"] = False
        relations = relate([_pr("utils", UTILS, "updateWebViewSettings", "app/WebViewUtils.kt"), held])
        self.assertNotIn("superseded_by", relations.get("utils", {}))

    def test_a_superseded_chain_ends_at_the_last_draft(self):
        relations = relate([_pr("c", UTILS, "u", "app/WebViewUtils.kt"),
                            _pr("b", UTILS + CHROME, "o", "app/WebChromeClient.kt"),
                            _pr("a", UTILS + CHROME + UTILS.replace("WebViewUtils", "Other"),
                                "p", "app/Other.kt")])
        self.assertEqual(relations["c"]["superseded_by"], "a")
        self.assertEqual(relations["b"]["superseded_by"], "a")


if __name__ == "__main__":
    unittest.main()
