"""A digest that names a stored file selects the rename-then-migrate policy."""
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.digest_file_name_evidence import digest_file_name_evidence  # noqa: E402
from cognalys.llm.migration_policy import generic_migration_policy  # noqa: E402

GENERAL = ("class General {\n    public static String sha1(final byte[] plaintext) {\n"
           "        MessageDigest digest = MessageDigest.getInstance(\"SHA-1\");\n"
           "        return hex(digest.digest(plaintext));\n    }\n}\n")
MANAGER = ("class RedditSubredditManager {\n"
           "    private static String getDbFilename(final String type, final RedditAccount user) {\n"
           "        return General.sha1(user.username.getBytes()) + \"_\" + type + \"_subreddits.db\";\n"
           "    }\n}\n")
MESSAGE = "expecting one of SHA-256,SHA-384,SHA-512 but found SHA-1"


class DigestFileNameTests(unittest.TestCase):
    def repo(self, *extra):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "src").mkdir()
        (root / "src/General.java").write_text(GENERAL, encoding="utf-8")
        (root / "src/RedditSubredditManager.java").write_text(MANAGER, encoding="utf-8")
        for index, text in enumerate(extra):
            (root / f"src/Other{index}.java").write_text(text, encoding="utf-8")
        return {"spec": "MessageDigestSpec", "error_message": MESSAGE,
                "unique_error_id": f"General:::sha1:::MessageDigestSpec:::UnsafeAlgorithm:::{MESSAGE}",
                "method_name": "sha1", "repository_path": str(root)}

    def test_the_redreader_database_name_selects_the_rename_policy(self):
        error = self.repo()
        evidence = digest_file_name_evidence(error)
        self.assertTrue(evidence["names_stored_file"])
        self.assertTrue(evidence["file_name_sites"][0]["statement"].startswith("return General.sha1("))
        policy = generic_migration_policy(error)
        self.assertEqual(policy["consumer_scope"], "persisted_file_name")
        self.assertIn("Rename, then migrate", policy["strategy"])
        self.assertTrue(any("name of a file the app stores" in fact for fact in policy["maintainer_facts"]))

    def test_a_digest_with_another_consumer_keeps_the_default_policy(self):
        token = ("class Rest {\n    String token(String password, String salt) {\n"
                 "        return General.sha1((password + salt).getBytes());\n    }\n}\n")
        error = self.repo(token)
        self.assertEqual(digest_file_name_evidence(error), {})
        self.assertEqual(generic_migration_policy(error)["consumer_scope"],
                         "internal_recomputed_digest_value")


    def test_a_kotlin_site_names_the_line_without_the_comment_after_it(self):
        # InterTune (2026-10-27): Kotlin has no ";", so the statement ran into
        # the next KDoc and the PR text quoted half of it.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "app").mkdir()
        (root / "app/WidgetStore.kt").write_text(
            "object WidgetStore {\n"
            "    private fun artFile(dir: File, id: String) = File(dir, \"${hash(id)}_c.png\")\n"
            "\n    /**\n     * The name every artwork file had before.\n     */\n"
            "    private fun hash(id: String): String =\n"
            "        MessageDigest.getInstance(\"SHA-1\").digest(id.toByteArray()).toString()\n"
            "}\n", encoding="utf-8")
        evidence = digest_file_name_evidence(
            {"method_name": "hash", "repository_path": str(root)})
        site = evidence["file_name_sites"][0]
        self.assertNotIn("/**", site["statement"])
        fact = evidence["maintainer_facts"]["stored_file_name"]
        self.assertIn("(WidgetStore.kt, line 2)", fact)
        self.assertNotIn("hash(id)", fact)

    def test_a_finding_without_a_checkout_does_not_scan_the_working_directory(self):
        self.assertEqual(digest_file_name_evidence(
            {"method_name": "sha1", "repository_path": ""}), {})


if __name__ == "__main__":
    unittest.main()
