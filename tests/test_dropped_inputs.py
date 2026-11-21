"""Inputs an edited function stops reading reach the behaviour review with their definitions.

Salty (2026-10-29, run_v2): the replan dropped BuildConfig.APP_SALT from the
key derivation of new messages; its definition (a buildConfigField fed by
System.getenv with a default) was in no packet, so the review could only call
it a maintainer decision.
"""
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.dropped_inputs import dropped_inputs  # noqa: E402

DERIVE_KEY = (
    "    private fun deriveKey(userSalt: String): SecretKeySpec {\n"
    "        val appSalt = BuildConfig.APP_SALT.toByteArray(StandardCharsets.UTF_8)\n"
    "        val combinedSalt = appSalt + userSalt.toByteArray(StandardCharsets.UTF_8)\n"
    "        val spec = PBEKeySpec(userSalt.toCharArray(), combinedSalt, 600000, 256)\n"
    "        return SecretKeySpec(factory.generateSecret(spec).encoded, \"AES\")\n"
    "    }\n")
NEW_DERIVE_KEY = (
    "    private fun deriveKey(userSalt: String, salt: ByteArray): SecretKeySpec {\n"
    "        val spec = PBEKeySpec(userSalt.toCharArray(), salt, 600000, 256)\n"
    "        return SecretKeySpec(factory.generateSecret(spec).encoded, \"AES\")\n"
    "    }\n\n"
    "    private fun deriveLegacyKey(userSalt: String): SecretKeySpec {\n"
    "        val appSalt = BuildConfig.APP_SALT.toByteArray(StandardCharsets.UTF_8)\n"
    "        val combinedSalt = appSalt + userSalt.toByteArray(StandardCharsets.UTF_8)\n"
    "        return SecretKeySpec(derive(userSalt, combinedSalt), \"AES\")\n"
    "    }\n")
BUILD_GRADLE = (
    "android {\n"
    "    defaultConfig {\n"
    "        def appSalt = (System.getenv(\"APP_SALT\") ?: \"Salty@AES-256\")\n"
    "        buildConfigField \"String\", \"APP_SALT\", \"\\\"${appSalt}\\\"\"\n"
    "    }\n"
    "}\n")


def edit(original, corrected, path="app/src/main/java/x/HashUtils.kt"):
    return {"source_file_path": path, "edit_kind": "method",
            "original_code": original, "corrected_code": corrected}


class DroppedInputTests(unittest.TestCase):
    def test_a_build_config_field_the_new_path_no_longer_reads_is_listed_with_its_definition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            (root / "app/build.gradle").write_text(BUILD_GRADLE, encoding="utf-8")
            dropped = dropped_inputs([edit(DERIVE_KEY, NEW_DERIVE_KEY)], root)
        self.assertEqual([item["input"] for item in dropped], ["BuildConfig.APP_SALT"])
        self.assertEqual(dropped[0]["function"], "deriveKey")
        codes = [place["code"] for place in dropped[0]["definitions"]]
        self.assertTrue(any(code.startswith("buildConfigField") for code in codes))
        self.assertTrue(any("System.getenv(\"APP_SALT\")" in code for code in codes))

    def test_a_copy_kept_for_a_legacy_path_does_not_count_but_a_helper_of_the_new_one_does(self):
        self.assertEqual(len(dropped_inputs([edit(DERIVE_KEY, NEW_DERIVE_KEY)])), 1)
        helper = NEW_DERIVE_KEY.replace("deriveLegacyKey", "passwordFor").replace(
            "val spec = PBEKeySpec(userSalt.toCharArray(), salt",
            "val spec = PBEKeySpec(passwordFor(userSalt), salt")
        self.assertEqual(dropped_inputs([edit(DERIVE_KEY, helper)]), [])

    def test_a_replaced_constant_iv_is_not_an_input(self):
        original = ("    fun encrypt(key: SecretKey, data: ByteArray): ByteArray {\n"
                    "        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(FIXED_IV))\n"
                    "        return cipher.doFinal(data)\n    }\n")
        corrected = ("    fun encrypt(key: SecretKey, data: ByteArray): ByteArray {\n"
                     "        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }\n"
                     "        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))\n"
                     "        return iv + cipher.doFinal(data)\n    }\n")
        self.assertEqual(dropped_inputs([edit(original, corrected)]), [])

    def test_a_parameter_the_new_version_ignores_is_listed(self):
        original = "    String hash(String text, String salt) {\n        return digest(salt + text);\n    }\n"
        corrected = "    String hash(String text, String salt) {\n        return digest(text);\n    }\n"
        dropped = dropped_inputs([edit(original, corrected, "src/main/java/x/H.java")])
        self.assertEqual([(item["input"], item["kind"]) for item in dropped], [("salt", "parameter")])

    def test_tests_and_created_files_are_not_read(self):
        self.assertEqual(dropped_inputs([edit(DERIVE_KEY, NEW_DERIVE_KEY,
                                              "app/src/test/java/x/HashUtilsTest.kt")]), [])
        self.assertEqual(dropped_inputs([{**edit(DERIVE_KEY, NEW_DERIVE_KEY), "edit_kind": "create"}]), [])


JAVA_SOURCE = (
    "class Main {\n"
    "    byte[] key(String userSalt) {\n"
    "        String material = BuildConfig.APP_SALT + userSalt;\n"
    "        return derive(material);\n"
    "    }\n"
    "    byte[] derive(String material) { return material.getBytes(); }\n"
    "}\n")
KEY_EDIT = {
    "symbol": "key",
    "original_code": ("    byte[] key(String userSalt) {\n"
                      "        String material = BuildConfig.APP_SALT + userSalt;\n"
                      "        return derive(material);\n"
                      "    }"),
    "corrected_code": ("    byte[] key(String userSalt) {\n"
                       "        String material = userSalt;\n"
                       "        return derive(material);\n"
                       "    }"),
}


class DroppedInputReviewTests(unittest.TestCase):
    """The review sees what a patch dropped; what it does not call the fix is regenerated."""

    def run_review(self, review):
        from test_applied_edits_match_text import _coordinated_run
        return _coordinated_run(review, [KEY_EDIT], source=JAVA_SOURCE)

    def test_a_dropped_input_is_regenerated_then_left_as_a_maintainer_note(self):
        from cognalys.llm.coordinated_generation import MAINTAINER_DECISION_PREFIX

        clean = {"regressions": [], "maintainer_decision_required": False,
                 "maintainer_decision": "", "rationale": ""}
        result, provider, _, _ = self.run_review(lambda call: clean)
        self.assertEqual(result["status"], "complete")
        self.assertGreater(provider.calls.count("behavior_review"), 1)
        self.assertTrue(any(item.startswith(MAINTAINER_DECISION_PREFIX)
                            and "BuildConfig.APP_SALT" in item
                            for item in result["review_assumptions"]))
        self.assertIn("dropped_inputs", provider.review_system)

    def test_a_single_round_draft_takes_the_note_at_once(self):
        # A single-round draft is its own final attempt: the dropped input
        # becomes the maintainer note, with no regeneration that never runs.
        from cognalys.llm.coordinated_generation import MAINTAINER_DECISION_PREFIX
        from test_applied_edits_match_text import _coordinated_run

        clean = {"regressions": [], "maintainer_decision_required": False,
                 "maintainer_decision": "", "rationale": ""}
        analysis = {"confirmed_cause": "cause",
                    "coordinated_fix_plan": {"required_edits": [
                        {"source_file_path": "src/Main.java", "symbol": "key"}]},
                    "v2": {"adjudication": {"single_round": True,
                                            "current_code_is_correct_use": True,
                                            "correct_use_reason": "documented"}}}
        result, provider, _, _ = _coordinated_run(
            lambda call: clean, [KEY_EDIT], source=JAVA_SOURCE,
            error_extra={"evidence_analysis": analysis})
        self.assertEqual(result["status"], "complete")
        self.assertEqual(provider.calls.count("behavior_review"), 1)
        self.assertTrue(any(item.startswith(MAINTAINER_DECISION_PREFIX)
                            and "BuildConfig.APP_SALT" in item
                            for item in result["review_assumptions"]))

    def test_an_input_the_review_calls_the_fix_is_not_held(self):
        from cognalys.llm.coordinated_generation import MAINTAINER_DECISION_PREFIX

        review = {"regressions": [], "maintainer_decision_required": False,
                  "maintainer_decision": "", "rationale": "",
                  "dropped_inputs_removed_by_fix": ["BuildConfig.APP_SALT"]}
        result, provider, _, _ = self.run_review(lambda call: review)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(provider.calls.count("behavior_review"), 1)
        self.assertFalse(any(str(item).startswith(MAINTAINER_DECISION_PREFIX)
                             for item in result["review_assumptions"]))


if __name__ == "__main__":
    unittest.main()
