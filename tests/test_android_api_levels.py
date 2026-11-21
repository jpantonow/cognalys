"""SMSecure run_v4 (2026-10-31): SecretKeyFactory "PBKDF2WithHmacSHA256" is in
Android's platform providers only from API 26; the app's minSdk is 24 and it
bundles no provider, so existing users on Android 7.x would be locked out."""
import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.validation import android_api_levels as levels  # noqa: E402

KDF = "app/src/main/java/org/smsecure/crypto/MasterSecretUtil.java"
ORIGINAL = ('SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWITHSHA1AND128BITAES-CBC-BC");\n'
            "PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, iterations);")
CORRECTED = ('private static final String CURRENT_KDF_ALGORITHM = "PBKDF2WithHmacSHA256";\n'
             "SecretKeyFactory skf = SecretKeyFactory.getInstance(CURRENT_KDF_ALGORITHM);\n"
             "PBEKeySpec spec = new PBEKeySpec(pw, salt, iterations, 128);")


def edit(corrected=CORRECTED, path=KDF, original=ORIGINAL):
    return {"source_file_path": path, "original_code": original, "corrected_code": corrected}


def repository(directory: str, min_sdk: int = 24, dependencies: str = "",
               source: str = "") -> Path:
    root = Path(directory)
    (root / "app").mkdir()
    (root / "app" / "build.gradle.kts").write_text(
        f"android {{ defaultConfig {{ minSdk = {min_sdk} }} }}\n"
        f"dependencies {{ {dependencies} }}\n", encoding="utf-8")
    if source:
        sources = root / "app" / "src" / "main" / "java"
        sources.mkdir(parents=True)
        (sources / "App.java").write_text(source, encoding="utf-8")
    return root


class AvailabilityTableTests(unittest.TestCase):
    def test_first_levels_come_from_the_table_without_regard_to_case(self):
        self.assertEqual(levels.first_api_level("SecretKeyFactory", "PBKDF2WithHmacSHA256"), 26)
        self.assertEqual(levels.first_api_level("SecretKeyFactory", "pbkdf2withhmacsha1"), 10)
        self.assertEqual(levels.first_api_level("Cipher", "AES/GCM/NoPadding"), 10)
        self.assertEqual(levels.first_api_level("Cipher", "ChaCha20/Poly1305/NoPadding"), 28)
        self.assertEqual(levels.first_api_level("SSLContext", "TLSv1.3"), 29)
        # A transformation the table lacks falls back to its algorithm.
        self.assertEqual(levels.first_api_level("Cipher", "AES/CBC/PKCS7Padding"), 1)

    def test_an_unknown_or_missing_name_never_triggers(self):
        self.assertIsNone(levels.first_api_level("MessageDigest", "SHA3-256"))
        self.assertIsNone(levels.first_api_level("SecretKeyFactory", "Argon2"))
        self.assertIsNone(levels.first_api_level("NoSuchService", "AES"))


class IntroducedAlgorithmTests(unittest.TestCase):
    def test_a_name_passed_through_a_constant_is_introduced(self):
        [found] = levels.introduced_algorithms([edit()])
        self.assertEqual((found["service"], found["name"]),
                         ("SecretKeyFactory", "PBKDF2WithHmacSHA256"))
        self.assertFalse(found["guarded"])

    def test_a_name_the_original_already_passed_or_a_test_is_not_introduced(self):
        same = 'MessageDigest.getInstance("SHA-256")'
        self.assertEqual(levels.introduced_algorithms([edit(same, original=same)]), [])
        self.assertEqual(levels.introduced_algorithms(
            [edit(path="app/src/test/java/org/smsecure/KdfTest.java")]), [])

    def test_a_guard_or_a_named_provider_is_recorded(self):
        guarded = "if (Build.VERSION.SDK_INT >= 26) {\n" + CORRECTED + "\n}"
        self.assertTrue(levels.introduced_algorithms([edit(guarded)])[0]["guarded"])
        named = 'SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BC")'
        self.assertTrue(levels.introduced_algorithms([edit(named)])[0]["provider_named"])


class AboveMinSdkTests(unittest.TestCase):
    def check(self, directory, edits=None):
        return levels.algorithms_above_min_sdk({"repository_path": directory}, edits or [edit()])

    def test_smsecure_is_flagged_with_the_constraint_explained(self):
        with tempfile.TemporaryDirectory() as directory:
            repository(directory)
            [issue] = self.check(directory)
        self.assertEqual(issue["code"], "ALGORITHM_ABOVE_MIN_SDK")
        self.assertEqual((issue["first_api_level"], issue["min_sdk"]), (26, 24))
        self.assertIn("Build.VERSION.SDK_INT >= 26", issue["message"])
        self.assertIn("minSdk 26", issue["message"])

    def test_a_high_enough_min_sdk_a_bundled_or_registered_provider_or_a_guard_passes(self):
        cases = {
            "min_sdk": {"min_sdk": 26},
            "bouncycastle": {"dependencies": 'implementation("org.bouncycastle:bcprov-jdk18on:1.78")'},
            "conscrypt": {"dependencies": 'implementation("org.conscrypt:conscrypt-android:2.5.2")'},
            "registered": {"source": "Security.insertProviderAt(new MyProvider(), 1);"},
        }
        for name, options in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                repository(directory, **options)
                self.assertEqual(self.check(directory), [])
        with tempfile.TemporaryDirectory() as directory:
            repository(directory)
            guarded = "if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {\n" + CORRECTED + "\n}"
            self.assertEqual(self.check(directory, [edit(guarded)]), [])

    def test_no_repository_or_an_unreadable_min_sdk_passes(self):
        self.assertEqual(levels.algorithms_above_min_sdk({}, [edit()]), [])
        with tempfile.TemporaryDirectory() as directory:
            root = repository(directory)
            (root / "app" / "build.gradle.kts").write_text(
                "android { defaultConfig { minSdk = libs.versions.unknownName.get() } }",
                encoding="utf-8")
            self.assertEqual(self.check(directory), [])

    def test_it_regenerates_and_on_the_last_attempt_is_a_note_never_a_refusal(self):
        valid = {"status": "valid", "errors": [], "warnings": []}
        with tempfile.TemporaryDirectory() as directory:
            repository(directory)
            error = {"repository_path": directory}
            retried = levels.with_api_level_check(valid, error, [edit()])
            final = levels.with_api_level_check(valid, error, [edit()], final_attempt=True)
        self.assertEqual(retried["status"], "invalid")
        self.assertEqual([item["code"] for item in retried["errors"]], ["ALGORITHM_ABOVE_MIN_SDK"])
        self.assertEqual(final["status"], "valid")
        self.assertTrue(final["warnings"][0]["maintainer_decides"])

    def test_the_note_reaches_the_publication_verdict_without_blocking(self):
        from cognalys.utils.disposition import publication_after_validation
        from test_finding_disposition import validated_draft

        warning = {"code": "ALGORITHM_ABOVE_MIN_SDK", "maintainer_decides": True,
                   "details": ["SecretKeyFactory PBKDF2WithHmacSHA256: API 26+; minSdk 24"]}
        result = publication_after_validation(validated_draft(semantic_validation={
            "status": "valid", "errors": [], "warnings": [warning]}))
        self.assertTrue(result["publishable"], result["blocks"])
        self.assertIn("for the maintainer: ALGORITHM_ABOVE_MIN_SDK: SecretKeyFactory "
                      "PBKDF2WithHmacSHA256: API 26+; minSdk 24", result["notes"])


class CallGuardTests(unittest.TestCase):
    """Review of batch 14 (2026-10-31): one SDK_INT anywhere in an edit hid
    an unguarded call beside it, and a guard around the edit was not seen."""

    def test_each_call_has_its_own_guard(self):
        corrected = ('val f = if (Build.VERSION.SDK_INT >= 26) '
                     'SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1") else null\n'
                     'val m = Mac.getInstance("HmacSHA224")\n')
        found = levels.introduced_algorithms([{"source_file_path": KDF, "original_code": "x",
                                               "corrected_code": corrected}])
        guarded = {item["name"]: item["guarded"] for item in found}
        self.assertEqual(guarded, {"PBKDF2WithHmacSHA1": True, "HmacSHA224": False})

    def test_an_open_guarded_block_covers_the_call(self):
        corrected = ('if (Build.VERSION.SDK_INT >= 26) {\n'
                     '    skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");\n}\n'
                     'mac = Mac.getInstance("HmacSHA224");\n')
        found = levels.introduced_algorithms([{"source_file_path": KDF, "original_code": "x",
                                               "corrected_code": corrected}])
        guarded = {item["name"]: item["guarded"] for item in found}
        self.assertEqual(guarded, {"PBKDF2WithHmacSHA256": True, "HmacSHA224": False})

    def test_a_guard_around_the_edit_in_the_file_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / KDF
            source.parent.mkdir(parents=True)
            source.write_text("class M {\n  @RequiresApi(26)\n  static Key k() {\n"
                              + ORIGINAL + "\n  }\n}\n", encoding="utf-8")
            edit = {"source_file_path": KDF, "original_code": ORIGINAL,
                    "corrected_code": CORRECTED}
            [inside] = levels.introduced_algorithms([edit], Path(directory))
            [alone] = levels.introduced_algorithms([edit])
        self.assertTrue(inside["guarded"])
        self.assertFalse(alone["guarded"])


class MaintainerNoteTests(unittest.TestCase):
    """Your Local Weather (2026-11-02): the kept warning never reached the body."""

    WARNING = {"code": "ALGORITHM_ABOVE_MIN_SDK", "service": "SecretKeyFactory",
               "algorithm": "PBKDF2WithHmacSHA256", "first_api_level": 26, "min_sdk": 23,
               "maintainer_decides": True}
    DIFF = ('+    public static final String ALGORITHM = "PBKDF2WithHmacSHA256";')

    def test_a_kept_warning_becomes_a_plain_sentence(self):
        from cognalys.validation.android_api_levels import maintainer_notes
        notes = maintainer_notes([self.WARNING], self.DIFF)
        self.assertEqual(len(notes), 1)
        self.assertIn("only from Android 8.0 (API 26)", notes[0])
        self.assertIn("minSdk is 23", notes[0])
        self.assertIn("on Android 6.0 to 7.1", notes[0])
        self.assertNotIn("ALGORITHM_ABOVE_MIN_SDK", notes[0])

    def test_no_sentence_without_the_maintainer_or_without_the_algorithm_in_the_diff(self):
        from cognalys.validation.android_api_levels import maintainer_notes
        self.assertEqual(maintainer_notes([{**self.WARNING, "maintainer_decides": False}],
                                          self.DIFF), [])
        self.assertEqual(maintainer_notes([self.WARNING], '+    x = "PBKDF2WithHmacSHA512";'), [])
        self.assertEqual(maintainer_notes(["text warning"], self.DIFF), [])

    def test_a_level_without_a_version_name_gives_the_range_by_api_level(self):
        # Review of batch 17 (2026-11-02): API 21 with minSdk 19 said
        # "on Android 4.4" because API 20 has no entry.
        from cognalys.validation.android_api_levels import maintainer_notes
        notes = maintainer_notes([{**self.WARNING, "first_api_level": 21, "min_sdk": 19}],
                                 self.DIFF)
        self.assertIn("on API 19 to 20", notes[0])
        self.assertNotIn("on Android 4.4`", notes[0])

    def test_no_sentence_when_the_added_lines_branch_on_the_api_level(self):
        from cognalys.validation.android_api_levels import maintainer_notes
        guarded = self.DIFF + "\n+    if (Build.VERSION.SDK_INT >= 26) {"
        self.assertEqual(maintainer_notes([self.WARNING], guarded), [])


if __name__ == "__main__":
    unittest.main()
