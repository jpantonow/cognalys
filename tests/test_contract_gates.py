import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm import contract_gates as gates  # noqa: E402
from cognalys.llm.semantic_validation import validate_coordinated_semantics  # noqa: E402

PIN_HASH_SINK = {
    "persisted": True, "transmitted": False,
    "consumers": [{"kind": "persistence", "path": "app/PinSetupActivity.java", "line": 103,
                   "statement": ".putString(PrefsUtil.PIN_HASH, UtilFunctions.appLockDataHash(value))"}],
}
HIBP_SINK = {
    "persisted": False, "transmitted": True,
    "consumers": [{"kind": "network", "path": "app/api/ApiService.kt", "line": 27,
                   "statement": '@GET("range/{hashPrefix}")'}],
}


def edit(path, original, corrected, kind="production"):
    return {"source_file_path": path, "original_code": original,
            "corrected_code": corrected, "edit_kind": kind}


class TestExpectationTests(unittest.TestCase):
    """org.cry.otp's TOTP patch deleted the RFC 6238 vectors its test pinned."""

    ORIGINAL_TEST = '''
    String seed = "3132333435363738393031323334353637383930";
    String[] expectedTotpValues = {
            "94287082", "46119246", "90693936",
            "07081804", "68084774", "25091201",
    };
    assertEquals(expectedTotpValues[i], TOTP.generateTOTP(seed, time, "8", "HmacSHA1"));
    '''

    TEST_PATH = "app/src/test/java/TotpTests.java"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.repo = Path(self.directory.name)
        (self.repo / self.TEST_PATH).parent.mkdir(parents=True)
        (self.repo / self.TEST_PATH).write_text(self.ORIGINAL_TEST, encoding="utf-8")
        self.error = {"repository_path": str(self.repo)}

    def tearDown(self):
        self.directory.cleanup()

    def test_removing_known_answer_values_is_flagged(self):
        corrected = '''
    String seed = "3132333435363738393031323334353637383930313233343536373839303132";
    String[] expectedHmacSha256Values = { "46119246", "68084774" };
    assertEquals(expectedHmacSha256Values[i], TOTP.generateTOTP(seed, time, "8", "HmacSHA256"));
    '''
        [issue] = gates.rewritten_test_expectations(
            self.error, [edit(self.TEST_PATH, self.ORIGINAL_TEST, corrected, "test")])
        self.assertEqual(issue["code"], "EXISTING_TEST_EXPECTATIONS_REWRITTEN")

    def test_adding_a_test_to_an_existing_file_is_not(self):
        corrected = self.ORIGINAL_TEST + '''
    @Test public void rejectsEmptySeed() { assertThrows(IllegalArgumentException.class, () -> TOTP.generateTOTP("", 0, "8", "HmacSHA1")); }
    '''
        self.assertEqual(gates.rewritten_test_expectations(
            self.error, [edit(self.TEST_PATH, self.ORIGINAL_TEST, corrected, "test")]), [])

    def test_a_generated_test_being_repaired_is_not(self):
        """validation_fix rewrites a test this pipeline wrote, not the project's."""
        generated = "assertTrue(Service.missingSeam().isEmpty())"
        self.assertEqual(gates.rewritten_test_expectations(
            self.error, [edit("app/src/test/java/GeneratedTest.java", generated,
                              "assertTrue(true)", "test")]), [])

    def test_a_new_test_file_is_not(self):
        self.assertEqual(gates.rewritten_test_expectations(
            self.error, [edit("app/src/test/java/NewTest.java", "", "assertTrue(x);", "test")]), [])

    def test_without_the_repository_nothing_is_flagged(self):
        self.assertEqual(gates.rewritten_test_expectations(
            {}, [edit(self.TEST_PATH, self.ORIGINAL_TEST, "", "test")]), [])

    def test_production_code_is_not_read_as_a_test(self):
        self.assertEqual(gates.rewritten_test_expectations(
            self.error, [edit("app/src/main/java/Totp.java", 'check(a, "1");', 'check(a, "2");')]), [])


class StoredDerivationTests(unittest.TestCase):
    def test_a_stored_pin_hash_with_a_new_iteration_count_is_flagged(self):
        """BitBanana: the stored PIN hash would stop matching."""
        original = "PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);"
        corrected = "PBEKeySpec spec = new PBEKeySpec(password, salt, 10000, bytes * 8);"
        [issue] = gates.changed_stored_derivations(
            {"derived_value_consumers": PIN_HASH_SINK},
            [edit("app/UtilFunctions.java", original, corrected)])
        self.assertEqual(issue["code"], "STORED_DERIVED_VALUE_CHANGED")
        self.assertIn("is stored", issue["details"][0])

    def test_a_digest_sent_to_a_service_is_flagged(self):
        """Password Monitor: api.pwnedpasswords.com only answers SHA-1 prefixes."""
        [issue] = gates.changed_stored_derivations(
            {"derived_value_consumers": HIBP_SINK},
            [edit("app/AppModule.kt", 'single { MessageDigest.getInstance("SHA-1") }',
                  'single { MessageDigest.getInstance("SHA-256") }')])
        self.assertIn("sent out of the app", issue["details"][0])

    def test_keeping_the_old_derivation_for_existing_values_passes(self):
        """Verify-then-migrate keeps the original derivation on a legacy path."""
        original = 'SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")'
        corrected = ('if (legacy) { f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"); }\n'
                     'else { f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); }')
        self.assertEqual(gates.changed_stored_derivations(
            {"derived_value_consumers": PIN_HASH_SINK},
            [edit("app/Kdf.java", original, corrected)]), [])

    def test_a_call_given_a_variable_is_kept_only_with_the_reported_value(self):
        """EinkBro run_v2 (2026-10-22): getInstance(algorithm) was reported as
        dropped though the draft kept getInstance("SHA-1") on a legacy path;
        with no literal and no reported value nothing counts as kept."""
        original = "val digest = MessageDigest.getInstance(algorithm)"
        legacy = ('fun legacyKey(input: String) = MessageDigest.getInstance("SHA-1").digest(input)\n'
                  'fun key(input: String) = MessageDigest.getInstance("SHA-256").digest(input)')
        error = {"derived_value_consumers": PIN_HASH_SINK, "spec": "MessageDigestSpec",
                 "error_message": "expecting one of SHA-256,SHA-512 but found SHA-1",
                 "detector_context": {"value": "SHA-1"}}
        self.assertEqual(gates.changed_stored_derivations(
            error, [edit("util/HashUtilities.kt", original, legacy)]), [])
        dropped = 'fun key(input: String) = MessageDigest.getInstance("SHA-256").digest(input)'
        self.assertTrue(gates.changed_stored_derivations(
            error, [edit("util/HashUtilities.kt", original, dropped)]))
        # No reported value: a variable argument is never vacuously kept.
        self.assertTrue(gates.changed_stored_derivations(
            {"derived_value_consumers": PIN_HASH_SINK},
            [edit("util/HashUtilities.kt", original, legacy)]))
        # A value reported for another API never stands for this one.
        self.assertEqual(gates.reported_value_for(
            {"spec": "CipherSpec", "detector_context": {"value": "SHA-1"}},
            "MessageDigest.getInstance"), "")
        self.assertEqual(gates.reported_value_for(
            {"spec": "MessageDigestSpec", "error_message": "but found MD5"},
            "MessageDigest.getInstance"), "MD5")

    def test_a_value_that_stays_in_memory_passes(self):
        self.assertEqual(gates.changed_stored_derivations(
            {"derived_value_consumers": {"persisted": False, "transmitted": False, "consumers": []}},
            [edit("a.java", 'MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-256")')]),
            [])

    def test_a_random_seed_is_not_a_derivation(self):
        """Metadata Remover: nobody re-derives SecureRandom's output."""
        self.assertEqual(gates.changed_stored_derivations(
            {"derived_value_consumers": PIN_HASH_SINK},
            [edit("a.kt", 'SecureRandom("75rgu86gr59ht86".toByteArray())', "SecureRandom()")]), [])

    COMET_HELPER = (
        "object EncryptionHelper {\n"
        "    fun generateRandom(length: Int): ByteArray {\n"
        "        val bytes = ByteArray(length)\n"
        "        SecureRandom().nextBytes(bytes)\n"
        "        return bytes\n"
        "    }\n"
        "    fun keyFrom(passphrase: String): ByteArray {\n"
        "        val bytes = passphrase.toByteArray()\n"
        "        return bytes\n"
        "    }\n"
        "}\n")
    KEYGEN = ('val generator = KeyGenerator.getInstance("AES")\n'
              "generator.init(256)\nval key = generator.generateKey()")

    def _repository(self, directory):
        path = Path(directory) / "app/EncryptionHelper.kt"
        path.parent.mkdir(parents=True)
        path.write_text(self.COMET_HELPER, encoding="utf-8")
        return {"derived_value_consumers": PIN_HASH_SINK, "repository_path": str(directory)}

    def test_a_constructor_fed_fresh_random_material_is_not_a_stored_derivation(self):
        """CometOTP run_v6 (2026-11-10): SecretKeySpec(raw, "AES"), raw from
        SecureRandom on the branch that creates the key file, was refused three times."""
        original = ("if (!keyFile.exists()) {\n"
                    "    val raw = generateRandom(Constants.ENCRYPTION_KEY_LENGTH)\n"
                    '    val key = SecretKeySpec(raw, "AES")\n}')
        with tempfile.TemporaryDirectory() as directory:
            error = self._repository(directory)
            self.assertEqual(gates.changed_stored_derivations(
                error, [edit("app/EncryptionHelper.kt", original, self.KEYGEN)]), [])

    def test_material_filled_by_next_bytes_in_the_edit_is_fresh(self):
        original = ("byte[] raw = new byte[32];\nnew SecureRandom().nextBytes(raw);\n"
                    'SecretKey key = new SecretKeySpec(raw, "AES");')
        self.assertEqual(gates.changed_stored_derivations(
            {"derived_value_consumers": PIN_HASH_SINK},
            [edit("app/Keys.java", original, self.KEYGEN)]), [])

    def test_a_constructor_that_also_takes_a_password_is_still_flagged(self):
        """SMSecure's PBEKeySpec(passphrase, salt, ...) is derived again from what is stored."""
        original = ("byte[] salt = new byte[16];\nnew SecureRandom().nextBytes(salt);\n"
                    "PBEKeySpec spec = new PBEKeySpec(passphrase, salt, 1000, 256);")
        corrected = "PBEKeySpec spec = new PBEKeySpec(passphrase, salt, 600000, 256);"
        [issue] = gates.changed_stored_derivations(
            {"derived_value_consumers": PIN_HASH_SINK}, [edit("app/Kdf.java", original, corrected)])
        self.assertIn("PBEKeySpec(", issue["details"][0])

    def test_a_helper_that_derives_from_its_parameter_is_still_flagged(self):
        original = ('val raw = keyFrom(passphrase)\nval key = SecretKeySpec(raw, "AES")')
        with tempfile.TemporaryDirectory() as directory:
            error = self._repository(directory)
            [issue] = gates.changed_stored_derivations(
                error, [edit("app/EncryptionHelper.kt", original, self.KEYGEN)])
        self.assertIn("SecretKeySpec(raw", issue["details"][0])

    def test_material_that_may_be_read_back_is_still_flagged(self):
        """Review of 2026-11-10: a random source anywhere in the initializer, or a
        name given stored bytes later, let a stored key's constructor go."""
        conditional = ('val raw = if (keyFile.exists()) keyFile.readBytes() '
                       'else ByteArray(32).also { SecureRandom().nextBytes(it) }\n'
                       'val key = SecretKeySpec(raw, "AES")')
        elvis = ('val raw = stored ?: SecureRandom().generateSeed(32)\n'
                 'val key = SecretKeySpec(raw, "AES")')
        reassigned = ("byte[] raw = new byte[32];\nif (exists) raw = read();\n"
                      "else new SecureRandom().nextBytes(raw);\n"
                      'SecretKey key = new SecretKeySpec(raw, "AES");')
        for original in (conditional, elvis, reassigned):
            self.assertTrue(gates.changed_stored_derivations(
                {"derived_value_consumers": PIN_HASH_SINK},
                [edit("app/Keys.kt", original, self.KEYGEN)]), original)

    def test_without_the_file_source_a_helper_call_is_not_exempt(self):
        original = ('val raw = generateRandom(32)\nval key = SecretKeySpec(raw, "AES")')
        with tempfile.TemporaryDirectory() as directory:
            error = self._repository(directory)
            # A repair reads a worktree the patch is already applied to.
            patched = {**error, "repository_includes_patch": True}
            self.assertTrue(gates.changed_stored_derivations(
                patched, [edit("app/EncryptionHelper.kt", original, self.KEYGEN)]))
        self.assertTrue(gates.changed_stored_derivations(
            {"derived_value_consumers": PIN_HASH_SINK},
            [edit("app/EncryptionHelper.kt", original, self.KEYGEN)]))

    SMS_MAC_SECRET = (
        "private static byte[] generateMacSecret() {\n"
        "  try {\n"
        '    KeyGenerator generator = KeyGenerator.getInstance("HmacSHA1");\n'
        "    return generator.generateKey().getEncoded();\n"
        "  } catch (NoSuchAlgorithmException e) {\n    return null;\n  }\n}")

    def test_an_algorithm_given_only_to_a_random_generator_is_not_a_derivation(self):
        """ShortMessageSecure's generateMacSecret (frozen run, 2026-11-13):
        the stored MAC secret is a KeyGenerator's random output, and a draft
        asking for "HmacSHA256" was refused as changing a stored value."""
        corrected = self.SMS_MAC_SECRET.replace(
            '"HmacSHA1");', '"HmacSHA256");\n    generator.init(160);')
        self.assertEqual(gates.changed_stored_derivations(
            {"derived_value_consumers": PIN_HASH_SINK},
            [edit("app/MasterSecretUtil.java", self.SMS_MAC_SECRET, corrected)]), [])

    def test_key_pair_and_secure_random_factories_are_random_generators_too(self):
        for original, corrected in (
                ('val kpg = KeyPairGenerator.getInstance("RSA")\nkpg.initialize(1024)',
                 'val kpg = KeyPairGenerator.getInstance("EC")\nkpg.initialize(256)'),
                ('SecureRandom r = SecureRandom.getInstance("SHA1PRNG");\n'
                 'KeyGenerator g = KeyGenerator.getInstance(\n    "DES");',
                 'SecureRandom r = new SecureRandom();\n'
                 'KeyGenerator g = KeyGenerator.getInstance("AES");')):
            with self.subTest(original=original):
                self.assertEqual(gates.changed_stored_derivations(
                    {"derived_value_consumers": PIN_HASH_SINK},
                    [edit("app/Keys.kt", original, corrected)]), [])

    def test_the_same_algorithm_also_deriving_a_value_is_still_flagged(self):
        # "HmacSHA1" also keys a Mac over stored input: that value is derived.
        original = (self.SMS_MAC_SECRET + "\n"
                    'Mac mac = Mac.getInstance("HmacSHA1");\nmac.init(stored);')
        corrected = original.replace('"HmacSHA1"', '"HmacSHA256"')
        [issue] = gates.changed_stored_derivations(
            {"derived_value_consumers": PIN_HASH_SINK},
            [edit("app/MasterSecretUtil.java", original, corrected)])
        self.assertIn("Mac.getInstance", issue["details"][0])

    def test_a_digest_algorithm_literal_is_still_flagged(self):
        original = 'byte[] h = MessageDigest.getInstance("SHA-1").digest(pin);'
        corrected = 'byte[] h = MessageDigest.getInstance("SHA-256").digest(pin);'
        self.assertTrue(gates.changed_stored_derivations(
            {"derived_value_consumers": PIN_HASH_SINK},
            [edit("app/Pin.java", original, corrected)]))

    def test_the_semantic_validation_reports_both(self):
        error = {"derived_value_consumers": HIBP_SINK, "repository_path": ""}
        result = validate_coordinated_semantics(error, [
            edit("app/AppModule.kt", 'MessageDigest.getInstance("SHA-1")', 'MessageDigest.getInstance("SHA-256")'),
        ])
        self.assertIn("STORED_DERIVED_VALUE_CHANGED", {item["code"] for item in result["errors"]})


class PlanPolicyReconciliationTests(unittest.TestCase):
    """Your Local Weather run_v4 (2026-11-02): the plan kept 65,536 iterations
    while the parameter policy required at least 100000."""

    ERROR = {"case_migration_policy": {"required_numeric_constants": [{
        "symbol_pattern": r"(?i)^(?!.*(?:legacy|old)).*iterations.*$",
        "minimum": 100000}]}}

    def test_pinning_invariant_and_forbidden_change_are_rewritten(self):
        plan = {
            "behavioral_invariants": [
                "Each derivation retains fresh salt generation, 65,536 iterations and the key length.",
                "The preference key is unchanged."],
            "forbidden_changes": [
                "Do not change the iteration count, salt generation or preference key."],
        }
        rewritten = gates.reconcile_plan_with_parameter_policies(plan, self.ERROR)
        self.assertEqual(len(rewritten), 2)
        self.assertNotIn("65,536", plan["behavioral_invariants"][0])
        self.assertIn("at least 100,000 iterations", plan["behavioral_invariants"][0])
        self.assertIn("parameter_policies requires", plan["forbidden_changes"][0])
        self.assertEqual(plan["behavioral_invariants"][1], "The preference key is unchanged.")
        self.assertEqual(len(plan["parameter_policy_reconciliations"]), 2)

    def test_legacy_value_the_policy_excludes_is_kept(self):
        plan = {"behavioral_invariants": [
            "Legacy verification keeps 65,536 iterations for old verifiers."]}
        self.assertEqual(gates.reconcile_plan_with_parameter_policies(plan, self.ERROR), [])

    def test_no_policy_or_value_at_minimum_changes_nothing(self):
        plan = {"behavioral_invariants": ["Keep 210,000 iterations."],
                "forbidden_changes": ["Do not change the iteration count."]}
        self.assertEqual(gates.reconcile_plan_with_parameter_policies(dict(plan), {}), [])
        only_invariant = {"behavioral_invariants": ["Keep 210,000 iterations."]}
        self.assertEqual(
            gates.reconcile_plan_with_parameter_policies(only_invariant, self.ERROR), [])


if __name__ == "__main__":
    unittest.main()
