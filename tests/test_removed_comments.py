"""Comments a patch deletes that its change does not make false (BlueGate run_v8, 2026-10-31)."""
import unittest

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils.removed_comments import (  # noqa: E402
    UNRELATED_COMMENT_REMOVED, unrelated_comment_issues, unrelated_removed_comments,
)

KEY_MANAGER = "app/src/main/java/org/cleverfox/bluegate/KeyManager.kt"

# generateNewKeyPair as BlueGate has it, with the maintainer's commented-out
# ed25519 alternative.
GENERATE_ORIGINAL = """    private fun generateNewKeyPair(alias: String): KeyPair {
        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        val parameterSpec: KeyGenParameterSpec =
//            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
//            KeyGenParameterSpec.Builder(
//                alias,
//                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
//            ).setAlgorithmParameterSpec(ECGenParameterSpec("ed25519"))
//                .build()
//        } else {
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
//        }
        kpg.initialize(parameterSpec)
        return kpg.generateKeyPair()
    }
"""
# What run_v8's draft made of it: a new return type, the alternative gone.
GENERATE_RUN_V8 = """    private fun generateNewPrivateKeyEntry(alias: String): KeyStore.PrivateKeyEntry {
        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        val ecParameterSpec = ECGenParameterSpec("secp256r1")
        val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).setAlgorithmParameterSpec(ecParameterSpec)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build()
        kpg.initialize(parameterSpec)
        kpg.generateKeyPair()
        return keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
    }
"""
GET_ORIGINAL = """    fun getOrCreateKeyPair(): KeyPair {
        val alias = "BlueGate"
        if (keyStore.containsAlias(alias)) {
            try {
                val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
                // The following line is for validation and might not be strictly necessary
                // if getEntry succeeds, but it's good practice.
                return KeyPair(entry.certificate.publicKey, entry.privateKey)
            } catch (e: Exception) {
                // The stored key is likely corrupted or from an old, incompatible version.
                // Delete it and generate a new one.
                keyStore.deleteEntry(alias)
            }
        }
        return generateNewKeyPair(alias)
    }
"""
GET_RUN_V8 = """    fun getOrCreatePrivateKeyEntry(): KeyStore.PrivateKeyEntry {
        val alias = "BlueGate"
        if (keyStore.containsAlias(alias)) {
            try {
                return keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
            } catch (e: Exception) {
                // The stored key is likely corrupted or from an old, incompatible version.
                // Delete it and generate a new one.
                keyStore.deleteEntry(alias)
            }
        }
        return generateNewPrivateKeyEntry(alias)
    }
"""


def edit(original, corrected, symbol="m", path=KEY_MANAGER):
    return {"source_file_path": path, "symbol": symbol, "edit_kind": "method",
            "original_code": original, "corrected_code": corrected}


class BlueGateRunV8Tests(unittest.TestCase):
    def test_the_deleted_commented_out_alternative_is_reported(self):
        found = unrelated_removed_comments([
            edit(GET_ORIGINAL, GET_RUN_V8, "getOrCreateKeyPair"),
            edit(GENERATE_ORIGINAL, GENERATE_RUN_V8, "generateNewKeyPair")])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["symbols"], ["generateNewKeyPair"])
        self.assertIn('KeyGenParameterSpec.Builder(', found[0]["lines"])
        self.assertIn(').setAlgorithmParameterSpec(ECGenParameterSpec("ed25519"))',
                      found[0]["lines"])

    def test_the_comment_on_the_removed_keypair_line_may_go(self):
        # "The following line ..." described `return KeyPair(...)`, which the
        # fix removed.
        self.assertEqual(unrelated_removed_comments(
            [edit(GET_ORIGINAL, GET_RUN_V8, "getOrCreateKeyPair")]), [])

    def test_the_draft_that_keeps_the_alternative_passes(self):
        kept = GENERATE_ORIGINAL.replace(
            "private fun generateNewKeyPair(alias: String): KeyPair {",
            "private fun generateNewPrivateKeyEntry(alias: String): KeyStore.PrivateKeyEntry {"
        ).replace("        return kpg.generateKeyPair()\n",
                  "        kpg.generateKeyPair()\n"
                  "        return keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry\n")
        self.assertEqual(unrelated_removed_comments([edit(GENERATE_ORIGINAL, kept)]), [])

    def test_the_error_regenerates_only_that_file_and_says_why(self):
        issues = unrelated_comment_issues([edit(GENERATE_ORIGINAL, GENERATE_RUN_V8,
                                                "generateNewKeyPair")])
        self.assertEqual([issue["code"] for issue in issues], [UNRELATED_COMMENT_REMOVED])
        self.assertEqual(issues[0]["affected_paths"], [KEY_MANAGER])
        self.assertIn("Keep them in corrected_code where they were, verbatim",
                      issues[0]["details"][0])
        # The check cannot always tell a comment the change made false
        # (review of 2026-10-31): the regeneration may still update one.
        self.assertIn("or updated to describe the new code", issues[0]["details"][0])
        self.assertIn("(in generateNewKeyPair)", issues[0]["details"][0])


class WhatAChangeMakesFalseTests(unittest.TestCase):
    def test_commented_out_code_naming_a_removed_identifier_may_go(self):
        original = "// legacyDigest(data)\nval hash = legacyDigest(data)\nsend(hash)"
        corrected = "val hash = sha256(data)\nsend(hash)"
        self.assertEqual(unrelated_removed_comments([edit(original, corrected)]), [])

    def test_commented_out_code_the_patch_enables_may_go(self):
        original = ('val ctx = SSLContext.getInstance("SSL")\n'
                    '// val ctx = SSLContext.getInstance("TLS")\nuse(ctx)')
        corrected = 'val ctx = SSLContext.getInstance("TLS")\nuse(ctx)'
        self.assertEqual(unrelated_removed_comments([edit(original, corrected)]), [])

    def test_prose_above_changed_code_may_go(self):
        original = ("// Use the legacy provider here\n"
                    'val cipher = Cipher.getInstance("DES")\n\nreturn cipher')
        corrected = 'val cipher = Cipher.getInstance("AES/GCM/NoPadding")\n\nreturn cipher'
        self.assertEqual(unrelated_removed_comments([edit(original, corrected)]), [])

    def test_prose_above_unchanged_code_is_reported(self):
        original = ("// Retry once: the server drops the first handshake\n"
                    "connect()\n\n"
                    'val cipher = Cipher.getInstance("DES")')
        corrected = 'connect()\n\nval cipher = Cipher.getInstance("AES/GCM/NoPadding")'
        found = unrelated_removed_comments([edit(original, corrected)])
        self.assertEqual(found[0]["lines"],
                         ["Retry once: the server drops the first handshake"])

    def test_a_todo_beside_the_change_is_reported(self):
        original = ('val md = MessageDigest.getInstance("MD5")\n'
                    "// TODO move hashing to a worker thread\nnotifyDone()\n")
        corrected = 'val md = MessageDigest.getInstance("SHA-256")\nnotifyDone()\n'
        self.assertEqual(len(unrelated_removed_comments([edit(original, corrected)])), 1)

    def test_a_trailing_comment_with_nothing_after_it_follows_the_code_before(self):
        # Nothing follows it, so it is read as describing the changed line
        # above: kept out of the verdict (the false-positive bar is high).
        original = ('val md = MessageDigest.getInstance("MD5")\n'
                    "// MD5 is enough for a cache key\n")
        corrected = 'val md = MessageDigest.getInstance("SHA-256")\n'
        self.assertEqual(unrelated_removed_comments([edit(original, corrected)]), [])

    def test_a_comment_reworded_in_place_is_an_update(self):
        # TOTP's @param line without HmacSHA1 (run_20261009_012517).
        original = ("/**\n * @param crypto the crypto algorithm (HmacSHA1, HmacSHA256)\n */\n"
                    "static byte[] hmac(String crypto) { return mac(crypto, \"RAW\"); }")
        corrected = ("/**\n * @param crypto the crypto algorithm (HmacSHA256)\n */\n"
                     "static byte[] hmac(String crypto) { return mac(crypto, \"RAW\"); }")
        self.assertEqual(unrelated_removed_comments([edit(original, corrected)]), [])

    def test_prose_made_false_by_a_removed_name_may_go(self):
        # zSMTH run7 (2026-10-17): the trust-all manager went, and so did
        # "Create an ssl socket factory with our all-trusting manager".
        original = ("sslContext.init(null, trustAllCerts, null);\n"
                    "// Create an ssl socket factory with our all-trusting manager\n"
                    "final SSLSocketFactory factory = sslContext.getSocketFactory();")
        corrected = ("sslContext.init(null, new TrustManager[] { platform }, null);\n"
                     "final SSLSocketFactory factory = sslContext.getSocketFactory();")
        self.assertEqual(unrelated_removed_comments([edit(original, corrected)]), [])

    def test_prose_above_code_moved_into_another_block_may_go(self):
        # Grocy run_v6 (2026-10-26): keyStore.load(null, null) moved under the
        # first-run branch, and "Initialize empty keystore" went with it.
        original = ("    // Initialize empty keystore\n    keyStore = KeyStore.getInstance(\"BKS\");\n"
                    "    try {\n      keyStore.load(null, null);\n    } catch (Exception e) {\n"
                    "      throw new KeyStoreException(e);\n    }\n    open(file);")
        corrected = ("    keyStore = KeyStore.getInstance(\"BKS\");\n    if (!file.exists()) {\n"
                     "      try {\n        keyStore.load(null, null);\n      } catch (Exception e) {\n"
                     "        throw new KeyStoreException(e);\n      }\n      return;\n    }\n"
                     "    open(file);")
        self.assertEqual(unrelated_removed_comments([edit(original, corrected)]), [])

    def test_a_comment_moved_or_reindented_is_not_deleted(self):
        original = "    // keep the old key readable\n    read(old)\n    x = 1"
        corrected = "    x = 2\n        // keep the old key readable\n        read(old)"
        self.assertEqual(unrelated_removed_comments([edit(original, corrected)]), [])

    def test_a_comment_kept_by_another_edit_of_the_file_is_not_deleted(self):
        first = edit("// shared salt\nval salt = SALT\nx = 1", "x = 2", "a")
        second = edit("y = 1", "// shared salt\nval salt = SALT\ny = 1", "b")
        self.assertEqual(unrelated_removed_comments([first, second]), [])

    def test_a_deleted_declaration_takes_its_comments_with_it(self):
        original = "/** Hashes with MD5. */\nfun md5(x: String) = digest(x)\n// unused()"
        self.assertEqual(unrelated_removed_comments([{**edit(original, ""),
                                                      "edit_kind": "delete"}]), [])

    def test_a_block_comment_line_is_a_comment(self):
        original = ("/*\n * Copyright the authors\n */\n"
                    'val c = Cipher.getInstance("DES")')
        corrected = 'val c = Cipher.getInstance("AES/GCM/NoPadding")'
        found = unrelated_removed_comments([edit(original, corrected)])
        self.assertEqual(found[0]["lines"], ["Copyright the authors"])

    def test_a_file_in_another_syntax_is_never_judged(self):
        original = "# keep this\nkey = 1\nother = 2"
        self.assertEqual(unrelated_removed_comments([
            edit(original, "other = 3", path="config/settings.py")]), [])


class CoordinatedGenerationTests(unittest.TestCase):
    def test_a_regenerating_error_before_the_last_attempt_a_warning_on_it(self):
        from cognalys.llm.coordinated_generation import with_removed_comment_check

        edits = [edit(GENERATE_ORIGINAL, GENERATE_RUN_V8, "generateNewKeyPair")]
        valid = {"status": "valid", "errors": [], "warnings": []}
        retried = with_removed_comment_check(valid, edits)
        self.assertEqual(retried["status"], "invalid")
        self.assertEqual([item["code"] for item in retried["errors"]],
                         [UNRELATED_COMMENT_REMOVED])
        kept = with_removed_comment_check(valid, edits, final_attempt=True)
        self.assertEqual(kept["status"], "valid")
        self.assertTrue(kept["warnings"][0]["kept_on_final_attempt"])
        self.assertIs(with_removed_comment_check(valid, [edit("a()", "b()")]), valid)

    def test_every_generator_and_the_plan_are_told_to_keep_comments(self):
        import inspect

        from cognalys.llm import coordinated_generation, finding_adjudication, prompt_builders
        from cognalys.llm.fix_generation_common import COMMENT_PRESERVATION_GUIDANCE
        from cognalys.validation import repair

        self.assertIn("a commented-out alternative, a TODO the change does not resolve",
                      COMMENT_PRESERVATION_GUIDANCE)
        self.assertIn("Only a comment that describes code this change removes or changes",
                      COMMENT_PRESERVATION_GUIDANCE)
        for module in (coordinated_generation, finding_adjudication, prompt_builders, repair):
            with self.subTest(module=module.__name__):
                self.assertIn("COMMENT_PRESERVATION_GUIDANCE", inspect.getsource(module))


NET = "app/src/main/java/org/example/Net.kt"


class ReviewOf20261031Tests(unittest.TestCase):
    """Probes of the independent review of 2026-10-31, each now decided as it must be."""

    def check(self, original, corrected, path=NET):
        return unrelated_removed_comments([edit(original, corrected, path=path)])

    def test_prose_ending_in_a_parenthesis_or_comma_is_not_commented_out_code(self):
        # It was read as code, so the line it describes was never looked at.
        for comment in ("        // Build the context (see issue #42)\n",
                        "        // Older devices, sadly,\n        // need this:\n"):
            with self.subTest(comment=comment):
                self.assertEqual(self.check(
                    "    fun client(): SSLContext {\n" + comment
                    + '        val ctx = SSLContext.getInstance("SSL")\n        return ctx\n    }',
                    '    fun client(): SSLContext {\n        val ctx = SSLContext.getInstance("TLS")\n'
                    "        return ctx\n    }"), [])

    def test_a_value_with_separators_is_read_whole(self):
        # The `1` of SHA-1 and the `2` of TLSv1.2 were too short to count.
        cases = [("SHA-1 fingerprints match what the admin panel shows", "SHA-1", "SHA-256"),
                 ("TLSv1.2 is the newest our server speaks", "TLSv1.2", "TLSv1.3")]
        for comment, before, after in cases:
            with self.subTest(value=before):
                self.assertEqual(self.check(
                    f"    fun f() {{\n        // {comment}\n        val host = config.host\n\n"
                    f'        val x = Api.getInstance("{before}")\n    }}',
                    f'    fun f() {{\n        val host = config.host\n\n'
                    f'        val x = Api.getInstance("{after}")\n    }}'), [])

    def test_a_todo_the_change_resolves_may_go(self):
        self.assertEqual(self.check(
            "    fun encrypt(data: ByteArray): ByteArray {\n        // TODO: switch to GCM\n"
            "        val key = loadKey()\n\n"
            '        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")\n'
            "        return cipher.doFinal(data)\n    }",
            "    fun encrypt(data: ByteArray): ByteArray {\n        val key = loadKey()\n\n"
            '        val cipher = Cipher.getInstance("AES/GCM/NoPadding")\n'
            "        return cipher.doFinal(data)\n    }"), [])

    def test_comments_in_a_block_the_patch_deleted_go_with_it(self):
        self.assertEqual(self.check(
            "    fun decrypt(data: ByteArray, legacy: Boolean): ByteArray {\n"
            "        if (legacy) {\n            // cipher.init(Cipher.DECRYPT_MODE, key)\n"
            "            return decryptLegacy(data)\n        }\n        return decryptGcm(data)\n    }",
            "    fun decrypt(data: ByteArray, legacy: Boolean): ByteArray {\n"
            "        return decryptGcm(data)\n    }"), [])

    def test_a_commented_out_alternative_of_the_changed_call_stays(self):
        # Like BlueGate's ed25519 alternative beside the secp256r1 builder: the
        # change does not make a commented-out alternative false.
        found = self.check(
            '    fun cipher(): Cipher {\n        // return Cipher.getInstance("AES/ECB/PKCS5Padding")\n'
            '        return Cipher.getInstance("AES")\n    }',
            '    fun cipher(): Cipher {\n        return Cipher.getInstance("AES/GCM/NoPadding")\n    }')
        self.assertEqual(found[0]["lines"], ['return Cipher.getInstance("AES/ECB/PKCS5Padding")'])

    def test_prose_sharing_only_a_kept_name_with_new_code_is_reported(self):
        found = self.check(
            "    fun store(key: PrivateKey, chain: Array<Certificate>) {\n"
            "        // The password comes from the user's settings, never hard-coded\n"
            "        val password = settings.password()\n\n"
            "        keyStore.setKeyEntry(ALIAS, key, password, chain)\n    }",
            "    fun store(key: PrivateKey, chain: Array<Certificate>) {\n"
            "        val password = settings.password()\n\n"
            "        keyStore.setEntry(ALIAS, KeyStore.PrivateKeyEntry(key, chain),\n"
            "            KeyStore.PasswordProtection(password))\n    }")
        self.assertEqual(found[0]["lines"],
                         ["The password comes from the user's settings, never hard-coded"])

    def test_an_unrelated_doc_comment_of_a_method_whose_body_changed_is_reported(self):
        found = self.check(
            "    /**\n     * Opens the app's key store.\n     * @param context used to open the bundled file\n"
            "     */\n    fun load(context: Context): KeyStore {\n"
            '        val ks = KeyStore.getInstance("BKS")\n        ks.load(open(context), PASSWORD)\n'
            "        return ks\n    }",
            "    fun load(context: Context): KeyStore {\n"
            "        val ks = KeyStore.getInstance(KeyStore.getDefaultType())\n"
            "        ks.load(open(context), PASSWORD)\n        return ks\n    }")
        self.assertEqual(len(found), 1)

    def test_prose_above_an_unchanged_statement_of_a_rewritten_run_is_reported(self):
        found = self.check(
            "    fun hash(data: ByteArray): ByteArray {\n        // Callers hold the lock while this runs\n"
            '        val copy = data.copyOf()\n        val md = MessageDigest.getInstance("MD5")\n'
            "        return md.digest(copy)\n    }",
            "    fun hash(data: ByteArray): ByteArray {\n        val copy = data.copyOf()\n"
            '        val md = MessageDigest.getInstance("SHA-256")\n        return md.digest(copy)\n    }')
        self.assertEqual(found[0]["lines"], ["Callers hold the lock while this runs"])


MAIN = "src/Main.java"
COMMENTED = "class X {\n    void method() {\n        // int legacy = 0;\n        int value = 1;\n    }\n}\n"
DELETES = {"symbol": "method", "original_code": "        // int legacy = 0;\n        int value = 1;",
           "corrected_code": "        int value = 2;"}
KEEPS = {"symbol": "method", "original_code": "        // int legacy = 0;\n        int value = 1;",
         "corrected_code": "        // int legacy = 0;\n        int value = 2;"}


def coordinated_run(drafts, reviews):
    """A coordinated generation of src/Main.java: draft call n carries drafts[n] (the
    last one repeats), behaviour review n answers reviews[n] (the last repeats)."""
    import json
    import logging
    import tempfile
    from pathlib import Path

    from cognalys.llm.generate_error_fixes import FixGenerator

    class Provider:
        def __init__(self):
            self.drafts = self.reviews = 0

        def generate(self, prompt, *args, **kwargs):
            if kwargs.get("schema_name") == "behavior_review":
                self.reviews += 1
                return json.dumps(reviews[min(self.reviews, len(reviews)) - 1])
            self.drafts += 1
            chosen = drafts[min(self.drafts, len(drafts)) - 1]
            return json.dumps({
                "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "source_file_path": MAIN,
                "explanation": "e",
                "edits": [{"source_file_path": MAIN, "edit_kind": "declaration",
                           "reason": "r", **chosen}],
                "no_change_required": False, "provided_contracts": [],
                "required_contracts": [], "required_tests": [],
                "manual_review_required": True, "review_assumptions": [], "confidence": "high"})

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "repo/src").mkdir(parents=True)
        (root / "repo" / MAIN).write_text(COMMENTED, encoding="utf-8")
        generator = object.__new__(FixGenerator)
        generator.output_dir = root / "out"
        generator.provider = Provider()
        generator.web_search = False
        generator.logger = logging.getLogger("test")
        error = {"repository_path": str(root / "repo"), "error_index": 2,
                 "source_file_path": MAIN, "method_name": "method",
                 "evidence_analysis": {"confirmed_cause": "cause", "coordinated_fix_plan": {
                     "required_edits": [{"source_file_path": MAIN, "symbol": "method"}]}}}
        result = generator.generate_coordinated_file_drafts(
            error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "method")
    return result, generator.provider


CLEAN = {"regressions": [], "maintainer_decision_required": False, "maintainer_decision": "",
         "rationale": ""}
REGRESSION = {**CLEAN, "regressions": [{"scenario": "first run", "before": "a", "after": "b",
                                        "source_file_path": MAIN}]}


class KeptDraftTests(unittest.TestCase):
    """Review of 2026-10-31: a draft regenerated only for a deleted comment was lost
    when the regenerated drafts failed for another reason."""

    def test_the_reviewed_draft_is_kept_when_the_regeneration_regresses(self):
        result, provider = coordinated_run([DELETES, KEEPS], [CLEAN, REGRESSION])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["edits"][0]["corrected_code"], DELETES["corrected_code"])
        self.assertTrue(any(item.get("code") == UNRELATED_COMMENT_REMOVED
                            and item.get("kept_on_final_attempt")
                            for item in result["semantic_validation"]["warnings"]))
        self.assertGreater(provider.drafts, 1)

    def test_a_regeneration_that_keeps_the_comment_wins(self):
        result, provider = coordinated_run([DELETES, KEEPS], [CLEAN])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["edits"][0]["corrected_code"], KEEPS["corrected_code"])
        self.assertEqual(provider.drafts, 2)

    def test_the_comment_check_is_a_note_on_the_last_attempt(self):
        result, provider = coordinated_run([DELETES], [CLEAN])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["edits"][0]["corrected_code"], DELETES["corrected_code"])
        self.assertEqual(provider.reviews, provider.drafts)




if __name__ == "__main__":
    unittest.main()
