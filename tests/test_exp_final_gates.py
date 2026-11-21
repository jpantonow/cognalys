"""Gates and facts added after the exp_final_20261019 subset review."""
import unittest

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.contract_gates import constant_material_flows  # noqa: E402
from cognalys.llm.evidence_packet import constant_material_evidence  # noqa: E402
from cognalys.llm.semantic_validation import (  # noqa: E402
    comment_only_changes, discarded_governed_calls,
)

KEYSTORE = {"specification_context": {"events": [
    {"name": "Load", "api_patterns": [".load("]},
    {"name": "GetEntry", "api_patterns": [".getEntry("]},
    {"name": "GetKey", "api_patterns": [".getKey("]},
]}}


def edit(original, corrected, path="app/src/main/java/a/CryptoManager.kt"):
    return {"source_file_path": path, "original_code": original,
            "corrected_code": corrected, "edit_kind": "method"}


class DiscardedGovernedCallTests(unittest.TestCase):
    ORIGINAL = "val k = (keyStore.getEntry(key, null) as? SecretKeyEntry)?.secretKey ?: createKey(key)"

    def test_the_traffic_light_patch_is_rejected(self):
        corrected = (
            "val entry = keyStore.getEntry(key, null)\n"
            "try {\n    keyStore.getKey(key, null)\n} catch (_: Exception) {\n"
            "    // Preserve the existing lookup.\n}\n"
            "val k = (entry as? SecretKeyEntry)?.secretKey ?: createKey(key)"
        )
        issues = discarded_governed_calls(KEYSTORE, [edit(self.ORIGINAL, corrected)])
        self.assertEqual([issue["code"] for issue in issues],
                         ["GOVERNED_CALL_RESULT_DISCARDED"])

    def test_the_tokn_patch_passes(self):
        corrected = "return keystore.getKey(KEY_ALIAS, null) as SecretKey"
        self.assertEqual(discarded_governed_calls(KEYSTORE, [edit(self.ORIGINAL, corrected)]), [])

    def test_a_call_outside_the_governed_api_is_not_flagged(self):
        corrected = self.ORIGINAL + "\ntry { file.delete() } catch (e: Exception) { }"
        self.assertEqual(discarded_governed_calls(KEYSTORE, [edit(self.ORIGINAL, corrected)]), [])

    def test_a_handled_exception_is_not_flagged(self):
        corrected = self.ORIGINAL + "\ntry { keyStore.getKey(key, null) } catch (e: Exception) { log(e) }"
        self.assertEqual(discarded_governed_calls(KEYSTORE, [edit(self.ORIGINAL, corrected)]), [])

    def test_an_existing_block_the_patch_kept_is_not_flagged(self):
        both = self.ORIGINAL + "\ntry { keyStore.getKey(key, null) } catch (e: Exception) { }"
        self.assertEqual(discarded_governed_calls(KEYSTORE, [edit(both, both + "\nx()")]), [])


class CommentOnlyChangeTests(unittest.TestCase):
    ORIGINAL = 'if (shaType == 0) {\n    crypto = "HmacSHA1";\n}'

    def test_the_motp_patch_is_rejected(self):
        corrected = ('if (shaType == 0) {\n    // RFC 6238 default; changing this breaks '
                     'SHA-1-enrolled authenticators.\n    crypto = "HmacSHA1";\n}')
        issues = comment_only_changes([edit(self.ORIGINAL, corrected, "app/src/main/java/TOTP.java")])
        self.assertEqual([issue["code"] for issue in issues], ["COMMENT_ONLY_CHANGE"])

    def test_a_literal_change_is_code(self):
        corrected = self.ORIGINAL.replace("HmacSHA1", "HmacSHA256")
        self.assertEqual(comment_only_changes([edit(self.ORIGINAL, corrected)]), [])

    def test_a_comment_beside_a_code_change_is_fine(self):
        corrected = self.ORIGINAL.replace('"HmacSHA1";', '"HmacSHA256"; // compliant')
        self.assertEqual(comment_only_changes([edit(self.ORIGINAL, corrected)]), [])

    def test_a_test_only_patch_is_not_judged_here(self):
        self.assertEqual(comment_only_changes([
            {**edit("a()", "a() // x", "app/src/test/java/T.java"), "edit_kind": "test"}]), [])


class ConstantMaterialTests(unittest.TestCase):
    MTGFAM = (
        "public void fetch() {\n"
        "    SecretKey sk = new SecretKeySpec(context.getString(R.string.key_lastLegalityUpdate)"
        ".substring(0, 16).getBytes(StandardCharsets.UTF_8), \"AES\");\n"
        "    IvParameterSpec iv = new IvParameterSpec(sk.getEncoded());\n"
        "}\n"
    )

    def test_the_mtgfam_key_and_iv_come_from_the_resource(self):
        flows = constant_material_flows(self.MTGFAM)
        self.assertEqual([flow["constant_sources"] for flow in flows],
                         [["R.string.key_lastLegalityUpdate"]] * 2)
        self.assertTrue(flows[1]["call"].startswith("IvParameterSpec(sk.getEncoded())"))
        self.assertTrue(flows[1]["through_locals"][0].startswith("sk = new SecretKeySpec("))
        self.assertIn("compiled into the application",
                      constant_material_evidence(self.MTGFAM)["meaning"])

    def test_algorithm_names_and_tag_lengths_are_not_material(self):
        code = ("SecretKeySpec k = new SecretKeySpec(key, KEY_ALGORITHM);\n"
                "GCMParameterSpec p = new GCMParameterSpec(TAG_SIZE * 8, nonce);\n"
                "SecretKeySpec m = new SecretKeySpec(keyBytes, \"RAW\");")
        self.assertEqual(constant_material_flows(code), [])

    def test_random_material_is_not_flagged(self):
        code = ("byte[] iv = new byte[16];\nnew SecureRandom().nextBytes(iv);\n"
                "IvParameterSpec spec = new IvParameterSpec(iv);")
        self.assertEqual(constant_material_flows(code), [])
        self.assertEqual(constant_material_evidence(code), {})

    def test_a_constant_seed_is_flagged(self):
        code = 'val random = SecureRandom("75rgu86gr59ht86".toByteArray(Charsets.UTF_8))'
        self.assertEqual(constant_material_flows(code)[0]["constant_sources"],
                         ['"75rgu86gr59ht86"'])


if __name__ == "__main__":
    unittest.main()


import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from cognalys.llm.semantic_validation import (  # noqa: E402
    caller_value_overrides, neutralized_option_branches, reported_value_untouched,
)


class CallerValueOverrideTests(unittest.TestCase):
    def test_the_droid_scep_key_length_coercion_is_rejected(self):
        original = ("    public void CertReq(int isKeyLen) {\n"
                    "        keyGen.initialize(isKeyLen);\n    }")
        corrected = ("    public void CertReq(int isKeyLen) {\n"
                     "        int keyLength = isKeyLen == 3072 ? 3072 : 4096;\n"
                     "        keyGen.initialize(keyLength);\n    }")
        issues = caller_value_overrides({}, [edit(original, corrected, "app/src/main/java/S.java")])
        self.assertEqual([issue["code"] for issue in issues], ["CALLER_SUPPLIED_VALUE_OVERRIDDEN"])

    def test_a_value_read_from_a_setting_counts(self):
        original = "    void f() {\n        int n = prefs.getInt(\"len\", 2048);\n    }"
        corrected = ("    void f() {\n        int n = prefs.getInt(\"len\", 2048);\n"
                     "        n = n.coerceIn(3072, 4096)\n    }")
        self.assertEqual(len(caller_value_overrides({}, [edit(original, corrected)])), 1)

    def test_replacing_an_application_literal_is_a_fix(self):
        original = "    void f() {\n        keyGen.initialize(1024);\n    }"
        corrected = "    void f() {\n        keyGen.initialize(3072);\n    }"
        self.assertEqual(caller_value_overrides({}, [edit(original, corrected)]), [])


class _RepositoryCase(unittest.TestCase):
    def run_gate(self, gate, relative, original, patched, error=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / relative).parent.mkdir(parents=True)
            (root / relative).write_text(original, encoding="utf-8")
            change = {"source_file_path": relative, "original_code": original,
                      "corrected_code": patched, "edit_kind": "method"}
            return gate({"repository_path": str(root), **(error or {})}, [change])


class NeutralizedOptionTests(_RepositoryCase):
    ORIGINAL = (
        "class S {\n    private SSLSocketFactory insecureFactory = build();\n"
        "    void open(HttpsURLConnection c) {\n"
        "        if (Util.isAllowInsecureEnabled(context)) {\n"
        "            c.setSSLSocketFactory(insecureFactory);\n        }\n    }\n}\n"
    )

    def test_the_dsub_option_emptied_of_its_effect_is_rejected(self):
        patched = self.ORIGINAL.replace(
            "private SSLSocketFactory insecureFactory = build();",
            "private SSLSocketFactory factory = platform();").replace(
            "c.setSSLSocketFactory(insecureFactory);", "c.setSSLSocketFactory(factory);")
        issues = self.run_gate(neutralized_option_branches, "app/S.java", self.ORIGINAL, patched)
        self.assertEqual([issue["code"] for issue in issues], ["USER_OPTION_NEUTRALIZED"])

    def test_a_patch_that_keeps_the_branch_passes(self):
        patched = self.ORIGINAL.replace("    void open", "    void other() {}\n    void open")
        self.assertEqual(self.run_gate(neutralized_option_branches, "app/S.java",
                                       self.ORIGINAL, patched), [])

    def test_a_removed_keyword_is_not_a_lost_behaviour(self):
        original = ("class P {\n    void f() {\n        if (Prefs.isEmergencyPinEnabled()) {\n"
                    "            try { g(); } catch (Exception e) { throw new RuntimeException(e); }\n"
                    "        }\n        throw new IllegalStateException();\n    }\n}\n")
        patched = original.replace(
            "try { g(); } catch (Exception e) { throw new RuntimeException(e); }", "g();").replace(
            "        throw new IllegalStateException();\n", "")
        self.assertEqual(self.run_gate(neutralized_option_branches, "app/P.java", original, patched), [])


class ReportedValueTests(_RepositoryCase):
    ORIGINAL = ("class U {\n    static byte[] derive(char[] p, byte[] s) {\n"
                "        PBEKeySpec spec = new PBEKeySpec(p, s, iterations(), 256);\n"
                "        return f(spec);\n    }\n    static int iterations() { return 5000; }\n}\n")
    ERROR = {"detector_context": {"value": "5000", "label": "violation",
                                  "source_location": "U.java:3"},
             "method_name": "derive", "csv_class": "a.U"}

    def test_the_bitbanana_side_fix_is_rejected(self):
        patched = self.ORIGINAL.replace("return f(spec);",
                                        "try { return f(spec); } finally { spec.clearPassword(); }")
        issues = self.run_gate(reported_value_untouched, "app/U.java", self.ORIGINAL, patched, self.ERROR)
        self.assertEqual([issue["code"] for issue in issues], ["REPORTED_VALUE_UNTOUCHED"])

    def test_changing_the_value_where_it_comes_from_is_a_fix(self):
        patched = self.ORIGINAL.replace("return 5000;", "return 210000;")
        self.assertEqual(self.run_gate(reported_value_untouched, "app/U.java",
                                       self.ORIGINAL, patched, self.ERROR), [])

    TOTP = ("class T {\n    byte[] hmac_sha(String crypto, byte[] keyBytes, byte[] text) {\n"
            "        Mac hmac = Mac.getInstance(crypto);\n"
            "        SecretKeySpec macKey = new SecretKeySpec(keyBytes, \"RAW\");\n"
            "        hmac.init(macKey);\n        return hmac.doFinal(text);\n    }\n"
            "    static String DEFAULT = \"HmacSHA1\";\n}\n")
    JOINT = {"detector_context": {"value": "HmacSHA1", "label": "violation",
                                  "source_location": "T.java:3"},
             "method_name": "hmac_sha", "csv_class": "a.T",
             "joint_findings": [{"unique_error_id": "k1", "specification": "SecretKeySpecSpec",
                                 "method": "hmac_sha"}],
             "joint_detector_contexts": {"k1": {"value": "RAW", "label": "violation",
                                                "source_location": "T.java:4"}}}

    def test_a_patch_that_fixes_only_the_joint_finding_is_left_to_the_review(self):
        """org.cry.otp hmac_sha, c_arm_k3 r2: the label fix died as REPORTED_VALUE_UNTOUCHED."""
        patched = self.TOTP.replace('new SecretKeySpec(keyBytes, "RAW")',
                                    'new SecretKeySpec(keyBytes, crypto)')
        self.assertEqual(self.run_gate(reported_value_untouched, "app/T.java",
                                       self.TOTP, patched, self.JOINT), [])

    def test_without_the_joint_finding_the_same_patch_is_still_flagged(self):
        patched = self.TOTP.replace('new SecretKeySpec(keyBytes, "RAW")',
                                    'new SecretKeySpec(keyBytes, crypto)')
        alone = {key: value for key, value in self.JOINT.items()
                 if key not in ("joint_findings", "joint_detector_contexts")}
        self.assertEqual([issue["code"] for issue in self.run_gate(
            reported_value_untouched, "app/T.java", self.TOTP, patched, alone)],
            ["REPORTED_VALUE_UNTOUCHED"])

    def test_a_patch_that_touches_neither_finding_is_still_flagged(self):
        patched = self.TOTP.replace("return hmac.doFinal(text);",
                                    "byte[] out = hmac.doFinal(text);\n        return out;")
        self.assertEqual([issue["code"] for issue in self.run_gate(
            reported_value_untouched, "app/T.java", self.TOTP, patched, self.JOINT)],
            ["REPORTED_VALUE_UNTOUCHED"])

    def test_a_not_observed_report_is_not_judged_by_its_value(self):
        error = {**self.ERROR, "detector_context": {**self.ERROR["detector_context"],
                                                    "label": "application-manager"}}
        patched = self.ORIGINAL.replace("return f(spec);", "return g(spec);")
        self.assertEqual(self.run_gate(reported_value_untouched, "app/U.java",
                                       self.ORIGINAL, patched, error), [])


class CallerValueOverrideSpellingTests(unittest.TestCase):
    """The same override in the spellings the model actually produced or might."""

    def check(self, added, flagged=True):
        original = "    public void CertReq(int isKeyLen) {\n        keyGen.initialize(isKeyLen);\n    }"
        corrected = ("    public void CertReq(int isKeyLen) {\n" + added
                     + "\n        keyGen.initialize(keyLength);\n    }")
        issues = caller_value_overrides({}, [edit(original, corrected, "app/src/main/java/S.java")])
        self.assertEqual(bool(issues), flagged, added)

    def test_the_second_droid_scep_draft(self):
        self.check("        int keyLength = isKeyLen == 3072 || isKeyLen == 4096 ? isKeyLen : 4096;")

    def test_kotlin_if_in_and_when(self):
        self.check("        val keyLength = if (isKeyLen in setOf(3072, 4096)) isKeyLen else 4096")
        self.check("        val keyLength = when (isKeyLen) { 3072, 4096 -> isKeyLen; else -> 4096 }")

    def test_a_plain_reassignment(self):
        self.check("        if (isKeyLen != 3072 && isKeyLen != 4096)\n        isKeyLen = 4096;")

    def test_using_the_value_unchanged_is_fine(self):
        self.check("        int keyLength = isKeyLen;", flagged=False)
        self.check("        int keyLength = isKeyLen > 0 ? isKeyLen : defaultLength();", flagged=False)


class OptionOnlyFieldTests(_RepositoryCase):
    ORIGINAL = (
        "class S {\n    private SSLSocketFactory insecureFactory;\n"
        "    S() {\n        insecureFactory = trustAll();\n    }\n"
        "    void open(HttpsURLConnection c) {\n"
        "        if (Util.isAllowInsecureEnabled(context)) {\n"
        "            c.setSSLSocketFactory(insecureFactory);\n        }\n    }\n"
        "    SSLSocketFactory getInsecureSSLSocketFactory() {\n        return insecureFactory;\n    }\n}\n"
    )

    def run_ctor(self, original_ctor, corrected_ctor):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            (root / "app/S.java").write_text(self.ORIGINAL, encoding="utf-8")
            change = {"source_file_path": "app/S.java", "original_code": original_ctor,
                      "corrected_code": corrected_ctor, "edit_kind": "method"}
            return neutralized_option_branches({"repository_path": str(root)}, [change])

    def test_the_second_dsub_draft_keeping_the_names_is_rejected(self):
        issues = self.run_ctor("        insecureFactory = trustAll();",
                               "        insecureFactory = platformFactory();")
        self.assertEqual([issue["code"] for issue in issues], ["USER_OPTION_NEUTRALIZED"])

    def test_a_field_also_used_on_the_default_path_is_not_flagged(self):
        original = self.ORIGINAL.replace("    }\n    SSLSocketFactory get",
                                         "        c.setSSLSocketFactory(insecureFactory);\n    }\n    SSLSocketFactory get", 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            (root / "app/S.java").write_text(original, encoding="utf-8")
            change = {"source_file_path": "app/S.java",
                      "original_code": "        insecureFactory = trustAll();",
                      "corrected_code": "        insecureFactory = platformFactory();",
                      "edit_kind": "method"}
            self.assertEqual(neutralized_option_branches({"repository_path": str(root)}, [change]), [])


class OptionLocalRenameTests(_RepositoryCase):
    def test_an_inlined_local_is_not_a_lost_behaviour(self):
        original = ("class P {\n    void save(String value) {\n"
                    "        String hashedValue = Util.hash(value);\n"
                    "        if (PrefsUtil.isEmergencyPinEnabled()) {\n"
                    "            store(hashedValue);\n        }\n    }\n}\n")
        patched = original.replace("        String hashedValue = Util.hash(value);\n", "").replace(
            "store(hashedValue);", "store(AppLockUtil.hash(value));")
        self.assertEqual(self.run_gate(neutralized_option_branches, "app/P.java", original, patched), [])


from cognalys.llm.fix_generation_common import post_validation_issue_candidate  # noqa: E402
from cognalys.utils.pr_text import PIPELINE_JARGON  # noqa: E402


class FallbackIssueTextTests(unittest.TestCase):
    def issue(self, blockers, spec="PBEKeySpecSpec"):
        return post_validation_issue_candidate(
            None, blockers, "encodePbkdf2", spec, "The PIN is hashed with 5000 iterations.", "v2")

    def test_gate_codes_and_automation_never_reach_the_maintainer(self):
        issue = self.issue(["STORED_DERIVED_VALUE_CHANGED; OBSOLETE_CHECKED_EXCEPTION_CATCH"])
        text = " ".join(str(value) for value in issue.values())
        self.assertNotRegex(text, r"\b[A-Z][A-Z_]{5,}\b")
        self.assertNotIn("automatic", text.lower())
        for word in PIPELINE_JARGON:
            self.assertNotIn(word, " ".join(issue[field] for field in
                                           ("title", "why_no_pr", "maintainer_question")).lower())
        self.assertIn("already stored", issue["why_no_pr"])
        self.assertEqual(issue["title"], "Question about the PBEKeySpec use in encodePbkdf2")

    def test_each_reason_is_said_once(self):
        issue = self.issue(["CALLER_SUPPLIED_VALUE_OVERRIDDEN", "CALLER_SUPPLIED_VALUE_OVERRIDDEN"],
                           "KeyPairGeneratorSpec")
        self.assertEqual(issue["why_no_pr"].count("override or refuse"), 1)
        self.assertEqual(issue["title"], "Question about the KeyPairGenerator use in encodePbkdf2")

    def test_building_is_mentioned_only_after_a_build_that_failed(self):
        """2026-10-29: 36 of 109 issues said "still builds cleanly" where no build ran
        (NotallyX md5Hash: review regressions; Bluegate: rename checks)."""
        for blockers in (["UNINTENDED_BEHAVIOR_CHANGE: MD5 16-byte -> SHA-256 32-byte digests"],
                         ["RENAME_REFERENCES_NOT_UPDATED", "NAME_CONTRADICTS_BEHAVIOR"],
                         ["TEST_IN_OTHER_MODULE"], ["some reason the model wrote"]):
            issue = self.issue(blockers)
            self.assertNotIn("build", issue["why_no_pr"].lower(), blockers)
            self.assertNotRegex(issue["why_no_pr"], r"\b[A-Z][A-Z_]{5,}\b")
        self.assertIn("changed what the app does",
                      self.issue(["UNINTENDED_BEHAVIOR_CHANGE"])["why_no_pr"])
        failed = post_validation_issue_candidate(
            None, ["UNINTENDED_BEHAVIOR_CHANGE"], "encodePbkdf2", "PBEKeySpecSpec",
            "The PIN is hashed with 5000 iterations.", "v2", build_failed=True)
        self.assertIn("builds cleanly", failed["why_no_pr"])

    def test_every_rename_and_test_code_has_its_plain_reason(self):
        from cognalys.llm.coordinated_generation import (
            _TEST_CAUSED_PRODUCTION_CODES, DROPPABLE_TEST_CODES,
        )
        from cognalys.llm.fix_generation_common import _DEFAULT_BLOCKER, plain_blocker_reasons
        from cognalys.llm.semantic_validation import _RENAME_CODES

        for code in _RENAME_CODES | DROPPABLE_TEST_CODES | _TEST_CAUSED_PRODUCTION_CODES:
            self.assertNotIn(_DEFAULT_BLOCKER, plain_blocker_reasons([code]), code)


from cognalys.llm.contract_gates import (  # noqa: E402
    kept_constant_key_material, protocol_algorithm_changes,
)


class ProtocolPerFileTests(unittest.TestCase):
    def test_motp_switched_to_a_new_helper_while_md5_stays_elsewhere(self):
        edits = [
            edit("class MD5 { MessageDigest.getInstance(\"MD5\"); }",
                 "class MD5 { MessageDigest.getInstance(\"MD5\"); }\n"
                 "class SHA256 { MessageDigest.getInstance(\"SHA-256\"); }",
                 "app/src/main/java/org/cry/otp/MD5.java"),
            edit("String secret = new MD5(seed).asHex();",
                 "String secret = new SHA256(seed).asHex();",
                 "app/src/main/java/org/cry/otp/mOTP.java"),
        ]
        issues = protocol_algorithm_changes({}, edits)
        self.assertEqual([issue["code"] for issue in issues], ["PROTOCOL_MANDATED_ALGORITHM"])
        self.assertIn("mOTP.java", issues[0]["path"])

    def test_a_non_protocol_file_may_change_its_digest(self):
        edits = [edit('MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-256")',
                      "app/src/main/java/a/DiskCache.kt")]
        self.assertEqual(protocol_algorithm_changes({}, edits), [])


class ShippedCiphertextTests(unittest.TestCase):
    ORIGINAL = ('SecretKey sk = new SecretKeySpec(getString(R.string.key).getBytes(), "AES");\n'
                'token = decrypt(a, "j9mxAigDGtwUdJscE38NUh6CKK2EpiPCG/pDURUxAeC8", sk, iv);')

    def test_replacing_the_key_but_keeping_the_shipped_ciphertext_is_rejected(self):
        corrected = ('SecretKey sk = keyStoreKey();\n'
                     'token = decrypt(a, "j9mxAigDGtwUdJscE38NUh6CKK2EpiPCG/pDURUxAeC8", sk, iv);\n'
                     'KeyStore.getInstance("AndroidKeyStore");')
        issues = kept_constant_key_material({}, [edit(self.ORIGINAL, corrected)])
        self.assertEqual([issue["code"] for issue in issues], ["SHIPPED_CIPHERTEXT_UNREADABLE"])

    def test_a_migration_that_keeps_the_constant_for_shipped_data_is_still_rejected(self):
        corrected = self.ORIGINAL + '\nKeyStore.getInstance("AndroidKeyStore"); reencrypt(token);'
        issues = kept_constant_key_material({}, [edit(self.ORIGINAL, corrected)])
        self.assertEqual([issue["code"] for issue in issues], ["CONSTANT_KEY_MATERIAL_KEPT"])

    def test_a_migration_of_runtime_data_is_still_allowed(self):
        original = ('SecretKey sk = new SecretKeySpec(getString(R.string.key).getBytes(), "AES");\n'
                    'value = decrypt(a, prefs.getString("token", ""), sk, iv);')
        corrected = original + '\nKeyStore.getInstance("AndroidKeyStore"); reencrypt(value);'
        self.assertEqual(kept_constant_key_material({}, [edit(original, corrected)]), [])


from cognalys.llm.migration_policy import generic_migration_policy  # noqa: E402


class VerifyThenMigrateTests(ReportedValueTests):
    def test_a_legacy_path_beside_a_compliant_one_is_not_untouched(self):
        patched = self.ORIGINAL.replace(
            "        return f(spec);\n",
            "        byte[] legacy = f(spec);\n"
            "        PBEKeySpec upgraded = new PBEKeySpec(p, s, NEW_ITERATIONS, 256);\n"
            "        store(f(upgraded));\n        return legacy;\n")
        self.assertEqual(self.run_gate(reported_value_untouched, "app/U.java",
                                       self.ORIGINAL, patched, self.ERROR), [])

    def test_the_pbkdf2_findings_get_the_migration_policy(self):
        for spec, message in (("PBEKeySpecSpec", "the third argument should be >= 10000"),
                              ("SecretKeyFactorySpec", "expecting one of PBKDF2WithHmacSHA256 "
                                                       "but found PBKDF2WithHmacSHA1")):
            policy = generic_migration_policy({"spec": spec, "error_message": message,
                                               "unique_error_id": f"a:::b:::{spec}:::X:::{message}"})
            self.assertEqual(policy.get("consumer_scope"), "stored_secret_verifier", spec)
            self.assertIn("Verify, then migrate", policy["strategy"])

    def test_an_unrelated_message_gets_no_policy(self):
        self.assertEqual(generic_migration_policy({
            "spec": "SecretKeyFactorySpec", "error_message": "expecting one of AES but found DES",
            "unique_error_id": "a:::b:::SecretKeyFactorySpec:::X:::m"}).get("consumer_scope"), None)


class ProtocolWholeFileTests(_RepositoryCase):
    def test_a_profiles_dialog_that_shows_the_motp_secret_is_protocol_code(self):
        original = ("class Profiles {\n    void show(int otpType, String seed) {\n"
                    "        if (otpType == Home.OTP_TYPE_MOTP) {\n"
                    "            String secret = new MD5(seed).asHex().substring(0, 16);\n"
                    "        }\n    }\n}\n")
        snippet = "            String secret = new MD5(seed).asHex().substring(0, 16);"
        issues = self.run_gate(
            lambda error, edits: protocol_algorithm_changes(error, [
                {**edits[0], "original_code": snippet,
                 "corrected_code": snippet.replace("new MD5(", "new SHA256(")}]),
            "app/src/main/java/org/cry/otp/Profiles.java", original, original)
        self.assertEqual([issue["code"] for issue in issues], ["PROTOCOL_MANDATED_ALGORITHM"])


from cognalys.llm.contract_gates import changed_stored_derivations  # noqa: E402


class LegacyDerivationTests(unittest.TestCase):
    STORED = {"derived_value_consumers": {"persisted": True, "consumers": [
        {"kind": "persistence", "path": "PinSetupActivity.java", "line": 103,
         "statement": ".putString(PIN_HASH, hash(value))"}]}}
    ORIGINAL = 'SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");'

    def test_a_parameterised_legacy_path_counts_as_kept(self):
        corrected = ('static final String LEGACY = "PBKDF2WithHmacSHA1";\n'
                     'static final String CURRENT = "PBKDF2WithHmacSHA256";\n'
                     'SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);')
        self.assertEqual(changed_stored_derivations(self.STORED, [edit(self.ORIGINAL, corrected)]), [])

    def test_changing_it_in_place_is_still_refused(self):
        corrected = 'SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");'
        issues = changed_stored_derivations(self.STORED, [edit(self.ORIGINAL, corrected)])
        self.assertEqual([issue["code"] for issue in issues], ["STORED_DERIVED_VALUE_CHANGED"])

    def test_the_old_value_only_in_a_comment_is_not_kept(self):
        corrected = ('// was "PBKDF2WithHmacSHA1"\n'
                     'SecretKeyFactory skf = SecretKeyFactory.getInstance(CURRENT);')
        issues = changed_stored_derivations(self.STORED, [edit(self.ORIGINAL, corrected)])
        self.assertEqual(len(issues), 1)


class ShippedCiphertextRemovedTests(ShippedCiphertextTests):
    def test_dropping_the_key_and_the_shipped_data_is_rejected(self):
        corrected = ('SecretKey sk = keyStoreKey();\n'
                     'token = provider.getClientId().decrypt(sk);\n'
                     'KeyStore.getInstance("AndroidKeyStore");')
        issues = kept_constant_key_material({}, [edit(self.ORIGINAL, corrected)])
        self.assertEqual([issue["code"] for issue in issues], ["SHIPPED_CIPHERTEXT_REMOVED"])


from cognalys.llm.semantic_validation import _obsolete_catches  # noqa: E402


class ObsoleteCatchTests(unittest.TestCase):
    PATCH_THROWS = {"appLockDataHash": set(), "encodePbkdf2": {"GeneralSecurityException"}}

    def test_a_catch_around_a_call_outside_the_patch_is_not_obsolete(self):
        code = ("try {\n    pinHash = PrefsUtil.getEncryptedPrefs().getString(PIN_HASH, \"\");\n"
                "} catch (GeneralSecurityException | IOException e) {\n    throw new RuntimeException(e);\n}")
        self.assertEqual(_obsolete_catches(code, self.PATCH_THROWS), set())

    def test_a_catch_left_after_the_patch_removed_the_throw_is_obsolete(self):
        code = ("try {\n    hash = appLockDataHash(value);\n"
                "} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {\n    fail();\n}")
        self.assertEqual(_obsolete_catches(code, self.PATCH_THROWS),
                         {"NoSuchAlgorithmException", "InvalidKeySpecException"})

    def test_an_unchecked_catch_is_never_obsolete(self):
        code = "try {\n    hash = appLockDataHash(value);\n} catch (IllegalStateException e) {\n}"
        self.assertEqual(_obsolete_catches(code, self.PATCH_THROWS), set())


from cognalys.llm.semantic_validation import stale_stored_value_readers  # noqa: E402


class StaleReaderTests(unittest.TestCase):
    def test_bitbanana_20261020_variable_write_does_not_use_commit_as_derivation(self):
        from cognalys.llm.semantic_validation import _store_writes
        self.assertEqual(_store_writes(
            'prefs.putString(PrefsUtil.EMERGENCY_PASSWORD_HASH, hashedValue).commit();'), {})

    def test_bitbanana_20261020_direct_derivation_survives_variable_write(self):
        from cognalys.llm.semantic_validation import _store_writes
        self.assertEqual(_store_writes(
            'prefs.putString(PrefsUtil.PIN_HASH, cached).commit();\n'
            'prefs.putString(PrefsUtil.PIN_HASH, UtilFunctions.appLockDataHash(value)).commit();'),
            {'PIN_HASH': 'appLockDataHash'})

    SETUP = ("class PinSetupActivity {\n    void pinCreated(String value) {\n"
             "        prefs.edit().putString(PrefsUtil.PIN_HASH, UtilFunctions.appLockDataHash(value)).commit();\n"
             "    }\n}\n")
    ENTRY = ("class PinEntryActivity {\n    void check(String pin) {\n"
             "        String hashed = UtilFunctions.appLockDataHash(pin);\n"
             "        boolean ok = prefs.getString(PrefsUtil.PIN_HASH, \"\").equals(hashed);\n    }\n}\n")

    def run_case(self, entry):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            (root / "app/PinSetupActivity.java").write_text(self.SETUP, encoding="utf-8")
            (root / "app/PinEntryActivity.java").write_text(entry, encoding="utf-8")
            line = "        prefs.edit().putString(PrefsUtil.PIN_HASH, UtilFunctions.appLockDataHash(value)).commit();"
            change = {"source_file_path": "app/PinSetupActivity.java", "edit_kind": "method",
                      "original_code": line,
                      "corrected_code": line.replace("appLockDataHash(", "createCurrentAppLockVerifier(")}
            return stale_stored_value_readers({"repository_path": str(root)}, [change])

    def test_the_unlock_screen_left_on_the_old_check_is_rejected(self):
        issues = self.run_case(self.ENTRY)
        self.assertEqual([issue["code"] for issue in issues], ["STORED_VALUE_READERS_NOT_UPDATED"])
        self.assertIn("PinEntryActivity.java", issues[0]["details"][0])

    def test_a_reader_on_the_new_check_passes(self):
        updated = self.ENTRY.replace(
            "String hashed = UtilFunctions.appLockDataHash(pin);\n", "").replace(
            '.equals(hashed)', '.isEmpty() || UtilFunctions.verifyAndMigrate(pin, x).isVerified()')
        self.assertEqual(self.run_case(updated), [])

    def run_same_name_case(self, corrected_helper, entry=None):
        original = ('class UtilFunctions {\n'
                    '    public static String appLockDataHash(String value) {\n'
                    '        return legacyHash(value);\n    }\n}\n')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'PinSetupActivity.java').write_text(self.SETUP, encoding='utf-8')
            (root / 'PinEntryActivity.java').write_text(entry or self.ENTRY, encoding='utf-8')
            (root / 'UtilFunctions.java').write_text(original, encoding='utf-8')
            return stale_stored_value_readers({'repository_path': str(root)}, [
                edit(original, corrected_helper, 'UtilFunctions.java')])

    def test_bitbanana_20261020_same_helper_name_new_return_rejects_old_pin_reader(self):
        helper = ('class UtilFunctions {\n'
                  '    public static String appLockDataHash(String value) {\n'
                  '        return createCurrentVerifier(value);\n    }\n}\n')
        issues = self.run_same_name_case(helper)
        self.assertEqual([issue['code'] for issue in issues], ['STORED_VALUE_READERS_NOT_UPDATED'])
        self.assertIn('PinEntryActivity.java', issues[0]['details'][0])

    def test_bitbanana_20261020_helper_cleanup_preserving_return_passes(self):
        helper = ('class UtilFunctions {\n'
                  '    public static String appLockDataHash(String value) {\n'
                  '        try { return legacyHash(value); } finally { clearPassword(); }\n'
                  '    }\n}\n')
        self.assertEqual(self.run_same_name_case(helper), [])

    def test_bitbanana_20261020_same_name_helper_updated_reader_passes(self):
        helper = ('class UtilFunctions {\n'
                  '    public static String appLockDataHash(String value) {\n'
                  '        return createCurrentVerifier(value);\n    }\n}\n')
        entry = self.ENTRY.replace('UtilFunctions.appLockDataHash(pin)', 'verifyAndMigrate(pin)')
        self.assertEqual(self.run_same_name_case(helper, entry), [])

    def test_bitbanana_20261020_updated_reader_can_still_create_current_values(self):
        helper = ('class UtilFunctions {\n'
                  '    public static String appLockDataHash(String value) {\n'
                  '        return createCurrentVerifier(value);\n    }\n}\n')
        entry = self.ENTRY.replace('UtilFunctions.appLockDataHash(pin)', 'verifyAndMigrate(pin)')
        entry += '\nprefs.putString(PrefsUtil.PIN_HASH, UtilFunctions.appLockDataHash(pin)).commit();'
        self.assertEqual(self.run_same_name_case(helper, entry), [])


from cognalys.llm.fix_generation_common import plain_blocker_reasons  # noqa: E402
from cognalys.llm.semantic_validation import (  # noqa: E402
    discarded_constructions, semantic_validation_retry_targets,
    validate_coordinated_semantics,
)

KEY_PAIR = {"specification_context": {"applies_to_types": ["java.security.KeyPair"]}}
SECRET_KEY_SPEC = {"specification_context": {
    "applies_to_types": ["javax.crypto.spec.SecretKeySpec"]}}


class DiscardedConstructionTests(_RepositoryCase):
    """BlueGate (2026-10-29): a KeyPair built only so the checker sees a constructor."""

    BLUEGATE_ORIGINAL = (
        "    private fun generateNewKeyPair(alias: String): KeyPair {\n"
        "        kpg.initialize(parameterSpec)\n"
        "        return kpg.generateKeyPair()\n"
        "    }\n"
    )
    BLUEGATE_CORRECTED = (
        "    private fun generateNewKeyPair(alias: String): KeyPair {\n"
        "        kpg.initialize(parameterSpec)\n"
        "        val generatedKeyPair = kpg.generateKeyPair()\n"
        "        KeyPair(generatedKeyPair.public, generatedKeyPair.private)\n"
        "        return generatedKeyPair\n"
        "    }\n"
    )
    KOTLIN_FILE = (
        "package org.cleverfox.bluegate\n\n"
        "import java.security.KeyPair\n"
        "import java.security.KeyPairGenerator\n\n"
        "class KeyManager {\n{body}}\n"
    )

    def kotlin(self, original, corrected, error=None, path="app/src/main/java/a/KeyManager.kt"):
        return discarded_constructions(error or {}, [edit(original, corrected, path)])

    def java(self, original, corrected, error=None):
        return discarded_constructions(
            error or {}, [edit(original, corrected, "app/src/main/java/a/Keys.java")])

    def in_repository(self, relative, file_text, original, corrected, error=None):
        """The gate on an edit of `original` inside `file_text`, read from a checkout."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / relative).parent.mkdir(parents=True)
            (root / relative).write_text(file_text, encoding="utf-8")
            return discarded_constructions({"repository_path": str(root), **(error or {})},
                                           [edit(original, corrected, relative)])

    def test_the_bluegate_patch_is_rejected(self):
        issues = self.kotlin(self.BLUEGATE_ORIGINAL, self.BLUEGATE_CORRECTED, KEY_PAIR)
        self.assertEqual([issue["code"] for issue in issues], ["DISCARDED_CONSTRUCTION"])
        self.assertIn("KeyPair(generatedKeyPair.public, generatedKeyPair.private)",
                      issues[0]["details"][0])
        self.assertIn("concerns the object that reaches the reported call",
                      issues[0]["details"][1])

    def test_the_governed_class_comes_from_the_specification_context_not_its_name(self):
        """Review (2026-10-29): "KeyPairSpec" -> KeyPair is a naming convention
        of the specifications; applies_to_types states the type."""
        self.assertEqual(self.kotlin(self.BLUEGATE_ORIGINAL, self.BLUEGATE_CORRECTED,
                                     {"spec": "KeyPairSpec"}), [])

    def test_a_platform_import_in_the_file_proves_a_class(self):
        file_text = self.KOTLIN_FILE.replace("{body}", self.BLUEGATE_ORIGINAL)
        issues = self.run_gate(
            discarded_constructions, "app/src/main/java/a/KeyManager.kt", file_text,
            file_text.replace(self.BLUEGATE_ORIGINAL, self.BLUEGATE_CORRECTED))
        self.assertEqual([issue["code"] for issue in issues], ["DISCARDED_CONSTRUCTION"])

    def test_a_class_of_the_app_is_not_judged(self):
        """Review (2026-10-29): a constructor of the app's own may do its work
        (`init { app.register(this) }`), in Kotlin and in Java."""
        corrected = ("class Watchdog(app: App) { init { app.register(this) } }\n"
                     "fun start() {\n    Watchdog(app)\n    run()\n}\n")
        self.assertEqual(self.kotlin("fun start() {\n    run()\n}\n", corrected, KEY_PAIR), [])
        self.assertEqual(self.java("void init() {\n  load();\n}",
                                   "void init() {\n  load();\n  new Scheduler(context);\n}",
                                   KEY_PAIR), [])

    def test_a_java_construction_statement_is_rejected(self):
        original = "KeyPair pair = generator.generateKeyPair();\nreturn pair;"
        corrected = ("KeyPair pair = generator.generateKeyPair();\n"
                     "new KeyPair(pair.getPublic(), pair.getPrivate());\nreturn pair;")
        issues = self.java(original, corrected, KEY_PAIR)
        self.assertEqual([issue["code"] for issue in issues], ["DISCARDED_CONSTRUCTION"])
        self.assertIn("new KeyPair(pair.getPublic(), pair.getPrivate())",
                      issues[0]["details"][0])

    def test_a_created_file_is_judged_from_its_start(self):
        created = {**edit("", "package a\nclass X {\n  fun f() {\n    KeyPair(a, b)\n"
                              "    g()\n  }\n}\n", "app/src/main/java/a/X.kt"),
                   "edit_kind": "create"}
        self.assertEqual([issue["code"] for issue in discarded_constructions(KEY_PAIR, [created])],
                         ["DISCARDED_CONSTRUCTION"])

    def test_java_constructions_whose_value_is_used_are_not_flagged(self):
        corrected = (
            "KeyPair pair = new KeyPair(pub, priv);\n"
            "use(new KeyPair(pub, priv));\n"
            "new Thread(task).start();\n"
            "Runnable r = null; new Handler(looper) { };\n"
            "if (pair == null) throw new IllegalStateException(\"no key\");\n"
            "return new KeyPair(pub, priv);\n"
        )
        self.assertEqual(self.java("", corrected, KEY_PAIR), [])

    def test_kotlin_constructions_whose_value_is_used_are_not_flagged(self):
        corrected = (
            "val pair = KeyPair(pub, priv)\n"
            "use(KeyPair(pub, priv))\n"
            "store(\n    KeyPair(pub, priv)\n)\n"
            "KeyPair(pub, priv).public\n"
            "KeyPair(pub, priv)\n    .also { remember(it) }\n"
            "if (missing) throw KeyPair(pub, priv)\n"
            "val fromBlock = run {\n    KeyPair(pub, priv)\n}\n"
            "val branch = if (fresh)\n    KeyPair(pub, priv)\nelse\n    old\n"
            "val chosen = when (mode) {\n    1 -> KeyPair(pub, priv)\n    else -> old\n}\n"
            "return KeyPair(pub, priv)\n"
        )
        self.assertEqual(self.kotlin("", corrected, KEY_PAIR), [])

    def test_a_line_ending_in_a_keyword_an_infix_call_or_an_annotation_carries_on(self):
        """Review (2026-10-29): `if (cached) old else`, `return`, `a to` and
        `@Suppress(...)` leave their operand on the next line."""
        for head in ("val pair = if (cached) old else", "return", "val p = a to",
                     "val x = @Suppress(\"X\")"):
            with self.subTest(head=head):
                corrected = head + "\n    KeyPair(pub, priv)\nuse(pair)\n"
                self.assertEqual(self.kotlin("", corrected, KEY_PAIR), [])

    def test_an_edit_starting_inside_a_split_statement_is_not_flagged(self):
        """Review (2026-10-29): the edit replaced only the second line of
        `SecretKeySpec spec =\\n    new SecretKeySpec(...)`; the line before
        it, in the file, takes the value."""
        java_file = ("import javax.crypto.spec.SecretKeySpec;\nclass Keys {\n"
                     "  Key key(byte[] raw) {\n    final SecretKeySpec spec =\n"
                     "        new SecretKeySpec(raw, \"DES\");\n    return spec;\n  }\n}\n")
        original = "        new SecretKeySpec(raw, \"DES\");\n"
        corrected = "        new SecretKeySpec(deriveKey(raw), \"AES\");\n"
        self.assertEqual(self.in_repository("app/src/main/java/a/Keys.java", java_file,
                                            original, corrected, SECRET_KEY_SPEC), [])
        kotlin_file = ("import javax.crypto.spec.SecretKeySpec\nclass Keys {\n"
                       "    fun enc(raw: ByteArray) {\n        val spec =\n"
                       "            SecretKeySpec(raw, \"DES\")\n"
                       "        cipher.init(Cipher.ENCRYPT_MODE, spec)\n    }\n}\n")
        k_original = ("            SecretKeySpec(raw, \"DES\")\n"
                      "        cipher.init(Cipher.ENCRYPT_MODE, spec)\n")
        k_corrected = k_original.replace("raw, \"DES\"", "deriveKey(raw), \"AES\"")
        self.assertEqual(self.in_repository("app/src/main/java/a/Keys.kt", kotlin_file,
                                            k_original, k_corrected, SECRET_KEY_SPEC), [])
        # Without the file, the line before the edit is unknown: not flagged.
        self.assertEqual(self.java(original, corrected, SECRET_KEY_SPEC), [])
        self.assertEqual(self.kotlin(k_original, k_corrected, SECRET_KEY_SPEC,
                                     "app/src/main/java/a/Keys.kt"), [])

    def test_a_construction_opening_an_edit_after_a_complete_statement_is_flagged(self):
        file_text = self.KOTLIN_FILE.replace("{body}", self.BLUEGATE_ORIGINAL)
        original = "        return kpg.generateKeyPair()\n"
        corrected = ("        KeyPair(pub, priv)\n"
                     "        return kpg.generateKeyPair()\n")
        issues = self.in_repository("app/src/main/java/a/KeyManager.kt", file_text,
                                    original, corrected, KEY_PAIR)
        self.assertEqual([issue["code"] for issue in issues], ["DISCARDED_CONSTRUCTION"])

    def test_a_construction_kept_for_the_exception_it_throws_is_not_flagged(self):
        """Review (2026-10-29): `try { new URL(s); return true; } catch ...`
        builds the object for the exception it throws on bad input."""
        kotlin = ("import java.net.URL\nfun isValid(s: String): Boolean {\n"
                  "    return try {\n        URL(s)\n        true\n"
                  "    } catch (e: MalformedURLException) {\n        false\n    }\n}\n")
        self.assertEqual(self.kotlin("fun isValid(s: String) = s.isNotEmpty()\n", kotlin), [])
        caught = ("import java.net.URL\nfun isValid(s: String) = runCatching {\n"
                  "    URL(s)\n    true\n}.getOrDefault(false)\n")
        self.assertEqual(self.kotlin("fun isValid(s: String) = s.isNotEmpty()\n", caught), [])
        java = ("import java.net.URL;\nboolean isValid(String s) {\n  try {\n"
                "    new URL(s);\n    return true;\n  } catch (MalformedURLException e) {\n"
                "    return false;\n  }\n}")
        self.assertEqual(self.java("boolean isValid(String s) { return true; }", java), [])

    def test_a_construction_moved_to_another_edit_is_not_flagged(self):
        """Review (2026-10-29): the statement left one method and reached a
        helper in another edit of the patch; nothing was added."""
        path = "app/src/main/java/a/Keys.java"
        issues = discarded_constructions(KEY_PAIR, [
            edit("void a() {\n  load();\n  new KeyPair(pub, priv);\n  go();\n}",
                 "void a() {\n  load();\n  helper();\n  go();\n}", path),
            edit("void b() {\n  stop();\n}",
                 "void b() {\n  stop();\n}\nvoid helper() {\n  log();\n"
                 "  new KeyPair(pub, priv);\n}", path),
        ])
        self.assertEqual(issues, [])

    def test_compose_style_functions_are_not_constructions(self):
        corrected = (
            "import androidx.compose.material.Text\n"
            "@Composable\nfun Screen(state: State) {\n"
            "    Text(state.title)\n"
            "    Spacer(Modifier.height(8.dp))\n"
            "    Column {\n        Label(state.body)\n    }\n"
            "    Footer(state)\n"
            "}\n"
        )
        self.assertEqual(self.kotlin("fun Screen(state: State) {\n}\n", corrected, KEY_PAIR), [])

    def test_a_construction_the_original_already_had_is_not_flagged(self):
        original = "new KeyPair(pub, priv);\nint size = 1;"
        self.assertEqual(self.java(original, original.replace("1", "2"), KEY_PAIR), [])
        kotlin = "KeyPair(pub, priv)\nval size = 1\n"
        self.assertEqual(self.kotlin(kotlin, kotlin.replace("1", "2"), KEY_PAIR), [])

    def test_a_test_edit_is_not_judged(self):
        self.assertEqual(discarded_constructions(KEY_PAIR, [
            {**edit("", "new KeyPair(pub, priv);\nassertTrue(x);",
                    "app/src/test/java/a/KeysTest.java"), "edit_kind": "test"}]), [])

    def test_the_coordinated_validator_regenerates_the_file_with_the_explanation(self):
        path = "app/src/main/java/a/KeyManager.kt"
        result = validate_coordinated_semantics(
            KEY_PAIR, [edit(self.BLUEGATE_ORIGINAL, self.BLUEGATE_CORRECTED, path)])
        self.assertEqual(result["status"], "invalid")
        [issue] = [item for item in result["errors"] if item["code"] == "DISCARDED_CONSTRUCTION"]
        self.assertEqual(semantic_validation_retry_targets(
            [issue], [path, "app/src/main/java/a/MainActivity.kt"]), {path})
        # When retries run out, the maintainer-facing reason is the plain one.
        self.assertEqual(plain_blocker_reasons(["DISCARDED_CONSTRUCTION"]),
                         ["the changes I could make left the reported call as it is"])


from cognalys.llm.semantic_validation import wrapped_same_objects  # noqa: E402

SSL_CONTEXT = {"specification_context": {"events": [
    {"name": "GetInstance", "api_patterns": ["SSLContext.getInstance("]},
    {"name": "Init", "api_patterns": [".init("]},
]}}


class WrappedSameObjectTests(unittest.TestCase):
    """ICSdroid (run_v2, 2026-10-29): a TrustManagerFactorySpi, a Provider and
    a TrustManagerFactory subclass the app wrote around the CustomCertManager
    that SSLContext.init already received; the review called it a repair."""

    PATH = "app/src/main/java/at/bitfire/icsdroid/AppHttpClient.kt"
    ORIGINAL = (
        "    private val certManager = CustomCertManager(\n"
        "        certStore = CustomCertStore.getInstance(context),\n"
        "        trustSystemCerts = true\n"
        "    )\n\n"
        "    private val sslContext = SSLContext.getInstance(\"TLS\")\n"
        "    init {\n"
        "        sslContext.init(null, arrayOf(certManager), null)\n"
        "    }\n"
    )
    IMPORTS = ("import java.security.KeyStore\nimport java.security.Provider\n"
               "import javax.net.ssl.ManagerFactoryParameters\nimport javax.net.ssl.SSLContext\n"
               "import javax.net.ssl.TrustManager\nimport javax.net.ssl.TrustManagerFactory\n"
               "import javax.net.ssl.TrustManagerFactorySpi\n")
    CLASSES = (
        "    private class CustomCertManagerFactoryParameters(\n"
        "        val createTrustManager: () -> CustomCertManager\n"
        "    ) : ManagerFactoryParameters\n\n"
        "    private class CustomCertManagerTrustManagerFactorySpi : TrustManagerFactorySpi() {\n"
        "        private var trustManagers: Array<TrustManager>? = null\n"
        "        override fun engineInit(keyStore: KeyStore?) {\n"
        "            throw KeyStoreException(\"requires custom parameters\")\n        }\n"
        "        override fun engineInit(parameters: ManagerFactoryParameters?) {\n"
        "            val custom = parameters as? CustomCertManagerFactoryParameters ?: throw X()\n"
        "            trustManagers = arrayOf<TrustManager>(custom.createTrustManager())\n"
        "        }\n"
        "        override fun engineGetTrustManagers(): Array<TrustManager> =\n"
        "            trustManagers?.copyOf() ?: throw IllegalStateException(\"not initialized\")\n"
        "    }\n\n"
        "    private object CustomCertManagerTrustManagerProvider : Provider(\n"
        "        \"CustomCertManagerTrustManagerProvider\", 1.0, \"policy\"\n    )\n\n"
        "    private class CustomCertManagerTrustManagerFactory : TrustManagerFactory(\n"
        "        CustomCertManagerTrustManagerFactorySpi(),\n"
        "        CustomCertManagerTrustManagerProvider,\n"
        "        \"CustomCertManager\"\n    )\n"
    )
    CORRECTED = (
        "    private val trustManagerFactory = CustomCertManagerTrustManagerFactory()\n"
        "    private val sslContext = SSLContext.getInstance(\"TLS\")\n"
        "    private val certManager: CustomCertManager\n\n"
        "    init {\n"
        "        trustManagerFactory.init(\n"
        "            CustomCertManagerFactoryParameters {\n"
        "                CustomCertManager(\n"
        "                    certStore = CustomCertStore.getInstance(context),\n"
        "                    trustSystemCerts = true\n"
        "                )\n"
        "            }\n"
        "        )\n"
        "        val trustManagers = trustManagerFactory.trustManagers\n"
        "        certManager = trustManagers.singleOrNull() as? CustomCertManager ?: throw X()\n"
        "        sslContext.init(null, trustManagers, null)\n"
        "    }\n"
    )

    def edits(self, original=None, corrected=None, path=None):
        return [
            edit("import javax.net.ssl.SSLContext\n", self.IMPORTS, path or self.PATH),
            edit(original or self.ORIGINAL, self.CLASSES + "\n" + (corrected or self.CORRECTED),
                 path or self.PATH),
        ]

    def test_the_icsdroid_factory_around_the_same_trust_manager_is_rejected(self):
        issues = wrapped_same_objects(SSL_CONTEXT, self.edits())
        self.assertEqual([issue["code"] for issue in issues], ["WRAPPED_SAME_OBJECT"])
        self.assertIn("CustomCertManagerTrustManagerFactorySpi", issues[0]["details"][0])
        self.assertIn("CustomCertManager, certManager", issues[0]["details"][0])
        self.assertIn("init(...)", issues[0]["details"][0])
        self.assertEqual(issues[0]["affected_paths"], [self.PATH])

    def test_a_provider_registered_for_get_instance_in_another_file_is_rejected(self):
        """Tasks.org's openConnection (2026-10-25): the Spi and the Provider sit
        in CustomCertManager.kt, and the factory comes from getInstance."""
        caller = "app/src/main/java/org/tasks/auth/DebugConnectionBuilder.kt"
        library = "cert4android/src/main/kotlin/at/bitfire/cert4android/CustomCertManager.kt"
        original = ("val customCertManager = CustomCertManager(certStore, settings)\n"
                    "val sslContext = SSLContext.getInstance(\"TLS\")\n"
                    "sslContext.init(null, arrayOf(customCertManager), null)\n")
        corrected = (
            "val customCertManager = CustomCertManager(certStore, settings)\n"
            "val trustManagerFactory = javax.net.ssl.TrustManagerFactory.getInstance(\n"
            "    CustomCertManagerProvider.ALGORITHM,\n    CustomCertManagerProvider()\n"
            ").apply {\n    init(CustomCertManagerFactoryParameters(certStore, settings))\n}\n"
            "val sslContext = SSLContext.getInstance(\"TLS\")\n"
            "sslContext.init(null, trustManagerFactory.trustManagers, null)\n")
        spi = (
            "import javax.net.ssl.TrustManagerFactorySpi\nimport java.security.Provider\n"
            "class CustomCertManagerTrustManagerFactorySpi : TrustManagerFactorySpi() {\n"
            "    override fun engineInit(spec: ManagerFactoryParameters?) {\n"
            "        val p = spec as CustomCertManagerFactoryParameters\n"
            "        trustManagers = arrayOf(CustomCertManager(p.certStore, p.settings))\n    }\n}\n"
            "class CustomCertManagerProvider : Provider(NAME, VERSION, INFO) {\n"
            "    init { put(\"TrustManagerFactory.x\", "
            "CustomCertManagerTrustManagerFactorySpi::class.java.name) }\n}\n")
        issues = wrapped_same_objects(SSL_CONTEXT, [
            edit(original, corrected, caller),
            edit("    }\n\n}\n", "    }\n\n}\n" + spi, library)])
        self.assertEqual([issue["code"] for issue in issues], ["WRAPPED_SAME_OBJECT"])
        self.assertEqual(issues[0]["affected_paths"], [caller, library])

    def test_a_platform_factory_initialised_with_a_key_store_passes(self):
        corrected = (
            "    private val sslContext = SSLContext.getInstance(\"TLS\")\n"
            "    init {\n"
            "        val factory = TrustManagerFactory.getInstance("
            "TrustManagerFactory.getDefaultAlgorithm())\n"
            "        factory.init(keyStore)\n"
            "        sslContext.init(null, factory.trustManagers, null)\n"
            "    }\n")
        self.assertEqual(wrapped_same_objects(SSL_CONTEXT, [
            edit(self.ORIGINAL, corrected, self.PATH)]), [])

    def test_a_provider_in_a_test_file_is_not_judged(self):
        """Test-only probes (xivpn, loki) must stay allowed."""
        path = "app/src/test/java/at/bitfire/icsdroid/AppHttpClientTest.kt"
        self.assertEqual(wrapped_same_objects(SSL_CONTEXT, self.edits(path=path)), [])

    def test_a_socket_factory_around_another_object_passes(self):
        """A TLS-enabling SSLSocketFactory wraps the context's own factory; the
        object init receives is untouched and goes nowhere near it."""
        corrected = self.ORIGINAL + (
            "    private class Tls12SocketFactory(private val delegate: SSLSocketFactory) :\n"
            "        SSLSocketFactory() {\n"
            "        override fun createSocket(): Socket = enable(delegate.createSocket())\n"
            "    }\n"
            "    val socketFactory = Tls12SocketFactory(sslContext.socketFactory)\n")
        self.assertEqual(wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext\n",
                 "import javax.net.ssl.SSLContext\nimport javax.net.ssl.SSLSocketFactory\n",
                 self.PATH),
            edit(self.ORIGINAL, corrected, self.PATH)]), [])

    def test_an_app_class_named_like_a_factory_is_not_an_extension_point(self):
        imports = self.IMPORTS.replace("import javax.net.ssl.TrustManagerFactory\n", "").replace(
            "import javax.net.ssl.TrustManagerFactorySpi\n", "").replace(
            "import java.security.Provider\n", "")
        self.assertEqual(wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext\n", imports, self.PATH),
            edit(self.ORIGINAL, self.CLASSES + "\n" + self.CORRECTED, self.PATH)]), [])

    def test_a_class_the_file_already_declared_is_not_new(self):
        before = self.CLASSES + "\n" + self.ORIGINAL
        self.assertEqual(wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext\n", self.IMPORTS, self.PATH),
            edit(before, self.CLASSES + "\n" + self.CORRECTED, self.PATH)]), [])

    ANONYMOUS = (
        "    private val trustManagerFactory = object : TrustManagerFactory(\n"
        "        object : TrustManagerFactorySpi() {\n"
        "            override fun engineInit(keyStore: KeyStore?) {}\n"
        "            override fun engineInit(p: ManagerFactoryParameters?) {}\n"
        "            override fun engineGetTrustManagers(): Array<TrustManager> =\n"
        "                arrayOf(certManager)\n"
        "        },\n"
        "        object : Provider(\"x\", 1.0, \"y\") {},\n"
        "        \"CustomCertManager\"\n    ) {}\n")

    def anonymous_corrected(self):
        return self.ANONYMOUS + self.ORIGINAL.replace(
            "sslContext.init(null, arrayOf(certManager), null)",
            "trustManagerFactory.init(null as KeyStore?)\n"
            "        sslContext.init(null, trustManagerFactory.trustManagers, null)")

    def test_the_same_classes_written_anonymously_are_rejected(self):
        """Review (2026-10-29): told about its named classes, a regeneration
        could write the same factory as object expressions and pass."""
        issues = wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext\n", self.IMPORTS, self.PATH),
            edit(self.ORIGINAL, self.anonymous_corrected(), self.PATH)])
        self.assertEqual([issue["code"] for issue in issues], ["WRAPPED_SAME_OBJECT"])
        self.assertIn("the patch declares an anonymous TrustManagerFactory",
                      issues[0]["details"][0])
        self.assertEqual(issues[0]["affected_paths"], [self.PATH])
        # Already in the code before the patch, it is not the patch's doing.
        self.assertEqual(wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext\n", self.IMPORTS, self.PATH),
            edit(self.ANONYMOUS + self.ORIGINAL, self.anonymous_corrected(), self.PATH)]), [])

    JAVA_PATH = "app/src/main/java/a/Http.java"
    JAVA_ORIGINAL = (
        "    private final CustomCertManager certManager = new CustomCertManager(context);\n"
        "    void setup() throws Exception {\n"
        "        SSLContext sslContext = SSLContext.getInstance(\"TLS\");\n"
        "        sslContext.init(null, new TrustManager[]{certManager}, null);\n    }\n")
    JAVA_CLASSES = (
        "    private static final class CertSpi extends TrustManagerFactorySpi {\n"
        "        private final CustomCertManager manager;\n"
        "        CertSpi(CustomCertManager manager) { this.manager = manager; }\n"
        "        protected void engineInit(KeyStore ks) {}\n"
        "        protected void engineInit(ManagerFactoryParameters p) {}\n"
        "        protected TrustManager[] engineGetTrustManagers() {\n"
        "            return new TrustManager[]{manager};\n        }\n    }\n"
        "    private static final class CertFactory extends TrustManagerFactory {\n"
        "        CertFactory(CustomCertManager m) {\n"
        "            super(new CertSpi(m), new Provider(\"x\", 1.0, \"y\") {}, \"x\");\n"
        "        }\n    }\n")
    JAVA_CORRECTED = (
        "    private final CustomCertManager certManager = new CustomCertManager(context);\n"
        "    void setup() throws Exception {\n"
        "        SSLContext sslContext = SSLContext.getInstance(\"TLS\");\n"
        "        TrustManagerFactory factory = new CertFactory(certManager);\n"
        "        factory.init((KeyStore) null);\n"
        "        sslContext.init(null, factory.getTrustManagers(), null);\n    }\n")

    def test_java_classes_under_a_wildcard_import_are_rejected(self):
        """Review (2026-10-29): `import javax.net.ssl.*` hid the supertypes."""
        issues = wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext;\n",
                 "import javax.net.ssl.*;\nimport java.security.*;\n", self.JAVA_PATH),
            edit(self.JAVA_ORIGINAL, self.JAVA_CLASSES + self.JAVA_CORRECTED, self.JAVA_PATH)])
        self.assertEqual([issue["code"] for issue in issues], ["WRAPPED_SAME_OBJECT"])
        self.assertIn("CertSpi", issues[0]["details"][0])
        # The app's own class of that name is not the platform's.
        self.assertEqual(wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext;\n",
                 "import javax.net.ssl.*;\nimport java.security.*;\n", self.JAVA_PATH),
            edit(self.JAVA_ORIGINAL,
                 self.JAVA_CLASSES.replace("Provider(", "AppProvider(")
                 + "    class TrustManagerFactorySpi {}\n    class TrustManagerFactory {}\n"
                 + self.JAVA_CORRECTED, self.JAVA_PATH)]), [])

    def test_a_java_anonymous_service_provider_interface_is_rejected(self):
        corrected = self.JAVA_CORRECTED.replace(
            "        TrustManagerFactory factory = new CertFactory(certManager);\n",
            "        TrustManagerFactory factory = new TrustManagerFactory(\n"
            "                new TrustManagerFactorySpi() {\n"
            "            protected void engineInit(KeyStore ks) {}\n"
            "            protected void engineInit(ManagerFactoryParameters p) {}\n"
            "            protected TrustManager[] engineGetTrustManagers() {\n"
            "                return new TrustManager[]{certManager};\n            }\n"
            "        }, new Provider(\"x\", 1.0, \"y\") {}, \"x\") {};\n")
        imports = ("import javax.net.ssl.SSLContext;\nimport javax.net.ssl.TrustManager;\n"
                   "import javax.net.ssl.TrustManagerFactory;\n"
                   "import javax.net.ssl.TrustManagerFactorySpi;\n"
                   "import java.security.KeyStore;\nimport java.security.Provider;\n")
        issues = wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext;\n", imports, self.JAVA_PATH),
            edit(self.JAVA_ORIGINAL, corrected, self.JAVA_PATH)])
        self.assertEqual([issue["code"] for issue in issues], ["WRAPPED_SAME_OBJECT"])
        self.assertEqual(issues[0]["affected_paths"], [self.JAVA_PATH])
        # An anonymous trust manager is no extension point: a platform factory
        # beside it passes.
        platform = self.JAVA_CORRECTED.replace(
            "        TrustManagerFactory factory = new CertFactory(certManager);\n",
            "        TrustManagerFactory factory = TrustManagerFactory.getInstance(\n"
            "                TrustManagerFactory.getDefaultAlgorithm());\n"
            "        X509TrustManager logged = new X509TrustManager() {\n"
            "            public X509Certificate[] getAcceptedIssuers() { return null; }\n"
            "        };\n")
        self.assertEqual(wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext;\n",
                 imports + "import javax.net.ssl.X509TrustManager;\n", self.JAVA_PATH),
            edit(self.JAVA_ORIGINAL, platform, self.JAVA_PATH)]), [])

    def test_the_coordinated_validator_regenerates_and_then_closes_without_impact(self):
        from cognalys.llm.coordinated_generation import CoordinatedGeneration

        result = validate_coordinated_semantics(SSL_CONTEXT, self.edits())
        [issue] = [item for item in result["errors"] if item["code"] == "WRAPPED_SAME_OBJECT"]
        self.assertEqual(semantic_validation_retry_targets(
            [issue], [self.PATH, "app/src/main/java/a/MainActivity.kt"]), {self.PATH})
        self.assertEqual(plain_blocker_reasons(["WRAPPED_SAME_OBJECT"]),
                         ["the changes I could make left the reported call as it is"])
        failed = {}
        CoordinatedGeneration._close_discarded_construction({}, failed, [issue])
        self.assertTrue(failed["correct_use"].startswith(
            "Every proposed change leaves the calls the checker observes as they were: "
            "the patch declares CustomCertManagerTrustManagerFactorySpi, "
            "CustomCertManagerTrustManagerProvider, CustomCertManagerTrustManagerFactory, "
            "extending a platform factory"))
        # With another failure left, the finding keeps that failure's ending.
        failed = {}
        CoordinatedGeneration._close_discarded_construction(
            {}, failed, [issue, {"code": "UNINTENDED_BEHAVIOR_CHANGE", "details": ["x"]}])
        self.assertEqual(failed, {})


class WrappedBehindHelperTests(unittest.TestCase):
    """Herald's mtlsEngine (frozen run, 2026-11-13): the factory came from a
    helper function, and the Provider received a lambda building the
    MtlsKeyManager the original passed; WRAPPED_SAME_OBJECT returned []."""

    PATH = "shared/core/src/androidMain/kotlin/dev/h/ClientCerts.android.kt"
    IMPORTS = ("import java.security.KeyStore\nimport java.security.Provider\n"
               "import javax.net.ssl.KeyManager\nimport javax.net.ssl.KeyManagerFactory\n"
               "import javax.net.ssl.KeyManagerFactorySpi\nimport javax.net.ssl.SSLContext\n")
    ENGINE = (
        "fun mtlsEngine(certs: Aliases): Engine {\n"
        "    val keyManager = MtlsKeyManager(resolveAlias = { host -> certs.aliasFor(host) })\n"
        "    val trustManager = defaultTrustManager()\n"
        "    return engine(tlsContext(keyManager, trustManager))\n}\n")
    CONTEXT = (
        "private fun tlsContext(keyManager: KeyManager, trustManager: X509TrustManager): "
        "SSLContext =\n"
        "    SSLContext.getInstance(\"TLS\").apply "
        "{ init(arrayOf(keyManager), arrayOf(trustManager), null) }\n")
    ENGINE_LAMBDA = (
        "fun mtlsEngine(certs: Aliases): Engine {\n"
        "    val createKeyManager = {\n"
        "        MtlsKeyManager(resolveAlias = { host -> certs.aliasFor(host) })\n    }\n"
        "    val trustManager = defaultTrustManager()\n"
        "    return engine(tlsContext(createKeyManager, trustManager))\n}\n")
    CONTEXT_HELPER = (
        "private fun tlsContext(createKeyManager: () -> X509ExtendedKeyManager,\n"
        "                       trustManager: X509TrustManager): SSLContext =\n"
        "    SSLContext.getInstance(\"TLS\").apply {\n"
        "        val factory = hostAwareKeyManagerFactory(createKeyManager)\n"
        "        factory.init(null as KeyStore?, null)\n"
        "        init(factory.keyManagers, arrayOf(trustManager), null)\n    }\n\n"
        "internal fun hostAwareKeyManagerFactory(createManager: () -> X509ExtendedKeyManager): "
        "KeyManagerFactory =\n"
        "    KeyManagerFactory.getInstance(\"HostAware\", HostAwareProvider(createManager))\n\n"
        "private class HostAwareProvider(createManager: () -> X509ExtendedKeyManager) :\n"
        "    Provider(\"HostAware\", 1.0, \"host-aware key managers\") {\n"
        "    init { put(\"KeyManagerFactory.HostAware\", HostAwareSpi::class.java.name) }\n}\n\n"
        "private class HostAwareSpi(private val createManager: () -> X509ExtendedKeyManager) :\n"
        "    KeyManagerFactorySpi() {\n"
        "    override fun engineInit(keyStore: KeyStore?, password: CharArray?) {}\n"
        "    override fun engineInit(spec: ManagerFactoryParameters?) {}\n"
        "    override fun engineGetKeyManagers(): Array<KeyManager> = arrayOf(createManager())\n"
        "}\n")

    def test_a_helper_and_a_supplier_lambda_are_followed(self):
        issues = wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext\n", self.IMPORTS, self.PATH),
            edit(self.ENGINE, self.ENGINE_LAMBDA, self.PATH),
            edit(self.CONTEXT, self.CONTEXT_HELPER, self.PATH)])
        self.assertEqual([issue["code"] for issue in issues], ["WRAPPED_SAME_OBJECT"])
        self.assertIn("whose product is MtlsKeyManager,", issues[0]["details"][0])
        self.assertIn("(built by createKeyManager)", issues[0]["details"][0])
        self.assertEqual(issues[0]["affected_paths"], [self.PATH])

    def test_a_helper_whose_class_hands_out_the_passed_parameter_is_followed(self):
        """agent_baseline herald_tls run: init(keyChainBackedManagers(keyManager), ...)."""
        corrected = (
            "private fun tlsContext(keyManager: KeyManager, trustManager: X509TrustManager): "
            "SSLContext =\n"
            "    SSLContext.getInstance(\"TLS\").apply {\n"
            "        init(keyChainBackedManagers(keyManager), arrayOf(trustManager), null)\n"
            "    }\n\n"
            "internal fun keyChainBackedManagers(keyManager: KeyManager): Array<KeyManager> {\n"
            "    val factory = KeyManagerFactory.getInstance(\"KeyChain\", "
            "KeyChainProvider(keyManager))\n"
            "    factory.init(null as KeyStore?, null)\n"
            "    return factory.keyManagers\n}\n\n"
            "private class KeyChainSpi(private val keyManager: KeyManager) : "
            "KeyManagerFactorySpi() {\n"
            "    override fun engineInit(keyStore: KeyStore?, password: CharArray?) {}\n"
            "    override fun engineInit(spec: ManagerFactoryParameters?) {}\n"
            "    override fun engineGetKeyManagers(): Array<KeyManager> = arrayOf(keyManager)\n"
            "}\n\n"
            "private class KeyChainProvider(keyManager: KeyManager) :\n"
            "    Provider(\"KeyChain\", 1.0, \"x\") {\n"
            "    init { put(\"KeyManagerFactory.KeyChain\", KeyChainSpi::class.java.name) }\n}\n")
        issues = wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext\n", self.IMPORTS, self.PATH),
            edit(self.CONTEXT, corrected, self.PATH)])
        self.assertEqual([issue["code"] for issue in issues], ["WRAPPED_SAME_OBJECT"])
        self.assertIn("whose product is keyManager,", issues[0]["details"][0])

    JAVA_PATH = "app/src/main/java/a/TlsIdentity.java"
    JAVA_IMPORTS = ("import java.security.KeyStore;\nimport java.security.KeyStoreSpi;\n"
                    "import java.security.Provider;\nimport javax.net.ssl.KeyManagerFactory;\n"
                    "import javax.net.ssl.SSLContext;\n")
    VIEW = (
        "    static KeyStore identityView(KeyStore backing) throws Exception {\n"
        "        Provider provider = new Provider(\"View\", 1.0, \"read-only view\") {};\n"
        "        KeyStore view = new KeyStore(new IdentitySpi(backing), provider, \"View\") {};\n"
        "        view.load(null, null);\n"
        "        return view;\n    }\n\n"
        "    private static final class IdentitySpi extends KeyStoreSpi {\n"
        "        private final KeyStore backing;\n"
        "        IdentitySpi(KeyStore backing) { this.backing = backing; }\n"
        "        public Key engineGetKey(String alias, char[] password) throws Exception {\n"
        "            if (!ALIAS.equals(alias)) return null;\n"
        "            return backing.getKey(alias, password);\n        }\n"
        "        public Certificate[] engineGetCertificateChain(String alias) {\n"
        "            return ALIAS.equals(alias) ? chainOf(backing, alias) : null;\n        }\n"
        "    }\n")

    def test_a_platform_factory_over_an_app_key_store_view_passes(self):
        """shellyelevatev2 (2026-11-14): the platform KeyManagerFactory makes
        its own key managers from a KeyStoreSpi view that only narrows the
        aliases; its product is not the SingleKeyManager the code passed."""
        original = (
            "    private TlsIdentity(KeyStore keyStore) throws Exception {\n"
            "        SSLContext context = SSLContext.getInstance(\"TLS\");\n"
            "        context.init(new KeyManager[]{new SingleKeyManager()}, null, "
            "new SecureRandom());\n"
            "    }\n")
        corrected = (
            "    private TlsIdentity(KeyStore keyStore) throws Exception {\n"
            "        KeyManagerFactory factory = KeyManagerFactory.getInstance("
            "KeyManagerFactory.getDefaultAlgorithm());\n"
            "        factory.init(identityView(keyStore), null);\n"
            "        SSLContext context = SSLContext.getInstance(\"TLS\");\n"
            "        context.init(factory.getKeyManagers(), null, new SecureRandom());\n"
            "    }\n\n" + self.VIEW)
        self.assertEqual(wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext;\n", self.JAVA_IMPORTS, self.JAVA_PATH),
            edit(original, corrected, self.JAVA_PATH)]), [])
        # Nor when the governed call is the factory's own init, fed a view of
        # the key store it was given: the view consults the store.
        original = ("    void setUp(KeyStore keyStore, char[] password) throws Exception {\n"
                    "        KeyManagerFactory factory = KeyManagerFactory.getInstance(\"X509\");\n"
                    "        factory.init(keyStore, password);\n    }\n")
        corrected = ("    void setUp(KeyStore keyStore, char[] password) throws Exception {\n"
                     "        KeyManagerFactory factory = KeyManagerFactory.getInstance(\"X509\");\n"
                     "        factory.init(identityView(keyStore), password);\n    }\n\n"
                     + self.VIEW)
        self.assertEqual(wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext;\n", self.JAVA_IMPORTS, self.JAVA_PATH),
            edit(original, corrected, self.JAVA_PATH)]), [])

    def test_a_pinning_trust_manager_passes(self):
        """A trust manager that changes what is trusted is the fix itself,
        not an extension point around the old object."""
        original = (
            "    private val sslContext = SSLContext.getInstance(\"TLS\").apply {\n"
            "        init(null, arrayOf(AcceptAnyTrustManager), null)\n    }\n")
        corrected = (
            "    private class PinningTrustManager(private val pin: String) : X509TrustManager {\n"
            "        override fun checkServerTrusted(chain: Array<X509Certificate>, auth: String) {\n"
            "            if (fingerprint(chain[0]) != pin) throw CertificateException(\"pin\")\n"
            "        }\n    }\n\n"
            "    private fun pinnedManagers(pin: String): Array<TrustManager> =\n"
            "        arrayOf(PinningTrustManager(pin))\n\n"
            "    private val sslContext = SSLContext.getInstance(\"TLS\").apply {\n"
            "        init(null, pinnedManagers(PIN), null)\n    }\n")
        self.assertEqual(wrapped_same_objects(SSL_CONTEXT, [
            edit("import javax.net.ssl.SSLContext\n",
                 "import javax.net.ssl.SSLContext\nimport javax.net.ssl.X509TrustManager\n",
                 self.PATH),
            edit(original, corrected, self.PATH)]), [])


from cognalys.llm.semantic_validation import fallbacks_to_original_call  # noqa: E402

KEY_PAIR_GENERATOR = {
    "specification_context": {"events": [
        {"name": "Get", "api_patterns": ["KeyPairGenerator.getInstance("]},
        {"name": "Init", "api_patterns": [".initialize("]},
        {"name": "Gen", "api_patterns": [".generateKeyPair("]},
    ]},
    "error_message": "expecting one of RSA,EC,DSA,DiffieHellman,DH but found ED25519",
}


class FallbackToOriginalTests(_RepositoryCase):
    """Trigger (run_v2, 2026-10-29): ED25519 became getInstance("EC") initialised
    with an Ed25519 parameter an EC generator rejects, inside a try whose catches
    fall through to getInstance("EdDSA") -- the key generation the code already
    did; the draft built and was counted ready."""

    PATH = "app/src/main/kotlin/app/trigger/ssh/GenerateIdentityTask.kt"
    ORIGINAL = (
        "    fun createKeyPair(type: String, bits: Int): KeyPairBean? {\n"
        "        val random = SecureRandom()\n"
        "        val keyPairGen = KeyPairGenerator.getInstance(type)\n"
        "        keyPairGen.initialize(bits, random)\n"
        "        return toBean(type, keyPairGen.generateKeyPair())\n"
        "    }\n"
    )
    CORRECTED = (
        "    private fun namedCurveGenerator(\n"
        "        generatorAlgorithm: String, namedCurve: String, bits: Int, random: SecureRandom,\n"
        "    ): KeyPairGenerator {\n"
        "        val keyPairGen = KeyPairGenerator.getInstance(generatorAlgorithm)\n"
        "        try {\n"
        "            val spec = Class.forName(\"java.security.spec.NamedParameterSpec\")\n"
        "                .getConstructor(String::class.java)\n"
        "                .newInstance(namedCurve) as AlgorithmParameterSpec\n"
        "            keyPairGen.initialize(spec, random)\n"
        "            return keyPairGen\n"
        "        } catch (_: ClassNotFoundException) {\n"
        "            // NamedParameterSpec was added in Android API 31.\n"
        "        } catch (_: java.security.InvalidAlgorithmParameterException) {\n"
        "            // This EC provider does not support Ed25519 named parameters.\n"
        "        }\n"
        "        val fallback = KeyPairGenerator.getInstance(\"EdDSA\")\n"
        "        fallback.initialize(bits, random)\n"
        "        return fallback\n"
        "    }\n"
    )
    LOCATION = {"value": "ED25519", "source_location": "GenerateIdentityTask.kt:3"}

    def gate(self, corrected, error=None, original=None):
        error = {**KEY_PAIR_GENERATOR, "source_file_path": self.PATH,
                 "detector_context": self.LOCATION, **(error or {})}
        return self.run_gate(fallbacks_to_original_call, self.PATH,
                             original or self.ORIGINAL, corrected, error)

    def test_the_trigger_fallback_to_the_ed25519_generator_is_rejected(self):
        [issue] = self.gate(self.CORRECTED)
        self.assertEqual(issue["code"], "FALLBACK_TO_ORIGINAL")
        self.assertEqual(issue["path"], self.PATH)
        self.assertIn('KeyPairGenerator.getInstance("EdDSA"), a value the rule does not allow',
                      issue["details"][0])
        self.assertIn("call it without the fallback", issue["details"][1])

    def test_without_the_reported_line_only_the_reported_value_or_argument_counts(self):
        # The allowlist governs the call the reported line makes; with that line
        # unknown, a literal outside it proves nothing about the fallback.
        unlocated = {"detector_context": {"value": "ED25519"}}
        self.assertEqual(self.gate(self.CORRECTED, unlocated), [])
        # JCA names are case-insensitive: "Ed25519" is the reported ED25519.
        [issue] = self.gate(self.CORRECTED.replace('"EdDSA"', '"Ed25519"'), unlocated)
        self.assertIn('getInstance("Ed25519"), the reported value', issue["details"][0])
        [issue] = self.gate(self.CORRECTED.replace('"EdDSA"', "type"), unlocated)
        self.assertIn("getInstance(type), the argument the original code passed",
                      issue["details"][0])

    def test_a_catch_body_falling_back_to_the_original_argument_is_rejected(self):
        original = ("Cipher cipher = Cipher.getInstance(transformation);\n"
                    "cipher.init(Cipher.ENCRYPT_MODE, key);\n")
        corrected = ("Cipher cipher;\n"
                     "try {\n"
                     "    cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
                     "} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {\n"
                     "    cipher = Cipher.getInstance(transformation);\n"
                     "}\n"
                     "cipher.init(Cipher.ENCRYPT_MODE, key);\n")
        cipher = {"specification_context": {"events": [
            {"name": "Get", "api_patterns": ["Cipher.getInstance("]},
            {"name": "Init", "api_patterns": [".init("]}]},
            "error_message": "expecting one of AES/GCM/NoPadding,... but found AES/ECB"}
        [issue] = fallbacks_to_original_call(cipher, [
            edit(original, corrected, "app/src/main/java/a/Crypto.java")])
        self.assertIn("Cipher.getInstance(transformation), the argument the original code "
                      "passed", issue["details"][0])

    def test_a_fallback_to_another_allowed_value_is_kept(self):
        # AntennaPod's SSLContext draft (run_v2): TLSv1.3, then TLSv1.2 where it is missing.
        original = "SSLContext context = SSLContext.getInstance(\"TLS\");\n"
        corrected = ("SSLContext context;\n"
                     "try {\n"
                     "    context = SSLContext.getInstance(\"TLSv1.3\");\n"
                     "} catch (NoSuchAlgorithmException e) {\n"
                     "    context = SSLContext.getInstance(\"TLSv1.2\");\n"
                     "}\n")
        ssl = {"specification_context": {"events": [
            {"name": "Get", "api_patterns": ["SSLContext.getInstance("]}]},
            "error_message": "expecting one of TLSv1.2,TLSv1.3 but found TLS"}
        self.assertEqual(fallbacks_to_original_call(ssl, [edit(original, corrected)]), [])

    SSL_PATH = "app/src/main/java/a/Net.java"
    SSL_EVENTS = {"events": [{"name": "Get", "api_patterns": ["SSLContext.getInstance("]},
                             {"name": "Init", "api_patterns": [".init("]}]}

    def ssl_gate(self, original, corrected, message, context):
        error = {"specification_context": self.SSL_EVENTS, "error_message": message,
                 "source_file_path": self.SSL_PATH, "detector_context": context}
        return self.run_gate(fallbacks_to_original_call, self.SSL_PATH, original, corrected,
                             error)

    def test_a_fallback_the_original_passed_elsewhere_is_kept_when_the_rule_allows_it(self):
        # The method already made an allowed TLSv1.2 context; falling back to
        # it where TLSv1.3 is missing is not the reported SSL (2026-10-30).
        original = ("SSLContext a = SSLContext.getInstance(\"TLSv1.2\");\n"
                    "SSLContext ctx = SSLContext.getInstance(\"SSL\");\n")
        corrected = ("SSLContext a = SSLContext.getInstance(\"TLSv1.2\");\n"
                     "SSLContext ctx;\ntry {\n    ctx = SSLContext.getInstance(\"TLSv1.3\");\n"
                     "} catch (NoSuchAlgorithmException e) {\n"
                     "    ctx = SSLContext.getInstance(\"TLSv1.2\");\n}\n")
        self.assertEqual(self.ssl_gate(
            original, corrected, "expecting one of TLSV1.2,TLSV1.3,TLS but found SSL",
            {"label": "violation", "value": "SSL", "source_location": "Net.java:2"}), [])

    def test_an_excluded_fallback_counts_only_behind_a_refused_input(self):
        # SSLv3 answered with TLSv1.3, then "TLS" where TLSv1.3 is missing: newer
        # devices use TLSv1.3, the compatibility path is the project's (2026-10-30).
        original = "SSLContext ctx = SSLContext.getInstance(\"SSLv3\");\n"
        corrected = ("SSLContext ctx;\ntry {\n    ctx = SSLContext.getInstance(\"TLSv1.3\");\n"
                     "} catch (NoSuchAlgorithmException e) {\n"
                     "    ctx = SSLContext.getInstance(\"TLS\");\n}\n")
        message = "expecting one of TLSv1.2,TLSv1.3 but found SSLv3"
        context = {"label": "violation", "value": "SSLv3", "source_location": "Net.java:1"}
        self.assertEqual(self.ssl_gate(original, corrected, message, context), [])
        # Behind a catch for a parameter the new value refuses, the excluded
        # value is what the reported input gets.
        [issue] = self.ssl_gate(original, corrected.replace(
            "NoSuchAlgorithmException", "InvalidAlgorithmParameterException"), message, context)
        self.assertIn('SSLContext.getInstance("TLS"), a value the rule does not allow',
                      issue["details"][0])

    def test_a_value_named_in_passing_by_a_not_observed_report_is_not_judged(self):
        # A trust-manager finding records the protocol "TLS" as its value; a
        # patch that replaces the manager and adds a TLSv1.3 path falling back
        # to "TLS" still changes what the checker sees (2026-10-30).
        original = ("SSLContext ctx = SSLContext.getInstance(\"TLS\");\n"
                    "ctx.init(null, new TrustManager[]{trustAll}, null);\n")
        corrected = ("SSLContext ctx;\ntry {\n    ctx = SSLContext.getInstance(\"TLSv1.3\");\n"
                     "} catch (NoSuchAlgorithmException e) {\n"
                     "    ctx = SSLContext.getInstance(\"TLS\");\n}\n"
                     "ctx.init(null, factory.getTrustManagers(), null);\n")
        self.assertEqual(self.ssl_gate(
            original, corrected,
            "the TrustManager[] given to SSLContext.init holds a manager of a class the "
            "application defines and was not observed coming from a TrustManagerFactory",
            {"label": "application-manager", "value": "TLS",
             "expected": "a TrustManager[] an observed TrustManagerFactory returned",
             "source_location": "Net.java:1"}), [])

    def test_a_call_other_than_the_reported_one_is_not_judged(self):
        # The key size was reported at init; a getInstance upgrade beside the
        # fix, falling back to the original algorithm, is not the reported call.
        path = "app/src/main/java/a/Keys.java"
        original = ("KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);\n"
                    "keyGen.init(64);\n")
        corrected = ("KeyGenerator keyGen;\ntry {\n"
                     "    keyGen = KeyGenerator.getInstance(\"AES\");\n"
                     "} catch (NoSuchAlgorithmException e) {\n"
                     "    keyGen = KeyGenerator.getInstance(algorithm);\n}\n"
                     "keyGen.init(256);\n")
        error = {"specification_context": {"events": [
            {"name": "Get", "api_patterns": ["KeyGenerator.getInstance("]},
            {"name": "Init", "api_patterns": [".init("]}]},
            "error_message": "expecting one of 128,192,256 but found 64",
            "source_file_path": path,
            "detector_context": {"label": "violation", "value": "64",
                                 "source_location": "Keys.java:2"}}
        self.assertEqual(self.run_gate(fallbacks_to_original_call, path, original, corrected,
                                       error), [])
        # At the reported line the same fallback is judged.
        error["detector_context"] = {**error["detector_context"],
                                     "source_location": "Keys.java:1"}
        [issue] = self.run_gate(fallbacks_to_original_call, path, original, corrected, error)
        self.assertIn("KeyGenerator.getInstance(algorithm), the argument the original code "
                      "passed", issue["details"][0])

    def test_a_migration_or_catch_all_fallback_is_not_judged(self):
        # Data written the old way is read back the old way; owncloud-news-reader's
        # published loadAppKeyStore keeps ks.load(null) under catch (Exception).
        for caught in ("javax.crypto.AEADBadTagException", "GeneralSecurityException",
                       "Exception", "Throwable"):
            with self.subTest(caught=caught):
                corrected = self.CORRECTED.replace(
                    "catch (_: ClassNotFoundException)", "catch (e: " + caught + ")").replace(
                    "catch (_: java.security.InvalidAlgorithmParameterException)",
                    "catch (f: " + caught + ")")
                self.assertEqual(self.gate(corrected), [])

    def test_a_try_the_original_already_had_or_a_version_check_is_not_judged(self):
        self.assertEqual(self.gate(self.CORRECTED, original=self.CORRECTED), [])
        version_check = (
            "    val keyPairGen = if (Build.VERSION.SDK_INT >= 33) {\n"
            "        KeyPairGenerator.getInstance(\"EC\")\n"
            "    } else {\n"
            "        KeyPairGenerator.getInstance(\"EdDSA\")\n"
            "    }\n")
        self.assertEqual(self.gate(version_check), [])

    def test_catches_that_exit_never_reach_the_code_after_the_try(self):
        corrected = self.CORRECTED.replace(
            "            // NamedParameterSpec was added in Android API 31.\n",
            "            throw IllegalStateException(\"unsupported\")\n").replace(
            "            // This EC provider does not support Ed25519 named parameters.\n",
            "            return null\n")
        self.assertEqual(self.gate(corrected), [])

    def test_the_coordinated_validator_regenerates_and_then_closes_without_impact(self):
        from cognalys.llm.coordinated_generation import CoordinatedGeneration

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / self.PATH).parent.mkdir(parents=True)
            (root / self.PATH).write_text(self.ORIGINAL, encoding="utf-8")
            error = {**KEY_PAIR_GENERATOR, "repository_path": str(root),
                     "source_file_path": self.PATH, "detector_context": self.LOCATION}
            result = validate_coordinated_semantics(
                error, [edit(self.ORIGINAL, self.CORRECTED, self.PATH)])
        [issue] = [item for item in result["errors"] if item["code"] == "FALLBACK_TO_ORIGINAL"]
        self.assertEqual(semantic_validation_retry_targets(
            [issue], [self.PATH, "app/src/main/kotlin/app/trigger/ssh/SshKeyPairActivity.kt"]),
            {self.PATH})
        self.assertEqual(plain_blocker_reasons(["FALLBACK_TO_ORIGINAL"]),
                         ["the changes I could make left the reported call as it is"])
        failed = {}
        CoordinatedGeneration._close_discarded_construction({}, failed, [issue])
        self.assertTrue(failed["correct_use"].startswith(
            "Every proposed change leaves the calls the checker observes as they were: "
            "the patch tries a new value in a try block"))


from cognalys.llm.semantic_validation import same_values_through_unobserved_apis  # noqa: E402

EC_GEN_PARAMETER_SPEC = {
    "specification_context": {
        "applies_to_types": ["java.security.spec.ECGenParameterSpec"],
        "events": [{"name": "c1", "api_patterns": [
            "new ECGenParameterSpec(", "ECGenParameterSpec(",
            "java.security.spec.ECGenParameterSpec("]}]},
    "error_message": "the elliptic curve standard name is not one the rule admits",
    "detector_context": {"label": "violation", "value": "ed25519",
                         "expected": "brainpoolP256r1,secp256r1,NIST P-256,"
                                     "X9.62 prime256v1,1.2.840.10045.3.1.7,secp384r1"},
}


class SameValueThroughUnobservedApiTests(_RepositoryCase):
    """AGrahn (run_v3, 2026-10-29): KeyPairGenerator.getInstance("EdDSA", BC)
    initialised with ECGenParameterSpec("ed25519") became Bouncy Castle's
    lightweight Ed25519KeyPairGenerator, converted back to JCA keys -- the same
    key through an API the checker does not instrument; the draft built and
    was counted ready."""

    PATH = "app/src/main/java/app/passwordstore/util/git/sshj/SshKey.kt"
    IMPORT = "import org.bouncycastle.jce.provider.BouncyCastleProvider"
    IMPORTS = (
        "import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator\n"
        "import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters\n"
        "import org.bouncycastle.crypto.util.PrivateKeyInfoFactory\n"
        "import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory\n"
        "import org.bouncycastle.jce.provider.BouncyCastleProvider")
    ORIGINAL = (
        "  fun generateKeystoreWrappedEd25519Key(requireAuthentication: Boolean) {\n"
        "    delete()\n"
        "    val keyPair =\n"
        "      KeyPairGenerator.getInstance(\"EdDSA\", BouncyCastleProvider()).run {\n"
        "        initialize(ECGenParameterSpec(\"ed25519\"), SecureRandom())\n"
        "        generateKeyPair()\n"
        "      }\n"
        "    store(keyPair)\n"
        "  }\n")
    CORRECTED = (
        "  fun generateKeystoreWrappedEd25519Key(requireAuthentication: Boolean) {\n"
        "    delete()\n"
        "    val ed25519KeyPair =\n"
        "      Ed25519KeyPairGenerator().apply {\n"
        "        init(Ed25519KeyGenerationParameters(SecureRandom()))\n"
        "      }\n"
        "        .generateKeyPair()\n"
        "    val keyFactory = KeyFactory.getInstance(\"Ed25519\", BouncyCastleProvider())\n"
        "    val keyPair =\n"
        "      KeyPair(\n"
        "        keyFactory.generatePublic(X509EncodedKeySpec(\n"
        "          SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(\n"
        "            ed25519KeyPair.public).encoded)),\n"
        "        keyFactory.generatePrivate(PKCS8EncodedKeySpec(\n"
        "          PrivateKeyInfoFactory.createPrivateKeyInfo(ed25519KeyPair.private).encoded)),\n"
        "      )\n"
        "    store(keyPair)\n"
        "  }\n")

    def edits(self, corrected=None, imports=None, original=None):
        return [
            edit(self.IMPORT, self.IMPORTS if imports is None else imports, self.PATH),
            edit(original or self.ORIGINAL, corrected or self.CORRECTED, self.PATH),
        ]

    def gate(self, edits, error=None):
        return same_values_through_unobserved_apis(
            {**EC_GEN_PARAMETER_SPEC, "source_file_path": self.PATH, **(error or {})}, edits)

    def test_the_agrahn_lightweight_ed25519_generator_is_rejected(self):
        [issue] = self.gate(self.edits())
        self.assertEqual(issue["code"], "SAME_VALUE_UNOBSERVED_API")
        self.assertEqual(issue["path"], self.PATH)
        self.assertIn('removes ECGenParameterSpec("ed25519") and produces the same ed25519 '
                      "through org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters, "
                      "org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator, an API "
                      "outside the platform's", issue["details"][0])
        # The conversion helpers name no value and are not listed.
        self.assertNotIn("PrivateKeyInfoFactory", issue["details"][0])
        self.assertIn("leave the code as it is", issue["details"][1])

    def test_a_qualified_reference_without_an_import_counts_too(self):
        corrected = self.CORRECTED.replace(
            "Ed25519KeyPairGenerator()",
            "org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator()")
        [issue] = self.gate(self.edits(corrected, imports=self.IMPORT))
        self.assertIn("Ed25519KeyPairGenerator", issue["details"][0])

    def test_a_class_the_file_already_imports_is_found_in_the_repository(self):
        # Without an import anywhere the class may be the app's own: not judged.
        self.assertEqual(self.run_gate(
            same_values_through_unobserved_apis, self.PATH, self.ORIGINAL, self.CORRECTED,
            {**EC_GEN_PARAMETER_SPEC, "source_file_path": self.PATH}), [])
        source = ("import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator\n"
                  + self.ORIGINAL)
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / self.PATH).parent.mkdir(parents=True)
            (Path(directory) / self.PATH).write_text(source, encoding="utf-8")
            [issue] = self.gate([edit(self.ORIGINAL, self.CORRECTED, self.PATH)],
                                {"repository_path": directory})
        self.assertIn("Ed25519KeyPairGenerator", issue["details"][0])

    def test_an_allowed_curve_through_the_governed_api_is_a_change(self):
        corrected = self.ORIGINAL.replace('getInstance("EdDSA"', 'getInstance("EC"').replace(
            '"ed25519"', '"secp256r1"')
        self.assertEqual(self.gate(self.edits(corrected, imports=self.IMPORT)), [])

    def test_a_different_allowed_value_through_the_other_library_is_a_change(self):
        # A P-256 key from the lightweight API is a different key, even unseen.
        corrected = self.CORRECTED.replace(
            "Ed25519KeyPairGenerator().apply {\n"
            "        init(Ed25519KeyGenerationParameters(SecureRandom()))",
            "ECKeyPairGenerator().apply {\n"
            "        init(ECKeyGenerationParameters(Secp256r1Domain.PARAMETERS, SecureRandom()))")
        imports = self.IMPORTS.replace("Ed25519KeyPairGenerator", "ECKeyPairGenerator")
        self.assertEqual(self.gate(self.edits(corrected, imports)), [])

    def test_a_new_name_naming_an_allowed_value_keeps_the_patch(self):
        # Cipher "AES" (ECB by default) answered with the lightweight AESEngine
        # inside GCMBlockCipher: the mode the rule allows is a change.
        path = "app/src/main/java/a/Crypto.java"
        original = "Cipher cipher = Cipher.getInstance(\"AES\");\ncipher.init(mode, key);\n"
        corrected = ("GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());\n"
                     "cipher.init(forEncryption, parameters);\n")
        imports = ("import org.bouncycastle.crypto.engines.AESEngine;\n"
                   "import org.bouncycastle.crypto.modes.GCMBlockCipher;\n")
        cipher = {"specification_context": {"events": [
            {"name": "Get", "api_patterns": ["Cipher.getInstance("]}]},
            "error_message": "expecting one of AES/GCM/NoPadding,AES/CBC/PKCS5Padding "
                             "but found AES"}
        changes = [edit("", imports, path), edit(original, corrected, path)]
        self.assertEqual(same_values_through_unobserved_apis(cipher, changes), [])
        # Without the mode, AESEngine alone is the reported AES again.
        [issue] = same_values_through_unobserved_apis(cipher, [
            edit("", "import org.bouncycastle.crypto.engines.AESEngine;\n", path),
            edit(original, "AESEngine cipher = new AESEngine();\n"
                           "cipher.init(forEncryption, parameters);\n", path)])
        self.assertIn('removes getInstance("AES") and produces the same AES through '
                      "org.bouncycastle.crypto.engines.AESEngine", issue["details"][0])

    def test_platform_classes_app_classes_and_kept_calls_are_not_judged(self):
        # A platform class reaches the platform's API, which the checker sees.
        platform = self.CORRECTED.replace(
            "Ed25519KeyPairGenerator()", "Ed25519ParameterHolder()")
        self.assertEqual(self.gate(self.edits(platform, imports=(
            self.IMPORT + "\nimport java.security.spec.Ed25519ParameterHolder"))), [])
        # A class the patch declares is the app's own; the review weighs it.
        declared = self.CORRECTED + "\nclass Ed25519KeyPairGenerator { }\n"
        self.assertEqual(self.gate(self.edits(declared, imports=self.IMPORT)), [])
        # The governed call still carrying the value is the checker's to see.
        kept = self.CORRECTED.replace(
            "    store(keyPair)\n", "    check(ECGenParameterSpec(\"Ed25519\"))\n"
                                    "    store(keyPair)\n")
        self.assertEqual(self.gate(self.edits(kept)), [])

    def test_a_report_without_a_value_or_with_a_short_one_is_not_judged(self):
        not_a_value = {"detector_context": {"label": "application-manager",
                                            "value": "ed25519"}}
        self.assertEqual(self.gate(self.edits(), not_a_value), [])
        short = {"detector_context": {"label": "violation", "value": "EC"}}
        self.assertEqual(self.gate(self.edits(), short), [])

    def test_the_coordinated_validator_regenerates_and_then_closes_without_impact(self):
        from cognalys.llm.coordinated_generation import CoordinatedGeneration

        result = validate_coordinated_semantics(
            {**EC_GEN_PARAMETER_SPEC, "source_file_path": self.PATH}, self.edits())
        [issue] = [item for item in result["errors"]
                   if item["code"] == "SAME_VALUE_UNOBSERVED_API"]
        self.assertEqual(semantic_validation_retry_targets(
            [issue], [self.PATH, "app/src/main/java/app/passwordstore/ui/sshkeygen/"
                                 "SshKeyGenActivity.kt"]), {self.PATH})
        self.assertEqual(plain_blocker_reasons(["SAME_VALUE_UNOBSERVED_API"]),
                         ["the changes I could make left the reported call as it is"])
        failed = {}
        CoordinatedGeneration._close_discarded_construction({}, failed, [issue])
        self.assertTrue(failed["correct_use"].startswith(
            "Every proposed change leaves the calls the checker observes as they were: "
            "the patch removes ECGenParameterSpec"))


MESSAGE_DIGEST = {
    "specification_context": {"events": [
        {"name": "Get", "api_patterns": ["MessageDigest.getInstance("]}]},
    "error_message": "expecting one of SHA-256,SHA-384,SHA-512 but found SHA-1",
}


class SameValueGateKeepsRealChangesTests(unittest.TestCase):
    """Adversarial review of SAME_VALUE_UNOBSERVED_API (2026-10-30): a new
    class whose name starts with the reported value is no proof that the
    value survived. Each patch below changes the value, yet the gate as
    first written closed it as a violation without security impact."""

    PATH = "app/src/main/java/a/Hashes.java"
    ORIGINAL = ('MessageDigest md = MessageDigest.getInstance("SHA-1");\n'
                "byte[] h = md.digest(data);\n")

    def gate(self, corrected, imports, error=None):
        return same_values_through_unobserved_apis(error or MESSAGE_DIGEST, [
            edit("", imports, self.PATH), edit(self.ORIGINAL, corrected, self.PATH)])

    def test_the_lightweight_digest_of_the_same_value_is_still_rejected(self):
        [issue] = self.gate("SHA1Digest md = new SHA1Digest();\n"
                            "md.update(data, 0, data.length);\n",
                            "import org.bouncycastle.crypto.digests.SHA1Digest;\n")
        self.assertIn('removes getInstance("SHA-1") and produces the same SHA-1 through '
                      "org.bouncycastle.crypto.digests.SHA1Digest", issue["details"][0])

    def test_a_governed_call_kept_with_a_new_value_is_a_change(self):
        # The digest moved to SHA-256 through the governed call; the app's
        # Sha1Legacy only reads hashes stored before.
        corrected = self.ORIGINAL.replace('"SHA-1"', '"SHA-256"') + (
            "if (legacy) h = Sha1Legacy.migrate(h);\n")
        self.assertEqual(self.gate(corrected, "import a.util.Sha1Legacy;\n"), [])
        # A constant the checker reads at run time is the same: the call stays.
        constant = self.ORIGINAL.replace('"SHA-1"', "DIGEST") + (
            "if (legacy) h = Sha1Legacy.migrate(h);\n")
        self.assertEqual(self.gate(constant, "import a.util.Sha1Legacy;\n"), [])

    def test_an_allowed_value_named_by_a_helper_or_a_literal_is_a_change(self):
        self.assertEqual(self.gate('byte[] h = Sha1Migration.rehash(data, "SHA-256");\n',
                                   "import a.util.Sha1Migration;\n"), [])
        self.assertEqual(self.gate("byte[] h = Sha1Migration.toSha256(data);\n",
                                   "import a.util.Sha1Migration;\n"), [])

    def test_a_value_that_names_the_governed_api_family_is_not_judged(self):
        # "SSL" is a word of SSLContext and the first word of Netty's
        # SslContextBuilder, whose default protocol is TLS.
        ssl = {"specification_context": {
            "applies_to_types": ["javax.net.ssl.SSLContext"],
            "events": [{"name": "Get", "api_patterns": ["SSLContext.getInstance("]}]},
            "error_message": "expecting one of TLSv1.2,TLSv1.3,TLS but found SSL"}
        path = "app/src/main/java/a/Net.java"
        original = ('SSLContext ctx = SSLContext.getInstance("SSL");\n'
                    "ctx.init(null, tms, null);\n"
                    "pipeline.addFirst(new SslHandler(ctx.createSSLEngine()));\n")
        corrected = ("SslContext ctx = SslContextBuilder.forClient().trustManager(tmf).build();\n"
                     "pipeline.addFirst(ctx.newHandler(channel.alloc()));\n")
        imports = ("import io.netty.handler.ssl.SslContext;\n"
                   "import io.netty.handler.ssl.SslContextBuilder;\n")
        self.assertEqual(same_values_through_unobserved_apis(
            ssl, [edit("", imports, path), edit(original, corrected, path)]), [])


from cognalys.llm.coordinated_generation import _NO_EFFECT_GATE_CODES  # noqa: E402

PBE_KEY_SPEC = {"specification_context": {
    "applies_to_types": ["javax.crypto.spec.PBEKeySpec"]}}


class RebuiltObjectsAreLeftToTheReviewTests(unittest.TestCase):
    """BlueGate (run_v4, 2026-10-30) repackaged the KeyPair it already held
    and the alias' entry it had just generated. A deterministic gate for it
    (batch 7) also closed, as "the same key material", a software generator's
    result dropped for an old keystore entry, a GCM nonce taken from a saved
    record and a PBEKeySpec rebuilt without its key length: what a producer
    stores and which getters a constructor needs are not readable from the
    patch. Those cases are judged by the behaviour review (contract 11)."""

    KEYS = "app/src/main/java/org/x/app/Keys.kt"

    def assert_left_to_the_review(self, spec, original_file, original, corrected):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / self.KEYS).parent.mkdir(parents=True)
            (root / self.KEYS).write_text(original_file, encoding="utf-8")
            result = validate_coordinated_semantics(
                {**spec, "repository_path": str(root)},
                [edit(original, corrected, self.KEYS)])
        codes = {item["code"] for item in result.get("errors", [])}
        self.assertFalse(codes & _NO_EFFECT_GATE_CODES, codes)

    def test_a_dropped_software_key_pair_for_a_stored_entry_is_not_no_effect(self):
        original = ("    fun fresh(alias: String): KeyPair {\n"
                    "        val kpg = KeyPairGenerator.getInstance(\"RSA\")\n"
                    "        kpg.initialize(2048)\n"
                    "        return kpg.generateKeyPair()\n"
                    "    }\n")
        corrected = ("    fun fresh(alias: String): KeyPair {\n"
                     "        val kpg = KeyPairGenerator.getInstance(\"RSA\")\n"
                     "        kpg.initialize(2048)\n"
                     "        kpg.generateKeyPair()\n"
                     "        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry\n"
                     "        return KeyPair(entry.certificate.publicKey, entry.privateKey)\n"
                     "    }\n")
        loader = ("    fun load(alias: String): KeyPair {\n"
                  "        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry\n"
                  "        return KeyPair(entry.certificate.publicKey, entry.privateKey)\n"
                  "    }\n")
        self.assert_left_to_the_review(
            KEY_PAIR, "class Keys(private val keyStore: KeyStore) {\n" + loader + original + "}\n",
            original, corrected)

    def test_a_spec_rebuilt_without_one_of_its_parts_is_not_no_effect(self):
        original = ("    fun derive(spec: PBEKeySpec): ByteArray {\n"
                    "        val used: PBEKeySpec = spec\n"
                    "        return factory.generateSecret(used).encoded\n"
                    "    }\n")
        corrected = ("    fun derive(spec: PBEKeySpec): ByteArray {\n"
                     "        val used: PBEKeySpec = PBEKeySpec(spec.password, spec.salt, "
                     "spec.iterationCount)\n"
                     "        return factory.generateSecret(used).encoded\n"
                     "    }\n")
        self.assert_left_to_the_review(
            PBE_KEY_SPEC, "class Pbe {\n" + original + "}\n", original, corrected)


from cognalys.llm.semantic_validation import same_parts_app_carriers  # noqa: E402


class SamePartsAppCarrierTests(unittest.TestCase):
    """BlueGate run_v7 (2026-10-31): RVSec's KeyPairSpec finding at
    `KeyPair(entry.certificate.publicKey, entry.privateKey)` was answered with a
    new data class KeyMaterial of the same two keys, threaded through four
    files: the monitor no longer saw a KeyPair constructor and the code held
    and signed with what it did. The behaviour review let it through."""

    PATH = "app/src/main/java/org/cleverfox/bluegate/KeyManager.kt"
    JAVA_PATH = "app/src/main/java/a/K.java"
    METHOD = (
        "    fun getOrCreateKeyPair(): KeyPair {\n"
        "        val alias = \"BlueGate\"\n"
        "        if (keyStore.containsAlias(alias)) {\n"
        "            val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry\n"
        "            return KeyPair(entry.certificate.publicKey, entry.privateKey)\n"
        "        }\n"
        "        return generateNewKeyPair(alias)\n"
        "    }\n")
    JAVA_METHOD = (
        "KeyPair load() throws Exception {\n"
        "    PrivateKey priv = (PrivateKey) keyStore.getKey(ALIAS, null);\n"
        "    PublicKey pub = keyStore.getCertificate(ALIAS).getPublicKey();\n"
        "    return new KeyPair(pub, priv);\n}\n")

    def setUp(self):
        # The gate reads the original file, as validation does through the
        # finding's repository_path: keyStore is a property the method does
        # not declare.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / self.PATH).parent.mkdir(parents=True)
        (root / self.PATH).write_text(
            "package org.cleverfox.bluegate\n\n"
            "class KeyManager(private val keyStore: KeyStore) {\n" + self.METHOD + "}\n")
        (root / self.JAVA_PATH).parent.mkdir(parents=True)
        (root / self.JAVA_PATH).write_text(
            "class K {\n    private final KeyStore keyStore;\n" + self.JAVA_METHOD + "}\n")
        self.KEY_PAIR = {"specification_context": {"applies_to_types": ["java.security.KeyPair"]},
                         "repository_path": str(root)}

    def edits(self, corrected_method, declaration="", path=None, original=None):
        path = path or self.PATH
        edits = [{"source_file_path": path, "edit_kind": "method",
                  "original_code": original or self.METHOD, "corrected_code": corrected_method}]
        if declaration:
            edits.insert(0, {"source_file_path": path, "edit_kind": "declaration",
                             "original_code": "class KeyManager(private val keyStore: KeyStore) {",
                             "corrected_code": declaration
                             + "\nclass KeyManager(private val keyStore: KeyStore) {"})
        return edits

    def java(self, corrected):
        return [{"source_file_path": self.JAVA_PATH, "edit_kind": "method",
                 "original_code": self.JAVA_METHOD, "corrected_code": corrected}]

    CARRIER = ("data class KeyMaterial(\n    val publicKey: PublicKey,\n"
               "    val privateKey: PrivateKey\n)\n")
    SAME_TEXT = METHOD.replace("return KeyPair(entry", "return KeyMaterial(entry")

    def flagged(self, edits, context=None):
        return [issue["code"] for issue in same_parts_app_carriers(context or self.KEY_PAIR, edits)]

    def test_bluegates_key_material_carrier_is_flagged(self):
        corrected = (self.METHOD.replace("KeyPair(entry", "KeyMaterial(entry")
                     .replace("getOrCreateKeyPair(): KeyPair", "getOrCreateKeyMaterial(): KeyMaterial"))
        [issue] = same_parts_app_carriers(self.KEY_PAIR, self.edits(corrected, self.CARRIER))
        self.assertEqual(issue["code"], "SAME_PARTS_APP_CARRIER")
        self.assertEqual(issue["path"], self.PATH)
        self.assertIn("KeyPair(entry.certificate.publicKey,entry.privateKey) -> "
                      "KeyMaterial(entry.certificate.publicKey,entry.privateKey)",
                      issue["details"][0])

    def test_standard_holders_records_and_plain_property_classes_are_carriers_too(self):
        # BlueGate's run of 2026-10-22 declared a plain `class KeyMaterial(val
        # publicKey: PublicKey, val privateKey: PrivateKey)`: with no body it
        # cannot hold an init block, so it is as decidable as a data class.
        record = ("record Keys(PublicKey pub, PrivateKey priv) {}\n"
                  + self.JAVA_METHOD.replace("new KeyPair(pub, priv)", "new Keys(pub, priv)"))
        allman = record.replace(") {}\n", ")\n{\n}\n", 1)
        for name, edits in (
                ("Pair", self.edits(self.METHOD.replace("return KeyPair(entry", "return Pair(entry"))),
                ("arrayOf", self.edits(self.METHOD.replace("return KeyPair(entry",
                                                           "return arrayOf(entry"))),
                ("plain class", self.edits(self.SAME_TEXT, self.CARRIER.replace("data class", "class"))),
                ("generic data class", self.edits(
                    self.METHOD.replace("return KeyPair(entry", "return Holder<PublicKey, PrivateKey>(entry"),
                    "data class Holder<A, B>(val a: A, val b: B)\n")),
                ("Java record", self.java(record)),
                ("Java record, Allman braces", self.java(allman)),
                ("Java Map.entry", self.java(self.JAVA_METHOD.replace("new KeyPair(pub, priv)",
                                                                      "Map.entry(pub, priv)")))):
            with self.subTest(name):
                self.assertEqual(self.flagged(edits), ["SAME_PARTS_APP_CARRIER"])

    def test_the_platform_entry_used_through_its_getters_is_a_change(self):
        # run_v6: return the KeyStore.PrivateKeyEntry the store gave and read
        # its own getters; no holder is built.
        corrected = (self.METHOD.replace("return KeyPair(entry.certificate.publicKey, "
                                         "entry.privateKey)", "return entry")
                     .replace("(): KeyPair", "(): KeyStore.PrivateKeyEntry"))
        self.assertEqual(same_parts_app_carriers(self.KEY_PAIR, self.edits(corrected)), [])

    def test_other_parts_other_sources_or_a_class_with_behaviour_are_not_flagged(self):
        # A part read elsewhere: the holder's arguments differ.
        other_part = self.METHOD.replace(
            "return KeyPair(entry.certificate.publicKey, entry.privateKey)",
            "return KeyMaterial(entry.certificate.publicKey, freshKey())")
        # The same text, but the local it reads now comes from another alias.
        other_source = (self.METHOD
                        .replace("keyStore.getEntry(alias, null)",
                                 "keyStore.getEntry(\"other\", null)")
                        .replace("return KeyPair(entry", "return KeyMaterial(entry"))
        other_alias = self.SAME_TEXT.replace('val alias = "BlueGate"', 'val alias = "Other"')
        behaving = ("data class KeyMaterial(val publicKey: PublicKey, val privateKey: "
                    "PrivateKey) {\n    init { require(publicKey.algorithm == \"EC\") }\n}\n")
        with_supertype = ("data class KeyMaterial(val publicKey: PublicKey, val privateKey: "
                          "PrivateKey) : Destroyable\n")
        for name, edits in (
                ("other part", self.edits(other_part, self.CARRIER)),
                ("other source", self.edits(other_source, self.CARRIER)),
                ("other value through a local", self.edits(other_alias, self.CARRIER)),
                ("class with a body", self.edits(self.SAME_TEXT, behaving)),
                ("class with a supertype", self.edits(self.SAME_TEXT, with_supertype)),
                ("open class", self.edits(self.SAME_TEXT, self.CARRIER.replace("data class",
                                                                               "open class"))),
                ("constructor parameter that is no property", self.edits(
                    self.SAME_TEXT, self.CARRIER.replace("val publicKey", "publicKey"))),
                ("default value", self.edits(self.SAME_TEXT, self.CARRIER.replace(
                    "val privateKey: PrivateKey\n", "val privateKey: PrivateKey,\n"
                    "    val at: Long = register()\n"))),
                ("governed object kept", self.edits(self.METHOD.replace(
                    "val alias", "val unused = 0\n        val alias"), self.CARRIER)),
                ("test file", [{**edit, "source_file_path": "app/src/test/java/KeyManagerTest.kt"}
                               for edit in self.edits(self.SAME_TEXT, self.CARRIER)])):
            with self.subTest(name):
                self.assertEqual(same_parts_app_carriers(self.KEY_PAIR, edits), [])

    def test_a_patch_that_still_builds_the_governed_object_gets_no_verdict(self):
        # Review of 2026-10-31: the holder fed back into KeyPair(...), with a
        # mismatched entry now regenerated, still calls the governed API.
        corrected = self.METHOD.replace(
            "            return KeyPair(entry.certificate.publicKey, entry.privateKey)\n",
            "            val parts = Pair(entry.certificate.publicKey, entry.privateKey)\n"
            "            if (parts.first.algorithm != parts.second.algorithm) {\n"
            "                keyStore.deleteEntry(alias)\n"
            "                return generateNewKeyPair(alias)\n"
            "            }\n"
            "            return KeyPair(parts.first, parts.second)\n")
        self.assertEqual(self.flagged(self.edits(corrected)), [])

    def test_a_part_given_another_value_anywhere_gets_no_verdict(self):
        # Review of 2026-10-31: these patches change where a part comes from
        # through forms a declaration-only reading missed.
        reassigned_original = self.METHOD.replace("val entry =", "var entry =")
        reassigned = reassigned_original.replace(
            "            return KeyPair(entry",
            "            if (entry.certificate.publicKey.algorithm != \"EC\") {\n"
            "                entry = regenerateEntry(alias)\n"
            "            }\n"
            "            return KeyMaterial(entry")
        deferred_original = ("KeyPair load() throws Exception {\n    PrivateKey priv;\n"
                             "    PublicKey pub;\n"
                             "    priv = (PrivateKey) keyStore.getKey(ALIAS, null);\n"
                             "    pub = keyStore.getCertificate(ALIAS).getPublicKey();\n"
                             "    return new KeyPair(pub, priv);\n}\n")
        deferred = ("record Keys(PublicKey pub, PrivateKey priv) {}\n"
                    "Keys load() throws Exception {\n    PrivateKey priv;\n    PublicKey pub;\n"
                    "    KeyPair fresh = generator.generateKeyPair();\n"
                    "    priv = fresh.getPrivate();\n    pub = fresh.getPublic();\n"
                    "    return new Keys(pub, priv);\n}\n")
        rewritten_callee_original = (
            "    fun pair(): KeyPair {\n        return KeyPair(loadPublic(), loadPrivate())\n    }\n"
            "    private fun loadPrivate(): PrivateKey = keyStore.getKey(ALIAS, null) as PrivateKey\n")
        rewritten_callee = (
            "    fun pair(): Pair<PublicKey, PrivateKey> {\n"
            "        return Pair(loadPublic(), loadPrivate())\n    }\n"
            "    private fun loadPrivate(): PrivateKey = generator.generateKeyPair().private\n")
        parameter_original = (self.METHOD.replace(
            "fun getOrCreateKeyPair()", "fun getOrCreateKeyPair(entry: KeyStore.PrivateKeyEntry)")
            .replace("            val entry = keyStore.getEntry(alias, null) as "
                     "KeyStore.PrivateKeyEntry\n", ""))
        for name, edits in (
                ("Kotlin reassignment", self.edits(reassigned, self.CARRIER,
                                                   original=reassigned_original)),
                ("Java deferred assignment", [{
                    "source_file_path": self.JAVA_PATH, "edit_kind": "method",
                    "original_code": deferred_original, "corrected_code": deferred}]),
                ("callee the patch rewrites", self.edits(rewritten_callee,
                                                         original=rewritten_callee_original)),
                ("parameter", self.edits(parameter_original.replace("return KeyPair(entry",
                                                                    "return Pair(entry"),
                                         original=parameter_original)),
                ("the class built with another store", self.edits(
                    self.METHOD.replace("return KeyPair(entry", "return Pair(entry")) + [{
                        "source_file_path": "app/src/main/java/org/cleverfox/bluegate/Main.kt",
                        "edit_kind": "method",
                        "original_code": "        keyManager = KeyManager(keyStore)\n",
                        "corrected_code": "        keyManager = KeyManager(otherStore)\n"}])):
            with self.subTest(name):
                self.assertEqual(self.flagged(edits), [])

    def test_a_body_on_the_next_line_is_a_body(self):
        # Review of 2026-10-31: Allman braces hid a validating body.
        record = ("record Keys(PublicKey pub, PrivateKey priv)\n{\n    Keys\n    {\n"
                  "        if (!pub.getAlgorithm().equals(priv.getAlgorithm())) "
                  "throw new IllegalStateException();\n    }\n}\n"
                  + self.JAVA_METHOD.replace("new KeyPair(pub, priv)", "new Keys(pub, priv)"))
        data_class = ("data class KeyMaterial(val publicKey: PublicKey, val privateKey: PrivateKey)\n"
                      "{\n    init { require(publicKey.algorithm == privateKey.algorithm) }\n}\n")
        self.assertEqual(self.flagged(self.java(record)), [])
        self.assertEqual(self.flagged(self.edits(self.SAME_TEXT, data_class)), [])

    def test_without_the_file_a_property_it_cannot_see_gets_no_verdict(self):
        context = {"specification_context": self.KEY_PAIR["specification_context"]}
        pair = self.METHOD.replace("return KeyPair(entry", "return Pair(entry")
        self.assertEqual(self.flagged(self.edits(pair), context), [])

    def test_a_changed_value_is_never_a_carrier(self):
        # "SSL" -> "TLS" stays a pull request: literals take part in the text.
        context = {"specification_context": {"applies_to_types": ["javax.crypto.spec.SecretKeySpec"]}}
        original = 'val key = SecretKeySpec(bytes, "DES")\n'
        corrected = ('data class Material(val bytes: ByteArray, val algorithm: String)\n'
                     'val key = Material(bytes, "AES")\n')
        self.assertEqual(same_parts_app_carriers(context, [{
            "source_file_path": "app/src/main/java/a/K.kt", "edit_kind": "method",
            "original_code": original, "corrected_code": corrected}]), [])

    def test_it_closes_the_finding_like_the_other_no_effect_gates(self):
        from cognalys.llm.coordinated_generation import _NO_EFFECT_GATE_CODES
        from cognalys.llm.semantic_validation import _SEMANTIC_VALIDATION_PRODUCTION_CODES

        self.assertIn("SAME_PARTS_APP_CARRIER", _NO_EFFECT_GATE_CODES)
        self.assertIn("SAME_PARTS_APP_CARRIER", _SEMANTIC_VALIDATION_PRODUCTION_CODES)
        self.assertEqual(plain_blocker_reasons(["SAME_PARTS_APP_CARRIER"]),
                         plain_blocker_reasons(["DISCARDED_CONSTRUCTION"]))


from cognalys.llm.semantic_validation import same_parts_app_keys  # noqa: E402

MAC_WITH_JOINT_SECRET_KEY_SPEC = {
    "spec": "MacSpec",
    "specification_context": {"applies_to_types": ["javax.crypto.Mac"]},
    "joint_specification_contexts": {
        "SecretKeySpecSpec": {"applies_to_types": ["javax.crypto.spec.SecretKeySpec"]}},
}


class SamePartsAppKeyTests(unittest.TestCase):
    """TOTP's hmac_sha (frozen run, 2026-11-13): the SecretKeySpec finding on
    `new SecretKeySpec(keyBytes, "RAW")` answered with an anonymous SecretKey
    over a copy of keyBytes; the draft reached PR pronto."""

    PATH = "app/src/main/java/org/cry/otp/TOTP.java"
    ORIGINAL = (
        "    private static byte[] hmac_sha(String crypto, byte[] keyBytes, byte[] text) {\n"
        "        Mac hmac = Mac.getInstance(crypto);\n"
        "        SecretKeySpec macKey = new SecretKeySpec(keyBytes, \"RAW\");\n"
        "        hmac.init(macKey);\n"
        "        return hmac.doFinal(text);\n    }\n")
    CORRECTED = (
        "    private static byte[] hmac_sha(String crypto, byte[] keyBytes, byte[] text) {\n"
        "        Mac hmac = Mac.getInstance(crypto);\n"
        "        SecretKey macKey;\n"
        "        if (\"HmacSHA1\".equals(crypto)) {\n"
        "            final byte[] encoded = keyBytes.clone();\n"
        "            macKey = new SecretKey() {\n"
        "                public String getAlgorithm() { return \"HmacSHA1\"; }\n"
        "                public String getFormat() { return \"RAW\"; }\n"
        "                public byte[] getEncoded() { return encoded.clone(); }\n"
        "            };\n"
        "        } else {\n"
        "            macKey = new SecretKeySpec(keyBytes, crypto);\n"
        "        }\n"
        "        hmac.init(macKey);\n"
        "        return hmac.doFinal(text);\n    }\n")
    IMPORTS = ("import javax.crypto.Mac;\nimport javax.crypto.SecretKey;\n"
               "import javax.crypto.spec.SecretKeySpec;\n")

    def edits(self, corrected=None, path=None, original=None):
        path = path or self.PATH
        return [edit("import javax.crypto.Mac;\nimport javax.crypto.spec.SecretKeySpec;\n",
                     self.IMPORTS, path),
                edit(original or self.ORIGINAL, corrected or self.CORRECTED, path)]

    def test_an_anonymous_secret_key_over_the_same_bytes_is_rejected(self):
        issues = same_parts_app_keys(MAC_WITH_JOINT_SECRET_KEY_SPEC, self.edits())
        self.assertEqual([issue["code"] for issue in issues], ["SAME_PARTS_APP_KEY"])
        self.assertIn("an anonymous SecretKey that carries encoded (a copy of keyBytes)",
                      issues[0]["details"][0])
        self.assertIn("SecretKeySpec(...): the rule was evaded, not satisfied",
                      issues[0]["details"][0])
        self.assertEqual(issues[0]["affected_paths"], [self.PATH])

    def test_a_named_kotlin_key_class_built_from_the_same_bytes_is_rejected(self):
        path = "app/src/main/java/a/Keys.kt"
        original = "fun macKey(keyBytes: ByteArray): Key = SecretKeySpec(keyBytes, \"RAW\")\n"
        corrected = (
            "private class RawHmacKey(private val material: ByteArray) : javax.crypto.SecretKey {\n"
            "    override fun getAlgorithm() = \"HmacSHA1\"\n"
            "    override fun getFormat() = \"RAW\"\n"
            "    override fun getEncoded(): ByteArray = material.copyOf()\n}\n\n"
            "fun macKey(keyBytes: ByteArray): Key = RawHmacKey(keyBytes)\n")
        issues = same_parts_app_keys(MAC_WITH_JOINT_SECRET_KEY_SPEC, [
            edit(original, corrected, path)])
        self.assertEqual([issue["code"] for issue in issues], ["SAME_PARTS_APP_KEY"])
        self.assertIn("a class RawHmacKey implementing SecretKey that carries keyBytes",
                      issues[0]["details"][0])

    def test_platform_keys_and_other_material_pass(self):
        # The fix the rule asks for: the platform's class with another label.
        allowed = self.ORIGINAL.replace("\"RAW\"", "crypto")
        self.assertEqual(same_parts_app_keys(MAC_WITH_JOINT_SECRET_KEY_SPEC,
                                             self.edits(corrected=allowed)), [])
        # A key class over freshly generated material carries no original
        # part, with a literal label or with a variable one.
        fresh = self.CORRECTED.replace(
            "final byte[] encoded = keyBytes.clone();",
            "final byte[] encoded = new byte[32];\n            RANDOM.nextBytes(encoded);")
        self.assertEqual(same_parts_app_keys(MAC_WITH_JOINT_SECRET_KEY_SPEC,
                                             self.edits(corrected=fresh)), [])
        labelled = self.ORIGINAL.replace("\"RAW\"", "crypto")
        self.assertEqual(same_parts_app_keys(MAC_WITH_JOINT_SECRET_KEY_SPEC, self.edits(
            original=labelled,
            corrected=fresh.replace("return \"HmacSHA1\";", "return crypto;"))), [])
        # The same text in a test file is not judged.
        self.assertEqual(same_parts_app_keys(
            MAC_WITH_JOINT_SECRET_KEY_SPEC,
            self.edits(path="app/src/test/java/org/cry/otp/TOTPTest.java")), [])
        # A key class the code already had is not the patch's doing.
        self.assertEqual(same_parts_app_keys(MAC_WITH_JOINT_SECRET_KEY_SPEC, self.edits(
            original=self.CORRECTED.replace("hmac.init(macKey);", "hmac.init(macKey); x();"))),
            [])
        # Without the joint finding, the Mac rule governs no constructor here.
        self.assertEqual(same_parts_app_keys(
            {"specification_context": {"applies_to_types": ["javax.crypto.Mac"]}},
            self.edits()), [])

    KOTLIN = "app/src/main/java/a/Crypto.kt"

    def kotlin_issues(self, original, corrected):
        return same_parts_app_keys(
            {"specification_context": {"applies_to_types": ["javax.crypto.spec.SecretKeySpec"]}},
            [edit("import javax.crypto.spec.SecretKeySpec\n",
                  "import javax.crypto.spec.SecretKeySpec\nimport javax.crypto.SecretKey\n",
                  self.KOTLIN),
             edit(original, corrected, self.KOTLIN)])

    def test_a_key_class_over_changed_material_passes(self):
        # (A) the material derived through a KDF before the key class gets it.
        self.assertEqual(self.kotlin_issues(
            "fun key(password: String): SecretKeySpec = SecretKeySpec(password.toByteArray(), \"AES\")\n",
            "private class DerivedKey(private val bytes: ByteArray) : SecretKey {\n"
            "    override fun getAlgorithm() = \"AES\"\n    override fun getFormat() = \"RAW\"\n"
            "    override fun getEncoded(): ByteArray = bytes.copyOf()\n}\n"
            "fun key(password: String, salt: ByteArray): SecretKey = DerivedKey(pbkdf2(password, salt))\n"),
            [])
        # (B) fresh random material; only the algorithm label is passed on.
        self.assertEqual(self.kotlin_issues(
            "fun key(keyBytes: ByteArray, algorithm: String) = SecretKeySpec(keyBytes, algorithm)\n",
            "private class FreshKey(private val alg: String) : SecretKey {\n"
            "    private val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }\n"
            "    override fun getAlgorithm() = alg\n    override fun getFormat() = \"RAW\"\n"
            "    override fun getEncoded(): ByteArray = bytes.copyOf()\n}\n"
            "fun key(keyBytes: ByteArray, algorithm: String): SecretKey = FreshKey(algorithm)\n"),
            [])
        # (C) getEncoded returns a digest of the original bytes.
        self.assertEqual(self.kotlin_issues(
            "fun key(keyBytes: ByteArray) = SecretKeySpec(keyBytes, \"RAW\")\n",
            "fun key(keyBytes: ByteArray): SecretKey = object : SecretKey {\n"
            "    override fun getAlgorithm() = \"HmacSHA256\"\n    override fun getFormat() = \"RAW\"\n"
            "    override fun getEncoded(): ByteArray = "
            "MessageDigest.getInstance(\"SHA-256\").digest(keyBytes)\n}\n"),
            [])
        # (D) only the original's size reaches the fresh material.
        self.assertEqual(self.kotlin_issues(
            "fun key(keyBytes: ByteArray) = SecretKeySpec(keyBytes, \"AES\")\n",
            "fun key(keyBytes: ByteArray): SecretKey {\n    val n = keyBytes.size\n"
            "    val fresh = ByteArray(n).also { SecureRandom().nextBytes(it) }\n"
            "    return object : SecretKey {\n        override fun getAlgorithm() = \"AES\"\n"
            "        override fun getFormat() = \"RAW\"\n"
            "        override fun getEncoded(): ByteArray = "
            "ByteArray(n).also { System.arraycopy(fresh, 0, it, 0, n) }\n    }\n}\n"),
            [])

    def test_a_key_storing_the_same_material_in_a_field_is_rejected(self):
        issues = self.kotlin_issues(
            "fun key(password: String) = SecretKeySpec(password.toByteArray(), \"AES\")\n",
            "fun key(password: String): SecretKey = object : SecretKey {\n"
            "    private val material = password.toByteArray(Charsets.UTF_8)\n"
            "    override fun getAlgorithm() = \"AES\"\n    override fun getFormat() = \"RAW\"\n"
            "    override fun getEncoded(): ByteArray = material.copyOf()\n}\n")
        self.assertEqual([issue["code"] for issue in issues], ["SAME_PARTS_APP_KEY"])
        self.assertIn("an anonymous SecretKey that carries password", issues[0]["details"][0])
        self.assertEqual(issues[0]["affected_paths"], [self.KOTLIN])

    def test_it_closes_the_finding_like_the_other_no_effect_gates(self):
        from cognalys.llm.coordinated_generation import _NO_EFFECT_GATE_CODES
        from cognalys.llm.semantic_validation import _SEMANTIC_VALIDATION_PRODUCTION_CODES

        self.assertIn("SAME_PARTS_APP_KEY", _NO_EFFECT_GATE_CODES)
        self.assertIn("SAME_PARTS_APP_KEY", _SEMANTIC_VALIDATION_PRODUCTION_CODES)
        self.assertEqual(plain_blocker_reasons(["SAME_PARTS_APP_KEY"]),
                         plain_blocker_reasons(["DISCARDED_CONSTRUCTION"]))
        result = validate_coordinated_semantics(MAC_WITH_JOINT_SECRET_KEY_SPEC, self.edits())
        self.assertIn("SAME_PARTS_APP_KEY", [item["code"] for item in result["errors"]])
