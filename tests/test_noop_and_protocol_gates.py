import unittest


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.contract_gates import (  # noqa: E402
    kept_constant_key_material,
    protocol_algorithm_changes,
)

MTG_PATH = "mobile/src/main/java/com/gelakinetic/mtgfam/helpers/tcgp/MarketPriceFetcher.java"
MTG_ORIGINAL = ('SecretKey sk = new SecretKeySpec(context.getString(R.string.key_lastLegalityUpdate)'
                '.substring(0, 16).getBytes(StandardCharsets.UTF_8), "AES");')


def edit(path, original, corrected, kind="method"):
    return {"source_file_path": path, "original_code": original, "corrected_code": corrected,
            "edit_kind": kind}


class KeptConstantKeyMaterialTests(unittest.TestCase):
    def test_moving_the_constant_into_a_helper_fixes_nothing(self):
        """MTG Familiar's fetch, 2026-10-12."""
        edits = [
            edit(MTG_PATH, MTG_ORIGINAL,
                 "SecretKey lifecycleKey = provisionTcgpAccessTokenKey();\n"
                 "SecretKey sk = new SecretKeySpec(lifecycleKey.getEncoded(), \"AES\");"),
            edit(MTG_PATH, "",
                 "private SecretKey provisionTcgpAccessTokenKey() {\n"
                 "    byte[] raw = mActivity.getString(R.string.key_lastLegalityUpdate)\n"
                 "            .substring(0, 16).getBytes(StandardCharsets.UTF_8);\n"
                 "    return new SecretKeySpec(raw, \"AES\");\n}"),
        ]
        [issue] = kept_constant_key_material({}, edits)
        self.assertEqual(issue["code"], "CONSTANT_KEY_MATERIAL_KEPT")
        self.assertIn("R.string.key_lastLegalityUpdate", issue["details"][0])
        self.assertEqual(issue["path"], MTG_PATH)

    def test_a_keystore_key_with_the_constant_kept_for_old_data_is_a_fix(self):
        corrected = ("SecretKey sk = keyStoreKey(\"tcgp\");\n"
                     "SecretKey legacy = new SecretKeySpec(context.getString("
                     "R.string.key_lastLegalityUpdate).substring(0, 16).getBytes(), \"AES\");\n"
                     "KeyStore store = KeyStore.getInstance(\"AndroidKeyStore\");")
        self.assertEqual(kept_constant_key_material({}, [edit(MTG_PATH, MTG_ORIGINAL, corrected)]), [])

    def test_replacing_a_constant_iv_with_a_random_one_is_a_fix(self):
        original = 'IvParameterSpec iv = new IvParameterSpec(FIXED_IV);'
        corrected = 'byte[] ivBytes = new byte[16];\nrandom.nextBytes(ivBytes);\n' \
                    'IvParameterSpec iv = new IvParameterSpec(ivBytes);'
        self.assertEqual(kept_constant_key_material({}, [edit("A.java", original, corrected)]), [])

    def test_a_hash_of_the_constant_is_still_the_constant(self):
        original = 'val spec = SecretKeySpec(BuildConfig.API_SECRET.toByteArray(), "AES")'
        corrected = ('val bytes = MessageDigest.getInstance("SHA-256").digest('
                     'BuildConfig.API_SECRET.toByteArray())\nval spec = SecretKeySpec(bytes, "AES")')
        [issue] = kept_constant_key_material({}, [edit("A.kt", original, corrected)])
        self.assertIn("BuildConfig.API_SECRET", issue["details"][0])

    def test_algorithm_names_and_charsets_are_not_key_sources(self):
        original = 'new SecretKeySpec(password.getBytes(StandardCharsets.UTF_8), "AES")'
        corrected = 'new SecretKeySpec(derive(password).getEncoded(), "AES")'
        self.assertEqual(kept_constant_key_material({}, [edit("A.java", original, corrected)]), [])

    def test_a_gcm_tag_length_is_not_key_material(self):
        """Tokn (2026-10-28): GCM_TAG_LENGTH beside the IV was read as the key."""
        original = ("val cipher = Cipher.getInstance(TRANSFORMATION)\n"
                    "cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), "
                    "GCMParameterSpec(GCM_TAG_LENGTH, iv))")
        corrected = original.replace("getOrCreateKey()", "key")
        self.assertEqual(kept_constant_key_material({}, [edit("A.kt", original, corrected)]), [])
        fixed_iv = "cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, FIXED_NONCE))"
        [issue] = kept_constant_key_material({}, [edit("A.kt", fixed_iv, fixed_iv + "\n")])
        self.assertIn("FIXED_NONCE", issue["details"][0])

    def test_tests_are_not_production(self):
        original = 'new SecretKeySpec(KEY_BYTES, "AES")'
        edits = [edit("app/src/main/java/A.java", original, "new SecretKeySpec(loadKey(), \"AES\")"),
                 edit("app/src/test/java/ATest.java", "", "new SecretKeySpec(KEY_BYTES, \"AES\")",
                      kind="test")]
        self.assertEqual(kept_constant_key_material({}, edits), [])


MOTP_ORIGINAL = """class mOTP {
    public static String gen(String PIN, String seed, String zone) {
        String secret = new MD5(seed).asHex().substring(0, 16);
        MD5 hash = new MD5(epoch + secret + PIN);
        return hash.asHex().substring(0, 6);
    }
}"""


class ProtocolAlgorithmTests(unittest.TestCase):
    def test_mOTP_keeps_MD5(self):
        """org.cry.otp, 2026-10-12: MD5 became SHA-256 and no code matched the server's."""
        corrected = MOTP_ORIGINAL.replace("MD5", "SHA256")
        md5 = edit("app/src/main/java/org/cry/otp/MD5.java",
                   'MessageDigest md = MessageDigest.getInstance("MD5");',
                   'MessageDigest md = MessageDigest.getInstance("SHA-256");', kind="declaration")
        [issue] = protocol_algorithm_changes(
            {"method_name": "<init>"},
            [md5, edit("app/src/main/java/org/cry/otp/mOTP.java", MOTP_ORIGINAL, corrected)])
        self.assertEqual(issue["code"], "PROTOCOL_MANDATED_ALGORITHM")
        self.assertIn("mOTP", issue["details"][0])
        self.assertIn("MD5", issue["details"][0])

    def test_TOTP_keeps_HmacSHA1(self):
        original = 'Mac mac = Mac.getInstance("HmacSHA1"); // RFC 6238 TOTP'
        corrected = 'Mac mac = Mac.getInstance("HmacSHA256"); // RFC 6238 TOTP'
        [issue] = protocol_algorithm_changes({"class_name": "org.cry.otp.TOTP"},
                                             [edit("TOTP.java", original, corrected)])
        self.assertIn("HmacSHA1", issue["details"][0])

    def test_a_fingerprint_keeps_its_algorithm(self):
        """FairEmail's getFingerprint, 2026-10-12."""
        [issue] = protocol_algorithm_changes(
            {"method_name": "getFingerprint"},
            [edit("Helper.java", 'return getFingerprint(context, "SHA1");',
                  'return getFingerprint(context, "SHA-256");')])
        self.assertIn("fingerprint", issue["details"][0])

    def test_a_legacy_path_next_to_the_new_algorithm_is_not_flagged(self):
        original = 'Mac.getInstance("HmacSHA1") // TOTP'
        corrected = 'Mac.getInstance(token.legacy ? "HmacSHA1" : "HmacSHA256") // TOTP'
        self.assertEqual(protocol_algorithm_changes({}, [edit("Totp.kt", original, corrected)]), [])

    def test_md5_outside_any_protocol_is_left_to_the_other_checks(self):
        original = 'MessageDigest.getInstance("MD5").digest(password)'
        corrected = 'MessageDigest.getInstance("SHA-256").digest(password)'
        self.assertEqual(protocol_algorithm_changes({"method_name": "hashPassword"},
                                                    [edit("Login.java", original, corrected)]), [])

    def test_a_biometric_fingerprint_is_not_a_certificate_fingerprint(self):
        original = 'FingerprintManager fm; MessageDigest.getInstance("SHA-1")'
        corrected = 'FingerprintManager fm; MessageDigest.getInstance("SHA-256")'
        self.assertEqual(protocol_algorithm_changes({}, [edit("Unlock.java", original, corrected)]), [])

    def test_a_protocol_that_fixes_another_algorithm_does_not_block(self):
        # Gravatar fixes MD5; replacing a SHA-1 next to it is not this gate's concern.
        original = 'gravatarUrl(md5(email)); MessageDigest.getInstance("SHA-1").digest(token)'
        corrected = 'gravatarUrl(md5(email)); MessageDigest.getInstance("SHA-256").digest(token)'
        self.assertEqual(protocol_algorithm_changes({}, [edit("Avatar.java", original, corrected)]), [])


FREAD_PATH = "framework/src/androidMain/kotlin/com/zhangke/framework/network/GlobalOkHttpClient.kt"
FREAD_ORIGINAL = ('val sslContext = SSLContext.getInstance("SSL")\n'
                  'sslContext.init(null, arrayOf(trustManager), SecureRandom())\n'
                  'sslContext.defaultSSLParameters.protocols = arrayOf("SSLv3")\n'
                  'return sslContext.socketFactory')
FREAD_SELECTOR_ONLY = ('val sslContext = SSLContext.getInstance("TLS")\n'
                       'sslContext.init(null, arrayOf(trustManager), SecureRandom())\n'
                       'return sslContext.socketFactory')
FOUND_SSL = {"spec": "SSLContextSpec",
             "error_message": "expecting one of TLSV1.2,TLSV1.3,TLS but found SSL",
             "unique_error_id": "c:::buildSSLFactory:::SSLContextSpec:::UnsafeProtocol:::x"}


def prompt_text(source):
    """A module's source with adjacent string literals joined, as the prompt reads."""
    import re

    return re.sub(r'"\s+"', "", source).replace('\\"', '"')


def filtering_policy(library="OkHttp", sites=()):
    """The "found SSL" policy with the filter variant on, as the evidence for
    a client that can still negotiate deprecated protocols selects it."""
    from unittest import mock
    from cognalys.llm import migration_policy

    evidence = {"deprecated_protocols_reachable": True,
                "client_excludes_deprecated_protocols": False,
                "http_client": {"library": library, "version": "3.12.0"}}
    if sites:
        evidence["protocol_configuration_sites"] = list(sites)
    with mock.patch.object(migration_policy, "_EVIDENCE", {"tls_trust": (
            lambda error: evidence, "established_tls_trust_evidence")}):
        return migration_policy.generic_migration_policy(FOUND_SSL)


class LegacyProtocolFilterGateTests(unittest.TestCase):
    """A missing socket filter is a consideration unless a deprecated protocol
    is still turned on (2026-10-29 review, P2)."""

    def validate(self, policy, edits):
        from cognalys.llm.semantic_validation import validate_coordinated_semantics

        return validate_coordinated_semantics({"case_migration_policy": policy}, edits)

    def test_a_selector_only_patch_on_okhttp_is_valid_with_a_consideration(self):
        policy = filtering_policy()
        self.assertTrue(policy["filters_deprecated_protocols"])
        result = self.validate(policy, [edit(FREAD_PATH, FREAD_ORIGINAL, FREAD_SELECTOR_ONLY)])
        self.assertEqual(result["status"], "valid", result["errors"])
        [warning] = [item for item in result["warnings"]
                     if item["code"] == "TLS_LEGACY_PROTOCOL_FILTER_MISSING"]
        self.assertIn("separate hardening", warning["publication_consideration"])

    def test_a_patch_that_keeps_compatible_tls_still_errors(self):
        original = FREAD_ORIGINAL + "\nval specs = listOf(ConnectionSpec.COMPATIBLE_TLS)"
        corrected = FREAD_SELECTOR_ONLY + "\nval specs = listOf(ConnectionSpec.COMPATIBLE_TLS)"
        result = self.validate(filtering_policy(), [edit(FREAD_PATH, original, corrected)])
        [issue] = [item for item in result["errors"]
                   if item["code"] == "TLS_LEGACY_PROTOCOL_FILTER_MISSING"]
        self.assertTrue(any("COMPATIBLE_TLS" in detail for detail in issue["details"]))

    def test_a_configuration_site_the_patch_leaves_alone_still_errors(self):
        result = self.validate(filtering_policy(sites=["app/src/main/java/c/Specs.kt"]),
                               [edit(FREAD_PATH, FREAD_ORIGINAL, FREAD_SELECTOR_ONLY)])
        self.assertIn("TLS_LEGACY_PROTOCOL_FILTER_MISSING",
                      {item["code"] for item in result["errors"]})

    def test_a_platform_socket_still_enabling_tlsv1_errors(self):
        original = 'socket.enabledProtocols = arrayOf("TLSv1", "TLSv1.2")\n' + FREAD_ORIGINAL
        corrected = 'socket.enabledProtocols = arrayOf("TLSv1", "TLSv1.2")\n' + FREAD_SELECTOR_ONLY
        result = self.validate(filtering_policy("platform socket"),
                               [edit(FREAD_PATH, original, corrected)])
        self.assertIn("TLS_LEGACY_PROTOCOL_FILTER_MISSING",
                      {item["code"] for item in result["errors"]})

    def test_the_review_does_not_set_a_maintainer_fact_aside_for_a_plan_premise(self):
        """Fread's review overrode openHAB's "OkHttp already rejects TLS 1.1"."""
        import inspect
        from cognalys.llm import coordinated_generation

        source = prompt_text(inspect.getsource(coordinated_generation))
        self.assertIn("is an assumption of the plan, not a maintainer fact", source)
        self.assertIn("do not set the response aside by deferring to the plan", source)
        self.assertGreaterEqual(coordinated_generation.REVIEW_CONTRACT_VERSION, 4)

    def test_the_adjudication_takes_analyzer_acceptance_from_the_reporter(self):
        import inspect
        from cognalys.llm import finding_adjudication

        source = prompt_text(inspect.getsource(finding_adjudication))
        self.assertIn("Only when the reporting detector's message gives no such list, say in "
                      "review_assumptions that the specification's exact-version predicate", source)
        self.assertIn("the category analyzer_reconfirmation", source)

    def test_the_removal_fact_is_never_claimed_without_a_filter_in_the_diff(self):
        from cognalys.extraction import tls_client_evidence
        from cognalys.llm.migration_policy import facts_supported_by_diff

        facts = tls_client_evidence.protocol_facts({"http_client": {"library": "platform socket"}})
        policy = {"maintainer_facts": list(facts.values())}
        self.assertEqual(facts_supported_by_diff(
            policy, [edit(FREAD_PATH, FREAD_ORIGINAL, FREAD_SELECTOR_ONLY)]), [])
        self.assertFalse(tls_client_evidence.diff_removes_deprecated_protocols(
            [edit(FREAD_PATH, FREAD_ORIGINAL, FREAD_SELECTOR_ONLY)]))


# Fread's generated test (tls_20261015, call 0009): every JSSE name and a
# future one, and the empty result.
FREAD_FILTER = ('override fun createSocket(): Socket = filter(delegate.createSocket())\n'
                'private fun filter(socket: Socket): Socket {\n'
                '    (socket as? SSLSocket)?.let { ssl ->\n'
                '        val kept = ssl.enabledProtocols.filterNot { it in LEGACY }\n'
                '        if (kept.isEmpty()) throw SSLException("no protocol left")\n'
                '        ssl.enabledProtocols = kept.toTypedArray()\n'
                '    }\n    return socket\n}')
FREAD_TEST = ('val enabled = arrayOf("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3", "TLSv1.4")\n'
              'assertArrayEquals(arrayOf("TLSv1.2", "TLSv1.3", "TLSv1.4"), filtered(enabled))\n'
              'assertFailsWith<SSLException> { filtered(arrayOf("SSLv3", "TLSv1")) }')


class ProtocolFilterTestContractTests(unittest.TestCase):
    """JSSE names, and only for a patch that adds a filter (P10)."""

    def warnings(self, edits):
        from cognalys.llm.semantic_validation import validate_coordinated_semantics

        result = validate_coordinated_semantics(
            {"case_migration_policy": filtering_policy("platform socket")}, edits)
        return [item for item in result["warnings"]
                if item["code"] == "TLS_PROTOCOL_FILTER_CONTRACT_NOT_TESTED"]

    def filter_edits(self, test):
        return [edit(FREAD_PATH, FREAD_ORIGINAL, FREAD_SELECTOR_ONLY),
                edit("framework/src/androidMain/kotlin/c/ProtocolFilteringSocketFactory.kt", "",
                     FREAD_FILTER, kind="create"),
                edit("framework/src/androidUnitTest/kotlin/c/FilterTest.kt", "", test, kind="test")]

    def test_the_complete_fread_test_gives_no_warning(self):
        self.assertEqual(self.warnings(self.filter_edits(FREAD_TEST)), [])

    def test_a_test_without_sslv3_names_it(self):
        test = FREAD_TEST.replace('"SSLv3", ', "")
        [warning] = self.warnings(self.filter_edits(test))
        self.assertEqual(warning["details"], ["SSLv3"])

    def test_tlsv1_0_spelling_satisfies_the_tlsv1_requirement(self):
        test = FREAD_TEST.replace('"TLSv1", "TLSv1.1"', '"TLSv1.0", "TLSv1.1"')
        test = test.replace('arrayOf("SSLv3", "TLSv1")', 'arrayOf("SSLv3", "TLSv1.0")')
        self.assertEqual(self.warnings(self.filter_edits(test)), [])

    def test_a_selector_only_patch_has_no_contract_to_test(self):
        self.assertEqual(self.warnings([edit(FREAD_PATH, FREAD_ORIGINAL, FREAD_SELECTOR_ONLY)]), [])


CLEAN_REVIEW = {"regressions": [], "maintainer_decision_required": False,
                "maintainer_decision": "", "rationale": ""}


class ReviewContractFourPromptTests(unittest.TestCase):
    """AntennaPod's six reviews named a regression "on a platform where" the documented
    defaults differ, naming none; Salty's review never saw where its ciphertext went
    or that " v1:..." no longer decoded (2026-10-29)."""

    def review_run(self):
        from test_applied_edits_match_text import METHOD_EDIT, _coordinated_run
        return _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])

    def test_an_undocumented_platform_divergence_is_no_regression(self):
        _, provider, _, _ = self.review_run()
        self.assertIn("A scenario that holds only if the platform or provider behaves "
                      "differently from its documentation or source is not a regression "
                      "unless the evidence names such a platform; say what evidence "
                      "establishes the difference.", provider.review_system)

    def test_a_change_a_parameter_policy_requires_is_no_regression(self):
        # Your Local Weather run_v4 (2026-11-02): drafts raising PBKDF2 to
        # 210,000 iterations for the 100000 policy were refused against the
        # plan invariant "65,536 iterations".
        _, provider, _, _ = self.review_run()
        system = " ".join(provider.review_system.split())
        self.assertIn("A change that an entry of parameter_policies requires", system)
        self.assertIn("is never a regression, even where a plan_invariant", system)
        self.assertIn('"parameter_policies"', provider.review_prompt)

    def test_a_new_read_path_accepts_what_the_old_one_did(self):
        _, provider, _, _ = self.review_run()
        self.assertIn("A new read path must accept every input the old read path accepted "
                      "(surrounding whitespace, padding, line breaks) when the value comes "
                      "from user input or an export sink", provider.review_system)
        self.assertIn("value_exports, when present", provider.review_system)
        self.assertIn("dropped_inputs_removed_by_fix", provider.review_system)

    def test_a_test_of_a_changed_function_is_never_unrelated(self):
        # NotallyX's md5Hash (2026-10-29): a test calling the renamed digest
        # helpers, asserting equal inputs match and different ones differ, was
        # dropped because the MD5 code passed it too.
        from cognalys.llm.llm_schemas import behavior_review_schema

        _, provider, _, _ = self.review_run()
        self.assertIn("A test that calls a function the patch changes or renames "
                      "directly, asserting a property the new code must keep",
                      " ".join(provider.review_system.split()))
        self.assertIn("is a regression test of that change even when the original code "
                      "passed it too; never list it.", provider.review_system)
        self.assertNotIn("asserts behaviour the production edits do not change",
                         provider.review_system)
        self.assertIn("calls no changed or renamed function directly", behavior_review_schema()
                      ["properties"]["unrelated_test_edits"]["items"]["description"])

    def test_a_test_reaching_the_change_only_through_callers_stays_unrelated(self):
        # Cryptomator's DoLicenseCheckTest (2026-10-24): it reaches the changed
        # getPublicKey only through DoLicenseCheck.execute, with the signing
        # algorithm mocked, and asserts the check still succeeds.
        _, provider, _, _ = self.review_run()
        prompt = " ".join(provider.review_system.split())
        self.assertIn("unrelated_test_edits each test file whose edit calls no function "
                      "the patch changes or renames and checks no value those edits "
                      "produce; a test that reaches the change only through callers or "
                      "mocks, asserting a result the change keeps, is unrelated.", prompt)
        self.assertNotIn("through a caller", prompt)

    def test_the_bumped_contract_is_recorded_in_behavior_review_json(self):
        from cognalys.llm.coordinated_generation import REVIEW_CONTRACT_VERSION

        # 8: AGrahn's same Ed25519 key through Bouncy Castle's lightweight
        # generator (run_v3, 2026-10-29).
        # 9: key_provider_constraints, Cryptomator Lite's keystore key refusing
        # the SecureRandom IV a draft gave BaseCipher (run_v6, 2026-10-30).
        # 10: finding.detector, Beta's helper inlined and statement split,
        # approved as "analyzer-facing" by a review that assumed a static
        # analyzer reported RVSec's finding (run_v2, 2026-10-30).
        # 11: BlueGate's KeyPair rebuilt from the parts of the one the code
        # already held, called a runtime-visible change (run_v4, 2026-10-30).
        # 12: BlueGate's KeyPair replaced by a KeyMaterial data class of the
        # same two keys, approved because the monitor no longer saw the
        # constructor (run_v7, 2026-10-31).
        # 13: effect judged per joint finding; BlueGate's generateNewKeyPair
        # share only moved ECGenParameterSpec into a local and was claimed
        # as resolved (run_v8, 2026-10-31).
        # 14: the reported finding judged like the joint findings; LocalSend's
        # patch changed only the joint KeyStoreSpec call and the pull request
        # was still KeyPairSpec's (run_v4, 2026-10-31).
        # 15: persisted_value_readers; a value written only under keys no code
        # reads is no regression (Your Local Weather run_v3, 2026-11-02).
        # 16: parameter_policies; a value raised as a policy requires is no
        # regression against a plan invariant (Your Local Weather run_v4).
        # 17: deliberate_insecurity; removing a behaviour kept on purpose with
        # no alternative is a regression (weeWX Weather, 2026-11-04).
        # 18: this repository's own answer for the same rule apart from other
        # projects' (InterTune#52, run_v2, 2026-11-08).
        # 19: plan_required_edits and each regression's source, plan or draft
        # (V1 restricted, 2026-11-09).
        # 20: "What the fix removes", function_contract and concern_verdicts;
        # a forbidden call kept only for earlier data is a change; a round
        # trip handing back the same material has no effect (Input Leaf,
        # RedReader, Session writeEntry; ESPEC_Q2Q3, 2026-11-11).
        # 21: a downgrade is a note; the new form the plan asks for is the
        # change (BitBanana#184, frozen run v2, 2026-11-13).
        # 22: the edits the target branch already holds are read as present
        # (NotallyX md5Hash, comparison arm C, 2026-11-13).
        # 23: a new persistent entry on every repeated operation, never removed
        # or reused, is a regression (KeyPass encrypt, comparison arm C,
        # 2026-11-13).
        self.assertEqual(REVIEW_CONTRACT_VERSION, 23)
        result, _, _, review_file = self.review_run()
        self.assertEqual(review_file["review_contract_version"], 23)
        self.assertEqual(result["behavior_review_summary"],
                         {"status": "reviewed", "review_contract_version": 23,
                          "regression_count": 0, "patch_has_no_effect": False})

    def test_a_new_persistent_entry_per_operation_is_a_regression(self):
        # KeyPass CryptoManager.encrypt (comparison arm C r2 and r4,
        # 2026-11-13): a fresh UUID key store alias on every encrypt and no
        # deleteEntry, reviewed with no regression. FreeOTP keeps one key per
        # token, keyed by the token: that is no unbounded growth.
        _, provider, _, _ = self.review_run()
        prompt = " ".join(provider.review_system.split())
        self.assertIn("A patch that makes the app create a new persistent entry -- a key "
                      "store alias, a file, a preference key, a database row -- each time "
                      "it performs an operation its own code repeats", prompt)
        self.assertIn("the store grows without bound through the app's normal use", prompt)
        self.assertIn("One entry per stored item -- named by that item's id or by a name "
                      "kept with the item, so that the item's own later writes reuse or "
                      "replace it --, a fixed name created once and reused, or an entry the "
                      "patch removes when its data goes, is not unbounded growth.", prompt)

    def test_each_regression_says_whether_the_plan_or_the_draft_causes_it(self):
        # V1 restricted (2026-11-09): 20 recorded units whose first plan
        # regressed reached a clean review by a redraft on that plan, mostly
        # fixing a slip the review had named; the plan is made again early
        # only when the plan itself causes the scenario.
        from cognalys.llm.llm_schemas import behavior_review_schema
        from test_applied_edits_match_text import METHOD_EDIT, _coordinated_run

        regression = behavior_review_schema()["properties"]["regressions"]["items"]
        self.assertEqual(regression["properties"]["source"]["enum"], ["draft", "plan"])
        self.assertIn("whenever you are unsure", regression["properties"]["source"]["description"])
        self.assertIn("source_reason", regression["required"])
        error_extra = {"evidence_analysis": {"confirmed_cause": "cause", "coordinated_fix_plan": {
            "required_edits": [{"source_file_path": "src/Main.java", "symbol": "method",
                                "reason": "drop TLSv1.1 from the enabled protocols",
                                "edit_category": "logic"}]}}}
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT],
                                             error_extra=error_extra)
        self.assertIn('"plan_required_edits"', provider.review_prompt)
        self.assertIn("drop TLSv1.1 from the enabled protocols", provider.review_prompt)
        self.assertNotIn("edit_category", provider.review_prompt.split(
            '"plan_required_edits"', 1)[1].split("]", 1)[0])
        system = " ".join(provider.review_system.split())
        self.assertIn("Give each regression its source: plan only when no draft that "
                      "follows the plan could avoid the scenario", system)
        self.assertIn("and whenever you are unsure", system)
        self.assertIn("it never makes a scenario more or less of a regression", system)

    def test_the_source_reaches_the_review_record_and_the_retry_failures(self):
        import json

        from cognalys.llm.generate_error_fixes import FixGenerator
        from test_applied_edits_match_text import METHOD_EDIT, _coordinated_run

        class Provider:
            def __init__(self, answer):
                self.answer = answer

            def generate(self, *args, **kwargs):
                return json.dumps(self.answer)

        scenario = {"source_file_path": "a", "scenario": "s", "before": "b", "after": "a"}
        generator = object.__new__(FixGenerator)
        generator.provider = Provider({**CLEAN_REVIEW, "regressions": [
            {**scenario, "source": "plan", "source_reason": "the plan removes TLSv1.1"},
            {**scenario, "source": "plan", "source_reason": ""},
            dict(scenario)]})
        review = generator.review_patch_behavior({}, [], {})
        self.assertEqual([item["source"] for item in review["regressions"]],
                         ["plan", "draft", "draft"])
        self.assertEqual(review["regressions"][0]["source_reason"], "the plan removes TLSv1.1")
        # The retry loop reads it from the attempt's failures; the redraft on
        # the same plan gets the scenario as before, without the label.
        result, provider, _, _ = _coordinated_run(
            lambda call: {**CLEAN_REVIEW, "regressions": [
                {**scenario, "source_file_path": "src/Main.java", "source": "plan",
                 "source_reason": "the plan removes TLSv1.1"}]} if call == 2 else CLEAN_REVIEW,
            [METHOD_EDIT])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(provider.calls.count("behavior_review"), 2)
        feedback = provider.draft_prompts[-1]
        self.assertIn('"code":"UNINTENDED_BEHAVIOR_CHANGE","message":"s: before, b; '
                      'after the patch, a","affected_paths":["src/Main.java"]}', feedback)
        self.assertNotIn("regression_source", feedback)
        self.assertNotIn("regression_in_new_test", feedback)

    def test_two_reviews_in_a_row_naming_the_plan_ask_for_the_replan_early(self):
        from unittest import mock

        from cognalys.llm.generate_error_fixes import FixGenerator
        from test_applied_edits_match_text import METHOD_EDIT, _coordinated_run

        for source, asked_after in (("plan", 2), ("draft", 3)):
            asked = []

            def replan(generator, error, failures, *args, **kwargs):
                asked.append((generator.provider.calls.count("behavior_review"),
                              [item.get("regression_source") for item in failures]))
                return False  # not taken: the plan's attempts left still run

            answer = {**CLEAN_REVIEW, "regressions": [{
                "source_file_path": "src/Main.java", "scenario": "s", "before": "b",
                "after": "a", "source": source, "source_reason": "the plan removes TLSv1.1"}]}
            with mock.patch.object(FixGenerator, "replan_after_regressions", replan), \
                    mock.patch.object(FixGenerator, "replan_after_draft_failures",
                                      lambda *args, **kwargs: False):
                result, provider, _, _ = _coordinated_run(lambda call: answer, [METHOD_EDIT])
            self.assertEqual(asked, [(asked_after, [source])], source)
            self.assertEqual(provider.calls.count("behavior_review"), 3)
            self.assertEqual(result["status"], "invalid")

    def test_the_governed_object_moved_into_an_app_owned_carrier_has_no_effect(self):
        # BlueGate run_v7 (2026-10-31): KeyPair(entry.certificate.publicKey,
        # entry.privateKey) returned as KeyMaterial(...) of a new data class and
        # threaded through four files; the review at 11 wrote that "the
        # reported KeyPair constructor event is removed", so not no-effect.
        from cognalys.llm.llm_schemas import behavior_review_schema

        _, provider, _, _ = self.review_run()
        system = " ".join(provider.review_system.split())
        self.assertIn("Replacing the governed object or value with a type of the app's own "
                      "-- a data class, record or class added for it, a Pair, Triple, Map, "
                      "list or array -- that carries the same parts from the same sources, "
                      "so that the governed API is simply no longer called, has no effect "
                      "either, although the checker then no longer observes the governed "
                      "call", system)
        self.assertIn("It is never a maintainer decision. Using an object the platform "
                      "already returns instead of rebuilding one (the "
                      "KeyStore.PrivateKeyEntry the store returned, read through its own "
                      "getters), or changing what the parts are or where they come from, "
                      "is a change.", system)
        # Review of 2026-10-31: a wrapper that validates the parts is judged
        # by that validation; the gate gives such a type no verdict either.
        self.assertIn("A type that also checks or transforms the parts is judged by what "
                      "that check or transformation changes for the app, not as a holder.",
                      system)
        # A changed value is still a change, after the carrier rule.
        self.assertGreater(system.index('A change of the value passed ("SSL" to "TLS") is '
                                        'not this'),
                           system.index("Replacing the governed object or value"))
        description = behavior_review_schema()["properties"]["patch_has_no_effect"][
            "description"]
        self.assertIn("replaced by a type of the app's own (a data class, record or class "
                      "added for it, a Pair, Triple, Map, list or array) carrying the same "
                      "parts from the same sources", description)
        self.assertIn("while an object the platform already returns used instead of a "
                      "rebuilt one, or other parts or sources, does", description)

    def test_the_generators_and_the_plan_are_told_a_carrier_corrects_nothing(self):
        # BlueGate run_v7 (2026-10-31): the plan named the KeyMaterial carrier
        # and every file draft built it.
        import inspect

        from cognalys.llm import coordinated_generation, finding_adjudication, prompt_builders
        from cognalys.llm.fix_generation_common import SAME_PARTS_CARRIER_GUIDANCE

        self.assertIn("Never replace the object or value the rule governs with a type of "
                      "the app's own", SAME_PARTS_CARRIER_GUIDANCE)
        self.assertIn("Using an object the platform already returns instead of rebuilding "
                      "one", SAME_PARTS_CARRIER_GUIDANCE)
        for module in (coordinated_generation, finding_adjudication, prompt_builders):
            with self.subTest(module=module.__name__):
                self.assertIn("SAME_PARTS_CARRIER_GUIDANCE", inspect.getsource(module))
        self.assertIn('"generator_contract_version": 19',
                      inspect.getsource(coordinated_generation))

    def test_an_object_rebuilt_from_its_own_parts_has_no_effect(self):
        # BlueGate run_v4 (2026-10-30): `keyPair = KeyPair(managed.public,
        # managed.private)` around the KeyPair the code already had, and the
        # generated KeyPair dropped for one rebuilt from the alias' entry, were
        # reviewed at 10 as a runtime-visible change and a
        # "verification_or_analyzer_concern".
        from cognalys.llm.llm_schemas import behavior_review_schema

        _, provider, _, _ = self.review_run()
        system = " ".join(provider.review_system.split())
        self.assertIn("A governed object constructed from the parts of one the code already "
                      "holds has no effect too: every part of that object, each in its own "
                      "place, read back through its own getters or properties "
                      "(KeyPair(kp.public, kp.private) around the KeyPair kp,", system)
        self.assertIn("the entry the original producer itself had just stored, re-read from "
                      "the same store under the same alias and repackaged after that "
                      "producer already returned it", system)
        self.assertIn("like a factory around the same object, and it is never a maintainer "
                      "decision. A construction that leaves out, moves or recomputes a "
                      "part, or takes different material -- a freshly generated key, a key "
                      "from another source or another entry, an entry the producer did not "
                      "store, different parameters -- is a change.", system)
        description = behavior_review_schema()["properties"]["patch_has_no_effect"][
            "description"]
        self.assertIn("constructed from the parts of one the code already holds", description)
        self.assertIn("the entry the original producer itself stored, re-read from the same "
                      "store and alias", description)
        self.assertIn("while one that leaves out, moves or recomputes a part or is built "
                      "from different material (a fresh generation, a key from another "
                      "source or entry, different parameters) does", description)

    def test_the_rebuilt_object_rule_does_not_open_as_a_change(self):
        # Batch 7 review (2026-10-30): the first wording followed "... is a
        # change." with "So is constructing a new governed object from the
        # parts ...", which read as the opposite of the rule it introduced.
        _, provider, _, _ = self.review_run()
        system = " ".join(provider.review_system.split())
        self.assertNotIn("is a change. So is constructing", system)
        self.assertIn("is a change. A governed object constructed from the parts of one the "
                      "code already holds has no effect too", system)

    def test_the_review_knows_a_runtime_monitor_reported_the_finding(self):
        # Beta run_v2 (2026-10-30): nothing told the review that RVSec runs
        # the app; it assumed "a source/static analyzer" and approved, as an
        # "analyzer-facing structural refactor", a patch that inlined
        # generateKeyPair and split generatePrivate(PKCS8EncodedKeySpec(x)).
        import json

        from test_applied_edits_match_text import METHOD_EDIT, _coordinated_run

        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT],
                                             error_extra={"tool": "rvsec"})
        payload = json.loads(provider.review_prompt.split(
            '<patch_and_source untrusted_data="true">\n', 1)[1].rsplit("\n</patch_and_source>", 1)[0])
        self.assertEqual(payload["finding"]["detector"],
                         {"tool": "rvsec", "kind": "runtime_monitor"})
        system = " ".join(provider.review_system.split())
        self.assertIn("finding.detector, when present, says a runtime monitor reported the "
                      "finding while the app ran: it observes each call, the object it is "
                      "made on and the values passed, never the source text.", system)
        self.assertIn("a helper inlined or extracted, an object's parts passed one by one "
                      "instead of the object, statements split or merged, locals renamed or "
                      "retyped -- cannot satisfy its rule: such a patch has no effect, and "
                      "'analyzer-facing', 'a refactor for the analyzer' or 'a flow the "
                      "analyzer can follow' is never a reason to accept it, nor a maintainer "
                      "decision.", system)
        # A finding a person or a static tool reported states no detector.
        # static:semgrep is an analyzer that never ran the app (intake's SARIF
        # and Semgrep rows); without it the cases above all fail
        # is_analyzer_tool, so a detector given to every analyzer would pass.
        for tool in ("static:manual", "", "web_research", "static:semgrep"):
            _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT],
                                                 error_extra={"tool": tool})
            self.assertNotIn('"detector"', provider.review_prompt)

    def test_the_schema_says_a_restructuring_the_monitor_sees_unchanged_has_no_effect(self):
        from cognalys.llm.llm_schemas import behavior_review_schema

        description = " ".join(behavior_review_schema()["properties"]["patch_has_no_effect"]
                               ["description"].split())
        self.assertIn("for a finding a runtime monitor reported, a restructuring it observes "
                      "as the same calls on the same objects with the same values -- a helper "
                      "inlined, statements split -- does not count, however "
                      "'analyzer-facing'", description)

    def test_a_fallback_to_the_original_value_or_an_alias_has_no_effect(self):
        # Trigger (run_v2, 2026-10-29): getInstance("EC") with an Ed25519
        # parameter an EC generator rejects, then getInstance("EdDSA"), the
        # provider's name for the generator the code already used.
        from cognalys.llm.llm_schemas import behavior_review_schema

        _, provider, _, _ = self.review_run()
        prompt = " ".join(provider.review_system.split())
        self.assertIn("So is a new governed call on a path guarded by a catch or fallback "
                      "that, for the reported input, reaches the original governed call "
                      "again -- the forbidden value itself, or another name of the same "
                      "algorithm, protocol or provider (a provider alias)", prompt)
        self.assertIn("unless the evidence shows the new path succeeding for that input on "
                      "the platforms the app targets (its minSdk)", prompt)
        self.assertIn("A fallback to another allowed value is not this.", prompt)
        self.assertIn("another name of the same algorithm, protocol or provider does not "
                      "count, unless the new path demonstrably succeeds",
                      behavior_review_schema()["properties"]["patch_has_no_effect"]
                      ["description"])

    def test_the_same_value_through_an_api_the_checker_does_not_observe_has_no_effect(self):
        # AGrahn (run_v3, 2026-10-29): ECGenParameterSpec("ed25519") on the JCA
        # generator replaced by Bouncy Castle's lightweight
        # Ed25519KeyPairGenerator, converted back to JCA keys.
        from cognalys.llm.llm_schemas import behavior_review_schema

        _, provider, _, _ = self.review_run()
        prompt = " ".join(provider.review_system.split())
        self.assertIn("So is producing the same value -- the same algorithm, curve, "
                      "protocol or key material -- through another library's or a "
                      "lower-level API that the checker does not observe, instead of the "
                      "governed call: a provider's lightweight API in place of its JCA "
                      "classes", prompt)
        self.assertIn("a native or JNI call, a hand-rolled implementation.", prompt)
        self.assertIn("A change to a different value the rule allows, reached through such "
                      "an API, is a change.", prompt)
        description = " ".join(behavior_review_schema()["properties"]["patch_has_no_effect"]
                               ["description"].split())
        self.assertIn("produced through another library's or a lower-level API the checker "
                      "does not observe", description)
        self.assertIn("while a different value the rule allows reached that way does",
                      description)

    def test_a_value_persisted_outside_preferences_reaches_the_review(self):
        # Syncthing-lite (2026-10-29): the device key is written to key.pem
        # and read back by the loader; a patch that stops reading it changes
        # the device identity.
        from test_applied_edits_match_text import METHOD_EDIT, _coordinated_run

        sink = {"path": "src/Keys.kt", "line": 3,
                "statement": "File(dir, FILENAME_KEY_PEM).writeText(pem)",
                "readers": [{"path": "src/Keys.kt", "line": 5, "names": "FILENAME_KEY_PEM",
                             "statement": "fun load(dir: File) = File(dir, FILENAME_KEY_PEM).readText()"}]}
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT], error_extra={
            "stored_value_contract": {"status": "not_modelled", "unmodelled_sinks": [sink]}})
        self.assertIn('"persisted_outside_preferences"', provider.review_prompt)
        self.assertIn("FILENAME_KEY_PEM).readText()", provider.review_prompt)
        self.assertIn("persisted_outside_preferences, when present", provider.review_system)
        _, provider, _, _ = self.review_run()
        self.assertNotIn('"persisted_outside_preferences"', provider.review_prompt)

    def test_the_plan_keeps_every_input_and_the_adjudication_reads_value_exports(self):
        import inspect

        from cognalys.llm.finding_adjudication import FindingAdjudication
        from cognalys.llm.fix_generation_common import DROPPED_INPUT_INVARIANT
        from test_applied_edits_match_text import _adjudication_system

        self.assertIn("still contributes to the new path, moved to another argument when "
                      "the rule forbids it in its slot, unless removing it is the fix itself; "
                      "never move a constant into a slot whose rule forbids constants",
                      DROPPED_INPUT_INVARIANT)
        self.assertIn("+ DROPPED_INPUT_INVARIANT", inspect.getsource(FindingAdjudication))
        system = _adjudication_system()
        self.assertIn("value_exports, when present", system)
        self.assertIn("finding.echo_of, when present", system)


class RuntimeMonitorGenerationTests(unittest.TestCase):
    """The generators know when a runtime monitor reported the finding.

    Beta run_v2 (2026-10-30): the coordinated draft of RVSec's KeyPairSpec and
    KeyFactorySpec findings wrote that they "are emitted by a source/static
    analyzer" while it inlined a helper and split a statement; only the
    behaviour review was told who reported the finding.
    """

    MONITOR = {"detector": {"tool": "rvsec", "kind": "runtime_monitor"}}
    RULE = ("A restructuring it would observe as the same calls on the same objects "
            "with the same values -- a helper inlined or extracted, an object's parts "
            "passed one by one instead of the object, statements split or merged, "
            "locals renamed or retyped -- cannot satisfy its rule")

    def test_one_helper_states_the_fact_for_a_runtime_monitor_only(self):
        from cognalys.llm.fix_generation_common import finding_detector

        self.assertEqual(finding_detector({"tool": "rvsec"}), self.MONITOR)
        self.assertEqual(finding_detector({"tool": " ape "}),
                         {"detector": {"tool": "ape", "kind": "runtime_monitor"}})
        for tool in ("static:manual", "static:semgrep", "", "web_research", None,
                     "codeql", "lint", "manual_static_review"):
            self.assertEqual(finding_detector({"tool": tool}), {})

    def test_every_coordinated_draft_carries_it_and_the_rule(self):
        import json

        from test_applied_edits_match_text import CLEAN_REVIEW, METHOD_EDIT, _coordinated_run

        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT],
                                             error_extra={"tool": "rvsec"})
        payload = json.loads(provider.draft_prompts[0].split("\n\n", 1)[1]
                             .split("\n\nREQUIRED JSON SCHEMA:", 1)[0])
        self.assertEqual(payload["detector"], self.MONITOR["detector"])
        self.assertIn(self.RULE, " ".join(provider.draft_system.split()))
        # The same fact the behaviour review reads, from the same helper.
        self.assertIn('"detector":{"tool":"rvsec","kind":"runtime_monitor"}',
                      provider.review_prompt.replace(" ", ""))
        for tool in ("static:manual", ""):
            _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT],
                                                 error_extra={"tool": tool})
            self.assertNotIn('"detector"', provider.draft_prompts[0])

class UnreviewedShapePromptTests(unittest.TestCase):
    """An unreviewed false-positive shape never supports not_confirmed.

    Aegis's SSLConnector.buildSocket was dismissed on SSLContextSpec's
    init(null, ...) shape, which no review had checked against the rule as
    written; the same construct in AntennaPod ended as a violation without
    security impact.
    """

    @classmethod
    def setUpClass(cls):
        from test_structured_outputs import _adjudication_system_prompt

        cls.system = " ".join(_adjudication_system_prompt().split())

    def test_a_literal_violation_of_an_unreviewed_shape_is_confirmed(self):
        start = self.system.index("reported_by_rule.unreviewed_false_positive_shapes")
        text = self.system[start:self.system.index("A shape matches only when", start)]
        self.assertIn("never support detector_violation not_confirmed", text)
        self.assertIn("literally violates the rule", text)
        self.assertIn("detector_violation confirmed and runtime_security_impact "
                      "non_security", text)
        self.assertIn("explicit-default or correct-use answer below", text)
        self.assertIn("Only a reviewed shape, in known_false_positive_shapes, "
                      "supports not_confirmed", text)
        # "below" must hold: the explicit-default and correct-use answers
        # for a null platform default come after this paragraph.
        self.assertLess(start, self.system.index(
            "This takes precedence over either list"))

    def test_the_known_shapes_are_the_reviewed_ones(self):
        start = self.system.index("reported_by_rule.known_false_positive_shapes")
        self.assertIn("kept by a review of each shape against the rule as written",
                      self.system[start:start + 300])


if __name__ == "__main__":
    unittest.main()
