import unittest


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.fix_generation_common import draft_quality_failure  # noqa: E402
from cognalys.llm.patch_effect_checks import (  # noqa: E402
    delegating_alias_calls,
    discarded_governed_reads,
    duplicated_adjacent_statements,
    empty_store_managers,
    equivalent_modulo_local_renames,
    rebuilt_from_own_encoding,
    required_parameter_spec_removed,
)
from cognalys.llm.semantic_validation import validate_coordinated_semantics  # noqa: E402

KSU = "app/src/main/java/io/github/muntashirakon/AppManager/crypto/ks/KeyStoreUtils.java"


def edit(path, original, corrected, kind="method", symbol="m"):
    return {"source_file_path": path, "original_code": original, "corrected_code": corrected,
            "edit_kind": kind, "symbol": symbol, "reason": "r"}


def spec_context(*patterns):
    return {"events": [{"api_patterns": list(patterns)}]}


RSA_ORIGINAL = """    public static KeyPair generateRSAKeyPair(String subject, int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize, SecureRandom.getInstance("SHA1PRNG"));
        java.security.KeyPair generateKeyPair = keyPairGenerator.generateKeyPair();
        return wrap(generateKeyPair.getPrivate(), generateKeyPair.getPublic());
    }"""


class DelegatingAliasTests(unittest.TestCase):
    """App Manager generateRSAKeyPair, 2026-11-01."""

    def test_an_alias_that_only_calls_the_method_changes_nothing(self):
        corrected = (RSA_ORIGINAL.replace("keyPairGenerator.generateKeyPair()", "keyPairGenerator.genKeyPair()")
                     .replace("generateKeyPair.", "keyPair.").replace("KeyPair generateKeyPair =", "KeyPair keyPair ="))
        [issue] = delegating_alias_calls({"method_name": "generateRSAKeyPair"},
                                         [edit(KSU, RSA_ORIGINAL, corrected)])
        self.assertEqual(issue["code"], "DELEGATING_ALIAS_CALL")
        self.assertIn("genKeyPair", issue["details"][0])

    def test_an_alias_with_a_real_change_is_not_flagged(self):
        corrected = (RSA_ORIGINAL.replace("generateKeyPair()", "genKeyPair()")
                     .replace('SecureRandom.getInstance("SHA1PRNG")', "new SecureRandom()"))
        self.assertEqual(delegating_alias_calls({"method_name": "generateRSAKeyPair"},
                                                [edit(KSU, RSA_ORIGINAL, corrected)]), [])

    def test_a_rule_only_value_change_is_not_an_alias(self):
        corrected = RSA_ORIGINAL.replace('"SHA1PRNG"', '"SHA256PRNG"')
        self.assertEqual(delegating_alias_calls({"method_name": "generateRSAKeyPair"},
                                                [edit(KSU, RSA_ORIGINAL, corrected)]), [])

    def test_renamed_locals_are_equivalent_but_renamed_calls_are_not(self):
        self.assertTrue(equivalent_modulo_local_renames("int a = f(b);", "int c = f(b);"))
        self.assertFalse(equivalent_modulo_local_renames("int a = f(b);", "int a = g(b);"))
        self.assertFalse(equivalent_modulo_local_renames('x("SSL")', 'x("TLS")'))


HMAC_ORIGINAL = """    public static byte[] calculateHmac(String token, byte[] data) throws IOException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(token.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKey);
        return mac.doFinal(data);
    }"""
HMAC_CORRECTED = """    static Key prepareHmacKey(String token) {
        return new SecretKeySpec(token.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    public static byte[] calculateHmac(String token, byte[] data) throws IOException {
        return calculateHmac(prepareHmacKey(token), data);
    }

    static byte[] calculateHmac(Key hmacKey, byte[] data) throws IOException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(hmacKey.getEncoded(), "HmacSHA256");
        mac.init(secretKey);
        return mac.doFinal(data);
    }"""


class RebuiltFromOwnEncodingTests(unittest.TestCase):
    """App Manager calculateHmac, 2026-11-01."""

    def test_a_key_rebuilt_from_its_own_bytes_is_the_same_key(self):
        [issue] = rebuilt_from_own_encoding({}, [edit("AuthUtils.java", HMAC_ORIGINAL, HMAC_CORRECTED)])
        self.assertEqual(issue["code"], "SAME_OBJECT_REBUILT")

    def test_a_local_rebuilt_from_itself_is_flagged(self):
        corrected = ('SecretKeySpec k = new SecretKeySpec(raw, "AES");\n'
                     'SecretKeySpec key = new SecretKeySpec(k.getEncoded(), "AES");')
        [issue] = rebuilt_from_own_encoding({}, [edit("A.java", 'x();', corrected)])
        self.assertEqual(issue["code"], "SAME_OBJECT_REBUILT")

    def test_a_generated_key_with_a_legacy_constant_kept_is_a_fix(self):
        corrected = ('SecretKey generated = keyGenerator.generateKey();\n'
                     'SecretKeySpec key = new SecretKeySpec(generated.getEncoded(), "AES");\n'
                     'SecretKeySpec legacy = new SecretKeySpec(LEGACY, "AES");')
        self.assertEqual(rebuilt_from_own_encoding({}, [edit("A.java", 'x();', corrected)]), [])


ADD_KEY_ORIGINAL = """    private Key getKey(String alias) throws Exception {
        char[] password = getAmKeyStorePassword();
        Key key = mAmKeyStore.getKey(alias, password);
        return key;
    }"""
ADD_KEY_CORRECTED = """    private Key getKey(String alias) throws Exception {
        char[] password = getAmKeyStorePassword();
        Key key;
        try {
            mAmKeyStore.getEntry(alias, new KeyStore.PasswordProtection(password));
            key = mAmKeyStore.getKey(alias, password);
        } catch (UnrecoverableEntryException e) {
            throw new UnrecoverableKeyException(e.getMessage());
        }
        return key;
    }"""


class DiscardedGovernedReadTests(unittest.TestCase):
    """App Manager addKeyPair, 2026-11-01."""

    error = {"specification_context": spec_context("KeyStore.getEntry(", ".setEntry(", ".load(")}

    def test_a_read_whose_entry_goes_nowhere_is_flagged(self):
        [issue] = discarded_governed_reads(self.error, [edit("K.java", ADD_KEY_ORIGINAL, ADD_KEY_CORRECTED)])
        self.assertEqual(issue["code"], "GOVERNED_CALL_RESULT_DISCARDED")
        self.assertIn("getEntry", issue["details"][0])

    def test_a_read_whose_value_is_used_is_not_flagged(self):
        corrected = ADD_KEY_ORIGINAL.replace(
            "Key key = mAmKeyStore.getKey(alias, password);",
            "Key key = ((KeyStore.PrivateKeyEntry) mAmKeyStore.getEntry(alias,\n"
            "        new KeyStore.PasswordProtection(password))).getPrivateKey();")
        self.assertEqual(discarded_governed_reads(self.error, [edit("K.java", ADD_KEY_ORIGINAL, corrected)]), [])

    def test_a_side_effect_call_is_not_a_read(self):
        corrected = ADD_KEY_ORIGINAL.replace("Key key", "mAmKeyStore.load(null);\n        Key key")
        self.assertEqual(discarded_governed_reads(self.error, [edit("K.java", ADD_KEY_ORIGINAL, corrected)]), [])

    def test_setkeyentry_to_setentry_stays_a_fix(self):
        original = "mAmKeyStore.setKeyEntry(alias, privateKey, password, chain);"
        corrected = ("mAmKeyStore.setEntry(alias, new KeyStore.PrivateKeyEntry(privateKey, chain),\n"
                     "        new KeyStore.PasswordProtection(password));")
        validation = validate_coordinated_semantics(self.error, [edit(KSU, original, corrected)])
        codes = {item["code"] for item in validation.get("errors", [])}
        self.assertFalse(codes & {"GOVERNED_CALL_RESULT_DISCARDED", "DELEGATING_ALIAS_CALL",
                                  "SAME_OBJECT_REBUILT", "DUPLICATED_ADJACENT_STATEMENT"})


DIGEST_ORIGINAL = """    private static void logEncoded(CharSequence name, byte[] bArr) {
        log(name + " - SHA-256: ", DigestUtils.getDigest(DigestUtils.SHA_256, bArr));
        log(name + " - SHA-1: ", DigestUtils.getDigest(DigestUtils.SHA_1, bArr));
        log(name + " - MD5: ", DigestUtils.getDigest(DigestUtils.MD5, bArr));
    }"""


class DuplicatedStatementTests(unittest.TestCase):
    """App Manager getDigest, 2026-11-01."""

    def test_a_line_turned_into_a_copy_of_its_neighbour_is_flagged(self):
        corrected = DIGEST_ORIGINAL.replace(
            'log(name + " - MD5: ", DigestUtils.getDigest(DigestUtils.MD5, bArr));',
            'log(name + " - SHA-256: ", DigestUtils.getDigest(DigestUtils.SHA_256, bArr));')
        [issue] = duplicated_adjacent_statements({}, [edit("Signer.java", DIGEST_ORIGINAL, corrected)])
        self.assertEqual(issue["code"], "DUPLICATED_ADJACENT_STATEMENT")
        self.assertTrue(draft_quality_failure([issue]))

    def test_removing_the_line_or_keeping_an_old_duplicate_passes(self):
        removed = "\n".join(line for line in DIGEST_ORIGINAL.splitlines() if "MD5" not in line)
        self.assertEqual(duplicated_adjacent_statements({}, [edit("S.java", DIGEST_ORIGINAL, removed)]), [])
        twice = "clearChars(password1);\nclearChars(password1);\n"
        self.assertEqual(duplicated_adjacent_statements(
            {}, [edit("S.java", twice + "a();", twice + "b();")]), [])

    def test_kotlin_expression_bodied_overloads_are_not_statements(self):
        corrected = ("    override fun createSocket(): java.net.Socket =\n"
                     "        filterProtocols(delegate.createSocket(host, port))\n"
                     "    @Throws(java.io.IOException::class)\n"
                     "    override fun createSocket(host: InetAddress, port: Int): java.net.Socket =\n"
                     "        filterProtocols(delegate.createSocket(host, port))\n")
        self.assertEqual(duplicated_adjacent_statements({}, [edit("F.kt", "x()", corrected)]), [])


DECRYPT_ORIGINAL = """    public static byte[] decryptData(Context context, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_GCM_CIPHER_TYPE);
        AlgorithmParameterSpec spec = new GCMParameterSpec(AES_GCM_KEY_SIZE_IN_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(data);
    }"""


class RequiredParameterSpecTests(unittest.TestCase):
    """App Manager decryptData, 2026-11-01."""

    def test_gcm_spec_replaced_by_an_iv_spec_is_flagged(self):
        corrected = DECRYPT_ORIGINAL.replace(
            "AlgorithmParameterSpec spec = new GCMParameterSpec(AES_GCM_KEY_SIZE_IN_BITS, iv);",
            "IvParameterSpec spec = new IvParameterSpec(iv);")
        [issue] = required_parameter_spec_removed({}, [edit("CompatUtil.java", DECRYPT_ORIGINAL, corrected)])
        self.assertEqual(issue["code"], "REQUIRED_PARAMETER_SPEC_REMOVED")
        self.assertFalse(draft_quality_failure([issue]))

    def test_moving_off_gcm_or_keeping_the_spec_passes(self):
        kept = DECRYPT_ORIGINAL.replace("spec);", "spec, random);")
        self.assertEqual(required_parameter_spec_removed({}, [edit("C.java", DECRYPT_ORIGINAL, kept)]), [])
        other = ('    Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");\n'
                 '    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));')
        self.assertEqual(required_parameter_spec_removed({}, [edit("C.java", DECRYPT_ORIGINAL, other)]), [])


class ReviewGapTests(unittest.TestCase):
    """Valid patches the first version of the checks held (2026-11-01 review)."""

    GCM = ('Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
           'c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, FIXED_IV));')

    def test_a_provider_generated_iv_or_a_spec_from_a_helper_keeps_gcm(self):
        provider = ('Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
                    'c.init(Cipher.ENCRYPT_MODE, key);\nbyte[] iv = c.getIV();')
        helper = ('Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
                  'c.init(Cipher.ENCRYPT_MODE, key, gcmSpec(iv));')
        for corrected in (provider, helper):
            self.assertEqual(required_parameter_spec_removed({}, [edit("A.java", self.GCM, corrected)]), [])

    def test_an_inline_iv_spec_for_gcm_is_still_flagged(self):
        corrected = ('Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
                     'c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));')
        [issue] = required_parameter_spec_removed({}, [edit("A.java", self.GCM, corrected)])
        self.assertEqual(issue["code"], "REQUIRED_PARAMETER_SPEC_REMOVED")
        passed = ('return decrypt(c, new IvParameterSpec(iv));\n}\n'
                  'static byte[] decrypt(Cipher c, IvParameterSpec ivSpec) {\n'
                  '    c.init(Cipher.DECRYPT_MODE, key, ivSpec);\n'
                  '    String t = AES_GCM_TYPE;')
        [issue] = required_parameter_spec_removed({}, [edit("A.java", self.GCM, passed)])
        self.assertEqual(issue["code"], "REQUIRED_PARAMETER_SPEC_REMOVED")

    def test_repeats_the_patch_adds_on_purpose_are_not_duplicates(self):
        separators = ("sb.append(hex(a));\nsb.append(SEPARATOR_X);\n"
                      "sb.append(hex(b));\nsb.append(SEPARATOR_X);")
        self.assertEqual(duplicated_adjacent_statements(
            {}, [edit("A.java", "sb.append(hex(a));\nsb.append(hex(b));", separators)]), [])
        salted = "md.update(salt);\nmd.update(input);\nmd.update(salt);"
        self.assertEqual(duplicated_adjacent_statements(
            {}, [edit("A.java", "md.update(input);", salted)]), [])

    def test_a_kotlin_block_value_is_not_a_discarded_read(self):
        error = {"specification_context": spec_context("KeyStore.getEntry(", ".getKey(")}
        corrected = "val key = run {\n    ks.getEntry(alias, null)\n}"
        self.assertEqual(discarded_governed_reads(
            error, [edit("a/src/main/kotlin/A.kt", "val key = ks.getKey(alias, pw)", corrected)]), [])
        branch = "val key = if (old) {\n    ks.getKey(alias, pw)\n} else {\n    ks.getEntry(alias, null)\n}"
        self.assertEqual(discarded_governed_reads(
            error, [edit("A.kt", "val key = ks.getKey(alias, pw)", branch)]), [])

    def test_a_kotlin_function_statement_is_still_a_discarded_read(self):
        error = {"specification_context": spec_context("KeyStore.getEntry(", ".getKey(")}
        corrected = "fun load() {\n    ks.getEntry(alias, null)\n}"
        [issue] = discarded_governed_reads(error, [edit("A.kt", "fun load() {\n}", corrected)])
        self.assertEqual(issue["code"], "GOVERNED_CALL_RESULT_DISCARDED")



HERMES_ORIGINAL = ('    private val defaultFactory = SSLContext.getInstance("TLS")'
                   '.apply { init(null, arrayOf(trust), null) }.socketFactory')
HERMES_CORRECTED = """    private val defaultFactory = run {
        val password = CharArray(32) { 'a' }
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, password)
        }
        val keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(keyStore, password)
        }.keyManagers
        SSLContext.getInstance("TLS").apply { init(keyManagers, arrayOf(trust), null) }.socketFactory
    }"""


class EmptyStoreManagersTests(unittest.TestCase):
    """Hermes Control CertificateSocketFactory.<init>, 2026-11-02."""

    def test_key_managers_over_an_empty_store_replace_null_without_effect(self):
        [issue] = empty_store_managers({}, [edit("F.kt", HERMES_ORIGINAL, HERMES_CORRECTED)])
        self.assertEqual(issue["code"], "EMPTY_STORE_MANAGERS")
        from cognalys.llm.coordinated_generation import _NO_EFFECT_GATE_CODES
        self.assertIn("EMPTY_STORE_MANAGERS", _NO_EFFECT_GATE_CODES)
        self.assertTrue(draft_quality_failure([issue]))

    def test_the_java_form_is_flagged_too(self):
        original = "ctx.init(null, trustManagers, null);"
        corrected = ("KeyStore ks = KeyStore.getInstance(\"PKCS12\");\n"
                     "ks.load(null, null);\n"
                     "KeyManagerFactory kmf = KeyManagerFactory.getInstance(\"X509\");\n"
                     "kmf.init(ks, null);\n"
                     "ctx.init(kmf.getKeyManagers(), trustManagers, null);")
        [issue] = empty_store_managers({}, [edit("F.java", original, corrected)])
        self.assertEqual(issue["code"], "EMPTY_STORE_MANAGERS")

    def test_a_store_that_receives_an_entry_or_a_stream_is_a_change(self):
        original = "ctx.init(null, trustManagers, null);"
        filled = ("KeyStore ks = KeyStore.getInstance(\"PKCS12\");\n"
                  "ks.load(null, null);\n"
                  "ks.setKeyEntry(\"c\", key, pw, chain);\n"
                  "KeyManagerFactory kmf = KeyManagerFactory.getInstance(\"X509\");\n"
                  "kmf.init(ks, pw);\n"
                  "ctx.init(kmf.getKeyManagers(), trustManagers, null);")
        streamed = filled.replace("ks.load(null, null);\nks.setKeyEntry(\"c\", key, pw, chain);\n",
                                  "ks.load(input, pw);\n")
        for corrected in (filled, streamed):
            self.assertEqual(empty_store_managers({}, [edit("F.java", original, corrected)]), [])

    def test_a_platform_backed_store_is_not_empty(self):
        # Cryptomator Lite tryToFindDefaultTrustManager (measured 2026-11-04):
        # AndroidCAStore is filled with the system CAs on load(null).
        original = "tmf.init(null as KeyStore?)"
        corrected = ('val trustStore = KeyStore.getInstance("AndroidCAStore")\n'
                     "trustStore.load(null)\n"
                     "tmf.init(trustStore)")
        self.assertEqual(empty_store_managers({}, [edit("F.kt", original, corrected)]), [])

    def test_a_store_that_already_was_empty_is_not_the_patch(self):
        original = ("KeyStore ks = KeyStore.getInstance(\"PKCS12\");\nks.load(null, null);\n"
                    "ctx.init(null, trustManagers, null);")
        corrected = original.replace("ctx.init(null,", "kmf.init(ks, null);\nctx.init(km,")
        self.assertEqual(empty_store_managers({}, [edit("F.java", original, corrected)]), [])


if __name__ == "__main__":
    unittest.main()
