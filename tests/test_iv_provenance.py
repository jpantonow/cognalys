"""An IV the cipher provider chose, and a keystore key that refuses any other.

Cryptomator Lite run_v6 (2026-10-30): RVSec reported "the IV material was
not observed to come from a randomized source" at CipherGCM.getIvParameterSpec,
whose spec only carries, for decryption, the IV BaseCipher's
init(ENCRYPT_MODE, key) let the provider generate and kept through getIV().
The evidence-gap promotion generated a SecureRandom IV for those inits; the
key is an AndroidKeyStore key generated in CryptoOperationsGCM without
setRandomizedEncryptionRequired(false), so every encryption would have thrown.
The behaviour review approved it, never having seen CryptoOperationsGCM.
"""
import json
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.iv_provenance import (  # noqa: E402
    iv_provenance_fact, provider_generated_iv,
)
from cognalys.llm.adjudication_rules import provider_iv_settlement  # noqa: E402
from cognalys.llm.finding_processing import provider_iv_settled  # noqa: E402
from cognalys.llm.semantic_validation import (  # noqa: E402
    caller_iv_on_randomized_keystore_key, key_provider_constraints, provider_iv_replaced,
)

CRYPTO = "util/src/main/java/org/cryptomator/util/crypto/"
GCM_SPEC = {"applies_to_types": ["javax.crypto.spec.GCMParameterSpec"]}

CIPHER_GCM = """package org.cryptomator.util.crypto;

class CipherGCM extends BaseCipher {

	CipherGCM(javax.crypto.Cipher cipher, SecretKey key) {
		super(cipher, key, 12);
	}

	@Override
	protected AlgorithmParameterSpec getIvParameterSpec(byte[] iv) {
		return new GCMParameterSpec(128, iv);
	}
}
"""
GET_IV_PARAMETER_SPEC = """	protected AlgorithmParameterSpec getIvParameterSpec(byte[] iv) {
		return new GCMParameterSpec(128, iv);
	}"""

ENCRYPT = """	public byte[] encrypt(byte[] data) {
		try {
			cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
			byte[] encrypted = cipher.doFinal(data);
			return CryptoByteArrayUtils.join(encrypted, cipher.getIV());
		} catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
			throw new FatalCryptoException(e);
		}
	}"""
# What run_v6 generated for it.
ENCRYPT_WITH_CALLER_IV = """	public byte[] encrypt(byte[] data) {
		try {
			byte[] iv = new byte[ivLength];
			RANDOM.nextBytes(iv);
			AlgorithmParameterSpec ivspec = getIvParameterSpec(iv);
			cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, ivspec);
			byte[] encrypted = cipher.doFinal(data);
			return CryptoByteArrayUtils.join(encrypted, iv);
		} catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
			throw new FatalCryptoException(e);
		}
	}"""

BASE_CIPHER = """package org.cryptomator.util.crypto;

abstract class BaseCipher implements Cipher {

	private final javax.crypto.Cipher cipher;
	private final SecretKey key;
	private final int ivLength;

	BaseCipher(javax.crypto.Cipher cipher, SecretKey key, int ivLength) {
		this.cipher = cipher;
		this.key = key;
		this.ivLength = ivLength;
	}

	protected abstract AlgorithmParameterSpec getIvParameterSpec(byte[] iv);

	@Override
""" + ENCRYPT + """

	@Override
	public byte[] decrypt(byte[] encryptedBytesWithIv) {
		try {
			byte[] iv = getIv(encryptedBytesWithIv);
			byte[] bytes = CryptoByteArrayUtils.getBytes(encryptedBytesWithIv, ivLength);
			AlgorithmParameterSpec ivspec = getIvParameterSpec(iv);
			cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, ivspec);
			return cipher.doFinal(bytes);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new FatalCryptoException(e);
		}
	}

	private byte[] getIv(byte[] encryptedBytesWithIv) {
		byte[] iv = new byte[ivLength];
		System.arraycopy(encryptedBytesWithIv, 0, iv, 0, iv.length);
		return iv;
	}
}
"""

CRYPTO_OPERATIONS_GCM = """package org.cryptomator.util.crypto;

class CryptoOperationsGCM implements CryptoOperations {

	@Override
	public Cipher cryptor(KeyStore keyStore, String alias) throws UnrecoverableStorageKeyException {
		try {
			final SecretKey key = (SecretKey) keyStore.getKey(alias, null);
			final javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
			return new CipherGCM(cipher, key);
		} catch (UnrecoverableKeyException e) {
			throw new UnrecoverableStorageKeyException(e);
		}
	}

	@Override
	public KeyGenerator initializeKeyGenerator(Context context, final String alias) {
		final javax.crypto.KeyGenerator generator;
		generator = javax.crypto.KeyGenerator.getInstance(ENCRYPTION_ALGORITHM, ANDROID_KEYSTORE);
		return requireUserAuthentication -> {
			KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec //
					.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT) //
					.setBlockModes(KeyProperties.BLOCK_MODE_GCM) //
					.setKeySize(256);
			generator.init(builder.build());
			generator.generateKey();
		};
	}
}
"""

# A Kotlin vault that builds the spec inline in its decryption.
VAULT = "app/src/main/java/org/example/Vault.kt"
VAULT_DECRYPT = """    fun decrypt(data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, data.copyOfRange(0, 12)))
        return cipher.doFinal(data.copyOfRange(12, data.size))
    }"""
VAULT_SOURCE = """class Vault(private val key: SecretKey) {
    fun encrypt(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.iv + cipher.doFinal(plain)
    }

""" + VAULT_DECRYPT + """
}
"""


def _repository(files):
    directory = tempfile.TemporaryDirectory()
    root = Path(directory.name)
    for relative, content in files.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(content, encoding="utf-8")
    return directory, root


def _cryptomator(**overrides):
    files = {CRYPTO + "CipherGCM.java": CIPHER_GCM, CRYPTO + "BaseCipher.java": BASE_CIPHER,
             CRYPTO + "CryptoOperationsGCM.java": CRYPTO_OPERATIONS_GCM}
    files.update({CRYPTO + name: content for name, content in overrides.items()})
    return _repository(files)


def _error(root, body=GET_IV_PARAMETER_SPEC, method="getIvParameterSpec",
           path=CRYPTO + "CipherGCM.java", specification=None):
    # run_v6's record: RVSec, a not-observed report.
    return {"repository_path": str(root), "method_body": body, "method_name": method,
            "source_file_path": path, "csv_class": "org.cryptomator.util.crypto.CipherGCM",
            "specification_context": GCM_SPEC if specification is None else specification,
            "tool": "rvsec", "detector_context": {"label": "not-observed",
                                                  "expected": "a randomized byte[]"}}


class ProviderGeneratedIvTests(unittest.TestCase):
    """iv_provenance: the IV a spec carries is the one the provider chose, or not settled."""

    def fact(self, files=None, **error):
        directory, root = _cryptomator(**(files or {}))
        self.addCleanup(directory.cleanup)
        return iv_provenance_fact(_error(root, **error))

    def test_cryptomators_decryption_spec_carries_the_iv_its_encryption_let_the_provider_choose(self):
        fact = self.fact()
        self.assertEqual(fact["status"], "provider_generated", fact)
        [use] = fact["uses"]
        self.assertEqual((use["api"], use["argument"]), ("GCMParameterSpec", "iv"))
        self.assertIn("DECRYPT_MODE", use["decryptions"][0])
        self.assertIn("cipher.getIV()", use["encryptions"][0]["iv_read_back"])
        self.assertIn("BaseCipher.java", fact["statement"])

    def test_a_kotlin_spec_built_inline_from_the_ciphertext_is_followed_in_its_own_file(self):
        directory, root = _repository({VAULT: VAULT_SOURCE})
        self.addCleanup(directory.cleanup)
        fact = provider_generated_iv(root, VAULT_DECRYPT, "decrypt", VAULT)
        self.assertEqual(fact["status"], "provider_generated", fact)

    def test_an_encryption_that_supplies_its_own_iv_settles_nothing(self):
        fact = self.fact({"BaseCipher.java": BASE_CIPHER.replace(ENCRYPT, ENCRYPT_WITH_CALLER_IV)})
        self.assertEqual(fact["status"], "not_established")
        # The encrypt call site hands the spec a nextBytes-filled array.
        self.assertIn("the code supplies its own IV", fact["reason"])
        # And with the spec built elsewhere, the file's encryption still decides.
        other = BASE_CIPHER.replace(ENCRYPT, ENCRYPT.replace(
            "ENCRYPT_MODE, key)", "ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce))"))
        fact = self.fact({"BaseCipher.java": other})
        self.assertEqual(fact["status"], "not_established")
        self.assertIn("does not encrypt with a provider-chosen IV", fact["reason"])

    def test_a_spec_that_reaches_an_encryption_is_not_the_providers(self):
        body = """    fun seal(key: SecretKey, iv: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(data)
    }"""
        directory, root = _repository({VAULT: "class Box {\n" + body + "\n}\n"})
        self.addCleanup(directory.cleanup)
        fact = provider_generated_iv(root, body, "seal", VAULT)
        self.assertEqual(fact["status"], "not_established")
        self.assertIn("not a decryption", fact["reason"])

    def test_a_constant_or_zero_iv_is_never_the_providers(self):
        for argument in ("FIXED_IV", "ByteArray(12)"):
            body = VAULT_DECRYPT.replace("data.copyOfRange(0, 12)", argument)
            directory, root = _repository({VAULT: VAULT_SOURCE.replace(VAULT_DECRYPT, body)})
            self.addCleanup(directory.cleanup)
            fact = provider_generated_iv(root, body, "decrypt", VAULT)
            self.assertEqual(fact["status"], "not_established", argument)
            self.assertIn("constant", fact["reason"])

    def test_an_encryption_that_discards_the_providers_iv_settles_nothing(self):
        source = VAULT_SOURCE.replace("return cipher.iv + cipher.doFinal(plain)",
                                      "return cipher.doFinal(plain)")
        directory, root = _repository({VAULT: source})
        self.addCleanup(directory.cleanup)
        self.assertEqual(provider_generated_iv(root, VAULT_DECRYPT, "decrypt", VAULT)["status"],
                         "not_established")

    def test_an_init_whose_mode_is_a_variable_settles_nothing(self):
        body = VAULT_DECRYPT.replace("Cipher.DECRYPT_MODE", "mode")
        source = VAULT_SOURCE.replace(VAULT_DECRYPT, body).replace(
            "fun decrypt(data: ByteArray)", "fun decrypt(mode: Int, data: ByteArray)")
        directory, root = _repository({VAULT: source})
        self.addCleanup(directory.cleanup)
        self.assertEqual(provider_generated_iv(root, body, "decrypt", VAULT)["status"],
                         "not_established")

    def test_a_spec_returned_again_by_a_caller_is_not_followed(self):
        caller = BASE_CIPHER.replace(
            "	private byte[] getIv(",
            "	AlgorithmParameterSpec spec(byte[] iv) {\n		return getIvParameterSpec(iv);\n	}\n\n"
            "	private byte[] getIv(")
        fact = self.fact({"BaseCipher.java": caller})
        self.assertEqual(fact["status"], "not_established")
        self.assertIn("returned again", fact["reason"])

    def test_only_a_rule_about_the_iv_spec_gets_the_fact(self):
        # tokn's KeystoreManager.decrypt (2026-10-28): its CipherSpec finding,
        # "no generator of the key given to Cipher.init was observed", is
        # about the key, though the method builds a GCMParameterSpec.
        fact = self.fact(specification={"applies_to_types": ["javax.crypto.Cipher"]})
        self.assertEqual(fact["status"], "rule_does_not_govern_an_iv_spec")
        self.assertEqual(iv_provenance_fact({"method_body": "x"})["status"], "no_checkout")

    def test_only_a_runtime_monitors_not_observed_report_gets_the_fact(self):
        # Review of batch4-iv (2026-10-30): the provider's IV answers "no
        # randomized producer observed" and nothing else -- not a value check
        # (a constant IV seen, a tag length outside the rule), not the echo of
        # a refused producer, not a static analyzer's data flow.
        directory, root = _cryptomator()
        self.addCleanup(directory.cleanup)
        # random-key-material (CometOTP, 2026-11-08): the monitor saw the
        # origin and the check does not admit it -- an unadmitted origin read
        # from data/detector_labels.json, not a gap the provider's IV answers.
        for label in ("violation", "upstream-refused", "random-key-material"):
            error = _error(root)
            error["detector_context"] = {"label": label}
            self.assertEqual(iv_provenance_fact(error)["status"],
                             "report_is_not_an_unobserved_origin", label)
        # The three labels whose report kind is unobserved_origin keep it.
        for label in ("not-observed", "platform-default", "application-manager"):
            error = _error(root)
            error["detector_context"] = {"label": label}
            self.assertEqual(iv_provenance_fact(error)["status"], "provider_generated", label)
        static = dict(_error(root), tool="static:cryptoguard")
        self.assertEqual(iv_provenance_fact(static)["status"], "not_a_runtime_report")
        # Records written before RVSec carried labels keep the fact.
        unlabelled = dict(_error(root), detector_context={})
        self.assertEqual(iv_provenance_fact(unlabelled)["status"], "provider_generated")

    def test_a_production_package_named_like_a_test_is_still_read(self):
        # Review of batch4-iv (2026-10-30): call sites were skipped whenever
        # "test" appeared in the path, so an attestation/ package handing the
        # spec a fixed IV for an encryption was never seen and the spec read
        # as the provider's.
        legacy = ("package org.cryptomator.attestation;\n\nclass Legacy {\n"
                  "	byte[] seal(CipherGCM gcm, byte[] data, byte[] fixedIv) throws Exception {\n"
                  "		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, gcm.getIvParameterSpec(fixedIv));\n"
                  "		return cipher.doFinal(data);\n	}\n}\n")
        directory, root = _cryptomator()
        self.addCleanup(directory.cleanup)
        path = root / "util/src/main/java/org/cryptomator/attestation/Legacy.java"
        path.parent.mkdir(parents=True)
        path.write_text(legacy, encoding="utf-8")
        fact = iv_provenance_fact(_error(root))
        self.assertEqual(fact["status"], "not_established")
        self.assertIn("attestation/Legacy.java", fact["reason"])
        # A real test source set is still left out.
        test = root / "util/src/test/java/org/cryptomator/util/crypto/CipherTest.java"
        test.parent.mkdir(parents=True)
        test.write_text(legacy.replace("attestation", "util.crypto"), encoding="utf-8")
        path.unlink()
        self.assertEqual(iv_provenance_fact(_error(root))["status"], "provider_generated")


class ProviderIvSettlementTests(unittest.TestCase):
    """A blocked IV finding whose IV the provider chose ends without security impact."""

    FACTS = {"iv_provenance": {"status": "provider_generated", "statement": "The IV is the provider's."}}
    BLOCKED = {"decision": "NO_SAFE_FIX", "generation_status": "blocked",
               "cause_status": "unknown", "detector_violation": "unknown"}

    def test_the_blocked_cryptomator_answer_is_settled_with_the_detectors_own_account(self):
        reason = provider_iv_settlement(self.FACTS, self.BLOCKED, {
            "label_meaning": "NOT OBSERVED: an IV parsed from the ciphertext looks the same."})
        self.assertTrue(reason.startswith("The IV is the provider's."))
        self.assertIn("NOT OBSERVED: an IV parsed from the ciphertext", reason)
        analysis = {"v2": {"adjudication": {"iv_provenance_settlement": reason}}}
        self.assertEqual(provider_iv_settled(analysis), reason)
        self.assertEqual(provider_iv_settled({"v2": {"adjudication": {}}}), "")

    def test_a_cause_the_source_established_keeps_the_adjudicators_outcome(self):
        confirmed = dict(self.BLOCKED, cause_status="confirmed", detector_violation="confirmed")
        self.assertEqual(provider_iv_settlement(self.FACTS, confirmed), "")
        # The evidence-gap promotion's cause is the runtime observation, not the source.
        observed = dict(confirmed, cause_authority={"kind": "runtime_observation"})
        self.assertTrue(provider_iv_settlement(self.FACTS, observed))

    def test_a_generating_answer_or_an_unsettled_fact_is_left_alone(self):
        generating = dict(self.BLOCKED, generation_status="supported_for_review")
        self.assertEqual(provider_iv_settlement(self.FACTS, generating), "")
        for fact in ({"status": "not_established"}, {"status": "rule_does_not_govern_an_iv_spec"}):
            self.assertEqual(provider_iv_settlement({"iv_provenance": fact}, self.BLOCKED), "")
        self.assertEqual(provider_iv_settlement(None, self.BLOCKED), "")

    def test_a_finding_analysed_with_others_is_not_settled(self):
        # Beta run_v2 (2026-10-25): beginUnwrap [CipherSpec], a key report,
        # was joined into beginUnwrap [GCMParameterSpecSpec]; the IV fact
        # does not answer it, and the unit's one ending would.
        joint = [{"specification": "CipherSpec", "method": "beginUnwrap",
                  "error_message": "no generator of the key given to Cipher.init was observed"}]
        self.assertEqual(provider_iv_settlement(self.FACTS, self.BLOCKED, None, joint), "")
        self.assertTrue(provider_iv_settlement(self.FACTS, self.BLOCKED, None, []))

    def test_the_adjudicator_is_told_what_the_fact_settles(self):
        from test_applied_edits_match_text import _adjudication_system

        system = " ".join(_adjudication_system().split())
        self.assertIn("derived_facts.iv_provenance provider_generated establishes that the IV "
                      "reaching the reported spec is the one the cipher provider generated", system)
        self.assertIn("do not block on the IV producer being unknown", system)


def _encrypt_edit(original=ENCRYPT, corrected=ENCRYPT_WITH_CALLER_IV):
    return [{"source_file_path": CRYPTO + "BaseCipher.java", "edit_kind": "method",
             "symbol": "BaseCipher.encrypt", "original_code": original,
             "corrected_code": corrected}]


class ProviderIvReplacedTests(unittest.TestCase):
    """Judging the patch: the code choosing an IV the provider already chooses."""

    def test_run_v6s_patch_replaces_the_providers_iv_and_is_refused(self):
        directory, root = _cryptomator()
        self.addCleanup(directory.cleanup)
        [issue] = provider_iv_replaced(_error(root), _encrypt_edit())
        self.assertEqual(issue["code"], "PROVIDER_IV_REPLACED")
        self.assertIn("ENCRYPT_MODE, key, ivspec", issue["details"][0])

    def test_without_the_fact_the_same_patch_is_not_judged_here(self):
        directory, root = _cryptomator()
        self.addCleanup(directory.cleanup)
        error = _error(root, specification={"applies_to_types": ["javax.crypto.Cipher"]})
        self.assertEqual(provider_iv_replaced(error, _encrypt_edit()), [])

    def test_the_finding_closes_without_security_impact_at_once(self):
        from cognalys.llm.coordinated_generation import CoordinatedGeneration

        failed = {"status": "invalid", "stage": "semantic_validation"}
        failures = [{"code": "PROVIDER_IV_REPLACED", "details": ["The IV is the provider's."]}]
        self.assertTrue(CoordinatedGeneration._close_provider_iv_replacement(failed, failures))
        self.assertIn("The IV is the provider's.", failed["correct_use"])
        self.assertFalse(CoordinatedGeneration._close_provider_iv_replacement(
            {"pipeline_failure": True}, failures))
        self.assertFalse(CoordinatedGeneration._close_provider_iv_replacement(
            {}, [{"code": "WRAPPED_SAME_OBJECT", "details": [""]}]))
        # A unit with joined findings retries with the failure as feedback.
        joined = {"joint_findings": [{"specification": "CipherSpec"}]}
        self.assertFalse(CoordinatedGeneration._close_provider_iv_replacement(
            {"status": "invalid"}, failures, joined))


class KeyProviderConstraintTests(unittest.TestCase):
    """What AndroidKeyStore enforces on a key, read from where the repository makes it."""

    def test_the_key_basecipher_receives_is_followed_to_its_keystore_generation(self):
        directory, root = _cryptomator()
        self.addCleanup(directory.cleanup)
        [constraint] = key_provider_constraints(
            {"repository_path": str(root)}, [CRYPTO + "BaseCipher.java"])
        self.assertTrue(constraint["randomized_encryption_required"])
        self.assertIn("CryptoOperationsGCM.java", constraint["key_from"][0])
        self.assertIn("keyStore.getKey(alias, null)", constraint["key_from"][0])
        self.assertIn("PURPOSE_ENCRYPT", constraint["key_generated"][0]["builder"])
        self.assertIn("InvalidAlgorithmParameterException", constraint["consequence"])

    def test_the_cross_file_caller_iv_is_refused_deterministically(self):
        directory, root = _cryptomator()
        self.addCleanup(directory.cleanup)
        [issue] = caller_iv_on_randomized_keystore_key(
            {"repository_path": str(root)}, _encrypt_edit())
        self.assertEqual(issue["code"], "CALLER_IV_REFUSED_BY_KEYSTORE_KEY")
        self.assertIn("CryptoOperationsGCM.java", issue["details"][0])

    def test_randomization_turned_off_by_the_repository_is_no_constraint(self):
        directory, root = _cryptomator(**{"CryptoOperationsGCM.java": CRYPTO_OPERATIONS_GCM.replace(
            ".setKeySize(256);", ".setKeySize(256).setRandomizedEncryptionRequired(false);")})
        self.addCleanup(directory.cleanup)
        [constraint] = key_provider_constraints(
            {"repository_path": str(root)}, [CRYPTO + "BaseCipher.java"])
        self.assertFalse(constraint["randomized_encryption_required"])
        self.assertEqual(caller_iv_on_randomized_keystore_key(
            {"repository_path": str(root)}, _encrypt_edit()), [])

    def test_one_construction_with_a_software_key_leaves_the_key_unresolved(self):
        software = ('class Legacy {\n	Cipher make(byte[] raw) {\n'
                    '		return new CipherGCM(cipher, new SecretKeySpec(raw, "AES"));\n	}\n}\n')
        directory, root = _cryptomator(**{"Legacy.java": software})
        self.addCleanup(directory.cleanup)
        self.assertEqual(key_provider_constraints(
            {"repository_path": str(root)}, [CRYPTO + "BaseCipher.java"]), [])
        self.assertEqual(caller_iv_on_randomized_keystore_key(
            {"repository_path": str(root)}, _encrypt_edit()), [])

    def test_an_envelope_key_built_from_raw_bytes_is_not_the_keystore_key(self):
        # Review of batch4-iv (2026-10-30): any keystore key a construction
        # passed was taken for the key the class encrypts with. Vault
        # receives a keystore wrapping key and encrypts with a SecretKeySpec
        # it builds; a caller IV is fine for that key.
        vault = ("class Vault {\n	private final SecretKey wrapKey;\n	private final SecretKey dataKey;\n"
                 "	Vault(SecretKey wrapKey, byte[] raw) {\n		this.wrapKey = wrapKey;\n"
                 '		this.dataKey = new SecretKeySpec(raw, "AES");\n	}\n'
                 "	byte[] seal(byte[] data) throws Exception {\n"
                 '		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\n'
                 "		cipher.init(Cipher.ENCRYPT_MODE, dataKey);\n"
                 "		return join(cipher.getIV(), cipher.doFinal(data));\n	}\n}\n")
        keys = CRYPTO_OPERATIONS_GCM.replace(
            "return new CipherGCM(cipher, key);", "return new Vault(key, raw);")
        directory, root = _repository({CRYPTO + "Vault.java": vault,
                                       CRYPTO + "CryptoOperationsGCM.java": keys})
        self.addCleanup(directory.cleanup)
        error = {"repository_path": str(root)}
        edit = [{"source_file_path": CRYPTO + "Vault.java",
                 "original_code": "cipher.init(Cipher.ENCRYPT_MODE, dataKey);",
                 "corrected_code": "cipher.init(Cipher.ENCRYPT_MODE, dataKey, new GCMParameterSpec(128, iv));"}]
        self.assertEqual(caller_iv_on_randomized_keystore_key(error, edit), [])
        self.assertEqual(key_provider_constraints(error, [CRYPTO + "Vault.java"]), [])
        # The member the constructor does assign from that parameter is followed.
        wrapping = vault.replace("ENCRYPT_MODE, dataKey", "ENCRYPT_MODE, wrapKey")
        (root / CRYPTO / "Vault.java").write_text(wrapping, encoding="utf-8")
        edit = [dict(edit[0], original_code="cipher.init(Cipher.ENCRYPT_MODE, wrapKey);",
                     corrected_code="cipher.init(Cipher.ENCRYPT_MODE, wrapKey, new GCMParameterSpec(128, iv));")]
        [issue] = caller_iv_on_randomized_keystore_key(error, edit)
        self.assertIn("CryptoOperationsGCM.java", issue["details"][0])

    def test_a_kotlin_property_parameter_is_followed_and_named_arguments_are_not(self):
        box = ("class Box(private val key: SecretKey, private val label: String) {\n"
               "    fun seal(data: ByteArray): ByteArray {\n"
               '        val cipher = Cipher.getInstance("AES/GCM/NoPadding")\n'
               "        cipher.init(Cipher.ENCRYPT_MODE, key)\n"
               "        return cipher.iv + cipher.doFinal(data)\n    }\n}\n")
        maker = ("class Maker {\n    fun box(keyStore: KeyStore): Box {\n"
                 '        val key = keyStore.getKey("alias", null) as SecretKey\n'
                 '        return Box(key, "main")\n    }\n'
                 "    fun create() {\n"
                 '        val generator = KeyGenerator.getInstance("AES", "AndroidKeyStore")\n'
                 '        generator.init(KeyGenParameterSpec.Builder("alias", '
                 "KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT).build())\n"
                 "        generator.generateKey()\n    }\n}\n")
        directory, root = _repository({"app/src/main/java/a/Box.kt": box,
                                       "app/src/main/java/a/Maker.kt": maker})
        self.addCleanup(directory.cleanup)
        error = {"repository_path": str(root)}
        [constraint] = key_provider_constraints(error, ["app/src/main/java/a/Box.kt"])
        self.assertIn("Maker.kt", constraint["key_from"][0])
        self.assertTrue(constraint["randomized_encryption_required"])
        (root / "app/src/main/java/a/Maker.kt").write_text(
            maker.replace('Box(key, "main")', 'Box(label = "main", key = key)'), encoding="utf-8")
        self.assertEqual(key_provider_constraints(error, ["app/src/main/java/a/Box.kt"]), [])

    def test_the_review_receives_the_constraint_and_the_rule(self):
        from test_applied_edits_match_text import CLEAN_REVIEW, METHOD_EDIT, _coordinated_run

        source = ("class Main {\n"
                  "    private final SecretKey key = createKey();\n"
                  "    SecretKey createKey() throws Exception {\n"
                  '        KeyGenerator generator = KeyGenerator.getInstance("AES", "AndroidKeyStore");\n'
                  '        generator.init(new KeyGenParameterSpec.Builder("alias", '
                  "KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).build());\n"
                  "        return generator.generateKey();\n    }\n"
                  "    byte[] method(Cipher cipher, byte[] data) throws Exception {\n"
                  "        int value = 1;\n"
                  "        cipher.init(Cipher.ENCRYPT_MODE, key);\n"
                  "        return cipher.doFinal(data);\n    }\n}\n")
        _, provider, _, review_file = _coordinated_run(
            lambda call: CLEAN_REVIEW, [METHOD_EDIT], source=source)
        payload = provider.review_prompt
        self.assertIn('"key_provider_constraints"', payload)
        self.assertIn('"randomized_encryption_required":true', payload)
        system = " ".join(provider.review_system.split())
        self.assertIn("key_provider_constraints, when present, lists the encryptions in the "
                      "edited files whose key the repository generates or imports in "
                      "AndroidKeyStore", system)
        self.assertIn("throws for that key on every call", system)
        # key_provider_constraints came with contract 9; later contracts keep it.
        from cognalys.llm.coordinated_generation import REVIEW_CONTRACT_VERSION
        self.assertGreaterEqual(REVIEW_CONTRACT_VERSION, 9)
        self.assertEqual(review_file["review_contract_version"], REVIEW_CONTRACT_VERSION)
        json.dumps(review_file)


if __name__ == "__main__":
    unittest.main()
