"""Lessons from QuantumBadger/RedReader PR #1373, closed by its maintainer.

The pull request replaced SHA-1 with SHA-256 inside `General.sha1`. The
analysis had called the value a regenerable cache key; its only caller builds a
database file name from it, so every user would have lost stored data. The
function also kept a name that no longer described what it computed, while
`General.sha256` already existed. These tests pin each safeguard added in
response, on repositories shaped like that one.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.migration_policy import (  # noqa: E402
    ground_usage_in_value_consumers,
    promote_bounded_digest_discriminator_review,
)
from cognalys.prs.pr_outcomes import record_pr_outcome, rejected_outcome_for  # noqa: E402
from cognalys.extraction.rename_safety import assess_rename_safety  # noqa: E402
from cognalys.llm.semantic_validation import (  # noqa: E402
    name_behavior_contradictions,
    rename_issues,
    validate_coordinated_semantics,
    variable_name_contradictions,
)
from cognalys.extraction.value_consumers import classify_statement, derived_value_consumers  # noqa: E402


GENERAL_KT = """package org.example.common

import java.security.MessageDigest

object General {
    @JvmStatic
    fun sha1(plaintext: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-1")
        return digest.digest(plaintext).joinToString("") { "%02x".format(it) }
    }

    @JvmStatic
    fun sha256(plaintext: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(plaintext.toByteArray()).joinToString("")
    }
}
"""

MANAGER_JAVA = """package org.example.reddit;

import org.example.common.General;

public class SubredditManager {
    private static String getDbFilename(final String type, final String user) {
        return General.sha1(user.getBytes()) + "_" + type + "_subreddits.db";
    }

    public void open(final Object context, final String user) {
        final Object db = new RawObjectDB(context, getDbFilename("subreddits", user));
    }
}
"""

APP_BUILD = "plugins {\n    id 'com.android.application'\n}\n"


def write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def line_of(text: str, needle: str) -> int:
    return next(number for number, line in enumerate(text.splitlines(), 1) if needle in line)


GENERAL = "app/src/main/java/org/example/common/General.kt"
MANAGER = "app/src/main/java/org/example/reddit/SubredditManager.java"


def redreader_like_repository(root: Path) -> list:
    write(root, "app/build.gradle", APP_BUILD)
    write(root, GENERAL, GENERAL_KT)
    write(root, MANAGER, MANAGER_JAVA)
    return [{"path": MANAGER, "line": line_of(MANAGER_JAVA, "General.sha1(")}]


def available(callers: list) -> dict:
    return {"status": "available", "resolved_callers": callers, "ambiguous_calls": []}


class DerivedValueConsumerTests(unittest.TestCase):
    def test_a_digest_that_names_a_database_file_is_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            result = derived_value_consumers(root, callers, "sha1")
        self.assertTrue(result["persisted"])
        self.assertEqual(result["consumers"][0]["path"], MANAGER)
        self.assertIn("_subreddits.db", result["consumers"][0]["statement"])

    def test_the_value_is_followed_through_a_return_into_a_file_name(self):
        source = (
            "class Store {\n"
            "    String name(byte[] b) {\n"
            "        return Hashes.md5(b);\n"
            "    }\n"
            "    void save(java.io.File dir, byte[] b) {\n"
            "        java.io.File target = new File(dir, name(b));\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "src/Store.java", source)
            result = derived_value_consumers(
                root, [{"path": "src/Store.java", "line": 3}], "md5",
            )
        self.assertTrue(result["persisted"])
        self.assertEqual(result["consumers"][0]["reached_through"], "returned through name()")

    def test_an_in_memory_comparison_is_not_persistence(self):
        source = (
            "class Check {\n"
            "    boolean same(byte[] a, String expected) {\n"
            "        String actual = Hashes.md5(a);\n"
            "        return actual.equals(expected);\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "src/Check.java", source)
            result = derived_value_consumers(
                root, [{"path": "src/Check.java", "line": 3}], "md5",
            )
        self.assertFalse(result["persisted"])
        self.assertFalse(result["transmitted"])
        self.assertEqual([item["kind"] for item in result["consumers"]], ["comparison"])

    def test_a_koin_provided_digest_reaches_the_request_it_is_sent_in(self):
        # StellarSand/Password-Monitor: the provider lambda has no caller in
        # the source; the digest reaches HIBP's range API through get<T>().
        module = (
            "val appModule =\n"
            "    module {\n"
            "        single { ApiRepository(get()) }\n"
            "        single { MessageDigest.getInstance(\"SHA-1\") }\n"
            "    }\n"
        )
        hashing = (
            "class HashUtils {\n"
            "    companion object : KoinComponent {\n"
            "        suspend fun prefixAndSuffix(password: String): Pair<String, String> {\n"
            "            return withContext(Dispatchers.Default) {\n"
            "                get<MessageDigest>().digest(password.toByteArray())\n"
            "                    .joinToString(\"\") { \"%02x\".format(it) }\n"
            "                    .let { it.take(5) to it.drop(5) }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        activity = (
            "class CheckActivity {\n"
            "    suspend fun check(password: String) {\n"
            "        val (prefix, suffix) = prefixAndSuffix(password)\n"
            "        show(get<ApiRepository>().getHashes(prefix), suffix)\n"
            "    }\n"
            "}\n"
        )
        service = (
            "class ApiService(private val client: HttpClient) {\n"
            "    suspend fun getHashes(prefix: String): String {\n"
            "        return client.get(\"https://api.pwnedpasswords.com/range/$prefix\").body()\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = "app/src/main/java/org/example/"
            write(root, base + "di/AppModule.kt", module)
            write(root, base + "utils/HashUtils.kt", hashing)
            write(root, base + "CheckActivity.kt", activity)
            write(root, base + "api/ApiService.kt", service)
            result = derived_value_consumers(
                root, [], "appModule$lambda$0$1",
                source_path=base + "di/AppModule.kt",
                source_line=line_of(module, "MessageDigest.getInstance"),
            )
        self.assertTrue(result["transmitted"])
        self.assertEqual(result["dependency_injection"]["provided_types"], ["MessageDigest"])
        network = [item for item in result["consumers"] if item["kind"] == "network"]
        self.assertEqual(network[0]["path"], base + "api/ApiService.kt")
        self.assertEqual(network[0]["reached_through"], "passed as prefix to getHashes()")

    def test_a_dagger_provided_digest_is_followed_from_an_injected_field(self):
        module = (
            "@Module\n"
            "public class CryptoModule {\n"
            "    @Provides\n"
            "    static MessageDigest provideDigest() throws Exception {\n"
            "        return MessageDigest.getInstance(\"MD5\");\n"
            "    }\n"
            "}\n"
        )
        cache = (
            "public class ThumbnailCache {\n"
            "    @Inject\n"
            "    MessageDigest digest;\n"
            "\n"
            "    File fileFor(File dir, String url) {\n"
            "        return new File(dir, hex(digest.digest(url.getBytes())) + \".png\");\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "app/src/main/java/CryptoModule.java", module)
            write(root, "app/src/main/java/ThumbnailCache.java", cache)
            result = derived_value_consumers(
                root, [], "provideDigest",
                source_path="app/src/main/java/CryptoModule.java",
                source_line=line_of(module, "getInstance"),
            )
        self.assertTrue(result["persisted"])
        self.assertEqual(result["dependency_injection"]["provided_types"], ["MessageDigest"])
        self.assertIn("bound to digest", result["consumers"][0]["reached_through"])

    def test_an_ordinary_method_is_not_taken_for_a_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            result = derived_value_consumers(
                root, callers, "sha1", source_path=GENERAL,
                source_line=line_of(GENERAL_KT, 'getInstance("SHA-1")'),
            )
        self.assertNotIn("dependency_injection", result)
        self.assertTrue(result["persisted"])

    def test_a_library_call_sharing_a_returning_methods_name_is_not_its_call_site(self):
        # The value returns through the app's Links.parse(); Uri.parse(...)
        # elsewhere is Android's, and its URLs carry nothing derived from it.
        links = (
            "public class Links {\n"
            "    static String parse(String raw) {\n"
            "        return Hashes.md5(raw);\n"
            "    }\n"
            "}\n"
        )
        browser = (
            "public class Browser {\n"
            "    void open(String link) {\n"
            "        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(link)));\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "src/main/java/Links.java", links)
            write(root, "src/main/java/Browser.java", browser)
            result = derived_value_consumers(
                root, [{"path": "src/main/java/Links.java", "line": 3}], "md5",
            )
        self.assertFalse(result["transmitted"])

    def test_test_fixture_file_names_are_not_persistence(self):
        production = (
            "public class Vault {\n"
            "    static byte[] open(byte[] key) {\n"
            "        return Crypto.createCipher(key);\n"
            "    }\n"
            "}\n"
        )
        fixture = (
            "public class VaultTest {\n"
            "    void opens() {\n"
            "        load(\"vault_encrypted.json\", Vault.open(KEY));\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "app/src/main/java/Vault.java", production)
            write(root, "app/src/test/java/VaultTest.java", fixture)
            result = derived_value_consumers(
                root, [{"path": "app/src/main/java/Vault.java", "line": 3}], "createCipher",
            )
        self.assertFalse(result["persisted"])

    def test_the_reported_line_comes_from_the_hint_or_the_detector_location(self):
        from cognalys.llm.finding_context import reported_line

        source = "app/src/main/java/org/example/di/AppModule.kt"
        self.assertEqual(reported_line({"source_line_hint": 32}, source), 32)
        self.assertEqual(reported_line(
            {"detector_context": {"source_location": "AppModule.kt:31"}}, source), 31)
        self.assertEqual(reported_line(
            {"detector_context": {"source_location": "Other.kt:31"}}, source), 0)

    def test_a_log_line_naming_a_file_stores_nothing(self):
        self.assertEqual(classify_statement('Log.d(TAG, "wrote cache.json " + hash);'), ("", ""))
        self.assertEqual(classify_statement('prefs.edit().putString("key", hash).apply();')[0],
                         "persistence")
        self.assertEqual(classify_statement('builder.addHeader("X-Sig", hash);')[0], "network")

    def test_a_digest_written_into_a_stream_by_a_void_method_is_persisted(self):
        """javalc6/rssreader: writeFile is void and writes its MD5 checksum into
        every backup, which readFile checks on restore."""
        source = (
            "final class FileManager {\n"
            "    private static void writeFile(GZIPOutputStream ostream, String content) throws Exception {\n"
            '        MessageDigest digester = MessageDigest.getInstance("MD5");\n'
            "        digester.update(content.getBytes(StandardCharsets.UTF_8));\n"
            "        String digest = Base64.encodeToString(digester.digest(), Base64.NO_WRAP);\n"
            "        ostream.write(digest.getBytes(StandardCharsets.UTF_8));\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "app/src/main/java/tools/FileManager.java", source)
            result = derived_value_consumers(
                root, [], "writeFile",
                source_path="app/src/main/java/tools/FileManager.java", source_line=3,
            )
        self.assertTrue(result["persisted"])
        self.assertIn("ostream.write(digest", result["consumers"][0]["statement"])
        # RVSec reports the order violation at digester.update(...), line 4.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "app/src/main/java/tools/FileManager.java", source)
            result = derived_value_consumers(
                root, [], "writeFile",
                source_path="app/src/main/java/tools/FileManager.java", source_line=4,
            )
        self.assertTrue(result["persisted"])

    def test_a_digest_compared_with_source_constants_is_fixed(self):
        """WiFiAnalyzer: MD5 of the package name checked against TYPE1..3."""
        source = (
            "class GraphWrapper {\n"
            "    fun calculateGraphType(): Int =\n"
            "        runCatching {\n"
            '            with(MessageDigest.getInstance("MD5")) {\n'
            "                update(packageName.toByteArray())\n"
            "                digest().contentHashCode()\n"
            "            }\n"
            "        }.getOrDefault(TYPE1)\n"
            "    fun size(value: Int): Int = if (value == TYPE1 || value == TYPE2) SIZE_MAX else SIZE_MIN\n"
            "}\n"
            "class TimeGraph {\n"
            "    fun configure() {\n"
            "        configuration.size = graphWrapper.size(graphWrapper.calculateGraphType())\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "app/src/main/kotlin/GraphWrapper.kt", source)
            result = derived_value_consumers(
                root, [{"path": "app/src/main/kotlin/GraphWrapper.kt", "line": 13}],
                "calculateGraphType",
            )
        self.assertTrue(result["fixed"])
        self.assertFalse(result["persisted"])
        self.assertIn("value == TYPE1", next(
            item["statement"] for item in result["consumers"] if item["kind"] == "fixed_value"))
        self.assertEqual(classify_statement("return actual.equals(expected)")[0], "comparison")

    def test_dropping_a_derivation_compared_with_constants_is_flagged(self):
        from cognalys.llm.contract_gates import changed_stored_derivations

        error = {"derived_value_consumers": {
            "fixed": True, "consumers": [{"kind": "fixed_value", "path": "G.kt", "line": 9,
                                          "statement": "value == TYPE1"}]}}
        edits = [{"source_file_path": "G.kt",
                  "original_code": 'with(MessageDigest.getInstance("MD5")) { digest() }',
                  "corrected_code": "fun calculateGraphType(): Int = TYPE1"}]
        issues = changed_stored_derivations(error, edits)
        self.assertEqual([issue["code"] for issue in issues], ["STORED_DERIVED_VALUE_CHANGED"])
        self.assertIn("compared with a value fixed in the source", issues[0]["details"][0])

    def test_a_value_changed_on_one_api_but_kept_by_another_is_flagged(self):
        """jimvixx/ShortMessageSecure#83: the generator renamed, the MAC unchanged."""
        from cognalys.llm.contract_gates import value_still_configures_other_api as gate

        def check(original, corrected, other_file):
            edits = [{"source_file_path": "app/src/main/java/c/A.java",
                      "original_code": original, "corrected_code": corrected}]
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write(root, "app/src/main/java/c/B.java", other_file)
                return [issue["code"] for issue in gate({"repository_path": str(root)}, edits)]

        flagged = ["VALUE_STILL_CONFIGURES_OTHER_API"]
        self.assertEqual(check('KeyGenerator.getInstance("HmacSHA1");',
                               'KeyGenerator.getInstance("HmacSHA256");',
                               'Mac m = Mac.getInstance("HmacSHA1");'), flagged)
        # Any pair sharing a value, not one family: RSA keys still fed to an RSA cipher.
        self.assertEqual(check('KeyPairGenerator.getInstance("RSA");',
                               'KeyPairGenerator.getInstance("EC");',
                               'Cipher c = Cipher.getInstance("RSA");'), flagged)
        # Migrating every side is a real change.
        self.assertEqual(check('KeyGenerator.getInstance("HmacSHA1");',
                               'KeyGenerator.getInstance("HmacSHA256");',
                               'Mac m = Mac.getInstance("HmacSHA256");'), [])
        # The same API elsewhere is a separate use, not the other side.
        self.assertEqual(check('MessageDigest.getInstance("MD5");',
                               'MessageDigest.getInstance("SHA-256");',
                               'MessageDigest d = MessageDigest.getInstance("MD5");'), [])

    def test_a_file_in_the_cache_directory_is_cache_not_persistence(self):
        """AmaRadio: File(ctx.cacheDir, "cache_" + key.md5())."""
        self.assertEqual(classify_statement("val file = File(ctx.cacheDir, fileName)")[0], "cache")
        self.assertEqual(classify_statement("File(context.getCacheDir(), name)")[0], "cache")
        self.assertEqual(classify_statement("File(context.filesDir, name)")[0], "persistence")
        self.assertEqual(classify_statement('File(dir, name + "_subreddits.db")')[0], "persistence")

    def test_a_digest_kept_in_a_local_buffer_is_not_a_stream_write(self):
        self.assertEqual(classify_statement("builder.append(hash);"), ("", ""))
        self.assertEqual(classify_statement("out.write(hash.getBytes());")[0], "persistence")


class UsageGroundingTests(unittest.TestCase):
    def _error(self, persisted=True):
        return {
            "case_migration_policy": {"consumer_scope": "internal_recomputed_digest_value"},
            "derived_value_consumers": {
                "persisted": persisted, "transmitted": False,
                "consumers": [{"kind": "persistence", "path": MANAGER, "line": 7,
                               "statement": 'return General.sha1(x) + "_subreddits.db";'}]
                if persisted else [],
            },
        }

    def test_a_cache_label_contradicted_by_a_file_name_voids_the_authorization(self):
        analysis = {
            "decision": "FIX_SUPPORTED",
            "migration_assessment": {"usage_kind": "cache", "policy_authorized": True},
        }
        correction = ground_usage_in_value_consumers(self._error(), analysis)
        self.assertEqual(correction["grounded"], "persistence")
        self.assertTrue(correction["policy_authorization_voided"])
        self.assertEqual(analysis["decision"], "NO_SAFE_FIX")
        self.assertTrue(analysis["migration_assessment"]["legacy_compatibility_required"])
        self.assertFalse(analysis["migration_assessment"]["policy_authorized"])

    def test_nothing_changes_without_consumer_evidence_or_for_a_persistent_label(self):
        analysis = {"decision": "FIX_SUPPORTED",
                    "migration_assessment": {"usage_kind": "cache"}}
        self.assertIsNone(ground_usage_in_value_consumers(self._error(False), analysis))
        self.assertEqual(analysis["decision"], "FIX_SUPPORTED")
        persistent = {"decision": "FIX_SUPPORTED",
                      "migration_assessment": {"usage_kind": "persistence"}}
        self.assertIsNone(ground_usage_in_value_consumers(self._error(), persistent))

    def test_a_persisted_value_is_never_promoted_as_an_internal_discriminator(self):
        analysis = {
            "decision": "NO_SAFE_FIX", "confirmed_cause": "SHA-1 digest",
            "migration_assessment": {"usage_kind": "cache"},
            "digest_contract_assessment": {},
        }
        self.assertIs(promote_bounded_digest_discriminator_review(self._error(), analysis),
                      analysis)
        self.assertEqual(analysis["decision"], "NO_SAFE_FIX")


class NameContradictionTests(unittest.TestCase):
    ORIGINAL = (
        "fun sha1(plaintext: ByteArray): String {\n"
        '    val digest = MessageDigest.getInstance("SHA-1")\n'
        "    return hex(digest.digest(plaintext))\n"
        "}\n"
    )

    def test_changing_the_algorithm_under_the_old_name_is_rejected_with_the_sibling(self):
        corrected = self.ORIGINAL.replace('"SHA-1"', '"SHA-256"')
        found = name_behavior_contradictions(self.ORIGINAL, corrected, (), GENERAL_KT)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["code"], "NAME_CONTRADICTS_BEHAVIOR")
        self.assertEqual(found[0]["name"], "sha1")
        self.assertEqual(found[0]["existing_alternatives"], ["sha256"])

    def test_a_renamed_function_or_an_unrelated_literal_is_not_a_contradiction(self):
        renamed = self.ORIGINAL.replace('"SHA-1"', '"SHA-256"').replace("fun sha1", "fun sha256")
        self.assertEqual(name_behavior_contradictions(self.ORIGINAL, renamed), [])
        encoding = (
            "fun decodeUtf8(b: ByteArray): String {\n"
            '    return String(b, charset("UTF-8"))\n'
            "}\n"
        )
        # An equivalent constant keeps the behaviour the name states.
        self.assertEqual(
            name_behavior_contradictions(encoding, encoding.replace('"UTF-8"', "Charsets.UTF_8")),
            [],
        )
        plain = 'String load() {\n    return read("data");\n}\n'
        self.assertEqual(name_behavior_contradictions(plain, plain.replace('"data"', '"other"')), [])

    # Fread's GlobalOkHttpClient (tls_20261015): "SSL" names the returned type.
    SSL_FACTORY = (
        "    private fun buildSSLFactory(): Pair<SSLSocketFactory, X509TrustManager> {\n"
        '        val sslContext = SSLContext.getInstance("SSL")\n'
        "        sslContext.init(null, arrayOf(trustManager), SecureRandom())\n"
        '        sslContext.defaultSSLParameters.protocols = arrayOf("SSLv3")\n'
        "        return sslContext.socketFactory to trustManager\n"
        "    }\n"
    )

    def test_a_name_echoing_a_type_it_uses_survives_a_protocol_change(self):
        corrected = (self.SSL_FACTORY.replace('"SSL"', '"TLS"')
                     .replace('        sslContext.defaultSSLParameters.protocols = arrayOf("SSLv3")\n', ""))
        self.assertEqual(name_behavior_contradictions(self.SSL_FACTORY, corrected), [])
        self.assertEqual(variable_name_contradictions(self.SSL_FACTORY, corrected), [])

    def test_a_type_word_must_be_whole_and_outside_comments_and_annotations(self):
        des = (
            "    fun encryptDES(file: FileDescriptor): ByteArray {\n"
            '        val cipher = Cipher.getInstance("DES")\n'
            "        return cipher.doFinal(read(file))\n"
            "    }\n"
        )
        self.assertEqual(len(name_behavior_contradictions(des, des.replace('"DES"', '"AES"'))), 1)
        # An annotation naming the word is not a type the code uses.
        suppressed = '    @RequiresSSL\n' + self.SSL_FACTORY.replace(
            "Pair<SSLSocketFactory, X509TrustManager>", "Pair<Any, X509TrustManager>")
        suppressed = suppressed.replace("SSLContext.getInstance", "Context.getInstance")
        self.assertEqual(
            [item["name"] for item in name_behavior_contradictions(
                suppressed, suppressed.replace('"SSL"', '"TLS"'))],
            ["buildSSLFactory"],
        )
        # BWT's EncryptDecryptHelper (rvsec_bwt_20261024): DES only in a
        # comment and an enum constant.
        bwt = (
            "    // DESKeySpec was the legacy format\n"
            "    fun encryptDES(data: ByteArray): ByteArray {\n"
            '        val cipher = Cipher.getInstance("DES")\n'
            "        log(Algorithm.DES)\n"
            "        return cipher.doFinal(data)\n"
            "    }\n"
        )
        corrected = bwt.replace('"DES"', '"AES"')
        self.assertEqual([item["name"] for item in name_behavior_contradictions(bwt, corrected)],
                         ["encryptDES"])
        # A class the code declares is its own name and exempts nothing.
        sha = ("object Sha1Util {\n    fun sha1(b: ByteArray): String {\n"
               '        return hex(MessageDigest.getInstance("SHA-1").digest(b))\n    }\n}\n')
        self.assertEqual(
            [item["name"] for item in name_behavior_contradictions(
                sha, sha.replace('"SHA-1"', '"SHA-256"'))],
            ["sha1"],
        )

    def test_the_coordinated_validator_reports_the_contradiction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            redreader_like_repository(root)
            result = validate_coordinated_semantics(
                {"repository_path": str(root), "source_file_path": GENERAL},
                [{
                    "source_file_path": GENERAL, "edit_kind": "production",
                    "original_code": self.ORIGINAL,
                    "corrected_code": self.ORIGINAL.replace('"SHA-1"', '"SHA-256"'),
                }],
            )
        codes = [item.get("code") for item in result["errors"]]
        self.assertIn("NAME_CONTRADICTS_BEHAVIOR", codes)
        self.assertEqual(result["status"], "invalid")


class RenameSafetyTests(unittest.TestCase):
    """rename_safety is a repository fact: hard blockers change the route of
    the fix, resolvable reasons only add references the patch updates."""

    def _assess(self, root, callers):
        return assess_rename_safety(root, GENERAL, "sha1", available(callers))

    def _assert_reason(self, reasons, expected):
        self.assertTrue(any(reason.startswith(expected) for reason in reasons), reasons)

    def test_a_single_application_method_with_resolved_callers_may_be_renamed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            result = self._assess(root, callers)
        self.assertTrue(result["allowed"], result["hard_blockers"])
        self.assertEqual(result["hard_blockers"], [])
        self.assertEqual(result["references"],
                         [{"path": MANAGER, "line": callers[0]["line"], "kind": "call"}])

    def test_names_in_scope_cover_the_file_and_its_package_in_the_module(self):
        from cognalys.extraction.rename_safety import compact_rename_safety

        sibling = GENERAL.rsplit("/", 1)[0] + "/Strings.kt"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            write(root, sibling, "package org.example.common\n\n"
                  "fun ByteArray.sha256Hex(): String = \"\"\n"
                  "val sha256Digest: String = \"\"\n")
            # Another package's declaration does not clash.
            write(root, "app/src/main/java/org/example/other/Other.kt",
                  "package org.example.other\n\nfun sha256Bytes() {}\n")
            result = self._assess(root, callers)
        names = result["names_in_scope"]
        self.assertTrue({"sha1", "sha256", "sha256Hex", "sha256Digest"} <= set(names), names)
        self.assertNotIn("sha256Bytes", names)
        compact = compact_rename_safety(result)
        self.assertEqual(compact["names_in_scope"], names)
        self.assertIn("must not be one of them", compact["free_name_rule"])

    def test_a_free_name_is_derived_from_the_planned_one(self):
        from cognalys.extraction.rename_safety import suggest_free_name

        self.assertEqual(suggest_free_name("sha256", {"sha1"}), "sha256")
        self.assertEqual(suggest_free_name("sha256", {"sha256"}), "sha256Hex")
        self.assertEqual(suggest_free_name("sha256", {"sha256", "sha256Hex"}), "sha256Digest")

    def test_conditions_no_build_or_edit_would_show_are_hard(self):
        cases = {
            "module_publishes_an_artifact": lambda root: write(
                root, "app/build.gradle",
                "plugins { id 'com.android.application'\n id 'maven-publish' }\n"),
            "module_is_not_an_application": lambda root: write(
                root, "app/build.gradle", "plugins { id 'com.android.library' }\n"),
            "referenced_outside_sources": lambda root: write(
                root, "app/proguard-rules.pro", "-keepclassmembers class * { *** sha1(...); }\n"),
            "name_in_string_literal": lambda root: write(
                root, "app/src/main/java/org/example/Reflect.java",
                'class Reflect { Object m = General.class.getMethod("sha1"); }\n'),
            "annotation_pins_or_overrides_the_name": lambda root: write(
                root, GENERAL, GENERAL_KT.replace("    @JvmStatic\n    fun sha1",
                                                  "    @Keep\n    fun sha1")),
            "referenced_outside_sources:app/src/main/res/layout": lambda root: write(
                root, "app/src/main/res/layout/main.xml",
                '<Button android:onClick="sha1" />\n'),
            "declared_inside_an_interface": lambda root: write(
                root, GENERAL, GENERAL_KT.replace("object General {",
                                                  "interface General {")),
            "reference_outside_the_built_sources:app/src/jvmMain": lambda root: write(
                root, "app/src/jvmMain/kotlin/org/example/Desktop.kt",
                "fun d(b: ByteArray) = General.sha1(b)\n"),
            "reference_outside_the_built_sources:app/src/paid": lambda root: (
                write(root, "app/build.gradle",
                      "plugins { id 'com.android.application' }\nandroid {\n"
                      " flavorDimensions 'tier'\n productFlavors {\n"
                      "  free { dimension 'tier' }\n  paid { dimension 'tier' }\n }\n}\n"),
                write(root, "app/src/paid/java/org/example/Paid.java",
                      "class Paid { String k(byte[] b) { return General.sha1(b); } }\n")),
        }
        for expected, mutate in cases.items():
            with self.subTest(expected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                callers = redreader_like_repository(root)
                mutate(root)
                result = self._assess(root, callers)
                self.assertFalse(result["allowed"])
                self._assert_reason(result["hard_blockers"], expected)

    def test_a_java_override_without_the_annotation_is_hard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "app/build.gradle", APP_BUILD)
            base = "app/src/main/java/org/example/Base.java"
            child = "app/src/main/java/org/example/Child.java"
            write(root, base, "class Base {\n    String digest(byte[] b) { return null; }\n}\n")
            write(root, child, "class Child extends Base {\n"
                               "    String digest(byte[] b) { return md(\"MD5\"); }\n}\n")
            result = assess_rename_safety(root, child, "digest", available([]))
        self._assert_reason(result["hard_blockers"], "java_override_without_annotation")

    def test_a_constructor_is_never_renamed_and_reads_as_no_override(self):
        """SMSecure's ConversationListAdapter(...) extends Adapter<ConversationListAdapter.VH>:
        its own name in a type argument is not a supertype."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "app/build.gradle", APP_BUILD)
            adapter = "app/src/main/java/org/example/ConversationListAdapter.java"
            write(root, adapter,
                  "class ConversationListAdapter extends Base<ConversationListAdapter.Holder> {\n"
                  "    ConversationListAdapter(Context c) { md(\"MD5\"); }\n}\n")
            result = assess_rename_safety(root, adapter, "ConversationListAdapter", available([]))
        self._assert_reason(result["hard_blockers"], "constructor_or_type_name")
        self.assertFalse([item for item in result["hard_blockers"]
                          if item.startswith("java_override_without_annotation")])

    def test_every_declaration_of_a_family_is_checked_for_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            write(root, GENERAL, GENERAL_KT.replace(
                "    @JvmStatic\n    fun sha256",
                "    fun sha1(text: String): String = text\n\n"
                "    override fun toString(): String = \"\"\n\n"
                "    @JvmStatic\n    fun sha256").replace(
                "fun sha1(text: String)", "open fun sha1(text: String)"))
            result = self._assess(root, callers)
        self._assert_reason(result["hard_blockers"], "override_or_overridable_declaration")

    def test_what_the_patch_can_update_is_resolvable(self):
        cases = {
            "overload_family_in_the_reported_file": lambda root: write(
                root, GENERAL, GENERAL_KT.replace(
                    "    @JvmStatic\n    fun sha256",
                    "    fun sha1(text: String): String = sha1(text.toByteArray())\n\n"
                    "    @JvmStatic\n    fun sha256")),
            "calls_not_in_the_semantic_resolution": lambda root: write(
                root, "app/src/main/java/org/example/Other.java",
                "class Other { String k(byte[] b) { return General.sha1(b); } }\n"),
            "method_references": lambda root: write(
                root, "app/src/main/java/org/example/Ref.kt",
                "val f = General::sha1\n"),
            "same_name_declared_elsewhere_in_the_repository": lambda root: write(
                root, "app/src/main/java/org/example/Legacy.kt",
                "object Legacy {\n    fun sha1(b: ByteArray): String = \"\"\n}\n"),
            "unrelated_interface_in_the_declaring_file": lambda root: write(
                root, GENERAL, GENERAL_KT + "\ninterface Listener {\n    fun done()\n}\n"),
            "in_repository_library_module_used_by": lambda root: (
                write(root, "app/build.gradle", "plugins { id 'com.android.library' }\n"),
                write(root, "phone/build.gradle",
                      "plugins { id 'com.android.application' }\n"
                      "dependencies { implementation project(':app') }\n")),
        }
        for expected, mutate in cases.items():
            with self.subTest(expected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                callers = redreader_like_repository(root)
                mutate(root)
                result = self._assess(root, callers)
                self.assertTrue(result["allowed"], result["hard_blockers"])
                self._assert_reason(result["resolvable"], expected)

    def test_prose_in_string_resources_and_changelogs_is_no_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            write(root, "app/src/main/res/values/strings.xml",
                  "<resources><string name=\"about\">uses sha1 for names</string></resources>\n")
            write(root, "fastlane/metadata/android/en-US/changelogs/12.txt", "Faster sha1.\n")
            result = self._assess(root, callers)
        self.assertTrue(result["allowed"], result["hard_blockers"])
        self.assertFalse([item for item in result["resolvable"] if "outside" in item])

    def test_resource_names_and_ids_are_no_reference(self):
        """Crypto apps name resources after the operation (KeyPass encrypt/decrypt):
        a resource is read through R, never by the method's name."""
        cases = {
            "app/src/main/res/values/strings.xml":
                '<resources><string name="sha1">SHA-1</string></resources>\n',
            "app/src/main/res/layout/main.xml":
                '<Button android:id="@+id/sha1" android:text="@string/sha1" />\n',
        }
        for path, text in cases.items():
            with self.subTest(path), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                callers = redreader_like_repository(root)
                write(root, path, text)
                result = self._assess(root, callers)
                self.assertTrue(result["allowed"], result["hard_blockers"])

    def test_a_data_binding_expression_is_a_reference(self):
        for value in ("@{() -> vm.sha1(bytes)}", "@{vm::sha1}"):
            with self.subTest(value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                callers = redreader_like_repository(root)
                write(root, "app/src/main/res/layout/main.xml",
                      f'<Button android:onClick="{value}" />\n')
                result = self._assess(root, callers)
                self.assertFalse(result["allowed"])
                self._assert_reason(result["hard_blockers"], "referenced_outside_sources:app/src/main/res/layout")

    def test_import_lines_and_method_references_are_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            user = "app/src/main/java/org/example/Use.kt"
            write(root, user, "package org.example\n\nimport org.example.common.General.sha1\n\n"
                              "val f = General::sha1\n")
            result = self._assess(root, callers)
        kinds = {(item["path"], item["kind"]) for item in result["references"]}
        self.assertIn((user, "import"), kinds)
        self.assertIn((user, "method_reference"), kinds)

    def test_a_nullable_or_generic_extension_receiver_is_a_declaration(self):
        """It used to read as a call of the name, not a second declaration."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            write(root, "app/src/main/java/org/example/Ext.kt",
                  "fun List<Byte>?.sha1(): String = \"\"\n")
            result = self._assess(root, callers)
        self._assert_reason(result["resolvable"], "same_name_declared_elsewhere_in_the_repository")
        self.assertFalse(any(reason.startswith("calls_not_in_the_semantic_resolution")
                             for reason in result["resolvable"]), result["resolvable"])

    def test_unattributable_calls_beside_a_same_named_declaration_are_hard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            redreader_like_repository(root)
            write(root, "app/src/main/java/org/example/Legacy.kt",
                  "object Legacy {\n    fun sha1(b: ByteArray): String = \"\"\n}\n")
            result = assess_rename_safety(root, GENERAL, "sha1", {"status": "unresolved"})
        self._assert_reason(result["hard_blockers"],
                            "unattributable_calls_with_same_name_declared_elsewhere")

    def test_unavailable_or_ambiguous_resolution_is_resolvable_when_every_lexical_reference_is_updated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            unresolved = assess_rename_safety(root, GENERAL, "sha1", {"status": "unresolved"})
            ambiguous = assess_rename_safety(root, GENERAL, "sha1", {
                **available(callers), "ambiguous_calls": [{"path": MANAGER}],
            })
        self.assertTrue(unresolved["allowed"], unresolved["hard_blockers"])
        self.assertIn("semantic_resolution_unavailable", unresolved["resolvable"])
        self.assertIn("ambiguous_same_name_calls", ambiguous["resolvable"])
        # Every lexical call is listed, so the validator demands its update.
        self.assertEqual([item["path"] for item in unresolved["references"]], [MANAGER])

    def test_the_overload_family_of_an_extension_is_renamable(self):
        """NotallyX: Context/File/InputStream.md5Hash in one file."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "app/build.gradle.kts", 'plugins { id("com.android.application") }\n')
            write(root, IO_EXTENSIONS, IO_EXTENSIONS_KT)
            write(root, EXPORT, EXPORT_KT)
            result = assess_rename_safety(root, IO_EXTENSIONS, "md5Hash", {"status": "unresolved"})
        self.assertTrue(result["allowed"], result["hard_blockers"])
        self._assert_reason(result["resolvable"], "overload_family_in_the_reported_file:3")
        self.assertEqual(
            {(item["path"], item["kind"]) for item in result["references"]},
            {(IO_EXTENSIONS, "call"), (EXPORT, "call"), (EXPORT, "import")})


IO_EXTENSIONS = "app/src/main/java/com/example/utils/IOExtensions.kt"
EXPORT = "app/src/main/java/com/example/backup/ExportExtensions.kt"
IO_EXTENSIONS_KT = """package com.example.utils

import java.io.File
import java.io.InputStream
import java.security.MessageDigest

internal fun Context.md5Hash(name: String): ByteArray {
    return File(name).md5Hash()
}

internal fun File.md5Hash(): ByteArray {
    return inputStream().md5Hash()
}

internal fun InputStream.md5Hash(): ByteArray {
    val digest = MessageDigest.getInstance("MD5")
    return digest.digest(readBytes())
}
"""
EXPORT_KT = """package com.example.backup

import com.example.utils.md5Hash

internal fun verify(source: java.io.File, target: java.io.File): Boolean {
    val sourceMd5 = source.md5Hash()
    val targetMd5 = target.md5Hash()
    return sourceMd5.contentEquals(targetMd5)
}
"""



class RenameDetectionTests(unittest.TestCase):
    def test_the_rename_is_named_when_other_declarations_also_disappear(self):
        """zSMTH: getUnsafeOkHttpClient renamed while an anonymous TrustManager,
        whose getAcceptedIssuers() also takes no arguments, was removed."""
        from cognalys.llm.semantic_validation import detected_renames

        original = (
            "  private static OkHttpClient getUnsafeOkHttpClient() {\n"
            "    TrustManager[] all = new TrustManager[] { new X509TrustManager() {\n"
            "      public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{}; }\n"
            "    } };\n"
            "    return null;\n"
            "  }\n")
        corrected = (
            "  private static OkHttpClient getSecureOkHttpClient() {\n"
            "    return null;\n"
            "  }\n")
        self.assertEqual(detected_renames(original, corrected),
                         [("getUnsafeOkHttpClient", "getSecureOkHttpClient")])

    def test_removing_an_anonymous_class_and_adding_helpers_is_no_rename(self):
        """zSMTH run5: `new X509TrustManager() {` read as a declaration."""
        from cognalys.llm.semantic_validation import declared_function_signatures, detected_renames

        original = (
            "  private static OkHttpClient getUnsafeOkHttpClient() {\n"
            "    final TrustManager[] all = new TrustManager[] {\n"
            "        new X509TrustManager() {\n"
            "          public X509Certificate[] getAcceptedIssuers() { return null; }\n"
            "        }\n"
            "    };\n"
            "  }\n")
        corrected = (
            "  private static OkHttpClient getUnsafeOkHttpClient() {\n"
            "    return build(createCompositeTrustManager());\n"
            "  }\n"
            "  private static X509TrustManager createCompositeTrustManager() {\n"
            "    return null;\n"
            "  }\n")
        self.assertNotIn("X509TrustManager", declared_function_signatures(original))
        self.assertEqual(detected_renames(original, corrected), [])

    def test_an_ambiguous_pairing_names_no_rename(self):
        from cognalys.llm.semantic_validation import detected_renames

        original = "  void alpha() {\n  }\n  void beta() {\n  }\n"
        corrected = "  void gamma() {\n  }\n"
        self.assertEqual(detected_renames(original, corrected), [])

    def test_a_replaced_override_is_no_rename(self):
        """LocalSend (2026-10-29): an accept-any X509TrustManager object gave
        way to a TrustManagerFactorySpi; getAcceptedIssuers() ->
        engineGetTrustManagers() was reported as an unauthorized rename."""
        from cognalys.llm.semantic_validation import detected_renames

        original = (
            "    private object AcceptAnyTrustManager : X509TrustManager {\n"
            "        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit\n"
            "        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()\n"
            "    }\n")
        corrected = (
            "    internal class PinnedTrustManagerFactorySpi : TrustManagerFactorySpi() {\n"
            "        override fun engineInit(keyStore: KeyStore?) {\n"
            "        }\n"
            "        override fun engineGetTrustManagers(): Array<TrustManager> =\n"
            "            arrayOf(manager)\n"
            "    }\n")
        self.assertEqual(detected_renames(original, corrected), [])
        java_original = ("    @Override\n    public X509Certificate[] getAcceptedIssuers() {\n"
                         "        return null;\n    }\n")
        java_corrected = ("    @Override\n    protected TrustManager[] engineGetTrustManagers() {\n"
                          "        return managers;\n    }\n")
        self.assertEqual(detected_renames(java_original, java_corrected), [])

    def test_an_extracted_helper_is_not_a_second_rename(self):
        """BlueGate (2026-10-29): generateNewKeyPair(alias) was renamed and a
        helper with the same parameters extracted; both were its rename."""
        from cognalys.llm.semantic_validation import detected_renames

        original = (
            "    private fun generateNewKeyPair(alias: String): KeyPair {\n"
            "        return generator.generateKeyPair()\n"
            "    }\n")
        corrected = (
            "    private fun generateNewKeyMaterial(alias: String): KeyMaterial {\n"
            "        val parameterSpec = prepareKeyGenParameterSpec(alias)\n"
            "        return KeyMaterial(generator.generateKeyPair())\n"
            "    }\n"
            "    private fun prepareKeyGenParameterSpec(alias: String): KeyGenParameterSpec =\n"
            "        KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN).build()\n")
        self.assertEqual(detected_renames(original, corrected),
                         [("generateNewKeyPair", "generateNewKeyMaterial")])


class RenameValidationTests(unittest.TestCase):
    DECLARATION = "fun sha1(plaintext: ByteArray): String {\n    return x(\"SHA-1\")\n}\n"
    CALLER = '        return General.sha1(user.getBytes()) + "_" + type + "_subreddits.db";\n'

    def _edits(self, new_name="sha256Bytes", update_caller=True):
        edits = [{
            "source_file_path": GENERAL, "edit_kind": "production",
            "original_code": self.DECLARATION,
            "corrected_code": self.DECLARATION.replace("sha1", new_name)
            .replace('"SHA-1"', '"SHA-256"'),
        }]
        if update_caller:
            edits.append({
                "source_file_path": MANAGER, "edit_kind": "production",
                "original_code": self.CALLER,
                "corrected_code": self.CALLER.replace("sha1", new_name),
            })
        return edits

    def _error(self, root, callers, allowed=True):
        return {
            "repository_path": str(root),
            "rename_safety": {
                "allowed": allowed, "symbol": "sha1",
                "declaration": {"path": GENERAL, "line": 7},
                "references": callers,
                "blocked_by": [] if allowed else ["module_is_not_an_application"],
            },
        }

    def test_an_authorized_rename_updating_every_reference_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            errors, accepted = rename_issues(self._error(root, callers), self._edits())
        self.assertEqual(errors, [])
        self.assertEqual(accepted, {("sha1", "sha256Bytes")})

    def test_renames_that_are_unauthorized_incomplete_or_colliding_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            unauthorized, _ = rename_issues(self._error(root, callers, allowed=False), self._edits())
            incomplete, _ = rename_issues(self._error(root, callers),
                                          self._edits(update_caller=False))
            colliding, _ = rename_issues(self._error(root, callers), self._edits("sha256"))
        self.assertEqual(unauthorized[0]["code"], "UNAUTHORIZED_RENAME")
        # The retry is told the rule and the non-rename route, with the reason.
        self.assertIn("module_is_not_an_application", unauthorized[0]["hint"])
        self.assertIn("add a correctly named function", unauthorized[0]["hint"])
        self.assertEqual(incomplete[0]["code"], "RENAME_REFERENCES_NOT_UPDATED")
        self.assertEqual(colliding[0]["code"], "RENAME_TARGET_ALREADY_DECLARED")
        # The retry learns which names are taken and one that is free
        # (RedReader's General.sha1, 2026-11-03).
        self.assertIn("sha256", colliding[0]["declared_names"])
        self.assertEqual(colliding[0]["suggested_name"], "sha256Hex")
        self.assertIn("sha256Hex", colliding[0]["hint"])

    def test_the_rename_retry_names_the_free_name(self):
        from cognalys.llm.semantic_validation import rename_retry_guidance

        errors = [{"code": "RENAME_TARGET_ALREADY_DECLARED", "path": GENERAL,
                   "details": [f"sha256 is already declared in {GENERAL}"],
                   "declared_names": ["sha1", "sha256"], "suggested_name": "sha256Hex"}]
        guidance = rename_retry_guidance(errors, [GENERAL], last_attempt=False)
        self.assertIn("a free name is sha256Hex", guidance)

    def _family_edits(self, import_updated=True, family=("md5Hash", "md5Hash", "md5Hash")):
        new = "sha256Hash"
        declaring = IO_EXTENSIONS_KT[IO_EXTENSIONS_KT.index("internal fun Context"):]
        corrected = declaring.replace('"MD5"', '"SHA-256"')
        for index, name in enumerate(family):
            target = ["Context.md5Hash", "File.md5Hash", "InputStream.md5Hash"][index]
            corrected = corrected.replace(target, target.replace("md5Hash", new if name == "md5Hash"
                                                                  else name))
        corrected = corrected.replace("File(name).md5Hash()", f"File(name).{new}()").replace(
            "inputStream().md5Hash()", f"inputStream().{new}()")
        caller = EXPORT_KT[EXPORT_KT.index("import"):]
        corrected_caller = caller.replace(".md5Hash()", f".{new}()").replace(
            "Md5 =", "Sha256 =").replace("sourceMd5.contentEquals(targetMd5)",
                                         "sourceSha256.contentEquals(targetSha256)")
        if import_updated:
            corrected_caller = corrected_caller.replace("utils.md5Hash", f"utils.{new}")
        return [
            {"source_file_path": IO_EXTENSIONS, "edit_kind": "method",
             "original_code": declaring, "corrected_code": corrected},
            {"source_file_path": EXPORT, "edit_kind": "method",
             "original_code": caller, "corrected_code": corrected_caller},
        ]

    def _family_error(self, root):
        write(root, "app/build.gradle.kts", 'plugins { id("com.android.application") }\n')
        write(root, IO_EXTENSIONS, IO_EXTENSIONS_KT)
        write(root, EXPORT, EXPORT_KT)
        return {
            "repository_path": str(root),
            "rename_safety": assess_rename_safety(
                root, IO_EXTENSIONS, "md5Hash", {"status": "unresolved"}),
        }

    def test_a_family_rename_with_callers_and_import_updated_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            error = self._family_error(root)
            errors, accepted = rename_issues(error, self._family_edits())
        self.assertEqual(errors, [])
        self.assertEqual(accepted, {("md5Hash", "sha256Hash")})

    def test_a_stale_import_fails_with_its_file_and_line(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            error = self._family_error(root)
            errors, accepted = rename_issues(error, self._family_edits(import_updated=False))
        self.assertEqual(accepted, set())
        self.assertEqual(errors[0]["code"], "RENAME_REFERENCES_NOT_UPDATED")
        self.assertIn(f"{EXPORT}:3: import com.example.utils.md5Hash", errors[0]["details"])
        self.assertIn(EXPORT, errors[0]["retry_paths"])
        self.assertIn(f"{EXPORT}:3", errors[0]["hint"])

    def test_renaming_one_overload_of_a_family_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            error = self._family_error(root)
            declaring = IO_EXTENSIONS_KT[IO_EXTENSIONS_KT.index("internal fun InputStream"):]
            edits = [{"source_file_path": IO_EXTENSIONS, "edit_kind": "method",
                      "original_code": declaring,
                      "corrected_code": declaring.replace("md5Hash", "sha256Hash")
                      .replace('"MD5"', '"SHA-256"')}]
            errors, _ = rename_issues(error, edits)
        self.assertEqual(errors[0]["code"], "RENAME_PARTIAL_FAMILY")

    def test_a_call_left_on_the_old_name_beside_a_same_named_declaration_rebinds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            write(root, "app/src/main/java/org/example/Legacy.kt",
                  "object Legacy {\n    fun sha1(b: ByteArray): String = \"\"\n}\n")
            error = {"repository_path": str(root),
                     "rename_safety": assess_rename_safety(root, GENERAL, "sha1",
                                                           available(callers))}
            errors, _ = rename_issues(error, self._edits(update_caller=False))
        self.assertEqual(errors[0]["code"], "RENAME_CALL_REBINDS")
        self.assertIn(f"{MANAGER}:{callers[0]['line']}", errors[0]["details"][0])

    def test_a_rename_of_a_non_reported_helper_is_assessed_on_its_own(self):
        """rename_issues used to authorise the reported symbol alone."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            error = self._error(root, callers)
            error["rename_safety"]["symbol"] = "reportedElsewhere"
            with mock.patch("cognalys.extraction.semantic_index.build_semantic_index",
                            return_value=available(callers)):
                errors, accepted = rename_issues(error, self._edits())
        self.assertEqual(errors, [])
        self.assertEqual(accepted, {("sha1", "sha256Bytes")})
        self.assertIn(f"{GENERAL}#sha1", error["rename_safety_by_symbol"])

    def test_an_accepted_kotlin_top_level_rename_widens_no_public_api(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "app/build.gradle", APP_BUILD)
            top = "app/src/main/java/org/example/Hash.kt"
            user = "app/src/main/java/org/example/User.kt"
            source = "package org.example\n\nfun md5(b: ByteArray): ByteArray = d(b, \"MD5\")\n"
            caller = "package org.example\n\nval h = md5(byteArrayOf())\n"
            write(root, top, source)
            write(root, user, caller)
            error = {"repository_path": str(root),
                     "rename_safety": assess_rename_safety(root, top, "md5", {"status": "unresolved"})}
            edits = [
                {"source_file_path": top, "edit_kind": "method",
                 "original_code": "fun md5(b: ByteArray): ByteArray = d(b, \"MD5\")\n",
                 "corrected_code": "fun sha256(b: ByteArray): ByteArray = d(b, \"SHA-256\")\n"},
                {"source_file_path": user, "edit_kind": "method",
                 "original_code": "val h = md5(byteArrayOf())\n",
                 "corrected_code": "val h = sha256(byteArrayOf())\n"},
            ]
            result = validate_coordinated_semantics(error, edits)
        codes = {item["code"] for item in result["errors"]}
        self.assertNotIn("UNNECESSARY_PUBLIC_API_EXPANSION", codes)
        self.assertNotIn("PUBLIC_API_CONTRACT_CHANGED", codes)
        self.assertNotIn("UNAUTHORIZED_RENAME", codes)

    def test_a_kotlin_return_of_the_call_is_a_reference_not_a_declaration(self):
        """BlueGate (2026-10-29): `return generateNewKeyMaterial(alias)` has no
        semicolon and read as a Java declaration with return type `return`, so
        the moved reference was never counted ("move 0 and write 0")."""
        from cognalys.extraction.rename_safety import _declaration_pattern
        from cognalys.llm.semantic_validation import _reference_count

        line = "        return generateNewKeyMaterial(alias)\n"
        self.assertIsNone(_declaration_pattern("generateNewKeyMaterial").search(line))
        self.assertEqual(_reference_count(line, "generateNewKeyMaterial"), 1)
        for declaration in ("    private fun generateNewKeyMaterial(alias: String): KeyMaterial {",
                            "    public KeyMaterial generateNewKeyMaterial(String alias) {",
                            "    returnValue generateNewKeyMaterial(String alias) {"):
            self.assertIsNotNone(_declaration_pattern("generateNewKeyMaterial").search(declaration))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manager = "app/src/main/java/org/example/KeyManager.kt"
            source = ("package org.example\n\nclass KeyManager {\n"
                      "    fun getOrCreateKeyPair(): KeyPair {\n"
                      "        return generateNewKeyPair(alias)\n"
                      "    }\n\n"
                      "    private fun generateNewKeyPair(alias: String): KeyPair {\n"
                      "        return generator.generateKeyPair()\n"
                      "    }\n}\n")
            write(root, "app/build.gradle", APP_BUILD)
            write(root, manager, source)
            body = source[source.index("    fun getOrCreateKeyPair"):source.rindex("}")]
            error = {"repository_path": str(root),
                     "rename_safety": assess_rename_safety(
                         root, manager, "generateNewKeyPair", {"status": "unresolved"})}
            errors, accepted = rename_issues(error, [{
                "source_file_path": manager, "edit_kind": "method", "original_code": body,
                "corrected_code": body.replace("generateNewKeyPair", "generateNewKeyMaterial")}])
        self.assertEqual(error["rename_safety"]["hard_blockers"], [])
        self.assertEqual(errors, [])
        self.assertEqual(accepted, {("generateNewKeyPair", "generateNewKeyMaterial")})

    def test_a_new_name_that_still_states_the_removed_algorithm_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            callers = redreader_like_repository(root)
            errors, _ = rename_issues(self._error(root, callers), self._edits("legacySha1Bytes"))
        self.assertEqual(errors[0]["code"], "NAME_CONTRADICTS_BEHAVIOR")


class ClosedPullRequestOutcomeTests(unittest.TestCase):
    METADATA = {
        "repo_owner": "QuantumBadger", "repo_name": "RedReader",
        "spec": "MessageDigestSpec", "csv_class": "org.quantumbadger.redreader.common.General",
        "method_name": "sha1", "finding_id": "f-1",
    }

    def test_a_closed_pull_request_blocks_the_same_finding_only(self):
        with tempfile.TemporaryDirectory() as directory:
            outcomes = Path(directory)
            record_pr_outcome(
                self.METADATA, {"html_url": "https://github.com/QuantumBadger/RedReader/pull/1373"},
                {"status": "closed"},
                [{"author": "QuantumBadger", "kind": "comment",
                  "body": "The premise is incorrect: this is a database file name."}],
                outcomes,
            )
            rejected = rejected_outcome_for(self.METADATA, outcomes)
            other_method = rejected_outcome_for({**self.METADATA, "method_name": "sha256"}, outcomes)
            other_repo = rejected_outcome_for({**self.METADATA, "repo_name": "Other"}, outcomes)
        self.assertIn("premise", rejected["maintainer_feedback"][0]["body"])
        self.assertIsNone(other_method)
        self.assertIsNone(other_repo)

    def test_a_merged_pull_request_does_not_block(self):
        with tempfile.TemporaryDirectory() as directory:
            outcomes = Path(directory)
            record_pr_outcome(self.METADATA, {"html_url": "u"}, {"status": "merged"}, [], outcomes)
            self.assertIsNone(rejected_outcome_for(self.METADATA, outcomes))

    def test_publication_is_blocked_for_a_rejected_finding(self):
        from cognalys.prs import pr_creator

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "finding.json"
            path.write_text(json.dumps(self.METADATA), encoding="utf-8")
            with mock.patch.object(pr_creator, "rejected_outcome_for",
                                   return_value={"pull_request": "u", "maintainer_feedback": []}):
                creator = pr_creator.AutomatedPRCreator(dry_run=True)
                self.assertEqual(creator.process_pr_file(path), "blocked")


if __name__ == "__main__":
    unittest.main()
