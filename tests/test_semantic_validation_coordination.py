"""A coordinated patch must be judged by what it will read once applied.

Two checks in semantic_validation.py judge a multi-file patch fragment by
fragment, and each had a blind spot that could only show up across files:

  unresolved_repository_symbols  resolved a receiver's type from the
                                 checkout on disk, never from what a
                                 sibling file in the SAME patch adds. A
                                 method one file declares and another file
                                 in the same coordinated edit calls read as
                                 SYMBOL_NOT_DECLARED_IN_REPOSITORY.
  the checked-exception check    treated "the exception's name literally
                                 appears somewhere in this fragment" as the
                                 only way a checked exception could be
                                 handled, so `catch (Exception e)` -- which
                                 structurally handles every checked
                                 exception without naming any of them --
                                 was invisible to it.

Both fired together on run_20260922_134405's dnsfilter.android
processIPPackageMode patch: DNSResolver.java added closeResponseOutput()
(declared `throws IOException`), DNSFilterService.java called it from
inside the repository's own pre-existing `catch (Exception e)` block, and
the coordinated patch -- cause confirmed, scope complete, high confidence --
was rejected for calling an undeclared method that does not propagate an
exception it does not declare. The real edits from that run are pinned here
as the primary regression; the rest are synthetic and isolate each half of
the fix, including the cases the fix must not silence.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.semantic_validation import (  # noqa: E402
    _coordinated_overlay,
    caller_iv_on_randomized_keystore_key,
    repository_type_source,
    unresolved_repository_symbols,
    validate_coordinated_semantics,
)

DRAFT_DIR = (
    ROOT / "outputs" / "run_20260922_134405" / "error_solutions"
    / "coordinated_drafts" / "dnsfilter.android_1505401.apk" / "0_processIPPackageMode"
)


@unittest.skipUnless(DRAFT_DIR.is_dir(), "run_20260922_134405 artifacts are not present")
class DnsfilterRegressionTests(unittest.TestCase):
    """The exact coordinated edit that run_20260922_134405 wrongly rejected."""

    def _edits(self):
        resolver = json.loads(
            (DRAFT_DIR / "01_DNSResolver.java.json").read_text(encoding="utf-8"))
        service = json.loads(
            (DRAFT_DIR / "02_DNSFilterService.java.json").read_text(encoding="utf-8"))
        return resolver["edits"] + service["edits"]

    def test_the_coordinated_patch_validates(self):
        error = {"repository_path": str(
            ROOT / "outputs" / "cloned_projects" / "dnsfilter.android_1505401.apk"
        )}
        if not Path(error["repository_path"]).is_dir():
            self.skipTest("the dnsfilter clone is not present")
        result = validate_coordinated_semantics(error, self._edits())
        self.assertEqual(result, {"status": "valid", "errors": [], "warnings": []})


class CoordinatedOverlayTests(unittest.TestCase):
    """The overlay applies every edit the same way solution_applicator does."""

    def test_edits_to_one_file_apply_in_order(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "A.java").write_text("class A {\n  int x;\n}\n", encoding="utf-8")
            overlay = _coordinated_overlay(repo, [
                {"source_file_path": "A.java", "original_code": "int x;",
                 "corrected_code": "int x;\n  int y;", "edit_kind": "declaration"},
                {"source_file_path": "A.java", "original_code": "int y;",
                 "corrected_code": "int y;\n  int z;", "edit_kind": "declaration"},
            ])
        self.assertIn("int z;", overlay["A.java"])

    def test_a_create_edit_needs_no_base_file(self):
        overlay = _coordinated_overlay(Path("/no/such/dir"), [
            {"source_file_path": "New.java", "corrected_code": "class New {}",
             "edit_kind": "create"},
        ])
        self.assertEqual(overlay["New.java"], "class New {}")

    def test_an_edit_whose_original_is_absent_is_skipped_not_raised(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "A.java").write_text("class A {}\n", encoding="utf-8")
            overlay = _coordinated_overlay(repo, [
                {"source_file_path": "A.java", "original_code": "nope",
                 "corrected_code": "class A { int y; }"},
            ])
        self.assertEqual(overlay["A.java"], "class A {}\n")

    def test_overlay_is_preferred_over_disk_by_repository_type_source(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "A.java").write_text("class A {\n}\n", encoding="utf-8")
            overlay = {"A.java": "class A {\n  void m() {}\n}\n"}
            source = repository_type_source(repo, "A", {}, overlay)
        self.assertIn("void m()", source)


class SiblingMethodResolutionTests(unittest.TestCase):
    """A call to a method a sibling file's edit declares is not invented."""

    def _repo(self, directory, resolver_body, service_body):
        repo = Path(directory)
        (repo / "Resolver.java").write_text(resolver_body, encoding="utf-8")
        (repo / "Service.java").write_text(service_body, encoding="utf-8")
        return repo

    def test_a_method_added_by_a_sibling_edit_is_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repo(
                directory,
                "class Resolver {\n  void run() {}\n}\n",
                "class Service {\n  void stop() {\n    Resolver r = new Resolver();\n"
                "    r.run();\n  }\n}\n",
            )
            edits = [
                {"source_file_path": "Resolver.java",
                 "original_code": "void run() {}",
                 "corrected_code": "void run() {}\n  void closeIt() throws java.io.IOException {}"},
                {"source_file_path": "Service.java",
                 "original_code": "r.run();",
                 "corrected_code": "Resolver r2 = r;\n    r2.closeIt();"},
            ]
            issues = unresolved_repository_symbols({"repository_path": str(repo)}, edits)
        self.assertEqual(issues, [])

    def test_a_call_to_a_method_nothing_declares_is_still_caught(self):
        # The fix must not silence the defect the check exists to catch: the
        # receiver's type is declared right in this fragment (as in the
        # passing case above), but no sibling edit and no repository file
        # declares the called method.
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repo(
                directory,
                "class Resolver {\n  void run() {}\n}\n",
                "class Service {\n  void stop() {}\n}\n",
            )
            edits = [
                {"source_file_path": "Service.java",
                 "original_code": "void stop() {}",
                 "corrected_code":
                 "void stop() {\n    Resolver r = new Resolver();\n    r.closeIt();\n  }"},
            ]
            issues = unresolved_repository_symbols({"repository_path": str(repo)}, edits)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["code"], "SYMBOL_NOT_DECLARED_IN_REPOSITORY")

    def test_a_package_qualified_receiver_is_not_the_repositorys_namesake(self):
        """Cryptomator declares its own Cipher; javax.crypto.Cipher.getInstance is not it."""
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repo(
                directory,
                "package org.cryptomator.util.crypto;\npublic interface Cipher {\n"
                "  byte[] encrypt(byte[] d);\n}\n",
                "package org.cryptomator.util.crypto;\nclass Service {\n  void stop() {}\n}\n",
            )
            (repo / "Resolver.java").rename(repo / "Cipher.java")
            qualified = [
                {"source_file_path": "Service.java", "original_code": "void stop() {}",
                 "corrected_code": "void stop() {\n    javax.crypto.Cipher c = "
                                   "javax.crypto.Cipher.getInstance(\"AES\");\n  }"}]
            self.assertEqual(unresolved_repository_symbols({"repository_path": str(repo)}, qualified), [])
            own = [
                {"source_file_path": "Service.java", "original_code": "void stop() {}",
                 "corrected_code": "void stop() {\n    org.cryptomator.util.crypto.Cipher.getInstance(\"AES\");\n  }"}]
            issues = unresolved_repository_symbols({"repository_path": str(repo)}, own)
        self.assertEqual([issue["code"] for issue in issues], ["SYMBOL_NOT_DECLARED_IN_REPOSITORY"])


class BroadCatchHandlesCheckedExceptionTests(unittest.TestCase):
    """`catch (Exception e)` covers a checked exception it never names."""

    def _validate(self, edits):
        return validate_coordinated_semantics(
            {"repository_path": str(ROOT)}, edits,
        )

    def test_a_bare_exception_catch_satisfies_a_named_checked_exception(self):
        edits = [
            {"source_file_path": "A.java", "edit_kind": "method",
             "original_code": "", "corrected_code":
             "void close() throws java.io.IOException {}"},
            {"source_file_path": "B.java", "edit_kind": "method",
             "original_code": "", "corrected_code":
             "void stop() {\n  try {\n    a.close();\n  } catch (Exception e) {\n"
             "    log(e);\n  }\n}"},
        ]
        result = self._validate(edits)
        self.assertEqual(
            [e for e in result["errors"] if e["code"] == "CHECKED_EXCEPTION_NOT_PROPAGATED"],
            [],
        )

    def test_a_throwable_catch_also_satisfies_it(self):
        edits = [
            {"source_file_path": "A.java", "edit_kind": "method",
             "original_code": "", "corrected_code":
             "void close() throws java.io.IOException {}"},
            {"source_file_path": "B.java", "edit_kind": "method",
             "original_code": "", "corrected_code":
             "void stop() {\n  try {\n    a.close();\n  } catch (Throwable t) {\n"
             "  }\n}"},
        ]
        result = self._validate(edits)
        self.assertEqual(
            [e for e in result["errors"] if e["code"] == "CHECKED_EXCEPTION_NOT_PROPAGATED"],
            [],
        )

    def test_a_method_declaring_throws_exception_also_satisfies_it(self):
        edits = [
            {"source_file_path": "A.java", "edit_kind": "method",
             "original_code": "", "corrected_code":
             "void close() throws java.io.IOException {}"},
            {"source_file_path": "B.java", "edit_kind": "method",
             "original_code": "", "corrected_code":
             "void stop() throws Exception {\n  a.close();\n}"},
        ]
        result = self._validate(edits)
        self.assertEqual(
            [e for e in result["errors"] if e["code"] == "CHECKED_EXCEPTION_NOT_PROPAGATED"],
            [],
        )

    def test_an_unhandled_checked_exception_is_still_caught(self):
        # The fix must not silence the defect the check exists to catch:
        # no catch at all, and the exception is never named either.
        edits = [
            {"source_file_path": "A.java", "edit_kind": "method",
             "original_code": "", "corrected_code":
             "void close() throws java.io.IOException {}"},
            {"source_file_path": "B.java", "edit_kind": "method",
             "original_code": "", "corrected_code":
             "void stop() {\n  a.close();\n}"},
        ]
        result = self._validate(edits)
        codes = [e["code"] for e in result["errors"]]
        self.assertIn("CHECKED_EXCEPTION_NOT_PROPAGATED", codes)

    def test_a_narrow_catch_of_an_unrelated_exception_is_still_caught(self):
        edits = [
            {"source_file_path": "A.java", "edit_kind": "method",
             "original_code": "", "corrected_code":
             "void close() throws java.io.IOException {}"},
            {"source_file_path": "B.java", "edit_kind": "method",
             "original_code": "", "corrected_code":
             "void stop() {\n  try {\n    a.close();\n  } catch (SQLException e) {\n"
             "  }\n}"},
        ]
        result = self._validate(edits)
        codes = [e["code"] for e in result["errors"]]
        self.assertIn("CHECKED_EXCEPTION_NOT_PROPAGATED", codes)

    def _with_original(self, enclosing: str):
        """B.java on disk, whose stop() wraps the edited anchor `a.read();`."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        Path(directory.name, "B.java").write_text(enclosing, encoding="utf-8")
        edits = [
            {"source_file_path": "A.java", "edit_kind": "method",
             "original_code": "", "corrected_code":
             "void close() throws java.io.IOException {}"},
            {"source_file_path": "B.java", "edit_kind": "method",
             "original_code": "a.read();", "corrected_code": "a.close();"},
        ]
        return validate_coordinated_semantics({"repository_path": directory.name}, edits)

    def test_an_outer_catch_outside_the_edited_fragment_handles_it(self):
        """MTG Familiar's fetch kept `catch (IOException e)` outside the anchor."""
        result = self._with_original(
            "class B {\n  void stop() {\n    try {\n      a.read();\n"
            "    } catch (IOException e) {\n      log(e);\n    }\n  }\n}\n")
        self.assertNotIn("CHECKED_EXCEPTION_NOT_PROPAGATED",
                         [e["code"] for e in result["errors"]])

    def test_an_enclosing_method_without_a_handler_is_still_caught(self):
        result = self._with_original(
            "class B {\n  void stop() {\n    a.read();\n  }\n}\n")
        self.assertIn("CHECKED_EXCEPTION_NOT_PROPAGATED",
                      [e["code"] for e in result["errors"]])

    def test_an_if_after_a_comment_ending_in_a_word_is_not_a_method_header(self):
        """BitBanana's continuePressed (frozen run, 2026-11-13): a comment
        ending "...get here..." above `if (...) {` read as a method `if`."""
        result = self._with_original(
            "class B {\n  public void continuePressed() {\n"
            "    // Ensure the delay is enforced even if the keyboard is used to get here...\n"
            "    if (mNumFails >= MAX_FAILS) {\n      return;\n    }\n"
            "    try {\n      a.read();\n"
            "    } catch (GeneralSecurityException | IOException e) {\n"
            "      e.printStackTrace();\n    }\n  }\n}\n")
        self.assertNotIn("CHECKED_EXCEPTION_NOT_PROPAGATED",
                         [e["code"] for e in result["errors"]])

    def test_control_flow_headers_after_a_word_are_not_method_headers(self):
        for statement in ("while (busy) {", "for (int i = 0; i < n; i++) {",
                          "synchronized (lock) {", "switch (mode) {"):
            with self.subTest(statement=statement):
                result = self._with_original(
                    "class B {\n  void stop() {\n    // wait here\n"
                    f"    {statement}\n      tick();\n    }}\n"
                    "    try {\n      a.read();\n    } catch (IOException e) {\n"
                    "      log(e);\n    }\n  }\n}\n")
                self.assertNotIn("CHECKED_EXCEPTION_NOT_PROPAGATED",
                                 [e["code"] for e in result["errors"]])

    def test_a_kotlin_else_if_or_when_is_not_a_method_header(self):
        for statement in ("} else if (ready) {", "return when (mode) {"):
            with self.subTest(statement=statement):
                result = self._with_original(
                    "class B {\n  void stop() {\n    if (x) {\n      y();\n"
                    f"    {statement}\n      z();\n    }}\n"
                    "    try {\n      a.read();\n    } catch (IOException e) {\n"
                    "      log(e);\n    }\n  }\n}\n")
                self.assertNotIn("CHECKED_EXCEPTION_NOT_PROPAGATED",
                                 [e["code"] for e in result["errors"]])

    def test_a_genuine_method_header_still_bounds_the_handler(self):
        # The catch belongs to another method: the edited one handles nothing.
        result = self._with_original(
            "class B {\n  void other() {\n    try {\n      b();\n"
            "    } catch (IOException e) {\n    }\n  }\n"
            "  private static String stop(String in) {\n"
            "    // read it here\n    if (in == null) {\n      return null;\n    }\n"
            "    a.read();\n    return in;\n  }\n}\n")
        self.assertIn("CHECKED_EXCEPTION_NOT_PROPAGATED",
                      [e["code"] for e in result["errors"]])

    def test_a_genuine_header_declaring_the_exception_handles_it(self):
        result = self._with_original(
            "class B {\n  public byte[] stop(String in) throws IOException {\n"
            "    // read it here\n    if (in == null) {\n      return null;\n    }\n"
            "    a.read();\n    return null;\n  }\n}\n")
        self.assertNotIn("CHECKED_EXCEPTION_NOT_PROPAGATED",
                         [e["code"] for e in result["errors"]])


# SimpleNotes' CredentialKeyProvider.kt (rvsec_simplenotes_20261025), trimmed.
_CREDENTIAL_KEY_PROVIDER = '''package dev.dettmer.simplenotes.utils

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val TRANSFORMATION = "AES/GCM/NoPadding"

/** Tests inject a `SecretKeySpec` through this seam. */
internal val androidKeyStoreKeyProvider = CredentialKeyProvider { create ->
    val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    val existing = keyStore.getKey(CREDENTIAL_KEY_ALIAS, null) as? SecretKey
    when {
        existing != null -> existing
        !create -> null
        else -> KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).apply {
            init(
                KeyGenParameterSpec.Builder(
                    CREDENTIAL_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setRandomizedEncryptionRequired(true)
                    .build()
            )
        }.generateKey()
    }
}

internal fun encryptCredential(key: SecretKey, plain: String): String {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, key)
    val ciphertext = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
    return (cipher.iv + ciphertext).joinToString("") { "%02x".format(it) }
}
'''

_SIMPLENOTES_ENCRYPT = (
    "    val cipher = Cipher.getInstance(TRANSFORMATION)\n"
    "    cipher.init(Cipher.ENCRYPT_MODE, key)\n"
)
_SIMPLENOTES_CALLER_IV = (
    "    val iv = ByteArray(GCM_IV_BYTES).also { SecureRandom().nextBytes(it) }\n"
    "    val cipher = Cipher.getInstance(TRANSFORMATION)\n"
    "    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))\n"
)

# Salty's HashUtils.kt (rvsec_salty_20261022), trimmed: a derived software key.
_HASH_UTILS = '''package com.vauth.salty.utils

object HashUtils {
    private const val ALGORITHM = "AES/GCM/NoPadding"

    fun encode(message: String, salt: String): String {
        return encodeLegacy(message, salt)
    }

    private fun deriveKey(userSalt: String): SecretKeySpec {
        val spec = PBEKeySpec(userSalt.toCharArray(), salt(userSalt), ITERATION_COUNT, KEY_LENGTH)
        val keyBytes = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY_ALGORITHM).generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, KEY_ALGORITHM)
    }
}
'''

_SALTY_KEYSTORE_KEY = '''
    private const val ANDROID_KEY_STORE = "AndroidKeyStore"

    @Synchronized
    private fun getCurrentEncryptionKey(): javax.crypto.SecretKey {
        val keyStore = java.security.KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null)
        val existingKey = keyStore.getKey(CURRENT_KEY_ALIAS, null)
        if (existingKey != null) {
            return existingKey as? javax.crypto.SecretKey
                ?: throw IllegalStateException("Current encryption key is not an AES secret key")
        }
        val keyGenerator = javax.crypto.KeyGenerator.getInstance(
            android.security.keystore.KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEY_STORE
        )
        val keySpec = android.security.keystore.KeyGenParameterSpec.Builder(
            CURRENT_KEY_ALIAS,
            android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or
                android.security.keystore.KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
            .build()
        keyGenerator.init(keySpec)
        return keyGenerator.generateKey()
    }
'''

_SALTY_ENCODE_CURRENT = '''
    private fun encodeCurrent(message: String, salt: String): String {
        val iv = ByteArray(GCM_IV_LENGTH)
        SecureRandom().nextBytes(iv)
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, getCurrentEncryptionKey(), GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        return Base64.encodeToString(iv + cipher.doFinal(message.toByteArray()), Base64.NO_WRAP)
    }
'''

_SALTY_ENCODE_LEGACY = '''
    private fun encodeLegacy(message: String, salt: String): String {
        val iv = ByteArray(GCM_IV_LENGTH)
        SecureRandom().nextBytes(iv)
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(salt), GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        return Base64.encodeToString(iv + cipher.doFinal(message.toByteArray()), Base64.NO_WRAP)
    }
'''


class CallerIvOnKeystoreKeyTests(unittest.TestCase):
    """A keystore key requiring randomized encryption refuses a caller IV."""

    CREDENTIALS = "app/src/main/java/dev/dettmer/simplenotes/utils/CredentialKeyProvider.kt"
    HASH_UTILS = "app/src/main/java/com/vauth/salty/utils/HashUtils.kt"

    def _issues(self, relative, content, edits):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        (Path(directory.name) / relative).parent.mkdir(parents=True)
        (Path(directory.name) / relative).write_text(content, encoding="utf-8")
        return caller_iv_on_randomized_keystore_key({"repository_path": directory.name}, edits)

    def _salty(self, *added):
        anchor = "    private fun deriveKey("
        return self._issues(self.HASH_UTILS, _HASH_UTILS, [{
            "source_file_path": self.HASH_UTILS, "edit_kind": "method",
            "original_code": anchor, "corrected_code": "".join(added).lstrip("\n") + "\n" + anchor,
        }])

    def test_a_caller_iv_on_a_key_handed_in_by_the_keystore_provider_is_refused(self):
        issues = self._issues(self.CREDENTIALS, _CREDENTIAL_KEY_PROVIDER, [{
            "source_file_path": self.CREDENTIALS, "edit_kind": "method",
            "original_code": _SIMPLENOTES_ENCRYPT, "corrected_code": _SIMPLENOTES_CALLER_IV,
        }])
        self.assertEqual([issue["code"] for issue in issues], ["CALLER_IV_REFUSED_BY_KEYSTORE_KEY"])
        self.assertEqual(issues[0]["path"], self.CREDENTIALS)

    def test_only_the_keystore_path_of_a_file_with_both_kinds_of_key_is_refused(self):
        issues = self._salty(_SALTY_KEYSTORE_KEY, _SALTY_ENCODE_CURRENT, _SALTY_ENCODE_LEGACY)
        self.assertEqual(len(issues), 1)
        self.assertIn("getCurrentEncryptionKey", issues[0]["details"][0])
        self.assertNotIn("deriveKey", issues[0]["details"][0])

    def test_a_caller_iv_on_a_software_key_beside_a_keystore_key_passes(self):
        self.assertEqual(self._salty(_SALTY_KEYSTORE_KEY, _SALTY_ENCODE_LEGACY), [])

    def test_randomized_encryption_turned_off_allows_a_caller_iv(self):
        relaxed = _CREDENTIAL_KEY_PROVIDER.replace(
            ".setRandomizedEncryptionRequired(true)", ".setRandomizedEncryptionRequired(false)")
        self.assertEqual(self._issues(self.CREDENTIALS, relaxed, [{
            "source_file_path": self.CREDENTIALS, "edit_kind": "method",
            "original_code": _SIMPLENOTES_ENCRYPT, "corrected_code": _SIMPLENOTES_CALLER_IV,
        }]), [])

    def test_a_caller_iv_the_original_already_passed_is_not_judged(self):
        content = _CREDENTIAL_KEY_PROVIDER.replace(_SIMPLENOTES_ENCRYPT, _SIMPLENOTES_CALLER_IV)
        self.assertEqual(self._issues(self.CREDENTIALS, content, [{
            "source_file_path": self.CREDENTIALS, "edit_kind": "method",
            "original_code": "    val ciphertext = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))\n",
            "corrected_code": "    val ciphertext = cipher.doFinal(plain.encodeToByteArray())\n",
        }]), [])

    def test_the_coordinated_validator_reports_it(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / self.CREDENTIALS
        path.parent.mkdir(parents=True)
        path.write_text(_CREDENTIAL_KEY_PROVIDER, encoding="utf-8")
        result = validate_coordinated_semantics({"repository_path": directory.name}, [{
            "source_file_path": self.CREDENTIALS, "edit_kind": "method",
            "original_code": _SIMPLENOTES_ENCRYPT, "corrected_code": _SIMPLENOTES_CALLER_IV,
        }])
        self.assertIn("CALLER_IV_REFUSED_BY_KEYSTORE_KEY",
                      [issue["code"] for issue in result["errors"]])

    def _one_edit(self, relative, content, original, corrected, *more):
        edits = [{"source_file_path": relative, "edit_kind": "method",
                  "original_code": original, "corrected_code": corrected}]
        edits += [{"source_file_path": relative, "edit_kind": "method",
                   "original_code": before, "corrected_code": after} for before, after in more]
        return [issue["code"] for issue in self._issues(relative, content, edits)]

    def test_randomization_turned_off_by_the_patch_itself_exempts_nothing(self):
        source = _CREDENTIAL_KEY_PROVIDER.replace("                    .setRandomizedEncryptionRequired(true)\n", "")
        builder = "                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)\n"
        self.assertEqual(self._one_edit(
            self.CREDENTIALS, source, _SIMPLENOTES_ENCRYPT, _SIMPLENOTES_CALLER_IV,
            (builder, builder + "                    .setRandomizedEncryptionRequired(false)\n"),
        ), ["CALLER_IV_REFUSED_BY_KEYSTORE_KEY"])

    def test_a_spec_bound_to_a_local_counts(self):
        bound = _SIMPLENOTES_CALLER_IV.replace(
            "    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))\n",
            "    val spec = GCMParameterSpec(GCM_TAG_BITS, iv)\n"
            "    cipher.init(Cipher.ENCRYPT_MODE, key, spec)\n")
        self.assertEqual(self._one_edit(self.CREDENTIALS, _CREDENTIAL_KEY_PROVIDER,
                                        _SIMPLENOTES_ENCRYPT, bound),
                         ["CALLER_IV_REFUSED_BY_KEYSTORE_KEY"])

    def test_the_java_new_form_counts(self):
        source = (
            "package x;\n\npublic class Vault {\n"
            '    private static final String KS = "AndroidKeyStore";\n\n'
            "    private SecretKey getKey() throws Exception {\n"
            "        KeyStore keyStore = KeyStore.getInstance(KS);\n"
            "        keyStore.load(null);\n"
            '        return (SecretKey) keyStore.getKey("vault", null);\n'
            "    }\n\n"
            "    public byte[] encrypt(byte[] data) throws Exception {\n"
            '        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\n'
            "        cipher.init(Cipher.ENCRYPT_MODE, getKey());\n"
            "        return cipher.doFinal(data);\n"
            "    }\n}\n"
        )
        self.assertEqual(self._one_edit(
            "app/src/main/java/x/Vault.java", source,
            "        cipher.init(Cipher.ENCRYPT_MODE, getKey());\n",
            "        byte[] iv = new byte[12];\n        new SecureRandom().nextBytes(iv);\n"
            "        cipher.init(Cipher.ENCRYPT_MODE, getKey(), new GCMParameterSpec(128, iv));\n",
        ), ["CALLER_IV_REFUSED_BY_KEYSTORE_KEY"])

    # KeyPass' CryptoManager (rvsec_keypass_20261025), trimmed, behind a
    # primary constructor: its createKey has no provider argument and still
    # lands in AndroidKeyStore through the KeyGenParameterSpec.
    KEYPASS = '''package com.yogeshpaliyal.common.utils

class CryptoManager(private val context: Context) {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private fun getKey(): SecretKey {
        val existingKey = keyStore.getEntry("secret", null) as? KeyStore.SecretKeyEntry
        return existingKey?.secretKey ?: createKey()
    }

    private fun createKey(): SecretKey {
        return KeyGenerator.getInstance(ALGORITHM).apply {
            init(
                KeyGenParameterSpec.Builder(
                    "secret",
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(BLOCK_MODE)
                    .build()
            )
        }.generateKey()
    }

    fun encrypt(bytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getKey())
        return cipher.iv + cipher.doFinal(bytes)
    }
}
'''

    def test_members_of_a_class_with_a_primary_constructor_are_followed(self):
        relative = "common/src/main/java/com/yogeshpaliyal/common/utils/CryptoManager.kt"
        original = "        cipher.init(Cipher.ENCRYPT_MODE, getKey())\n"
        caller_iv = ("        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }\n"
                     "        cipher.init(Cipher.ENCRYPT_MODE, {key}, IvParameterSpec(iv))\n")
        for key in ("getKey()", "createKey()"):
            self.assertEqual(self._one_edit(relative, self.KEYPASS, original,
                                            caller_iv.replace("{key}", key)),
                             ["CALLER_IV_REFUSED_BY_KEYSTORE_KEY"], key)

    def test_a_lazy_keystore_member_is_followed(self):
        # tokn's KeystoreManager (rvsec_tokn_20261028), trimmed.
        source = '''package me.diamondforge.tokn.security

open class KeystoreManager @Inject constructor(
    @param:ApplicationContext private val context: Context,
) {
    private val keystore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    open fun encrypt(data: ByteArray): String {
        val key = getOrCreateKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return Base64.encodeToString(cipher.iv + cipher.doFinal(data), Base64.NO_WRAP)
    }

    private fun getOrCreateKey(): SecretKey {
        return keystore.getKey(KEY_ALIAS, null) as SecretKey
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
'''
        self.assertEqual(self._one_edit(
            "app/src/main/java/me/diamondforge/tokn/security/KeystoreManager.kt", source,
            "        cipher.init(Cipher.ENCRYPT_MODE, key)\n",
            "        val iv = generateRandomBytes(GCM_IV_LENGTH)\n"
            "        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH * 8, iv))\n",
        ), ["CALLER_IV_REFUSED_BY_KEYSTORE_KEY"])

    def test_a_key_parameter_beside_a_bare_keystore_lookup_is_not_judged(self):
        source = '''package x

object CryptoUtil {
    fun hasAlias(alias: String) =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(alias)

    fun encrypt(key: SecretKey, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.iv + cipher.doFinal(data)
    }
}
'''
        self.assertEqual(self._one_edit(
            "app/src/main/java/x/CryptoUtil.kt", source,
            "        cipher.init(Cipher.ENCRYPT_MODE, key)\n",
            "        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }\n"
            "        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))\n",
        ), [])

    def test_a_key_parameter_is_judged_by_what_every_caller_in_the_file_passes(self):
        source = _HASH_UTILS.replace("    private fun deriveKey(", _SALTY_KEYSTORE_KEY + '''
    fun seal(message: String, salt: String): String = sealWith(getCurrentEncryptionKey(), message)

    fun sealLegacy(message: String, salt: String): String = sealWith(deriveKey(salt), message)

    private fun sealWith(key: javax.crypto.SecretKey, message: String): String {
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return Base64.encodeToString(cipher.iv + cipher.doFinal(message.toByteArray()), Base64.NO_WRAP)
    }

    private fun deriveKey(''')
        original = "        cipher.init(Cipher.ENCRYPT_MODE, key)\n"
        caller_iv = ("        val iv = ByteArray(GCM_IV_LENGTH).also { SecureRandom().nextBytes(it) }\n"
                     "        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))\n")
        # One caller hands it the derived software key: not every key refuses the IV.
        self.assertEqual(self._one_edit(self.HASH_UTILS, source, original, caller_iv), [])
        keystore_only = source.replace("sealWith(deriveKey(salt), message)",
                                       "sealWith(getCurrentEncryptionKey(), message)")
        self.assertEqual(self._one_edit(self.HASH_UTILS, keystore_only, original, caller_iv),
                         ["CALLER_IV_REFUSED_BY_KEYSTORE_KEY"])

    def test_a_software_key_unwrapped_by_a_keystore_key_is_not_judged(self):
        # An AndroidKeyStore RSA key wrapping the AES key, the pre-API-23 way.
        source = '''package x

class Vault(private val prefs: Prefs) {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun aesKey(): SecretKey {
        val rsaKey = keyStore.getKey("rsa", null) as PrivateKey
        val rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        rsa.init(Cipher.UNWRAP_MODE, rsaKey)
        return rsa.unwrap(prefs.wrapped(), "AES", Cipher.SECRET_KEY) as SecretKey
    }

    fun encrypt(data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey())
        return cipher.iv + cipher.doFinal(data)
    }
}
'''
        self.assertEqual(self._one_edit(
            "app/src/main/java/x/Vault.kt", source,
            "        cipher.init(Cipher.ENCRYPT_MODE, aesKey())\n",
            "        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }\n"
            "        cipher.init(Cipher.ENCRYPT_MODE, aesKey(), IvParameterSpec(iv))\n",
        ), [])


class CallerIvRefusalWordingTests(unittest.TestCase):
    """The refusal reaches a maintainer's issue as its own plain reason and question."""

    def test_the_refusal_has_its_own_reason_and_question(self):
        from cognalys.llm.fix_generation_common import (
            _DEFAULT_BLOCKER, _DEFAULT_QUESTION, plain_blocker_question, plain_blocker_reasons,
        )
        from cognalys.utils.pr_text import PIPELINE_JARGON

        blockers = ["CALLER_IV_REFUSED_BY_KEYSTORE_KEY: the key requires randomized encryption"]
        reasons = plain_blocker_reasons(blockers)
        question, next_step = plain_blocker_question(blockers)
        self.assertEqual(len(reasons), 1)
        self.assertNotEqual(reasons[0], _DEFAULT_BLOCKER)
        self.assertIn("Keystore", reasons[0])
        self.assertNotEqual((question, next_step), _DEFAULT_QUESTION)
        text = " ".join(reasons + [question, next_step])
        self.assertNotIn("CALLER_IV", text)
        self.assertEqual([word for word in PIPELINE_JARGON if word in text.lower()], [])


class CallSiteSourceRebuildTests(unittest.TestCase):
    """NotallyX md5Hash (2026-10-28): the plan blocked, correctly, on a
    call-site file it had only as exact_source_available=false; the
    correction dropped the blocker and planned an unused helper."""

    TARGET = "app/src/main/java/x/IOExtensions.kt"
    CALLER = "app/src/main/java/x/backup/ExportExtensions.kt"
    TARGET_SOURCE = ("package x\n\ninternal fun File.md5Hash(): ByteArray {\n"
                     "    return MessageDigest.getInstance(\"MD5\").digest(readBytes())\n}\n")
    CALLER_SOURCE = ("package x.backup\n\nimport x.md5Hash\n\n"
                     "fun same(a: File, b: File) = a.md5Hash().contentEquals(b.md5Hash())\n")

    def _run(self, caller_on_disk=True, adjudication=None, error_extra=None,
             plan_blocker=True, plan_abstains=False, invalid_replan=False):
        import logging

        from cognalys.llm.generate_error_fixes import FixGenerator
        from cognalys.llm.pipeline_architecture import FindingEvidencePacketBuilder, PolicyRegistry

        prompts = {}
        # Each stage's system prompt, for the tests that read the rules.
        systems = self.systems = {}
        target, caller = self.TARGET, self.CALLER

        class Provider:
            provider_name, model = "test", "test-model"

            @staticmethod
            def get_token_usage():
                return {"input": 0, "output": 0}

            def generate(self, prompt, system=None, **kwargs):
                stage = kwargs.get("trace_stage", "")
                prompts.setdefault(stage, prompt)
                systems.setdefault(stage, system or kwargs.get("system", ""))
                if stage.startswith("evidence_extraction"):
                    return json.dumps({
                        "claims": [{"claim_id": "CLM-001", "statement": "MD5 is passed",
                                    "epistemic_status": "confirmed", "evidence_ids": ["SRC-001"]}],
                        "observed_events": [], "predicate_assessment": [],
                        "confirmed_dataflows": [], "relations": [], "unresolved_questions": [],
                        "needs_more_evidence": False, "requested_evidence": [],
                        "family_assessment": {"summary": "s", "evidence_ids": []}})
                if stage.startswith("adjudication"):
                    return json.dumps({**{
                        "cause_status": "confirmed", "confirmed_cause": "MD5 is passed",
                        "detector_violation": "confirmed", "runtime_security_impact": "unknown",
                        "compatibility_status": "unknown", "scope_status": "complete",
                        "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                        "decision_claim_ids": ["CLM-001"], "blocking_for_generation": [],
                        "blocking_for_publication": [], "generation_status": "supported_for_review",
                        "publication_status": "blocked", "required_edit_categories": [],
                        "required_tests": [], "forward_compatibility_strategy": "",
                        "authorized_behavior_change": {"authorized": False, "description": "",
                                                       "policy_reference": ""},
                        "review_assumptions": []}, **(adjudication or {})})
                edits = [{"source_file_path": target, "create_new_file": False,
                          "supporting_claim_ids": ["CLM-001"], "symbol": "md5Hash",
                          "edit_category": "e", "reason": "r"}]
                blockers = []
                if plan_abstains:
                    return json.dumps({
                        "decision": "NO_SAFE_FIX", "required_edits": [],
                        "required_tests": [], "behavioral_invariants": [], "allowed_apis": [],
                        "forbidden_changes": [], "publication_blockers": [],
                        "generation_blockers": ["no edit satisfies the rule and keeps the "
                                                "key format the callers read"]})
                if stage == "patch_planning":
                    if plan_blocker:
                        blockers = ["ExportExtensions.kt is present in the manifest only "
                                    "with exact_source_available=false"]
                else:
                    edits.append({**edits[0], "source_file_path": caller, "symbol": "same"})
                    if invalid_replan and stage == "patch_planning.call_site_sources":
                        edits = [{**item, "supporting_claim_ids": ["CLM-404"]}
                                 for item in edits]
                return json.dumps({
                    "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "required_edits": edits,
                    "required_tests": [], "behavioral_invariants": [], "allowed_apis": [],
                    "forbidden_changes": [], "generation_blockers": blockers,
                    "publication_blockers": []})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            (root / Path(target).parent).mkdir(parents=True)
            (root / target).write_text(self.TARGET_SOURCE, encoding="utf-8")
            if caller_on_disk:
                (root / Path(caller).parent).mkdir(parents=True)
                (root / caller).write_text(self.CALLER_SOURCE, encoding="utf-8")
            generator = object.__new__(FixGenerator)
            generator.output_dir = Path(directory) / "out"
            generator.provider = Provider()
            generator.web_search = False
            generator.architecture_version = "v2"
            generator.logger = logging.getLogger("test")
            generator.evidence_packet_builder = FindingEvidencePacketBuilder(
                repository_context_budget=140_000)
            generator.policy_registry = PolicyRegistry(Path(directory) / "no_policies")
            error = {
                "spec": "MacSpec", "method_name": "md5Hash", "csv_class": "x.IOExtensionsKt",
                "method_body": self.TARGET_SOURCE, "imports": "", "error_index": 0,
                "source_file_path": target, "repository_path": str(root),
                "error_message": "expecting one of {SHA-256} but found MD5",
                "rename_safety": {"symbol": "md5Hash", "allowed": True, "hard_blockers": [],
                                  "resolvable": [], "declaration": {"path": target, "line": 3},
                                  "references": [{"path": caller, "line": 5, "kind": "call"}]},
                "expanded_repository_context": {"multi_file_impact": {
                    "status": "available",
                    "exact_candidate_sources": [{"source_file_path": target,
                                                 "content": self.TARGET_SOURCE}],
                    "semantic_resolution": {"status": "available", "resolved_callers": [
                        {"path": caller, "line": 5, "enclosing_symbol": "same",
                         "snippet": "a.md5Hash()"}]},
                    "coverage_requirements": {},
                    "scope_completeness": {"status": "complete", "reasons": []},
                }},
            }
            error.update(error_extra or {})
            analysis, artifacts = generator.adjudicate_finding(error, "app.apk", "md5Hash")
        return analysis, artifacts, error, prompts

    def test_a_blocker_naming_an_unseen_call_site_rebuilds_and_replans(self):
        _, artifacts, error, prompts = self._run()
        self.assertIn("patch_planning.call_site_sources", prompts)
        self.assertNotIn("patch_planning.correction", prompts)
        plan = artifacts["patch_plan"]
        self.assertEqual(plan["generation_blockers"], [])
        self.assertEqual({item["source_file_path"] for item in plan["required_edits"]},
                         {self.TARGET, self.CALLER})
        impact = error["expanded_repository_context"]["multi_file_impact"]
        self.assertIn(self.CALLER, {item["source_file_path"]
                                    for item in impact["exact_candidate_sources"]})
        self.assertTrue(error["caller_source_gap"]["resolved"])
        # rename_safety reached the adjudication and the plan as data.
        self.assertIn('"rename_safety":{"symbol":"md5Hash"', prompts["adjudication"])
        self.assertIn('"rename_safety":{"symbol":"md5Hash"', prompts["patch_planning"])

    def test_the_plan_knows_a_runtime_monitor_reported_the_finding(self):
        # Beta run_v2 (2026-10-30): the KeyPairSpec draft said RVSec's
        # findings came from "a source/static analyzer"; the plan it followed
        # had not been told either.
        _, _, _, prompts = self._run(error_extra={"tool": "rvsec"})
        self.assertIn('"detector":{"tool":"rvsec","kind":"runtime_monitor"}',
                      prompts["patch_planning"])
        self.assertIn("detector, when present, says a runtime monitor reported the finding "
                      "while the app ran", " ".join(self.systems["patch_planning"].split()))
        _, _, _, prompts = self._run()
        self.assertNotIn('"detector":', prompts["patch_planning"])

    def test_a_call_site_that_cannot_be_supplied_is_an_evidence_gap_not_a_correction(self):
        analysis, artifacts, error, prompts = self._run(caller_on_disk=False)
        self.assertNotIn("patch_planning.correction", prompts)
        self.assertEqual(error["caller_source_gap"]["unsupplied"], [self.CALLER])
        blocker = artifacts["adjudication"]["blocking_for_generation"][0]
        self.assertEqual(blocker["kind"], "invalid_patch_plan")
        self.assertEqual(blocker["category"], "code_evidence_missing")
        self.assertEqual(blocker["caller_sources_unavailable"], [self.CALLER])

    def test_a_planner_abstaining_after_a_review_promotion_is_recorded(self):
        """Audit of 2026-10-31: promoted to a reviewable fix, then no edit
        planned, and Trigger's decodePublic became a maintainer issue."""
        promoted = {"decision": "NO_SAFE_FIX", "generation_status": "blocked",
                    "blocking_for_generation": [{
                        "kind": "approval", "description": "the maintainer must approve",
                        "category": "maintainer_decision", "supporting_claim_ids": ["CLM-001"]}]}
        _, artifacts, _, _ = self._run(adjudication=promoted, plan_abstains=True)
        abstention = artifacts["adjudication"]["planner_abstained_after_review_promotion"]
        self.assertEqual(abstention["promotions"], ["human_decided_blockers"])
        self.assertIn("keeps the key format", abstention["reason"])
        self.assertEqual(artifacts["adjudication"]["decision"], "NO_SAFE_FIX")
        # The adjudicator's own fix decision is not a promotion.
        _, artifacts, _, _ = self._run(plan_abstains=True)
        self.assertNotIn("planner_abstained_after_review_promotion", artifacts["adjudication"])

    def test_the_adjudication_reads_internal_contracts_and_protocol_digests(self):
        """BlueGate run_v10 (an app-internal return type called a contract) and
        Xtra (RFC 6455's SHA-1 sent to the maintainer), 2026-10-31."""
        self._run()
        system = next(text for stage, text in self.systems.items()
                      if stage.startswith("adjudication"))
        self.assertIn("whose every caller is in this repository is not an external "
                      "contract", " ".join(system.split()))
        self.assertIn("answer NON_SECURITY_HASH_USAGE", system)
        self.assertIn("nor to a fingerprint", system)

    def test_the_plan_lists_an_edit_or_says_why_and_reads_earlier_draft_failures(self):
        """Audit of 2026-10-31: 39 plans kept the decision with no edit and no
        reason; replanned units now carry the checks every draft failed."""
        from cognalys.llm.finding_adjudication import PLAN_PROMPT_VERSION

        failures = [{"code": "UNNECESSARY_PUBLIC_API_EXPANSION", "message": "made public",
                     "affected_paths": [self.TARGET]}]
        _, _, _, prompts = self._run(error_extra={"previous_draft_failures": failures})
        system = " ".join(self.systems["patch_planning"].split())
        self.assertIn("never return the decision with an empty required_edits and no reason",
                      system)
        self.assertIn("previous_draft_failures, when present", system)
        self.assertIn('"previous_draft_failures"', prompts["patch_planning"])
        self.assertGreaterEqual(PLAN_PROMPT_VERSION, 2)

    def test_this_repositorys_maintainer_responses_reach_adjudication_and_plan(self):
        """Amethyst#4642, closed under GCMParameterSpecSpec, never reached the
        Amethyst v3 CipherSpec draft (2026-10-31)."""
        from cognalys.llm.finding_adjudication import (
            ADJUDICATION_PROMPT_VERSION, PLAN_PROMPT_VERSION)

        self._run()
        adjudication = next(text for stage, text in self.systems.items()
                            if stage.startswith("adjudication"))
        for system in (adjudication, self.systems["patch_planning"]):
            self.assertIn("maintainer_responses_in_this_repository, when present",
                          " ".join(system.split()))
        self.assertGreaterEqual(ADJUDICATION_PROMPT_VERSION, 2)
        self.assertGreaterEqual(PLAN_PROMPT_VERSION, 3)

    def test_this_repositorys_answer_for_the_same_rule_has_its_own_section(self):
        """InterTune run_v2 (2026-11-08): InterTune#52, closed for this very
        method, was read as what maintainers of other projects answered."""
        from cognalys.llm.finding_adjudication import (
            ADJUDICATION_PROMPT_VERSION, PLAN_PROMPT_VERSION)

        self._run()
        adjudication = next(text for stage, text in self.systems.items()
                            if stage.startswith("adjudication"))
        for system in (adjudication, self.systems["patch_planning"]):
            joined = " ".join(system.split())
            self.assertIn("maintainer_responses_to_this_rule_in_this_repository, when present, "
                          "are what this repository's own maintainers answered", joined)
            self.assertIn("never propose again a change their stated objection applies to",
                          joined)
            self.assertIn("it does not by itself make the finding false", joined)
        self.assertGreaterEqual(ADJUDICATION_PROMPT_VERSION, 5)
        self.assertGreaterEqual(PLAN_PROMPT_VERSION, 11)

    def test_the_plan_keeps_to_the_values_the_violation_is_about(self):
        """Your Local Weather (2026-11-02): an algorithm-name finding was
        planned with a higher iteration count and two new constants."""
        from cognalys.llm.finding_adjudication import PLAN_PROMPT_VERSION

        self._run()
        system = " ".join(self.systems["patch_planning"].split())
        self.assertIn("Leave every other argument of the reported call as it is", system)
        self.assertIn("a literal stays a literal", system)
        self.assertGreaterEqual(PLAN_PROMPT_VERSION, 4)

    def test_the_kept_arguments_yield_to_the_listed_parameter_policies(self):
        """Your Local Weather run_v2 (2026-11-02): the plan kept 65536
        iterations as told and CURRENT_PARAMETER_BELOW_POLICY refused every
        draft; the guidance now defers to parameter_policies."""
        from cognalys.llm.finding_adjudication import PLAN_PROMPT_VERSION

        self._run()
        system = " ".join(self.systems["patch_planning"].split())
        self.assertIn("unless parameter_policies requires a different value", system)
        self.assertGreaterEqual(PLAN_PROMPT_VERSION, 5)

    def test_plan_invariants_may_not_keep_what_parameter_policies_change(self):
        """Your Local Weather run_v4 (2026-11-02): the plan's invariant kept
        65,536 iterations and the review refused drafts meeting the policy."""
        from cognalys.llm.finding_adjudication import PLAN_PROMPT_VERSION

        self._run()
        system = " ".join(self.systems["patch_planning"].split())
        self.assertIn("never write a behavioral_invariant or forbidden_change that keeps "
                      "the current value of a parameter parameter_policies requires to "
                      "change", system)
        self.assertGreaterEqual(PLAN_PROMPT_VERSION, 7)


class JudgeDischargeTests(unittest.TestCase):
    """judge() itself runs the rename and analyzer-acceptance discharges and
    hands an echo its producer: the helpers alone are tested elsewhere."""

    # The call-site harness: a stub provider through adjudicate_finding.
    TARGET, CALLER = CallSiteSourceRebuildTests.TARGET, CallSiteSourceRebuildTests.CALLER
    TARGET_SOURCE = CallSiteSourceRebuildTests.TARGET_SOURCE
    CALLER_SOURCE = CallSiteSourceRebuildTests.CALLER_SOURCE
    _run = CallSiteSourceRebuildTests._run

    def test_rename_and_analyzer_blockers_end_as_publication_notes(self):
        blockers = [
            {"kind": "rename_safety_authorization", "category": "rename_authorization",
             "description": "a reviewer must approve renaming md5Hash",
             "supporting_claim_ids": ["CLM-001"]},
            {"kind": "analyzer_reconfirmation", "category": "analyzer_reconfirmation",
             "description": "whether the analyzer accepts SHA-256 when it reruns",
             "supporting_claim_ids": ["CLM-001"]},
        ]
        _, artifacts, _, prompts = self._run(adjudication={
            "blocking_for_generation": blockers,
            "forward_compatibility_strategy": 'Replace "MD5" with "SHA-256".',
        }, plan_blocker=False)
        adjudication = artifacts["adjudication"]
        self.assertNotIn("adjudication.correction", prompts)
        self.assertEqual(adjudication["blocking_for_generation"], [])
        self.assertEqual(adjudication["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(sorted(item["category"] for item in adjudication["discharged_blockers"]),
                         ["analyzer_reconfirmation", "rename_authorization"])
        self.assertIn("rename_authorization", {
            item.get("category") for item in adjudication["publication_considerations"]})
        accepted = next(item for item in adjudication["discharged_blockers"]
                        if item["category"] == "analyzer_reconfirmation")
        self.assertEqual(accepted["discharging_values"], ["SHA-256"])

    def test_an_echo_takes_its_producers_cause_through_judge(self):
        producer = {"method": "deriveKey", "specification": "PBEKeySpecSpec",
                    "error_message": "salt not from a randomized source",
                    "binding": "key", "reaches": "cipher.init"}
        _, artifacts, _, prompts = self._run(adjudication={
            "cause_status": "unknown", "decision": "NO_SAFE_FIX",
            "generation_status": "blocked",
            "blocking_for_generation": [{
                "kind": "key_provenance", "category": "code_evidence_missing",
                "description": "where the key comes from is not settled",
                "supporting_claim_ids": ["CLM-001"]}],
        }, error_extra={"echo_of": producer, "tool": "RVSec"}, plan_blocker=False)
        # The packet carries it to the adjudication prompt ...
        self.assertIn('"echo_of":{"method":"deriveKey"', prompts["adjudication"])
        # ... and judge() hands it to the evidence-gap promotion.
        authority = artifacts["adjudication"].get("cause_authority") or {}
        self.assertEqual(authority.get("kind"), "producer_finding")
        self.assertEqual(authority.get("method"), "deriveKey")


class ReviewRoutingBeforeCorrectionTests(unittest.TestCase):
    """Syncthing-lite generateKeystore (2026-10-29): review generation whose
    blockers were all human-decided was rejected only for "supported decision
    has generation blockers", and the correction turned it into
    MULTI_FILE_FIX_REQUIRES_POLICY. The deterministic router goes first."""

    TARGET, CALLER = CallSiteSourceRebuildTests.TARGET, CallSiteSourceRebuildTests.CALLER
    TARGET_SOURCE = CallSiteSourceRebuildTests.TARGET_SOURCE
    CALLER_SOURCE = CallSiteSourceRebuildTests.CALLER_SOURCE
    _run = CallSiteSourceRebuildTests._run

    BLOCKERS = [
        {"kind": "replacement_algorithm_and_identity_migration_policy",
         "category": "maintainer_decision",
         "description": "a reviewer chooses the replacement and the rotation policy",
         "supporting_claim_ids": ["CLM-001"]},
        {"kind": "existing_persisted_identity_compatibility",
         "category": "compatibility_contract",
         "description": "existing persisted identities must keep loading",
         "supporting_claim_ids": ["CLM-001"]},
    ]

    def test_human_decided_blockers_route_to_review_without_a_correction(self):
        _, artifacts, _, prompts = self._run(adjudication={
            "blocking_for_generation": self.BLOCKERS}, plan_blocker=False)
        adjudication = artifacts["adjudication"]
        self.assertNotIn("adjudication.correction", prompts)
        self.assertEqual(adjudication["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(adjudication["blocking_for_generation"], [])
        self.assertEqual(adjudication["correction_skipped"], {
            "router": "route_unsettled_compatibility_to_review",
            "settled_issues": ["supported decision has generation blockers"]})
        self.assertTrue({"maintainer_decision", "compatibility_contract"} <= {
            item.get("category") for item in adjudication["blocking_for_publication"]})

    def test_a_blocker_no_reviewer_settles_still_gets_the_correction(self):
        blockers = [{**self.BLOCKERS[0], "category": "code_evidence_missing"}]
        _, artifacts, _, prompts = self._run(adjudication={
            "blocking_for_generation": blockers}, plan_blocker=False)
        self.assertIn("adjudication.correction", prompts)
        self.assertNotIn("correction_skipped", artifacts["adjudication"])


class CorrectionAppendedToTheAnsweredRequestTests(unittest.TestCase):
    """A correction shared no prefix with the call it corrects (C arm of
    comparison_20261113: 21 plan and 8 adjudication corrections, 0 characters
    each): it serialized the sections again. It is now the answered request
    byte for byte, a cache boundary at its end, then the note, the rejected
    answer and the deterministic errors."""

    TARGET, CALLER = CallSiteSourceRebuildTests.TARGET, CallSiteSourceRebuildTests.CALLER
    TARGET_SOURCE = CallSiteSourceRebuildTests.TARGET_SOURCE
    CALLER_SOURCE = CallSiteSourceRebuildTests.CALLER_SOURCE
    _run = CallSiteSourceRebuildTests._run

    def _appended(self, original, correction):
        self.assertTrue(correction.startswith(original))
        self.assertEqual(correction.cache_boundaries, (len(original),))
        return correction[len(original):]

    def test_correction_request_is_the_original_then_the_rejection(self):
        from cognalys.llm.finding_adjudication import correction_request
        from cognalys.llm.llm_providers import PromptWithCacheBoundaries

        original = PromptWithCacheBoundaries("Do it.\n\n<d>" + "x" * 50 + "</d>", [5])
        request, data = correction_request(
            original, "Correct it.", "rejected_answer", {"a": 1}, ["e1", "e2"], "fix")
        self.assertTrue(request.startswith(original))
        # The original's own boundaries are kept, and its end is one.
        self.assertEqual(request.cache_boundaries, (5, len(original)))
        self.assertEqual(request[len(original):], (
            '\n\nCorrect it.\n\n<fix untrusted_data="true">\n'
            '{"rejected_answer":{"a":1},"deterministic_validation_errors":["e1","e2"]}'
            '\n</fix>'))
        self.assertEqual(data, {"rejected_answer": {"a": 1},
                                "deterministic_validation_errors": ["e1", "e2"]})

    def test_the_adjudication_correction_appends_to_the_adjudication_request(self):
        from cognalys.llm.finding_adjudication import ADJUDICATION_CORRECTION_NOTE

        blockers = [{**ReviewRoutingBeforeCorrectionTests.BLOCKERS[0],
                     "category": "code_evidence_missing"}]
        _, _, _, prompts = self._run(adjudication={
            "blocking_for_generation": blockers}, plan_blocker=False)
        appended = self._appended(prompts["adjudication"], prompts["adjudication.correction"])
        self.assertTrue(appended.startswith("\n\n" + ADJUDICATION_CORRECTION_NOTE + "\n\n"))
        self.assertIn('<adjudication_correction untrusted_data="true">\n'
                      '{"rejected_adjudication":{', appended)
        self.assertIn('"deterministic_validation_errors":["supported decision has '
                      'generation blockers"', appended)
        # The adjudication data is not serialized a second time.
        self.assertNotIn("<adjudication_data", appended)
        self.assertNotIn('"validated_evidence_extraction"', appended)

    def test_the_plan_correction_appends_to_the_planning_request(self):
        from cognalys.llm.finding_adjudication import PLAN_CORRECTION_NOTE

        _, _, _, prompts = self._run(plan_abstains=True)
        appended = self._appended(prompts["patch_planning"],
                                  prompts["patch_planning.correction"])
        self.assertTrue(appended.startswith("\n\n" + PLAN_CORRECTION_NOTE + "\n\n"))
        self.assertIn('<plan_correction untrusted_data="true">\n{"rejected_plan":{', appended)
        self.assertIn('"deterministic_validation_errors":[', appended)
        self.assertNotIn("original_planning_input", appended)
        self.assertNotIn("<planning_data", appended)

    def test_after_a_call_site_replan_the_correction_appends_to_the_replan(self):
        # The replan's request holds the call-site sources the first did not.
        _, _, _, prompts = self._run(invalid_replan=True)
        appended = self._appended(prompts["patch_planning.call_site_sources"],
                                  prompts["patch_planning.correction"])
        self.assertIn("CLM-404", appended)
        self.assertFalse(prompts["patch_planning.correction"].startswith(
            prompts["patch_planning"]))


class DroppedUnrelatedTestRecordTests(unittest.TestCase):
    """Winterhold run_v6 (2026-11-10): the behaviour review dropped the
    generated test, and neither the manifest nor the log said so, while the
    pull-request record kept "WebUser is accessible to the module's unit tests"."""

    TEST = "src/test/MainTest.java"

    def _run(self, test_assumptions, production_assumptions):
        import logging

        from cognalys.llm.generate_error_fixes import FixGenerator

        test_path = self.TEST

        class Provider:
            def generate(self, prompt, *args, **kwargs):
                if kwargs.get("schema_name") == "behavior_review":
                    return json.dumps({"regressions": [], "unrelated_test_edits": [test_path],
                                       "maintainer_decision_required": False,
                                       "maintainer_decision": "",
                                       "current_code_is_correct_use": False,
                                       "correct_use_reason": "", "rationale": ""})
                import re
                path = re.search(r'"target_file":\s*"([^"]+)"', prompt).group(1)
                test = "MainTest" in path
                original = "int t = 1;" if test else "int value = 1;"
                return json.dumps({
                    "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "source_file_path": path,
                    "explanation": "e", "edits": [{"source_file_path": path, "symbol": "v",
                                                   "edit_kind": "declaration",
                                                   "original_code": original,
                                                   "corrected_code": original.replace("1", "2"),
                                                   "reason": "r"}],
                    "no_change_required": False, "provided_contracts": [],
                    "required_contracts": [], "required_tests": [],
                    "manual_review_required": True,
                    "review_assumptions": test_assumptions if test else production_assumptions,
                    "confidence": "high"})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "repo/src/test").mkdir(parents=True)
            (root / "repo/src/Main.java").write_text("class X { int value = 1; }", encoding="utf-8")
            (root / "repo" / test_path).write_text("class T { int t = 1; }", encoding="utf-8")
            generator = object.__new__(FixGenerator)
            generator.output_dir = root / "out"
            generator.provider = Provider()
            generator.web_search = False
            generator.logger = logging.getLogger("test")
            error = {"repository_path": str(root / "repo"), "error_index": 2,
                     "evidence_analysis": {"confirmed_cause": "cause", "coordinated_fix_plan": {
                         "required_edits": [{"source_file_path": "src/Main.java", "symbol": "value"},
                                            {"source_file_path": test_path, "symbol": "t"}]}}}
            with self.assertLogs("test", level="WARNING") as logs:
                result = generator.generate_coordinated_file_drafts(
                    error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "method")
            manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        return result, manifest, logs.output

    def test_a_test_the_review_drops_as_unrelated_is_recorded_and_its_assumptions_go(self):
        result, manifest, logs = self._run(
            ["WebUser is accessible to the module's unit tests"],
            ["The stored value keeps its format"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["dropped_unrelated_tests"], [self.TEST])
        self.assertEqual(manifest["dropped_unrelated_tests"], [self.TEST])
        self.assertTrue(any("unrelated to the change" in line and self.TEST in line
                            for line in logs))
        self.assertNotIn("WebUser is accessible to the module's unit tests",
                         result["review_assumptions"])
        self.assertIn("The stored value keeps its format", result["review_assumptions"])

    def test_an_assumption_a_kept_file_also_made_stays(self):
        from cognalys.llm.coordinated_generation import assumptions_without_files

        shared = "Existing callers pass a non-null context"
        result, _, _ = self._run([shared, "only the test said this"], [shared])
        self.assertIn(shared, result["review_assumptions"])
        self.assertNotIn("only the test said this", result["review_assumptions"])
        drafts = [{"source_file_path": "a.kt", "review_assumptions": ["x", "y"]},
                  {"source_file_path": "b.kt", "review_assumptions": ["y", "z"]}]
        self.assertEqual(assumptions_without_files(["x", "y", "z", "w"], drafts, ["a.kt"]),
                         ["y", "z", "w"])


class EmptyDraftNamingUnplannableSourceTests(unittest.TestCase):
    """Session LogFile$Writer.writeEntry (session_writeentry_joint, 2026-11-10):
    the draft of PersistentLogger.kt returned no edit twice and named
    LogSecretProvider, which the plan had only as fetched evidence; the shape
    failure discarded the finished LogFile.java draft and the unit became an
    issue saying no behaviour-preserving change was found."""

    PROVIDER = "app/src/main/java/org/x/logging/LogSecretProvider.kt"
    SESSION_DRAFT = {
        "explanation": "The supplied file only obtains the secret through "
                       "getOrCreateAttachmentSecret(); an edit here cannot implement the "
                       "requested generation change safely.",
        "review_assumptions": ["LogSecretProvider's implementation and persistence API "
                               "were not supplied."],
        "no_change_required": False, "edits": []}

    def test_the_session_draft_names_the_file_without_exact_source(self):
        from cognalys.llm.coordinated_generation import draft_names_unplannable_sources

        self.assertEqual(draft_names_unplannable_sources(self.SESSION_DRAFT, [self.PROVIDER]),
                         [self.PROVIDER])
        # A draft with edits, or one saying no change is required, is not this case.
        self.assertEqual(draft_names_unplannable_sources(
            {**self.SESSION_DRAFT, "edits": [{"x": 1}]}, [self.PROVIDER]), [])
        self.assertEqual(draft_names_unplannable_sources(
            {**self.SESSION_DRAFT, "no_change_required": True}, [self.PROVIDER]), [])
        # A file it does not name, or one whose name another listed file shares.
        self.assertEqual(draft_names_unplannable_sources(
            self.SESSION_DRAFT, ["app/src/main/java/org/x/Other.kt"]), [])
        self.assertEqual(draft_names_unplannable_sources(
            self.SESSION_DRAFT, [self.PROVIDER, "lib/src/LogSecretProvider.kt"]), [])

    def test_the_manifest_files_without_exact_text_are_recorded_for_the_drafts(self):
        from cognalys.llm.finding_adjudication import sources_without_exact_text

        manifest = [
            {"source_file_path": self.PROVIDER, "exact_source_available": False},
            {"source_file_path": "app/A.kt", "exact_source_available": False},
            {"source_file_path": "app/A.kt", "exact_source_available": True},
            {"source_file_path": "app/build.gradle", "exact_source_available": False}]
        self.assertEqual(sources_without_exact_text(manifest), [self.PROVIDER])

    def _generator(self, root, plans):
        import logging

        from cognalys.llm.generate_error_fixes import FixGenerator

        provider_path = self.PROVIDER
        session_draft = self.SESSION_DRAFT

        class Provider:
            def generate(self, prompt, *args, **kwargs):
                if kwargs.get("schema_name") == "behavior_review":
                    return json.dumps({"regressions": [], "unrelated_test_edits": [],
                                       "maintainer_decision_required": False,
                                       "maintainer_decision": "",
                                       "current_code_is_correct_use": False,
                                       "correct_use_reason": "", "rationale": ""})
                import re
                path = re.search(r'"target_file":\s*"([^"]+)"', prompt).group(1)
                if path.endswith("PersistentLogger.kt"):
                    return json.dumps({**session_draft, "source_file_path": path,
                                       "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                                       "provided_contracts": [], "required_contracts": [],
                                       "required_tests": [], "manual_review_required": True,
                                       "confidence": "high"})
                original = {"LogFile.java": "int value = 1;",
                            "LogSecretProvider.kt": "val size = 1"}[Path(path).name]
                return json.dumps({
                    "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "source_file_path": path,
                    "explanation": "e", "edits": [{"source_file_path": path, "symbol": "v",
                                                   "edit_kind": "declaration",
                                                   "original_code": original,
                                                   "corrected_code": original.replace("1", "2"),
                                                   "reason": "r"}],
                    "no_change_required": False, "provided_contracts": [],
                    "required_contracts": [], "required_tests": [],
                    "manual_review_required": True, "review_assumptions": [],
                    "confidence": "high"})

        generator = object.__new__(FixGenerator)
        generator.output_dir = root / "out"
        generator.provider = Provider()
        generator.web_search = False
        generator.logger = logging.getLogger("test")

        def adjudicate(error, apk, method):
            plans.append(dict(error.get("previous_draft_needed_exact_sources") or {}))
            return {"generation_status": "supported_for_review",
                    "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "confirmed_cause": "cause",
                    "coordinated_fix_plan": {"required_edits": [
                        {"source_file_path": "app/LogFile.java", "symbol": "value"},
                        {"source_file_path": provider_path, "symbol": "size"}]}}, {}

        generator.adjudicate_finding = adjudicate
        return generator

    def test_the_empty_draft_supplies_the_file_and_plans_once_more(self):
        from unittest import mock

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            for path, text in (("app/LogFile.java", "class L { int value = 1; }"),
                               ("app/PersistentLogger.kt", "class P { val x = 1 }"),
                               (self.PROVIDER, "class S { val size = 1 }")):
                (repo / path).parent.mkdir(parents=True, exist_ok=True)
                (repo / path).write_text(text, encoding="utf-8")
            plans = []
            generator = self._generator(root, plans)
            error = {"repository_path": str(repo), "error_index": 0,
                     "plan_sources_without_exact_text": [self.PROVIDER],
                     "expanded_repository_context": {"multi_file_impact": {
                         "exact_candidate_sources": [], "coverage_requirements": {}}},
                     "evidence_analysis": {
                         "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                         "confirmed_cause": "cause", "coordinated_fix_plan": {
                             "required_edits": [
                                 {"source_file_path": "app/LogFile.java", "symbol": "value"},
                                 {"source_file_path": "app/PersistentLogger.kt",
                                  "symbol": "x"}]}}}
            with mock.patch("cognalys.llm.coordinated_generation._replan_refusal",
                            return_value=""):
                result = generator.generate_coordinated_file_drafts(
                    error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "writeEntry")
            impact = error["expanded_repository_context"]["multi_file_impact"]
        self.assertEqual(result["status"], "complete")
        self.assertEqual(sorted(edit["source_file_path"] for edit in result["edits"]),
                         ["app/LogFile.java", self.PROVIDER])
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0]["supplied_as_exact_source"], [self.PROVIDER])
        self.assertIn("LogSecretProvider", " ".join(
            plans[0]["empty_draft"]["review_assumptions"]))
        self.assertIn(self.PROVIDER, impact["required_caller_sources"])
        self.assertTrue(error["_exact_source_replanned"])

    def test_a_new_plan_whose_drafts_fail_leaves_the_first_ending_and_a_record(self):
        """Review of 2026-11-10: the drafts directory then holds the second plan's
        files; the manifest says the replan ran and how it ended."""
        from unittest import mock

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            for path, text in (("app/LogFile.java", "class L { int value = 1; }"),
                               ("app/PersistentLogger.kt", "class P { val x = 1 }"),
                               (self.PROVIDER, "class S { val size = 1 }")):
                (repo / path).parent.mkdir(parents=True, exist_ok=True)
                (repo / path).write_text(text, encoding="utf-8")
            plans = []
            generator = self._generator(root, plans)
            first_plan = {"required_edits": [
                {"source_file_path": "app/LogFile.java", "symbol": "value"},
                {"source_file_path": "app/PersistentLogger.kt", "symbol": "x"}]}

            def adjudicate(error, apk, method):
                plans.append(1)
                return {"generation_status": "supported_for_review",
                        "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                        "confirmed_cause": "cause", "coordinated_fix_plan": first_plan}, {}

            generator.adjudicate_finding = adjudicate
            error = {"repository_path": str(repo), "error_index": 0,
                     "plan_sources_without_exact_text": [self.PROVIDER],
                     "expanded_repository_context": {"multi_file_impact": {
                         "exact_candidate_sources": [], "coverage_requirements": {}}},
                     "evidence_analysis": {
                         "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                         "confirmed_cause": "cause", "coordinated_fix_plan": first_plan}}
            with mock.patch("cognalys.llm.coordinated_generation._replan_refusal",
                            return_value=""):
                result = generator.generate_coordinated_file_drafts(
                    error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "writeEntry")
            manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["draft_needs_exact_sources"], [self.PROVIDER])
        self.assertEqual(len(plans), 1)
        self.assertEqual(manifest["replan_with_exact_sources"]["status"], "invalid")
        self.assertEqual(result["replan_with_exact_sources"],
                         manifest["replan_with_exact_sources"])

    def test_without_the_route_the_shape_failure_stands_and_it_runs_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plans = []
            generator = self._generator(root, plans)
            result = {"draft_needs_exact_sources": [self.PROVIDER]}
            # Another replan already spent, or no impact to add the file to.
            self.assertFalse(generator.replan_with_exact_sources(
                {"_behavior_replanned": True, "expanded_repository_context": {
                    "multi_file_impact": {}}}, result, "a.apk", "m"))
            self.assertFalse(generator.replan_with_exact_sources({}, result, "a.apk", "m"))
        self.assertEqual(plans, [])


if __name__ == "__main__":
    unittest.main()
