import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.apk_evidence import (  # noqa: E402
    application_package,
    class_in_application_namespace,
    class_in_application_namespaces,
    collect_apk_evidence,
    repository_namespaces,
    dex_entries_containing,
    find_dexdump,
    library_versions,
    name_looks_obfuscated,
    parse_dexdump_class,
)
from cognalys.extraction.artifact_cache import (  # noqa: E402
    ArtifactCache,
    github_repository_url,
    upstream_repository_for,
)
from cognalys.llm.pipeline_architecture import (  # noqa: E402
    adjudication_schema,
    bytecode_argument_origins,
    cause_rule_section_issues,
    collateral_constraint_violations,
    evidence_extraction_schema,
    field_call_sequences,
    violation_rule_section,
)
from cognalys.llm.generate_error_fixes import FixGenerator, collateral_issue_candidate  # noqa: E402


SPECS = ROOT / "data" / "specifications"
KEYSTORE_SPEC = json.loads((SPECS / "KeyStoreSpec.json").read_text(encoding="utf-8"))
TMF_SPEC = json.loads(
    (SPECS / "TrustManagerFactorySpec.json").read_text(encoding="utf-8")
)

FREEOTP_ID = (
    "org.fedorahosted.freeotp.TokenPersistence:::<init>:::KeyStoreSpec:::"
    "InvalidSequenceOfMethodCalls:::unknown"
)

# org.fedorahosted.freeotp's TokenPersistence, reduced to what the matching
# reads: the field is assigned in the constructor and used in two methods.
FREEOTP_SOURCE = """package org.fedorahosted.freeotp;

public class TokenPersistence {
    private final SharedPreferences mTokens;
    private final KeyStore mKeyStore;

    public TokenPersistence(Context ctx)
            throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException {
        mTokens = ctx.getSharedPreferences(STORE, MODE_PRIVATE);

        mKeyStore = KeyStore.getInstance("AndroidKeyStore");
        mKeyStore.load(null);
    }

    public boolean provision(EncryptedKey mk, KeyProtection kp, String password) throws GeneralSecurityException {
        // Store the master key in the key store restricted to encrypt-only.
        mKeyStore.setEntry(MASTER, new KeyStore.SecretKeyEntry(mk.decrypt(password)), kp);
        return mBackups.edit().commit();
    }

    public List<RestoredData> restore(String pwd) throws GeneralSecurityException,
            IOException, JSONException, BadPasswordException  {
        mKeyStore.setEntry(MASTER, new KeyStore.SecretKeyEntry(mk.decrypt(pwd)), kp);

        for (Map.Entry<String, ?> item : mBackups.getAll().entrySet()) {
            if (uuid.equals(MASTER)) {
                continue;
            }
            Key key = mKeyStore.getKey(uuid, null);
        }
        return restored;
    }
}
"""
_CONSTRUCTOR_START = FREEOTP_SOURCE.index("    public TokenPersistence(")
FREEOTP_CONSTRUCTOR = FREEOTP_SOURCE[
    _CONSTRUCTOR_START:FREEOTP_SOURCE.index("    }\n", _CONSTRUCTOR_START) + 6
]

FREEOTP_CAUSE = (
    "The reported constructor matches the rule's documented false-positive "
    'shape: Android application code calls java.security.KeyStore.getInstance('
    '"AndroidKeyStore"), but the static rule applies its five-value KeyStore '
    "type whitelist literally."
)
TYPE_PREDICATE = {
    "event": "The constructor's KeyStore factory type argument belongs to the "
             "KeyStoreSpec permitted type set.",
    "status": "violated",
    "rule_section": "constraint",
    "evidence": 'Evidence IDs: SRC-001, SPEC-001. The source passes the literal '
                '"AndroidKeyStore". The supplied specification\'s permitted set '
                "is JCEKS, JKS, DKS, PKCS11, and PKCS12.",
}
STORE_PREDICATE = {
    "event": "The provision method's modeled write branch includes Store after "
             "its SetEntry before the method returns.",
    "status": "violated",
    "rule_section": "order",
    "evidence": "Evidence IDs: SRC-001. provision invokes mKeyStore.setEntry and "
                "returns without a store call.",
}

# Real `dexdump -d` output (build-tools 37.0.0) for a class compiled with d8.
DEXDUMP_OUTPUT = """Processing '/tmp/dexsample/dex/classes.dex'...
Opened '/tmp/dexsample/dex/classes.dex', DEX version '038'
Class #0            -
  Class descriptor  : 'Lp/q/Box$Inner;'
  Access flags      : 0x0001 (PUBLIC)
  Direct methods    -
    #0              : (in Lp/q/Box$Inner;)
      name          : 'run'
      type          : '()V'
      access        : 0x0000 ()
      code          -
000208:                                        |[000208] p.q.Box$Inner.run:()V
000218: 0e00                                   |0000: return-void

Class #1            -
  Class descriptor  : 'Lp/q/Box;'
  Access flags      : 0x0011 (PUBLIC FINAL)
  Instance fields   -
    #0              : (in Lp/q/Box;)
      name          : 'runtime'
      type          : 'Ljava/lang/String;'
      access        : 0x0012 (PRIVATE FINAL)
  Direct methods    -
    #1              : (in Lp/q/Box;)
      name          : 'literal'
      type          : '()Ljavax/net/ssl/TrustManagerFactory;'
      access        : 0x0009 (PUBLIC STATIC)
      code          -
00021c:                                        |[00021c] p.q.Box.literal:()Ljavax/net/ssl/TrustManagerFactory;
00022c: 1a00 1000                              |0000: const-string v0, "PKIX" // string@0010
000230: 7110 0200 0000                         |0002: invoke-static {v0}, Ljavax/net/ssl/TrustManagerFactory;.getInstance:(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory; // method@0002
000236: 0c00                                   |0005: move-result-object v0
000238: 1100                                   |0006: return-object v0
      catches       : (none)

    #2              : (in Lp/q/Box;)
      name          : 'runtime'
      type          : '()Ljavax/net/ssl/TrustManagerFactory;'
      access        : 0x0009 (PUBLIC STATIC)
      code          -
00023c:                                        |[00023c] p.q.Box.runtime:()Ljavax/net/ssl/TrustManagerFactory;
00024c: 7100 0100 0000                         |0000: invoke-static {}, Ljavax/net/ssl/TrustManagerFactory;.getDefaultAlgorithm:()Ljava/lang/String; // method@0001
000252: 0c00                                   |0003: move-result-object v0
000254: 7110 0200 0000                         |0004: invoke-static {v0}, Ljavax/net/ssl/TrustManagerFactory;.getInstance:(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory; // method@0002
00025a: 0c00                                   |0007: move-result-object v0
00025c: 1100                                   |0008: return-object v0

Class #2            -
  Class descriptor  : 'Lp/q/Other;'
"""

# javap -c -p for okhttp-4.12.0's Platform.platformTrustManager, trimmed.
JAVAP_METHOD = {
    "signature": "public javax.net.ssl.X509TrustManager platformTrustManager();",
    "disassembly": (
        "  public javax.net.ssl.X509TrustManager platformTrustManager();\n"
        "    Code:\n"
        "       0: invokestatic  #40                 // Method javax/net/ssl/TrustManagerFactory.getDefaultAlgorithm:()Ljava/lang/String;\n"
        "       3: invokestatic  #43                 // Method javax/net/ssl/TrustManagerFactory.getInstance:(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;\n"
        "       6: astore_1\n"
    ),
}


def _publish(root, group, artifact, version, name, content):
    directory = root / group / artifact / version / "0123abcd"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(content, encoding="utf-8")


class ViolationSectionTests(unittest.TestCase):
    """A confirmed cause has to be about the part of the rule reported."""

    FINDING = {"reported_violation": "InvalidSequenceOfMethodCalls"}

    def test_the_detector_types_map_to_rule_sections(self):
        self.assertEqual(violation_rule_section("InvalidSequenceOfMethodCalls"), "order")
        self.assertEqual(violation_rule_section("InvalidKeyStoreType"), "constraint")
        self.assertEqual(violation_rule_section("UnsafeAlgorithm"), "constraint")

    def test_a_type_from_another_detector_family_maps_to_nothing(self):
        self.assertEqual(violation_rule_section("URLEncoder_EncodeUTF8"), "")

    def test_a_cause_from_another_section_is_rejected(self):
        """freeotp: a sequence error explained by the type whitelist."""
        issues = cause_rule_section_issues(
            {"cause_status": "confirmed", "cause_rule_section": "constraint"},
            self.FINDING,
        )
        self.assertEqual(len(issues), 1)
        self.assertIn("order", issues[0])
        self.assertIn("InvalidSequenceOfMethodCalls", issues[0])

    def test_a_cause_from_the_reported_section_passes(self):
        self.assertEqual(cause_rule_section_issues(
            {"cause_status": "confirmed", "cause_rule_section": "order"},
            self.FINDING,
        ), [])

    def test_an_unconfirmed_cause_is_not_held_to_a_section(self):
        self.assertEqual(cause_rule_section_issues(
            {"cause_status": "unknown", "cause_rule_section": "constraint"},
            self.FINDING,
        ), [])

    def test_an_adjudication_without_the_field_is_not_held_to_it(self):
        self.assertEqual(cause_rule_section_issues(
            {"cause_status": "confirmed"}, self.FINDING,
        ), [])

    def test_an_unmapped_violation_type_is_not_enforced(self):
        self.assertEqual(cause_rule_section_issues(
            {"cause_status": "confirmed", "cause_rule_section": "other"},
            {"reported_violation": "URLEncoder_EncodeUTF8"},
        ), [])

    def test_both_schemas_ask_for_the_section(self):
        adjudication = adjudication_schema("generic")["properties"]
        self.assertIn("order", adjudication["cause_rule_section"]["enum"])
        predicate = (evidence_extraction_schema("generic")["properties"]
                     ["predicate_assessment"]["items"]["properties"])
        self.assertIn("constraint", predicate["rule_section"]["enum"])


class CollateralDismissalTests(unittest.TestCase):
    """freeotp's issue asked maintainers about the documented false positive."""

    ERROR = {
        "unique_error_id": FREEOTP_ID, "spec": "KeyStoreSpec",
        "specification_context": KEYSTORE_SPEC,
    }

    def _analysis(self, *predicates, cause=FREEOTP_CAUSE):
        return {"confirmed_cause": cause, "predicate_assessment": list(predicates)}

    def test_a_value_the_analysis_dismissed_as_documented_is_not_raised(self):
        excluded = []
        collateral = collateral_constraint_violations(
            self._analysis(TYPE_PREDICATE), self.ERROR, excluded=excluded,
        )
        self.assertEqual(collateral, [])
        self.assertEqual(len(excluded), 1)
        self.assertIn('"androidkeystore"', excluded[0]["reason"])

    def test_the_reported_section_is_not_raised_again(self):
        collateral = collateral_constraint_violations(
            self._analysis(STORE_PREDICATE), self.ERROR,
        )
        self.assertEqual(collateral, [])

    def test_without_a_dismissal_the_literal_violation_still_stands(self):
        """The shape alone never suppresses: the analysis must have said so."""
        collateral = collateral_constraint_violations(
            self._analysis(TYPE_PREDICATE, cause=""), self.ERROR,
        )
        self.assertEqual(len(collateral), 1)

    def test_an_ungrounded_specification_cannot_dismiss_anything(self):
        error = dict(self.ERROR, specification_context=dict(
            KEYSTORE_SPEC, shapes_grounded=False,
        ))
        collateral = collateral_constraint_violations(
            self._analysis(TYPE_PREDICATE), error,
        )
        self.assertEqual(len(collateral), 1)

    def test_dismissal_texts_from_the_adjudication_count(self):
        collateral = collateral_constraint_violations(
            {"predicate_assessment": [TYPE_PREDICATE]}, self.ERROR,
            dismissal_texts=[FREEOTP_CAUSE],
        )
        self.assertEqual(collateral, [])

    def test_evidence_ids_are_lifted_out_of_the_text(self):
        predicate = dict(TYPE_PREDICATE)
        collateral = collateral_constraint_violations(
            {"predicate_assessment": [predicate]}, self.ERROR,
        )
        [item] = collateral
        self.assertEqual(item["evidence_ids"], ["SRC-001", "SPEC-001"])
        self.assertFalse(item["explanation"].startswith("Evidence IDs"))


class CollateralIssueTitleTests(unittest.TestCase):
    COLLATERAL = [{
        "predicate": "The password input is not hard-coded.",
        "evidence_ids": ["SRC-001"],
        "explanation": 'It is the literal "password".',
    }]

    def test_the_title_names_the_class_and_api_not_internal_ids(self):
        issue = collateral_issue_candidate(
            self.COLLATERAL, "<init>", "KeyStoreSpec", "v1",
            class_name="org.fedorahosted.freeotp.TokenPersistence",
            api_name="KeyStore",
        )
        self.assertEqual(
            issue["title"], "Possible KeyStore issue in the TokenPersistence constructor",
        )
        self.assertNotIn("<init>", issue["finding_summary"])
        self.assertNotIn("KeyStoreSpec", issue["finding_summary"].split(":")[0])

    def test_the_summary_has_no_doubled_punctuation(self):
        issue = collateral_issue_candidate(
            self.COLLATERAL, "load", "KeyStoreSpec", "v2",
            class_name="a.b.Store", api_name="KeyStore",
        )
        self.assertNotIn("..", issue["finding_summary"])
        self.assertEqual(issue["title"], "Possible KeyStore issue in Store.load")


class FieldSequenceTests(unittest.TestCase):
    def _sequences(self):
        return field_call_sequences(FREEOTP_SOURCE, FREEOTP_CONSTRUCTOR, KEYSTORE_SPEC)

    def test_the_field_is_followed_through_every_method_that_uses_it(self):
        [sequence] = self._sequences()
        self.assertEqual(sequence["field"], "mKeyStore")
        self.assertEqual(
            [item["event"] for item in sequence["occurrences"]],
            ["Get", "Load", "SetEntry", "SetEntry", "GetKey"],
        )
        self.assertEqual(
            sequence["methods"], ["TokenPersistence", "provision", "restore"],
        )

    def test_a_local_variable_is_not_a_field(self):
        body = (
            "    void make() {\n"
            '        KeyStore ks = KeyStore.getInstance("PKCS12");\n'
            "        ks.load(null);\n"
            "    }\n"
        )
        source = "class A {\n" + body + "    void other() { ks.store(out, pw); }\n}\n"
        self.assertEqual(field_call_sequences(source, body, KEYSTORE_SPEC), [])

    def test_nothing_without_a_class_source(self):
        self.assertEqual(field_call_sequences("", FREEOTP_CONSTRUCTOR, KEYSTORE_SPEC), [])


class ArgumentOriginTests(unittest.TestCase):
    """What the detector renders as "found ." the bytecode states plainly."""

    def _dex_methods(self):
        _, literal = parse_dexdump_class(DEXDUMP_OUTPUT.splitlines(), "Lp/q/Box;", "literal")
        _, runtime = parse_dexdump_class(DEXDUMP_OUTPUT.splitlines(), "Lp/q/Box;", "runtime")
        return literal, runtime

    def test_a_runtime_default_is_recognised_in_dex_bytecode(self):
        _, runtime = self._dex_methods()
        [origin] = bytecode_argument_origins(runtime, TMF_SPEC)
        self.assertEqual(origin["call"], "TrustManagerFactory.getInstance")
        self.assertEqual(origin["argument_origin"], "method_return")
        self.assertIn("getDefaultAlgorithm", origin["producer"])

    def test_a_literal_is_recognised_in_dex_bytecode(self):
        literal, _ = self._dex_methods()
        [origin] = bytecode_argument_origins(literal, TMF_SPEC)
        self.assertEqual(origin["argument_origin"], "string_literal")
        self.assertEqual(origin["value"], "PKIX")

    def test_a_runtime_default_is_recognised_in_javap_output(self):
        [origin] = bytecode_argument_origins([JAVAP_METHOD], TMF_SPEC)
        self.assertEqual(origin["argument_origin"], "method_return")
        self.assertIn("javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm",
                      origin["producer"])

    def test_a_value_passed_through_a_local_variable_is_followed(self):
        """Conscrypt 2.5.0's createDefaultX509TrustManager, verbatim in shape."""
        method = {"signature": "createDefaultX509TrustManager()", "disassembly": (
            "       0: invokestatic  #117                // Method javax/net/ssl/TrustManagerFactory.getDefaultAlgorithm:()Ljava/lang/String;\n"
            "       3: astore_0\n"
            "       4: aload_0\n"
            "       5: invokestatic  #118                // Method javax/net/ssl/TrustManagerFactory.getInstance:(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;\n"
            "       8: astore_1\n"
        )}
        [origin] = bytecode_argument_origins([method], TMF_SPEC)
        self.assertEqual(origin["argument_origin"], "method_return")
        self.assertIn("getDefaultAlgorithm", origin["producer"])

    def test_a_dex_register_is_followed_past_unrelated_instructions(self):
        method = {"signature": "m()", "disassembly": (
            '0000: const-string v1, "PKIX" // string@0010\n'
            "0002: sget-object v0, Lp/Q;.x:Ljava/lang/Object; // field@0001\n"
            "0004: iput-object v1, v0, Lp/Q;.y:Ljava/lang/String; // field@0002\n"
            "0006: invoke-static {v1}, Ljavax/net/ssl/TrustManagerFactory;.getInstance:(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory; // method@0002\n"
        )}
        [origin] = bytecode_argument_origins([method], TMF_SPEC)
        self.assertEqual(origin["argument_origin"], "string_literal")
        self.assertEqual(origin["value"], "PKIX")

    def test_a_field_read_is_named_not_guessed(self):
        method = {"signature": "m()", "disassembly": (
            "       0: getstatic     #5                  // Field ALGORITHM:Ljava/lang/String;\n"
            "       3: invokestatic  #43                 // Method javax/net/ssl/TrustManagerFactory.getInstance:(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;\n"
        )}
        [origin] = bytecode_argument_origins([method], TMF_SPEC)
        self.assertEqual(origin["argument_origin"], "field")
        self.assertIn("ALGORITHM", origin["field"])

    def test_a_specification_naming_no_typed_factory_traces_nothing(self):
        self.assertEqual(bytecode_argument_origins(
            [JAVAP_METHOD], {"events": [{"api_patterns": [".init("]}]},
        ), [])


class DexdumpParsingTests(unittest.TestCase):
    def test_only_the_requested_class_and_method_are_returned(self):
        found, methods = parse_dexdump_class(
            DEXDUMP_OUTPUT.splitlines(), "Lp/q/Box;", "runtime",
        )
        self.assertTrue(found)
        # The field named "runtime" is not a method.
        [method] = methods
        self.assertEqual(
            method["signature"],
            "0x0009 (PUBLIC STATIC) runtime()Ljavax/net/ssl/TrustManagerFactory;",
        )
        self.assertIn("getDefaultAlgorithm", method["disassembly"])
        self.assertNotIn("PKIX", method["disassembly"])
        self.assertFalse(method["disassembly"].startswith("["))

    def test_a_nested_class_is_its_own_block(self):
        found, methods = parse_dexdump_class(
            DEXDUMP_OUTPUT.splitlines(), "Lp/q/Box$Inner;", "run",
        )
        self.assertTrue(found)
        self.assertEqual(len(methods), 1)

    def test_a_class_the_dex_does_not_define_is_reported_as_absent(self):
        found, methods = parse_dexdump_class(
            DEXDUMP_OUTPUT.splitlines(), "Lp/q/Missing;", "run",
        )
        self.assertFalse(found)
        self.assertEqual(methods, [])


class ApkEvidenceTests(unittest.TestCase):
    def _apk(self, directory: Path) -> Path:
        path = directory / "app.example_12.apk"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("classes.dex", b"dex\n038\x00Lp/q/Other;")
            archive.writestr("classes2.dex", b"dex\n038\x00Lp/q/Box;")
            archive.writestr(
                "META-INF/androidx.security_security-crypto.version", "1.1.0-alpha06\n",
            )
            archive.writestr("META-INF/services/x.version", "ignored")
        return path

    def test_the_application_package_comes_from_the_file_name(self):
        self.assertEqual(
            application_package("com.mde.potdroid_82.apk"), "com.mde.potdroid",
        )
        self.assertEqual(application_package("x_1.apk", "org.declared"), "org.declared")

    def test_classes_in_the_application_package_are_its_own(self):
        self.assertTrue(class_in_application_namespace(
            "com.mde.potdroid.helpers.f", "com.mde.potdroid",
        ))
        self.assertFalse(class_in_application_namespace(
            "com.mde.potdroidx.Thing", "com.mde.potdroid",
        ))
        self.assertFalse(class_in_application_namespace(
            "okhttp3.internal.platform.Platform", "org.jellyfin.mobile",
        ))

    def test_a_version_name_suffix_is_not_part_of_the_package(self):
        self.assertEqual(
            application_package("com.duckduckgo.mobile.android_5.148.0.apk"),
            "com.duckduckgo.mobile.android",
        )

    def test_the_repositorys_own_namespaces_are_read(self):
        """DuckDuckGo: published as ...mobile.android, coded as ...app.browser."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            (root / "app" / "build.gradle").write_text(
                'android {\n  namespace \'com.duckduckgo.app.browser\'\n'
                '  defaultConfig { applicationId "com.duckduckgo.mobile.android" }\n}\n',
                encoding="utf-8",
            )
            (root / "lib" / "src" / "main").mkdir(parents=True)
            (root / "lib" / "src" / "main" / "AndroidManifest.xml").write_text(
                '<manifest xmlns:android="x" package="com.duckduckgo.lib"/>',
                encoding="utf-8",
            )
            (root / "build" / "generated").mkdir(parents=True)
            (root / "build" / "generated" / "build.gradle").write_text(
                'namespace "ignored.generated"', encoding="utf-8",
            )
            namespaces = repository_namespaces(root)
        self.assertEqual(
            sorted(namespaces),
            ["com.duckduckgo.app.browser", "com.duckduckgo.lib",
             "com.duckduckgo.mobile.android"],
        )

    def test_a_sibling_package_of_a_declared_namespace_is_the_applications(self):
        self.assertTrue(class_in_application_namespaces(
            "com.duckduckgo.app.global.api.ApiRequest",
            ["com.duckduckgo.mobile.android", "com.duckduckgo.app.browser"],
        ))

    def test_a_library_owned_by_a_declared_dependency_is_not_claimed(self):
        """An app under com.google.android.apps must not claim Play Services."""
        self.assertFalse(class_in_application_namespaces(
            "com.google.android.gms.common.GooglePlayServicesUtil",
            ["com.google.android.apps.authenticator"],
            owned_by_dependency=True,
        ))

    def test_an_unrelated_library_is_not_claimed(self):
        self.assertFalse(class_in_application_namespaces(
            "okhttp3.internal.platform.Platform",
            ["org.jellyfin.mobile", "org.jellyfin.mobile.app"],
        ))

    def test_obfuscated_names_are_recognised(self):
        self.assertTrue(name_looks_obfuscated("com.mde.potdroid.helpers.f", "a"))
        self.assertFalse(name_looks_obfuscated(
            "com.vayunmathur.passwords.cable.CableEid", "encrypt",
        ))

    def test_library_versions_come_from_meta_inf(self):
        with tempfile.TemporaryDirectory() as directory:
            versions = library_versions(self._apk(Path(directory)))
        self.assertEqual(
            versions, {"androidx.security_security-crypto": "1.1.0-alpha06"},
        )

    def test_the_dex_holding_the_class_is_found(self):
        with tempfile.TemporaryDirectory() as directory:
            entries = dex_entries_containing(self._apk(Path(directory)), "Lp/q/Box;")
        self.assertEqual(entries, ["classes2.dex"])

    def test_without_dexdump_the_record_says_so_and_keeps_the_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = self._apk(Path(directory))
            evidence = collect_apk_evidence(
                apk.name, "https://example.invalid/app.apk", "p.q.Box", "run",
                Path(directory), dexdump="", fetch=lambda url, cache, name: apk,
            )
        self.assertEqual(evidence["status"], "unavailable")
        self.assertEqual(evidence["reason"], "dexdump_not_found")
        self.assertIn("androidx.security_security-crypto", evidence["library_versions"])

    def test_a_minified_apk_is_not_mistaken_for_one_without_the_class(self):
        """maskan's F-Droid build: Tink renamed to A, B, C by R8."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.minified_1.apk"
            renamed = b"".join(
                f"L{a}/{b};".encode() for a in "abcdefgh" for b in "ABCDEFGH"
            )
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("classes.dex", b"dex\n038\x00" + renamed)
            evidence = collect_apk_evidence(
                path.name, "https://example.invalid/a.apk",
                "com.google.crypto.tink.integration.android.AndroidKeystoreAesGcm",
                "encryptInternal", Path(directory), dexdump="",
                fetch=lambda url, cache, name: path,
            )
        self.assertEqual(evidence["reason"], "class_not_in_minified_apk")
        self.assertTrue(evidence["minification"]["minified"])
        self.assertIn("not the binary the detector analysed", evidence["note"])

    def test_an_unminified_apk_without_the_class_says_only_that(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = collect_apk_evidence(
                "app.example_12.apk", "https://example.invalid/a.apk",
                "p.q.Missing", "run", Path(directory), dexdump="",
                fetch=lambda url, cache, name: self._apk(Path(directory)),
            )
        self.assertEqual(evidence["reason"], "class_not_in_apk")
        self.assertNotIn("note", evidence)

    def test_no_url_means_no_download(self):
        evidence = collect_apk_evidence("a_1.apk", "", "p.Q", "m", Path("."))
        self.assertEqual(evidence["reason"], "no_apk_url")

    def test_a_failed_download_is_recorded_not_raised(self):
        def failing(url, cache, name):
            raise OSError("network unreachable")
        evidence = collect_apk_evidence(
            "a_1.apk", "https://example.invalid/a_1.apk", "p.Q", "m", Path("."),
            fetch=failing,
        )
        self.assertIn("apk_download_failed", evidence["reason"])

    def test_a_real_dex_is_disassembled(self):
        """End to end through javac, d8 and dexdump, when they are installed."""
        dexdump = find_dexdump()
        d8 = Path(dexdump).parent / "lib" / "d8.jar" if dexdump else None
        if not (dexdump and d8 and d8.is_file() and shutil.which("javac")
                and shutil.which("java")):
            self.skipTest("javac, java, d8 and dexdump are required")
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            source = work / "src" / "p" / "q" / "Box.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package p.q;\nimport javax.net.ssl.TrustManagerFactory;\n"
                "public final class Box {\n"
                "  public static TrustManagerFactory runtime() throws Exception {\n"
                "    return TrustManagerFactory.getInstance("
                "TrustManagerFactory.getDefaultAlgorithm());\n  }\n}\n",
                encoding="utf-8",
            )
            classes = work / "classes"
            subprocess.run(["javac", "--release", "11", "-d", str(classes), str(source)],
                           check=True, capture_output=True)
            dex_dir = work / "dex"
            dex_dir.mkdir()
            subprocess.run(
                ["java", "-cp", str(d8), "com.android.tools.r8.D8", "--min-api", "26",
                 "--output", str(dex_dir), str(classes / "p" / "q" / "Box.class")],
                check=True, capture_output=True,
            )
            apk = work / "app.example_1.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.write(dex_dir / "classes.dex", "classes.dex")
            evidence = collect_apk_evidence(
                apk.name, "https://example.invalid/app.apk", "p.q.Box", "runtime",
                work, fetch=lambda url, cache, name: apk,
            )
        self.assertEqual(evidence["status"], "available")
        [origin] = bytecode_argument_origins(evidence["methods"], TMF_SPEC)
        self.assertEqual(origin["argument_origin"], "method_return")


class UpstreamRepositoryTests(unittest.TestCase):
    def test_scm_spellings_normalise_to_one_url(self):
        for text in (
            "https://github.com/square/okhttp",
            "https://github.com/square/okhttp/",
            "scm:git:git@github.com:square/okhttp.git",
            "scm:git:https://github.com/square/okhttp.git",
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    github_repository_url(text), "https://github.com/square/okhttp",
                )
        self.assertEqual(github_repository_url("https://gitlab.com/a/b"), "")

    def test_the_library_pom_names_its_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _publish(root, "com.google.crypto.tink", "tink-android", "1.8.0",
                     "tink-android-1.8.0.pom",
                     "<project><scm><url>https://github.com/google/tink</url></scm></project>")
            found = upstream_repository_for(
                [{"group": "com.google.crypto.tink", "artifact": "tink-android",
                  "version": "1.8.0"}],
                ArtifactCache([root]),
            )
        self.assertEqual(found["url"], "https://github.com/google/tink")

    def test_an_inherited_scm_is_read_from_the_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _publish(root, "org.example", "lib", "2.0", "lib-2.0.pom",
                     "<project><parent><groupId>org.example</groupId>"
                     "<artifactId>parent</artifactId><version>5</version></parent></project>")
            _publish(root, "org.example", "parent", "5", "parent-5.pom",
                     "<project><scm><connection>scm:git:git://github.com/example/lib.git"
                     "</connection></scm></project>")
            found = upstream_repository_for(
                [{"group": "org.example", "artifact": "lib", "version": "2.0"}],
                ArtifactCache([root]),
            )
        self.assertEqual(found["url"], "https://github.com/example/lib")


class IssueRepositoryTests(unittest.TestCase):
    APP = "https://github.com/jellyfin/jellyfin-android"

    def test_an_application_finding_goes_to_the_application(self):
        match, target, reason = FixGenerator.issue_repository(
            {"repository_url": self.APP, "extraction_status": "success"}, "NO_SAFE_FIX",
        )
        self.assertEqual((match.group(1), match.group(2)), ("jellyfin", "jellyfin-android"))
        self.assertEqual(target, "application_repository")
        self.assertEqual(reason, "")

    def test_library_code_goes_to_the_library(self):
        match, target, _ = FixGenerator.issue_repository({
            "repository_url": self.APP,
            "extraction_status": "external_dependency_candidate",
            "dependency_context": {
                "owning_library_repository": {"url": "https://github.com/square/okhttp"},
            },
        }, "NO_SAFE_FIX")
        self.assertEqual((match.group(1), match.group(2)), ("square", "okhttp"))
        self.assertEqual(target, "upstream_library")

    def test_library_code_with_no_known_repository_goes_nowhere(self):
        match, _, reason = FixGenerator.issue_repository({
            "repository_url": self.APP,
            "extraction_status": "external_dependency_candidate",
            "csv_class": "okhttp3.internal.platform.Platform",
        }, "NO_SAFE_FIX")
        self.assertIsNone(match)
        self.assertIn("library code", reason)

    def test_a_dependency_change_is_the_applications_to_make(self):
        _, target, _ = FixGenerator.issue_repository({
            "repository_url": self.APP,
            "extraction_status": "external_dependency_candidate",
        }, "DEPENDENCY_FIX_SUPPORTED")
        self.assertEqual(target, "application_repository")


class AnalysableTests(unittest.TestCase):
    BASE = {"method_body": "", "source_file_path": "", "surrounding_context": ""}

    def test_an_application_class_missing_from_the_checkout_says_so(self):
        reason = FixGenerator.unanalysable_reason(dict(
            self.BASE, extraction_status="application_class_not_in_checkout",
            application_namespace={"package": "com.mde.potdroid",
                                   "name_looks_obfuscated": True},
            apk_evidence={"status": "unavailable", "reason": "class_not_in_apk"},
        ))
        self.assertIn("application's own package com.mde.potdroid", reason)
        self.assertIn("obfuscated", reason)
        self.assertIn("class_not_in_apk", reason)
        self.assertNotIn("dependency matched", reason)

    def test_an_identified_dependency_reported_at_an_application_class_is_analysed(self):
        """dep_analyzer names an application class for an OkHttp version."""
        self.assertEqual(FixGenerator.unanalysable_reason(dict(
            self.BASE, extraction_status="application_class_not_in_checkout",
            error_message="com.squareup.okhttp3:okhttp 3.12.0 is outdated",
            dependency_context={"status": "identified", "likely_dependency": {
                "group": "com.squareup.okhttp3", "artifact": "okhttp",
            }},
        )), "")

    def test_a_dependency_the_message_does_not_name_leaves_it_unanalysable(self):
        """run_20260914_122712: libkiwix matched org.kiwix.kiwixmobile by name."""
        reason = FixGenerator.unanalysable_reason(dict(
            self.BASE, extraction_status="application_class_not_in_checkout",
            error_message="SecurityException: Permission denial reading external storage.",
            application_namespace={"package": "org.kiwix.kiwixmobile"},
            dependency_context={"status": "identified", "likely_dependency": {
                "group": "org.kiwix", "artifact": "libkiwix",
            }},
        ))
        self.assertIn("org.kiwix:libkiwix", reason)
        self.assertIn("does not name it", reason)

    def test_a_class_missing_from_an_unminified_apk_does_not_match_the_build(self):
        reason = FixGenerator.unanalysable_reason(dict(
            self.BASE, extraction_status="application_class_not_in_checkout",
            application_namespace={"package": "org.schabi.newpipe"},
            apk_evidence={"status": "unavailable", "reason": "class_not_in_apk"},
        ))
        self.assertTrue(reason.startswith("the reported class is in neither"))
        self.assertIn("does not correspond to the build", reason)
        self.assertNotIn("revision", reason)

    def test_a_minified_apk_keeps_the_revision_explanation(self):
        reason = FixGenerator.unanalysable_reason(dict(
            self.BASE, extraction_status="application_class_not_in_checkout",
            application_namespace={"package": "org.schabi.newpipe"},
            apk_evidence={"status": "unavailable",
                          "reason": "class_not_in_minified_apk"},
        ))
        self.assertIn("revision", reason)

    def test_rows_recorded_without_source_say_what_stopped_them(self):
        for status, fragment in (
            ("repository_not_cloned", "could not be cloned"),
            ("source_file_unreadable", "could not be read"),
            ("missing_class_or_method", "names no class"),
        ):
            with self.subTest(status=status):
                self.assertIn(fragment, FixGenerator.unanalysable_reason(
                    dict(self.BASE, extraction_status=status)))

    def test_a_method_the_existing_class_does_not_declare_is_closed(self):
        reason = FixGenerator.unanalysable_reason(dict(
            self.BASE, extraction_status="method_not_found",
            source_file_path="terminal-emulator/src/TerminalSession.java",
            method_name="initialize",
        ))
        self.assertIn("declares no method named initialize", reason)

    def test_a_missing_method_whose_message_names_a_dependency_is_analysed(self):
        self.assertEqual(FixGenerator.unanalysable_reason(dict(
            self.BASE, extraction_status="method_not_found",
            source_file_path="app/src/NewPipeSettings.java",
            dependency_finding={"status": "confirmed"},
        )), "")

    def test_the_apks_bytecode_makes_a_finding_analysable(self):
        self.assertEqual(FixGenerator.unanalysable_reason(dict(
            self.BASE, extraction_status="application_class_not_in_checkout",
            apk_evidence={"status": "available", "methods": [{"signature": "a()V"}]},
        )), "")


if __name__ == "__main__":
    unittest.main()
