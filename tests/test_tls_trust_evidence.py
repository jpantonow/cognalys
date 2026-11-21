import tempfile
import unittest
from pathlib import Path
from unittest import mock


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction import tls_trust_evidence as tls  # noqa: E402
from cognalys.llm import migration_policy  # noqa: E402

# Shaped like zSMTH's SMTHHelper (2026-10-17).
SOURCE = '''
public class SMTHHelper {
  static private final String SERVER = "https://www.newsmth.net";
  static private final String CDN = "https://static.newsmth.net";
  private static OkHttpClient getUnsafeOkHttpClient() {
    final TrustManager[] trustAllCerts = new TrustManager[] {
      new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }
      }
    };
    final SSLContext sslContext = SSLContext.getInstance("SSL");
    builder.hostnameVerifier(new HostnameVerifier() {
      @Override
      public boolean verify(String hostname, SSLSession session) {
        return true;
      }
    });
  }
}
'''
ROOT = "-----BEGIN CERTIFICATE-----\nMIIBroot\n-----END CERTIFICATE-----\n"


def resolver(results):
    return lambda host: results[host]


class TlsTrustEvidenceTests(unittest.TestCase):
    def finding(self, directory):
        root = Path(directory)
        source = root / "app/src/main/java/c/SMTHHelper.java"
        source.parent.mkdir(parents=True)
        source.write_text(SOURCE)
        return {"repository_path": str(root),
                "source_file_path": "app/src/main/java/c/SMTHHelper.java"}

    def test_overrides_and_hosts_are_read_from_the_class(self):
        self.assertEqual(tls.trust_overrides(SOURCE), {"trust_all": True, "any_hostname": True})
        self.assertEqual(tls.hardcoded_hosts(SOURCE), ["static.newsmth.net", "www.newsmth.net"])
        self.assertEqual(tls.trust_overrides("checkServerTrusted(c, a) { verify(chain); }"),
                         {"trust_all": False, "any_hostname": False})

    def test_resolved_anchors_become_provided_files_and_unreachable_hosts_are_named(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = tls.tls_trust_evidence(self.finding(directory), resolver({
                "www.newsmth.net": {"host": "www.newsmth.net", "root_pem": ROOT,
                                    "root_subject": "CN=ISRG Root X1,O=ISRG,C=US",
                                    "root_not_after": "Jun 4 2035"},
                "static.newsmth.net": {"host": "static.newsmth.net", "unreachable": True,
                                       "error": "does not resolve"}}))
        self.assertTrue(evidence["trust_all_hosts_resolved"])
        self.assertEqual(evidence["unverified_hosts"], ["static.newsmth.net"])
        [provided] = evidence["provided_files"]
        self.assertEqual(provided["path"], "app/src/main/res/raw/tls_root_isrg_root_x1.pem")
        self.assertEqual(provided["resource_reference"], "R.raw.tls_root_isrg_root_x1")
        self.assertEqual(provided["content"], ROOT)

    def test_a_certificate_problem_blocks_the_trust_change(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = tls.tls_trust_evidence(self.finding(directory), resolver({
                "www.newsmth.net": {"host": "www.newsmth.net",
                                    "error": "the server certificate does not verify"},
                "static.newsmth.net": {"host": "static.newsmth.net", "unreachable": True,
                                       "error": "does not resolve"}}))
        self.assertFalse(evidence["trust_all_hosts_resolved"])
        self.assertNotIn("provided_files", evidence)


class TlsTrustPolicyTests(unittest.TestCase):
    finding = {"spec": "SSLContextSpec", "error_message":
               "expecting one of TLSV1.2,TLSV1.3,TLS but found SSL",
               "unique_error_id": "c:::m:::SSLContextSpec:::ConstraintError:::x"}

    def test_without_resolved_evidence_the_scope_is_the_selector_only(self):
        with mock.patch.object(migration_policy, "_EVIDENCE",
                               {"tls_trust": (lambda error: {}, "established_tls_trust_evidence")}):
            policy = migration_policy.generic_migration_policy(self.finding)
        self.assertEqual(policy["consumer_scope"], "tls_selector_only")
        self.assertIn("Do not change trust managers, certificate validation, or hostname "
                      "verification.", policy["forbidden_changes"])
        self.assertNotIn("provided_files", policy)

    def test_resolved_evidence_selects_trust_restoration_with_the_provided_files(self):
        evidence = {"trust_all": True, "trust_all_hosts_resolved": True,
                    "provided_files": [{"path": "app/src/main/res/raw/r.pem", "content": ROOT}]}
        with mock.patch.object(migration_policy, "_EVIDENCE",
                               {"tls_trust": (lambda error: evidence, "established_tls_trust_evidence")}):
            policy = migration_policy.generic_migration_policy(self.finding)
        self.assertEqual(policy["consumer_scope"], "tls_trust_restoration")
        self.assertEqual(policy["provided_files"][0]["content"], ROOT)
        self.assertNotIn("provided_files", policy["established_tls_trust_evidence"])

    def test_provided_files_are_written_verbatim_over_any_model_edit(self):
        policy = {"provided_files": [{"path": "app/src/main/res/raw/r.pem", "content": ROOT},
                                     {"path": "../outside.pem", "content": "x"}]}
        edits = [{"source_file_path": "app/src/main/res/raw/r.pem", "edit_kind": "create",
                  "corrected_code": "retyped by a model"},
                 {"source_file_path": "app/src/main/java/A.java", "edit_kind": "method"}]
        result = migration_policy.with_provided_files(edits, policy)
        created = [edit for edit in result if edit["source_file_path"].endswith("r.pem")]
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0]["corrected_code"], ROOT)
        self.assertFalse(any("outside" in edit["source_file_path"] for edit in result))
        self.assertEqual(len(result), 2)


class ProvidedFileAuthorizationTests(unittest.TestCase):
    """zSMTH run4: the applicator refused the bundled root as outside the plan."""

    def test_a_provided_file_is_authorized_and_nothing_else_is(self):
        from cognalys.solutions.solution_applicator import validate_coordinated_edit_authorization

        plan = {"required_edits": [{"source_file_path": "app/src/main/java/A.java"}]}
        policy = {"provided_files": [{"path": "app/src/main/res/raw/r.pem", "content": ROOT}]}
        migration_policy.authorize_provided_files(plan, policy)
        solution = {"llm_architecture": {"version": "v2"}, "authorized_patch_plan": plan,
                    "coordinated_edits": migration_policy.with_provided_files(
                        [{"source_file_path": "app/src/main/java/A.java", "edit_kind": "method"}],
                        policy)}
        self.assertEqual(validate_coordinated_edit_authorization(solution), [])
        solution["coordinated_edits"].append(
            {"source_file_path": "app/src/main/res/raw/other.pem", "edit_kind": "create"})
        self.assertEqual(validate_coordinated_edit_authorization(solution),
                         ["EDIT_OUTSIDE_AUTHORIZED_PLAN:app/src/main/res/raw/other.pem"])


class TrustFactsTests(unittest.TestCase):
    """The sentences the pull request states about the bundled root."""

    evidence = {"host_roots": [
        {"host": "www.newsmth.net", "root_subject": "CN=ISRG Root X1,O=ISRG,C=US",
         "root_not_after": "Jun  4 11:04:38 2035 GMT"},
        {"host": "m.newsmth.net", "root_subject": "CN=ISRG Root X1,O=ISRG,C=US",
         "root_not_after": "Jun  4 11:04:38 2035 GMT"},
        {"host": "static.newsmth.net", "unreachable": True}],
        "unverified_hosts": ["static.newsmth.net"]}
    store = {"ISRG Root X1": {"api_level": 25, "release": "7.1.1"}}

    def test_the_hosts_the_root_and_why_it_is_bundled_are_stated(self):
        text = tls.trust_facts(self.evidence, 21, self.store)["trust_hosts"]
        self.assertIn("I checked `m.newsmth.net` and `www.newsmth.net`: "
                      "both chain to ISRG Root X1", text)
        self.assertIn("which Android trusts only from 7.1.1 (the app supports "
                      "API 21), so the root is bundled (valid until 2035)", text)
        self.assertIn("`static.newsmth.net` does not resolve from my network, so "
                      "its chain is unchecked", text)

    def test_a_root_every_supported_release_has_is_called_a_fallback(self):
        text = tls.trust_facts(self.evidence, 26, self.store)["trust_hosts"]
        self.assertIn("already trusts", text)
        self.assertNotIn("trusts only from", text)

    def test_a_root_the_store_data_does_not_know_is_explained_without_a_release(self):
        text = tls.trust_facts(self.evidence, 21, {})["trust_hosts"]
        self.assertIn("for devices whose system store lacks it", text)
        self.assertNotIn("7.1.1", text)

    def test_facts_are_stated_only_when_the_policy_names_them(self):
        evidence = {"trust_all": True, "trust_all_hosts_resolved": True,
                    "maintainer_facts": {"trust_hosts": "checked", "client_protocols": "okhttp"},
                    "client_excludes_deprecated_protocols": True,
                    "provided_files": [{"path": "app/src/main/res/raw/r.pem", "content": ROOT}]}
        with mock.patch.object(migration_policy, "_EVIDENCE",
                               {"tls_trust": (lambda error: evidence, "established_tls_trust_evidence")}):
            restored = migration_policy.generic_migration_policy(TlsTrustPolicyTests.finding)
        self.assertEqual(restored["maintainer_facts"], ["checked", "okhttp"])
        self.assertNotIn("maintainer_facts", restored["established_tls_trust_evidence"])
        evidence.pop("trust_all_hosts_resolved")
        with mock.patch.object(migration_policy, "_EVIDENCE",
                               {"tls_trust": (lambda error: evidence, "established_tls_trust_evidence")}):
            selector = migration_policy.generic_migration_policy(TlsTrustPolicyTests.finding)
        self.assertEqual(selector["consumer_scope"], "tls_selector_only")
        self.assertEqual(selector["maintainer_facts"], ["okhttp"])

    def test_a_reachable_deprecated_protocol_turns_the_filter_on(self):
        evidence = {"deprecated_protocols_reachable": True,
                    "maintainer_facts": {"client_protocols": "filtered"}}
        with mock.patch.object(migration_policy, "_EVIDENCE",
                               {"tls_trust": (lambda error: evidence, "established_tls_trust_evidence")}):
            policy = migration_policy.generic_migration_policy(TlsTrustPolicyTests.finding)
        self.assertTrue(policy["filters_deprecated_protocols"])
        self.assertIn("minus SSLv3, TLSv1 and TLSv1.1", policy["strategy"])
        self.assertTrue(policy["strategy"].startswith("Replace only the reported"))
        self.assertEqual(policy["maintainer_facts"], ["filtered"])


# Shaped like Read You's OkHttpClientModule.kt (2026-10-18).
DEFAULT_TRUST_ALL = """
fun cachingHttpClient(trustAllCerts: Boolean = true): OkHttpClient {
    val builder = OkHttpClient.Builder()
    if (trustAllCerts) builder.setupSsl(trustAllCerts)
    return builder.build()
}
fun OkHttpClient.Builder.setupSsl(trustAllCerts: Boolean) {
    val trustManager = if (trustAllCerts) {
        hostnameVerifier { _, _ -> true }
        object : X509TrustManager {
            override fun checkServerTrusted(
                chain: Array<out X509Certificate>?,
                authType: String?
            ) = Unit
        }
    } else {
        Platform.get().platformTrustManager()
    }
}
"""
MANIFEST = """<manifest>
    <application
        android:name=".App"
        android:usesCleartextTraffic="true">
    </application>
</manifest>
"""


class DefaultValidationTests(unittest.TestCase):
    """Read You defaults its client to trust-all; the servers are user-configured."""

    def finding(self, directory, manifest=MANIFEST, extra=None):
        root = Path(directory)
        source = root / "app/src/main/java/m/OkHttpClientModule.kt"
        source.parent.mkdir(parents=True)
        source.write_text(DEFAULT_TRUST_ALL)
        (root / "app/src/main/AndroidManifest.xml").write_text(manifest)
        (root / "app/build.gradle.kts").write_text("android { defaultConfig { targetSdk = 34 } }")
        for name, text in (extra or {}).items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)
        return {"repository_path": str(root),
                "source_file_path": "app/src/main/java/m/OkHttpClientModule.kt"}

    def test_a_user_ca_config_and_its_manifest_attribute_are_provided(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = tls.tls_trust_evidence(self.finding(directory), resolver({}))
        self.assertTrue(evidence["trust_all_default_with_validating_branch"])
        self.assertFalse(evidence["trust_all_hosts_resolved"])
        config, manifest = evidence["provided_files"]
        self.assertEqual(config["path"], "app/src/main/res/xml/network_security_config.xml")
        self.assertIn('<certificates src="user" />', config["content"])
        # The manifest allowed cleartext; a config would otherwise turn it off.
        self.assertIn('cleartextTrafficPermitted="true"', config["content"])
        edits = migration_policy.with_provided_files([], {"provided_files": [config, manifest]})
        edited = MANIFEST.replace(edits[1]["original_code"], edits[1]["corrected_code"], 1)
        self.assertIn('<application\n        android:networkSecurityConfig='
                      '"@xml/network_security_config"\n        android:name=".App"', edited)
        self.assertEqual(edits[1]["edit_kind"], "declaration")
        self.assertIn("install that CA",
                      evidence["maintainer_facts"]["user_configured_servers"])

    def test_an_existing_config_is_left_alone(self):
        manifest = MANIFEST.replace('<application', '<application android:networkSecurityConfig="@xml/n"')
        with tempfile.TemporaryDirectory() as directory:
            evidence = tls.tls_trust_evidence(self.finding(directory, manifest), resolver({}))
        self.assertTrue(evidence["network_security_config_exists"])
        self.assertNotIn("provided_files", evidence)
        self.assertNotIn("install that CA",
                         evidence["maintainer_facts"]["user_configured_servers"])

    def test_an_unconditional_trust_all_is_not_made_the_default_change(self):
        """Without a validating branch nothing says validation was an intended mode."""
        with tempfile.TemporaryDirectory() as directory:
            finding = self.finding(directory)
            source = Path(directory) / finding["source_file_path"]
            source.write_text(DEFAULT_TRUST_ALL.replace("Platform.get().platformTrustManager()", "null"))
            evidence = tls.tls_trust_evidence(finding, resolver({}))
        self.assertNotIn("trust_all_default_with_validating_branch", evidence)

    def test_a_trust_all_the_user_opts_into_is_left_to_the_user(self):
        """KPassNotes/DSub: "ignore SSL errors" comes from settings, not a default."""
        with tempfile.TemporaryDirectory() as directory:
            finding = self.finding(directory)
            source = Path(directory) / finding["source_file_path"]
            source.write_text(DEFAULT_TRUST_ALL.replace(
                "trustAllCerts: Boolean = true", "trustAllCerts: Boolean = settings.ignoreSsl"))
            evidence = tls.tls_trust_evidence(finding, resolver({}))
        self.assertNotIn("trust_all_default_with_validating_branch", evidence)
        self.assertEqual(tls.accept_all_default(DEFAULT_TRUST_ALL), "trustAllCerts")

    def test_the_policy_selects_default_validation_and_states_the_fact(self):
        evidence = {"trust_all": True, "trust_all_default_with_validating_branch": True,
                    "maintainer_facts": {"user_configured_servers": "rejected"},
                    "provided_files": [{"path": "app/src/main/res/xml/n.xml", "content": "<x/>"}]}
        finding = {"spec": "SSLContextSpec", "error_message": (
            "the TrustManager[] given to SSLContext.init holds a manager of a class the "
            "application defines and was not observed coming from a TrustManagerFactory")}
        with mock.patch.object(migration_policy, "_EVIDENCE",
                               {"tls_trust": (lambda error: evidence, "established_tls_trust_evidence")}):
            policy = migration_policy.generic_migration_policy(finding)
        self.assertEqual(policy["consumer_scope"], "tls_default_validation")
        self.assertEqual(policy["maintainer_facts"], ["rejected"])
        self.assertEqual(policy["provided_files"][0]["path"], "app/src/main/res/xml/n.xml")

    def test_an_edited_provided_file_is_authorized_as_an_edit_not_a_creation(self):
        plan = {"required_edits": []}
        migration_policy.authorize_provided_files(plan, {"provided_files": [
            {"path": "app/src/main/AndroidManifest.xml", "original": "<application ",
             "replacement": "<application a=\"b\" "}]})
        self.assertFalse(plan["required_edits"][0]["create_new_file"])


class AcceptAllNameTests(unittest.TestCase):
    """Read You run2 kept `if (trustAllCerts)` and made its branch validate."""

    def test_a_selector_whose_branch_now_validates_contradicts_its_name(self):
        from cognalys.llm.semantic_validation import accept_all_name_contradictions

        rewritten = DEFAULT_TRUST_ALL.replace(
            """hostnameVerifier { _, _ -> true }
        object : X509TrustManager {
            override fun checkServerTrusted(
                chain: Array<out X509Certificate>?,
                authType: String?
            ) = Unit
        }""", "factory.trustManagers.first()")
        [found] = accept_all_name_contradictions(DEFAULT_TRUST_ALL, rewritten)
        self.assertEqual((found["code"], found["name"]), ("NAME_CONTRADICTS_BEHAVIOR", "trustAllCerts"))

    def test_flipping_the_default_or_removing_the_branch_is_consistent(self):
        from cognalys.llm.semantic_validation import accept_all_name_contradictions

        flipped = DEFAULT_TRUST_ALL.replace("trustAllCerts: Boolean = true", "trustAllCerts: Boolean = false")
        self.assertEqual(accept_all_name_contradictions(DEFAULT_TRUST_ALL, flipped), [])
        removed = "fun OkHttpClient.Builder.setupSsl() { val trustManager = platformTrustManager() }"
        self.assertEqual(accept_all_name_contradictions(DEFAULT_TRUST_ALL, removed), [])


class UnreachableTrustAllTests(unittest.TestCase):
    """ToFShare (2026-10-31 review): is the accept-all branch reachable at all?"""

    CLIENT = """class Client {
    void build() {
        if (Settings.USE_PROXY) {
            other();
        } else {
            TrustManager[] all = new TrustManager[]{ new X509TrustManager() {
                public void checkServerTrusted(X509Certificate[] c, String a) {
                }
            }};
        }
    }
}
"""

    def repository(self, settings):
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        (root / "app").mkdir()
        (root / "app" / "Client.java").write_text(self.CLIENT, encoding="utf-8")
        (root / "app" / "Settings.java").write_text(settings, encoding="utf-8")
        self.addCleanup(directory.cleanup)
        return root

    def test_a_guard_never_given_the_needed_value_is_recorded(self):
        root = self.repository("class Settings { static boolean USE_PROXY = true; }\n")
        note = tls.unreachable_trust_all(root, self.CLIENT)
        self.assertEqual(note["guard"], "USE_PROXY")
        self.assertEqual(note["declared_at"], "app/Settings.java:1")
        self.assertIn("cannot run", note["note"])
        self.assertIn("The finding stands", note["note"])

    def test_a_guard_set_from_settings_or_defaulting_to_the_branch_is_reachable(self):
        root = self.repository("class Settings { static boolean USE_PROXY = true;\n"
                               "  void load() { USE_PROXY = prefs.getBoolean(\"p\", true); } }\n")
        self.assertEqual(tls.unreachable_trust_all(root, self.CLIENT), {})
        root = self.repository("class Settings { static boolean USE_PROXY = false; }\n")
        self.assertEqual(tls.unreachable_trust_all(root, self.CLIENT), {})

    def test_a_guard_anything_else_may_set_is_not_recorded(self):
        """2026-11-01 review: reflection, a setter, data binding, a Kotlin var, a
        compound assignment, another source set or module."""
        cases = {
            "reflection": ("class Settings { static boolean USE_PROXY = true;\n"
                           "  void f() { Settings.class.getDeclaredField(\"USE_PROXY\"); } }\n"),
            "setter": ("class Settings { static boolean USE_PROXY = true;\n"
                       "  void f() { o.setUSE_PROXY(false); } }\n"),
            "kotlin var": "object Settings { var USE_PROXY = true }\n",
            "kotlin getter": "object Settings { val USE_PROXY: Boolean\n  get() = flag() }\n",
            "compound": ("class Settings { static boolean USE_PROXY = true;\n"
                         "  void f() { USE_PROXY &= other; } }\n"),
        }
        for label, settings in cases.items():
            self.assertEqual(tls.unreachable_trust_all(self.repository(settings), self.CLIENT), {}, label)
        root = self.repository("class Settings { static boolean USE_PROXY = true; }\n")
        (root / "app" / "layout.xml").write_text('<x checked="@={vm.USE_PROXY}"/>', encoding="utf-8")
        self.assertEqual(tls.unreachable_trust_all(root, self.CLIENT), {}, "data binding")
        root = self.repository("class Other {}\n")
        flavour = root / "app" / "src" / "debug" / "java"
        flavour.mkdir(parents=True)
        (flavour / "Settings.java").write_text("class Settings { static boolean USE_PROXY = true; }\n",
                                               encoding="utf-8")
        self.assertEqual(tls.unreachable_trust_all(root, self.CLIENT), {}, "source set")
        root = self.repository("class Other {}\n")
        lib = root / "lib" / "src" / "main" / "java"
        lib.mkdir(parents=True)
        (lib / "Settings.java").write_text("class Settings { static boolean USE_PROXY = true; }\n",
                                           encoding="utf-8")
        self.assertEqual(tls.unreachable_trust_all(root, self.CLIENT, "app/src/main/java/Client.java"),
                         {}, "module")

    def test_the_branch_value_follows_then_else_and_negation(self):
        self.assertEqual(tls.trust_all_guard(self.CLIENT), {"name": "Settings.USE_PROXY", "needed": False})
        negated = self.CLIENT.replace("if (Settings.USE_PROXY)", "if (!Settings.USE_PROXY)")
        self.assertEqual(tls.trust_all_guard(negated)["needed"], True)
        self.assertEqual(tls.trust_all_guard("class A { void f() { checkServerTrusted(c, a) {} } }"), {})


if __name__ == "__main__":
    unittest.main()
