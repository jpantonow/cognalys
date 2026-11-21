import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils.deliberate_insecurity import (  # noqa: E402
    DELIBERATE_INSECURITY_GUIDANCE, deliberate_insecurity, deliberate_insecurity_evidence)

# weeWX Weather (2026-11-04): a trust-all manager built in the static
# initialiser of a class suppressing the lint checks, installed
# unconditionally with a hostname verifier returning true.
NETWORK_CLIENT = """package a;

import android.annotation.SuppressLint;

@SuppressLint({"CustomX509TrustManager", "TrustAllX509TrustManager"})
class NetworkClient
{
\tprivate static TrustManager[] trustAllCerts;
\tprivate static SSLSocketFactory sslSocketFactory;

\tstatic
\t{
\t\ttry
\t\t{
\t\t\ttrustAllCerts = new TrustManager[]{new X509TrustManager()
\t\t\t{
\t\t\t\tpublic void checkServerTrusted(X509Certificate[] chain, String authType) {}
\t\t\t}};
\t\t\tSSLContext sslContext = SSLContext.getInstance("TLS");
\t\t\tsslContext.init(null, trustAllCerts, new SecureRandom());
\t\t\tsslSocketFactory = sslContext.getSocketFactory();
\t\t} catch(Exception e) {
\t\t\tLog.e("NetworkClient", "failed");
\t\t}
\t}

\tstatic void generate()
\t{
\t\tif (sslSocketFactory != null)
\t\t{
\t\t\tbuilder = new OkHttpClient.Builder()
\t\t\t\t.sslSocketFactory(sslSocketFactory, (X509TrustManager)trustAllCerts[0])
\t\t\t\t.hostnameVerifier((hostname, session) -> true);
\t\t}
\t}
}
"""
CLINIT_BODY = NETWORK_CLIENT[NETWORK_CLIENT.index("\tstatic\n"):NETWORK_CLIENT.index("\tstatic void")].rstrip()
NETWORK_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config xmlns:tools="http://schemas.android.com/tools">
\t<base-config cleartextTrafficPermitted="true"
\t\ttools:ignore="InsecureBaseConfiguration">
\t</base-config>
</network-security-config>
"""
CLIENT_PATH = "app/src/main/java/a/NetworkClient.java"

# xivpn's Utils and SubscriptionWork (2026-10-15): the trust-all context is
# used only when the user turned on "subscription_no_verify".
UTILS_KT = """package a

object Utils {
    lateinit var insecureContext: SSLContext

    fun buildInsecure() {
        insecureContext = SSLContext.getInstance("TLS")
        insecureContext.init(null, arrayOf(TrustAll()), null)
    }
}
"""
WORK_KT = """package a

class SubscriptionWork {
    fun fetch(prefs: SharedPreferences) {
        val noVerify = prefs.getBoolean("subscription_no_verify", false)
        if (noVerify) {
            client.sslSocketFactory(Utils.insecureContext.socketFactory, TrustAll())
        }
    }
}
"""


def _repository(directory: str, files: dict) -> Path:
    root = Path(directory)
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text, encoding="utf-8")
    return root


def _weewx(directory: str) -> dict:
    root = _repository(directory, {CLIENT_PATH: NETWORK_CLIENT,
                                   "app/src/main/res/xml/network_security_config.xml":
                                       NETWORK_CONFIG})
    return deliberate_insecurity(root, CLIENT_PATH, "<clinit>", CLINIT_BODY,
                                 "a.NetworkClient", 20)


class DeliberateInsecurityTests(unittest.TestCase):

    def test_a_class_level_suppression_of_an_unconditional_trust_all_manager(self):
        with tempfile.TemporaryDirectory() as directory:
            result = _weewx(directory)
        self.assertEqual(result["status"], "signs_found")
        self.assertEqual(result["suppressions"][0]["scope"], "class NetworkClient")
        self.assertEqual(result["suppressions"][0]["line"], 5)
        self.assertEqual(result["suppressions"][0]["ids"],
                         ["CustomX509TrustManager", "TrustAllX509TrustManager"])
        # A null check around the use is not an option.
        self.assertEqual(result["gate"]["status"], "unconditional")
        sites = {site["line"]: site["role"] for site in result["gate"]["unguarded_sites"]}
        self.assertEqual(sites[20], "reported line")
        self.assertIn("use of sslSocketFactory", sites[32])
        self.assertIn("use of trustAllCerts", sites[32])
        self.assertEqual(result["network_security_configuration"][0]["line"], 3)
        self.assertEqual(result["module_resource_suppressions"][0]["ids"],
                         ["InsecureBaseConfiguration"])

    def test_a_use_under_a_preference_in_another_file_is_gated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _repository(directory, {"app/src/main/java/a/Utils.kt": UTILS_KT,
                                           "app/src/main/java/a/SubscriptionWork.kt": WORK_KT})
            result = deliberate_insecurity(root, "app/src/main/java/a/Utils.kt", "buildInsecure",
                                           "", "a.Utils", 8)
        self.assertEqual(result["status"], "signs_found")
        self.assertEqual(result["suppressions"], [])
        # The reported line itself runs whenever buildInsecure is called, and
        # the context is used only under the option.
        self.assertEqual(result["gate"]["status"], "partially_gated")
        gated = result["gate"]["gated_sites"][0]
        self.assertEqual((gated["file"], gated["line"]), ("app/src/main/java/a/SubscriptionWork.kt", 7))
        self.assertEqual(gated["guards"][0]["kind"], "option")
        self.assertEqual(gated["guards"][0]["preference_keys"], ["subscription_no_verify"])
        evidence = deliberate_insecurity_evidence(result)
        self.assertIn("(preference subscription_no_verify)", evidence["gate"]["gated_sites"][0])

    def test_a_debug_build_flag_and_an_option_inside_the_method(self):
        method = """class Http {
    void configure(Builder builder) {
        if (BuildConfig.DEBUG) {
            builder.hostnameVerifier((h, s) -> true);
        }
    }
}
"""
        option = method.replace("BuildConfig.DEBUG", "settings.isAllowInsecure()")
        for source, kind in ((method, "build_flag"), (option, "option")):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = _repository(directory, {"app/src/main/java/a/Http.java": source})
                result = deliberate_insecurity(root, "app/src/main/java/a/Http.java",
                                               "configure", "", "a.Http", 4)
                self.assertEqual(result["gate"]["status"], "gated")
                self.assertEqual(result["gate"]["gated_sites"][0]["guards"][0]["kind"], kind)
                self.assertEqual(result["gate"]["gated_sites"][0]["guards"][0]["line"], 3)

    def test_an_else_branch_takes_the_if_condition(self):
        source = """class Http {
    void configure(Builder builder) {
        if (!prefs.getBoolean("allow_self_signed", false)) {
            builder.useDefaults();
        } else {
            builder.hostnameVerifier((h, s) -> true);
        }
    }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = _repository(directory, {"app/src/main/java/a/Http.java": source})
            result = deliberate_insecurity(root, "app/src/main/java/a/Http.java",
                                           "configure", "", "a.Http", 6)
        guard = result["gate"]["gated_sites"][0]["guards"][0]
        self.assertEqual((guard["line"], guard["negated"]), (3, True))
        self.assertEqual(guard["preference_keys"], ["allow_self_signed"])

    def test_a_comment_stating_the_intent_is_a_sign(self):
        source = """class Http {
    // Home servers usually run with a self-signed certificate.
    void configure(Builder builder) {
        builder.hostnameVerifier((h, s) -> true); // accept all hosts on purpose
    }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = _repository(directory, {"app/src/main/kotlin/a/Http.java": source})
            result = deliberate_insecurity(root, "app/src/main/kotlin/a/Http.java",
                                           "configure", "", "a.Http", 4)
        self.assertEqual(result["status"], "signs_found")
        self.assertEqual([item["line"] for item in result["comments"]], [2, 4])
        self.assertEqual(result["gate"]["status"], "unconditional")

    def test_an_unrelated_or_other_method_suppression_is_not_a_sign(self):
        source = """class Web {
    @SuppressLint("SetJavaScriptEnabled")
    void other(WebView view) {
        view.getSettings().setJavaScriptEnabled(true);
    }

    @SuppressLint("ClickableViewAccessibility")
    String digest(byte[] data) {
        return hex(MessageDigest.getInstance("MD5").digest(data));
    }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = _repository(directory, {"app/src/main/java/a/Web.java": source})
            result = deliberate_insecurity(root, "app/src/main/java/a/Web.java",
                                           "digest", "", "a.Web", 9)
        self.assertEqual(result["status"], "none")
        self.assertEqual(result["suppressions"], [])
        self.assertEqual(deliberate_insecurity_evidence(result), {})

    def test_kotlin_suppress_and_noinspection_name_a_known_id(self):
        source = """@file:Suppress("CustomX509TrustManager")
package a

class Tls {
    fun build(): SSLContext {
        //noinspection TrustAllX509TrustManager
        return SSLContext.getInstance("TLS").apply { init(null, arrayOf(All()), null) }
    }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = _repository(directory, {"app/src/main/java/a/Tls.kt": source})
            result = deliberate_insecurity(root, "app/src/main/java/a/Tls.kt",
                                           "build", "", "a.Tls", 7)
        scopes = {item["scope"]: item["ids"] for item in result["suppressions"]}
        self.assertEqual(scopes, {"statement in the method": ["TrustAllX509TrustManager"],
                                  "file": ["CustomX509TrustManager"]})

    def test_a_suppression_of_a_check_the_reported_line_does_not_touch_is_left_out(self):
        # Bookwyrm (2026-11-04 measurement): SetJavaScriptEnabled on an
        # onCreate reported for its GCMParameterSpec.
        source = """class Start {
    @SuppressLint("SetJavaScriptEnabled")
    void onCreate() {
        web.getSettings().setJavaScriptEnabled(true);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
    }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = _repository(directory, {"app/src/main/java/a/Start.java": source})
            result = deliberate_insecurity(root, "app/src/main/java/a/Start.java",
                                           "onCreate", "", "a.Start", 5)
            self.assertEqual(result["status"], "none")
            on_the_line = deliberate_insecurity(root, "app/src/main/java/a/Start.java",
                                                "onCreate", "", "a.Start", 4)
        self.assertEqual(on_the_line["suppressions"][0]["ids"], ["SetJavaScriptEnabled"])

    def test_a_call_of_the_method_in_its_own_file_under_an_option(self):
        # memories' HttpService (2026-11-04 measurement): getInsecureTLSContext
        # is called inside `client = if (trustAll) {`; the javadoc says why.
        source = """class HttpService {
    fun build(url: String?, trustAll: Boolean) {
        client = if (trustAll) {
            val (sc, tm) = getInsecureTLSContext()
            OkHttpClient.Builder().sslSocketFactory(sc.socketFactory, tm).build()
        } else {
            OkHttpClient()
        }
    }

    /**
     * Get a SSL Context that trusts all certificates
     */
    private fun getInsecureTLSContext(): Pair<SSLContext, X509TrustManager> {
        val sslContext = SSLContext.getInstance("SSL")
        sslContext.init(null, arrayOf(trustAllCerts), SecureRandom())
        return Pair(sslContext, trustAllCerts)
    }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = _repository(directory, {"app/src/main/java/a/HttpService.kt": source})
            result = deliberate_insecurity(root, "app/src/main/java/a/HttpService.kt",
                                           "getInsecureTLSContext", "", "a.HttpService", 16)
        self.assertEqual(result["comments"][0]["line"], 12)
        self.assertEqual(result["gate"]["status"], "partially_gated")
        gated = result["gate"]["gated_sites"][0]
        self.assertEqual((gated["line"], gated["role"]), (4, "call of getInsecureTLSContext"))
        self.assertEqual(gated["guards"][0]["line"], 3)

    def test_a_call_inside_the_condition_is_not_gated_by_it(self):
        # BirdoVPN's SettingsHmac (2026-11-04 measurement): computeHmac is
        # the condition of `if (storedHmac == computeHmac(key, ... prefs ...))`.
        source = """object SettingsHmac {
    fun verify(prefs: SharedPreferences): Boolean {
        if (storedHmac == computeHmac(key, canonical(prefs))) { return true }
        return false
    }

    fun computeHmac(key: ByteArray, data: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        return hex(mac.doFinal(data.toByteArray()))
    }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = _repository(directory, {"app/src/main/java/a/SettingsHmac.kt": source})
            result = deliberate_insecurity(root, "app/src/main/java/a/SettingsHmac.kt",
                                           "computeHmac", "", "a.SettingsHmac", 9)
        self.assertEqual(result["status"], "none")
        self.assertEqual(result["gate"]["unguarded_sites"][1]["role"], "call of computeHmac")

    def test_a_missing_file_or_method_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _repository(directory, {"app/src/main/java/a/A.java": "class A {}\n"})
            self.assertEqual(deliberate_insecurity(root, "app/src/main/java/a/B.java", "m")["status"],
                             "unavailable")
            self.assertEqual(deliberate_insecurity(root, "app/src/main/java/a/A.java", "m")["status"],
                             "unavailable")


class DeliberateInsecurityEvidenceTests(unittest.TestCase):
    """The reading reaches extraction, adjudication, planning and the review."""

    POLICY = {"registry_version": "2.0", "specification": "SSLContextSpec",
              "family": "generic", "common": {}, "family_policy": {}}

    def test_the_evidence_quotes_file_and_line(self):
        with tempfile.TemporaryDirectory() as directory:
            result = _weewx(directory)
        evidence = deliberate_insecurity_evidence(result)
        self.assertEqual(evidence["suppressions"][0],
                         f'{CLIENT_PATH}:5: @SuppressLint({{"CustomX509TrustManager", '
                         '"TrustAllX509TrustManager"}) [scope: class NetworkClient] '
                         "[ids: CustomX509TrustManager, TrustAllX509TrustManager]")
        self.assertEqual(evidence["gate"]["status"], "unconditional")
        self.assertIn("it runs for every user", evidence["gate"]["statement"])
        self.assertIn("never makes the finding a false positive", DELIBERATE_INSECURITY_GUIDANCE)
        self.assertEqual(deliberate_insecurity_evidence({"status": "none"}), {})
        self.assertEqual(deliberate_insecurity_evidence(None), {})

    def test_the_reading_reaches_the_evidence_packet(self):
        from cognalys.llm.evidence_packet import FindingEvidencePacketBuilder

        with tempfile.TemporaryDirectory() as directory:
            result = _weewx(directory)
            packet = FindingEvidencePacketBuilder().build({
                "csv_class": "a.NetworkClient", "method_name": "<clinit>",
                "method_body": CLINIT_BODY, "source_file_path": CLIENT_PATH,
                "repository_path": directory, "spec": "SSLContextSpec",
                "deliberate_insecurity": result}, self.POLICY)
        items = [item for item in packet["evidence_catalog"]
                 if item["kind"] == "deliberate_insecurity"]
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["evidence_id"].startswith("INTENT-"))
        self.assertEqual(items[0]["data"]["gate"]["status"], "unconditional")

    def test_no_sign_adds_no_evidence(self):
        from cognalys.llm.evidence_packet import FindingEvidencePacketBuilder

        packet = FindingEvidencePacketBuilder().build({
            "csv_class": "a.A", "method_name": "m", "source_file_path": "A.java",
            "repository_path": "/nonexistent", "spec": "SSLContextSpec",
            "deliberate_insecurity": {"status": "none"}}, self.POLICY)
        self.assertEqual([item for item in packet["evidence_catalog"]
                          if item["kind"] == "deliberate_insecurity"], [])

    def test_the_review_payload_and_prompt_carry_it(self):
        from test_applied_edits_match_text import CLEAN_REVIEW, METHOD_EDIT, _coordinated_run

        with tempfile.TemporaryDirectory() as directory:
            result = _weewx(directory)
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT],
                                             error_extra={"deliberate_insecurity": result})
        self.assertIn('"deliberate_insecurity"', provider.review_prompt)
        self.assertIn("TrustAllX509TrustManager", provider.review_prompt)
        system = " ".join(provider.review_system.split())
        self.assertIn("deliberate_insecurity, when present, is a repository reading", system)
        self.assertIn("a patch that removes it and leaves the users who rely on it no way "
                      "to keep doing what they did", system)

    def test_adjudication_and_plan_prompts_carry_the_guidance(self):
        from cognalys.llm import finding_adjudication

        source = Path(finding_adjudication.__file__).read_text(encoding="utf-8")
        self.assertEqual(source.count("+ DELIBERATE_INSECURITY_GUIDANCE"), 2)
        self.assertIn('{"deliberate_insecurity": intent}', source)
        self.assertIn("An INTENT deliberate_insecurity entry is a repository reading", source)
        self.assertIn("do not invent a new setting", DELIBERATE_INSECURITY_GUIDANCE)

    def test_versions_record_the_change(self):
        from cognalys.llm.coordinated_generation import REVIEW_CONTRACT_VERSION
        from cognalys.llm.finding_adjudication import (
            ADJUDICATION_PROMPT_VERSION, PLAN_PROMPT_VERSION)
        from cognalys.llm.pipeline_common import CONTEXT_BUILDER_VERSION

        self.assertGreaterEqual(REVIEW_CONTRACT_VERSION, 17)
        self.assertGreaterEqual(ADJUDICATION_PROMPT_VERSION, 4)
        self.assertGreaterEqual(PLAN_PROMPT_VERSION, 10)
        self.assertGreaterEqual(tuple(map(int, CONTEXT_BUILDER_VERSION.split("."))), (2, 17))


if __name__ == "__main__":
    unittest.main()
