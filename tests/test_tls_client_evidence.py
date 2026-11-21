import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction import tls_client_evidence as client  # noqa: E402

SOURCE = "class Helper { OkHttpClient build() { return new OkHttpClient.Builder().build(); } }"


class TlsClientEvidenceTests(unittest.TestCase):
    """zSMTH (2026-10-17) uses OkHttp 4.12.0: deprecated TLS is already off."""

    def repository(self, directory, gradle, source=SOURCE, extra=None):
        root = Path(directory)
        (root / "app/src/main/java/c").mkdir(parents=True)
        (root / "app/src/main/java/c/Helper.java").write_text(source)
        (root / "app/build.gradle").write_text(gradle)
        for name, text in (extra or {}).items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)
        return {"repository_path": str(root), "source_file_path": "app/src/main/java/c/Helper.java"}

    def test_a_variable_version_is_resolved_and_modern_okhttp_needs_no_filter(self):
        # zSMTH: the app module reads minSdk from the root project; a library
        # module bundled in the repository declares a lower one.
        gradle = ("ext { OKHTTP_VERSION = '4.12.0' }\n"
                  "android { defaultConfig { minSdkVersion rootProject.minSdkVersion } }\n"
                  'dependencies { implementation "com.squareup.okhttp3:okhttp:$OKHTTP_VERSION" }\n')
        with tempfile.TemporaryDirectory() as directory:
            finding = self.repository(directory, gradle, extra={
                "build.gradle": "ext {\n    minSdkVersion = 21\n}\n",
                "swipebackhelper/build.gradle": "android { defaultConfig { minSdkVersion 17 } }\n"})
            evidence = client.tls_client_evidence(finding)
            self.assertEqual(client.module_min_sdk(Path(directory), finding["source_file_path"]), 21)
        self.assertEqual(evidence["http_client"], {"library": "OkHttp", "version": "4.12.0"})
        self.assertTrue(evidence["client_excludes_deprecated_protocols"])
        self.assertFalse(evidence["deprecated_protocols_reachable"])
        self.assertIn("OkHttp 4.12.0 already negotiates only TLS 1.2 and 1.3",
                      evidence["maintainer_facts"]["client_protocols"])

    def test_a_version_catalog_reference_is_resolved(self):
        toml = ('[versions]\nokhttp = "3.12.13"\n[libraries]\n'
                'okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }\n')
        with tempfile.TemporaryDirectory() as directory:
            evidence = client.tls_client_evidence(self.repository(
                directory, "", extra={"gradle/libs.versions.toml": toml}))
        self.assertEqual(evidence["http_client"]["version"], "3.12.13")
        self.assertTrue(evidence["deprecated_protocols_reachable"])

    def test_a_catalog_entry_by_group_and_name_is_resolved(self):
        """Read You: okhttp = { group = "com.squareup.okhttp3", name = "okhttp", ... }."""
        toml = ('[versions]\nokhttp = "5.0.0-alpha.12"\n[libraries]\n'
                'okhttp = { group = "com.squareup.okhttp3", name = "okhttp", version.ref = "okhttp" }\n')
        with tempfile.TemporaryDirectory() as directory:
            evidence = client.tls_client_evidence(self.repository(
                directory, "", extra={"gradle/libs.versions.toml": toml}))
        self.assertEqual(evidence["http_client"]["version"], "5.0.0-alpha.12")
        self.assertTrue(evidence["client_excludes_deprecated_protocols"])

    def test_compatible_tls_keeps_deprecated_protocols_reachable(self):
        source = SOURCE.replace(".build()", ".connectionSpecs(listOf(ConnectionSpec.COMPATIBLE_TLS)).build()")
        with tempfile.TemporaryDirectory() as directory:
            evidence = client.tls_client_evidence(self.repository(
                directory, 'implementation "com.squareup.okhttp3:okhttp:4.12.0"', source))
        self.assertTrue(evidence["legacy_protocols_configured"])
        self.assertTrue(evidence["deprecated_protocols_reachable"])
        self.assertIn("removed", evidence["maintainer_facts"]["client_protocols"])

    def test_a_platform_socket_client_is_reachable_and_an_unknown_client_says_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = client.tls_client_evidence(self.repository(
                directory, "", "class H { void c() { HttpsURLConnection c = null; } }"))
        self.assertTrue(raw["deprecated_protocols_reachable"])
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(client.tls_client_evidence(self.repository(
                directory, "", "class H { void c() { } }")), {})


class EffectiveProtocolConfigurationTests(unittest.TestCase):
    """Fread (tls_20261015): only a configuration that takes effect counts."""

    # GlobalOkHttpClient.buildSSLFactory, shortened: the SSLv3 assignment goes
    # to a copy of the default parameters and configures nothing.
    FREAD = ("object GlobalOkHttpClient {\n"
             "    fun buildSSLFactory(): SSLSocketFactory {\n"
             "        val sslContext = SSLContext.getInstance(\"SSL\")\n"
             "        sslContext.init(null, arrayOf(trustManager), SecureRandom())\n"
             "        sslContext.defaultSSLParameters.protocols = arrayOf(\"SSLv3\")\n"
             "        return sslContext.socketFactory\n"
             "    }\n"
             "    val client = OkHttpClient.Builder()\n"
             "        .sslSocketFactory(buildSSLFactory(), trustManager).build()\n"
             "}\n")

    def repository(self, directory, source, gradle='implementation "com.squareup.okhttp3:okhttp:4.12.0"',
                   extra=None):
        root = Path(directory)
        (root / "app/src/main/java/c").mkdir(parents=True)
        (root / "app/src/main/java/c/Client.kt").write_text(source)
        (root / "app/build.gradle").write_text(gradle)
        for name, text in (extra or {}).items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)
        return {"repository_path": str(root), "source_file_path": "app/src/main/java/c/Client.kt"}

    def test_okhttp_with_only_the_default_parameters_literal_is_not_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = client.tls_client_evidence(self.repository(directory, self.FREAD))
        self.assertFalse(evidence["legacy_protocols_configured"])
        self.assertTrue(evidence["client_excludes_deprecated_protocols"])
        self.assertFalse(evidence["deprecated_protocols_reachable"])
        self.assertIn("OkHttp 4.12.0 already negotiates only TLS 1.2 and 1.3",
                      evidence["maintainer_facts"]["client_protocols"])
        self.assertNotIn("fact_conditions", evidence)

    def test_okhttp_with_compatible_tls_in_another_file_is_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = client.tls_client_evidence(self.repository(directory, self.FREAD, extra={
                "app/src/main/java/c/Specs.kt":
                    "val specs = builder.connectionSpecs(listOf(ConnectionSpec.COMPATIBLE_TLS))\n"}))
        self.assertFalse(evidence["client_excludes_deprecated_protocols"])
        self.assertTrue(evidence["deprecated_protocols_reachable"])
        self.assertEqual(evidence["protocol_configuration_sites"], ["app/src/main/java/c/Specs.kt"])
        self.assertEqual(evidence["fact_conditions"],
                         {"client_protocols": "diff_removes_deprecated_protocols"})

    def test_a_protocol_literal_in_okhttp_code_is_overridden_by_the_spec(self):
        source = self.FREAD.replace(
            "        return sslContext.socketFactory\n",
            "        socket.enabledProtocols = arrayOf(\"TLSv1\", \"TLSv1.2\")\n"
            "        return sslContext.socketFactory\n")
        self.assertEqual(client.okhttp_legacy_sinks(source), [])
        self.assertEqual(client.okhttp_legacy_sinks(
            'ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS).tlsVersions("TLSv1", "TLSv1.2")'),
            ['tlsVersions("TLSv1", "TLSv1.2")'])

    def test_a_platform_socket_enabling_tlsv1_is_legacy(self):
        source = ("class Factory : SSLSocketFactory() {\n"
                  "    fun configure(socket: SSLSocket) {\n"
                  "        socket.enabledProtocols = arrayOf(\"TLSv1\", \"TLSv1.2\")\n"
                  "    }\n}\n")
        with tempfile.TemporaryDirectory() as directory:
            evidence = client.tls_client_evidence(self.repository(directory, source, gradle=""))
        self.assertEqual(evidence["http_client"]["library"], "platform socket")
        self.assertTrue(evidence["legacy_protocols_configured"])
        self.assertTrue(evidence["deprecated_protocols_reachable"])

    def test_a_platform_socket_whose_only_literal_is_on_default_parameters_is_not_legacy(self):
        source = ("class Factory {\n"
                  "    fun configure(socket: SSLSocket, context: SSLContext) {\n"
                  "        context.defaultSSLParameters.protocols = arrayOf(\"TLSv1\")\n"
                  "        context.getDefaultSSLParameters().setProtocols(new String[]{\"SSLv3\"});\n"
                  "    }\n}\n")
        with tempfile.TemporaryDirectory() as directory:
            evidence = client.tls_client_evidence(self.repository(directory, source, gradle=""))
        self.assertFalse(evidence["legacy_protocols_configured"])
        # The platform default is not known to exclude them, so they stay reachable.
        self.assertTrue(evidence["deprecated_protocols_reachable"])

    def test_parameters_given_to_the_socket_and_filters_are_told_apart(self):
        applied = ("val params = context.defaultSSLParameters\n"
                   "params.protocols = arrayOf(\"TLSv1.1\", \"TLSv1.2\")\n"
                   "socket.sslParameters = params\n")
        self.assertEqual(len(client.platform_legacy_sinks(applied)), 1)
        block = ("socket.sslParameters = SSLParameters().apply {\n"
                 "    protocols = arrayOf(\"SSLv3\")\n}\n")
        self.assertEqual(len(client.platform_legacy_sinks(block)), 1)
        never_given = "val params = SSLParameters()\nparams.protocols = arrayOf(\"TLSv1\")\n"
        self.assertEqual(client.platform_legacy_sinks(never_given), [])
        java_filter = ("socket.setEnabledProtocols(Arrays.stream(socket.getEnabledProtocols())"
                       ".filter(p -> !p.equals(\"TLSv1\")).toArray(String[]::new));")
        self.assertEqual(client.platform_legacy_sinks(java_filter), [])
        kotlin_filter = ('socket.enabledProtocols = socket.enabledProtocols'
                         '.filterNot { it == "TLSv1" || it == "SSLv3" }.toTypedArray()')
        self.assertEqual(client.platform_legacy_sinks(kotlin_filter), [])
        self.assertEqual(len(client.platform_legacy_sinks(
            'socket.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.2"});')), 1)
        self.assertEqual(client.platform_legacy_sinks(
            '// socket.enabledProtocols = arrayOf("TLSv1")\n'), [])

    def test_the_removal_fact_is_stated_only_when_the_diff_filters(self):
        from cognalys.llm import migration_policy

        policy = {"maintainer_facts": [client.PROTOCOL_REMOVAL_FACT, "Other fact."],
                  "maintainer_fact_conditions": {
                      client.PROTOCOL_REMOVAL_FACT: "diff_removes_deprecated_protocols"}}
        selector_only = [{"source_file_path": "app/src/main/java/c/Client.kt",
                          "original_code": 'SSLContext.getInstance("SSL")',
                          "corrected_code": 'SSLContext.getInstance("TLS")'}]
        self.assertEqual(migration_policy.facts_supported_by_diff(policy, selector_only),
                         ["Other fact."])
        filtering = selector_only + [{
            "source_file_path": "app/src/main/java/c/Filtering.kt", "edit_kind": "create",
            "original_code": "",
            "corrected_code": ('socket.enabledProtocols = socket.enabledProtocols'
                               '.filterNot { it == "SSLv3" || it == "TLSv1" }.toTypedArray()')}]
        self.assertEqual(migration_policy.facts_supported_by_diff(policy, filtering),
                         [client.PROTOCOL_REMOVAL_FACT, "Other fact."])
        # A policy stored before conditions were recorded reads the same way.
        stored = {"maintainer_facts": [client.PROTOCOL_REMOVAL_FACT]}
        self.assertEqual(migration_policy.facts_supported_by_diff(stored, selector_only), [])

    def test_a_found_ssl_finding_with_a_client_that_excludes_gets_no_filter(self):
        from unittest import mock
        from cognalys.llm import migration_policy

        finding = {"spec": "SSLContextSpec",
                   "error_message": "expecting one of TLSV1.2,TLSV1.3,TLS but found SSL",
                   "unique_error_id": "c:::m:::SSLContextSpec:::UnsafeProtocol:::x"}
        with mock.patch.object(migration_policy, "_EVIDENCE", {"tls_trust": (
                lambda error: {"client_excludes_deprecated_protocols": True},
                "established_tls_trust_evidence")}):
            policy = migration_policy.generic_migration_policy(finding)
        self.assertEqual(policy["consumer_scope"], "tls_selector_only")
        self.assertFalse(policy["filters_deprecated_protocols"])
        self.assertTrue(policy["client_enforces_protocols"])


class OpenHabTests(unittest.TestCase):
    """openHAB #4039 (2026-10-18): OkHttp's default specs already filter protocols."""

    METHOD = ("fun updateHttpClientForClientCert() {\n"
              "    val sslContext = SSLContext.getInstance(\"TLS\")\n"
              "    httpClient = httpClient.newBuilder()\n"
              "        .sslSocketFactory(sslContext.socketFactory, trustManager).build()\n}\n")
    CLASS = ("class ConnectionFactory {\n" + METHOD
             + "    fun video() { HttpsURLConnection.setDefaultSSLSocketFactory(f) }\n}\n")

    def repository(self, directory, extra=None):
        root = Path(directory)
        (root / "mobile/src/main/java/o").mkdir(parents=True)
        (root / "mobile/src/main/java/o/ConnectionFactory.kt").write_text(self.CLASS)
        (root / "gradle").mkdir()
        (root / "gradle/libs.versions.toml").write_text(
            '[versions]\nokhttp = "5.5.0"\n[libraries]\n'
            'okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }\n')
        for name, text in (extra or {}).items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)
        return {"repository_path": str(root), "method_body": self.METHOD,
                "source_file_path": "mobile/src/main/java/o/ConnectionFactory.kt"}

    def test_the_method_decides_the_client_and_modern_okhttp_needs_no_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = client.tls_client_evidence(self.repository(directory))
        self.assertEqual(evidence["http_client"], {"library": "OkHttp", "version": "5.5.0"})
        self.assertTrue(evidence["client_excludes_deprecated_protocols"])

    def test_connection_specs_chosen_anywhere_in_the_repository_count(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = client.tls_client_evidence(self.repository(directory, {
                "mobile/src/main/java/o/Http.kt":
                    "val c = builder.connectionSpecs(listOf(ConnectionSpec.COMPATIBLE_TLS))"}))
        self.assertFalse(evidence["client_excludes_deprecated_protocols"])
        self.assertEqual(evidence["protocol_configuration_sites"], ["mobile/src/main/java/o/Http.kt"])

    def test_choosing_the_modern_spec_explicitly_does_not_count(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = client.tls_client_evidence(self.repository(directory, {
                "mobile/src/main/java/o/Http.kt":
                    "val c = builder.connectionSpecs(listOf(ConnectionSpec.MODERN_TLS))"}))
        self.assertTrue(evidence["client_excludes_deprecated_protocols"])

    def test_the_negotiating_selector_finding_proposes_no_filter_for_such_a_client(self):
        from unittest import mock
        from cognalys.llm import migration_policy

        finding = {"spec": "SSLContextSpec",
                   "error_message": "expecting one of {TLSv1.2, TLSv1.3} but found TLS.",
                   "unique_error_id": "c:::m:::SSLContextSpec:::UnsafeProtocol:::x"}
        with mock.patch.object(migration_policy, "_EVIDENCE", {"tls_trust": (
                lambda error: {"client_excludes_deprecated_protocols": True},
                "established_tls_trust_evidence")}):
            policy = migration_policy.generic_migration_policy(finding)
        # Not a blanket "change nothing": another problem in the same code is
        # still fixed; only the protocol filter is ruled out.
        self.assertTrue(policy["authorized"])
        self.assertFalse(policy["filters_deprecated_protocols"])
        self.assertTrue(policy["client_enforces_protocols"])
        self.assertTrue(policy["strategy"].startswith("Add no protocol filter"))


if __name__ == "__main__":
    unittest.main()
