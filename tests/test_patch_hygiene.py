import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.config.apply_solutions_config import ApplySolutionsConfig  # noqa: E402
from cognalys.llm.semantic_validation import (  # noqa: E402
    caller_value_rejections, statements_without_effect, private_member_calls_in_tests,
)
from cognalys.solutions.solution_applicator import SolutionApplicator  # noqa: E402
from cognalys.solutions.solution_mapper import SolutionMapper  # noqa: E402
from cognalys.validation import applied_solutions as vas  # noqa: E402


PRODUCTION = """package a

class AccessPointsAdapterData {
    private fun calculateChildType(): Int = 1
    private fun update(value: Int) = value
    fun update(): Int = 2
}
"""


class PrivateMemberTestCallTests(unittest.TestCase):
    def _issues(self, test_code: str):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "app/src/main/kotlin/a/AccessPointsAdapterData.kt"
            path.parent.mkdir(parents=True)
            path.write_text(PRODUCTION, encoding="utf-8")
            error = {"repository_path": str(root),
                     "source_file_path": "app/src/main/kotlin/a/AccessPointsAdapterData.kt"}
            edits = [{"source_file_path": "app/src/test/kotlin/a/DataTest.kt",
                      "edit_kind": "create", "original_code": "",
                      "corrected_code": test_code}]
            return private_member_calls_in_tests(error, edits)

    def test_a_call_on_an_instance_of_the_class_is_flagged(self):
        issues = self._issues(
            "val data = AccessPointsAdapterData()\n"
            "val type = data.calculateChildType()\n"
        )
        self.assertEqual(issues[0]["code"], "TEST_CALLS_PRIVATE_MEMBER")
        self.assertIn("AccessPointsAdapterData.calculateChildType", issues[0]["details"][0])

    def test_a_call_on_the_constructor_is_flagged(self):
        self.assertTrue(self._issues("AccessPointsAdapterData().calculateChildType()\n"))

    def test_a_same_named_method_of_another_type_is_not_flagged(self):
        self.assertEqual(self._issues(
            "val digest = MessageDigest.getInstance(\"SHA-256\")\n"
            "digest.calculateChildType()\n"
        ), [])

    def test_a_wider_overload_makes_the_call_legal(self):
        self.assertEqual(self._issues(
            "val data = AccessPointsAdapterData()\n"
            "data.update()\n"
        ), [])


class StatementWithoutEffectTests(unittest.TestCase):
    def _issues(self, original: str, corrected: str):
        return statements_without_effect([{
            "source_file_path": "core/src/main/java/K.kt", "edit_kind": "method",
            "original_code": original, "corrected_code": corrected,
        }])

    def test_an_added_discarded_cast_is_flagged(self):
        issues = self._issues(
            "return (keystore.getEntry(KEY, null) as KeyStore.SecretKeyEntry).secretKey\n",
            "keystore.getEntry(KEY, null) as KeyStore.SecretKeyEntry\n"
            "return keystore.getKey(KEY, null) as SecretKey\n",
        )
        self.assertEqual(len(issues), 1)
        self.assertNotIn("return", issues[0]["details"][0])

    def test_casts_whose_value_is_used_are_not_flagged(self):
        self.assertEqual(self._issues(
            "",
            "val key = entry as SecretKey\n"
            "return entry as SecretKey\n"
            "if (x as Boolean) run()\n",
        ), [])

    def test_a_cast_line_the_original_already_had_is_not_flagged(self):
        line = "holder as? View\n"
        self.assertEqual(self._issues(line, line + "run()\n"), [])

    def test_a_cast_continuing_an_assignment_is_not_flagged(self):
        # Tasks' AndroidOkHttpClientFactory draft (rvsec_tasks_20261025).
        self.assertEqual(self._issues(
            "",
            "        val trustManagerFactory = customCertManager.trustManagerFactory\n"
            "        val trustManager = trustManagerFactory.trustManagers\n"
            "            .single { it is X509TrustManager } as X509TrustManager\n"
            '        val sslContext = SSLContext.getInstance("TLS")\n',
        ), [])

    def test_a_lambda_result_followed_by_an_elvis_is_not_flagged(self):
        # Ursa's TlsTrust and Cryptomator's SSLSocketFactories drafts.
        self.assertEqual(self._issues(
            "",
            "        val chain = peerCertificates.map { certificate ->\n"
            "            certificate as? X509Certificate\n"
            '                ?: throw CertificateException("Server sent a non-X.509 certificate")\n'
            "        }.toTypedArray()\n",
        ), [])
        self.assertEqual(self._issues(
            "",
            "\t\t\t\t\tval chain = delegate.session.peerCertificates.map { certificate ->\n"
            "\t\t\t\t\t\tcertificate as? X509Certificate\n"
            '\t\t\t\t\t\t\t?: throw CertificateException("Peer supplied a non-X509 certificate")\n'
            "\t\t\t\t\t}.toTypedArray()\n",
        ), [])

    def test_a_discarded_cast_opening_or_closing_a_block_is_still_flagged(self):
        cast = "    keystore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry\n"
        first = self._issues("", "fun key(): SecretKey {\n" + cast
                             + "    return keystore.getKey(KEY_ALIAS, null) as SecretKey\n}\n")
        last = self._issues("", "fun touch() {\n    keystore.load(null)\n" + cast + "}\n")
        self.assertEqual(len(first), 1)
        self.assertEqual(len(last), 1)


class CallerValueRejectionTests(unittest.TestCase):
    """A patch must not make a method refuse values its callers pass today."""

    def _issues(self, original: str, corrected: str, path="app/src/main/java/T.java"):
        return caller_value_rejections(
            {"repository_path": "/nonexistent"},
            [{"source_file_path": path, "edit_kind": "method",
              "original_code": original, "corrected_code": corrected}],
        )

    def test_throwing_for_a_parameter_value_that_used_to_work_is_flagged(self):
        original = (
            "    public static String generateTOTP(String key, int shaType) {\n"
            "        if (shaType == 0) {\n"
            "            crypto = \"HmacSHA1\";\n"
            "        }\n"
            "    }\n"
        )
        corrected = original.replace(
            '            crypto = "HmacSHA1";\n',
            '            throw new IllegalArgumentException("SHA-1 TOTP is not supported");\n',
        )
        issues = self._issues(original, corrected)
        self.assertEqual(issues[0]["code"], "REJECTS_CALLER_SUPPLIED_VALUE")
        self.assertIn("shaType", issues[0]["details"][0])

    def test_a_new_allow_list_guard_on_a_parameter_is_flagged(self):
        original = (
            "    public static void certReq(String url, int isKeyLen) throws Exception {\n"
            "        keyGen.initialize(isKeyLen);\n"
            "    }\n"
        )
        corrected = original.replace(
            "        keyGen.initialize(isKeyLen);\n",
            "        if(isKeyLen != 3072 && isKeyLen != 4096) {\n"
            "            throw new IllegalArgumentException(\"Unsupported: \" + isKeyLen);\n"
            "        }\n"
            "        keyGen.initialize(isKeyLen);\n",
        )
        self.assertTrue(self._issues(original, corrected))

    def test_a_kotlin_require_on_a_parameter_is_flagged(self):
        original = "    fun digest(algorithm: String): ByteArray {\n        return run(algorithm)\n    }\n"
        corrected = original.replace(
            "        return run(algorithm)\n",
            "        require(algorithm != \"MD5\")\n        return run(algorithm)\n",
        )
        self.assertTrue(self._issues(original, corrected, "app/src/main/kotlin/D.kt"))

    def test_a_guard_on_a_local_variable_is_not_flagged(self):
        original = (
            "    public TLSSocketFactory() throws IOException {\n"
            "        int secureProtocolCount = count();\n"
            "    }\n"
        )
        corrected = original.replace(
            "        int secureProtocolCount = count();\n",
            "        int secureProtocolCount = count();\n"
            "        if (secureProtocolCount == 0) {\n"
            "            throw new IOException(\"no secure protocol\");\n"
            "        }\n",
        )
        self.assertEqual(self._issues(original, corrected), [])

    def test_a_format_check_against_constants_is_not_flagged(self):
        original = "    fun decrypt(envelope: String): String {\n        return open(envelope)\n    }\n"
        corrected = original.replace(
            "        return open(envelope)\n",
            "        val components = envelope.split(\":\")\n"
            "        require(components[1] == KDF_ALGORITHM)\n"
            "        return open(envelope)\n",
        )
        self.assertEqual(self._issues(original, corrected, "app/src/main/kotlin/S.kt"), [])

    def test_a_null_check_is_not_flagged(self):
        original = "    public void init(String key) {\n        use(key);\n    }\n"
        corrected = original.replace(
            "        use(key);\n",
            "        if (key == null) {\n            throw new IllegalArgumentException(\"key\");\n        }\n"
            "        use(key);\n",
        )
        self.assertEqual(self._issues(original, corrected), [])

    def test_changing_a_literal_the_app_chose_is_not_flagged(self):
        original = "    void configure(SSLSocket s) {\n        s.setEnabledProtocols(new String[] {\"TLSv1\"});\n    }\n"
        corrected = original.replace('"TLSv1"', '"TLSv1.2"')
        self.assertEqual(self._issues(original, corrected), [])


class EmptiedFileTests(unittest.TestCase):
    def test_edits_that_empty_an_existing_file_delete_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Ext.kt"
            body = "fun trustAll() {\n}\n"
            source.write_text(body, encoding="utf-8")
            caller = root / "Client.kt"
            caller.write_text("fun client() {\n    trustAll()\n}\n", encoding="utf-8")
            applicator = SolutionApplicator(ApplySolutionsConfig(
                error_solutions_dir=str(root / "solutions"),
                cloned_projects_dir=str(root), output_dir=str(root / "results"),
                worktrees_dir=str(root / "worktrees"), save_backups=False,
            ))
            solution = {"coordinated_edits": [{
                "source_file_path": "Ext.kt", "symbol": "trustAll",
                "edit_kind": "delete", "original_code": body,
                "corrected_code": "", "reason": "remove the trust-all helper",
            }, {
                "source_file_path": "Client.kt", "symbol": "client",
                "edit_kind": "delete", "original_code": "    trustAll()\n",
                "corrected_code": "", "reason": "stop installing it",
            }]}
            ok, changes, error = applicator._apply_coordinated_edits(
                solution, SolutionMapper(str(root / "solutions"), str(root)), root
            )
            self.assertTrue(ok, error)
            self.assertFalse(source.exists())
            self.assertTrue(changes[0]["file_deleted"])


FREAD_CLIENT = """package a

object GlobalOkHttpClient {
    val client = buildClient()

    fun buildSSLFactory(): SSLSocketFactory {
        val context = SSLContext.getInstance("SSL")
        return context.socketFactory
    }
}

fun later() = 1
"""

FREAD_ORIGINAL = """    fun buildSSLFactory(): SSLSocketFactory {
        val context = SSLContext.getInstance("SSL")
        return context.socketFactory
    }
}
"""

FREAD_CORRECTED = """    fun buildSSLFactory(): SSLSocketFactory {
        val context = SSLContext.getInstance("TLS")
        return ProtocolFilteringSSLSocketFactory(context.socketFactory)
    }
}

class ProtocolFilteringSSLSocketFactory(
    private val delegate: SSLSocketFactory,
) : SSLSocketFactory() {
    override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
}
"""


class MethodIndentationTests(unittest.TestCase):
    """A method edit keeps its layout and the scope of the code after it."""

    def _apply(self, original: str, corrected: str, content: str = FREAD_CLIENT):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "GlobalOkHttpClient.kt"
            source.write_text(content, encoding="utf-8")
            applicator = SolutionApplicator(ApplySolutionsConfig(
                error_solutions_dir=str(root / "solutions"),
                cloned_projects_dir=str(root), output_dir=str(root / "results"),
                worktrees_dir=str(root / "worktrees"), save_backups=False,
            ))
            solution = {
                "authorized_patch_plan": {"required_edits": [
                    {"source_file_path": "GlobalOkHttpClient.kt"}]},
                "coordinated_edits": [{
                    "source_file_path": "GlobalOkHttpClient.kt",
                    "symbol": "buildSSLFactory", "edit_kind": "method",
                    "original_code": original, "corrected_code": corrected,
                    "reason": "use the TLS selector",
                }],
            }
            ok, _changes, error = applicator._apply_coordinated_edits(
                solution, SolutionMapper(str(root / "solutions"), str(root)), root
            )
            return ok, error, source.read_text(encoding="utf-8")

    def test_an_edit_closing_the_enclosing_object_keeps_its_indentation(self):
        ok, error, updated = self._apply(FREAD_ORIGINAL, FREAD_CORRECTED)
        self.assertTrue(ok, error)
        self.assertEqual(updated, FREAD_CLIENT.replace(FREAD_ORIGINAL, FREAD_CORRECTED))
        self.assertIn("\nclass ProtocolFilteringSSLSocketFactory(", updated)
        self.assertIn("\n    fun buildSSLFactory()", updated)

    def test_an_unindented_body_is_indented_to_the_original(self):
        original = FREAD_ORIGINAL[: -len("}\n")]
        corrected = (
            "fun buildSSLFactory(): SSLSocketFactory {\n"
            "    val context = SSLContext.getInstance(\"TLS\")\n"
            "    return context.socketFactory\n"
            "}\n"
        )
        ok, error, updated = self._apply(original, corrected)
        self.assertTrue(ok, error)
        self.assertIn(
            "    fun buildSSLFactory(): SSLSocketFactory {\n"
            "        val context = SSLContext.getInstance(\"TLS\")\n"
            "        return context.socketFactory\n"
            "    }\n}\n", updated)

    def test_an_over_indented_body_is_shifted_back(self):
        original = FREAD_ORIGINAL[: -len("}\n")]
        corrected = (
            "        fun buildSSLFactory(): SSLSocketFactory {\n"
            "            val context = SSLContext.getInstance(\"TLS\")\n"
            "            return context.socketFactory\n"
            "        }\n"
        )
        ok, error, updated = self._apply(original, corrected)
        self.assertTrue(ok, error)
        self.assertIn(
            "\n    fun buildSSLFactory(): SSLSocketFactory {\n"
            "        val context = SSLContext.getInstance(\"TLS\")\n"
            "        return context.socketFactory\n"
            "    }\n}\n", updated)

    def test_alignment_never_goes_below_column_zero(self):
        from cognalys.solutions.solution_mapper import MethodReplacer
        aligned = MethodReplacer.align_generated_indentation(
            "fun a() {\n    b()\n}", "    fun a() {\n        c()\n    }")
        self.assertEqual(aligned, "fun a() {\n    c()\n}")

    def test_a_block_that_moves_later_lines_into_another_scope_is_rejected(self):
        corrected = FREAD_CORRECTED.replace("    }\n}\n\nclass", "    }\n\nclass", 1)
        ok, error, updated = self._apply(FREAD_ORIGINAL, corrected)
        self.assertFalse(ok)
        self.assertTrue(error.startswith("EDIT_CHANGES_ENCLOSING_SCOPE:"), error)
        self.assertIn("fun later() = 1", error)
        self.assertEqual(updated, FREAD_CLIENT)

    def test_the_draft_check_sends_a_scope_change_back_to_the_model(self):
        from cognalys.llm.coordinated_generation import CoordinatedGeneration
        corrected = FREAD_CORRECTED.replace("    }\n}\n\nclass", "    }\n\nclass", 1)
        generated = {"source_file_path": "GlobalOkHttpClient.kt", "edits": [{
            "source_file_path": "GlobalOkHttpClient.kt", "symbol": "buildSSLFactory",
            "edit_kind": "method", "original_code": FREAD_ORIGINAL,
            "corrected_code": corrected, "reason": "use the TLS selector",
        }]}
        sources = {"GlobalOkHttpClient.kt": FREAD_CLIENT}
        issues = CoordinatedGeneration._coordinated_draft_issues(
            generated, "GlobalOkHttpClient.kt",
            {"source_file_path": "GlobalOkHttpClient.kt"}, [], sources, "")
        self.assertTrue(any("brace scope" in issue for issue in issues), issues)
        generated["edits"][0]["corrected_code"] = FREAD_CORRECTED
        self.assertEqual(CoordinatedGeneration._coordinated_draft_issues(
            generated, "GlobalOkHttpClient.kt",
            {"source_file_path": "GlobalOkHttpClient.kt"}, [], sources, ""), [])

    def test_a_backtick_name_with_an_apostrophe_is_not_a_scope_change(self):
        from cognalys.solutions.scope_utils import scope_change_outside_edit
        content = "class T {\n    fun a() {\n    }\n}\n\nfun b() = 1\n"
        original = "    fun a() {\n    }\n"
        corrected = "    fun `it doesn't crash`() {\n        val s = \"\"\"{\"\"\"\n    }\n"
        self.assertEqual(scope_change_outside_edit(content, original, corrected), "")


class BuildSideEffectTests(unittest.TestCase):
    def _git(self, root: Path, *args: str):
        subprocess.run(["git", "-C", str(root), *args], check=True,
                       capture_output=True, text=True)

    def test_only_files_the_build_modified_are_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.email", "t@example.com")
            self._git(root, "config", "user.name", "t")
            (root / "app").mkdir()
            (root / "app" / "build.properties").write_text("version_build=11\n")
            (root / "app" / "A.kt").write_text("val a = 1\n")
            self._git(root, "add", "-A")
            self._git(root, "commit", "-q", "-m", "base")
            # The patch's own edit, made before the build.
            (root / "app" / "A.kt").write_text("val a = 2\n")
            before = vas.modified_tracked_files(root / "app")
            # The build's side effect.
            (root / "app" / "build.properties").write_text("version_build=12\n")
            restored = vas.restore_build_side_effects(root / "app", before)
            self.assertEqual(restored, ["app/build.properties"])
            self.assertEqual((root / "app" / "build.properties").read_text(), "version_build=11\n")
            self.assertEqual((root / "app" / "A.kt").read_text(), "val a = 2\n")

    def test_outside_a_git_checkout_nothing_is_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNone(vas.modified_tracked_files(root))
            self.assertEqual(vas.restore_build_side_effects(root, None), [])


if __name__ == "__main__":
    unittest.main()
