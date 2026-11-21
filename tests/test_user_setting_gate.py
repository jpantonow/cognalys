import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.contract_gates import removed_user_setting  # noqa: E402

WORK = "app/src/main/java/cn/gov/xivpn2/service/SubscriptionWork.java"


class UserSettingTests(unittest.TestCase):
    """xivpn's patch deleted the branch behind "subscription_no_verify"."""

    def test_removing_an_opted_in_branch_is_refused(self):
        original = ('if (prefs.getBoolean("subscription_no_verify", false)) {\n'
                    "    builder.sslSocketFactory(Utils.trustAllSslSocketFactory, tm);\n}")
        issues = removed_user_setting({}, [{
            "source_file_path": WORK, "original_code": original,
            "corrected_code": "OkHttpClient client = new OkHttpClient.Builder().build();"}])
        self.assertEqual(issues[0]["code"], "USER_SETTING_REMOVED")
        self.assertIn("subscription_no_verify", issues[0]["details"][0])

    def test_keeping_the_setting_passes(self):
        code = 'if (prefs.getBoolean("subscription_no_verify", false)) { a(); }'
        self.assertEqual(removed_user_setting({}, [{
            "source_file_path": WORK, "original_code": code,
            "corrected_code": code.replace("a();", "b();")}]), [])
        self.assertEqual(removed_user_setting({}, [{
            "source_file_path": "app/src/test/java/A.java", "original_code": code,
            "corrected_code": ""}]), [])

    def test_validation_leaves_the_setting_to_the_maintainer(self):
        """2026-10-22: a removed setting is a warning, the maintainer decides."""
        from cognalys.llm.semantic_validation import validate_coordinated_semantics

        original = ('if (prefs.getBoolean("subscription_no_verify", false)) {\n'
                    "    builder.sslSocketFactory(Utils.trustAllSslSocketFactory, tm);\n}")
        result = validate_coordinated_semantics({}, [{
            "source_file_path": WORK, "edit_kind": "method", "symbol": "build",
            "reason": "r", "original_code": original,
            "corrected_code": "OkHttpClient client = new OkHttpClient.Builder().build();"}])
        self.assertNotIn("USER_SETTING_REMOVED", [e["code"] for e in result["errors"]])
        warning = [w for w in result["warnings"] if w["code"] == "USER_SETTING_REMOVED"]
        self.assertTrue(warning and warning[0]["maintainer_decides"])


class OptionOnlyLocalTests(unittest.TestCase):
    """A local the edited snippet declares is not a field the option reads.

    Clash Fest (rvsec_alpha_20261028): generateAndroidKeyStoreKey declared
    `kpg` and `now`; mintSelfSigned, an opt-in member by its name, declared
    its own, so every other use sat inside the option and the gate warned
    that users who enabled it lose that behaviour.
    """

    TLS = "app/src/main/java/c/CompanionTlsIdentity.kt"
    ORIGINAL = (
        "object CompanionTlsIdentity {\n"
        "    private fun generateAndroidKeyStoreKey(alias: String) {\n"
        "        val kpg = KeyPairGenerator.getInstance(\"EC\", \"AndroidKeyStore\")\n"
        "        val now = System.currentTimeMillis()\n"
        "        kpg.initialize(spec(alias, now))\n"
        "        kpg.generateKeyPair()\n"
        "    }\n"
        "    private fun mintSelfSigned(alias: String): X509Certificate {\n"
        "        val kpg = KeyPairGenerator.getInstance(\"EC\")\n"
        "        val now = System.currentTimeMillis()\n"
        "        return sign(kpg.generateKeyPair(), now)\n"
        "    }\n"
        "}\n"
    )

    def run_gate(self, original, snippet, corrected):
        from cognalys.llm.semantic_validation import neutralized_option_branches

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / self.TLS).parent.mkdir(parents=True)
            (root / self.TLS).write_text(original, encoding="utf-8")
            return neutralized_option_branches({"repository_path": str(root)}, [{
                "source_file_path": self.TLS, "original_code": snippet,
                "corrected_code": corrected, "edit_kind": "method"}])

    def test_the_clash_fest_locals_are_not_option_fields(self):
        start = self.ORIGINAL.index("    private fun generateAndroidKeyStoreKey")
        snippet = self.ORIGINAL[start:self.ORIGINAL.index("    private fun mintSelfSigned")]
        corrected = snippet.replace("kpg.initialize(spec(alias, now))\n",
                                    "kpg.initialize(spec(alias, now, PURPOSE_SIGN))\n")
        self.assertEqual(self.run_gate(self.ORIGINAL, snippet, corrected), [])

    def test_a_reassigned_user_option_is_still_flagged(self):
        original = (
            "class Client {\n"
            "    private var insecureFactory: SSLSocketFactory? = null\n"
            "    fun setup() {\n"
            "        val context = app()\n"
            "        insecureFactory = trustAll()\n"
            "    }\n"
            "    fun open(c: HttpsURLConnection) {\n"
            "        if (Prefs.isAllowInsecureEnabled(context)) {\n"
            "            c.sslSocketFactory = insecureFactory\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        snippet = "        val context = app()\n        insecureFactory = trustAll()\n"
        issues = self.run_gate(original, snippet, snippet.replace("trustAll()", "platform()"))
        self.assertEqual([issue["code"] for issue in issues], ["USER_OPTION_NEUTRALIZED"])
        self.assertIn("insecureFactory", issues[0]["details"][0])

    def test_a_member_declared_with_its_initializer_is_still_flagged(self):
        """The DSub pattern, with the insecure factory built in its declaration."""
        cases = {
            "app/src/main/java/c/Client.java": (
                "public class Client {\n"
                "    private SSLSocketFactory insecureFactory = trustAll();\n"
                "    void open(HttpsURLConnection c) {\n"
                "        if (Util.isAllowInsecureEnabled(context)) {\n"
                "            c.setSSLSocketFactory(insecureFactory);\n"
                "        }\n"
                "    }\n"
                "}\n",
                "    private SSLSocketFactory insecureFactory = trustAll();\n"),
            "app/src/main/java/c/Client.kt": (
                "class Client(private val context: Context) {\n"
                "    private val insecureFactory = trustAll()\n"
                "    fun open(c: HttpsURLConnection) {\n"
                "        if (Util.isAllowInsecureEnabled(context)) {\n"
                "            c.sslSocketFactory = insecureFactory\n"
                "        }\n"
                "    }\n"
                "}\n",
                "    private val insecureFactory = trustAll()\n"),
            # A Kotlin member needs no modifier.
            "app/src/main/java/c/Holder.kt": (
                "object Holder {\n"
                "    val insecureFactory = trustAll()\n"
                "    fun open(c: HttpsURLConnection) {\n"
                "        if (Prefs.isAllowInsecureEnabled()) {\n"
                "            c.sslSocketFactory = insecureFactory\n"
                "        }\n"
                "    }\n"
                "}\n",
                "    val insecureFactory = trustAll()\n"),
        }
        for path, (original, snippet) in cases.items():
            with self.subTest(path=path):
                self.TLS = path
                issues = self.run_gate(original, snippet, snippet.replace("trustAll()", "platform()"))
                self.assertEqual([issue["code"] for issue in issues], ["USER_OPTION_NEUTRALIZED"])
                self.assertIn("insecureFactory", issues[0]["details"][0])

    def test_members_and_locals_in_context(self):
        from cognalys.llm.semantic_validation import _names_declared_in

        java = (
            "class A {\n    int total = 0;\n"
            "    Runnable r = new Runnable() {\n        int count = 0;\n"
            "        public void run() { int step = 1; }\n    };\n"
            "    static { int boot = 2; }\n}\n"
        )
        self.assertEqual(_names_declared_in(java, java, 0), {"step", "boot"})
        kotlin = (
            "val top = 1\nclass B(val ctor: Int) : Base() {\n    var field = 0\n"
            "    init { val early = 1 }\n    companion object { val shared = 2 }\n"
            "    fun f() { items.forEach { item -> val inner = item } }\n"
            "    val anon = object : Runnable { val own = 3\n        override fun run() { val mine = 4 } }\n}\n"
        )
        self.assertEqual(_names_declared_in(kotlin, kotlin, 0), {"early", "item", "inner", "mine"})
        # Without the file every declaration counts, as in a lone fragment.
        self.assertIn("field", _names_declared_in(kotlin))

    def test_declaration_forms(self):
        from cognalys.llm.semantic_validation import _names_declared_in

        code = (
            "val kpg = a()\nvar (left, right) = pair\nfinal Map<String, Integer> counts = m;\n"
            "byte[] iv;\nfor (String item : items) {}\nfor ((key, value) in map) {}\n"
            "list.forEach { entry -> use(entry) }\nrun((first, second) -> f(first))\n"
            "items.map(single -> single)\n"
        )
        self.assertEqual(_names_declared_in(code), {
            "kpg", "left", "right", "counts", "iv", "item", "key", "value", "entry",
            "first", "second", "single"})

    def test_reassignments_and_branches_declare_nothing(self):
        from cognalys.llm.semantic_validation import _names_declared_in

        code = (
            "val ctx = app\ninsecureFactory = trustAll()\nreturn result;\n"
            "} else factory = platform();\nwhen {\n    allowInsecure -> a()\n}\n"
            "do factory = trustAll(); while (retry);\n"
        )
        self.assertEqual(_names_declared_in(code), {"ctx"})


if __name__ == "__main__":
    unittest.main()
