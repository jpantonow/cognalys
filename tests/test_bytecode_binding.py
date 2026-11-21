"""What a call binds to, read from the invoke instructions of the shipped dex.

run_20260927_175748 abstained on two published advisories for the same
reason: the source text could not bind a call the rule governs. Home
Assistant's `binding.webview.loadUrl(...)` (CVE-2023-41898) has a ViewBinding
property as its receiver, and WordPress's `getIntent()` (GHSL-2022-046) has
none. The dex names both owners; these tests pin that the pipeline reads
them, and that it still refuses when the dex does not single out one type.
"""
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.bytecode_binding import (  # noqa: E402
    ClassInfo, dotted, invocations, method_bytecode_bindings, parameter_count,
    resolve_owner,
    resolved_invocations, settle_from_bytecode, bindings_by_name,
)
from cognalys.extraction.evidence_facts import governed_call_bindings  # noqa: E402
from cognalys.extraction.symbol_binding import resolve_call_bindings  # noqa: E402


# Lines as `dexdump -d` prints them, from Home Assistant 2023.6.0's
# MyActivity.onCreate.
DISASSEMBLY = "\n".join([
    "0019: invoke-virtual {v5}, Lio/ha/MyActivity;.getIntent:()Landroid/content/Intent; // method@1e0b",
    "0065: invoke-virtual {v0}, Landroid/net/Uri;.buildUpon:()Landroid/net/Uri$Builder; // method@0201",
    "0069: invoke-virtual {v0, v2, v1}, Landroid/net/Uri$Builder;.appendQueryParameter:"
    "(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri$Builder; // method@0202",
    "0073: invoke-virtual {v1}, Landroid/webkit/WebView;.getSettings:()Landroid/webkit/WebSettings; // m",
    "0077: invoke-virtual {v2, v4}, Landroid/webkit/WebSettings;.setJavaScriptEnabled:(Z)V // m",
    "008a: invoke-virtual {v6, v0}, Landroid/webkit/WebView;.loadUrl:(Ljava/lang/String;)V // method@03c3",
    "0090: invoke-static/range {v0 .. v5}, Lio/ha/Util;.join:(IJ[Ljava/lang/String;Ljava/util/List;Z)V // m",
])

# MyActivity -> BaseActivity -> AppCompatActivity, all packaged in the APK;
# android.app.Activity is not.
HIERARCHY = {
    "Lio/ha/MyActivity;": ClassInfo(superclass="Lio/ha/BaseActivity;"),
    "Lio/ha/BaseActivity;": ClassInfo(superclass="Landroidx/appcompat/app/AppCompatActivity;"),
    "Landroidx/appcompat/app/AppCompatActivity;": ClassInfo(
        superclass="Landroid/app/Activity;",
        methods=frozenset({"setContentView:(Landroid/view/View;)V"}),
    ),
    "Lio/ha/Util;": ClassInfo(
        superclass="Ljava/lang/Object;",
        methods=frozenset({"join:(IJ[Ljava/lang/String;Ljava/util/List;Z)V"}),
    ),
}


class ParsingTests(unittest.TestCase):
    def test_invoke_instructions_are_read_with_their_arity(self):
        found = invocations(DISASSEMBLY)
        self.assertEqual(
            [(item["name"], item["arity"]) for item in found],
            [("getIntent", 0), ("buildUpon", 0), ("appendQueryParameter", 2),
             ("getSettings", 0), ("setJavaScriptEnabled", 1), ("loadUrl", 1),
             ("join", 5)],
        )

    def test_descriptors_count_arrays_and_wide_types_once(self):
        self.assertEqual(parameter_count("(IJ[Ljava/lang/String;[[BZ)V"), 5)
        self.assertEqual(parameter_count("()V"), 0)

    def test_member_classes_read_as_source_names_them(self):
        self.assertEqual(dotted("Landroid/net/Uri$Builder;"), "android.net.Uri.Builder")
        self.assertEqual(dotted("Lio/ha/MyActivity$onCreate$1$1;"),
                         "io.ha.MyActivity$onCreate$1$1")


class OwnerResolutionTests(unittest.TestCase):
    def test_an_inherited_platform_method_resolves_to_the_platform_type(self):
        owner = resolve_owner("Lio/ha/MyActivity;", "getIntent",
                              "()Landroid/content/Intent;", HIERARCHY.get)
        self.assertEqual(owner, {"resolution": "outside_apk",
                                 "qualified_type": "android.app.Activity"})

    def test_a_method_a_packaged_class_declares_resolves_to_that_class(self):
        owner = resolve_owner("Lio/ha/MyActivity;", "setContentView",
                              "(Landroid/view/View;)V", HIERARCHY.get)
        self.assertEqual(owner["resolution"], "declared_in_apk")
        self.assertEqual(owner["qualified_type"], "androidx.appcompat.app.AppCompatActivity")

    def test_a_platform_receiver_is_its_own_owner(self):
        resolved = resolved_invocations(DISASSEMBLY, HIERARCHY.get)
        load = next(item for item in resolved if item["name"] == "loadUrl")
        self.assertEqual(load["qualified_type"], "android.webkit.WebView")

    def test_a_cycle_is_unresolved_rather_than_looping(self):
        looping = {"La;": ClassInfo(superclass="Lb;"), "Lb;": ClassInfo(superclass="La;")}
        owner = resolve_owner("La;", "run", "()V", looping.get)
        self.assertEqual(owner["resolution"], "unresolved")


class UnreadableApkTests(unittest.TestCase):
    def test_an_unreadable_apk_is_a_status_not_an_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "broken.apk"
            apk.write_bytes(b"not a zip")
            record = method_bytecode_bindings(apk, [{"disassembly": DISASSEMBLY}])
        self.assertEqual(record["status"], "unavailable")


class SettleFromBytecodeTests(unittest.TestCase):
    GROUPED = bindings_by_name({"methods": [
        {"invocations": resolved_invocations(DISASSEMBLY, HIERARCHY.get)}]})

    def test_an_implicit_receiver_is_settled_by_the_dex(self):
        settled = settle_from_bytecode(
            {"called_name": "getIntent", "arity": 0, "receiver_kind": "implicit",
             "resolution": "unresolved", "qualified_type": ""},
            self.GROUPED,
        )
        self.assertEqual(settled["resolution"], "bytecode_invocation")
        self.assertEqual(settled["qualified_type"], "android.app.Activity")

    def test_a_different_arity_is_not_matched(self):
        binding = {"called_name": "loadUrl", "arity": 2, "resolution": "unresolved",
                   "qualified_type": ""}
        self.assertEqual(settle_from_bytecode(binding, self.GROUPED), binding)

    def test_two_owners_for_one_name_stay_unresolved_with_candidates(self):
        grouped = {"close": [
            {"name": "close", "arity": 0, "qualified_type": "java.io.InputStream",
             "resolution": "outside_apk", "static_owner": "", "descriptor": "()V"},
            {"name": "close", "arity": 0, "qualified_type": "android.database.Cursor",
             "resolution": "outside_apk", "static_owner": "", "descriptor": "()V"},
        ]}
        settled = settle_from_bytecode(
            {"called_name": "close", "arity": 0, "resolution": "unresolved"}, grouped)
        self.assertEqual(settled["resolution"], "unresolved")
        self.assertEqual(settled["bytecode_candidates"],
                         ["android.database.Cursor", "java.io.InputStream"])


class GovernedCallBindingWithBytecodeTests(unittest.TestCase):
    SPEC = {"events": [{
        "name": "load_untrusted_url",
        "api_patterns": ["WebView.loadUrl(url)", "WebSettings.setJavaScriptEnabled(true)"],
        "condition": "A call to android.webkit.WebView.loadUrl(String) or "
                     "android.webkit.WebSettings.setJavaScriptEnabled(boolean).",
    }]}
    SOURCE = (
        "package io.ha\n"
        "class MyActivity : BaseActivity() {\n"
        "  override fun onCreate(b: Bundle?) {\n"
        "    val binding = ActivityMyBinding.inflate(layoutInflater)\n"
        "    binding.webview.apply { settings.javaScriptEnabled = true }\n"
        "    binding.webview.loadUrl(newUri.toString())\n"
        "  }\n"
        "}\n"
    )
    BYTECODE = {"status": "available", "methods": [
        {"invocations": resolved_invocations(DISASSEMBLY, HIERARCHY.get)}]}

    def _record(self, bytecode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = "app/src/main/java/io/ha/MyActivity.kt"
            (root / relative).parent.mkdir(parents=True)
            (root / relative).write_text(self.SOURCE, encoding="utf-8")
            return governed_call_bindings(root, relative, self.SPEC, bytecode=bytecode)

    def test_a_generated_code_receiver_is_bound_from_the_dex(self):
        record = self._record(self.BYTECODE)
        self.assertEqual(record["status"], "resolved_to_governed_type")
        self.assertEqual(record["bindings"][0]["resolution"], "bytecode_invocation")

    def test_without_bytecode_the_same_call_stays_unresolved(self):
        self.assertEqual(self._record(None)["status"], "unresolved")

    def test_a_property_access_the_dex_compiles_to_a_call_is_listed(self):
        record = self._record(self.BYTECODE)
        self.assertEqual(
            [item["name"] for item in record["bytecode_only_calls"]],
            ["setJavaScriptEnabled"],
        )


class ChainedReceiverTests(unittest.TestCase):
    def test_a_call_after_a_not_null_assertion_is_not_implicit(self):
        binding = resolve_call_bindings(
            "val u = intent.data!!.buildUpon()", ["buildUpon"])[0]
        self.assertEqual(binding["receiver_kind"], "chained")

    def test_a_call_on_a_call_result_is_not_implicit(self):
        binding = resolve_call_bindings(
            "x.getData().buildUpon()", ["buildUpon"])[0]
        self.assertEqual(binding["receiver_kind"], "chained")

    def test_a_call_without_receiver_is_still_implicit(self):
        binding = resolve_call_bindings("setResult(RESULT_OK, i)", ["setResult"])[0]
        self.assertEqual(binding["receiver_kind"], "implicit")

    def test_a_name_inside_a_longer_identifier_is_not_a_call_of_it(self):
        self.assertEqual(resolve_call_bindings("rebuild()", ["build"]), [])


if __name__ == "__main__":
    unittest.main()
