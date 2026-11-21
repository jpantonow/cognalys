"""Evidence requests about a member's uses are answered with its reference sites.

exp_final_20261019 declined 217 of 584 requests as "no matching file in the
repository"; most named a member (Helper.getFingerprint(Context, String),
MainViewModel.random, getDbFilename) whose declaring file was already in the
packet, and asked where it is used.
"""
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm import evidence_requests  # noqa: E402
from cognalys.llm.evidence_requests import (  # noqa: E402
    requested_member_names, resolve_evidence_requests,
)


class ReferenceSiteTests(unittest.TestCase):
    def test_members_are_read_from_the_way_a_request_writes_them(self):
        self.assertEqual(requested_member_names(
            {"symbol": "Helper.getFingerprint(Context, String)"}), ["getFingerprint"])
        self.assertEqual(requested_member_names({"symbol": "Helper#getFingerprint return value"}),
                         ["getFingerprint"])
        self.assertEqual(requested_member_names(
            {"symbol": "RedditSubredditManager.getDbFilename / *_subreddits.db"}),
            ["getDbFilename"])
        self.assertEqual(requested_member_names({"symbol": "appLockDataHash outputs and values"}), [])

    def _repo(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "app").mkdir()
        (root / "app" / "Helper.java").write_text(
            "class Helper {\n  static String getFingerprint(Context c, String h) {\n"
            "    return digest(h);\n  }\n}\n", encoding="utf-8")
        (root / "app" / "Settings.java").write_text(
            "class Settings {\n  void show() {\n"
            "    String fp = Helper.getFingerprint(ctx, \"SHA-1\");\n"
            "    prefs.edit().putString(\"fp\", fp).apply();\n  }\n}\n", encoding="utf-8")
        return root

    def test_a_usage_request_is_answered_even_when_the_declaring_file_was_supplied(self):
        root = self._repo()
        request = {"kind": "derived_value_sink_inventory",
                   "symbol": "Helper#getFingerprint return value",
                   "reason": "Determine whether the value is persisted or transmitted."}
        result = resolve_evidence_requests(root, [request], {"app/Helper.java"})
        self.assertEqual(result["declined"], [])
        [entry] = result["entries"]
        self.assertEqual(entry["kind"], "requested_reference_sites")
        self.assertEqual(entry["data"]["member"], "getFingerprint")
        self.assertIn("app/Settings.java:3:", entry["data"]["content"])
        self.assertIn('putString("fp", fp)', entry["data"]["content"])

    def test_a_file_named_without_its_directory_is_fetched_when_unique(self):
        root = self._repo()
        (root / "app" / "keys.properties").write_text("key.size=1024\n", encoding="utf-8")
        request = {"kind": "configuration_file", "symbol": "key size in keys.properties"}
        result = resolve_evidence_requests(root, [request], set())
        self.assertEqual(result["declined"], [])
        self.assertEqual([entry["data"]["source_file_path"] for entry in result["entries"]],
                         ["app/keys.properties"])
        # Two files of that name: nothing is guessed.
        (root / "lib").mkdir()
        (root / "lib" / "keys.properties").write_text("key.size=2048\n", encoding="utf-8")
        result = resolve_evidence_requests(root, [request], set())
        self.assertEqual(result["entries"], [])

    def _droid_scep(self):
        # Droid_SCEP CertReq (exp_final_20261019): both requests for the key
        # size were declined as "no matching file in the repository".
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        files = {
            "app/src/main/res/layout/fragment_scep.xml": (
                '<LinearLayout>\n  <Spinner\n      android:id="@+id/spinnerKeySize"\n'
                '      android:entries="@array/key_sizes" />\n</LinearLayout>\n'),
            "app/src/main/res/values/arrays.xml": (
                '<resources>\n  <string-array name="key_sizes">\n    <item>1024</item>\n'
                '    <item>2048</item>\n  </string-array>\n</resources>\n'),
            "app/src/main/res/values/strings.xml": (
                '<resources>\n  <string name="default_rsa_len">2048</string>\n'
                '  <string name="other">x</string>\n</resources>\n'),
            "app/src/main/res/values-de/strings.xml": (
                '<resources>\n  <string name="default_rsa_len">4096</string>\n</resources>\n'),
            "app/src/main/res/xml/app_restrictions.xml": (
                '<restrictions>\n  <restriction android:key="rsa-key-length" '
                'android:restrictionType="string" />\n</restrictions>\n'),
            "app/src/main/java/scep/ScepClient.java": (
                "class ScepClient {\n  void CertReq() { kpg.initialize(size); }\n}\n"),
        }
        for relative, text in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text, encoding="utf-8")
        return root

    def test_android_resources_are_answered_with_their_declared_values(self):
        root = self._droid_scep()
        requests = [
            {"kind": "resource",
             "symbol": "R.id.spinnerKeySize entries (spinner entries array or layout fragment_scep.xml)"},
            {"kind": "resource",
             "symbol": "R.string.default_rsa_len and app_restrictions.xml rsa-key-length"},
        ]
        result = resolve_evidence_requests(
            root, requests, set(),
            target={"source_file_path": "app/src/main/java/scep/ScepClient.java"})
        self.assertEqual(result["declined"], [])
        values = [entry for entry in result["entries"]
                  if entry["kind"] == "android_resource_values"]
        self.assertEqual(len(values), 2)
        spinner = "\n".join(item["declaration"] for item in values[0]["data"]["declarations"])
        self.assertIn('android:id="@+id/spinnerKeySize"', spinner)
        self.assertIn("<item>2048</item>", spinner)
        rsa = values[1]["data"]["declarations"]
        self.assertEqual({(item["qualifier"], item["declaration"]) for item in rsa}, {
            ("values", '<string name="default_rsa_len">2048</string>'),
            ("values-de", '<string name="default_rsa_len">4096</string>'),
        })
        # Labelled as declared values, not the value seen at run time.
        self.assertIn("not a value observed at run time", values[1]["data"]["derivation"])
        fetched = {entry["data"]["source_file_path"] for entry in result["entries"]
                   if entry["kind"] == "requested_source"}
        self.assertEqual(fetched, {"app/src/main/res/layout/fragment_scep.xml",
                                   "app/src/main/res/xml/app_restrictions.xml"})

    def test_a_widget_field_reaches_its_views_entries(self):
        """The request Droid_SCEP's runs actually wrote (rerun_correcoes_20261022):
        the field, not the view id, so @array/rsa_lens never reached the packet."""
        root = self._droid_scep()
        fragment = root / "app/src/main/java/scep/ScepFragment.java"
        fragment.write_text(
            "class ScepFragment {\n  Spinner spinnerKeyLen;\n"
            "  void onCreateView(View v) {\n"
            "    spinnerKeyLen = v.findViewById(R.id.spinnerKeySize);\n  }\n"
            "  int size() { return Integer.parseInt(String.valueOf("
            "spinnerKeyLen.getSelectedItem())); }\n}\n", encoding="utf-8")
        request = {"kind": "resource_source",
                   "reason": "Resolve the spinner's available values and the default RSA key length.",
                   "symbol": "spinnerKeyLen / R.string.default_rsa_len"}
        target = {"source_file_path": "app/src/main/java/scep/ScepClient.java"}
        result = resolve_evidence_requests(root, [request], set(), target=target)
        [values] = [entry for entry in result["entries"]
                    if entry["kind"] == "android_resource_values"]
        self.assertEqual(values["data"]["references"],
                         ["@string/default_rsa_len", "@id/spinnerKeySize"])
        declared = "\n".join(item["declaration"] for item in values["data"]["declarations"])
        self.assertIn('<string-array name="key_sizes">', declared)
        self.assertIn("<item>1024</item>", declared)

    def test_kotlin_and_view_binding_fields_reach_their_views(self):
        root = self._droid_scep()
        (root / "app/src/main/res/layout/activity_main.xml").write_text(
            '<LinearLayout>\n  <Spinner android:id="@+id/digest_choice"\n'
            '      android:entries="@array/key_sizes" />\n'
            '  <Spinner android:id="@+id/modeSpinner" />\n</LinearLayout>\n', encoding="utf-8")
        (root / "app/src/main/java/scep/MainActivity.kt").write_text(
            "class MainActivity {\n"
            "  private val chosenDigest: Spinner by lazy { findViewById<Spinner>(R.id.digest_choice) }\n"
            "  fun bind() { mPicker = binding.digestChoice\n"
            "    val modeView: Spinner = findViewById(R.id.modeSpinner) }\n}\n", encoding="utf-8")
        index = evidence_requests.RepositoryIndex(root)
        target = {"source_file_path": "app/src/main/java/scep/MainActivity.kt"}

        def ids(symbol):
            return evidence_requests.widget_view_ids(index, target, {"symbol": symbol})

        self.assertEqual(ids("chosenDigest selected item"), ["digest_choice"])
        self.assertEqual(ids("modeView"), ["modeSpinner"])
        # binding.digestChoice is @+id/digest_choice.
        self.assertEqual(ids("mPicker.getSelectedItem()"), ["digest_choice"])
        # A binding property named on its own is its view.
        self.assertEqual(ids("digestChoice"), ["digest_choice"])
        # A plain word, or a member after a dot, is not a field the request names.
        self.assertEqual(ids("spinner values"), [])
        self.assertEqual(ids("binding.digestChoice"), [])

    def test_an_identifier_bound_to_no_view_adds_nothing(self):
        root = self._droid_scep()
        index = evidence_requests.RepositoryIndex(root)
        target = {"source_file_path": "app/src/main/java/scep/ScepClient.java"}
        self.assertEqual(evidence_requests.widget_view_ids(
            index, target, {"symbol": "keyGen / R.string.default_rsa_len"}), [])
        result = resolve_evidence_requests(
            root, [{"kind": "resource", "symbol": "keyGen / R.string.default_rsa_len"}],
            set(), target=target)
        [values] = [entry for entry in result["entries"]
                    if entry["kind"] == "android_resource_values"]
        self.assertEqual(values["data"]["references"], ["@string/default_rsa_len"])

    def test_a_field_only_request_keeps_the_method_bodys_resources(self):
        """A Spinner without android:entries filled in the method body by
        createFromResource: naming the field must not drop that array."""
        root = self._droid_scep()
        (root / "app/src/main/res/layout/fragment_keys.xml").write_text(
            '<LinearLayout>\n  <Spinner android:id="@+id/spinnerKeyChoice" />\n'
            '</LinearLayout>\n', encoding="utf-8")
        (root / "app/src/main/java/scep/KeysFragment.java").write_text(
            "class KeysFragment {\n  Spinner keySpinner;\n"
            "  void onCreateView(View v) {\n"
            "    keySpinner = v.findViewById(R.id.spinnerKeyChoice);\n"
            "    keySpinner.setAdapter(ArrayAdapter.createFromResource(v.getContext(), "
            "R.array.key_sizes, 0));\n  }\n}\n", encoding="utf-8")
        target = {"source_file_path": "app/src/main/java/scep/KeysFragment.java",
                  "method_body": "keySpinner.setAdapter(ArrayAdapter.createFromResource("
                                 "v.getContext(), R.array.key_sizes, 0));"}
        for symbol, views in (("key size choices", []),
                              ("keySpinner choices", ["@id/spinnerKeyChoice"])):
            result = resolve_evidence_requests(
                root, [{"kind": "resource", "symbol": symbol}], set(), target=target)
            [values] = [entry for entry in result["entries"]
                        if entry["kind"] == "android_resource_values"]
            self.assertEqual(values["data"]["references"], views + ["@array/key_sizes"], symbol)
            declared = "\n".join(item["declaration"] for item in values["data"]["declarations"])
            self.assertIn("<item>1024</item>", declared)

    def test_the_method_body_names_the_resources_only_for_a_bare_resource_request(self):
        root = self._droid_scep()
        target = {"source_file_path": "app/src/main/java/scep/ScepClient.java",
                  "method_body": "int size = res.getInteger(R.string.default_rsa_len);"}
        result = resolve_evidence_requests(
            root, [{"kind": "resource", "symbol": "key size value"}], set(), target=target)
        self.assertEqual([entry["kind"] for entry in result["entries"]],
                         ["android_resource_values"])
        # "resources" that are streams to close are about the stream type.
        result = resolve_evidence_requests(
            root, [{"kind": "resource_cleanup", "symbol": "FileInputStream close"}],
            set(), target=target)
        self.assertNotIn("android_resource_values",
                         [entry["kind"] for entry in result["entries"]])

    def test_a_caller_question_is_answered_for_the_member_it_names(self):
        # Cryptomator asked for "BaseCipher.decrypt(byte[]) callers" and got
        # the callers of the reported getIvParameterSpec.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "app").mkdir()
        (root / "app" / "BaseCipher.java").write_text(
            "package app;\nclass BaseCipher {\n"
            "  IvParameterSpec getIvParameterSpec(byte[] iv) { return new IvParameterSpec(iv); }\n"
            "  byte[] decrypt(byte[] data) { return run(getIvParameterSpec(data)); }\n}\n",
            encoding="utf-8")
        (root / "app" / "Vault.java").write_text(
            "package app;\nclass Vault {\n  void open(BaseCipher c) { c.decrypt(bytes); }\n}\n",
            encoding="utf-8")
        result = resolve_evidence_requests(
            root, [{"kind": "caller_inventory", "symbol": "BaseCipher.decrypt(byte[]) callers"}],
            set(), target={"source_file_path": "app/BaseCipher.java",
                           "method_name": "getIvParameterSpec", "csv_class": "app.BaseCipher"})
        [entry] = result["entries"]
        record = entry["data"]["record"]
        self.assertEqual(record["searched_name"], "decrypt")
        self.assertEqual([caller["source_file_path"] for caller in record["callers"]],
                         ["app/Vault.java"])

    def test_a_string_is_not_answered_with_the_array_of_the_same_name(self):
        # `\b` after the tag matched `<string-array`; Android allows a string
        # and an array to share a name.
        root = self._droid_scep()
        (root / "app/src/main/res/values/keys.xml").write_text(
            '<resources>\n  <string-array name="key_len">\n    <item>1024</item>\n'
            '  </string-array>\n  <string name="key_len">2048</string>\n</resources>\n',
            encoding="utf-8")
        result = resolve_evidence_requests(
            root, [{"kind": "resource", "symbol": "@string/key_len"}], set())
        [entry] = [entry for entry in result["entries"]
                   if entry["kind"] == "android_resource_values"]
        self.assertEqual([item["declaration"] for item in entry["data"]["declarations"]],
                         ['<string name="key_len">2048</string>'])

    def test_resource_declarations_are_capped_like_any_entry(self):
        root = self._droid_scep()
        value = "x" * 1_400
        for qualifier in range(24):
            folder = root / f"app/src/main/res/values-v{qualifier + 1}"
            folder.mkdir(parents=True)
            (folder / "strings.xml").write_text(
                f'<resources>\n  <string name="big">{value}</string>\n</resources>\n',
                encoding="utf-8")
        result = resolve_evidence_requests(
            root, [{"kind": "resource", "symbol": "R.string.big"}], set())
        [entry] = result["entries"]
        declarations = entry["data"]["declarations"]
        self.assertLessEqual(sum(len(item["declaration"]) for item in declarations),
                             evidence_requests.MAX_ENTRY_CHARACTERS)
        self.assertLess(len(declarations), 24)
        self.assertIs(entry["data"]["truncated"], True)

    def test_a_resource_request_also_gets_the_types_it_names(self):
        # autoshine's "all code and resources affecting the nine EditText
        # fields" used to get its sources; answered with resources, it did not.
        root = self._droid_scep()
        result = resolve_evidence_requests(
            root, [{"kind": "resource", "symbol": "R.string.default_rsa_len read by ScepClient"}],
            set())
        self.assertEqual(
            [(entry["kind"], entry["data"].get("source_file_path", "")) for entry in result["entries"]],
            [("android_resource_values", ""),
             ("requested_source", "app/src/main/java/scep/ScepClient.java")])

    def test_a_constructor_caller_question_names_its_class(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "q").mkdir()
        (root / "q" / "MacInstance.kt").write_text(
            "package q\nclass MacInstance(algorithm: String, key: ByteArray)\n", encoding="utf-8")
        (root / "q" / "Tag.kt").write_text(
            "package q\nfun tag(k: ByteArray) = MacInstance(\"HmacSHA256\", k)\n", encoding="utf-8")
        result = resolve_evidence_requests(
            root, [{"kind": "caller_inventory", "symbol": "MacInstance.<init> callers"}], set(),
            target={"source_file_path": "q/Tag.kt", "method_name": "tag", "csv_class": "q.TagKt"})
        [entry] = result["entries"]
        record = entry["data"]["record"]
        self.assertEqual((record["searched_name"], record["name_resolution"]),
                         ("MacInstance", "constructor"))
        self.assertEqual(entry["data"]["source_file_path"], "q/MacInstance.kt")
        self.assertEqual([caller["source_file_path"] for caller in record["callers"]], ["q/Tag.kt"])

    def test_a_member_used_nowhere_is_still_declined(self):
        root = self._repo()
        result = resolve_evidence_requests(
            root, [{"kind": "consumer_inventory", "symbol": "Helper.neverCalled()"}],
            {"app/Helper.java"})
        self.assertEqual(result["entries"], [])
        self.assertEqual(len(result["declined"]), 1)


if __name__ == "__main__":
    unittest.main()
