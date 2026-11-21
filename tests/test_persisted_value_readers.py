import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils.persisted_value_readers import (  # noqa: E402
    discharge_compatibility_without_readers, unread_written_keys)

# Your Local Weather (2026-11-02): encryptKey's hash is written under one
# preference key that nothing reads.
FRAGMENT = """class GeneralPreferenceFragment {
    void save() {
        preferences.edit().putString(Constants.KEY_PREF_WEATHER_INITIAL_TOKEN, encryptKey(input.getText())).apply();
    }

    private String encryptKey(String key) {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return hex(factory.generateSecret(spec).getEncoded());
    }
}
"""
CONSTANTS = """class Constants {
    public static final String KEY_PREF_WEATHER_INITIAL_TOKEN = "weather_forecast_initial token_pref_key";
}
"""
BLOCKER = {"category": "compatibility_contract", "kind": "stored-value consumer",
           "description": "establish every reader of KEY_PREF_WEATHER_INITIAL_TOKEN"}


def _repository(directory: str, extra: dict | None = None) -> Path:
    root = Path(directory)
    files = {"app/src/main/java/a/GeneralPreferenceFragment.java": FRAGMENT,
             "app/src/main/java/a/Constants.java": CONSTANTS, **(extra or {})}
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text, encoding="utf-8")
    return root


class UnreadWrittenKeyTests(unittest.TestCase):
    def test_a_value_only_written_under_a_key_nothing_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            result = unread_written_keys(_repository(directory), "encryptKey")
        self.assertEqual(result["status"], "no_reader")
        self.assertEqual(result["keys"], ["Constants.KEY_PREF_WEATHER_INITIAL_TOKEN"])
        self.assertEqual(result["writes"][0]["line"], 3)

    def test_a_reader_of_the_constant_or_its_literal_is_found(self):
        for reader in ('String t = prefs.getString(Constants.KEY_PREF_WEATHER_INITIAL_TOKEN, "");',
                       '<EditTextPreference android:key="weather_forecast_initial token_pref_key"/>'):
            with self.subTest(reader=reader), tempfile.TemporaryDirectory() as directory:
                result = unread_written_keys(_repository(directory, {
                    "app/src/main/java/a/Reader.java" if reader.startswith("String")
                    else "app/src/main/res/xml/prefs.xml": reader}), "encryptKey")
                self.assertEqual(result["status"], "read")

    def test_another_use_of_the_method_or_a_write_inside_it_settles_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _repository(directory, {"app/src/main/java/a/Net.java":
                                           "class Net { void s() { send(f.encryptKey(k)); } }"})
            self.assertEqual(unread_written_keys(root, "encryptKey")["status"], "other_use")
            self.assertEqual(unread_written_keys(
                root, "encryptKey", "prefs.edit().putString(K, v).apply();")["status"],
                "writes_inside")
            self.assertEqual(unread_written_keys(root, "missing")["status"], "no_call_found")


class ReaderTheSearchCannotRuleOutTests(unittest.TestCase):
    """Refuted 2026-11-02: each of these came out "no_reader"."""

    def _status(self, files):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path, text in files.items():
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(text, encoding="utf-8")
            return unread_written_keys(root, "hash")["status"]

    WRITE = ('class A { static final String K = "tok"; String hash(String k) { return k; }\n'
             ' void s() { prefs.edit().putString(K, hash(t)).apply(); } }')

    def test_a_put_into_a_map_or_an_intent_is_another_use(self):
        for line in ('headers.put("Authorization", hash(t)); client.send(headers);',
                     'intent.putExtra("token", hash(t)); startActivity(intent);',
                     'values.put("k", hash(t)); db.insert("t", null, values);',
                     'bundle.putString("k", hash(t));'):
            with self.subTest(line=line):
                self.assertEqual(self._status({"A.java": "class A { String hash(String k) "
                                               "{ return k; }\n void s() { " + line + " } }"}),
                                 "other_use")

    def test_an_editor_variable_or_a_datastore_edit_is_a_persistent_write(self):
        editor = ('class A { static final String K = "tok"; String hash(String k) { return k; }\n'
                  ' void s() { SharedPreferences.Editor e = prefs.edit();\n'
                  ' e.putString(K, hash(t)); e.apply(); } }')
        datastore = ('object A { val K = stringPreferencesKey("tok")\n'
                     ' fun hash(k: String) = k\n suspend fun s() { store.edit { prefs ->\n'
                     '  prefs[K] = hash(t)\n } } }')
        self.assertEqual(self._status({"A.java": editor}), "no_reader")
        self.assertEqual(self._status({"A.kt": datastore}), "no_reader")

    def test_get_all_backup_or_a_dynamic_reader_key_leaves_it_unknown(self):
        for name, text in (
                ("E.java", "class E { void x() { for (Object e : prefs.getAll().entrySet()) "
                           "out.write(e); } }"),
                ("R.java", 'class R { String r() { return prefs.getString("t" + "ok", null); } }'),
                ("R2.java", "class R { int r(String k) { return prefs.getInt(k, 0); } }"),
                ("AndroidManifest.xml", '<application android:fullBackupContent="@xml/b"/>'),
                ("native/lib.cpp", 'const char *key = "tok";')):
            with self.subTest(name=name):
                self.assertEqual(self._status({"A.java": self.WRITE, name: text}), "unknown")

    def test_resource_and_one_argument_getters_are_not_preference_reads(self):
        other = ('class T { String t() { return context.getString(label, v) + b.getString(k)'
                 ' + s.contains("(,"); } }')
        self.assertEqual(self._status({"A.java": self.WRITE, "T.java": other}), "no_reader")


class DischargeTests(unittest.TestCase):
    def _notes(self):
        return {"publication_blocker_record": {"blockers": [BLOCKER],
                                               "plan_publication_blockers": [
                                                   "Before publication, establish every reader of "
                                                   "Constants.KEY_PREF_WEATHER_INITIAL_TOKEN.",
                                                   "Other line."]},
                "publication_considerations": [BLOCKER],
                "publication_blockers": ["establish every reader of "
                                         "Constants.KEY_PREF_WEATHER_INITIAL_TOKEN", "Other line."]}

    def _solution(self, **extra):
        return {"method_name": "encryptKey", "coordinated_edits": [
            {"edit_kind": "method", "symbol": "encryptKey"},
            {"edit_kind": "constant", "symbol": "Constants"}], **extra}

    def test_the_blocker_moves_to_discharged_with_its_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            notes = discharge_compatibility_without_readers(
                self._notes(), _repository(directory), self._solution())
        record = notes["publication_blocker_record"]
        self.assertEqual(record["blockers"], [])
        self.assertEqual(record["discharged_blockers"][0]["discharged_by"],
                         "no reader of the written key")
        self.assertEqual(record["plan_publication_blockers"], ["Other line."])
        self.assertEqual(notes["publication_considerations"], [])
        self.assertEqual(notes["publication_blockers"], ["Other line."])
        self.assertEqual(notes["persisted_value_readers"]["status"], "no_reader")

    def test_a_read_key_or_an_edit_of_another_method_keeps_the_blocker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = _repository(directory, {"app/src/main/java/a/Reader.java":
                                           "x = p.getString(Constants.KEY_PREF_WEATHER_INITIAL_TOKEN, null);"})
            notes = discharge_compatibility_without_readers(self._notes(), root, self._solution())
            self.assertEqual(notes["publication_blocker_record"]["blockers"], [BLOCKER])
            other = self._solution(coordinated_edits=[{"edit_kind": "method", "symbol": "save"}])
            notes = discharge_compatibility_without_readers(
                self._notes(), root, other)
            self.assertEqual(notes["publication_blocker_record"]["blockers"], [BLOCKER])


if __name__ == "__main__":
    unittest.main()


class ReadersEvidenceTests(unittest.TestCase):
    """The search reaches the model before the PR step (Your Local Weather run_v3)."""

    POLICY = {"registry_version": "2.0", "specification": "SecretKeySpec",
              "family": "generic", "common": {}, "family_policy": {}}

    def test_only_no_reader_becomes_evidence(self):
        from cognalys.utils.persisted_value_readers import readers_evidence

        with tempfile.TemporaryDirectory() as directory:
            found = readers_evidence(unread_written_keys(_repository(directory), "encryptKey"),
                                     "encryptKey")
        self.assertIn("KEY_PREF_WEATHER_INITIAL_TOKEN at "
                      "app/src/main/java/a/GeneralPreferenceFragment.java:3",
                      found["statement"])
        for status in ("unknown", "read", "other_use", "dynamic_key", "no_call_found"):
            self.assertEqual(readers_evidence({"status": status}, "encryptKey"), {})
        self.assertEqual(readers_evidence(None, "encryptKey"), {})

    def _packet(self, readers: dict) -> list:
        from cognalys.llm.evidence_packet import FindingEvidencePacketBuilder

        with tempfile.TemporaryDirectory() as directory:
            root = _repository(directory)
            packet = FindingEvidencePacketBuilder().build({
                "csv_class": "a.GeneralPreferenceFragment", "method_name": "encryptKey",
                "method_body": "return hex(factory.generateSecret(spec).getEncoded());",
                "source_file_path": "app/src/main/java/a/GeneralPreferenceFragment.java",
                "repository_path": str(root), "spec": "SecretKeySpec",
                "persisted_value_readers": readers}, self.POLICY)
        return [item for item in packet["evidence_catalog"]
                if item["kind"] == "persisted_value_readers"]

    def test_a_key_nothing_reads_reaches_the_evidence_packet(self):
        with tempfile.TemporaryDirectory() as directory:
            readers = unread_written_keys(_repository(directory), "encryptKey")
        items = self._packet(readers)
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["evidence_id"].startswith("FLOW-"))
        self.assertEqual(items[0]["data"]["keys"],
                         ["Constants.KEY_PREF_WEATHER_INITIAL_TOKEN"])

    def test_an_unsettled_search_adds_no_evidence(self):
        self.assertEqual(self._packet({"status": "unknown", "detail": "getAll"}), [])

    def test_the_prompts_carry_the_guidance(self):
        from cognalys.llm import coordinated_generation, finding_adjudication
        from cognalys.utils.persisted_value_readers import NO_READER_GUIDANCE

        for module in (coordinated_generation, finding_adjudication):
            source = Path(module.__file__).read_text(encoding="utf-8")
            self.assertIn("NO_READER_GUIDANCE", source)
        self.assertIn("not a reason for NO_SAFE_FIX", NO_READER_GUIDANCE)
