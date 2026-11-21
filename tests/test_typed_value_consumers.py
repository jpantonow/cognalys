"""The app declarations that receive the reported method's value with its type.

BlueGate run_v9 (2026-10-31): getOrCreateKeyPair(): KeyPair is kept in
MainActivity's `private lateinit var keyPair: KeyPair` and handed to
`Authenticator(this, bleManager, keyPair, ...)`, whose constructor declares
`private val keyPair: KeyPair`. The plan left Authenticator.kt out, every draft
could only rebuild the KeyPair in the callers, and the behaviour review's
no-effect verdict closed the finding at once.
"""
import json
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.typed_consumers import (  # noqa: E402
    compact_typed_consumers, returned_type, typed_value_consumers)

KEY_MANAGER = "app/src/main/java/b/KeyManager.kt"
MAIN = "app/src/main/java/b/MainActivity.kt"
FILES = {
    KEY_MANAGER: ("package b\n\nclass KeyManager(private val keyStore: KeyStore) {\n"
                  "    fun getOrCreateKeyPair(): KeyPair {\n"
                  "        val entry = keyStore.getEntry(\"a\", null) as KeyStore.PrivateKeyEntry\n"
                  "        return KeyPair(entry.certificate.publicKey, entry.privateKey)\n"
                  "    }\n}\n"),
    MAIN: ("package b\n\nclass MainActivity : AppCompatActivity() {\n"
           "    private lateinit var keyPair: KeyPair\n"
           "    private lateinit var keyManager: KeyManager\n\n"
           "    override fun onCreate(savedInstanceState: Bundle?) {\n"
           "        keyManager = KeyManager(store)\n"
           "        keyPair = keyManager.getOrCreateKeyPair()\n"
           "        val raw = keyManager.extract(keyPair.public.encoded)\n"
           "    }\n\n"
           "    private fun connect() {\n"
           "        val authenticator = Authenticator(this, bleManager, keyPair, raw, handler)\n"
           "        authenticator.start()\n"
           "    }\n}\n"),
    "app/src/main/java/b/Authenticator.kt": (
        "package b\n\nclass Authenticator(\n"
        "    private val context: Context,\n"
        "    private val bleManager: BleManager,\n"
        "    private val keyPair: KeyPair,\n"
        "    private val raw: ByteArray,\n"
        "    private val handler: Handler\n) {\n"
        "    fun sign(data: ByteArray) = Signer(keyPair).sign(data)\n}\n"),
    "app/src/main/java/b/Signer.java": (
        "package b;\n\npublic class Signer {\n    private final KeyPair pair;\n\n"
        "    public Signer(KeyPair pair) {\n        this.pair = pair;\n    }\n}\n"),
    # A parameter of another type at the same position is no consumer.
    "app/src/main/java/b/Logger.kt": ("package b\n\nclass Logger(private val a: Context, "
                                      "private val b: BleManager, private val c: String)\n"),
    "app/src/test/java/b/AuthenticatorTest.kt": (
        "package b\n\nclass AuthenticatorTest { val a = Authenticator(c, m, keyPair, r, h) }\n"),
}


class TypedValueConsumerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for relative, text in FILES.items():
            (self.root / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.root / relative).write_text(text, encoding="utf-8")

    def consumers(self, callers=None):
        return typed_value_consumers(
            self.root, callers if callers is not None else [{"path": MAIN, "line": 9}],
            "getOrCreateKeyPair", source_path=KEY_MANAGER, source_cache={
                str(self.root / relative): text for relative, text in FILES.items()})

    def test_the_value_is_followed_through_a_property_into_another_method(self):
        result = self.consumers()
        self.assertEqual(result["value_type"], "KeyPair")
        found = {(item["path"].rsplit("/", 1)[-1], item["line"], item["kind"])
                 for item in result["consumers"]}
        self.assertIn(("MainActivity.kt", 4, "property"), found)
        self.assertIn(("Authenticator.kt", 6, "constructor parameter"), found)
        authenticator = next(item for item in result["consumers"]
                             if item["path"].endswith("Authenticator.kt"))
        self.assertEqual(authenticator["receives_from"], f"{MAIN}:14")
        self.assertIn("keyPair: KeyPair", authenticator["declaration"])

    def test_a_constructor_property_is_followed_into_its_class(self):
        # Authenticator's keyPair reaches Signer's Java constructor, which
        # stores it in its field.
        found = {item["path"].rsplit("/", 1)[-1] for item in self.consumers()["consumers"]}
        self.assertIn("Signer.java", found)

    def test_tests_and_other_types_are_not_consumers(self):
        found = {item["path"] for item in self.consumers()["consumers"]}
        self.assertFalse(any("/test/" in path or "Logger" in path for path in found))

    def test_a_basic_type_is_not_followed(self):
        files = {"A.kt": "class A {\n    fun md5Hash(): String {\n        return x\n    }\n}\n",
                 "B.kt": "class B(private val s: String)\nfun use() { val h = A().md5Hash()\n"
                         "B(h) }\n"}
        for relative, text in files.items():
            (self.root / relative).write_text(text, encoding="utf-8")
        result = typed_value_consumers(self.root, [{"path": "B.kt", "line": 2}], "md5Hash",
                                       source_path="A.kt")
        self.assertEqual(result["status"], "no_typed_value")
        self.assertEqual(result["consumers"], [])

    def test_no_caller_no_consumer_and_the_compact_form(self):
        self.assertEqual(self.consumers([])["status"], "none")
        self.assertEqual(compact_typed_consumers(self.consumers([])), {})
        compact = compact_typed_consumers(self.consumers())
        self.assertEqual(compact["value_type"], "KeyPair")
        self.assertEqual(set(compact["consumers"][0]),
                         {"path", "line", "kind", "declaration", "receives_from"})

    def test_the_context_supplies_the_consumer_files_as_exact_source(self):
        # BlueGate run_v9's tree-sitter parse resolved no caller; the lexical
        # direct_callers held both activities' calls.
        import logging
        from cognalys.llm.generate_error_fixes import FixGenerator

        generator = object.__new__(FixGenerator)
        generator.logger = logging.getLogger("typed-consumers")
        impact = {"status": "available", "direct_callers": [{"path": MAIN, "line": 9}],
                  "semantic_resolution": {"resolved_callers": []}, "exact_candidate_sources": []}
        error = {"repository_path": str(self.root), "source_file_path": KEY_MANAGER,
                 "method_name": "getOrCreateKeyPair",
                 "expanded_repository_context": {"multi_file_impact": impact}}
        generator.collect_typed_value_consumers(error)
        self.assertEqual(error["typed_value_consumers"]["status"], "found")
        self.assertIn("app/src/main/java/b/Authenticator.kt", impact["required_caller_sources"])

    def test_java_return_types(self):
        self.assertEqual(returned_type(["  public static KeyPair load(String a) {"], "load"),
                         "KeyPair")
        self.assertEqual(returned_type(["fun load(): java.security.KeyPair? {"], "load"),
                         "KeyPair")


class CollectorScopeTests(unittest.TestCase):
    """Review of batch 13 (2026-10-31): declarations the collector recorded that
    never receive the value."""

    def collect(self, files, callers, method, source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, text in files.items():
                (root / relative).parent.mkdir(parents=True, exist_ok=True)
                (root / relative).write_text(text, encoding="utf-8")
            return typed_value_consumers(
                root, callers, method, source_path=source,
                source_cache={str(root / relative): text for relative, text in files.items()})

    def test_other_platform_targets_and_test_sets_are_not_consumers(self):
        manager = "shared/src/androidMain/kotlin/a/KeyManager.kt"
        authenticator = "class Authenticator(private val keyPair: KeyPair)\n"
        found = self.collect({
            manager: "class KeyManager {\n    fun getOrCreateKeyPair(): KeyPair {\n"
                     "        return gen()\n    }\n}\n",
            "shared/src/androidMain/kotlin/a/Main.kt": (
                "class Main {\n    fun go() {\n        val kp = km.getOrCreateKeyPair()\n"
                "        Authenticator(kp)\n    }\n}\n"),
            "shared/src/androidMain/kotlin/a/Authenticator.kt": authenticator,
            "shared/src/jvmMain/kotlin/a/Authenticator.kt": authenticator,
            "desktopApp/src/jvmMain/kotlin/a/Authenticator.kt": authenticator,
            "shared/src/iosMain/kotlin/a/Authenticator.kt": authenticator,
            "shared/src/commonTest/kotlin/a/KeyTest.kt": (
                "class KeyTest {\n    fun t() {\n        val kp = km.getOrCreateKeyPair()\n"
                "        FakeSigner(kp)\n    }\n}\nclass FakeSigner(val kp: KeyPair)\n"),
        }, [{"path": "shared/src/androidMain/kotlin/a/Main.kt", "line": 3},
            {"path": "shared/src/commonTest/kotlin/a/KeyTest.kt", "line": 3}],
            "getOrCreateKeyPair", manager)
        self.assertEqual([item["path"] for item in found["consumers"]],
                         ["shared/src/androidMain/kotlin/a/Authenticator.kt"])

    def test_a_call_is_matched_to_the_declaration_its_receiver_owns(self):
        keys = "app/src/main/java/a/Keys.kt"
        found = self.collect({
            keys: ("class Keys {\n    fun getSecretKey(): SecretKey {\n"
                   "        return ks.getKey(\"k\", null) as SecretKey\n    }\n"
                   "    fun enc(cipher: Cipher) {\n        val key = getSecretKey()\n"
                   "        cipher.init(Cipher.ENCRYPT_MODE, key)\n    }\n}\n"),
            "app/src/main/java/a/Unrelated.kt": (
                "class Unrelated {\n    fun init(mode: Int, key: SecretKey) {\n"
                "        store(mode, key)\n    }\n}\n"),
        }, [{"path": keys, "line": 6}], "getSecretKey", keys)
        self.assertEqual(found["consumers"], [])
        manager = "app/src/main/java/a/KeyManager.kt"
        found = self.collect({
            manager: "class KeyManager {\n    fun getOrCreateKeyPair(): KeyPair {\n"
                     "        return gen()\n    }\n}\n",
            "app/src/main/java/a/Main.kt": (
                "class Main {\n    fun go(storage: Storage) {\n"
                "        val kp = km.getOrCreateKeyPair()\n        storage.save(kp)\n    }\n}\n"),
            "app/src/main/java/a/Storage.kt": "class Storage {\n    fun save(kp: KeyPair) { }\n}\n",
            "app/src/main/java/a/Backup.kt": "class Backup {\n    fun save(pair: KeyPair) { }\n}\n",
            "wear/src/main/java/a/Exporter.kt": "class Exporter {\n    fun save(pair: KeyPair) { }\n}\n",
        }, [{"path": "app/src/main/java/a/Main.kt", "line": 3}], "getOrCreateKeyPair", manager)
        self.assertEqual([item["path"] for item in found["consumers"]],
                         ["app/src/main/java/a/Storage.kt"])

    def test_a_local_is_not_the_property_it_shadows(self):
        keys = "app/src/main/java/a/Keys.kt"
        sync = "app/src/main/java/a/Sync.kt"
        found = self.collect({
            keys: ("class Keys {\n    fun getSecretKey(): SecretKey {\n"
                   "        return ks.getKey(\"k\", null) as SecretKey\n    }\n}\n"),
            sync: ("class Sync(private val keys: Keys) {\n"
                   "    private val key: SecretKey = SecretKeySpec(serverBytes, \"AES\")\n"
                   "    fun local() {\n        val key = keys.getSecretKey()\n"
                   "        cipher.init(1, key)\n    }\n"
                   "    fun upload() {\n        Sender(key).send()\n    }\n}\n"),
            "app/src/main/java/a/Sender.kt": (
                "class Sender(private val k: SecretKey) {\n    fun send() {}\n}\n"),
        }, [{"path": sync, "line": 4}], "getSecretKey", keys)
        self.assertEqual(found["consumers"], [])


class NoEffectReplanTests(unittest.TestCase):
    """A no-effect verdict gets one new plan (BlueGate run_v9 vs run_v8)."""

    def run_unit(self, reviews, replan=True, single_round=False, consumers=True):
        import sys

        sys.path.insert(0, str(Path(__file__).parent))
        from test_applied_edits_match_text import CLEAN_REVIEW, METHOD_EDIT, _coordinated_run

        calls = {"adjudications": 0, "reviews": 0}
        no_effect = {**CLEAN_REVIEW, "patch_has_no_effect": True,
                     "no_effect_reason": "KeyPair rebuilt from the entry's own parts"}

        regression = {**CLEAN_REVIEW, "regressions": [{
            "scenario": "first run", "before": "the key is created", "after": "it throws",
            "source_file_path": "src/Main.java"}]}

        def review(call):
            calls["reviews"] += 1
            answer = reviews[min(calls["reviews"], len(reviews)) - 1]
            return regression if answer == "regress" else no_effect if answer else CLEAN_REVIEW

        def adjudicate(error, apk_name, method_name):
            calls["adjudications"] += 1
            calls["seed"] = dict(error.get("previous_patch_no_effect") or {})
            return {"generation_status": "supported" if replan else "blocked",
                    "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                    "coordinated_fix_plan": {"required_edits": [
                        {"source_file_path": "src/Main.java", "symbol": "method"}]}}, {}

        from cognalys.llm.generate_error_fixes import FixGenerator

        original = getattr(FixGenerator, "adjudicate_finding", None)
        FixGenerator.adjudicate_finding = lambda self, *args: adjudicate(*args)
        try:
            extra = {"typed_value_consumers": {"value_type": "KeyPair", "consumers": [
                {"path": "src/Authenticator.kt", "line": 23, "kind": "constructor parameter",
                 "declaration": "private val keyPair: KeyPair,"}] if consumers else []}}
            if single_round:
                extra["evidence_analysis"] = {
                    "confirmed_cause": "cause", "v2": {"adjudication": {"single_round": True}},
                    "coordinated_fix_plan": {"required_edits": [
                        {"source_file_path": "src/Main.java", "symbol": "method"}]}}
            result, _, error, _ = _coordinated_run(review, [METHOD_EDIT], error_extra=extra)
        finally:
            if original is None:
                del FixGenerator.adjudicate_finding
            else:
                FixGenerator.adjudicate_finding = original
        return result, calls, error

    def test_a_no_effect_verdict_replans_once_seeded_with_the_reason_and_the_consumers(self):
        result, calls, _ = self.run_unit([True, False])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(calls["adjudications"], 1)
        self.assertEqual(calls["seed"]["reason"], "KeyPair rebuilt from the entry's own parts")
        self.assertEqual([item["path"] for item in calls["seed"]["typed_value_consumers_outside_plan"]],
                         ["src/Authenticator.kt"])

    def test_the_finding_closes_only_when_the_new_plan_has_no_effect_either(self):
        result, calls, _ = self.run_unit([True, True])
        self.assertEqual(calls["adjudications"], 1)
        self.assertEqual(result["stage"], "behavior_review")
        self.assertIn("PATCH_HAS_NO_EFFECT", result["issues"][0])
        self.assertTrue(result["correct_use"])

    def test_a_single_round_unit_and_a_refused_plan_close_at_once(self):
        result, calls, _ = self.run_unit([True], single_round=True)
        self.assertEqual(calls["adjudications"], 0)
        self.assertIn("PATCH_HAS_NO_EFFECT", result["issues"][0])
        result, calls, _ = self.run_unit([True], replan=False)
        self.assertEqual(calls["adjudications"], 1)
        self.assertIn("PATCH_HAS_NO_EFFECT", result["issues"][0])

    def test_without_anything_new_to_plan_with_the_finding_closes_at_once(self):
        # Review of batch 13 (2026-10-31): 17 of the 20 no-effect units had no
        # typed consumer outside the plan and no draft note on an unplanned
        # file; each replan cost a new adjudication, plan, drafts and review.
        result, calls, _ = self.run_unit([True], consumers=False)
        self.assertEqual(calls["adjudications"], 0)
        self.assertEqual(calls["reviews"], 1)
        self.assertIn("PATCH_HAS_NO_EFFECT", result["issues"][0])
        self.assertTrue(result["correct_use"])

    def test_a_new_plan_that_fails_otherwise_keeps_the_first_verdict(self):
        # Review of batch 13 (2026-10-31): the replanned drafts regressed, the
        # first plan's no-effect verdict was lost and the finding became a
        # maintainer issue instead of a violation without security impact.
        result, calls, error = self.run_unit([True, "regress"])
        # One new plan in all: no replan_after_regressions after it.
        self.assertEqual(calls["adjudications"], 1)
        self.assertEqual(result["stage"], "behavior_review")
        self.assertIn("PATCH_HAS_NO_EFFECT", result["issues"][0])
        self.assertTrue(result["correct_use"])
        self.assertFalse(result.get("pipeline_failure"))
        self.assertEqual(result["replan_after_no_effect"]["status"], "invalid")
        # Closed under the plan the verdict judged, not the new one.
        self.assertEqual(error["evidence_analysis"]["confirmed_cause"], "cause")

    def test_the_drafts_notes_on_unplanned_files_seed_the_plan(self):
        from cognalys.llm.coordinated_generation import unplanned_draft_notes

        with tempfile.TemporaryDirectory() as directory:
            draft = Path(directory) / "02_MainActivity.kt.json"
            draft.write_text(json.dumps({
                "review_assumptions": [
                    "Authenticator continues to require a java.security.KeyPair, so this "
                    "activity reconstructs it.", "The alias stays BlueGate."],
                "required_contracts": ["KeyManager.kt returns KeyStore.PrivateKeyEntry"]}))
            notes = unplanned_draft_notes([str(draft)], ["app/KeyManager.kt", "app/MainActivity.kt"],
                                          ["app/Authenticator.kt"])
        self.assertEqual(len(notes), 1)
        self.assertIn("Authenticator continues", notes[0])

    def test_the_plan_sees_the_typed_consumers_and_the_no_effect_seed(self):
        import inspect
        from cognalys.llm import finding_adjudication

        source = inspect.getsource(finding_adjudication)
        self.assertIn('plan_sections["typed_value_consumers"] = typed', source)
        self.assertIn('plan_sections["previous_patch_no_effect"]', source)


if __name__ == "__main__":
    unittest.main()
