"""A derived value that leaves through a Kotlin property and keys a store is persisted.

EinkBro (2026-10-22): hash() -> sha() -> `val String.sha1 get() = sha("SHA-1", ...)`
-> `val id by lazy { url.sha1 }` -> `filterDataLoader.load(filter.id)` ->
`binaryDataStore.loadData(id)`. The consumers stopped at the getter, so the
SHA-256 patch passed the stored-value gate and would have orphaned every
downloaded filter.
"""
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.value_consumers import derived_value_consumers  # noqa: E402
from cognalys.llm.contract_gates import changed_stored_derivations  # noqa: E402

UTIL = "lib/HashUtilities.kt"
FILES = {
    UTIL: ('package a\n\n'
           'val String.sha1: String\n'
           '    get() = sha("SHA-1", this.toByteArray())\n\n'
           'private fun sha(algorithm: String, bytes: ByteArray): String {\n'
           '    val digest = hash(algorithm, bytes)\n'
           '    return digest.toString()\n}\n\n'
           'private fun hash(algorithm: String, bytes: ByteArray): ByteArray {\n'
           '    val md = MessageDigest.getInstance(algorithm)\n'
           '    return md.digest(bytes)\n}\n'),
    "lib/Filter.kt": ('package a\n\ndata class Filter(val url: String) {\n'
                      '    val id by lazy { url.sha1 }\n}\n'),
    "lib/FilterDataLoader.kt": ('package a\n\nclass FilterDataLoader(private val binaryDataStore: Store) {\n'
                                '    fun load(id: String) {\n'
                                '        if (binaryDataStore.hasData(id)) { use(id) }\n    }\n}\n'),
    "lib/Model.kt": ('package a\n\nclass Model(private val filterDataLoader: FilterDataLoader) {\n'
                     '    fun enable(filter: Filter) {\n'
                     '        filterDataLoader.load(filter.id)\n    }\n}\n'),
}


class KotlinPropertyConsumerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for relative, text in FILES.items():
            (self.root / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.root / relative).write_text(text, encoding="utf-8")

    def consumers(self):
        return derived_value_consumers(
            self.root, [{"path": UTIL, "line": 7}], "hash", source_path=UTIL, source_line=12)

    def test_the_value_is_followed_through_properties_into_the_store(self):
        result = self.consumers()
        self.assertTrue(result["persisted"])
        store = [c for c in result["consumers"] if c["kind"] == "persistence"]
        self.assertIn("binaryDataStore.hasData(id)", store[0]["statement"])

    def test_the_gate_sees_a_changed_algorithm_literal_with_an_unchanged_call(self):
        issues = changed_stored_derivations(
            {"derived_value_consumers": self.consumers()},
            [{"source_file_path": UTIL, "edit_kind": "declaration",
              "original_code": 'val String.sha1: String\n    get() = sha("SHA-1", this.toByteArray())',
              "corrected_code": 'val String.sha256: String\n    get() = sha("SHA-256", this.toByteArray())'}])
        self.assertEqual(issues[0]["code"], "STORED_DERIVED_VALUE_CHANGED")
        self.assertIn('algorithm literal "SHA-1"', issues[0]["details"][0])

    def test_keeping_the_old_literal_for_existing_values_passes(self):
        corrected = ('val String.sha256: String\n    get() = sha("SHA-256", this.toByteArray())\n'
                     'val String.legacySha1: String\n    get() = sha("SHA-1", this.toByteArray())')
        self.assertEqual(changed_stored_derivations(
            {"derived_value_consumers": self.consumers()},
            [{"source_file_path": UTIL, "edit_kind": "declaration",
              "original_code": 'val String.sha1: String\n    get() = sha("SHA-1", this.toByteArray())',
              "corrected_code": corrected}]), [])


class StoredEntryKeyPolicyTests(KotlinPropertyConsumerTests):
    """The policy offers a migration for a digest that keys stored entries."""

    def test_the_rekey_then_migrate_variant_applies(self):
        from cognalys.llm.migration_policy import generic_migration_policy

        policy = generic_migration_policy({
            "spec": "MessageDigestSpec", "method_name": "hash",
            "error_message": "expecting one of SHA-256,SHA-384,SHA-512 but found SHA-1",
            "repository_path": str(self.root), "derived_value_consumers": self.consumers(),
        })
        self.assertEqual(policy["consumer_scope"], "stored_entry_key")
        self.assertTrue(policy["keeps_legacy_derivation"])
        self.assertIn("Re-key, then migrate", policy["strategy"])
        evidence = policy["established_digest_store_key_evidence"]
        self.assertEqual(evidence["store_files"], ["lib/FilterDataLoader.kt"])

    def test_a_digest_also_sent_out_gets_no_rekey_policy(self):
        from cognalys.extraction.digest_store_key_evidence import digest_store_key_evidence

        consumers = dict(self.consumers(), transmitted=True)
        self.assertEqual(digest_store_key_evidence({"derived_value_consumers": consumers}), {})


if __name__ == "__main__":
    unittest.main()
