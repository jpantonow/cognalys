import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction import digest_reference_evidence as digests  # noqa: E402
from cognalys.llm import semantic_validation  # noqa: E402

# Shaped like whoBIRD's Downloader.java (2026-10-18).
SOURCE = '''
public class Downloader {
    static final String modelURL = "https://example.org/model.tflite";
    static final String metaURL = "https://example.org/meta.tflite";
    static final String modelMD5 = "0b1c981fe261910b473b9b7eec9ebcd4";
    static final String metaMD5 = "c12c2baafe4d1bb098e65291bfcb2f8c";
    static final String metaV1MD5 = "f1a078ae0f244a1ff5a8f1ccb645c805";
    static String hash(byte[] data) throws Exception {
        byte[] hash = MessageDigest.getInstance("MD5").digest(data);
        return new BigInteger(1, hash).toString(16);
    }
}
'''
FILES = {
    "https://example.org/model.tflite": {"MD5": "0b1c981fe261910b473b9b7eec9ebcd4",
                                         "SHA-1": "x", "SHA-256": "00ab" + "1" * 60, "size": 10},
    "https://example.org/meta.tflite": {"MD5": "c12c2baafe4d1bb098e65291bfcb2f8c",
                                        "SHA-1": "x", "SHA-256": "2" * 64, "size": 5},
}


class DigestReferenceTests(unittest.TestCase):
    def finding(self, directory):
        root = Path(directory)
        (root / "app/src/main/java/o").mkdir(parents=True)
        (root / "app/src/main/java/o/Downloader.java").write_text(SOURCE)
        return {"repository_path": str(root), "source_file_path": "app/src/main/java/o/Downloader.java",
                "error_message": "expecting one of SHA-256,SHA-512 but found MD5"}

    def test_each_constant_is_paired_with_the_file_whose_digest_it_is(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = digests.digest_reference_evidence(
                self.finding(directory), fetch=lambda url: {"url": url, **FILES[url]})
        self.assertTrue(evidence["expected_digests_verified"])
        values = {item["constant"]: item["new_value"] for item in evidence["replacement_values"]}
        # BigInteger.toString(16) drops leading zeros, so the new value does too.
        self.assertEqual(values, {"modelMD5": "ab" + "1" * 60, "metaMD5": "2" * 64})
        self.assertEqual(evidence["unmatched_digest_constants"], ["metaV1MD5"])
        self.assertIn("`metaV1MD5` matches none of them, so I removed its check",
                      evidence["maintainer_facts"]["digest_references"])

    def test_nothing_is_claimed_when_no_download_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = digests.digest_reference_evidence(
                self.finding(directory),
                fetch=lambda url: {"url": url, "MD5": "f" * 32, "SHA-1": "", "SHA-256": "", "size": 1})
        self.assertFalse(evidence["expected_digests_verified"])
        self.assertNotIn("replacement_values", evidence)

    def test_a_patch_must_carry_the_given_values(self):
        values = [{"constant": "metaMD5", "old_value": "c12c2baafe4d1bb098e65291bfcb2f8c",
                   "new_value": "2" * 64}]
        error = {"case_migration_policy": {"replacement_values": values}}
        good = [{"source_file_path": "Downloader.java", "edit_kind": "declaration",
                 "original_code": 'metaMD5 = "c12c2baafe4d1bb098e65291bfcb2f8c"',
                 "corrected_code": 'metaSHA256 = "' + "2" * 64 + '"'}]
        bad = [dict(good[0], corrected_code='metaSHA256 = "' + "3" * 64 + '"')]
        codes = lambda edits: {item["code"] for item in semantic_validation.validate_coordinated_semantics(
            error, edits)["errors"]}
        self.assertNotIn("REPLACEMENT_VALUES_NOT_APPLIED", codes(good))
        self.assertIn("REPLACEMENT_VALUES_NOT_APPLIED", codes(bad))


class VariableNameTests(unittest.TestCase):
    """whoBIRD run7 kept `model16MD5` and `calcModelMD5` holding SHA-256 values."""

    original = ('static final String model16MD5 = "b1c981fe261910b473b9b7eec9ebcd4e";\n'
                'String calcModelMD5 = "";\n'
                'byte[] hash = MessageDigest.getInstance("MD5").digest(data);')

    def test_a_kept_name_stating_the_removed_algorithm_is_reported(self):
        corrected = (self.original.replace('"MD5"', '"SHA-256"')
                     .replace("b1c981fe261910b473b9b7eec9ebcd4e", "5c64" + "0" * 60))
        names = {item["name"] for item in
                 semantic_validation.variable_name_contradictions(self.original, corrected)}
        self.assertEqual(names, {"model16MD5", "calcModelMD5"})
        renamed = corrected.replace("model16MD5", "model16Sha256").replace(
            "calcModelMD5", "calcModelSha256")
        self.assertEqual(semantic_validation.variable_name_contradictions(self.original, renamed), [])

    def test_a_name_used_elsewhere_is_left_alone(self):
        corrected = self.original.replace('"MD5"', '"SHA-256"')
        self.assertEqual(semantic_validation.variable_name_contradictions(
            self.original, corrected, referenced_elsewhere=lambda name: True), [])

    def test_a_lambda_body_is_named_by_its_enclosing_method(self):
        from cognalys.utils.pr_text import short_symbol

        self.assertEqual(short_symbol("o.Downloader", "lambda$downloadModels$4"),
                         "Downloader.downloadModels")


class FixedValueMovesWithDerivationTests(unittest.TestCase):
    """whoBIRD run6 was refused as STORED_DERIVED_VALUE_CHANGED although every
    MD5 constant was replaced by the SHA-256 of the same file."""

    error = {"derived_value_consumers": {"fixed": True, "consumers": [{"kind": "fixed_value"}]},
             "case_migration_policy": {"replacement_values": [
                 {"constant": "metaMD5", "old_value": "c12c2baafe4d1bb098e65291bfcb2f8c",
                  "new_value": "2" * 64}]}}
    original = ('static final String metaMD5 = "c12c2baafe4d1bb098e65291bfcb2f8c";\n'
                'byte[] h = MessageDigest.getInstance("MD5").digest(d);')

    def edits(self, corrected):
        return [{"source_file_path": "app/src/main/java/o/Downloader.java",
                 "edit_kind": "declaration", "original_code": self.original,
                 "corrected_code": corrected}]

    def test_a_replaced_fixed_value_is_not_a_broken_contract(self):
        from cognalys.llm.contract_gates import changed_stored_derivations

        replaced = ('static final String metaSHA256 = "' + "2" * 64 + '";\n'
                    'byte[] h = MessageDigest.getInstance("SHA-256").digest(d);')
        self.assertEqual(changed_stored_derivations(self.error, self.edits(replaced)), [])
        # Algorithm changed, constant left alone: still refused.
        algorithm_only = self.original.replace('"MD5"', '"SHA-256"')
        self.assertTrue(changed_stored_derivations(self.error, self.edits(algorithm_only)))
        # A stored value is never covered.
        stored = {**self.error, "derived_value_consumers": {"persisted": True, "consumers": []}}
        self.assertTrue(changed_stored_derivations(stored, self.edits(replaced)))


if __name__ == "__main__":
    unittest.main()
