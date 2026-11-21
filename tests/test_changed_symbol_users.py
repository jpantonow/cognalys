import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils.changed_symbol_users import (  # noqa: E402
    changed_symbol_users, discharge_sites_gaps, sites_gap)

# primftpd run_v2 (2026-11-03), after the patch: SshBuilder no longer lists
# the ARCFOUR factories, and BaseRC4Cipher.init throws.
BUILDER = """package s;
public class SshBuilder {
    void build() { factories = setUpDefaultCiphers(); }
    protected static List<NamedFactory<Cipher>> setUpDefaultCiphers() {
        avail.add(new AES128CTR.Factory());
        return avail;
    }
}
"""
BASE = """package s;
public class BaseRC4Cipher extends BaseCipher {
    public BaseRC4Cipher(int ivsize, int bsize) { super(ivsize, bsize); }
    @Override
    public void init(Mode mode, byte[] key, byte[] iv) throws Exception {
        throw new UnsupportedOperationException("RC4 is no longer supported");
    }
}
"""
ARCFOUR = """package s;
public class ARCFOUR128 extends BaseRC4Cipher {
    public ARCFOUR128() { super(8, 16); }
}
"""
SESSION = """package s;
class AbstractSession {
    void kex() { cipher.init(Mode.Decrypt, key, iv); }
}
"""
EDITS = [
    {"source_file": "s/BaseRC4Cipher.java", "edit_kind": "delete", "symbol": "SecretKeySpec",
     "original_code": "import javax.crypto.spec.SecretKeySpec;", "corrected_code": ""},
    {"source_file": "s/BaseRC4Cipher.java", "edit_kind": "method", "symbol": "init",
     "original_code": "    public void init(Mode mode, byte[] key, byte[] iv) {"},
    {"source_file": "s/SshBuilder.java", "edit_kind": "method", "symbol": "setUpDefaultCiphers",
     "original_code": "    protected static List<NamedFactory<Cipher>> setUpDefaultCiphers() {"},
]
CHANGED = ["s/BaseRC4Cipher.java", "s/SshBuilder.java"]
GAP = {"category": "code_evidence_missing", "kind": "missing_negotiation_source",
       "description": "The packet does not establish the registration or negotiation sites "
                      "that would need to change to retire RC4, and caller resolution is partial."}


def _repository(directory: str, extra: dict | None = None) -> Path:
    root = Path(directory)
    files = {"s/SshBuilder.java": BUILDER, "s/BaseRC4Cipher.java": BASE,
             "s/ARCFOUR128.java": ARCFOUR, "s/AbstractSession.java": SESSION, **(extra or {})}
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text, encoding="utf-8")
    return root


class ChangedSymbolUsersTests(unittest.TestCase):
    def test_every_user_inside_the_patch_or_an_unused_subclass_is_accounted(self):
        with tempfile.TemporaryDirectory() as directory:
            result = changed_symbol_users(_repository(directory), EDITS, CHANGED)
        self.assertEqual(result["status"], "accounted", result)
        self.assertTrue(any("setUpDefaultCiphers: s/SshBuilder.java" in item
                            for item in result["sites"]))
        self.assertTrue(any("in ARCFOUR128, which nothing else uses" in item
                            for item in result["sites"]))

    def test_a_user_outside_the_patch_is_unexplained(self):
        extra = {"s/Config.java": "class Config { Object c = new ARCFOUR128(); }\n"}
        with tempfile.TemporaryDirectory() as directory:
            result = changed_symbol_users(_repository(directory, extra), EDITS, CHANGED)
        self.assertEqual(result["status"], "unexplained")
        self.assertTrue(any(item.startswith("ARCFOUR128: s/Config.java")
                            for item in result["unexplained"]))

    def test_a_name_in_a_string_or_an_edit_it_does_not_follow_resolves_nothing(self):
        extra = {"s/Loader.java": 'class Loader { Object c = Class.forName("s.ARCFOUR128"); }\n'}
        with tempfile.TemporaryDirectory() as directory:
            self.assertNotEqual(changed_symbol_users(
                _repository(directory, extra), EDITS, CHANGED)["status"], "accounted")
            declaration = [{"source_file": "s/SshBuilder.java", "edit_kind": "declaration",
                            "symbol": "FIELD", "original_code": "int a;"}]
            self.assertEqual(changed_symbol_users(
                _repository(directory), declaration, CHANGED)["status"], "unresolved")

    def test_only_gaps_about_sites_are_candidates(self):
        self.assertTrue(sites_gap(GAP["description"]))
        self.assertFalse(sites_gap("The packet does not show the key's provenance."))


class DischargeTests(unittest.TestCase):
    def test_the_gap_moves_to_discharged_with_the_sites(self):
        notes = {"publication_blocker_record": {"blockers": [
            GAP, {"category": "compatibility_contract", "description": "legacy peers"}]}}
        solution = {"coordinated_edits": EDITS, "changed_files": CHANGED}
        with tempfile.TemporaryDirectory() as directory:
            settled = discharge_sites_gaps(notes, _repository(directory), solution)
        record = settled["publication_blocker_record"]
        self.assertEqual([item["category"] for item in record["blockers"]],
                         ["compatibility_contract"])
        self.assertEqual(record["discharged_blockers"][0]["kind"], "missing_negotiation_source")
        self.assertTrue(record["discharged_blockers"][0]["sites"])
        # The input is not changed.
        self.assertEqual(len(notes["publication_blocker_record"]["blockers"]), 2)

    def test_the_gap_stays_when_the_search_finds_another_user(self):
        notes = {"publication_blocker_record": {"blockers": [GAP]}}
        extra = {"s/Config.java": "class Config { Object c = new ARCFOUR128(); }\n"}
        solution = {"coordinated_edits": EDITS, "changed_files": CHANGED}
        with tempfile.TemporaryDirectory() as directory:
            kept = discharge_sites_gaps(notes, _repository(directory, extra), solution)
        self.assertEqual(kept["publication_blocker_record"]["blockers"], [GAP])
        self.assertEqual(kept["changed_symbol_users"]["status"], "unexplained")


if __name__ == "__main__":
    unittest.main()
