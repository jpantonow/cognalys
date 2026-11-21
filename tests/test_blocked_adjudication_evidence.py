"""An adjudication blocked on missing evidence fetches what its blockers name.

exp_final_20261019: 21 adjudications blocked generation for an unconfirmed
cause, missing code evidence or an unresolved target, and only 6 had had an
evidence round; the blockers named what was missing and nothing fetched it.
"""
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.finding_context import FindingContextCollection  # noqa: E402


def _collector():
    return object.__new__(FindingContextCollection)


class BlockedAdjudicationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "Store.java").write_text(
            "class Store {\n  String key() { return Helper.getFingerprint(c, \"SHA-1\"); }\n}\n",
            encoding="utf-8")
        (self.root / "Helper.java").write_text(
            "class Helper {\n  static String getFingerprint(Context c, String h) { return h; }\n}\n",
            encoding="utf-8")
        self.prefix = self.root / "out" / "0_m"
        self.prefix.parent.mkdir()

    def _adjudication(self, category):
        return {"decision": "NO_SAFE_FIX", "generation_status": "blocked",
                "blocking_for_generation": [{
                    "kind": "consumer_inventory", "category": category,
                    "description": "Helper.getFingerprint(Context, String) consumers are unknown"}]}

    def test_an_evidence_blocker_becomes_a_request_and_is_answered(self):
        supplied = {"evidence_catalog": [{"data": {"source_file_path": "Helper.java"}}]}
        supplement = _collector()._evidence_for_blocked_adjudication(
            {"repository_path": str(self.root)}, supplied,
            self._adjudication("code_evidence_missing"), self.prefix)
        self.assertEqual(len(supplement), 1)
        self.assertEqual(supplement[0]["evidence_id"], "ADJ-001")
        self.assertIn("Store.java:2:", supplement[0]["data"]["content"])
        self.assertTrue((self.prefix.parent / "0_m_adjudication_supplement.json").is_file())

    def test_a_blocker_that_is_not_about_evidence_fetches_nothing(self):
        supplement = _collector()._evidence_for_blocked_adjudication(
            {"repository_path": str(self.root)}, {"evidence_catalog": []},
            self._adjudication("compatibility_contract"), self.prefix)
        self.assertEqual(supplement, [])


class BlockerIdentifierTests(unittest.TestCase):
    """A blocker's prose yields code identifiers, not capitalised English (B11).

    k3v10's adjudication blocker "The packet does not include the hash
    implementation..." became a request for the symbol "The".
    """

    def test_a_sentence_initial_word_is_not_a_symbol(self):
        from cognalys.llm.finding_context import blocker_identifiers

        text = ("code_evidence_missing The packet does not include the hash "
                "implementation of WidgetCodec, nor how Snapshot.encode( is called.")
        self.assertEqual(blocker_identifiers(text), "WidgetCodec Snapshot.encode(")

    def test_code_shapes_and_declared_names_are_kept(self):
        from cognalys.llm.finding_context import blocker_identifiers

        text = "Replacing MD5 needs SHA256, MAX_SIZE, Cipher( and Store, then cipher.init."
        self.assertEqual(blocker_identifiers(text), "MD5 SHA256 MAX_SIZE Cipher( cipher.init")
        self.assertEqual(blocker_identifiers(text, declared={"Store"}.__contains__),
                         "MD5 SHA256 MAX_SIZE Cipher( Store cipher.init")

    def test_a_blocker_naming_only_prose_asks_for_nothing(self):
        supplement = _collector()._evidence_for_blocked_adjudication(
            {"repository_path": tempfile.gettempdir() + "/no-such-checkout"},
            {"evidence_catalog": []},
            {"blocking_for_generation": [{
                "kind": "code_evidence_missing", "category": "code_evidence_missing",
                "description": "The packet does not show it."}]},
            Path(tempfile.gettempdir()) / "no-such-out" / "0_m")
        self.assertEqual(supplement, [])


class UnreviewedShapeTests(unittest.TestCase):
    """Only shapes the shape review kept may argue for a dismissal.

    Aegis's SSLConnector.buildSocket (rvsec_aegis_20261022/run_v2) was
    answered detector_violation not_confirmed on SSLContextSpec's
    init(null, ...) shape, which says such code cannot satisfy the rule's
    provenance predicates: none of the stored specifications had been
    through place_false_positive_shapes.
    """

    SPEC = {
        "spec_id": "SSLContextSpec",
        "source_verified": True,
        "source_url": "https://example.invalid/SSLContext.crysl",
        "known_false_positive_shapes": [
            "ctx.init(null, null, null) relies on provider defaults.",
        ],
    }

    def test_an_unstamped_specification_sends_unreviewed_shapes(self):
        from cognalys.llm.research_questions import verified_detector_semantics

        semantics = verified_detector_semantics(self.SPEC)
        self.assertEqual(semantics["unreviewed_false_positive_shapes"],
                         self.SPEC["known_false_positive_shapes"])
        self.assertNotIn("known_false_positive_shapes", semantics)

    def test_a_stamped_specification_sends_known_shapes(self):
        from cognalys.llm.research_questions import verified_detector_semantics

        spec = dict(self.SPEC, generation_evidence={
            "false_positive_shape_review": {"version": 1, "moved": []}})
        semantics = verified_detector_semantics(spec)
        self.assertEqual(semantics["known_false_positive_shapes"],
                         self.SPEC["known_false_positive_shapes"])
        self.assertNotIn("unreviewed_false_positive_shapes", semantics)

    def test_a_malformed_stamp_is_not_a_review(self):
        from cognalys.llm.pipeline_common import false_positive_shapes_reviewed

        for evidence in (None, {}, {"false_positive_shape_review": True},
                         {"false_positive_shape_review": {"version": "x"}},
                         {"false_positive_shape_review": {"moved": []}}):
            self.assertFalse(false_positive_shapes_reviewed(
                dict(self.SPEC, generation_evidence=evidence)), evidence)


if __name__ == "__main__":
    unittest.main()
