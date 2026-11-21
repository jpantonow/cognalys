import json
import unittest


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm import false_positive_rules as fp  # noqa: E402
from _reviewed_shapes import reviewed_false_positive_shapes, stamped  # noqa: E402
from cognalys.specifications.generate_specifications import carry_curated_fields  # noqa: E402


SHAPE = 'SSLContext.getInstance("TLS") followed by downstream configuration.'


class FalsePositiveTriggersFromDataTests(unittest.TestCase):
    """The 2026-10-17 audit moved these out of code keyed by specification name."""

    def specification(self, shapes, reviewed=True):
        specification = {"known_false_positive_shapes": shapes,
                         "false_positive_triggers": [{"shape_contains": 'getInstance("TLS") followed',
                                                      "detector_message": "found TLS.",
                                                      "external_class_only": True}]}
        return stamped(specification) if reviewed else specification

    def test_a_trigger_resolves_to_the_shape_the_specification_documents(self):
        [trigger] = fp.false_positive_triggers("Any", self.specification([SHAPE]))
        self.assertEqual(trigger["shape"], SHAPE)
        self.assertEqual(trigger["detector_message"], "found TLS.")

    def test_a_shape_the_specification_no_longer_documents_is_not_claimed(self):
        self.assertEqual(fp.false_positive_triggers(
            "Any", self.specification(["A different, rewritten shape."])), [])

    def test_an_unreviewed_shape_resolves_no_trigger(self):
        # P14: an unreviewed shape may describe code that breaks the rule as
        # written, so it dismisses nothing on the deterministic routes either.
        self.assertEqual(fp.false_positive_triggers(
            "Any", self.specification([SHAPE], reviewed=False)), [])

    def test_a_shipped_unreviewed_specification_dismisses_nothing(self):
        # Measured 2026-10-29: no stored specification carries the
        # shape-review stamp, so SSLContextSpec's message trigger is inert.
        if fp.false_positive_triggers("SSLContextSpec"):
            self.skipTest("SSLContextSpec's shapes have been reviewed")
        self.assertNotIn("SSLContextSpec", fp.KNOWN_FALSE_POSITIVE_MESSAGES)
        self.assertEqual(fp.confirmed_false_positive_reason(
            "SSLContextSpec", "expecting one of {TLSv1.2, TLSv1.3} but found TLS.",
            True, ""), "")

    def test_the_shipped_tables_come_from_the_specifications(self):
        with reviewed_false_positive_shapes():
            self.assertIn("SSLContextSpec", fp.KNOWN_FALSE_POSITIVE_MESSAGES)
            self.assertIn("known_false_positive_shapes",
                          next(iter(fp.KNOWN_FALSE_POSITIVE_MESSAGES["SSLContextSpec"].values()))
                          ["rationale"])
            self.assertEqual(fp.UNMODELLED_CALL_SHAPES["KeyStoreSpec"]["methods"],
                             ("setCertificateEntry", "setKeyEntry"))

    def test_regeneration_keeps_curated_fields(self):
        previous = json.dumps({"false_positive_triggers": [{"shape_contains": "x"}], "old": 1})
        regenerated = carry_curated_fields({"known_false_positive_shapes": ["x y"]}, previous)
        self.assertEqual(regenerated["false_positive_triggers"], [{"shape_contains": "x"}])
        self.assertNotIn("old", regenerated)


if __name__ == "__main__":
    unittest.main()
