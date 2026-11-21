"""A review-only patch inherits the adjudication's assumptions when the generator omits them."""
import unittest

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.finding_processing import adjudicated_review_assumptions  # noqa: E402


class InheritedReviewAssumptionsTests(unittest.TestCase):
    def test_the_v2_adjudication_assumptions_are_used(self):
        analysis = {"v2": {"adjudication": {"review_assumptions": [
            "The seed material is a literal.", "  "]}}}
        self.assertEqual(adjudicated_review_assumptions(analysis),
                         ["The seed material is a literal."])

    def test_the_analysis_assumptions_are_the_fallback(self):
        analysis = {"review_assumptions": ["Callers were not all reviewed."]}
        self.assertEqual(adjudicated_review_assumptions(analysis),
                         ["Callers were not all reviewed."])

    def test_nothing_is_invented_when_the_adjudication_recorded_none(self):
        self.assertEqual(adjudicated_review_assumptions({"v2": {"adjudication": {}}}), [])
        self.assertEqual(adjudicated_review_assumptions(None), [])


if __name__ == "__main__":
    unittest.main()
