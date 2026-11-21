"""A defect a published advisory confirms is proposed for review, not dropped.

run_20260927_175748 analysed four advisory findings at their vulnerable
revisions and abstained on three, each blocked only on "the cause is not
established from the source" plus questions a reviewer settles. These tests
pin the promotion and, as hard, every case where it must not happen.
"""
import sys
import unittest
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.pipeline_architecture import (  # noqa: E402
    independent_finding_authority,
    promote_authority_confirmed_cause_to_review,
)


FINDING = {
    "error_message": "External finding (GHSL-2022-046): saveResult returns "
                     "the incoming Intent through setResult.",
    "target": {"class": "org.wordpress.android.ui.posts.EditPostActivity",
               "method": "saveResult"},
    "reported_violation": "UnsafeIntentReflection",
}
EXTRACTION = {"claims": [{"claim_id": "CLM-001"}, {"claim_id": "CLM-003"}]}
AUTHORITY = {"kind": "published_advisory", "identifiers": ["GHSL-2022-046"],
             "revision": "f7a357fd9e56591a87e2e6ffba392414cccc783e"}


def adjudication(*categories, cause="inferred"):
    return {
        "cause_status": cause,
        "confirmed_cause": "No confirmed source-level cause exists in this packet.",
        "detector_violation": "unknown",
        "compatibility_status": "unknown",
        "scope_status": "incomplete",
        "decision": "NO_SAFE_FIX",
        "decision_claim_ids": ["CLM-001", "CLM-003"],
        "generation_status": "blocked",
        "publication_status": "blocked",
        "blocking_for_generation": [
            {"kind": f"blocker {category}", "category": category,
             "description": "", "supporting_claim_ids": []}
            for category in categories
        ],
        "blocking_for_publication": [],
        "review_assumptions": [],
    }


class AuthorityTests(unittest.TestCase):
    def test_an_advisory_at_its_revision_is_an_authority(self):
        self.assertEqual(
            independent_finding_authority({
                "error_message": FINDING["error_message"],
                "pinned_revision": AUTHORITY["revision"],
            }),
            AUTHORITY,
        )

    def test_an_advisory_at_the_current_branch_is_not(self):
        self.assertEqual(
            independent_finding_authority({
                "error_message": FINDING["error_message"], "pinned_revision": "",
            }),
            {},
        )


class PromotionTests(unittest.TestCase):
    def test_an_unconfirmed_cause_with_reviewer_questions_is_proposed(self):
        record = adjudication("cause_unconfirmed", "compatibility_contract")
        settled = promote_authority_confirmed_cause_to_review(
            record, EXTRACTION, FINDING, AUTHORITY)
        self.assertEqual(settled, ["cause_unconfirmed", "compatibility_contract"])
        self.assertEqual(record["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(record["generation_status"], "supported_for_review")
        self.assertEqual(record["publication_status"], "blocked")
        self.assertEqual(record["blocking_for_generation"], [])
        self.assertEqual(len(record["blocking_for_publication"]), 2)
        self.assertIn("GHSL-2022-046", record["confirmed_cause"])
        self.assertIn("EditPostActivity.saveResult", record["confirmed_cause"])
        self.assertIn("not on the source reading alone",
                      record["review_assumptions"][-1])

    def test_an_unknown_cause_is_proposed_too(self):
        record = adjudication("cause_unconfirmed", cause="unknown")
        self.assertTrue(promote_authority_confirmed_cause_to_review(
            record, EXTRACTION, FINDING, AUTHORITY))

    def test_without_authority_nothing_changes(self):
        record = adjudication("cause_unconfirmed")
        before = deepcopy(record)
        self.assertEqual(promote_authority_confirmed_cause_to_review(
            record, EXTRACTION, FINDING, {}), [])
        self.assertEqual(record, before)

    def test_missing_source_is_not_something_an_advisory_answers(self):
        record = adjudication("cause_unconfirmed", "code_evidence_missing")
        self.assertEqual(promote_authority_confirmed_cause_to_review(
            record, EXTRACTION, FINDING, AUTHORITY), [])
        self.assertEqual(record["decision"], "NO_SAFE_FIX")

    def test_a_blocker_without_a_category_is_not_promoted(self):
        record = adjudication("cause_unconfirmed")
        record["blocking_for_generation"].append({"kind": "deterministic_validation"})
        self.assertEqual(promote_authority_confirmed_cause_to_review(
            record, EXTRACTION, FINDING, AUTHORITY), [])

    def test_only_human_questions_are_left_to_the_other_promotion(self):
        # No cause_unconfirmed blocker: the adjudicator did not doubt the
        # cause, so the advisory settles nothing here.
        record = adjudication("maintainer_decision")
        self.assertEqual(promote_authority_confirmed_cause_to_review(
            record, EXTRACTION, FINDING, AUTHORITY), [])

    def test_the_flag_nothing_passed_is_gone(self):
        # B2: documented_false_positive was never passed in production; a
        # matched shape is answered not_confirmed and the dismissal rule
        # (dismissal_justification_issues) checks what it rests on.
        with self.assertRaises(TypeError):
            promote_authority_confirmed_cause_to_review(
                adjudication("cause_unconfirmed"), EXTRACTION, FINDING, AUTHORITY,
                documented_false_positive=True)

    def test_a_dependency_finding_is_not_promoted(self):
        record = adjudication("cause_unconfirmed")
        self.assertEqual(promote_authority_confirmed_cause_to_review(
            record, EXTRACTION, FINDING, AUTHORITY, family="dependency"), [])

    def test_an_answer_citing_no_claims_is_not_promoted(self):
        record = adjudication("cause_unconfirmed")
        record["decision_claim_ids"] = []
        self.assertEqual(promote_authority_confirmed_cause_to_review(
            record, EXTRACTION, FINDING, AUTHORITY), [])


if __name__ == "__main__":
    unittest.main()
