import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils.disposition import (  # noqa: E402
    PUBLICATION_BLOCKED,
    REVIEW_ONLY_DECISIONS,
    FindingDisposition,
)


class AppliableVersusPublishableTests(unittest.TestCase):
    """The asymmetry that used to live in an omitted clause.

    solution_applicator left publication_allowed out of its review_only
    expression on purpose: a blocked publication must still be applied and
    built, because the block is on handing the patch to a maintainer and
    validation cannot run against a patch that was never applied. Nothing said
    so. Setting manual_review_required for a publication-blocked finding
    therefore looked correct and silently stopped application --
    run_20260908_154553 generated a 90%-confidence Zip Slip fix and discarded
    it before any build.
    """

    def test_a_blocked_publication_is_still_appliable(self):
        disposition = FindingDisposition(
            decision="FIX_SUPPORTED", publication_status=PUBLICATION_BLOCKED
        )
        self.assertTrue(disposition.appliable)
        self.assertFalse(disposition.publishable)
        self.assertFalse(disposition.needs_human_review)

    def test_an_unblocked_supported_decision_is_publishable(self):
        disposition = FindingDisposition(
            decision="FIX_SUPPORTED",
            publication_status="eligible_after_validation",
        )
        self.assertTrue(disposition.appliable)
        self.assertTrue(disposition.publishable)

    def test_a_review_only_decision_is_neither(self):
        for decision in sorted(REVIEW_ONLY_DECISIONS):
            with self.subTest(decision=decision):
                disposition = FindingDisposition(decision=decision)
                self.assertTrue(disposition.needs_human_review)
                self.assertFalse(disposition.appliable)
                self.assertFalse(disposition.publishable)

    def test_an_unknown_publication_status_does_not_block(self):
        """Only the adjudication's own "blocked" verdict blocks."""
        disposition = FindingDisposition(
            decision="FIX_SUPPORTED", publication_status=""
        )
        self.assertTrue(disposition.publishable)


class MetadataRoundTripTests(unittest.TestCase):
    """One producer, one interpretation.

    The three flags were built in two places 200 lines apart and read with
    four different boolean expressions across four modules. A fix to the
    publication gate landed in one producer and missed the other; only a test
    caught it.
    """

    def test_the_flags_a_producer_writes_rebuild_the_same_disposition(self):
        for decision, status in (
            ("FIX_SUPPORTED", PUBLICATION_BLOCKED),
            ("FIX_SUPPORTED", "eligible_after_validation"),
            ("MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", PUBLICATION_BLOCKED),
            ("NO_SAFE_FIX", ""),
        ):
            with self.subTest(decision=decision, status=status):
                original = FindingDisposition(decision, status)
                rebuilt = FindingDisposition.from_metadata(
                    original.as_metadata()
                )
                self.assertEqual(rebuilt.appliable, original.appliable)
                self.assertEqual(rebuilt.publishable, original.publishable)

    def test_a_blocked_publication_writes_the_flags_the_pipeline_reads(self):
        metadata = FindingDisposition(
            "FIX_SUPPORTED", PUBLICATION_BLOCKED
        ).as_metadata()
        self.assertIs(metadata["auto_apply"], True)
        self.assertIs(metadata["publication_allowed"], False)
        self.assertIs(metadata["manual_review_required"], False)

    def test_a_record_predating_publication_status_still_reads_as_blocked(self):
        """publication_allowed=False recorded the same fact before the field."""
        rebuilt = FindingDisposition.from_metadata({
            "decision": "FIX_SUPPORTED", "publication_allowed": False,
        })
        self.assertFalse(rebuilt.publishable)
        self.assertTrue(rebuilt.appliable)

    def test_an_empty_record_is_permissive(self):
        """Matches how such records were treated when they were written."""
        rebuilt = FindingDisposition.from_metadata({})
        self.assertTrue(rebuilt.appliable)
        self.assertTrue(rebuilt.publishable)


def validated_draft(*blockers, **extra) -> dict:
    """A review-only draft after a passing build and a current, clean review.

    Orgzly's sha1 shape (2026-10-29): MULTI_FILE_FIX_PROPOSED_FOR_REVIEW with
    a maintainer-decision blocker, built, committed and reviewed.
    """
    from cognalys.llm.coordinated_generation import REVIEW_CONTRACT_VERSION

    record = {
        "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "publication_status": "blocked",
        "build_validation": {"status": "success", "phases": {
            "production": {"status": "success"}, "patched_tests": {"status": "success"}}},
        "commit_hash": "abc123", "changed_files": ["app/src/main/java/x/MiscUtils.java"],
        "text_problems": [], "uncommitted_patch_files": [],
        "review_contract_version": REVIEW_CONTRACT_VERSION, "behavior_review_recorded": True,
        "fix_scope": "review_only",
        "semantic_validation": {"status": "valid", "errors": [], "warnings": []},
        "coordinated_edits": [{"source_file": "app/src/main/java/x/MiscUtils.java",
                               "original_code": 'MessageDigest.getInstance("SHA-1")',
                               "corrected_code": 'MessageDigest.getInstance("SHA-256")'}],
        "publication_blocker_record": {
            "blockers": [{"category": category, "kind": category,
                          "description": f"{category} question",
                          "discharged_by_pipeline_validation": False}
                         for category in blockers],
            "discharged_blockers": [], "plan_publication_blockers": [],
            "behavior_review": {"status": "reviewed",
                                "review_contract_version": REVIEW_CONTRACT_VERSION,
                                "regression_count": 0, "patch_has_no_effect": False},
        },
    }
    record.update(extra)
    return record


class PublicationAfterValidationTests(unittest.TestCase):
    """The verdict once the patch is built and reviewed (P7, conservative)."""

    def verdict(self, record):
        from cognalys.utils.disposition import publication_after_validation
        return publication_after_validation(record)

    def test_human_decided_notes_with_a_clean_review_are_publishable_with_notes(self):
        result = self.verdict(validated_draft(
            "maintainer_decision", "runtime_behavior", "analyzer_reconfirmation",
            "rename_authorization"))
        self.assertTrue(result["publishable"], result["blocks"])
        self.assertEqual(result["blocks"], [])
        self.assertEqual(len(result["notes"]), 4)

    def test_an_evidence_gap_blocks(self):
        result = self.verdict(validated_draft("maintainer_decision", "code_evidence_missing"))
        self.assertFalse(result["publishable"])
        self.assertTrue(any(item.startswith("code_evidence_missing") for item in result["blocks"]))

    def test_a_build_that_did_not_pass_or_no_commit_or_an_uncompiled_change_blocks(self):
        for status in ("failed", "not_run", "timeout"):
            self.assertFalse(self.verdict(validated_draft(
                build_validation={"status": status}))["publishable"])
        self.assertFalse(self.verdict(validated_draft(commit_hash=""))["publishable"])
        jvm_only = self.verdict(validated_draft(
            changed_files=["shared/src/jvmMain/kotlin/x/Crypto.kt"]))
        self.assertTrue(any("compiles none" in item for item in jvm_only["blocks"]))

    def test_text_problems_or_uncommitted_files_block(self):
        self.assertFalse(self.verdict(validated_draft(
            text_problems=["pipeline vocabulary: governed"]))["publishable"])
        self.assertFalse(self.verdict(validated_draft(
            uncommitted_patch_files=["app/src/main/java/x/MiscUtils.java"]))["publishable"])

    def test_a_stale_absent_regressing_or_no_effect_review_blocks(self):
        self.assertFalse(self.verdict(validated_draft(review_contract_version=1))["publishable"])
        absent = validated_draft(review_contract_version=None)
        absent["publication_blocker_record"]["behavior_review"]["review_contract_version"] = None
        self.assertFalse(self.verdict(absent)["publishable"])
        regressed = validated_draft()
        regressed["publication_blocker_record"]["behavior_review"]["regression_count"] = 1
        self.assertFalse(self.verdict(regressed)["publishable"])
        no_effect = validated_draft()
        no_effect["publication_blocker_record"]["behavior_review"]["patch_has_no_effect"] = True
        self.assertFalse(self.verdict(no_effect)["publishable"])

    def test_a_test_coverage_warning_is_a_note_and_a_misplaced_test_blocks(self):
        coverage = self.verdict(validated_draft(semantic_validation={
            "status": "valid", "errors": [],
            "warnings": [{"code": "TLS_PROTOCOL_FILTER_CONTRACT_NOT_TESTED"}]}))
        self.assertTrue(coverage["publishable"])
        self.assertIn("test coverage: TLS_PROTOCOL_FILTER_CONTRACT_NOT_TESTED", coverage["notes"])
        for code in ("TEST_PLACED_IN_UNRELATED_FILE", "TEST_IN_OTHER_MODULE"):
            self.assertFalse(self.verdict(validated_draft(semantic_validation={
                "status": "valid", "errors": [], "warnings": [{"code": code}]}))["publishable"])

    def test_blockers_only_about_a_finding_without_effect_do_not_hold_the_pull_request(self):
        """LocalSend run_v5 (2026-10-31): attributed to KeyStoreSpec, held by the
        KeyPairSpec plan's cause_unconfirmed."""
        from cognalys.utils.disposition import without_blockers_of_findings_without_effect

        draft = validated_draft()
        draft["publication_blocker_record"]["blockers"] = [
            {"category": "cause_unconfirmed", "kind": "The reported KeyPairSpec order condition "
             "cannot be attributed.", "description": "A patch would be speculative.",
             "discharged_by_pipeline_validation": False},
            {"category": "compatibility_contract", "kind": "Any KeyStoreSpec-conforming "
             "replacement must keep PKCS12 retrieval.", "description": "Keep the contract.",
             "discharged_by_pipeline_validation": False},
            {"category": "code_evidence_missing", "kind": "The producer is unknown.",
             "description": "No spec named.", "discharged_by_pipeline_validation": False}]
        draft["publication_blocker_record"]["plan_publication_blockers"] = [
            "Obtain the resolved trace for the KeyPairSpec report.",
            "Confirm the KeyStoreSpec sequence and whether the KeyPairSpec observation remains."]
        notes = {key: draft.pop(key) for key in ("publication_blocker_record",)}
        notes["publication_blockers"] = list(
            notes["publication_blocker_record"]["plan_publication_blockers"])
        filtered, dropped = without_blockers_of_findings_without_effect(
            notes, ["KeyPairSpec"], ["KeyStoreSpec"])
        categories = [item["category"] for item in
                      filtered["publication_blocker_record"]["blockers"]]
        self.assertEqual(categories, ["compatibility_contract", "code_evidence_missing"])
        self.assertEqual(filtered["publication_blockers"], [
            "Confirm the KeyStoreSpec sequence and whether the KeyPairSpec observation remains."])
        self.assertEqual(len(dropped), 2)
        result = self.verdict({**draft, **filtered})
        self.assertFalse(any(item.startswith("cause_unconfirmed") for item in result["blocks"]))
        self.assertTrue(any(item.startswith("compatibility_contract") for item in result["blocks"]))
        # A spec both sides share, or no finding without effect, drops nothing.
        self.assertEqual(without_blockers_of_findings_without_effect(
            notes, ["KeyStoreSpec"], ["KeyStoreSpec"])[1], [])
        self.assertEqual(without_blockers_of_findings_without_effect(notes, [], ["X"])[1], [])

    def test_a_compatibility_contract_blocks(self):
        """SMSecure's <init> stays review-only: the review cannot see data older versions wrote."""
        self.assertFalse(self.verdict(validated_draft("compatibility_contract"))["publishable"])

    def test_an_uncategorised_blocker_blocks(self):
        self.assertFalse(self.verdict(validated_draft("other"))["publishable"])
        self.assertFalse(self.verdict(validated_draft(""))["publishable"])

    def test_a_build_checklist_line_the_build_discharged_is_dropped(self):
        record = validated_draft("maintainer_decision")
        record["publication_blocker_record"]["plan_publication_blockers"] = [
            "Before publication, build the affected module and run its unit tests.",
            "Confirm on a device that existing notes still open.",
        ]
        result = self.verdict(record)
        self.assertTrue(result["publishable"])
        self.assertEqual(result["dropped_plan_blockers"],
                         ["Before publication, build the affected module and run its unit tests."])
        self.assertIn("Confirm on a device that existing notes still open.", result["notes"])

    def test_runtime_behaviour_notes_go_when_no_new_value_literal_is_introduced(self):
        removal = validated_draft("runtime_behavior", coordinated_edits=[{
            "source_file": "x/Client.kt",
            "original_code": 'ctx.init(null, tms, null)\nparams.protocols = arrayOf("SSLv3")',
            "corrected_code": "ctx.init(null, tms, null)"}])
        self.assertEqual(self.verdict(removal)["notes"], [])
        self.assertTrue(self.verdict(validated_draft("runtime_behavior"))["notes"])

    def test_non_generating_and_own_gate_decisions_block(self):
        self.assertFalse(self.verdict(validated_draft(decision="NO_SAFE_FIX"))["publishable"])
        self.assertFalse(self.verdict(validated_draft(
            decision="BACKEND_MIGRATION_REQUIRED_REVIEW_ONLY"))["publishable"])
        self.assertFalse(self.verdict(validated_draft(
            decision="DEPENDENCY_FIX_SUPPORTED"))["publishable"])

    def test_the_record_keeps_every_publication_blocker_with_its_category(self):
        from cognalys.llm.adjudication_rules import publication_blocker_record

        analysis = {"v2": {
            "adjudication": {
                "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                "blocking_for_publication": [
                    {"category": "maintainer_decision", "kind": "k", "description": "d1",
                     "discharged_by_pipeline_validation": False},
                    {"category": "maintainer_decision", "kind": "k", "description": "d1"},
                    {"category": "other", "kind": "build", "description": "d2",
                     "discharged_by_pipeline_validation": True}],
                "discharged_blockers": [{"category": "code_evidence_missing", "description": "d3",
                                         "discharged_by_producer_finding": True}],
                "evidence_gap_promoted": []},
            "patch_plan": {"publication_blockers": ["Build the module."]}}}
        record = publication_blocker_record(
            analysis, {"status": "reviewed", "review_contract_version": 4,
                       "regression_count": 0, "patch_has_no_effect": False})
        self.assertEqual([(item["category"], item["discharged_by_pipeline_validation"])
                          for item in record["blockers"]],
                         [("maintainer_decision", False), ("other", True)])
        self.assertEqual(record["discharged_blockers"][0]["discharged_by"],
                         "discharged_by_producer_finding")
        self.assertEqual(record["plan_publication_blockers"], ["Build the module."])
        self.assertEqual(record["behavior_review"]["review_contract_version"], 4)
        self.assertEqual(publication_blocker_record({})["behavior_review"]["status"], "not_reviewed")

    def test_analyzer_and_rename_questions_have_categories_that_never_block_generation(self):
        from cognalys.llm.llm_contracts import BLOCKER_CATEGORIES, HUMAN_DECIDED_BLOCKER_CATEGORIES
        from cognalys.llm.pipeline_architecture import promote_human_decided_blockers_to_review

        for category in ("analyzer_reconfirmation", "rename_authorization"):
            self.assertIn(category, BLOCKER_CATEGORIES)
            self.assertIn(category, HUMAN_DECIDED_BLOCKER_CATEGORIES)
        adjudication = {
            "decision": "NO_SAFE_FIX", "generation_status": "blocked",
            "publication_status": "blocked", "cause_status": "confirmed",
            "confirmed_cause": "SSL reaches SSLContext.getInstance",
            "detector_violation": "confirmed", "scope_status": "complete",
            "decision_claim_ids": ["C-001"], "blocking_for_publication": [],
            "blocking_for_generation": [{
                "kind": "analyzer", "category": "analyzer_reconfirmation",
                "description": "whether the analyzer accepts TLS", "supporting_claim_ids": []}],
        }
        moved = promote_human_decided_blockers_to_review(
            adjudication, {"claims": [{"claim_id": "C-001"}]},
            {"error_message": "expecting one of TLSV1.2,TLSV1.3,TLS but found SSL"})
        self.assertEqual(moved, ["analyzer_reconfirmation"])
        self.assertEqual(adjudication["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")

    def test_the_decision_label_follows_the_final_diff(self):
        from cognalys.utils.disposition import decision_label

        self.assertEqual(decision_label("MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                                        ["a/src/main/X.kt", "a/src/test/XTest.kt"]),
                         "SINGLE_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(decision_label("MULTI_FILE_FIX_SUPPORTED", ["a/X.kt", "b/Y.kt"]),
                         "MULTI_FILE_FIX_SUPPORTED")
        self.assertEqual(decision_label("FIX_SUPPORTED", ["a/X.kt", "b/Y.kt"]),
                         "MULTI_FILE_FIX_SUPPORTED")


if __name__ == "__main__":
    unittest.main()
