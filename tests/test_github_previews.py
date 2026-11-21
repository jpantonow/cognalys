import importlib.util
import sys
import unittest
import unittest.mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)
from _reviewed_shapes import reviewed_false_positive_shapes  # noqa: E402
MODULE_PATH = ROOT / "src" / "cognalys" / "prs" / "generate_github_previews.py"
SPEC = importlib.util.spec_from_file_location("generate_github_previews", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FindingReviewPreviewTests(unittest.TestCase):
    def test_analysis_preview_labels_confirmed_cause_without_confirmed_violation(self):
        preview = MODULE.analysis_preview({
            "status": "NO_SAFE_FIX",
            "analysis": {
                "decision": "NO_SAFE_FIX",
                "cause_status": "confirmed",
                "confirmed_cause": "HmacSHA1 reaches Mac.getInstance.",
                "detector_violation": "unknown",
                "runtime_security_impact": "unknown",
                "evidence_status": {
                    "scope_status": "incomplete",
                    "generation_status": "blocked",
                    "publication_status": "blocked",
                },
                "diagnostic_evidence": {
                    "evidence_id": "DET-001",
                    "informational_only": True,
                },
            },
        })

        self.assertIn(
            "**Review status:** `CONFIRMED_CAUSE_ONLY_NO_SAFE_FIX`", preview
        )
        self.assertNotIn(
            "**Review status:** `CONFIRMED_FINDING_NO_SAFE_FIX`", preview
        )
        self.assertIn("**Detector violation:** `unknown`", preview)
        self.assertIn("**Diagnostic evidence:** `DET-001`", preview)
        self.assertIn("**Diagnostic authority:** `informational_only`", preview)

    def test_analysis_preview_requires_confirmed_detector_violation_for_label(self):
        preview = MODULE.analysis_preview({
            "status": "NO_SAFE_FIX",
            "analysis": {
                "confirmed_cause": "source flow",
                "detector_violation": "confirmed",
            },
        })

        self.assertIn(
            "**Review status:** `CONFIRMED_FINDING_NO_SAFE_FIX`", preview
        )

    def test_analysis_preview_closes_curated_dependency_false_positive(self):
        with reviewed_false_positive_shapes():
            preview = MODULE.analysis_preview({
                "status": "UNCONFIRMED_FINDING",
                "spec": "SSLContextSpec",
                "error_message": "expecting one of {TLSv1.2, TLSv1.3} but found TLS.",
                "source_file": "",
                "analysis": {
                    "cause_status": "unknown",
                    "detector_violation": "unknown",
                    "dependency_fix_assessment": {"external_class_confirmed": True},
                },
            })

        self.assertIn("**Review status:** `CONFIRMED_FALSE_POSITIVE`", preview)
        self.assertIn("confirmed false positive, not", preview)
        self.assertIn("known_false_positive_shapes", preview)

    def test_analysis_preview_keeps_unconfirmed_when_app_source_exists(self):
        preview = MODULE.analysis_preview({
            "status": "UNCONFIRMED_FINDING",
            "spec": "SSLContextSpec",
            "error_message": "expecting one of {TLSv1.2, TLSv1.3} but found TLS.",
            "source_file": "app/src/Foo.java",
            "analysis": {
                "cause_status": "unknown",
                "detector_violation": "unknown",
                "dependency_fix_assessment": {"external_class_confirmed": True},
            },
        })

        self.assertIn("**Review status:** `UNCONFIRMED_FINDING`", preview)

    def test_review_only_preview_shows_exact_approval_flag_when_eligible(self):
        preview = MODULE.finding_review_preview({
            "finding_id": "d28032440293",
            "solution_revision": "revision-1",
            "preview_status": "REVIEW_ONLY_NOT_PUBLISHABLE",
            "manual_review_required": True,
            "auto_apply": False,
            "publication_allowed": False,
            "publishable": False,
            "build_validation": {"status": "success"},
            "commit_hash": "abc123",
        })

        self.assertIn("| Finding ID | `d28032440293` |", preview)
        self.assertIn("| Build validation | `success` |", preview)
        self.assertIn("--approve-reviewed-finding d28032440293", preview)
        self.assertIn("build success alone does not approve", preview)

    def test_review_only_preview_explains_approval_blockers(self):
        preview = MODULE.finding_review_preview({
            "finding_id": "finding-1",
            "manual_review_required": True,
            "auto_apply": False,
            "publication_allowed": False,
            "build_validation": {"status": "failed"},
            "commit_hash": "",
        })

        self.assertNotIn("--approve-reviewed-finding", preview)
        self.assertIn("build status is failed", preview)
        self.assertIn("commit hash is missing", preview)

    def test_app_module_only_success_still_offers_the_approval_flag(self):
        """The preview must not tell a reviewer approval is impossible.

        pr_creator accepts "success_app_module_only" for explicit approval, so
        a preview that lists it as an approval blocker sends the reviewer away
        from a command that would have worked.
        """
        preview = MODULE.finding_review_preview({
            "finding_id": "479800df7ec6",
            "manual_review_required": False,
            "auto_apply": True,
            "publication_allowed": False,
            "publishable": False,
            "build_validation": {"status": "success_app_module_only"},
            "commit_hash": "abc123",
        })

        self.assertIn("--approve-reviewed-finding 479800df7ec6", preview)
        self.assertNotIn("build status is success_app_module_only", preview)

    def test_publishable_preview_is_marked_ready(self):
        preview = MODULE.finding_review_preview({
            "finding_id": "finding-2",
            "manual_review_required": False,
            "auto_apply": True,
            "publication_allowed": True,
            "publishable": True,
            "build_validation": {"status": "success"},
            "commit_hash": "def456",
        })

        self.assertIn("marked ready for publication", preview)

    def test_a_draft_cleared_after_validation_is_recommended_with_its_notes(self):
        """P7: READY_FOR_PUBLICATION_WITH_NOTES, still behind the approval flag."""
        preview = MODULE.finding_review_preview({
            "finding_id": "83f22cfa5b18",
            "preview_status": "READY_FOR_PUBLICATION_WITH_NOTES",
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "publication_status": "blocked",
            "manual_review_required": True, "auto_apply": False,
            "publication_allowed": False, "publishable": True,
            "publication_promoted_after_validation": True,
            "publication_notes": ["maintainer_decision: keep the SHA-1 helper for old data?"],
            "build_validation": {"status": "success"},
            "commit_hash": "abc123",
        })
        self.assertIn("| Preview status | `READY_FOR_PUBLICATION_WITH_NOTES` |", preview)
        self.assertIn("recommended for publication", preview)
        self.assertIn("--approve-reviewed-finding 83f22cfa5b18", preview)
        self.assertIn("- maintainer_decision: keep the SHA-1 helper for old data?", preview)
        self.assertNotIn("marked ready for publication", preview)

    def test_a_review_only_draft_says_what_keeps_it_back(self):
        preview = MODULE.finding_review_preview({
            "finding_id": "2b8cb7f6653b", "preview_status": "REVIEW_ONLY_NOT_PUBLISHABLE",
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "publication_status": "blocked",
            "publishable": False, "build_validation": {"status": "success"},
            "commit_hash": "abc123",
            "publication_verdict_blocks": ["code_evidence_missing: the key provenance is not settled"],
        })
        self.assertIn("What keeps it review-only after validation:", preview)
        self.assertIn("- code_evidence_missing: the key provenance is not settled", preview)


class OperatorNotesTests(unittest.TestCase):
    """Four "PR pronto" drafts of 2026-10-27/28 carried a "for the maintainer
    to decide" note no preview showed; Trigger's said a user picking the
    ED25519 option now gets an EC identity."""

    METADATA = {
        "finding_id": "f1", "publishable": False, "manual_review_required": True,
        "build_validation": {"status": "success"}, "commit_hash": "abc123",
        "review_assumptions": [
            "The provider supports EC with 256 bits.",
            "For the maintainer to decide: ED25519 requests now generate EC/256.",
        ],
        "review_blockers": [
            {"code": "USER_OPTION_NEUTRALIZED", "details": ["kpg is only used where the option is on"],
             "maintainer_decides": True},
            {"code": "SETTLED_BY_BUILD", "details": ["not for a person"]},
        ],
        "publication_considerations": [
            {"category": "compatibility_contract", "description": "Existing Ed25519 keys keep working."},
        ],
        "publication_blockers": ["Maintainer authorization for EC/256 is required."],
    }

    def test_the_notes_a_person_decides_come_before_the_pull_request_text(self):
        from cognalys.prs.publication_checks import current_review_contract_version

        metadata = dict(self.METADATA, review_contract_version=current_review_contract_version())
        preview = MODULE.pull_request_preview("o/r", "Title", "Body text.", metadata)
        notes, _, body = preview.partition("\n---\n")

        self.assertIn("Notes before approving", notes)
        self.assertIn("Maintainer decision: ED25519 requests now generate EC/256.", notes)
        self.assertIn("`USER_OPTION_NEUTRALIZED`: kpg is only used", notes)
        self.assertIn("compatibility_contract: Existing Ed25519 keys keep working.", notes)
        self.assertIn("Maintainer authorization for EC/256 is required.", notes)
        self.assertNotIn("SETTLED_BY_BUILD", preview)
        self.assertNotIn("The provider supports EC", preview)
        self.assertNotIn("current behaviour review", preview)
        self.assertNotIn("Maintainer decision", body)

    def test_a_draft_without_the_current_review_says_it_needs_a_rerun(self):
        preview = MODULE.finding_review_preview(dict(self.METADATA, behavior_review_recorded=False))
        self.assertIn("did not pass the current behaviour review", preview)
        self.assertIn("no behaviour review ran on this draft", preview)
        self.assertIn("--allow-stale-review", preview)

    def test_a_single_method_draft_is_noted_not_sent_to_a_rerun(self):
        preview = MODULE.finding_review_preview(dict(
            self.METADATA, behavior_review_recorded=False, fix_scope="single_method"))
        self.assertIn("No behaviour review: the single_method fix path", preview)
        self.assertNotIn("--allow-stale-review", preview)

    def test_the_maintainer_decision_prefix_is_the_one_the_review_writes(self):
        """A reworded prefix would drop every maintainer decision from the notes."""
        import inspect

        from cognalys.llm import coordinated_generation

        self.assertIn(MODULE.MAINTAINER_DECISION_PREFIX, inspect.getsource(coordinated_generation))

    def test_an_earlier_runs_pr_file_gets_its_notes_from_the_solution_file(self):
        import json
        import tempfile

        apk = "app.trigger.debug_1.apk"
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            pull_request = run / "pull_requests" / f"{apk}_createKeyPair_KeyPairGeneratorSpec_pr.json"
            pull_request.parent.mkdir(parents=True)
            solution = run / "error_solutions" / apk / "0_createKeyPair_solution.json"
            solution.parent.mkdir(parents=True)
            solution.write_text(json.dumps({"solution_metadata": {
                "csv_class": "a.Task", "method_name": "createKeyPair", "spec": "KeyPairGeneratorSpec",
                "review_assumptions": ["For the maintainer to decide: EC for ED25519."],
            }}), encoding="utf-8")
            metadata = MODULE.with_recorded_review_notes(
                {"csv_class": "a.Task", "method_name": "createKeyPair",
                 "spec": "KeyPairGeneratorSpec"}, pull_request)

        self.assertEqual(MODULE.operator_notes(metadata), ["Maintainer decision: EC for ED25519."])
        self.assertIsNone(metadata["review_contract_version"])
        self.assertFalse(metadata["behavior_review_recorded"])

    def test_a_gate_warning_with_a_consideration_reaches_the_operator(self):
        """TLS_LEGACY_PROTOCOL_FILTER_MISSING no longer refuses a selector-only fix."""
        metadata = {"fix_scope": "coordinated", "review_contract_version": 4, "review_blockers": [
            {"code": "TLS_LEGACY_PROTOCOL_FILTER_MISSING", "details": ["no filter"],
             "publication_consideration": "The client can still negotiate deprecated protocols."},
            {"code": "TLS_PROTOCOL_FILTER_CONTRACT_NOT_TESTED", "details": ["SSLv3"]}]}
        self.assertIn("`TLS_LEGACY_PROTOCOL_FILTER_MISSING`: The client can still negotiate "
                      "deprecated protocols.", MODULE.operator_notes(metadata))
        self.assertFalse(any("CONTRACT_NOT_TESTED" in note
                             for note in MODULE.operator_notes(metadata)))

    def test_a_review_outage_reads_as_no_review_not_an_old_one(self):
        """The review file of an outage (status not_run) is still a file."""
        import json
        import tempfile

        apk = "app.debug_1.apk"
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            pull_request = run / "pull_requests" / f"{apk}_m_S_pr.json"
            pull_request.parent.mkdir(parents=True)
            solution = run / "error_solutions" / apk / "0_m_solution.json"
            solution.parent.mkdir(parents=True)
            solution.write_text(json.dumps({"solution_metadata": {
                "csv_class": "a.C", "method_name": "m", "spec": "S",
                "fix_scope": "coordinated", "review_contract_version": None,
            }}), encoding="utf-8")
            review = run / "error_solutions" / "coordinated_drafts" / apk / "0_m"
            review.mkdir(parents=True)
            (review / "behavior_review.json").write_text(
                '{"status": "not_run", "regressions": []}', encoding="utf-8")
            # A PR file from older code that called any review file a review.
            metadata = MODULE.with_recorded_review_notes(
                {"csv_class": "a.C", "method_name": "m", "spec": "S",
                 "review_assumptions": [], "fix_scope": "coordinated",
                 "behavior_review_recorded": True}, pull_request)
        self.assertFalse(metadata["behavior_review_recorded"])
        preview = MODULE.finding_review_preview(dict(self.METADATA, **metadata))
        self.assertIn("no behaviour review ran on this draft", preview)
        self.assertNotIn("predates", preview)

    def test_an_empty_review_field_in_the_pr_file_gives_way_to_the_recorded_one(self):
        """As pr_generator.review_notes and the statistics read it."""
        import json
        import tempfile

        from cognalys.prs.publication_checks import current_review_contract_version

        current = current_review_contract_version()
        apk = "app.debug_1.apk"
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            pull_request = run / "pull_requests" / f"{apk}_m_S_pr.json"
            pull_request.parent.mkdir(parents=True)
            solution = run / "error_solutions" / apk / "0_m_solution.json"
            solution.parent.mkdir(parents=True)
            solution.write_text(json.dumps({"solution_metadata": {
                "csv_class": "a.C", "method_name": "m", "spec": "S",
                "fix_scope": "coordinated", "review_contract_version": current,
            }}), encoding="utf-8")
            review = run / "error_solutions" / "coordinated_drafts" / apk / "0_m"
            review.mkdir(parents=True)
            (review / "behavior_review.json").write_text(
                '{"status": "reviewed", "regressions": []}', encoding="utf-8")
            metadata = MODULE.with_recorded_review_notes(
                {"csv_class": "a.C", "method_name": "m", "spec": "S",
                 "review_contract_version": None, "fix_scope": ""}, pull_request)
        self.assertEqual(metadata["review_contract_version"], current)
        self.assertEqual(metadata["fix_scope"], "coordinated")
        preview = MODULE.finding_review_preview(dict(self.METADATA, **metadata))
        self.assertNotIn("did not pass the current behaviour review", preview)


class PublishedDraftPreviewTests(unittest.TestCase):
    """A draft pr_creator already published from its own file: the preview
    asked for a rerun and showed an approval command for it."""

    def test_a_published_stale_draft_says_so_instead_of_asking_for_a_rerun(self):
        import contextlib
        import io
        import json
        import tempfile

        apk = "app.debug_1.apk"
        with tempfile.TemporaryDirectory() as directory:
            pull_requests = Path(directory) / "run" / "pull_requests"
            pull_requests.mkdir(parents=True)
            draft = pull_requests / f"{apk}_m_S_pr.json"
            metadata = dict(OperatorNotesTests.METADATA, behavior_review_recorded=False,
                            decision="MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                            csv_class="a.C", method_name="m", spec="S",
                            source_file="src/A.java", title="Fix it", body="Body text.")
            draft.write_text(json.dumps(metadata), encoding="utf-8")
            output = Path(directory) / "previews"
            argv = ["x", "--pull-requests-dir", str(pull_requests), "--output-dir", str(output),
                    "--issue-title", "T", "--issue-body", "B"]

            def render() -> str:
                with unittest.mock.patch.object(sys, "argv", argv), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(MODULE.main(), 0)
                return (output / "pull_requests" / f"{apk}_m_S.md").read_text(encoding="utf-8")

            unpublished = render()
            # pr_creator's record of a dry run opened nothing.
            record = pull_requests / f"{apk}_m_S_pr_created.json"
            record.write_text(json.dumps({"dry_run": True, "html_url": "https://x/pull/1"}),
                              encoding="utf-8")
            dry_run = render()
            record.write_text(json.dumps({"dry_run": False,
                                          "html_url": "https://github.com/o/r/pull/7"}),
                              encoding="utf-8")
            published = render()

        for preview in (unpublished, dry_run):
            self.assertIn("did not pass the current behaviour review", preview)
            self.assertIn("--approve-reviewed-finding f1", preview)
        self.assertIn("already published: https://github.com/o/r/pull/7", published)
        # Not "skips it": an unapproved or rejected draft stops at an earlier gate.
        self.assertIn("pr_creator will not publish it again", published)
        self.assertNotIn("did not pass the current behaviour review", published)
        self.assertNotIn("--approve-reviewed-finding", published)
        self.assertNotIn("has not been published", published)



class LocalCheckoutPreviewTests(unittest.TestCase):
    """A preview is read locally; only publication needs a hosted repository."""

    def test_a_local_checkout_gets_a_preview(self):
        self.assertEqual(
            MODULE.preview_repository({"repo_host": "", "repo_owner": "", "repo_name": ""}),
            MODULE.LOCAL_REPOSITORY)

    def test_a_hosted_repository_is_named(self):
        self.assertEqual(MODULE.preview_repository(
            {"repo_host": "github.com", "repo_owner": "o", "repo_name": "app"}), "o/app")

    def test_a_partial_identification_is_still_an_error(self):
        with self.assertRaises(ValueError):
            MODULE.preview_repository({"repo_host": "github.com", "repo_owner": "o"})


if __name__ == "__main__":
    unittest.main()
