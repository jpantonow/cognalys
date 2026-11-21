"""Regressions for the three gates that emptied run_20260917_230558.

That run confirmed five causes, produced five valid patch plans and
published nothing. Three of the five findings died on gates that were
reading a label instead of the evidence in front of them:

  * a confirmed single-file repair the adjudicator authorised for review
    only (FIX_SUPPORTED + generation_status supported_for_review) was read
    as auto-apply by every downstream consumer, so the scope waiver written
    for exactly that situation never fired and the finding abstained before
    any code was generated (hmdm extract, oxproxion createLanHttpClient);

  * a review-only decision whose plan required exactly one edit was
    rejected for supplying one edit, because the edit-count floor was fixed
    at two while the sibling distinct-file check already allowed one
    (tuisku importUnencryptedNotes -- its draft was complete and
    semantically valid when it was discarded);

  * deleting a trust-all X509TrustManager written as an anonymous class
    counted as removing three public methods from the file's API
    (seafile getMediaSource), which is the repair, not a regression.

Each test states the shape the pipeline must keep accepting, not the one
finding that exposed it.
"""
import logging
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm import semantic_validation as sv  # noqa: E402
from cognalys.llm.generate_error_fixes import FixGenerator  # noqa: E402


class AnonymousImplementationContractTests(unittest.TestCase):
    """A method inside an inline implementation is not this file's API."""

    JAVA_TRUST_ALL = """
class UnsafeOkHttpClient {
    private final TrustManager[] trustAllCerts = new TrustManager[]{
        new X509TrustManager() {
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[]{};
            }
        }
    };
}
"""

    def _validate(self, original: str, corrected: str):
        return sv.validate_coordinated_semantics(
            {"repository_path": "", "source_file_path": "src/Client.java"},
            [{
                "source_file_path": "src/Client.java",
                "symbol": "trustAllCerts",
                "edit_kind": "declaration",
                "original_code": original,
                "corrected_code": corrected,
                "reason": "remove permissive TLS validation",
            }],
        )

    def test_removing_an_anonymous_implementation_is_not_a_contract_change(self):
        result = self._validate(self.JAVA_TRUST_ALL, "class UnsafeOkHttpClient {\n}\n")
        codes = [item.get("code") for item in result.get("errors", [])]
        self.assertNotIn("PUBLIC_API_CONTRACT_CHANGED", codes)

    def test_removing_a_real_public_method_is_still_a_contract_change(self):
        result = self._validate(
            "class Client {\n    public String token(int id) {\n"
            "        return \"t\";\n    }\n}\n",
            "class Client {\n}\n",
        )
        codes = [item.get("code") for item in result.get("errors", [])]
        self.assertIn("PUBLIC_API_CONTRACT_CHANGED", codes)

    def test_kotlin_object_expression_bodies_are_inline_implementations(self):
        code = (
            "class ViewModel {\n"
            "    val verifier = object : HostnameVerifier {\n"
            "        public fun verify(host: String): Boolean { return true }\n"
            "    }\n"
            "}\n"
        )
        spans = sv.anonymous_class_spans(code)
        self.assertEqual(len(spans), 1)
        start, end = spans[0]
        self.assertIn("verify", code[start:end])

    def test_a_brace_inside_a_string_does_not_open_a_span(self):
        self.assertEqual(
            sv.anonymous_class_spans('class A { String s = "}{"; }'), []
        )

    def test_a_lambda_argument_is_not_an_anonymous_class(self):
        self.assertEqual(
            sv.anonymous_class_spans(
                "class A { void g() { new Thread(() -> { run(); }).start(); } }"
            ),
            [],
        )


class ReviewableGenerationLabelTests(unittest.TestCase):
    """generation_status decides who applies the patch, not the label."""

    def _normalized(self, decision: str, generation_status: str) -> str:
        """The decision `_analysis_record` records for this adjudication."""
        # Mirrors the single normalization point in adjudication.py; kept as
        # a direct call so the rule is tested rather than the plumbing.
        from cognalys.llm.adjudication import _analysis_record

        record = _analysis_record(
            {"unique_error_id": "x", "source_file_path": "src/A.java"},
            {"finding": {}, "evidence_catalog": [], "versions": {},
             "input_hashes": {}, "specification_context": {}},
            {},
            {"claims": [], "predicate_assessment": [], "relations": []},
            {
                "decision": decision,
                "generation_status": generation_status,
                "publication_status": "blocked",
                "cause_status": "confirmed",
                "confirmed_cause": "the entry name is not contained",
                "detector_violation": "confirmed",
                "blocking_for_generation": [],
                "blocking_for_publication": [],
            },
            {"required_edits": [
                {"source_file_path": "src/A.java", "symbol": "extract",
                 "reason": "validate containment"},
            ]},
            {},
        )
        return str(record.get("decision", ""))

    def test_reviewable_single_file_repair_is_relabelled_for_review(self):
        self.assertEqual(
            self._normalized("FIX_SUPPORTED", "supported_for_review"),
            "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
        )

    def test_automatic_single_file_repair_keeps_its_label(self):
        self.assertEqual(
            self._normalized("FIX_SUPPORTED", "supported"), "FIX_SUPPORTED"
        )


class PlanSizedEditFloorTests(unittest.TestCase):
    """The authorised plan sets how many edits a generation must carry."""

    class _Provider:
        provider_name = "test"
        model = "test-model"
        context_length = 16384
        requested_context_length = 16384
        last_context_length = 16384
        max_output_tokens = 4096

        @staticmethod
        def get_token_usage():
            return {"input": 0, "output": 0}

        @staticmethod
        def generate(*_args, **_kwargs):
            return "{}"

    def _harness(self, directory: str):
        root = Path(directory)
        repo = root / "repo"
        source = repo / "src" / "PortManager.kt"
        source.parent.mkdir(parents=True)
        source.write_text("class PortManager {}", encoding="utf-8")
        # A second file that exists in the checkout: only an existing
        # planned file is required to be covered by the generated edits.
        (repo / "src" / "Port.kt").write_text(
            "class Port {}", encoding="utf-8"
        )
        input_file = root / "app.apk" / "1_importUnencryptedNotes.json"
        input_file.parent.mkdir()
        generator = FixGenerator(
            input_dir=input_file.parent,
            output_dir=root / "out",
            provider=self._Provider(),
            logger=logging.getLogger("plan-sized-floor"),
            api_logger=logging.getLogger("plan-sized-floor-api"),
        )
        error = {
            "_file_path": input_file,
            "repository_path": str(repo),
            "source_file_path": "src/PortManager.kt",
            "method_name": "importUnencryptedNotes",
            "csv_class": "com.omaawr.tuisku.managers.PortManager",
            "method_body": "File(ctx.filesDir, entry.name)",
            "spec": "ZipSlipSpec",
            "error_message": "entry names reach File(ctx.filesDir, entry.name)",
            "unique_error_id": (
                "com.omaawr.tuisku.managers.PortManager:::"
                "importUnencryptedNotes:::ZipSlipSpec:::PathTraversal:::x"
            ),
            "expanded_repository_context": {"multi_file_impact": {}},
        }
        return generator, error

    def _analysis(self, planned_files):
        return {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "cause_status": "confirmed",
            "detector_violation": "confirmed",
            "confirmed_cause": "the destination is not contained by the root",
            "scope_assessment": {"status": "complete"},
            "coordinated_fix_plan": {
                "required_edits": [
                    {"source_file_path": path, "symbol": "importUnencryptedNotes",
                     "reason": "validate containment"}
                    for path in planned_files
                ],
            },
        }

    def _generation(self, paths):
        return {
            "status": "complete",
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "explanation": "resolve the destination and reject traversal",
            "confidence": 70,
            "manual_review_required": True,
            "review_assumptions": ["a reviewer settles the rejection policy"],
            "required_tests": ["an out-of-root entry is rejected"],
            "edits": [
                {
                    "source_file_path": path,
                    "symbol": "importUnencryptedNotes",
                    "edit_kind": "declaration",
                    "original_code": "class PortManager {}",
                    "corrected_code": "class PortManager { }",
                    "reason": "validate containment",
                }
                for path in paths
            ],
        }

    def _drive(self, generator, error, analysis, generation):
        with ExitStack() as stack:
            stack.enter_context(patch.object(
                generator, "adjudicate_finding", return_value=(analysis, {})
            ))
            stack.enter_context(
                patch.object(generator, "persist_blocked_issue_candidate")
            )
            stack.enter_context(patch.object(
                generator, "generate_coordinated_file_drafts",
                return_value=generation,
            ))
            return generator.process_finding(error)

    def test_a_one_edit_plan_accepts_one_edit(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            result = self._drive(
                generator, error,
                self._analysis(["src/PortManager.kt"]),
                self._generation(["src/PortManager.kt"]),
            )
        # The draft is carried forward instead of being discarded for
        # supplying exactly what its plan required.
        self.assertIsNotNone(result.solution)

    def test_a_two_edit_plan_still_rejects_a_single_edit(self):
        # Lowering the floor to the plan's size does not let a generation
        # skip a planned file: plan coverage is checked separately, against
        # the planned files that exist in the checkout.
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            result = self._drive(
                generator, error,
                self._analysis(["src/PortManager.kt", "src/Port.kt"]),
                self._generation(["src/PortManager.kt"]),
            )
        self.assertIsNone(result.solution)
        self.assertEqual(result.outcome, "abstained")


class IncompleteScopeDemotionTests(unittest.TestCase):
    """An incomplete scope forbids applying unattended, not reviewing.

    hmdm extract, run_20260920_175850: cause confirmed, zero generation
    blockers, adjudicated `generation_status: supported` -- and abandoned
    because five consumers of the changed value were not individually
    reviewed. The same finding adjudicated `supported_for_review` would have
    been generated. The authority now only goes down.
    """

    def _analysis(self, **adjudication) -> dict:
        return {
            "decision": "FIX_SUPPORTED",
            "cause_status": "confirmed",
            "scope_assessment": {
                "status": "incomplete",
                "unresolved_relations": [{
                    "kind": "other", "blocking_for_generation": False,
                    "blocking_for_publication": True,
                    "description": "runtime reachability is not established",
                }],
            },
            "v2": {"adjudication": {
                "decision": "FIX_SUPPORTED", "generation_status": "supported",
                "publication_status": "blocked", "blocking_for_generation": [],
                **adjudication,
            }},
        }

    ISSUES = ["scope_assessment.status must be complete"]

    def test_a_confirmed_repair_is_demoted_to_review(self):
        from cognalys.llm.pipeline_architecture import demote_incomplete_scope_to_review

        analysis = self._analysis()
        self.assertTrue(demote_incomplete_scope_to_review(
            analysis, "FIX_SUPPORTED", self.ISSUES,
        ))
        self.assertEqual(analysis["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        adjudication = analysis["v2"]["adjudication"]
        self.assertEqual(adjudication["generation_status"], "supported_for_review")
        self.assertEqual(adjudication["publication_status"], "blocked")
        self.assertEqual(analysis["demoted_from"], "FIX_SUPPORTED")
        self.assertTrue(any("scope could not be completed" in item
                            for item in analysis["review_assumptions"]))

    def test_nothing_is_demoted_past_a_generation_blocker(self):
        from cognalys.llm.pipeline_architecture import demote_incomplete_scope_to_review

        analysis = self._analysis(blocking_for_generation=[{"kind": "x"}])
        self.assertFalse(demote_incomplete_scope_to_review(
            analysis, "FIX_SUPPORTED", self.ISSUES,
        ))
        analysis = self._analysis()
        analysis["scope_assessment"]["unresolved_relations"][0][
            "blocking_for_generation"] = True
        self.assertFalse(demote_incomplete_scope_to_review(
            analysis, "FIX_SUPPORTED", self.ISSUES,
        ))

    def test_nothing_is_demoted_without_a_confirmed_cause(self):
        from cognalys.llm.pipeline_architecture import demote_incomplete_scope_to_review

        analysis = self._analysis()
        analysis["cause_status"] = "unknown"
        self.assertFalse(demote_incomplete_scope_to_review(
            analysis, "FIX_SUPPORTED", self.ISSUES,
        ))

    def test_dependency_decisions_keep_their_own_gates(self):
        from cognalys.llm.pipeline_architecture import demote_incomplete_scope_to_review

        self.assertFalse(demote_incomplete_scope_to_review(
            self._analysis(), "DEPENDENCY_FIX_SUPPORTED", self.ISSUES,
        ))

    def test_a_review_label_with_publication_open_gets_publication_blocked(self):
        """winterhold derive, c_arm_k3 r3: `supported_for_review` with
        publication `eligible_after_validation` was relabelled to the review
        label without blocking publication, so the scope waiver never applied
        and the finding stopped as a scope_gap."""
        from cognalys.llm.pipeline_architecture import demote_incomplete_scope_to_review

        analysis = self._analysis(
            decision="MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            generation_status="supported_for_review",
            publication_status="eligible_after_validation",
        )
        self.assertTrue(demote_incomplete_scope_to_review(
            analysis, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", self.ISSUES,
        ))
        self.assertEqual(analysis["v2"]["adjudication"]["publication_status"], "blocked")
        self.assertEqual(analysis["publication_status"], "blocked")
        self.assertTrue(any("scope could not be completed" in item
                            for item in analysis["review_assumptions"]))

    def test_a_review_label_already_blocked_or_unconfirmed_is_left_alone(self):
        from cognalys.llm.pipeline_architecture import demote_incomplete_scope_to_review

        self.assertFalse(demote_incomplete_scope_to_review(
            self._analysis(decision="MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                           generation_status="supported_for_review"),
            "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", self.ISSUES,
        ))
        analysis = self._analysis(
            generation_status="supported_for_review",
            publication_status="eligible_after_validation",
        )
        analysis["cause_status"] = "unknown"
        self.assertFalse(demote_incomplete_scope_to_review(
            analysis, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", self.ISSUES,
        ))
        self.assertFalse(demote_incomplete_scope_to_review(
            self._analysis(generation_status="supported_for_review",
                           publication_status="eligible_after_validation",
                           blocking_for_generation=[{"kind": "x"}]),
            "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", self.ISSUES,
        ))

    def test_a_blocked_generation_is_not_authorised_by_demotion(self):
        from cognalys.llm.pipeline_architecture import demote_incomplete_scope_to_review

        self.assertFalse(demote_incomplete_scope_to_review(
            self._analysis(generation_status="blocked"), "FIX_SUPPORTED",
            self.ISSUES,
        ))


class SharedEditFloorTests(unittest.TestCase):
    """The generator and the applicator must apply one rule, not two.

    run_20260920_175850: einkbro's restoreLegacyBackupData was generated as
    a valid one-edit review-only patch -- its plan required exactly one edit
    -- and the applicator, which kept its own fixed floor of two, refused it
    with INVALID_COORDINATED_EDIT_COUNT before it was ever built.
    """

    def test_the_rule(self):
        from cognalys.utils.disposition import minimum_coordinated_edits

        cases = [
            # decision, planned edits, fix_scope, expected floor
            ("MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", 1, "review_only", 1),
            ("MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", 3, "review_only", 1),
            ("MULTI_FILE_FIX_SUPPORTED", 3, "coordinated", 2),
            ("MULTI_FILE_FIX_SUPPORTED", 1, "coordinated", 1),
            ("DEPENDENCY_FIX_SUPPORTED", 4, "dependency", 1),
            ("MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", 0, "review_only", 2),
        ]
        for decision, planned, scope, expected in cases:
            self.assertEqual(
                minimum_coordinated_edits(decision, planned, scope), expected,
                f"{decision} with {planned} planned edit(s)",
            )

    def test_the_applicator_accepts_a_one_edit_review_only_patch(self):
        from cognalys.solutions.solution_applicator import SolutionApplicator

        solution = {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "fix_scope": "review_only",
            "llm_architecture": {"version": "v2"},
            "authorized_patch_plan": {"required_edits": [{
                "source_file_path": "app/src/main/java/a/BackupUnit.kt",
                "symbol": "restoreLegacyBackupData",
            }]},
            "coordinated_edits": [{
                "source_file_path": "app/src/main/java/a/BackupUnit.kt",
                "symbol": "restoreLegacyBackupData",
                "edit_kind": "method",
                "original_code": "fun restoreLegacyBackupData() {}",
                "corrected_code": "fun restoreLegacyBackupData() { check() }",
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            applicator = SolutionApplicator.__new__(SolutionApplicator)
            applicator.logger = logging.getLogger("applicator-floor")
            _ok, _edits, error = applicator._apply_coordinated_edits(
                solution, None, Path(directory),
            )
        # Whatever else the stub repository makes it fail on, it is no
        # longer refused for its size.
        self.assertNotEqual(error, "INVALID_COORDINATED_EDIT_COUNT")

        # And the gate is really reached: the same single edit under an
        # auto-applied decision whose plan asks for two is still refused.
        solution["decision"] = "MULTI_FILE_FIX_SUPPORTED"
        solution["fix_scope"] = "coordinated"
        solution["authorized_patch_plan"]["required_edits"].append({
            "source_file_path": "app/src/main/java/a/Other.kt", "symbol": "x",
        })
        with tempfile.TemporaryDirectory() as directory:
            _ok, _edits, error = applicator._apply_coordinated_edits(
                solution, None, Path(directory),
            )
        self.assertEqual(error, "INVALID_COORDINATED_EDIT_COUNT")


if __name__ == "__main__":
    unittest.main()
