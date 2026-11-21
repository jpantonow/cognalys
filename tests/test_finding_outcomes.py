"""Pin the outcome `process_finding` reports at every one of its exits.

The method is 1090 lines with eleven return statements. It used to report
what happened by assigning to `self.last_outcome` / `self.last_decision`
from wherever it gave up, and these tests were written first, against that
version, to record exactly what each exit concluded. Converting those
attributes into the returned FindingOutcome then had to leave all of them
green, unchanged apart from how the result is read -- which is what makes
the conversion verifiable rather than assumed.

They remain characterization tests. They record what the method does,
including one thing that looks wrong: the exit taken when the model itself
answers NO_SAFE_FIX leaves the outcome at "failed", so that finding is
counted as a failed analysis rather than an abstention. That is pinned here
as it stands -- changing it is a separate decision about what the run
statistics mean, not something to slip into a refactor.
"""
import json
import logging
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.generate_error_fixes import FixGenerator  # noqa: E402
from cognalys.llm.llm_providers import (  # noqa: E402
    BackgroundCreateFailed, BackgroundResponseFailed, ProviderContentRefusal,
    ProviderRequestRejected,
)
from cognalys.llm.run_statistics import failure_kind  # noqa: E402
from cognalys.orchestration.run_status import RESUMABLE_FAILURE_KINDS  # noqa: E402


class _TokenProvider:
    """Stands in for the LLM. Returns queued responses in order."""

    # The successful single-method path records the provider's identity and
    # window in solution_metadata. A stub missing any of these raises inside
    # process_finding's own try, which swallows it and returns a plain failure
    # -- so an incomplete stub silently tests the wrong exit.
    provider_name = "test"
    model = "test-model"
    context_length = 16384
    requested_context_length = 16384
    last_context_length = 16384
    max_output_tokens = 4096

    def __init__(self, responses=()):
        self.responses = list(responses)
        self.prompts = []

    @staticmethod
    def get_token_usage():
        return {"input": 0, "output": 0}

    def generate(self, prompt, *_args, **_kwargs):
        self.prompts.append(prompt)
        if not self.responses:
            return "{}"
        return self.responses.pop(0)


def _edit(relative: str, kind: str = "declaration") -> dict:
    return {
        "source_file_path": relative,
        "symbol": "value",
        "edit_kind": kind,
        "original_code": "int value = 1;",
        "corrected_code": "int value = 2;",
        "reason": "coordinated",
    }


class FindingOutcomeTests(unittest.TestCase):
    """One test per return statement in process_finding."""

    def _harness(self, directory: str, provider=None):
        root = Path(directory)
        repo = root / "repo"
        source = repo / "src" / "PwsFile.java"
        source.parent.mkdir(parents=True)
        source.write_text("class PwsFile {}", encoding="utf-8")
        (repo / "src" / "Other.java").write_text(
            "class Other {}", encoding="utf-8"
        )
        input_file = root / "app.apk" / "2_getCipher.json"
        input_file.parent.mkdir()

        generator = FixGenerator(
            input_dir=input_file.parent,
            output_dir=root / "out",
            provider=provider or _TokenProvider(),
            logger=logging.getLogger("finding-outcomes"),
            api_logger=logging.getLogger("finding-outcomes-api"),
        )
        error = {
            "_file_path": input_file,
            "repository_path": str(repo),
            "source_file_path": "src/PwsFile.java",
            "method_name": "getCipher",
            "csv_class": "org.pwsafe.lib.file.PwsFile",
            "method_body": 'Cipher.getInstance("AES/CTR/NoPadding")',
            "spec": "CipherSpec",
            "error_message": "authenticated encryption required",
            "unique_error_id": (
                "org.pwsafe.lib.file.PwsFile:::getCipher:::CipherSpec:::"
                "UnsafeAlgorithm:::authenticated encryption required"
            ),
            "expanded_repository_context": {"multi_file_impact": {}},
        }
        return generator, error

    def _drive(self, generator, error, analysis, coordinated=None):
        """Drive process_finding once and report everything it decided.

        Not named _outcome: TestCase already owns that attribute.
        """
        with ExitStack() as stack:
            stack.enter_context(patch.object(
                generator, "adjudicate_finding", return_value=(analysis, {})
            ))
            stack.enter_context(
                patch.object(generator, "persist_blocked_issue_candidate")
            )
            if coordinated is not None:
                stack.enter_context(patch.object(
                    generator, "generate_coordinated_file_drafts",
                    return_value=coordinated,
                ))
            result = generator.process_finding(error)
        return result.solution, result.success, result.outcome, result.decision

    # -- exit 1: the evidence analysis was not usable JSON ------------------

    def test_unusable_evidence_analysis_fails_without_a_decision(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            solution, success, outcome, decision = self._drive(
                generator, error, {}
            )

        self.assertIsNone(solution)
        self.assertFalse(success)
        self.assertEqual(outcome, "failed")
        # This exit is taken before the local `decision` variable is bound at
        # all, which is why the refactor cannot simply pass it along here.
        self.assertEqual(decision, "")

    # -- exit 2: the evidence phase itself abstained ------------------------

    def test_evidence_phase_abstention_reports_its_decision(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            solution, success, outcome, decision = self._drive(
                generator, error, {
                    "decision": "NO_SAFE_FIX",
                    "confirmed_cause": "",
                    "cause_status": "unknown",
                },
            )

        self.assertIsNone(solution)
        self.assertFalse(success)
        self.assertEqual(outcome, "abstained")
        self.assertEqual(decision, "NO_SAFE_FIX")

    def test_supported_decision_without_a_confirmed_cause_abstains(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            solution, success, outcome, decision = self._drive(
                generator, error, {
                    "decision": "FIX_SUPPORTED",
                    "confirmed_cause": "",
                    "cause_status": "confirmed",
                    "scope_assessment": {"status": "complete"},
                },
            )

        self.assertIsNone(solution)
        self.assertFalse(success)
        self.assertEqual(outcome, "abstained")
        self.assertEqual(decision, "FIX_SUPPORTED")

    # -- exit 3: a dependency fix without official migration evidence -------

    def test_unsupported_dependency_evidence_abstains(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            solution, success, outcome, decision = self._drive(
                generator, error, {
                    "decision": "DEPENDENCY_FIX_SUPPORTED",
                    "confirmed_cause": "the pinned library is unmaintained",
                    "cause_status": "confirmed",
                    "scope_assessment": {"status": "complete"},
                    "dependency_fix_assessment": {
                        "compatibility_constraints_satisfied": False,
                    },
                },
            )

        self.assertIsNone(solution)
        self.assertFalse(success)
        self.assertEqual(outcome, "abstained")
        self.assertEqual(decision, "DEPENDENCY_FIX_SUPPORTED")

    # -- exit 4: coordinated generation did not complete --------------------

    def test_incomplete_coordinated_generation_abstains(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            solution, success, outcome, decision = self._drive(
                generator, error, self._review_analysis(),
                coordinated={
                    "status": "failed", "issues": ["stop after persistence"],
                },
            )

        self.assertIsNone(solution)
        self.assertFalse(success)
        self.assertEqual(outcome, "abstained")
        self.assertEqual(decision, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")

    # -- exit 5: the generated edits failed validation ----------------------

    def test_rejected_coordinated_edits_abstain(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            solution, success, outcome, decision = self._drive(
                generator, error, self._review_analysis(),
                coordinated=self._complete_generation(
                    # One edit, and the analysis carries no required_edits:
                    # an empty plan authorises nothing, so the floor stays at
                    # two rather than following the plan down to one.
                    edits=[_edit("src/PwsFile.java")],
                ),
            )

        self.assertIsNone(solution)
        self.assertFalse(success)
        self.assertEqual(outcome, "abstained")
        self.assertEqual(decision, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")

    # -- exit 6: the generation carried no explanation ----------------------

    def test_coordinated_generation_without_an_explanation_abstains(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            solution, success, outcome, decision = self._drive(
                generator, error, self._review_analysis(),
                coordinated=self._complete_generation(explanation="   "),
            )

        self.assertIsNone(solution)
        self.assertFalse(success)
        self.assertEqual(outcome, "abstained")
        self.assertEqual(decision, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")

    # -- exit 7: a coordinated solution ------------------------------------

    def test_complete_coordinated_generation_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            solution, success, outcome, decision = self._drive(
                generator, error, self._review_analysis(),
                coordinated=self._complete_generation(),
            )

        self.assertTrue(success)
        self.assertIsNotNone(solution)
        # A review-only decision is scoped "review_only", not "coordinated",
        # so run_analysis does not count it under coordinated_solutions.
        self.assertEqual(
            solution["solution_metadata"]["fix_scope"], "review_only"
        )
        # Success leaves the outcome at its initial value: run_analysis reads
        # the returned flag, not this attribute, on the successful path.
        self.assertEqual(outcome, "failed")
        self.assertEqual(decision, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")

    def test_the_solution_records_the_review_contract_its_draft_passed(self):
        # finding_statistics and the publication gate read the version from
        # the solution; a draft no behaviour review judged records None
        # rather than leaving them to guess from behavior_review.json.
        reviewed = dict(self._complete_generation(), review_contract_version=3)
        for generation, expected in ((reviewed, 3), (self._complete_generation(), None)):
            with tempfile.TemporaryDirectory() as directory:
                generator, error = self._harness(directory)
                solution, success, _outcome, _decision = self._drive(
                    generator, error, self._review_analysis(), coordinated=generation)
            self.assertTrue(success)
            metadata = solution["solution_metadata"]
            self.assertIn("review_contract_version", metadata)
            self.assertEqual(metadata["review_contract_version"], expected)

    # -- B3: a supported change inside the reported method -----------------

    def _single_fix_analysis(self) -> dict:
        return {
            "decision": "FIX_SUPPORTED",
            "confirmed_cause": "AES/CTR does not authenticate ciphertext",
            "cause_status": "confirmed",
            "detector_violation": "confirmed",
            "scope_assessment": {"status": "complete"},
            "coordinated_fix_plan": {"required_edits": []},
        }

    def _one_method_generation(self, **extra):
        return {
            "status": "complete",
            "decision": "FIX_SUPPORTED",
            "explanation": "use an authenticated transformation",
            "edits": [{
                "source_file_path": "src/PwsFile.java", "symbol": "getCipher",
                "edit_kind": "method",
                "original_code": 'Cipher.getInstance("AES/CTR/NoPadding")',
                "corrected_code": 'Cipher.getInstance("AES/GCM/NoPadding")',
                "reason": "authenticated encryption"}],
            "required_tests": ["round trip"],
            "review_assumptions": [],
            "manual_review_required": False,
            "confidence": "high",
            "review_contract_version": 20,
            **extra,
        }

    def test_a_supported_one_method_plan_takes_the_per_file_path(self):
        """B3: no single-method generator; the per-file path, its checks and its review."""
        seen = {}

        def generate(error, decision, apk_name, method_name):
            seen["decision"] = decision
            seen["plan"] = error["evidence_analysis"]["coordinated_fix_plan"]
            return self._one_method_generation()

        with tempfile.TemporaryDirectory() as directory:
            provider = _TokenProvider()
            generator, error = self._harness(directory, provider=provider)
            with patch.object(generator, "generate_coordinated_file_drafts",
                              side_effect=generate):
                solution, success, outcome, decision = self._drive(
                    generator, error, self._single_fix_analysis())

        self.assertTrue(success)
        self.assertEqual(decision, "FIX_SUPPORTED")
        # Under its own decision, not demoted to review.
        self.assertEqual(seen["decision"], "FIX_SUPPORTED")
        # The plan named no edit: the reported method becomes its one edit.
        self.assertEqual(
            [(item["source_file_path"], item["symbol"]) for item in seen["plan"]["required_edits"]],
            [("src/PwsFile.java", "getCipher")])
        metadata = solution["solution_metadata"]
        self.assertEqual(metadata["fix_scope"], "coordinated")
        self.assertEqual(metadata["review_contract_version"], 20)
        self.assertEqual(len(solution["corrected_implementation"]["coordinated_edits"]), 1)
        # No call went to a single-method generator.
        self.assertEqual(provider.prompts, [])

    def test_a_one_method_draft_the_per_file_checks_reject_is_no_solution(self):
        """BlueGate's discarded construction, Trigger's fallback and AGrahn's
        unobserved library were caught on both paths; on the one path left a
        rejected draft is an abstention with its reason, as any other."""
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            solution, success, outcome, decision = self._drive(
                generator, error, self._single_fix_analysis(),
                coordinated={"status": "failed", "issues": [
                    "DISCARDED_CONSTRUCTION: GCMParameterSpec is built and dropped"]})

        self.assertIsNone(solution)
        self.assertFalse(success)
        self.assertEqual(outcome, "abstained")
        self.assertEqual(decision, "FIX_SUPPORTED")

    # -- exit 11: an unexpected exception -----------------------------------

    def test_an_unexpected_exception_is_reported_as_a_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            with patch.object(
                generator, "adjudicate_finding",
                side_effect=RuntimeError("simulated"),
            ):
                result = generator.process_finding(error)

            self.assertIsNone(result.solution)
            self.assertFalse(result.success)
            # "crashed", not "failed": a defect in this pipeline is not the
            # same event as an analysis that ran and produced nothing, and
            # only the first should fail the step.
            self.assertEqual(result.outcome, "crashed")
            self.assertEqual(result.decision, "")
            self.assertIn("RuntimeError: simulated", result.failure_cause)

    def test_a_provider_content_refusal_is_not_reported_as_a_crash(self):
        """run_20260907_210458 lost a finding to OpenAI's cyber_policy filter
        23 minutes in, and the run recorded it as "Failed to analyze" with no
        cause. A refusal is a verdict on the prompt, identical on every retry,
        so it is named, recorded, and does not fail the step."""
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            with patch.object(
                generator, "adjudicate_finding",
                side_effect=ProviderContentRefusal(
                    "refused", code="cyber_policy", status_code=400,
                ),
            ):
                result = generator.process_finding(error)

            self.assertIsNone(result.solution)
            self.assertFalse(result.success)
            self.assertEqual(result.outcome, "provider_refused")
            self.assertIn("refused", result.failure_cause)

    def test_a_provider_that_failed_to_answer_is_not_recorded_as_a_refusal(self):
        """agent_baseline_20261108 run_v4 (2026-11-09): evidence extraction met
        Flex responses failed with server_is_overloaded, and five of nine
        findings were recorded as "Provider refused this finding's content".
        A failure that outlasts the call's resends is the provider's, not a
        verdict on the text: provider_unavailable, left for a resume pass."""
        for failure in (
                BackgroundResponseFailed(
                    "OpenAI background response failed (server_is_overloaded): "
                    "Our servers are currently overloaded.",
                    code="server_is_overloaded"),
                BackgroundCreateFailed("OpenAI API HTTP 500: boom", status_code=500)):
            with self.subTest(type(failure).__name__), \
                    tempfile.TemporaryDirectory() as directory:
                generator, error = self._harness(directory)
                with patch.object(generator, "adjudicate_finding", side_effect=failure), \
                        self.assertLogs(level="ERROR") as logs:
                    result = generator.process_finding(error)

                self.assertIsNone(result.solution)
                self.assertEqual(result.outcome, "provider_unavailable")
                self.assertIn(type(failure).__name__, result.failure_cause)
                self.assertFalse(any("refused" in line for line in logs.output))
                self.assertIn("provider_unavailable", RESUMABLE_FAILURE_KINDS)

    def test_a_request_the_provider_rejects_is_a_failed_analysis_not_resumed(self):
        """Review of 2026-11-09: a coded 4xx (context_length_exceeded) was a
        content refusal until that day and would otherwise read as a crash,
        resumed twice for the same answer. A failed analysis is concluded
        and fails the step."""
        rejected = ProviderRequestRejected(
            "OpenAI API HTTP 400: Your input exceeds the context window of this model.",
            code="context_length_exceeded", status_code=400)
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            with patch.object(generator, "adjudicate_finding", side_effect=rejected), \
                    self.assertLogs(level="ERROR") as logs:
                result = generator.process_finding(error)

        self.assertIsNone(result.solution)
        self.assertEqual(result.outcome, "failed_analysis")
        self.assertIn("ProviderRequestRejected", result.failure_cause)
        self.assertTrue(any("context_length_exceeded" in line for line in logs.output))
        self.assertFalse(any("refused this finding" in line for line in logs.output))
        self.assertNotIn(failure_kind(result.outcome), RESUMABLE_FAILURE_KINDS)

    # -- before any model call ---------------------------------------------

    def test_a_finding_with_no_source_and_no_artifact_never_reaches_the_model(self):
        """run_20260909_100446 spent 2m19s establishing that it knew nothing.

        Extraction had written an empty method_body and an empty
        source_file_path because the reported class does not exist in the
        analysed checkout, and the dependency match was ambiguous, so there
        was neither code to review nor a version to change.
        """
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            error = dict(error)
            error["method_body"] = ""
            error["source_file_path"] = ""
            error["surrounding_context"] = ""
            error["extraction_status"] = "external_dependency_candidate"
            error["dependency_context"] = {"status": "ambiguous"}

            with patch.object(
                generator, "adjudicate_finding",
                side_effect=AssertionError("the model must not be called"),
            ):
                result = generator.process_finding(error)

            self.assertEqual(result.outcome, "not_analyzable")
            self.assertIn("no source", result.failure_cause)
            self.assertIn("external_dependency_candidate", result.failure_cause)

    def test_an_identified_dependency_artifact_is_still_analysed(self):
        """A dependency finding is fixed by changing a declared version, not
        by editing a method, so an empty body alone must not withhold it."""
        error = {
            "method_body": "",
            "source_file_path": "",
            "surrounding_context": "",
            "extraction_status": "external_dependency_candidate",
            "dependency_context": {"status": "identified"},
        }
        self.assertEqual(FixGenerator.unanalysable_reason(error), "")

    def test_a_finding_with_source_is_always_analysed(self):
        self.assertEqual(
            FixGenerator.unanalysable_reason({"method_body": "void f() {}"}),
            "",
        )
        self.assertEqual(
            FixGenerator.unanalysable_reason({"source_file_path": "src/A.java"}),
            "",
        )

    # -- shared analysis and generation shapes ------------------------------

    def _review_analysis(self) -> dict:
        return {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "confirmed_cause": "AES/CTR does not authenticate ciphertext",
            "cause_status": "confirmed",
            "detector_violation": "confirmed",
            "scope_assessment": {"status": "complete"},
            "coordinated_fix_plan": {"required_edits": []},
        }

    def _complete_generation(self, edits=None, explanation="coordinated fix"):
        return {
            "status": "complete",
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "explanation": explanation,
            "edits": edits if edits is not None else [
                _edit("src/PwsFile.java", "method"),
                _edit("src/Other.java"),
            ],
            "required_tests": ["round trip"],
            "review_assumptions": ["reviewer confirms the callers"],
            "manual_review_required": True,
            "confidence": "medium",
        }


if __name__ == "__main__":
    unittest.main()


class PublicationBlockedMetadataTests(FindingOutcomeTests):
    """An adjudication that blocked publication must not produce a publishable fix.

    publication_allowed was derived from the decision label alone, so an
    auto-apply decision whose adjudication set publication_status "blocked" --
    on something this pipeline cannot discharge, such as deployed platform
    behaviour or an external data contract -- still reached pr_generator as
    publishable. Live on me.blog.korn123.easydiary's Zip Slip finding in
    run_20260908_151705: FIX_SUPPORTED, generation supported, publication
    blocked on unestablished Android filesystem behaviour.
    """

    def _solution_for(self, publication_status):
        analysis = self._single_fix_analysis()
        if publication_status is not None:
            analysis["publication_status"] = publication_status
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            solution, success, _, _ = self._drive(
                generator, error, analysis, coordinated=self._one_method_generation())
        self.assertTrue(success)
        return solution["solution_metadata"]

    def test_blocked_publication_is_not_publishable(self):
        metadata = self._solution_for("blocked")
        self.assertFalse(metadata["publication_allowed"])

    def test_blocked_publication_is_still_applied_and_validated(self):
        """The block is on publishing, not on applying.

        solution_applicator skips anything with manual_review_required, and it
        can only re-admit such a solution when semantic_validation reports
        "valid" -- a field the single-method path never wrote. Marking a
        publication block as manual review therefore dropped the generated
        patch before it was ever applied or built: run_20260908_154553
        generated a 90%-confidence fix and applied nothing.
        """
        metadata = self._solution_for("blocked")
        self.assertFalse(metadata["manual_review_required"])
        self.assertTrue(metadata["auto_apply"])

    def test_eligible_publication_stays_publishable(self):
        metadata = self._solution_for("eligible_after_validation")
        self.assertTrue(metadata["publication_allowed"])
        self.assertFalse(metadata["manual_review_required"])

    def test_a_legacy_analysis_without_the_field_is_not_blocked(self):
        metadata = self._solution_for(None)
        self.assertTrue(metadata["publication_allowed"])


class DecisionPathTests(unittest.TestCase):
    """Where a finding ends when the decision path, not the model, decides.

    Reuses FindingOutcomeTests' harness without inheriting it, so its tests
    are not collected a second time.
    """

    _harness = FindingOutcomeTests._harness

    def _run(self, generator, error, analysis, coordinated=None):
        with ExitStack() as stack:
            stack.enter_context(patch.object(
                generator, "adjudicate_finding", return_value=(analysis, {})
            ))
            persisted = stack.enter_context(
                patch.object(generator, "persist_blocked_issue_candidate")
            )
            if coordinated is not None:
                stack.enter_context(patch.object(
                    generator, "generate_coordinated_file_drafts",
                    return_value=coordinated,
                ))
            result = generator.process_finding(error)
        return result, persisted

    # -- item 9: documented use stopped at adjudication ---------------------

    def _documented_use_analysis(self, correct_use=True, reason=(
            "A null KeyStore is the documented request for the platform's "
            "default trust material.")):
        return {
            "decision": "NO_SAFE_FIX",
            "confirmed_cause": "init(null) selects the platform trust store",
            "cause_status": "confirmed",
            "detector_violation": "confirmed",
            "scope_assessment": {"status": "complete"},
            "coordinated_fix_plan": {"required_edits": []},
            "v2": {"adjudication": {
                "decision": "NO_SAFE_FIX",
                "current_code_is_correct_use": correct_use,
                "correct_use_reason": reason,
            }},
        }

    def test_documented_use_is_a_violation_without_security_impact(self):
        # Grocy's MemorizingTrustManager.getTrustManager: adjudication
        # answered NO_SAFE_FIX for TrustManagerFactory.init(null).
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            result, persisted = self._run(
                generator, error, self._documented_use_analysis())
            records = list((Path(directory) / "out" / "no_security_impact")
                           .rglob("*.json"))
            self.assertEqual(len(records), 1)
            record = json.loads(records[0].read_text(encoding="utf-8"))

        self.assertEqual(result.outcome, "abstained")
        self.assertIn("documented request", record["reason"])
        # Only a collateral violation may still be written as an issue.
        persisted.assert_called_once()
        self.assertIs(persisted.call_args.kwargs.get("collateral_only"), True)

    def test_without_the_judgement_the_finding_stays_an_issue(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            _result, persisted = self._run(
                generator, error,
                self._documented_use_analysis(correct_use=False))
            self.assertFalse(
                (Path(directory) / "out" / "no_security_impact").exists())

        persisted.assert_called_once()
        self.assertFalse(persisted.call_args.kwargs.get("collateral_only", False))

    def test_a_call_site_file_the_rebuild_could_not_supply_is_a_pipeline_failure(self):
        # The plan blocked on a caller file the rebuild could not supply: a gap
        # in the pipeline's context, neither "sem impacto" nor an issue.
        analysis = self._documented_use_analysis()
        analysis["v2"]["adjudication"]["blocking_for_generation"] = [{
            "kind": "invalid_patch_plan", "category": "code_evidence_missing",
            "caller_sources_unavailable": ["app/src/ExportExtensions.kt"]}]
        for name, error_extra, record in (
                ("recorded gap", {"caller_source_gap": {
                    "paths": ["app/src/ExportExtensions.kt"], "rebuilt": True,
                    "supplied": [], "unsupplied": ["app/src/ExportExtensions.kt"],
                    "resolved": False}}, self._documented_use_analysis()),
                ("blocker field", {}, analysis)):
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                generator, error = self._harness(directory)
                error.update(error_extra)
                with patch.object(generator, "record_no_security_impact") as no_impact:
                    result, persisted = self._run(generator, error, record)
                failures = list((Path(directory) / "out").rglob("*_pipeline_failure.json"))
                self.assertEqual(len(failures), 1)
                stored = json.loads(failures[0].read_text(encoding="utf-8"))
                self.assertEqual(result.outcome, "abstained")
                no_impact.assert_not_called()
                persisted.assert_not_called()
                self.assertEqual(stored["caller_sources_unavailable"],
                                 ["app/src/ExportExtensions.kt"])

    def test_a_generated_pipeline_failure_is_never_no_security_impact(self):
        # A behaviour-review regression carries correct_use, and the failing
        # paths outside generation_paths also make it a pipeline failure.
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            generation = {"status": "invalid", "correct_use": "documented use",
                          "pipeline_failure": True, "issues": ["caller missing"],
                          "edits": []}
            with patch.object(generator, "record_no_security_impact") as no_impact:
                result, persisted = self._run(
                    generator, error, self._supported_analysis(), coordinated=generation)
            failures = list((Path(directory) / "out").rglob("*_pipeline_failure.json"))
        self.assertEqual(result.outcome, "abstained")
        no_impact.assert_not_called()
        persisted.assert_not_called()
        self.assertEqual(len(failures), 1)

    def test_drafts_failing_only_checks_on_themselves_are_no_maintainer_issue(self):
        # Audit of 2026-10-31: Ursa's sessionPinnedClient (an API the draft
        # widened) and Trigger's createKeyPair (the reported value untouched)
        # became maintainer issues about drafts the pipeline had refused.
        for name, issues, shortfall in (
                ("draft checks only", ["UNNECESSARY_PUBLIC_API_EXPANSION",
                                       "RENAME_REFERENCES_NOT_UPDATED"], True),
                ("a regression the review named", ["UNNECESSARY_PUBLIC_API_EXPANSION",
                                                   "UNINTENDED_BEHAVIOR_CHANGE"], False),
                ("a stored value", ["STORED_DERIVED_VALUE_CHANGED"], False),
                ("free text", ["case policy requires a test-file edit"], False)):
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                generator, error = self._harness(directory)
                stale = Path(directory) / "out/issue_candidates/app.apk/0_getCipher_issue.json"
                stale.parent.mkdir(parents=True)
                stale.write_text("{}", encoding="utf-8")
                result, persisted = self._run(
                    generator, error, self._supported_analysis(),
                    coordinated={"status": "invalid", "issues": issues, "edits": []})
                records = list((Path(directory) / "out" / "generation_shortfall").rglob("*.json"))
                self.assertEqual(result.outcome, "abstained")
                self.assertEqual(len(records), int(shortfall))
                # Only a collateral violation may still reach the maintainer.
                persisted.assert_called_once()
                self.assertEqual(bool(persisted.call_args.kwargs.get("collateral_only")),
                                 shortfall)
                if shortfall:
                    stored = json.loads(records[0].read_text(encoding="utf-8"))
                    self.assertEqual(stored["generation_blockers"], issues)
                    self.assertFalse(stale.exists())

    def test_a_planner_abstaining_after_a_promotion_is_no_maintainer_issue(self):
        # Audit of 2026-10-31: Trigger's decodePublic was promoted to a
        # reviewable fix, the planner found no edit, and the issue asked the
        # maintainer "Is there a constraint I may be missing?".
        def analysis(correct_use=False, violation="confirmed", abstained=True):
            record = self._documented_use_analysis(correct_use=correct_use)
            record["detector_violation"] = violation
            if abstained:
                record["v2"]["adjudication"]["planner_abstained_after_review_promotion"] = {
                    "promotions": ["evidence_gap"], "reason": "no edit keeps ED25519 working"}
            return record

        for name, record, recorded, collateral_only in (
                ("abstained after a promotion", analysis(), True, True),
                ("no promotion", analysis(abstained=False), False, False),
                ("not confirmed", analysis(violation="not_confirmed"), False, False)):
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                generator, error = self._harness(directory)
                result, persisted = self._run(generator, error, record)
                records = list((Path(directory) / "out" / "confirmed_without_safe_fix")
                               .rglob("*.json"))
                self.assertEqual(result.outcome, "abstained")
                self.assertEqual(len(records), int(recorded))
                if recorded:
                    stored = json.loads(records[0].read_text(encoding="utf-8"))
                    self.assertEqual(stored["reason"], "no edit keeps ED25519 working")
                self.assertFalse((Path(directory) / "out" / "no_security_impact").exists())
                persisted.assert_called_once()
                self.assertEqual(bool(persisted.call_args.kwargs.get("collateral_only")),
                                 collateral_only)
        # The correct-use judgement, when given, still comes first.
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            self._run(generator, error, analysis(correct_use=True))
            self.assertTrue((Path(directory) / "out" / "no_security_impact").exists())
            self.assertFalse((Path(directory) / "out" / "confirmed_without_safe_fix").exists())

    # -- Q1: a blocked violation without a confirmed impact ------------------

    def _impact_analysis(self, impact, correct_use=False):
        record = self._documented_use_analysis(correct_use=correct_use)
        if impact is not None:
            record["runtime_security_impact"] = impact
        return record

    def _route(self, record, spec=None):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            if spec:
                error["spec"] = spec
            result, persisted = self._run(generator, error, record)
            out = Path(directory) / "out"
            stored = [json.loads(path.read_text(encoding="utf-8")) for path in
                      (out / "confirmed_without_safe_fix").rglob("*.json")]
            no_impact = (out / "no_security_impact").exists()
        self.assertEqual(result.outcome, "abstained")
        return stored, no_impact, persisted

    def test_a_blocked_violation_without_a_confirmed_impact_is_no_maintainer_issue(self):
        # 2026-11-10: 17 of the 47 production issues were a NO_SAFE_FIX or an
        # external contract whose impact the adjudication did not confirm.
        for impact in ("not_established", "non_security", "unknown"):
            with self.subTest(impact):
                stored, no_impact, persisted = self._route(self._impact_analysis(impact))
                self.assertEqual(len(stored), 1)
                self.assertEqual(stored[0]["kind"], "no_safe_fix")
                self.assertEqual(stored[0]["reason"],
                                 "init(null) selects the platform trust store")
                self.assertFalse(no_impact)
                persisted.assert_called_once()
                self.assertIs(persisted.call_args.kwargs.get("collateral_only"), True)
        not_confirmed = self._impact_analysis("not_established")
        not_confirmed["detector_violation"] = "not_confirmed"
        gate_turned = self._impact_analysis("not_established")
        gate_turned["v2"]["adjudication"]["decision"] = "SAFE_INTERNAL_DIGEST_MIGRATION"
        planned = self._impact_analysis("not_established")
        planned["coordinated_fix_plan"]["required_edits"] = [
            {"source_file_path": "src/A.java", "change": "x"}]
        for name, record in (("confirmed", self._impact_analysis("confirmed")),
                             ("no field", self._impact_analysis(None)),
                             ("violation not confirmed", not_confirmed),
                             ("a gate's NO_SAFE_FIX", gate_turned),
                             ("a planned edit", planned)):
            with self.subTest(name):
                stored, _no_impact, persisted = self._route(record)
                self.assertEqual(stored, [])
                if name in ("confirmed", "no field"):
                    persisted.assert_called_once()
                    self.assertFalse(persisted.call_args.kwargs.get("collateral_only", False))

    def test_an_external_contract_without_a_confirmed_impact_is_recorded_as_one(self):
        def analysis(impact):
            record = self._impact_analysis(impact)
            record["decision"] = "EXTERNAL_DIGEST_CONTRACT_NO_CLIENT_ONLY_FIX"
            record["v2"]["adjudication"]["decision"] = (
                "EXTERNAL_DIGEST_CONTRACT_NO_CLIENT_ONLY_FIX")
            record["digest_contract_assessment"] = {
                "contract_kind": "external", "backend_change_required": True,
                "client_only_change_safe": False,
                "expected_digest_source": "the third-party API fixes MD5"}
            return record

        stored, _no_impact, persisted = self._route(
            analysis("not_established"), spec="MessageDigestSpec")
        self.assertEqual([item["kind"] for item in stored], ["external_contract"])
        self.assertIs(persisted.call_args.kwargs.get("collateral_only"), True)
        stored, _no_impact, persisted = self._route(
            analysis("confirmed"), spec="MessageDigestSpec")
        self.assertEqual(stored, [])
        persisted.assert_called_once()
        self.assertFalse(persisted.call_args.kwargs.get("collateral_only", False))

    def test_a_planner_abstention_ends_the_same_with_or_without_a_promotion(self):
        # Without a promotion: the planner's own words, not the validator's.
        record = self._impact_analysis("not_established")
        record["v2"]["adjudication"]["blocking_for_generation"] = [{
            "kind": "invalid_patch_plan",
            "description": "supported adjudication requires at least one planned edit"}]
        record["v2"]["patch_plan"] = {"generation_blockers": [
            "no edit keeps ED25519 working",
            "supported adjudication requires at least one planned edit"]}
        stored, _no_impact, persisted = self._route(record)
        self.assertEqual([item["reason"] for item in stored], ["no edit keeps ED25519 working"])
        self.assertIs(persisted.call_args.kwargs.get("collateral_only"), True)

        def promoted(impact):
            record = self._impact_analysis(impact)
            record["v2"]["adjudication"]["planner_abstained_after_review_promotion"] = {
                "promotions": ["evidence_gap"], "reason": "no edit keeps ED25519 working"}
            return record

        stored, _no_impact, persisted = self._route(promoted("not_established"))
        self.assertEqual([item["reason"] for item in stored], ["no edit keeps ED25519 working"])
        self.assertIs(persisted.call_args.kwargs.get("collateral_only"), True)
        # MeloX run_v5 (2026-11-09): a confirmed impact reaches the maintainer.
        stored, _no_impact, persisted = self._route(promoted("confirmed"))
        self.assertEqual(stored, [])
        persisted.assert_called_once()
        self.assertFalse(persisted.call_args.kwargs.get("collateral_only", False))

    def test_correct_use_needs_a_non_security_impact(self):
        for impact, closes, recorded in (("non_security", True, False),
                                         ("confirmed", False, False),
                                         ("not_established", False, True),
                                         (None, True, False)):
            with self.subTest(impact):
                stored, no_impact, persisted = self._route(
                    self._impact_analysis(impact, correct_use=True))
                self.assertEqual(no_impact, closes)
                self.assertEqual(len(stored), int(recorded))
                if impact == "confirmed":
                    self.assertFalse(persisted.call_args.kwargs.get("collateral_only", False))

    def test_documented_use_comes_before_the_blocked_violation(self):
        stored, no_impact, _persisted = self._route(
            self._impact_analysis("non_security", correct_use=True))
        self.assertTrue(no_impact)
        self.assertEqual(stored, [])

    def test_a_digest_a_public_standard_fixes_is_no_maintainer_issue(self):
        # Xtra (audit of 2026-10-31): RFC 6455's Sec-WebSocket-Accept SHA-1
        # became an issue asking for an endpoint change.
        def analysis(violation="confirmed", edits=()):
            return {"decision": "NON_SECURITY_HASH_USAGE", "cause_status": "confirmed",
                    "confirmed_cause": "RFC 6455 section 4.2.2 fixes SHA-1 for the key",
                    "detector_violation": violation,
                    "scope_assessment": {"status": "complete"},
                    "coordinated_fix_plan": {"required_edits": list(edits)},
                    "v2": {"adjudication": {"decision": "NON_SECURITY_HASH_USAGE",
                                            "generation_status": "blocked"}}}

        for name, record, settled in (
                ("confirmed", analysis(), True),
                ("not confirmed", analysis(violation="not_confirmed"), False)):
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                generator, error = self._harness(directory)
                error["spec"] = "MessageDigestSpec"
                result, persisted = self._run(generator, error, record)
                records = list((Path(directory) / "out" / "no_security_impact").rglob("*.json"))
                self.assertEqual(len(records), int(settled))
                if settled:
                    self.assertIn("RFC 6455", json.loads(
                        records[0].read_text(encoding="utf-8"))["reason"])
                persisted.assert_called_once()
                self.assertEqual(bool(persisted.call_args.kwargs.get("collateral_only")),
                                 settled)

    def test_a_finding_settled_before_analysis_costs_no_model_call(self):
        # 2026-10-31: Grocy's load/save rerun while our #1013 was open, Fread's
        # buildSSLFactory while #168 was; each paid a full analysis.
        from cognalys.llm import finding_processing

        url = "https://github.com/o/a/pull/7"
        for name, earlier, base, commit, kind in (
                ("open", {"pull_request": url, "state": "open", "created_at": "x"}, {}, None,
                 "open_pull_request"),
                ("merged after the analysed commit", {
                    "pull_request": url, "state": "merged",
                    "created_at": "2026-10-24T00:00:00Z"}, {}, "2026-10-01T00:00:00+00:00",
                 "merged_pull_request"),
                ("file absent", {}, {"target_present": False, "base_branch": "main",
                                     "source_file_path": "src/PwsFile.java"}, None,
                 "file_absent_from_base")):
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                generator, error = self._harness(directory)
                error["contribution_base"] = base
                with patch("cognalys.prs.outcome_report.earlier_pull_request_for",
                           return_value=earlier), \
                        patch.object(finding_processing, "_analysed_commit_date",
                                     return_value=finding_processing._instant(commit or "")), \
                        patch.object(generator, "adjudicate_finding") as adjudicate:
                    result = generator.process_finding(error)
                adjudicate.assert_not_called()
                [record] = list((Path(directory) / "out" / "settled_before_analysis")
                                .rglob("*.json"))
                stored = json.loads(record.read_text(encoding="utf-8"))
                self.assertEqual(result.outcome, "not_applicable")
                self.assertEqual(stored["kind"], kind)
        # Merged before the analysed commit: the analysis says whether it came back.
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            with patch("cognalys.prs.outcome_report.earlier_pull_request_for", return_value={
                    "pull_request": url, "state": "merged",
                    "created_at": "2026-09-01T00:00:00Z"}), \
                    patch.object(finding_processing, "_analysed_commit_date",
                                 return_value=finding_processing._instant("2026-10-01T00:00:00Z")):
                self.assertEqual(finding_processing.settled_before_analysis(error, []), {})

    def test_a_joined_unit_is_settled_only_when_every_finding_has_a_pull_request(self):
        # Review of batch 14 (2026-10-31): a new `save` joined to `load`, whose
        # PR was open, was skipped as "PR já aberto" for a PR not covering it.
        import hashlib

        from cognalys.llm import finding_processing

        def record(directory, uid, method, number):
            created = Path(directory) / f"x_{method}_KeyStoreSpec_pr_created.json"
            created.write_text(json.dumps({"state": "open",
                                           "created_at": "2026-10-20T00:00:00Z"}),
                               encoding="utf-8")
            return (created, {"finding_id": hashlib.sha256(uid.encode()).hexdigest()[:12]},
                    f"https://github.com/o/r/pull/{number}")

        unit = {"unique_error_id": "NEW", "method_name": "save", "spec": "KeyStoreSpec",
                "source_file_path": "src/K.java", "repository_url": "https://github.com/o/r",
                "joint_findings": [{"unique_error_id": "OLD", "method": "load",
                                    "specification": "KeyStoreSpec"}]}
        with tempfile.TemporaryDirectory() as directory:
            outcomes = Path(directory) / "outcomes"
            only_old = [record(directory, "OLD", "load", 5)]
            self.assertEqual(finding_processing.settled_before_analysis(
                unit, only_old, outcomes), {})
            both = only_old + [record(directory, "NEW", "save", 6)]
            self.assertEqual(finding_processing.settled_before_analysis(
                unit, both, outcomes)["kind"], "open_pull_request")

    def test_a_shortfall_whose_statement_left_the_base_keeps_that_record(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            error["contribution_base"] = {"reported_statement_present": False,
                                          "source_file_path": "src/PwsFile.java"}
            result, persisted = self._run(
                generator, error, self._supported_analysis(),
                coordinated={"status": "invalid", "issues": ["STATEMENT_WITHOUT_EFFECT"],
                             "edits": []})
            self.assertFalse((Path(directory) / "out" / "generation_shortfall").exists())
        persisted.assert_called_once()

    @staticmethod
    def _with_question(analysis, category="maintainer_decision", discharged=False):
        analysis = json.loads(json.dumps(analysis))
        analysis.setdefault("v2", {}).setdefault("adjudication", {})[
            "blocking_for_publication"] = [{
                "kind": "LAN trust model", "category": category,
                "description": "Decide whether self-signed LAN servers stay supported.",
                "discharged_by_pipeline_validation": discharged}]
        return analysis

    def test_mechanical_draft_shape_failures_are_no_maintainer_issue(self):
        # Input Leaf (2026-11-05) asked its maintainer about "draft path
        # differs from requested path; file draft contains no edits", and
        # Cryptomator Lite (2026-11-04) about an edit that moved a brace.
        shape = ["draft path differs from requested path", "file draft contains no edits"]
        brace = ["original_code must occur exactly once",
                 "edit changes the brace scope of the code after it: line 191 ('}') "
                 "would move from brace depth 2 to 1"]
        mixed = ["UNNECESSARY_PUBLIC_API_EXPANSION: made public",
                 "delete edit must have exactly empty corrected_code"]
        supported = self._supported_analysis()
        for name, issues, analysis, kind in (
                ("shape", shape, supported, "draft_shape"),
                ("brace", brace, supported, "draft_shape"),
                ("draft code and shape", mixed, supported, "draft_shape"),
                ("a maintainer question", shape, self._with_question(supported), ""),
                ("a question the build settles", shape,
                 self._with_question(supported, discharged=True), "draft_shape"),
                ("a note", shape,
                 self._with_question(supported, category="rename_authorization"),
                 "draft_shape"),
                ("the generator abstained", shape + ["coordinated generation abstained"],
                 supported, "")):
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                generator, error = self._harness(directory)
                result, persisted = self._run(
                    generator, error, analysis,
                    coordinated={"status": "invalid", "issues": issues, "edits": []})
                records = list((Path(directory) / "out" / "generation_shortfall").rglob("*.json"))
                self.assertEqual(result.outcome, "abstained")
                self.assertEqual(len(records), int(bool(kind)))
                persisted.assert_called_once()
                self.assertEqual(bool(persisted.call_args.kwargs.get("collateral_only")),
                                 bool(kind))
                if kind:
                    stored = json.loads(records[0].read_text(encoding="utf-8"))
                    self.assertEqual(stored["shortfall_kind"], kind)
                    self.assertEqual(stored["generation_blockers"], issues)

    def test_an_assembled_draft_failing_only_shape_checks_is_no_maintainer_issue(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            generated = self._supported_generation(untestable=False)
            generated["edits"][1]["corrected_code"] = generated["edits"][1]["original_code"]
            result, persisted = self._run(generator, error, self._supported_analysis(),
                                          coordinated=generated)
            [record] = list((Path(directory) / "out" / "generation_shortfall").rglob("*.json"))
            stored = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(result.outcome, "abstained")
        persisted.assert_called_once()
        self.assertIs(persisted.call_args.kwargs.get("collateral_only"), True)
        self.assertEqual(stored["shortfall_kind"], "draft_shape")
        self.assertTrue(any(item.startswith("no-op edit for src/Other.java")
                            for item in stored["generation_blockers"]))

    def test_a_scope_gap_the_pipeline_could_close_is_no_maintainer_issue(self):
        # Winterhold's derive (2026-11-07 and the baseline's run_v3), Zen
        # Companion's diskKey and Xtra's WebSocket digest: a supported fix
        # whose only blockers were the analysis' own incomplete scope became
        # an issue for the maintainer.
        from cognalys.llm import finding_processing

        gap = ["scope_assessment.status must be complete",
               "scope_assessment.local_code_scope must be complete",
               "scope assessment did not review required files: src/Other.java",
               "structural repository scope is incomplete"]
        review = self._supported_analysis("MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        for name, issues, analysis, shortfall in (
                ("scope only", gap, review, True),
                ("a maintainer question", gap, self._with_question(review), False),
                ("a blocking relation", gap + [
                    "scope_assessment has generation-blocking relations"], review, False),
                ("cause not confirmed", gap, dict(review, cause_status="inferred"), False),
                ("not reportable", gap, dict(review, detector_violation="not_confirmed"),
                 False)):
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                generator, error = self._harness(directory)
                with patch.object(finding_processing, "validate_multi_file_scope",
                                  return_value=list(issues)), \
                        patch.object(generator, "generate_coordinated_file_drafts") as drafts:
                    result, persisted = self._run(generator, error, analysis)
                records = list((Path(directory) / "out" / "generation_shortfall").rglob("*.json"))
                drafts.assert_not_called()
                self.assertEqual(result.outcome, "abstained")
                self.assertEqual(len(records), int(shortfall))
                persisted.assert_called_once()
                # Only a collateral violation may still reach the maintainer.
                self.assertEqual(bool(persisted.call_args.kwargs.get("collateral_only")),
                                 shortfall)
                if shortfall:
                    stored = json.loads(records[0].read_text(encoding="utf-8"))
                    self.assertEqual(stored["shortfall_kind"], "scope_gap")

    def test_every_listed_shortfall_message_is_one_the_pipeline_writes(self):
        """MECHANICAL_DRAFT_MESSAGES and SCOPE_GAP_MESSAGES name messages
        other modules write; a reworded message would silently become an
        issue again."""
        import re

        from cognalys.llm import fix_generation_common

        source = "\n".join(path.read_text(encoding="utf-8") for path in (
            Path(fix_generation_common.__file__).parent).glob("*.py")
            if path.name != "fix_generation_common.py")
        for pattern in (fix_generation_common.MECHANICAL_DRAFT_MESSAGES
                        + fix_generation_common.SCOPE_GAP_MESSAGES):
            literal = re.sub(r"\\w\+ ", "", pattern).replace("\\.", ".")
            with self.subTest(pattern):
                self.assertIn(literal, source)

    def test_the_judgement_applies_only_where_it_can(self):
        from cognalys.llm.finding_processing import (  # noqa: PLC0415
            documented_use_without_security_impact,
        )
        self.assertTrue(documented_use_without_security_impact(
            self._documented_use_analysis()))
        planned = self._documented_use_analysis()
        planned["coordinated_fix_plan"]["required_edits"] = [
            {"source_file_path": "src/PwsFile.java", "symbol": "getCipher"}]
        unconfirmed = dict(self._documented_use_analysis(), cause_status="inferred")
        # A decision the pipeline turned into NO_SAFE_FIX keeps its issue.
        external = self._documented_use_analysis()
        external["v2"]["adjudication"]["decision"] = (
            "EXTERNAL_DIGEST_CONTRACT_NO_CLIENT_ONLY_FIX")
        # A violation adjudication did not confirm stays a false positive or
        # insufficient evidence, never a violation without impact.
        not_confirmed = dict(self._documented_use_analysis(),
                             detector_violation="not_confirmed")
        unknown = dict(self._documented_use_analysis(),
                       detector_violation="unknown")
        for name, analysis in (
                ("planned edits", planned),
                ("unconfirmed cause", unconfirmed),
                ("no reason", self._documented_use_analysis(reason="  ")),
                ("external decision", external),
                ("violation not confirmed", not_confirmed),
                ("violation unknown", unknown)):
            with self.subTest(name):
                self.assertEqual(
                    documented_use_without_security_impact(analysis), "")

    # -- item 5: a supported plan whose test the pipeline ruled untestable --

    def _supported_analysis(self, decision="MULTI_FILE_FIX_SUPPORTED"):
        return {
            "decision": decision,
            "confirmed_cause": "SHA-1 discriminates in-process note state",
            "cause_status": "confirmed",
            "detector_violation": "confirmed",
            "scope_assessment": {"status": "complete"},
            "coordinated_fix_plan": {"required_edits": [
                {"source_file_path": "src/PwsFile.java", "symbol": "sha1"},
                {"source_file_path": "src/Other.java", "symbol": "value"},
            ]},
            "dependency_fix_assessment": {
                "compatibility_constraints_satisfied": True,
                "fork_or_vcs_dependency": False,
                "official_migration_source": "https://example.invalid/notes",
            },
            # The plan planned a test; a draft without one is missing it.
            "v2": {"patch_plan": {
                "publication_blockers": ["confirm SHA-256 provider availability"],
                "required_tests": ["the discriminator changes when the note does"]}},
        }

    def _supported_generation(self, decision="MULTI_FILE_FIX_SUPPORTED",
                              untestable=True):
        return {
            "status": "complete", "decision": decision,
            "review_contract_version": 1,
            "explanation": "SHA-256 replaces SHA-1",
            "edits": [_edit("src/PwsFile.java", "method"),
                      _edit("src/Other.java")],
            "required_tests": [], "review_assumptions": [],
            "manual_review_required": False, "confidence": "high",
            "skipped_planned_files": [{
                "source_file_path": "src/androidTest/DigestTest.kt",
                "reason": "test_cannot_exercise",
                "detail": "an instrumented test is compiled but never run "
                          "by the validation",
            }] if untestable else [],
        }

    def _with_required_test(self, error):
        error = dict(error)
        error["case_migration_policy"] = {
            "required_tests": ["the discriminator changes when the note does"]}
        return error

    def test_an_untestable_supported_plan_is_generated_for_review(self):
        # Orgzly's MiscUtils.sha1 (2026-10-25): rejected only because its
        # one planned test was an androidTest.
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            result, _ = self._run(
                generator, self._with_required_test(error),
                self._supported_analysis(), self._supported_generation())
            evidence = json.loads(next(
                (Path(directory) / "out" / "evidence_reviews")
                .rglob("*_evidence.json")).read_text(encoding="utf-8"))

        self.assertTrue(result.success)
        # The persisted evidence review says what the solution says.
        self.assertEqual(evidence["status"], "PROPOSED_FIX_REQUIRES_REVIEW")
        self.assertEqual(evidence["analysis"]["decision"],
                         "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(evidence["analysis"]["demoted_from"],
                         "MULTI_FILE_FIX_SUPPORTED")
        metadata = result.solution["solution_metadata"]
        self.assertEqual(metadata["fix_scope"], "review_only")
        self.assertEqual(metadata["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertTrue(metadata["manual_review_required"])
        self.assertEqual(result.decision, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        notes = " ".join(metadata["review_assumptions"])
        self.assertIn("No automated test accompanies this patch", notes)
        self.assertIn("never run", notes)
        self.assertIn("confirm SHA-256 provider availability", notes)

    def test_a_test_missing_for_another_reason_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            result, persisted = self._run(
                generator, self._with_required_test(error),
                self._supported_analysis(),
                self._supported_generation(untestable=False))

        self.assertIsNone(result.solution)
        self.assertEqual(result.outcome, "abstained")
        self.assertEqual(result.decision, "MULTI_FILE_FIX_SUPPORTED")
        blockers = persisted.call_args.args[5]
        self.assertIn("case policy requires at least one concrete "
                      "test-file edit", blockers)

    def test_a_salvaged_draft_no_review_judged_is_still_rejected(self):
        # _without_rejected_new_tests keeps the production change after every
        # generated test failed the test-quality checks; no behaviour review
        # judged what is left, so a supported plan does not ship it.
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            generation = self._supported_generation(untestable=False)
            del generation["review_contract_version"]
            generation["dropped_generated_tests"] = ["src/test/DigestTest.kt"]
            result, persisted = self._run(
                generator, self._with_required_test(error),
                self._supported_analysis(), generation)

        self.assertIsNone(result.solution)
        self.assertEqual(result.decision, "MULTI_FILE_FIX_SUPPORTED")
        self.assertIn("case policy requires at least one concrete "
                      "test-file edit", persisted.call_args.args[5])

    def test_a_reviewed_draft_whose_test_held_every_regression_goes_to_review(self):
        # LocalSend's loadOrCreateKeyStore (2026-10-29): the generated test was
        # dropped for a regression only it had, and the draft that ships was
        # reviewed again; it goes to review, saying why it has no test.
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            generation = self._supported_generation(untestable=False)
            generation["dropped_generated_tests"] = ["src/androidTest/StoreTest.kt"]
            generation["dropped_generated_tests_reason"] = (
                "the behaviour review found the generated test fails on its own")
            result, persisted = self._run(
                generator, self._with_required_test(error),
                self._supported_analysis(), generation)

        self.assertTrue(result.success)
        persisted.assert_not_called()
        metadata = result.solution["solution_metadata"]
        self.assertEqual(metadata["fix_scope"], "review_only")
        self.assertIn("No automated test accompanies this patch (the behaviour review "
                      "found the generated test fails on its own)",
                      " ".join(metadata["review_assumptions"]))

    def _review_dropped_the_test(self, directory, generation, unrelated):
        draft = Path(directory) / "draft"
        draft.mkdir(exist_ok=True)
        (draft / "behavior_review.json").write_text(json.dumps(
            {"review_contract_version": 4, "regressions": [],
             "unrelated_test_edits": unrelated}), encoding="utf-8")
        generation["manifest"] = str(draft / "manifest.json")

    def test_a_supported_draft_whose_test_the_review_dropped_goes_to_review(self):
        # NotallyX's md5Hash (2026-10-29): the review found no regression and
        # dropped the only test edit as asserting what MD5 already did; the
        # supported draft then lost to "requires a test-file edit" and became
        # an issue.
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            generation = self._supported_generation(untestable=False)
            self._review_dropped_the_test(
                directory, generation, ["app/src/test/kotlin/a/IOExtensionsTest.kt"])
            result, persisted = self._run(
                generator, self._with_required_test(error),
                self._supported_analysis(), generation)

        self.assertTrue(result.success)
        persisted.assert_not_called()
        self.assertEqual(result.decision, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        metadata = result.solution["solution_metadata"]
        self.assertEqual(metadata["fix_scope"], "review_only")
        self.assertTrue(metadata["manual_review_required"])
        notes = " ".join(metadata["review_assumptions"])
        self.assertIn("No automated test accompanies this patch (the behaviour "
                      "review found the generated tests assert behaviour the "
                      "change does not alter)", notes)
        self.assertIn("the discriminator changes when the note does", notes)

    def test_a_review_that_dropped_only_production_or_nothing_still_rejects(self):
        # No test left out on purpose: the supported draft is held to its
        # test as before.
        for name, unrelated in (("nothing dropped", []),
                                ("production path", ["src/main/java/a/Prod.java"])):
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                generator, error = self._harness(directory)
                generation = self._supported_generation(untestable=False)
                self._review_dropped_the_test(directory, generation, unrelated)
                result, persisted = self._run(
                    generator, self._with_required_test(error),
                    self._supported_analysis(), generation)
                self.assertIsNone(result.solution)
                self.assertEqual(result.decision, "MULTI_FILE_FIX_SUPPORTED")
                self.assertIn("case policy requires at least one concrete "
                              "test-file edit", persisted.call_args.args[5])

    def _plan_without_a_test(self, required_edits=()):
        analysis = self._supported_analysis()
        analysis["v2"]["patch_plan"]["required_tests"] = []
        analysis["v2"]["patch_plan"]["required_edits"] = [
            {"source_file_path": path, "symbol": "value"} for path in required_edits]
        return analysis

    def test_a_supported_plan_that_planned_no_test_goes_to_review(self):
        # NotallyX's md5Hash and Orgzly's sha1 (2026-10-29): the replanned
        # SHA-256 change planned no test, as the plan prompt allows for a
        # value replacement; the reviewed draft without regressions then lost
        # to the policy's required_tests and became an issue.
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            generation = self._supported_generation(untestable=False)
            self._review_dropped_the_test(directory, generation, [])
            result, persisted = self._run(
                generator, self._with_required_test(error),
                self._plan_without_a_test(["src/PwsFile.java", "src/Other.java"]),
                generation)

        self.assertTrue(result.success)
        persisted.assert_not_called()
        self.assertEqual(result.decision, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        metadata = result.solution["solution_metadata"]
        self.assertTrue(metadata["manual_review_required"])
        notes = " ".join(metadata["review_assumptions"])
        self.assertIn("No automated test accompanies this patch (the plan found "
                      "no unit test that observes this change)", notes)
        self.assertIn("the discriminator changes when the note does", notes)

    def test_a_plan_whose_test_is_an_edit_or_unknown_still_rejects(self):
        # A test path among the planned edits is a planned test; a plan that
        # does not say what it planned is not read as planning none.
        no_tests_key = self._supported_analysis()
        del no_tests_key["v2"]["patch_plan"]["required_tests"]
        for name, analysis in (
                ("test path planned", self._plan_without_a_test(
                    ["src/PwsFile.java", "app/src/test/java/a/DigestTest.kt"])),
                ("no required_tests key", no_tests_key)):
            with self.subTest(name), tempfile.TemporaryDirectory() as directory:
                generator, error = self._harness(directory)
                result, persisted = self._run(
                    generator, self._with_required_test(error), analysis,
                    self._supported_generation(untestable=False))
                self.assertIsNone(result.solution)
                self.assertEqual(result.decision, "MULTI_FILE_FIX_SUPPORTED")
                self.assertIn("case policy requires at least one concrete "
                              "test-file edit", persisted.call_args.args[5])

    def test_a_dropped_test_beside_an_unreviewed_draft_still_rejects(self):
        # The review file sits beside a draft no review judged (salvaged).
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            generation = self._supported_generation(untestable=False)
            del generation["review_contract_version"]
            self._review_dropped_the_test(
                directory, generation, ["src/test/DigestTest.kt"])
            result, persisted = self._run(
                generator, self._with_required_test(error),
                self._supported_analysis(), generation)

        self.assertIsNone(result.solution)
        self.assertIn("case policy requires at least one concrete "
                      "test-file edit", persisted.call_args.args[5])

    def _routed_case(self, directory, assumptions=()):
        generator, error = self._harness(directory)
        analysis = self._supported_analysis("FIX_SUPPORTED")
        # The plan edits a caller besides the reported method, so the digest
        # decision is generated as a reviewable change.
        analysis["coordinated_fix_plan"]["required_edits"] = [
            {"source_file_path": "src/PwsFile.java", "symbol": "getCipher"},
            {"source_file_path": "src/Other.java", "symbol": "value"}]
        analysis["review_assumptions"] = list(assumptions)
        generation = self._supported_generation(
            "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", untestable=False)
        # What the per-file generator returns for a review-only decision.
        generation["manual_review_required"] = True
        self._review_dropped_the_test(directory, generation, [])
        result, persisted = self._run(
            generator, self._with_required_test(error), analysis, generation)
        return result, persisted

    def test_a_decision_routed_to_review_is_held_to_the_review_test_rule(self):
        # Orgzly's MiscUtils.sha1 (frozen run, 2026-11-13): adjudicated
        # SAFE_INTERNAL_DIGEST_MIGRATION (FIX_SUPPORTED takes the same route),
        # routed to review because the plan
        # edits a caller; the clean-reviewed draft was refused by the test
        # gate as if the supported decision still held.
        with tempfile.TemporaryDirectory() as directory:
            result, persisted = self._routed_case(
                directory, ["confirm stored note hashes are recomputed"])

        self.assertTrue(result.success)
        persisted.assert_not_called()
        self.assertEqual(result.decision, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        metadata = result.solution["solution_metadata"]
        self.assertEqual(metadata["fix_scope"], "review_only")
        self.assertTrue(metadata["manual_review_required"])
        notes = " ".join(metadata["review_assumptions"])
        # The missing test is a note for the reviewer, not a refusal.
        self.assertIn("Before merging", notes)
        self.assertIn("the discriminator changes when the note does", notes)

    def test_a_routed_decision_without_assumptions_states_the_routing(self):
        # No assumption from the adjudication or the drafts: the reason the
        # pipeline routed it to review is what the reviewer is told.
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            analysis = self._supported_analysis("FIX_SUPPORTED")
            analysis["coordinated_fix_plan"]["required_edits"] = [
                {"source_file_path": "src/PwsFile.java", "symbol": "getCipher"},
                {"source_file_path": "src/Other.java", "symbol": "value"}]
            generation = self._supported_generation(
                "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", untestable=False)
            generation["manual_review_required"] = True
            result, persisted = self._run(generator, error, analysis, generation)

        self.assertTrue(result.success)
        persisted.assert_not_called()
        notes = " ".join(result.solution["solution_metadata"]["review_assumptions"])
        self.assertIn("beyond the reported method", notes)
        self.assertIn("src/Other.java", notes)

    def test_a_dependency_decision_keeps_its_label(self):
        decision = "DEPENDENCY_FIX_SUPPORTED"
        with tempfile.TemporaryDirectory() as directory:
            generator, error = self._harness(directory)
            result, persisted = self._run(
                generator, self._with_required_test(error),
                self._supported_analysis(decision),
                self._supported_generation(decision))

        self.assertIsNone(result.solution)
        self.assertEqual(result.decision, decision)
        self.assertIn("case policy requires at least one concrete "
                      "test-file edit", persisted.call_args.args[5])

    # -- item 15(a): a planned test the behaviour review dropped ------------

    TEST_FILE = "src/test/PwsFileTest.java"

    def _plan_with_test(self, directory):
        generator, error = self._harness(directory)
        test_file = Path(error["repository_path"]) / self.TEST_FILE
        test_file.parent.mkdir(parents=True)
        test_file.write_text("class PwsFileTest {}", encoding="utf-8")
        analysis = {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "confirmed_cause": "AES/CTR does not authenticate ciphertext",
            "cause_status": "confirmed",
            "detector_violation": "confirmed",
            "scope_assessment": {"status": "complete"},
            "coordinated_fix_plan": {"required_edits": [
                {"source_file_path": "src/PwsFile.java", "symbol": "getCipher"},
                {"source_file_path": "src/Other.java", "symbol": "value"},
                {"source_file_path": self.TEST_FILE, "symbol": "verifies"},
            ]},
        }
        generation = {
            "status": "complete",
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "explanation": "coordinated fix",
            "edits": [_edit("src/PwsFile.java", "method"),
                      _edit("src/Other.java")],
            "required_tests": [],
            "review_assumptions": ["reviewer confirms the callers"],
            "manual_review_required": True, "confidence": "medium",
        }
        return generator, error, analysis, generation

    @staticmethod
    def _shortfall_blockers(directory):
        [record] = list((Path(directory) / "out" / "generation_shortfall").rglob("*.json"))
        return json.loads(record.read_text(encoding="utf-8"))["generation_blockers"]

    def _persist_review(self, directory, generation, unrelated):
        draft = Path(directory) / "draft"
        draft.mkdir(exist_ok=True)
        (draft / "behavior_review.json").write_text(json.dumps(
            {"unrelated_test_edits": unrelated}), encoding="utf-8")
        generation["manifest"] = str(draft / "manifest.json")

    def test_a_test_edit_the_review_dropped_is_not_required_back(self):
        # Cryptomator (2026-10-24): the review dropped DoLicenseCheckTest's
        # Mockito verifications as testing nothing the change touched.
        with tempfile.TemporaryDirectory() as directory:
            generator, error, analysis, generation = self._plan_with_test(directory)
            self._persist_review(directory, generation, [self.TEST_FILE])
            generation["review_contract_version"] = 1
            result, _ = self._run(generator, error, analysis, generation)

        self.assertTrue(result.success)

    def test_the_drafts_own_record_of_dropped_tests_is_read_first(self):
        """Winterhold run_v6 (2026-11-10): the path that drops the test records it."""
        from cognalys.llm.finding_processing import behavior_review_dropped_tests

        self.assertEqual(behavior_review_dropped_tests({
            "manifest": "/no/such/draft/manifest.json",
            "dropped_unrelated_tests": [self.TEST_FILE, "src/main/java/Prod.java"]}),
            [self.TEST_FILE])
        with tempfile.TemporaryDirectory() as directory:
            generation = {"review_contract_version": 1,
                          "dropped_unrelated_tests": [self.TEST_FILE]}
            self._persist_review(directory, generation, ["src/test/Other.java"])
            self.assertEqual(behavior_review_dropped_tests(generation), [self.TEST_FILE])

    def test_a_review_of_another_attempt_drops_nothing(self):
        # A salvaged draft shares the draft directory with earlier attempts;
        # the review persisted there judged other edits.
        with tempfile.TemporaryDirectory() as directory:
            generator, error, analysis, generation = self._plan_with_test(directory)
            self._persist_review(directory, generation, [self.TEST_FILE])
            generation["dropped_generated_tests"] = ["src/test/NewTest.java"]
            result, persisted = self._run(generator, error, analysis, generation)
            blockers = self._shortfall_blockers(directory)

        self.assertIsNone(result.solution)
        # A plan file the drafts left uncovered is the pipeline's shortfall,
        # not a maintainer issue (generation_shortfall); only a collateral
        # violation may still reach the maintainer.
        self.assertIs(persisted.call_args.kwargs.get("collateral_only"), True)
        self.assertIn("generated edits do not cover the required plan", blockers)

    def test_a_planned_test_nobody_dropped_is_still_required(self):
        with tempfile.TemporaryDirectory() as directory:
            generator, error, analysis, generation = self._plan_with_test(directory)
            result, persisted = self._run(generator, error, analysis, generation)
            blockers = self._shortfall_blockers(directory)

        self.assertIsNone(result.solution)
        self.assertIs(persisted.call_args.kwargs.get("collateral_only"), True)
        self.assertIn("generated edits do not cover the required plan", blockers)

    def test_only_test_files_count_as_dropped(self):
        from cognalys.llm.finding_processing import (  # noqa: PLC0415
            behavior_review_dropped_tests,
        )
        with tempfile.TemporaryDirectory() as directory:
            generation = {"review_contract_version": 1}
            self._persist_review(directory, generation, [
                self.TEST_FILE, "src/main/java/a/Prod.java"])
            self.assertEqual(behavior_review_dropped_tests(generation),
                             [self.TEST_FILE])
        self.assertEqual(behavior_review_dropped_tests({}), [])
        self.assertEqual(behavior_review_dropped_tests(
            {"manifest": "/nonexistent/draft/manifest.json",
             "review_contract_version": 1}), [])
