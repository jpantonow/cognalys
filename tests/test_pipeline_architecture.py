import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)
from _reviewed_shapes import reviewed_false_positive_shapes  # noqa: E402

from cognalys.extraction.sink_reachability import (  # noqa: E402
    _passed_identifiers,
    reaches_security_sink,
    sink_reachability_in_source,
)
from cognalys.llm.pipeline_architecture import (  # noqa: E402
    FindingEvidencePacketBuilder,
    PolicyRegistry,
    adjudication_schema,
    blocked_finding_review_status,
    canonical_hash,
    case_scoped_specification_context,
    enforced_input_size_evidence,
    manifest_component_evidence,
    specification_is_externally_anchored,
    classify_spec_family,
    confirmed_false_positive_reason,
    detector_arity_overmatch_reason,
    detector_matching_research_question,
    false_positive_rationale,
    fields_reached_through_accessors,
    shared_state_mutation_evidence,
    parameterless_governed_methods,
    unconstrained_arity_matcher,
    verified_detector_semantics,
    unmodelled_calls_in_source,
    security_sink_evidence,
    detector_message_is_absent,
    discharge_analyzer_acceptance,
    evidence_extraction_schema,
    governed_api_types,
    non_literal_getinstance_arguments,
    observed_call_sequence,
    planned_replacement_values,
    reported_violation,
    sanitize_evidence_extraction,
    DECISIONS,
    message_names_dependency,
    promote_human_decided_blockers_to_review,
    route_unsettled_compatibility_to_review,
    target_source_completeness,
    dismissal_justification_issues,
    route_non_security_repair_to_review,
    validate_adjudication,
    validate_adjudication_of,
    validate_evidence_extraction,
)
from cognalys.utils.disposition import (  # noqa: E402
    CLASSIFICATION_DECISIONS,
    POLICY_DECISIONS,
    REPAIR_DECISIONS,
    REVIEW_ONLY_DECISIONS,
)


class PacketCoherenceTests(unittest.TestCase):
    """What the packet says about its own contents, and about the message."""

    def test_an_empty_target_is_not_complete(self):
        empty = [{"kind": "target_method", "data": {"content": ""}}]
        self.assertEqual(target_source_completeness(empty), "missing")
        present = [{"kind": "target_source", "data": {"content": "class A {}"}}]
        self.assertEqual(target_source_completeness(present), "complete")
        self.assertEqual(target_source_completeness([]), "unknown")

    def test_a_message_names_a_dependency_by_artifact_or_group(self):
        okhttp = {"group": "com.squareup.okhttp3", "artifact": "okhttp"}
        self.assertTrue(message_names_dependency(
            "OkHttp 3.12.0 is outdated; use 4.12.0", okhttp))
        self.assertTrue(message_names_dependency(
            "okhttp3.internal.platform.Platform uses TLSv1", okhttp))

    def test_an_unrelated_message_names_no_dependency(self):
        self.assertFalse(message_names_dependency(
            "OutOfMemoryError: Java heap space while generating 4K video "
            "thumbnail.",
            {"group": "com.github.SimpleMobileTools",
             "artifact": "Simple-Commons"},
        ))
        self.assertFalse(message_names_dependency(
            "SecurityException: Permission denial reading external storage.",
            {"group": "org.kiwix", "artifact": "libkiwix"},
        ))
        self.assertFalse(message_names_dependency("anything", {}))


class DecisionVocabularyTests(unittest.TestCase):
    """The named decision sets and the non-security routing."""

    def test_the_named_sets_partition_the_schema_decisions(self):
        groups = [REPAIR_DECISIONS, REVIEW_ONLY_DECISIONS, POLICY_DECISIONS,
                  CLASSIFICATION_DECISIONS, frozenset({"NO_SAFE_FIX"})]
        self.assertEqual(sum(len(group) for group in groups), len(DECISIONS))
        self.assertEqual(frozenset().union(*groups), frozenset(DECISIONS))

    CONFIRMED = {
        "decision": "CONFIRMED_SPEC_VIOLATION_NON_SECURITY_USAGE",
        "generation_status": "supported_for_review",
        "detector_violation": "confirmed",
        "cause_status": "confirmed",
        "confirmed_cause": "a final field written once is read unlocked",
        "decision_claim_ids": ["C-001"],
        "blocking_for_generation": [],
    }
    EXTRACTION = {"claims": [{"claim_id": "C-001"}]}

    def test_a_non_security_repair_is_kept_under_review(self):
        adjudication = dict(self.CONFIRMED, generation_status="supported")
        replaced = route_non_security_repair_to_review(adjudication)
        self.assertEqual(
            replaced, "CONFIRMED_SPEC_VIOLATION_NON_SECURITY_USAGE")
        self.assertEqual(
            adjudication["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(
            adjudication["generation_status"], "supported_for_review")
        self.assertEqual(
            validate_adjudication_of(
                adjudication, self.EXTRACTION,
                {"error_message": "expected a monitor"}),
            [],
        )

    def test_a_classification_without_generation_is_left_alone(self):
        adjudication = dict(self.CONFIRMED, generation_status="blocked")
        self.assertEqual(route_non_security_repair_to_review(adjudication), "")
        self.assertEqual(
            adjudication["decision"],
            "CONFIRMED_SPEC_VIOLATION_NON_SECURITY_USAGE")

    def test_an_unconfirmed_violation_is_not_routed(self):
        adjudication = dict(self.CONFIRMED, detector_violation="not_confirmed")
        self.assertEqual(route_non_security_repair_to_review(adjudication), "")

    def _blocked(self, *categories, **extra):
        base = {
            "decision": "NO_SAFE_FIX",
            "generation_status": "blocked",
            "publication_status": "blocked",
            "cause_status": "confirmed",
            "confirmed_cause": "notes are encrypted with DES/ECB",
            "detector_violation": "confirmed",
            "scope_status": "complete",
            "decision_claim_ids": ["C-001"],
            "blocking_for_generation": [
                {"kind": f"k{index}", "category": category,
                 "description": "d", "supporting_claim_ids": ["C-001"]}
                for index, category in enumerate(categories)
            ],
            "blocking_for_publication": [],
        }
        base.update(extra)
        return base

    FINDING = {"error_message": "expecting AES but found DES"}

    def test_blockers_only_a_reviewer_settles_become_a_review_patch(self):
        adjudication = self._blocked(
            "compatibility_contract", "maintainer_decision",
            "runtime_behavior")
        moved = promote_human_decided_blockers_to_review(
            adjudication, self.EXTRACTION, self.FINDING)
        self.assertEqual(moved, [
            "compatibility_contract", "maintainer_decision",
            "runtime_behavior"])
        self.assertEqual(
            adjudication["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(
            adjudication["generation_status"], "supported_for_review")
        self.assertEqual(adjudication["publication_status"], "blocked")
        self.assertEqual(adjudication["blocking_for_generation"], [])
        self.assertEqual(len(adjudication["blocking_for_publication"]), 3)
        self.assertTrue(all(
            item["discharged_by_pipeline_validation"] is False
            for item in adjudication["blocking_for_publication"]))

    def _orgzly_shaped(self):
        """Orgzly's sha1 (2026-10-25): review-only, held only by a rename."""
        return self._blocked(
            decision="MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            generation_status="supported_for_review",
            blocking_for_generation=[],
            blocking_for_publication=[{
                "kind": "rename_safety_authorization", "category": "rename_authorization",
                "description": "A reviewer must approve the rename of the weak-named helper.",
                "supporting_claim_ids": ["C-001"],
                "discharged_by_pipeline_validation": False}],
            authorized_behavior_change={
                "authorized": False, "policy_reference": "rename_safety",
                "description": "the rename needs a separate authorization"},
        )

    def test_a_refusal_not_tied_to_the_rename_stays_a_refusal(self):
        # Only a structured field ties a refusal to the rename; one about the
        # cache keys every installed copy wrote is a compatibility refusal,
        # even when the rename blocker was the only one filed.
        from cognalys.llm.adjudication_rules import discharge_rename_authorization_blockers

        for reference in ("case_policy", ""):
            with self.subTest(reference=reference):
                adjudication = self._orgzly_shaped()
                adjudication["publication_status"] = "blocked"
                adjudication["authorized_behavior_change"] = {
                    "authorized": False, "policy_reference": reference,
                    "description": "Changing the digest from SHA-1 to SHA-256 changes "
                                   "the cache keys every installed copy already wrote."}
                moved = discharge_rename_authorization_blockers(
                    adjudication, self.EXTRACTION, self.FINDING)
                self.assertEqual([item["kind"] for item in moved],
                                 ["rename_safety_authorization"])
                self.assertIs(adjudication["authorized_behavior_change"]["authorized"], False)
                self.assertNotIn("refusal_discharged_as_rename_note",
                                 adjudication["authorized_behavior_change"])
                self.assertEqual(adjudication["publication_status"], "blocked")

    def test_a_rename_blocker_becomes_a_publication_note_whatever_rename_safety_says(self):
        from cognalys.llm.adjudication_rules import (
            discharge_rename_authorization_blockers, human_decided_publication_considerations)

        # rename_safety allowed the rename (Orgzly) or refused it: the answer
        # is the same, because a refused rename changes the route, never
        # whether there is a patch.
        for allowed in (True, False):
            with self.subTest(allowed=allowed):
                adjudication = self._orgzly_shaped()
                adjudication["rename_safety_allowed"] = allowed
                moved = discharge_rename_authorization_blockers(
                    adjudication, self.EXTRACTION, self.FINDING)
                self.assertEqual([item["kind"] for item in moved],
                                 ["rename_safety_authorization"])
                self.assertEqual(adjudication["blocking_for_publication"], [])
                self.assertEqual(adjudication["discharged_blockers"][0]["moved_from"],
                                 "blocking_for_publication")
                self.assertEqual(adjudication["publication_status"], "eligible_after_validation")
                # The refusal could only have been about the rename: a note too.
                self.assertTrue(adjudication["authorized_behavior_change"]["authorized"])
                notes = human_decided_publication_considerations(
                    {"v2": {"adjudication": adjudication}})
                self.assertEqual({note["category"] for note in notes}, {"rename_authorization"})
                self.assertEqual(validate_adjudication_of(
                    adjudication, self.EXTRACTION, self.FINDING), [])

    def test_a_rename_generation_blocker_never_stops_a_confirmed_fix(self):
        from cognalys.llm.adjudication_rules import discharge_rename_authorization_blockers

        adjudication = self._blocked("rename_authorization")
        discharge_rename_authorization_blockers(adjudication, self.EXTRACTION, self.FINDING)
        self.assertEqual(adjudication["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(adjudication["generation_status"], "supported_for_review")
        self.assertEqual(adjudication["blocking_for_generation"], [])

    def test_other_blockers_stand_beside_a_discharged_rename_blocker(self):
        from cognalys.llm.adjudication_rules import discharge_rename_authorization_blockers

        adjudication = self._blocked("rename_authorization", "code_evidence_missing")
        discharge_rename_authorization_blockers(adjudication, self.EXTRACTION, self.FINDING)
        self.assertEqual(adjudication["decision"], "NO_SAFE_FIX")
        self.assertEqual([item["category"] for item in adjudication["blocking_for_generation"]],
                         ["code_evidence_missing"])
        # Only the structured category moves: the same words under another
        # category are not read.
        prose = self._blocked("maintainer_decision")
        prose["blocking_for_generation"][0]["description"] = "rename authorization missing"
        self.assertEqual(discharge_rename_authorization_blockers(prose), [])

    def test_the_schema_offers_the_rename_category(self):
        category = adjudication_schema("message_digest")["properties"][
            "blocking_for_publication"]["items"]["properties"]["category"]
        self.assertIn("rename_authorization", category["enum"])

    def test_a_policy_decision_is_promoted_too(self):
        adjudication = self._blocked(
            "maintainer_decision", decision="MULTI_FILE_FIX_REQUIRES_POLICY")
        self.assertTrue(promote_human_decided_blockers_to_review(
            adjudication, self.EXTRACTION, self.FINDING))

    def test_missing_source_keeps_generation_blocked(self):
        adjudication = self._blocked(
            "compatibility_contract", "code_evidence_missing")
        before = dict(adjudication)
        self.assertEqual(promote_human_decided_blockers_to_review(
            adjudication, self.EXTRACTION, self.FINDING), [])
        self.assertEqual(adjudication, before)

    def test_a_record_without_categories_is_not_promoted(self):
        adjudication = self._blocked("maintainer_decision")
        for item in adjudication["blocking_for_generation"]:
            del item["category"]
        self.assertEqual(promote_human_decided_blockers_to_review(
            adjudication, self.EXTRACTION, self.FINDING), [])

    def test_a_documented_false_positive_is_never_promoted(self):
        # A matched shape is answered not_confirmed, and that is never promoted.
        adjudication = dict(self._blocked("maintainer_decision"),
                            detector_violation="not_confirmed")
        self.assertEqual(promote_human_decided_blockers_to_review(
            adjudication, self.EXTRACTION, self.FINDING), [])
        self.assertEqual(adjudication["decision"], "NO_SAFE_FIX")

    def test_unconfirmed_or_incomplete_findings_are_not_promoted(self):
        for extra in ({"cause_status": "unknown"},
                      {"detector_violation": "not_confirmed"},
                      {"scope_status": "incomplete"},
                      {"decision_claim_ids": []}):
            adjudication = self._blocked("maintainer_decision", **extra)
            self.assertEqual(promote_human_decided_blockers_to_review(
                adjudication, self.EXTRACTION, self.FINDING), [], extra)

    def test_dependency_decisions_keep_their_semantics(self):
        adjudication = self._blocked(
            "maintainer_decision", decision="DEPENDENCY_FIX_REQUIRES_POLICY")
        self.assertEqual(promote_human_decided_blockers_to_review(
            adjudication, self.EXTRACTION, self.FINDING), [])
        adjudication = self._blocked("maintainer_decision")
        self.assertEqual(promote_human_decided_blockers_to_review(
            adjudication, self.EXTRACTION, self.FINDING,
            family="dependency"), [])

    def test_a_promotion_that_fails_validation_is_discarded(self):
        # source_established with a rendered message is not allowed.
        adjudication = self._blocked(
            "maintainer_decision", detector_violation="source_established")
        self.assertEqual(promote_human_decided_blockers_to_review(
            adjudication, self.EXTRACTION, self.FINDING), [])
        self.assertEqual(adjudication["decision"], "NO_SAFE_FIX")

    def test_a_correct_use_answer_is_promoted_for_a_single_round(self):
        # AntennaPod's AntennaPodSslSocketFactory.<init> (misuse5 run_v2):
        # promoted twice, six drafts and a replan, the same "sem impacto".
        adjudication = self._blocked(
            "compatibility_contract", current_code_is_correct_use=True,
            correct_use_reason="SSLContext.init documents a null KeyManager[] "
                               "as the platform default key managers.")
        self.assertTrue(promote_human_decided_blockers_to_review(
            adjudication, self.EXTRACTION, self.FINDING))
        self.assertEqual(
            adjudication["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertIs(adjudication["single_round"], True)

    def test_without_a_correct_use_reason_the_promotion_is_unchanged(self):
        for extra in ({}, {"current_code_is_correct_use": True},
                      {"current_code_is_correct_use": False,
                       "correct_use_reason": "documented"}):
            adjudication = self._blocked("compatibility_contract", **extra)
            self.assertTrue(promote_human_decided_blockers_to_review(
                adjudication, self.EXTRACTION, self.FINDING), extra)
            self.assertNotIn("single_round", adjudication, extra)

    def _unsettled(self, **extra):
        # org.bombusmod's baosFromBase64 (run_20260915_175048): every answer
        # confirmed the cause; only the generation claim was rejected.
        base = {
            "decision": "FIX_SUPPORTED",
            "generation_status": "supported",
            "publication_status": "blocked",
            "cause_status": "confirmed",
            "confirmed_cause": (
                "baosFromBase64 closes a local ByteArrayOutputStream before "
                "returning it"),
            "detector_violation": "confirmed",
            "compatibility_status": "regression_risk",
            "scope_status": "complete",
            "decision_claim_ids": ["C-001"],
            "blocking_for_generation": [],
            "blocking_for_publication": [],
        }
        base.update(extra)
        return base

    def test_a_confirmed_repair_with_unsettled_compatibility_goes_to_review(self):
        adjudication = self._unsettled()
        issues = validate_adjudication_of(
            adjudication, self.EXTRACTION, self.FINDING)
        self.assertEqual(
            issues, ["automatic generation requires preserved compatibility"])
        self.assertTrue(route_unsettled_compatibility_to_review(
            adjudication, issues, self.EXTRACTION, self.FINDING))
        self.assertEqual(
            adjudication["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(
            adjudication["generation_status"], "supported_for_review")
        self.assertEqual(adjudication["publication_status"], "blocked")
        self.assertEqual(adjudication["cause_status"], "confirmed")
        blocker = adjudication["blocking_for_publication"][0]
        self.assertEqual(blocker["category"], "compatibility_contract")
        self.assertIs(blocker["discharged_by_pipeline_validation"], False)
        self.assertEqual(validate_adjudication_of(
            adjudication, self.EXTRACTION, self.FINDING), [])

    def test_reviewer_blockers_listed_for_generation_move_to_publication(self):
        adjudication = self._unsettled(
            generation_status="supported_for_review",
            blocking_for_generation=[{
                "kind": "caller_contract", "category": "compatibility_contract",
                "description": "callers may rely on the closed stream",
                "supporting_claim_ids": ["C-001"],
            }],
        )
        issues = validate_adjudication_of(
            adjudication, self.EXTRACTION, self.FINDING)
        self.assertIn("supported decision has generation blockers", issues)
        self.assertTrue(route_unsettled_compatibility_to_review(
            adjudication, issues, self.EXTRACTION, self.FINDING))
        self.assertEqual(adjudication["blocking_for_generation"], [])
        self.assertIn("caller_contract", [
            item["kind"] for item in adjudication["blocking_for_publication"]])

    def test_any_other_objection_keeps_the_adjudication_as_it_was(self):
        adjudication = self._unsettled(decision_claim_ids=[])
        issues = validate_adjudication_of(
            adjudication, self.EXTRACTION, self.FINDING)
        before = json.loads(json.dumps(adjudication))
        self.assertFalse(route_unsettled_compatibility_to_review(
            adjudication, issues, self.EXTRACTION, self.FINDING))
        self.assertEqual(adjudication, before)

    def test_a_blocker_no_reviewer_can_settle_is_not_routed(self):
        adjudication = self._unsettled(blocking_for_generation=[{
            "kind": "k", "category": "code_evidence_missing",
            "description": "d", "supporting_claim_ids": ["C-001"],
        }])
        issues = validate_adjudication_of(
            adjudication, self.EXTRACTION, self.FINDING)
        self.assertFalse(route_unsettled_compatibility_to_review(
            adjudication, issues, self.EXTRACTION, self.FINDING))
        self.assertEqual(adjudication["decision"], "FIX_SUPPORTED")

    def test_a_documented_false_positive_is_not_routed(self):
        # A matched shape is answered not_confirmed, and that is never routed.
        adjudication = dict(self._unsettled(), detector_violation="not_confirmed")
        issues = validate_adjudication_of(
            adjudication, self.EXTRACTION, self.FINDING)
        self.assertFalse(route_unsettled_compatibility_to_review(
            adjudication, issues, self.EXTRACTION, self.FINDING))

    def test_the_schema_asks_for_a_blocker_category(self):
        blocker = adjudication_schema("generic")["properties"][
            "blocking_for_generation"]["items"]
        self.assertIn("category", blocker["required"])
        self.assertIn(
            "maintainer_decision", blocker["properties"]["category"]["enum"])

    def test_the_schema_asks_whether_the_current_use_is_documented(self):
        # Grocy's TrustManagerFactory.init(null): the model's judgement that
        # decides "violação sem impacto" over an issue (finding_processing).
        for family in ("generic", "tls", "dependency"):
            with self.subTest(family=family):
                schema = adjudication_schema(family)
                self.assertIn("current_code_is_correct_use", schema["required"])
                self.assertIn("correct_use_reason", schema["required"])
                self.assertEqual(
                    schema["properties"]["current_code_is_correct_use"]["type"],
                    "boolean")

    def test_the_review_route_still_needs_a_confirmed_cause(self):
        adjudication = dict(self.CONFIRMED, cause_status="unknown")
        route_non_security_repair_to_review(adjudication)
        self.assertIn(
            "supported decision requires confirmed cause",
            validate_adjudication_of(
                adjudication, self.EXTRACTION,
                {"error_message": "expected a monitor"}),
        )


class PipelineArchitectureTests(unittest.TestCase):
    def _error(self):
        return {
            "unique_error_id": "finding-1",
            "spec": "javax.net.ssl.SSLContextSpec",
            "error_message": "predicate failed",
            "source_file_path": "src/main/java/A.java",
            "method_name": "connect",
            "method_body": "void connect() {}",
            "expanded_repository_context": {
                "multi_file_impact": {
                    "exact_candidate_sources": [{
                        "source_file_path": "src/main/java/A.java",
                        "content": "A" * 17000,
                        "relevance": ["target"],
                    }, {
                        "source_file_path": "src/main/java/Unrelated.java",
                        "content": "U" * 17000,
                        "relevance": ["lexical"],
                    }],
                    "semantic_resolution": {
                        "status": "available",
                        "resolved_callers": [{
                            "path": "src/main/java/Caller.java", "line": 8,
                            "resolved_symbol_id": "A#connect/0",
                        }],
                        "ambiguous_calls": [], "parse_error_files": [],
                    },
                    "direct_callers": [{"path": "raw-lexical.java"}],
                    "scope_completeness": {"status": "complete", "reasons": []},
                }
            },
        }

    def test_packet_is_stable_and_never_silently_truncates_mandatory_source(self):
        error = self._error()
        policy = PolicyRegistry(ROOT / "data" / "llm_policies").select(
            "tls", error["spec"]
        )
        builder = FindingEvidencePacketBuilder(16000)
        first = builder.build(error, policy)
        second = builder.build(error, policy)
        self.assertEqual(canonical_hash(first), canonical_hash(second))
        self.assertEqual(first["evidence_catalog"][0]["evidence_id"], "SRC-001")
        self.assertTrue(first["evidence_catalog"][0]["mandatory"])
        self.assertEqual(
            first["diagnostic_evidence"]["evidence_id"], "DET-001"
        )
        self.assertTrue(first["diagnostic_evidence"]["informational_only"])
        self.assertEqual(
            first["diagnostic_evidence"]["decision_authority"], "none"
        )
        self.assertNotIn(
            "DET-001",
            {item["evidence_id"] for item in first["evidence_catalog"]},
        )
        self.assertGreater(
            first["selection_metrics"]["budget_exceeded_by_mandatory_evidence"], 0
        )
        exclusions = json.dumps(first["excluded_evidence"])
        self.assertIn("rank_below_repository_context_budget", exclusions)
        self.assertIn("superseded_by_semantic_resolution", exclusions)
        self.assertNotIn("detector_context", first["diagnostic_evidence"]["data"])

    def test_detector_context_reaches_det_001_and_stays_uncitable(self):
        error = self._error()
        error["detector_context"] = {
            "code": "SSLCONTEXT-NOBS-05", "label": "application-manager",
        }
        policy = PolicyRegistry(ROOT / "data" / "llm_policies").select(
            "tls", error["spec"]
        )
        packet = FindingEvidencePacketBuilder(16000).build(error, policy)
        self.assertEqual(
            packet["diagnostic_evidence"]["data"]["detector_context"],
            error["detector_context"],
        )
        self.assertNotIn(
            "DET-001",
            {item["evidence_id"] for item in packet["evidence_catalog"]},
        )

    def test_confirmed_claim_requires_known_evidence(self):
        packet = {"evidence_catalog": [{"evidence_id": "SRC-001"}]}
        invalid = {
            "claims": [{
                "claim_id": "C-1", "statement": "fact",
                "epistemic_status": "confirmed", "evidence_ids": ["SRC-999"],
            }],
            "predicate_assessment": [],
        }
        issues = validate_evidence_extraction(invalid, packet)
        self.assertTrue(any("unknown evidence" in issue for issue in issues))

    def test_available_specification_is_a_citable_mandatory_evidence_item(self):
        error = self._error()
        error["specification_context"] = {
            "status": "available",
            "spec_id": "MessageDigestSpec",
            "source_verified": True,
            "detector_semantics": {
                "predicates": [
                    'algorithm in {"SHA-256", "SHA-384", "SHA-512"}'
                ]
            },
        }
        policy = PolicyRegistry(ROOT / "data" / "llm_policies").select(
            "message_digest", "MessageDigestSpec"
        )

        packet = FindingEvidencePacketBuilder(16000).build(error, policy)

        spec = next(
            item for item in packet["evidence_catalog"]
            if item["evidence_id"] == "SPEC-001"
        )
        self.assertTrue(spec["mandatory"])
        self.assertEqual(spec["trust_level"], "verified_primary_specification")

    def test_a_vendored_target_is_reported_as_a_placement_signal(self):
        error = self._error()
        error["source_file_path"] = "app/thirdparty/java/other/Vendored.java"
        error["expanded_repository_context"]["multi_file_impact"][
            "exact_candidate_sources"
        ] = [{
            "source_file_path": "app/thirdparty/java/other/Vendored.java",
            "content": (
                "// COPIED FROM https://example.org/upstream/V.java"
                + chr(10) + "class Vendored {}"
            ),
            "relevance": ["reported finding location"],
        }]
        policy = PolicyRegistry(ROOT / "data" / "llm_policies").select(
            "tls", error["spec"]
        )

        packet = FindingEvidencePacketBuilder(16000).build(error, policy)

        vendored = packet["finding"]["vendored_source"]
        self.assertTrue(vendored["vendored"])
        self.assertEqual(
            vendored["upstream"], "https://example.org/upstream/V.java"
        )
        self.assertTrue(any(
            "thirdparty" in signal for signal in vendored["signals"]
        ))

    def test_ordinary_application_source_carries_no_vendored_signal(self):
        error = self._error()
        policy = PolicyRegistry(ROOT / "data" / "llm_policies").select(
            "tls", error["spec"]
        )

        packet = FindingEvidencePacketBuilder(16000).build(error, policy)

        self.assertNotIn("vendored_source", packet["finding"])

    def test_class_construction_sites_are_citable_evidence(self):
        error = self._error()
        error["expanded_repository_context"]["class_construction_sites"] = [{
            "path": "src/main/java/Document.java",
            "line": 307,
            "snippet": "307: new A(Build.VERSION.SDK_INT, new SecureRandom());",
        }]
        policy = PolicyRegistry(ROOT / "data" / "llm_policies").select(
            "tls", error["spec"]
        )

        packet = FindingEvidencePacketBuilder(60000).build(error, policy)

        construction = next(
            item for item in packet["evidence_catalog"]
            if item["kind"] == "class_construction_site"
        )
        self.assertTrue(construction["evidence_id"].startswith("CTOR-"))
        self.assertIn("SecureRandom", construction["data"]["snippet"])

    def test_supported_ephemeral_discriminator_is_citable_flow_evidence(self):
        error = self._error()
        context = error["expanded_repository_context"]
        context["ephemeral_runtime_discriminator_assessment"] = {
            "supported": True,
            "classification": "ephemeral_runtime_discriminator",
            "blocking_sinks": [],
            "comparison_evidence": [{"path": "Caller.java", "line": 10}],
        }
        context["value_usage_graph"] = {"status": "available"}
        context["repository_call_sites"] = [{"path": "Caller.java", "line": 8}]
        policy = PolicyRegistry(ROOT / "data" / "llm_policies").select(
            "message_digest", "MessageDigestSpec"
        )

        packet = FindingEvidencePacketBuilder(16000).build(error, policy)

        flow = next(
            item for item in packet["evidence_catalog"]
            if item["evidence_id"] == "FLOW-001"
        )
        self.assertTrue(flow["mandatory"])

    def test_test_relation_exposes_canonical_source_path(self):
        error = self._error()
        error["expanded_repository_context"]["multi_file_impact"][
            "exact_candidate_sources"
        ][0]["content"] = "class A {}"
        error["expanded_repository_context"]["multi_file_impact"][
            "exact_candidate_sources"
        ] = error["expanded_repository_context"]["multi_file_impact"][
            "exact_candidate_sources"
        ][:1]
        error["expanded_repository_context"]["tests"] = [{
            "path": "app/src/androidTest/java/example/ExistingTest.java",
            "relevance": "established test source set",
        }]
        policy = PolicyRegistry(ROOT / "data" / "llm_policies").select(
            "tls", error["spec"]
        )
        packet = FindingEvidencePacketBuilder(16000).build(error, policy)
        test_item = next(
            item for item in packet["evidence_catalog"]
            if item["kind"] == "test_context"
        )
        self.assertEqual(
            test_item["data"]["source_file_path"],
            "app/src/androidTest/java/example/ExistingTest.java",
        )

    def test_supported_decision_requires_confirmed_provenance(self):
        extraction = {"claims": [{"claim_id": "C-1"}]}
        adjudication = {
            "decision": "FIX_SUPPORTED", "cause_status": "inferred",
            "confirmed_cause": "", "detector_violation": "unknown",
            "decision_claim_ids": [], "blocking_for_generation": [],
            "publication_status": "blocked", "blocking_for_publication": [],
        }
        issues = validate_adjudication(adjudication, extraction)
        self.assertGreaterEqual(len(issues), 3)

    def test_blocked_status_does_not_conflate_cause_with_violation(self):
        self.assertEqual(
            blocked_finding_review_status({
                "cause_status": "confirmed",
                "confirmed_cause": "source flow is confirmed",
                "detector_violation": "unknown",
            }),
            "CONFIRMED_CAUSE_ONLY_NO_SAFE_FIX",
        )
        self.assertEqual(
            blocked_finding_review_status({
                "cause_status": "confirmed",
                "confirmed_cause": "source flow is confirmed",
                "detector_violation": "confirmed",
            }),
            "CONFIRMED_FINDING_NO_SAFE_FIX",
        )

    def test_confirmed_false_positive_reason_requires_no_app_source(self):
        message = "expecting one of {TLSv1.2, TLSv1.3} but found TLS."
        with reviewed_false_positive_shapes():
            self.assertTrue(confirmed_false_positive_reason(
                "SSLContextSpec", message, True, ""
            ))
        self.assertEqual(confirmed_false_positive_reason(
            "SSLContextSpec", message, True, "app/src/Foo.java"
        ), "")

    def test_confirmed_false_positive_reason_requires_external_class(self):
        message = "expecting one of {TLSv1.2, TLSv1.3} but found TLS."
        self.assertEqual(confirmed_false_positive_reason(
            "SSLContextSpec", message, False, ""
        ), "")

    def test_confirmed_false_positive_reason_requires_exact_message_match(self):
        self.assertEqual(confirmed_false_positive_reason(
            "SSLContextSpec", "unknown", True, ""
        ), "")
        self.assertEqual(confirmed_false_positive_reason(
            "SSLContextSpec",
            "expecting one of {TLSv1.2, TLSv1.3} but found .",
            True, "",
        ), "")

    def test_confirmed_false_positive_reason_requires_curated_spec(self):
        message = "expecting one of {TLSv1.2, TLSv1.3} but found TLS."
        self.assertEqual(confirmed_false_positive_reason(
            "SomeOtherSpec", message, True, ""
        ), "")

    def test_blocked_status_closes_curated_dependency_false_positive(self):
        analysis = {
            "cause_status": "unknown",
            "detector_violation": "unknown",
            "dependency_fix_assessment": {"external_class_confirmed": True},
        }
        arguments = dict(
            spec_id="SSLContextSpec",
            error_message="expecting one of {TLSv1.2, TLSv1.3} but found TLS.",
            app_source_file_path="",
        )
        with reviewed_false_positive_shapes():
            self.assertEqual(blocked_finding_review_status(analysis, **arguments),
                             "CONFIRMED_FALSE_POSITIVE")
        # An unreviewed shape never dismisses (P14): it stays unconfirmed.
        self.assertEqual(blocked_finding_review_status(analysis, **arguments),
                         "UNCONFIRMED_FINDING")

    def test_blocked_status_stays_unconfirmed_when_app_source_exists(self):
        analysis = {
            "cause_status": "unknown",
            "detector_violation": "unknown",
            "dependency_fix_assessment": {"external_class_confirmed": True},
        }
        self.assertEqual(
            blocked_finding_review_status(
                analysis,
                spec_id="SSLContextSpec",
                error_message=(
                    "expecting one of {TLSv1.2, TLSv1.3} but found TLS."
                ),
                app_source_file_path="app/src/Foo.java",
            ),
            "UNCONFIRMED_FINDING",
        )

    def test_blocked_status_ignores_curated_shapes_without_extra_context(self):
        analysis = {
            "cause_status": "unknown",
            "detector_violation": "unknown",
            "dependency_fix_assessment": {"external_class_confirmed": True},
        }
        self.assertEqual(
            blocked_finding_review_status(analysis),
            "UNCONFIRMED_FINDING",
        )

    def test_family_routing_has_specialized_schemas(self):
        self.assertEqual(classify_spec_family("SSLContextSpec"), "tls")
        self.assertEqual(classify_spec_family("MessageDigestSpec"), "message_digest")
        tls = evidence_extraction_schema("tls")
        digest = evidence_extraction_schema("message_digest")
        self.assertIn("generic_context_observed", tls["properties"]["family_assessment"]["properties"])
        self.assertIn("usage_kind", digest["properties"]["family_assessment"]["properties"])
        key_generation = evidence_extraction_schema("key_generation")
        self.assertIn(
            "initialization_status",
            key_generation["properties"]["family_assessment"]["properties"],
        )
        decisions = adjudication_schema("dependency")["properties"]["decision"]["enum"]
        self.assertIn("DEPENDENCY_FIX_SUPPORTED", decisions)

    def test_non_literal_getinstance_argument_is_reported(self):
        body = (
            "SSLContext sslContext = SSLContext.getInstance("
            "TlsVersion.TLS_1_3.javaName());"
        )
        self.assertEqual(
            non_literal_getinstance_arguments(body),
            ["TlsVersion.TLS_1_3.javaName()"],
        )

    def test_plain_and_concatenated_string_literals_are_not_reported(self):
        body = (
            'SSLContext.getInstance("TLS" + "v1.2");\n'
            'KeyStore.getInstance("AndroidKeyStore");'
        )
        self.assertEqual(non_literal_getinstance_arguments(body), [])

    def test_provider_argument_is_ignored_when_algorithm_is_literal(self):
        body = 'MessageDigest.getInstance("SHA-256", provider);'
        self.assertEqual(non_literal_getinstance_arguments(body), [])

    def test_nested_call_expression_is_reported(self):
        body = "KeyStore.getInstance(KeyStore.getDefaultType());"
        self.assertEqual(
            non_literal_getinstance_arguments(body),
            ["KeyStore.getDefaultType()"],
        )

    def test_no_getinstance_call_reports_nothing(self):
        self.assertEqual(
            non_literal_getinstance_arguments("class Foo { void bar() {} }"), []
        )

    def test_results_are_deduplicated_and_bounded(self):
        body = "\n".join(
            f'Mac.getInstance(ALGO_{i});' for i in range(10)
        ) + "\nMac.getInstance(ALGO_0);"
        results = non_literal_getinstance_arguments(body, limit=3)
        self.assertEqual(len(results), 3)
        self.assertEqual(len(set(results)), 3)

    def test_governed_types_ignore_unrelated_getinstance_receiver(self):
        # OfflineManager.getInstance() is an unrelated app-level singleton
        # factory that happens to share the getInstance() name with the
        # CrySL-governed crypto factories this pipeline actually researches.
        body = "OfflineManager mgr = OfflineManager.getInstance(CONFIG);"
        self.assertEqual(
            non_literal_getinstance_arguments(
                body, governed_types=["MessageDigest"]
            ),
            [],
        )

    def test_governed_types_still_match_simple_or_qualified_name(self):
        body = "MessageDigest.getInstance(ALGO);"
        for governed in (["MessageDigest"], ["java.security.MessageDigest"]):
            with self.subTest(governed=governed):
                self.assertEqual(
                    non_literal_getinstance_arguments(
                        body, governed_types=governed
                    ),
                    ["ALGO"],
                )

    def test_no_governed_types_keeps_broad_legacy_matching(self):
        # A specification with no type metadata must not silently lose
        # research coverage: fall back to matching every getInstance() call.
        body = "OfflineManager.getInstance(CONFIG);"
        self.assertEqual(
            non_literal_getinstance_arguments(body, governed_types=[]),
            ["CONFIG"],
        )

    def test_governed_api_types_prefers_applies_to_types_over_fallback(self):
        context = {
            "applies_to_types": ["javax.crypto.Cipher"],
            "generation_evidence": {"expected_api_simple_name": "MessageDigest"},
        }
        self.assertEqual(governed_api_types(context), ["javax.crypto.Cipher"])

    def test_governed_api_types_falls_back_to_expected_api_simple_name(self):
        context = {"generation_evidence": {"expected_api_simple_name": "MessageDigest"}}
        self.assertEqual(governed_api_types(context), ["MessageDigest"])

    def test_case_scoped_unknowns_ask_about_the_governed_api(self):
        """Research questions are about the API, not the reported app.

        They used to name the application class and method and ask whether
        the path through them was "feasible at runtime and has
        security-relevant impact". No primary source can answer that -- the
        same prompt forbids inspecting repository behaviour -- and phrased
        that way it reads as an exploitability assessment of a named
        product, which a provider refused on 2026-09-07 after ten minutes of
        web search. What the adjudication consumes is the documented
        contract of the governed API, so that is what is asked.
        """
        context = {
            "unknowns": ["generic spec-level question"],
            "applies_to_types": ["java.security.MessageDigest"],
            "generation_evidence": {"detector_examples": ["unrelated example"]},
        }
        first = case_scoped_specification_context(context, {
            "finding_id": "F-1",
            "error_message": "SHA-1 used to hash a request identifier",
            "target": {"class": "AeSimpleSHA1", "method": "getSHA1"},
        })
        second = case_scoped_specification_context(context, {
            "finding_id": "F-2",
            "error_message": "MD5 used for a cache key",
            "target": {"class": "CacheKeyBuilder", "method": "buildKey"},
        })

        for scoped in (first, second):
            for question in scoped["unknowns"]:
                self.assertIn("java.security.MessageDigest", question)
            # No question asks the open web about the reported application.
            self.assertNotIn(
                "AeSimpleSHA1", " ".join(scoped["unknowns"])
            )
            self.assertNotIn(
                "CacheKeyBuilder", " ".join(scoped["unknowns"])
            )

        # The finding's own message still distinguishes one case from
        # another, and the target it belongs to is still recorded.
        self.assertNotEqual(first["unknowns"], second["unknowns"])
        self.assertIn(
            "SHA-1 used to hash a request identifier", first["unknowns"][0]
        )
        self.assertIn("MD5 used for a cache key", second["unknowns"][0])
        self.assertEqual(
            first["case_scope"]["target"],
            {"class": "AeSimpleSHA1", "method": "getSHA1"},
        )
        self.assertNotIn(
            "detector_examples", first.get("generation_evidence", {})
        )
        # The original context (and its unrelated cross-finding examples)
        # must not be mutated by scoping it for one finding.
        self.assertIn("detector_examples", context["generation_evidence"])

    def test_a_specification_is_anchored_only_with_a_source_and_a_type(self):
        anchored = {
            "source_verified": True,
            "applies_to_types": ["javax.crypto.Cipher"],
        }
        self.assertTrue(specification_is_externally_anchored(anchored))
        # SQLInjectionSpec's shape: its source_url answered 404, and its one
        # applies_to_types entry is a class that does not exist.
        self.assertFalse(specification_is_externally_anchored({
            "source_verified": False,
            "applies_to_types": ["com.owncloud.android.providers.SQLInjection"],
        }))
        self.assertFalse(specification_is_externally_anchored({
            "source_verified": True, "applies_to_types": [],
        }))
        self.assertFalse(specification_is_externally_anchored(None))

    def test_sanitize_extraction_strips_det001_without_discarding_valid_claims(self):
        packet = {
            "evidence_catalog": [{"evidence_id": "SRC-001"}],
            "external_evidence_catalog": [],
        }
        extraction = {
            "claims": [
                {
                    "claim_id": "C-1", "statement": "SHA-1 is used literally",
                    "epistemic_status": "confirmed", "evidence_ids": ["SRC-001"],
                },
                {
                    "claim_id": "C-2", "statement": "detector says so",
                    "epistemic_status": "confirmed", "evidence_ids": ["DET-001"],
                },
            ],
            "predicate_assessment": [{
                "predicate": "uses_secure_algorithm", "status": "violated",
                "evidence_ids": ["SRC-001", "DET-001"], "explanation": "",
            }],
        }
        sanitized, notes = sanitize_evidence_extraction(extraction, packet)
        self.assertTrue(notes)
        c1 = next(c for c in sanitized["claims"] if c["claim_id"] == "C-1")
        c2 = next(c for c in sanitized["claims"] if c["claim_id"] == "C-2")
        self.assertEqual(c1["epistemic_status"], "confirmed")
        self.assertEqual(c1["evidence_ids"], ["SRC-001"])
        self.assertEqual(c2["epistemic_status"], "unknown")
        self.assertEqual(c2["evidence_ids"], [])
        predicate = sanitized["predicate_assessment"][0]
        self.assertEqual(predicate["status"], "violated")
        self.assertEqual(predicate["evidence_ids"], ["SRC-001"])
        self.assertEqual(validate_evidence_extraction(sanitized, packet), [])

    def test_sanitize_extraction_drops_malformed_entries_individually(self):
        packet = {"evidence_catalog": [{"evidence_id": "SRC-001"}]}
        extraction = {
            "claims": [
                "not-an-object",
                {"claim_id": "", "statement": "no id"},
                {"claim_id": "C-1", "statement": "kept", "evidence_ids": []},
                {"claim_id": "C-1", "statement": "duplicate", "evidence_ids": []},
            ],
            "predicate_assessment": [],
        }
        sanitized, notes = sanitize_evidence_extraction(extraction, packet)
        self.assertEqual(len(sanitized["claims"]), 1)
        self.assertEqual(sanitized["claims"][0]["statement"], "kept")
        self.assertEqual(len(notes), 3)


class ReportedViolationTests(unittest.TestCase):
    """The detector names the predicate even when it renders no message.

    95 of the 133 sampled candidates (71%) arrive with message "unknown",
    every one of them an InvalidSequenceOfMethodCalls. The type was always
    present inside unique_error_id, which the pipeline carried verbatim and
    never read.
    """

    def test_recovers_the_predicate_from_the_finding_id(self):
        self.assertEqual(
            reported_violation({"unique_error_id": (
                "p.Crypto:::encrypt:::CipherSpec:::"
                "InvalidSequenceOfMethodCalls:::unknown"
            )}),
            "InvalidSequenceOfMethodCalls",
        )

    def test_returns_empty_for_a_finding_id_without_a_predicate(self):
        for value in ("", "not-a-structured-id", "a:::b:::c"):
            with self.subTest(value=value):
                self.assertEqual(
                    reported_violation({"unique_error_id": value}), ""
                )

    def test_a_rendered_message_still_carries_its_predicate(self):
        self.assertEqual(
            reported_violation({"unique_error_id": (
                "p.K:::generateKey:::KeyPairGeneratorSpec:::"
                "InvalidKeySize:::invalid key size for algorithm DSA."
            )}),
            "InvalidKeySize",
        )


class ObservedCallSequenceTests(unittest.TestCase):
    """The observed sequence must describe the calls, not the spec's overloads.

    enrich_spec_context records one occurrence per modelled event, and several
    events share an api_pattern because they differ only by overload: a single
    `.update(` matches UpdateByte, UpdateByteArray, UpdateByteArrayRange and
    UpdateByteBuffer. Listing each as its own step would tell the analysis
    there are four calls where the source has one.
    """

    def _context(self, events):
        return {"specification_context": {
            "protocol": "Get, Update*, Digest",
            "observed_source_events": events,
        }}

    def test_one_call_matching_several_overloads_is_a_single_position(self):
        sequence = observed_call_sequence(self._context([
            {"event": "Get", "observed": True, "occurrences": [
                {"pattern": "MessageDigest.getInstance(", "method_line": 3}]},
            {"event": "UpdateByte", "observed": True, "occurrences": [
                {"pattern": ".update(", "method_line": 8}]},
            {"event": "UpdateByteArray", "observed": True, "occurrences": [
                {"pattern": ".update(", "method_line": 8}]},
        ]))
        self.assertEqual(len(sequence), 2)
        self.assertTrue(sequence[0]["unambiguous"])
        self.assertEqual(sequence[0]["event"], "Get")
        self.assertFalse(sequence[1]["unambiguous"])
        self.assertEqual(
            sequence[1]["candidate_events"], ["UpdateByte", "UpdateByteArray"]
        )

    def test_positions_are_ordered_by_source_line(self):
        sequence = observed_call_sequence(self._context([
            {"event": "Digest", "observed": True, "occurrences": [
                {"pattern": ".digest(", "method_line": 11}]},
            {"event": "Get", "observed": True, "occurrences": [
                {"pattern": ".getInstance(", "method_line": 3}]},
        ]))
        self.assertEqual([item["event"] for item in sequence], ["Get", "Digest"])

    def test_unobserved_events_are_left_out(self):
        sequence = observed_call_sequence(self._context([
            {"event": "Init", "observed": False, "occurrences": []},
            {"event": "Get", "observed": True, "occurrences": [
                {"pattern": ".getInstance(", "method_line": 1}]},
        ]))
        self.assertEqual([item["event"] for item in sequence], ["Get"])

    def test_empty_without_a_specification_context(self):
        self.assertEqual(observed_call_sequence({}), [])


class LexicalCallerFallbackTests(unittest.TestCase):
    """Caller evidence must survive a semantic index that resolved nothing.

    direct_callers was dropped unconditionally as "superseded by semantic
    resolution", but the substitution was best-effort: on
    net.gaast.giggity the index reported resolved_callers "unknown" and
    contributed nothing, so the packet carried no caller evidence at all --
    and validate_multi_file_scope then failed the analysis for not reviewing
    Reminder.java, the file deriving alarm identifiers from the changed value.
    """

    def _error(self, resolved):
        return {
            "unique_error_id": "finding-1",
            "spec": "javax.net.ssl.SSLContextSpec",
            "error_message": "predicate failed",
            "source_file_path": "src/main/java/A.java",
            "method_name": "connect",
            "method_body": "void connect() {}",
            "expanded_repository_context": {
                "multi_file_impact": {
                    "exact_candidate_sources": [{
                        "source_file_path": "src/main/java/A.java",
                        "content": "class A {}",
                        "relevance": ["target"],
                    }],
                    "semantic_resolution": {
                        "status": "available",
                        "resolved_callers": resolved,
                        "ambiguous_calls": [], "parse_error_files": [],
                    },
                    "direct_callers": [
                        {"path": "src/main/java/Reminder.java", "line": 12},
                    ],
                    "coverage_requirements": {
                        "caller_files": ["src/main/java/Reminder.java"],
                    },
                    "scope_completeness": {"status": "incomplete", "reasons": []},
                }
            },
        }

    def _packet(self, resolved):
        policy = PolicyRegistry(ROOT / "data" / "llm_policies").select(
            "tls", "javax.net.ssl.SSLContextSpec"
        )
        return FindingEvidencePacketBuilder(16000).build(
            self._error(resolved), policy
        )

    def _kinds(self, packet):
        return {item.get("kind") for item in packet.get("evidence_catalog", [])}

    def _excluded(self, packet):
        return {item.get("kind") for item in packet.get("excluded_evidence", [])}

    def test_lexical_callers_are_supplied_when_resolution_found_none(self):
        packet = self._packet([])
        self.assertIn("lexical_caller", self._kinds(packet))
        self.assertNotIn("direct_callers", self._excluded(packet))
        self.assertIn("Reminder.java", json.dumps(packet))

    def test_lexical_callers_are_dropped_once_resolution_succeeds(self):
        packet = self._packet([{
            "path": "src/main/java/Caller.java", "line": 8,
            "resolved_symbol_id": "A#connect/0",
        }])
        kinds = self._kinds(packet)
        self.assertIn("resolved_caller", kinds)
        self.assertNotIn("lexical_caller", kinds)
        self.assertIn("direct_callers", self._excluded(packet))

    def test_caller_files_are_prioritised_like_the_validator_demands(self):
        """required_paths must match what validate_multi_file_scope requires.

        caller_files was demanded there but not prioritised here, so a caller
        could be graded unreviewed while never having been offered.
        """
        packet = self._packet([])
        self.assertIn("Reminder.java", json.dumps(packet))



class SourceEstablishedViolationTests(unittest.TestCase):
    """A detector that rendered no message must not veto a source-proved cause.

    The analyzer writes "unknown" as the message for 99,611 of the 142,580
    recorded findings. A supported decision used to require
    detector_violation == "confirmed", and there is nothing to confirm when
    no message exists, so every such finding abstained by construction:
    across the recorded runs, all four findings with a confirmed source
    cause and an unknown message were closed NO_SAFE_FIX, while 21 of 23
    with a rendered message reached an actionable decision.

    The message is left exactly as the detector wrote it. What changed is
    that the adjudication may rest on source evidence when there is no
    detector claim to corroborate, and must say so in the record.
    """

    UNKNOWN_FINDING = {
        "error_message": "unknown",
        "reported_violation": "InvalidSequenceOfMethodCalls",
    }
    RENDERED_FINDING = {
        "error_message": "expecting one of {SHA-256} but found MD5.",
    }

    def _adjudication(self, **extra):
        base = {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "generation_status": "supported_for_review",
            "cause_status": "confirmed",
            "confirmed_cause": "both load password arguments are a literal",
            "detector_violation": "source_established",
            "decision_claim_ids": ["C-001"],
            "blocking_for_generation": [],
            "review_assumptions": [
                "The detector rendered no message, so its own report could "
                "not be corroborated."
            ],
        }
        base.update(extra)
        return base

    EXTRACTION = {"claims": [{"claim_id": "C-001"}]}

    def _issues(self, adjudication, finding):
        return validate_adjudication(adjudication, self.EXTRACTION, finding)

    def test_detector_message_absence_is_recognised(self):
        self.assertTrue(detector_message_is_absent({"error_message": "unknown"}))
        self.assertTrue(detector_message_is_absent({"error_message": "  "}))
        self.assertTrue(detector_message_is_absent({}))
        self.assertFalse(detector_message_is_absent(self.RENDERED_FINDING))

    def test_a_source_established_violation_is_decidable(self):
        self.assertEqual(
            self._issues(self._adjudication(), self.UNKNOWN_FINDING), [])

    def test_the_old_requirement_still_holds_when_a_message_exists(self):
        issues = self._issues(
            self._adjudication(), self.RENDERED_FINDING)
        self.assertTrue(any("only for a finding whose detector" in item
                            for item in issues))

    def test_an_unknown_detector_still_needs_a_confirmed_cause(self):
        issues = self._issues(
            self._adjudication(cause_status="unknown"), self.UNKNOWN_FINDING)
        self.assertIn("source_established requires a confirmed cause", issues)

    def test_the_missing_corroboration_must_be_stated(self):
        issues = self._issues(
            self._adjudication(review_assumptions=["unrelated"]),
            self.UNKNOWN_FINDING)
        self.assertTrue(any("could not be corroborated" in item
                            for item in issues))

    def test_it_never_authorises_automatic_generation(self):
        issues = self._issues(
            self._adjudication(generation_status="supported",
                               compatibility_status="preserved"),
            self.UNKNOWN_FINDING)
        self.assertTrue(any("cannot authorize automatic" in item
                            for item in issues))

    def test_an_unresolved_detector_state_is_still_rejected(self):
        issues = self._issues(
            self._adjudication(detector_violation="unknown"),
            self.UNKNOWN_FINDING)
        self.assertTrue(any("confirmed, or source_established" in item
                            for item in issues))

    def test_a_confirmed_detector_violation_is_unaffected(self):
        self.assertEqual(
            self._issues(
                self._adjudication(detector_violation="confirmed"),
                self.RENDERED_FINDING),
            [],
        )

    def test_the_schema_offers_the_new_state(self):
        schema = adjudication_schema("generic")
        self.assertIn(
            "source_established",
            schema["properties"]["detector_violation"]["enum"],
        )

    def test_a_missing_finding_does_not_waive_the_message_check(self):
        # Both production call sites once omitted the finding, and an absent
        # finding read as "no message", so this rule was never enforced.
        issues = validate_adjudication(self._adjudication(), self.EXTRACTION)
        self.assertTrue(any("without the finding" in item for item in issues))

    def test_the_pipeline_entry_point_reads_the_rendered_message(self):
        issues = validate_adjudication_of(
            self._adjudication(), self.EXTRACTION, self.RENDERED_FINDING)
        self.assertTrue(any("only for a finding whose detector" in item
                            for item in issues))
        self.assertEqual(
            validate_adjudication_of(
                self._adjudication(), self.EXTRACTION, self.UNKNOWN_FINDING),
            [],
        )


class PromptClausesNameNoAppTest(unittest.TestCase):
    """B10: a prompt states the rule, not the app that motivated it."""

    def test_no_prompt_literal_names_the_app_behind_a_clause(self):
        import ast
        from cognalys.llm import finding_adjudication

        path = Path(finding_adjudication.__file__)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = {
            id(node.body[0].value) for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef))
            and node.body and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)}
        literals = [node.value for node in ast.walk(tree)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in docstrings]
        self.assertFalse([text for text in literals if "FreeOTP" in text])
        self.assertTrue(any("ships only its test" in text for text in literals))
        self.assertTrue(any("never questioned" in text for text in literals))
        # B10 bumped them to 8 and 12; later prompt changes (partial units
        # and peer hardening, 2026-11-13) raise them again.
        self.assertGreaterEqual(finding_adjudication.ADJUDICATION_PROMPT_VERSION, 8)
        self.assertGreaterEqual(finding_adjudication.PLAN_PROMPT_VERSION, 12)


class DismissalJustificationTest(unittest.TestCase):
    """B1: a not_confirmed answer shows its grounds, as a repair shows its cause.

    The code never decides that a finding is a false positive; it only
    refuses a dismissal that cites nothing verifiable, which then goes
    through the correction and, still rejected, to an unknown violation.
    """

    SHAPE = ("a runtime-supported provider alias or non-standard algorithm "
             "spelling is rejected because it is absent from the rule's explicit "
             "finite allowlist")
    EXTRACTION = {"claims": [
        {"claim_id": "C-001", "epistemic_status": "confirmed", "evidence_ids": ["SRC-001"]},
        {"claim_id": "C-002", "epistemic_status": "confirmed", "evidence_ids": ["WEB-001"]},
        {"claim_id": "C-003", "epistemic_status": "inferred", "evidence_ids": ["SRC-001"]},
        {"claim_id": "C-004", "epistemic_status": "confirmed",
         "evidence_ids": ["WEB-002", "SPEC-001"]},
    ]}

    def _dismissal(self, **extra):
        base = {
            "decision": "NO_SAFE_FIX",
            "generation_status": "blocked",
            "cause_status": "confirmed",
            "confirmed_cause": "The IV is read back from the stored record.",
            "detector_violation": "not_confirmed",
            "decision_claim_ids": ["C-001"],
            "blocking_for_generation": [],
        }
        base.update(extra)
        return base

    def _issues(self, adjudication, rule=None):
        return validate_adjudication_of(
            adjudication, self.EXTRACTION, {"error_message": "x"}, rule)

    def test_a_dismissal_without_claims_is_rejected(self):
        issues = self._issues(self._dismissal(decision_claim_ids=[]))
        self.assertTrue(any("requires supporting claim IDs" in item for item in issues))

    def test_a_confirmed_repository_claim_is_accepted(self):
        self.assertEqual(self._issues(self._dismissal()), [])
        self.assertEqual(self._issues(self._dismissal(decision_claim_ids=["C-004"])), [])

    def test_a_web_only_or_inferred_claim_is_rejected(self):
        for claim in ("C-002", "C-003"):
            issues = self._issues(self._dismissal(decision_claim_ids=["C-001", claim]))
            self.assertTrue(any("not so: " + claim in item for item in issues), claim)

    def test_an_unreviewed_shape_does_not_support_the_dismissal(self):
        rule = {"unreviewed_false_positive_shapes": [self.SHAPE]}
        quoted = self._dismissal(confirmed_cause=(
            "Matched: a runtime-supported provider alias or non-standard algorithm "
            "spelling is rejected."))
        named = self._dismissal(confirmed_cause=(
            "This is the rule's documented false-positive shape for this API."))
        for adjudication in (quoted, named):
            issues = self._issues(adjudication, rule)
            self.assertTrue(any("did not keep" in item for item in issues))
        # Without the rule nothing counts as reviewed.
        self.assertTrue(any("did not keep" in item for item in self._issues(named)))

    def test_a_reviewed_shape_supports_it(self):
        rule = {"known_false_positive_shapes": [self.SHAPE]}
        adjudication = self._dismissal(confirmed_cause=(
            "Matches the known false-positive shape: a runtime-supported provider "
            "alias or non-standard algorithm spelling is rejected."))
        self.assertEqual(self._issues(adjudication, rule), [])

    def test_other_answers_are_not_held_to_it(self):
        adjudication = self._dismissal(detector_violation="unknown", decision_claim_ids=[])
        self.assertEqual(dismissal_justification_issues(adjudication, self.EXTRACTION), [])



_TLS_METHOD = """    public synchronized OkHttpClient getOkHttpClient() {
        if (mOkHttpClient == null) {
            final X509TrustManager trustManager = new AdvancedX509TrustManager(
                    NetworkUtils.getKnownServersStore(mContext));
            final SSLContext sslContext = buildSSLContext();
            sslContext.init(keyManagers, new TrustManager[]{trustManager}, null);
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            mOkHttpClient = buildNewOkHttpClient(sslSocketFactory, trustManager);
        }
        return mOkHttpClient;
    }
"""


class SinkReachabilityTests(unittest.TestCase):
    """Establish that a finding's value reaches a security-relevant use.

    eu.opencloud.android's getKnownServersStore was closed NO_SAFE_FIX partly
    because "the evidence does not establish that stored certificates affect
    production TLS validation" -- while HttpClient.java, which establishes
    exactly that, was already in the evidence packet as SRC-002. The chain
    passes through a local rename, which the repository-wide lexical slice in
    value_usage_graph cannot follow: probed on this finding it reported
    persistence, network and credential sinks in unrelated files and nothing
    about the TLS installation at all.
    """

    def test_finds_the_chain_through_a_local_binding(self):
        found = reaches_security_sink(
            _TLS_METHOD, "getKnownServersStore",
            source_file_path="HttpClient.java")
        self.assertIsNotNone(found)
        self.assertEqual(found["sink_family"], "tls_trust_configuration")
        self.assertIn("sslContext.init", found["sink_source_line"])
        self.assertEqual(found["reached_through"], ["trustManager"])

    def test_a_wrapped_assignment_is_still_followed(self):
        # The binding spans two lines in the real source; read one line at a
        # time the right-hand side never contains the seed.
        self.assertIn(
            "trustManager",
            reaches_security_sink(_TLS_METHOD, "getKnownServersStore")
            ["reached_through"],
        )

    def test_reports_only_the_bindings_that_precede_the_sink(self):
        # mOkHttpClient is assigned from trustManager after the sink line; it
        # is not part of the chain that reaches it.
        found = reaches_security_sink(_TLS_METHOD, "getKnownServersStore")
        self.assertNotIn("mOkHttpClient", found["reached_through"])

    def test_a_sink_that_does_not_carry_the_value_is_not_a_hit(self):
        self.assertIsNone(reaches_security_sink(
            "KeyStore ks = build();\n"
            "sslContext.init(km, new TrustManager[]{other}, null);\n",
            "build"))

    def test_init_without_a_trust_manager_is_not_a_tls_sink(self):
        self.assertIsNone(reaches_security_sink(
            "KeyStore ks = build();\nthing.init(ks);\n", "build"))

    def test_a_value_reaching_nothing_security_relevant_is_silent(self):
        self.assertIsNone(reaches_security_sink(
            "int total = compute();\nint doubled = total * 2;\n", "compute"))

    def test_an_unrelated_method_in_the_same_file_cannot_join_the_chain(self):
        source = (
            "public class A {\n"
            "    public KeyStore build() {\n"
            "        KeyStore store = load();\n"
            "        return store;\n"
            "    }\n"
            "    public void other() {\n"
            "        X509TrustManager trustManager = somethingElse();\n"
            "        sslContext.init(km, new TrustManager[]{trustManager}, null);\n"
            "    }\n"
            "}\n"
        )
        self.assertIsNone(sink_reachability_in_source(source, "load", "A.java"))

    def test_the_record_states_the_bound_it_was_computed_under(self):
        found = reaches_security_sink(_TLS_METHOD, "getKnownServersStore")
        self.assertEqual(
            found["analysis_kind"], "intra_method_local_assignment_chain")
        self.assertIn("silence is not evidence", found["limits"])


class SecuritySinkEvidenceTests(unittest.TestCase):
    """The conclusion is derived only from source the packet already carries."""

    def _catalog(self):
        return [{
            "evidence_id": "SRC-002",
            "kind": "related_source",
            "data": {
                "source_file_path": "http/HttpClient.java",
                "content": "public class HttpClient {\n" + _TLS_METHOD + "}\n",
            },
        }]

    def test_a_reached_sink_becomes_a_citable_entry(self):
        entry = security_sink_evidence(self._catalog(), "getKnownServersStore")
        self.assertEqual(entry["evidence_id"], "FLOW-001")
        self.assertEqual(entry["kind"], "security_sink_reachability")
        self.assertFalse(entry["mandatory"])
        self.assertEqual(entry["data"]["corroborates_evidence_id"], "SRC-002")

    def test_it_names_the_entry_it_was_derived_from(self):
        entry = security_sink_evidence(self._catalog(), "getKnownServersStore")
        self.assertEqual(entry["data"]["sink_family"], "tls_trust_configuration")

    def test_no_entry_when_nothing_is_reached(self):
        self.assertIsNone(
            security_sink_evidence(self._catalog(), "unrelatedMethod"))

    def test_no_entry_without_a_method_name(self):
        self.assertIsNone(security_sink_evidence(self._catalog(), ""))

    def test_no_entry_from_an_empty_catalog(self):
        self.assertIsNone(security_sink_evidence([], "getKnownServersStore"))

    def test_it_reads_no_source_the_packet_did_not_supply(self):
        # An entry with no content contributes nothing: the check never
        # reaches outside the packet for more.
        self.assertIsNone(security_sink_evidence(
            [{"evidence_id": "SRC-002",
              "data": {"source_file_path": "http/HttpClient.java"}}],
            "getKnownServersStore"))



class InlineArgumentBodyTests(unittest.TestCase):
    """A class body written inside an argument list is not a passed value.

    Sweeping ten repositories produced five reachability hits and four of
    them were this shape: a hostname verifier written inline, whose declared
    `verify` method was read as an identifier passed to setHostnameVerifier.
    The distinction matters because the array initializer this check exists
    to follow, `new TrustManager[]{trustManager}`, is also a brace block --
    and there the contents really are the value.
    """

    INLINE_VERIFIER = (
        "public void configure() {\n"
        "    conn.setHostnameVerifier(new HostnameVerifier() {\n"
        "        @Override public boolean verify(String host, SSLSession s) {\n"
        "            return true;\n"
        "        }\n"
        "    });\n"
        "}\n"
    )

    def test_a_method_declared_inline_is_not_a_passed_value(self):
        self.assertIsNone(
            reaches_security_sink(self.INLINE_VERIFIER, "verify"))

    def test_an_array_initializer_still_carries_its_contents(self):
        found = reaches_security_sink(
            "KeyStore ks = build();\n"
            "X509TrustManager tm = new Custom(ks);\n"
            "sslContext.init(km, new TrustManager[]{tm}, null);\n",
            "build")
        self.assertIsNotNone(found)
        self.assertIn("tm", found["reached_through"])

    def test_a_value_passed_beside_an_inline_body_is_still_seen(self):
        found = reaches_security_sink(
            "X509TrustManager tm = fromStore();\n"
            "clientBuilder.sslSocketFactory(factory, tm);\n",
            "fromStore")
        self.assertIsNotNone(found)
        self.assertEqual(found["sink_family"], "tls_trust_configuration")

    def test_passed_identifiers_drops_only_declaring_blocks(self):
        self.assertNotIn(
            "verify",
            _passed_identifiers(
                "new HostnameVerifier() { public boolean verify(String h) {} }"),
        )
        self.assertIn(
            "trustManager",
            _passed_identifiers("km, new TrustManager[]{trustManager}, null"),
        )



class DocumentedFalsePositiveShapeTests(unittest.TestCase):
    """Close a finding the specification itself documents as a false positive.

    The curated route needs the detector's exact message text, and 95 of the
    133 sampled candidates report "unknown" -- every one of them an
    InvalidSequenceOfMethodCalls -- so it could never reach 71% of the data.
    opencloud's KeyStore finding is the shape: the code runs
    getInstance -> load -> setCertificateEntry -> store, and KeyStoreSpec's
    own known_false_positive_shapes records that the rule models setEntry
    and not setCertificateEntry, so a valid sequence reads as a broken one.

    The rationale returned is the specification's text, never this module's
    words: a spec that stops documenting a shape stops the claim with it.
    """

    SOURCE = (
        "KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());\n"
        "ks.load(in, password);\n"
        "ks.setCertificateEntry(alias, cert);\n"
        "ks.store(out, password);\n"
    )
    # Verified and grounded: a documented shape may only be quoted when the
    # source it came from can be produced. KeyStoreSpec's can -- the audit
    # reaches its CrySL rule and finds `SPEC java.security.KeyStore` -- and
    # ten other specifications in this project cite a URL that answers 404,
    # whose shapes must never reach a rationale.
    SHAPES = {
        "source_verified": True,
        "shapes_grounded": True,
        "known_false_positive_shapes": [
            "Android application code using KeyStore.getInstance(\"AndroidKeyStore\").",
            "Valid code using documented setKeyEntry(...) or "
            "setCertificateEntry(...) instead of the rule's modeled setEntry(...).",
        ]
    }
    BLOCKED = {"cause_status": "unknown", "detector_violation": "unknown",
               "confirmed_cause": ""}

    def setUp(self):
        # The trigger routes resolve only over reviewed shapes (P14).
        self.enterContext(reviewed_false_positive_shapes())

    def _status(self, **overrides):
        arguments = {
            "spec_id": "KeyStoreSpec",
            "error_message": "unknown",
            "app_source_file_path": "src/NetworkUtils.java",
            "reported_violation": "InvalidSequenceOfMethodCalls",
            "observed_calls": ["setCertificateEntry"],
            "specification_context": self.SHAPES,
        }
        arguments.update(overrides)
        return blocked_finding_review_status(self.BLOCKED, **arguments)

    def test_the_unmodelled_call_is_found_in_the_source(self):
        self.assertEqual(
            unmodelled_calls_in_source("KeyStoreSpec", self.SOURCE),
            ["setCertificateEntry"],
        )

    def test_a_specification_without_a_shape_rule_finds_nothing(self):
        self.assertEqual(
            unmodelled_calls_in_source("SecureRandomSpec", self.SOURCE), [])

    def test_the_finding_closes_as_a_documented_false_positive(self):
        self.assertEqual(self._status(), "CONFIRMED_FALSE_POSITIVE")

    def test_the_rationale_is_quoted_from_the_specification(self):
        reason = false_positive_rationale(
            "KeyStoreSpec", "unknown", False, "src/NetworkUtils.java",
            "InvalidSequenceOfMethodCalls", ["setCertificateEntry"],
            self.SHAPES)
        self.assertIn(reason, self.SHAPES["known_false_positive_shapes"])

    def test_it_stays_silent_when_the_specification_cannot_be_grounded(self):
        # The shapes are there; the source they came from is not. Ten of
        # this project's specifications are in exactly that state, holding
        # 66 shapes between them.
        self.assertEqual(
            self._status(specification_context=dict(
                self.SHAPES, source_verified=False, shapes_grounded=False,
            )),
            "UNCONFIRMED_FINDING",
        )

    def test_it_stays_silent_when_the_specification_documents_no_shape(self):
        # Without the documentation the claim has no authority behind it.
        self.assertEqual(
            self._status(specification_context={
                "known_false_positive_shapes": []}),
            "UNCONFIRMED_FINDING",
        )

    def test_it_stays_silent_for_a_different_violation_type(self):
        self.assertEqual(
            self._status(reported_violation="ConstraintError"),
            "UNCONFIRMED_FINDING",
        )

    def test_it_stays_silent_when_the_source_makes_no_such_call(self):
        self.assertEqual(self._status(observed_calls=[]), "UNCONFIRMED_FINDING")

    def test_a_confirmed_cause_is_never_overridden(self):
        confirmed = dict(self.BLOCKED, cause_status="confirmed",
                         confirmed_cause="a real cause")
        self.assertEqual(
            blocked_finding_review_status(
                confirmed, spec_id="KeyStoreSpec",
                reported_violation="InvalidSequenceOfMethodCalls",
                observed_calls=["setCertificateEntry"],
                specification_context=self.SHAPES),
            "CONFIRMED_CAUSE_ONLY_NO_SAFE_FIX",
        )

    def test_a_confirmed_detector_violation_is_never_overridden(self):
        confirmed = dict(self.BLOCKED, detector_violation="confirmed")
        self.assertEqual(
            blocked_finding_review_status(
                confirmed, spec_id="KeyStoreSpec",
                reported_violation="InvalidSequenceOfMethodCalls",
                observed_calls=["setCertificateEntry"],
                specification_context=self.SHAPES),
            "CONFIRMED_FINDING_NO_SAFE_FIX",
        )

    def test_the_curated_message_route_still_works(self):
        # SSLContextSpec's exact-message shape must keep closing findings
        # whose reported class lives outside the application repository.
        self.assertEqual(
            blocked_finding_review_status(
                {"cause_status": "unknown", "detector_violation": "unknown",
                 "dependency_fix_assessment": {"external_class_confirmed": True}},
                spec_id="SSLContextSpec",
                error_message=(
                    "expecting one of {TLSv1.2, TLSv1.3} but found TLS."),
                app_source_file_path=""),
            "CONFIRMED_FALSE_POSITIVE",
        )

    def test_calling_without_the_new_arguments_behaves_as_before(self):
        self.assertEqual(
            blocked_finding_review_status(self.BLOCKED, spec_id="KeyStoreSpec"),
            "UNCONFIRMED_FINDING",
        )


class DocumentedFalsePositiveShapeTests2(unittest.TestCase):
    """A rejected value named in a documented shape no longer closes a finding.

    The route closed KeyStoreSpec's AndroidKeyStore findings, even against a
    confirmed violation, because the rejected value appeared as a word in the
    specification's first known_false_positive_shapes entry. It never checked
    the condition the shape describes, which is deterministic triage of a
    known false-positive pattern; it was removed on 2026-10-28 and these tests
    pin its absence.
    """

    SPEC = {
        "spec_id": "KeyStoreSpec",
        "source_verified": True,
        "source_url": "https://example.invalid/KeyStore.crysl",
        "applies_to_types": ["java.security.KeyStore"],
        "known_false_positive_shapes": [
            "Android application code using java.security.KeyStore."
            "getInstance(\"AndroidKeyStore\") where the static rule's "
            "five-value type whitelist is applied literally.",
            "Valid code using documented setKeyEntry(...) instead of the "
            "rule's modeled setEntry(...).",
        ],
    }
    MESSAGE = (
        "expecting one ofJCEKS,JKS,DKS,PKCS11,PKCS12 but found "
        "AndroidKeyStore."
    )
    SOURCE = (
        'private val keyStore = KeyStore.getInstance("AndroidKeyStore")'
        ".apply { load(null) }\n"
    )
    CONFIRMED = {
        "cause_status": "confirmed",
        "detector_violation": "confirmed",
        "confirmed_cause": "the supplied type is outside the allowlist",
    }

    def test_a_documented_value_no_longer_closes_the_finding(self):
        import cognalys.llm.false_positive_rules as rules
        import cognalys.llm.pipeline_architecture as architecture

        for module in (rules, architecture):
            for name in ("documented_false_positive_shape",
                         "constraint_value_false_positive_reason"):
                self.assertFalse(hasattr(module, name), (module, name))
        self.assertEqual(
            false_positive_rationale(
                "KeyStoreSpec", self.MESSAGE, False, "src/X.java",
                specification_context=self.SPEC, source=self.SOURCE,
            ),
            "",
        )
        self.assertEqual(
            blocked_finding_review_status(
                {"cause_status": "unknown", "detector_violation": "unknown"},
                spec_id="KeyStoreSpec",
                error_message=self.MESSAGE,
                app_source_file_path="src/X.java",
                specification_context=self.SPEC,
                source=self.SOURCE,
            ),
            "UNCONFIRMED_FINDING",
        )

    def test_a_confirmed_violation_stays_confirmed(self):
        self.assertEqual(
            blocked_finding_review_status(
                self.CONFIRMED,
                spec_id="KeyStoreSpec",
                error_message=self.MESSAGE,
                app_source_file_path="app/src/CryptoManager.kt",
                specification_context=self.SPEC,
                source=self.SOURCE,
            ),
            "CONFIRMED_FINDING_NO_SAFE_FIX",
        )

    def test_the_shapes_travel_with_the_verified_rule(self):
        # Unstamped, they travel as unreviewed; once the shape review has
        # run they are the rule's known false positives.
        self.assertEqual(
            verified_detector_semantics(
                self.SPEC
            )["unreviewed_false_positive_shapes"],
            self.SPEC["known_false_positive_shapes"],
        )
        reviewed = dict(self.SPEC, generation_evidence={
            "false_positive_shape_review": {"version": 1, "moved": []}})
        self.assertEqual(
            verified_detector_semantics(
                reviewed
            )["known_false_positive_shapes"],
            self.SPEC["known_false_positive_shapes"],
        )


class SharedStateMutationEvidenceTests(unittest.TestCase):
    """Whether a second writer exists decides a concurrency finding's impact.

    gtalksms's HelpCmd.<init> traverses a Collections.synchronizedSet without
    holding its monitor, which really does violate the documented contract.
    But CommandManager.mCommandHandlersSet is final and has exactly one
    mutation site, so no concurrent modification is possible and the hazard
    cannot arise. The adjudication recorded runtime_security_impact
    "unknown" (run_20260911_095238) because it had to derive that across two
    accessor hops and did not.
    """

    MANAGER = (
        "public class CommandManager {\n"
        "    private final Set<Handler> mHandlers = "
        "Collections.synchronizedSet(new HashSet<Handler>());\n"
        "    public Set<Handler> getHandlerSet() {\n"
        "        return mHandlers;\n"
        "    }\n"
        "    public void setup() {\n"
        "        for (Class<?> c : sCommands) {\n"
        "            mHandlers.add(make(c));\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    SERVICE = (
        "public class MainService {\n"
        "    public static Set<Handler> getHandlers() {\n"
        "        if (sInstance != null) {\n"
        "            return sInstance.mManager.getHandlerSet();\n"
        "        }\n"
        "        return null;\n"
        "    }\n"
        "}\n"
    )
    BODY = (
        "public HelpCmd(MainService service) {\n"
        "    Set<Handler> set = MainService.getHandlers();\n"
        "    for (Handler h : set) { total += h.help(); }\n"
        "}\n"
    )

    def _catalog(self, *sources):
        return [
            {
                "evidence_id": f"SRC-{index:03d}",
                "kind": "related_source",
                "data": {"source_file_path": f"src/F{index}.java",
                         "content": text},
            }
            for index, text in enumerate(sources or (self.MANAGER, self.SERVICE), 1)
        ]

    def test_it_follows_the_accessor_chain_to_the_field(self):
        self.assertEqual(
            fields_reached_through_accessors(
                self.BODY,
                [("a", self.SERVICE), ("b", self.MANAGER)],
            ),
            ["mHandlers"],
        )

    def test_the_single_writer_is_reported_with_the_field(self):
        evidence = shared_state_mutation_evidence(self._catalog(), self.BODY)
        record = evidence["data"]["fields_reached_through_accessors"][0]
        self.assertEqual(record["field"], "mHandlers")
        self.assertTrue(record["final"])
        self.assertEqual(record["mutation_site_count"], 1)
        self.assertEqual(
            record["mutation_sites"][0]["statement"], "mHandlers.add(make(c));"
        )

    def test_the_declarations_initializer_is_not_a_mutation_site(self):
        # Counting it would give every field at least one writer, which is
        # exactly the count that decides whether the hazard can arise.
        evidence = shared_state_mutation_evidence(self._catalog(), self.BODY)
        record = evidence["data"]["fields_reached_through_accessors"][0]
        self.assertIn("synchronizedSet", record["initializer"])
        for site in record["mutation_sites"]:
            self.assertNotIn("synchronizedSet", site["statement"])

    def test_a_second_writer_is_reported_too(self):
        manager = self.MANAGER.replace(
            "    public void setup() {",
            "    public void drop(Handler h) { mHandlers.remove(h); }\n"
            "    public void setup() {",
        )
        evidence = shared_state_mutation_evidence(
            self._catalog(manager, self.SERVICE), self.BODY
        )
        record = evidence["data"]["fields_reached_through_accessors"][0]
        self.assertEqual(record["mutation_site_count"], 2)

    def test_the_writers_own_call_sites_are_reported(self):
        # How often the writer runs decides as much as how many writers
        # there are: one mutating call inside a method called from
        # everywhere is not a single write.
        evidence = shared_state_mutation_evidence(self._catalog(), self.BODY)
        site = evidence["data"][
            "fields_reached_through_accessors"
        ][0]["mutation_sites"][0]
        self.assertEqual(site["enclosing_method"], "setup")
        self.assertEqual(site["call_sites_in_examined_scope"], [])

    def test_a_public_writer_can_have_callers_outside_the_scope(self):
        # setup() is public, so a count of zero here is a fact about how
        # much source this packet carries, not about the program.
        evidence = shared_state_mutation_evidence(self._catalog(), self.BODY)
        site = evidence["data"][
            "fields_reached_through_accessors"
        ][0]["mutation_sites"][0]
        self.assertFalse(site["call_sites_complete"])

    def test_a_private_writer_has_every_caller_in_its_own_file(self):
        manager = self.MANAGER.replace(
            "    public void setup() {",
            "    public void start() { setup(); }\n"
            "    private void setup() {",
        )
        evidence = shared_state_mutation_evidence(
            self._catalog(manager, self.SERVICE), self.BODY
        )
        site = evidence["data"][
            "fields_reached_through_accessors"
        ][0]["mutation_sites"][0]
        self.assertTrue(site["call_sites_complete"])
        self.assertEqual(len(site["call_sites_in_examined_scope"]), 1)
        self.assertIn("setup();", site["call_sites_in_examined_scope"][0])

    def test_it_draws_no_conclusion_and_states_its_bound(self):
        evidence = shared_state_mutation_evidence(self._catalog(), self.BODY)
        self.assertEqual(evidence["evidence_id"], "MUT-001")
        self.assertEqual(
            evidence["trust_level"], "derived_from_supplied_source"
        )
        self.assertFalse(evidence["mandatory"])
        self.assertIn("draws no conclusion", evidence["data"]["bound"])
        self.assertIn("reflection", evidence["data"]["bound"])

    def test_a_method_reaching_no_accessor_field_produces_nothing(self):
        body = "public void run() { int x = 1 + 2; }\n"
        self.assertIsNone(
            shared_state_mutation_evidence(self._catalog(), body)
        )

    def test_a_local_variable_is_not_mistaken_for_a_field(self):
        # The field declaration requires a modifier; a local of the same
        # shape has none, so the accessor resolves to nothing.
        manager = self.MANAGER.replace(
            "    private final Set<Handler> mHandlers = "
            "Collections.synchronizedSet(new HashSet<Handler>());\n",
            "",
        )
        self.assertIsNone(
            shared_state_mutation_evidence(
                self._catalog(manager, self.SERVICE), self.BODY
            )
        )

    def test_an_empty_catalog_produces_nothing(self):
        self.assertIsNone(shared_state_mutation_evidence([], self.BODY))


class DetectorArityOvermatchTests(unittest.TestCase):
    """Close a finding whose rule matched a method that shares a name.

    Object_MonitorOwner's verified source matches
    `call(* Object+.notify(..))`, which constrains neither the receiver type
    nor the parameter list, and then reports whenever the calling thread does
    not hold the receiver's monitor. java.lang.Object declares notify() with
    no parameters, so NotificationManager.notify(int, Notification) -- which
    no Android app synchronizes on -- is reported by every run. agit's
    RepoNotifications.notifyCompletionWith (run_20260910_235224) is that
    finding, and 38 of the 55 rows in data/processed/exp01_novo.csv are the
    same specification.

    Nothing here names Object or Android: the governed arity comes from the
    specification's own api_patterns and the unconstrained matcher from its
    own event conditions.
    """

    SPEC = {
        "spec_id": "Object_MonitorOwner",
        "source_verified": True,
        "source_title": "Object_MonitorOwner.mop (JavaMOP monitor specification)",
        "source_url": "https://example.invalid/props/Object_MonitorOwner.mop",
        "applies_to_types": ["java.lang.Object"],
        "events": [
            {
                "name": "bad_notify",
                "api_patterns": [".notify()", ".notifyAll()"],
                "condition": (
                    "Observed event: a before-call join point matching "
                    "`call(* Object+.notify(..)) || "
                    "call(* Object+.notifyAll(..))` with receiver `o`."
                ),
            },
            {
                "name": "bad_wait",
                "api_patterns": [".wait()", ".wait("],
                "condition": (
                    "Observed event: a before-call join point matching "
                    "`call(* Object+.wait(..))` with receiver `o`, covering "
                    "Object.wait overloads."
                ),
            },
        ],
    }
    SOURCE = (
        "public void notifyCompletionWith(OpNotification completion) {\n"
        "    Notification cn = createNotificationWith(completion);\n"
        "    cn.flags |= FLAG_AUTO_CANCEL;\n"
        "    notificationManager.notify(completionNotificationId, cn);\n"
        "}\n"
    )
    BLOCKED = {"cause_status": "unknown", "detector_violation": "unknown",
               "confirmed_cause": ""}

    def test_the_governed_arity_is_read_from_the_specification(self):
        # wait is listed both as ".wait()" and as the open-ended ".wait(",
        # because Object declares wait(), wait(long) and wait(long, int).
        # An argument-carrying wait() call therefore proves nothing.
        self.assertEqual(
            parameterless_governed_methods(self.SPEC), ["notify", "notifyAll"]
        )

    def test_the_unconstrained_matcher_is_quoted_from_the_specification(self):
        self.assertIn(
            "call(* Object+.notify(..))",
            unconstrained_arity_matcher(self.SPEC),
        )

    def test_an_argument_carrying_call_cannot_be_the_governed_method(self):
        reason = detector_arity_overmatch_reason(self.SPEC, self.SOURCE)
        self.assertIn("notificationManager.notify(...)", reason)
        self.assertIn("call(* Object+.notify(..))", reason)

    def test_the_finding_closes_as_a_confirmed_false_positive(self):
        self.assertEqual(
            blocked_finding_review_status(
                self.BLOCKED,
                spec_id="Object_MonitorOwner",
                error_message=(
                    "Object_MonitorOwner notify() and notifyAll() can be "
                    "called only by the owner of this object's monitor."
                ),
                app_source_file_path="agit/RepoNotifications.java",
                specification_context=self.SPEC,
                source=self.SOURCE,
            ),
            "CONFIRMED_FALSE_POSITIVE",
        )

    def test_a_parameterless_call_of_the_same_name_stays_unknown(self):
        # One genuine Object.notify() in the reviewed source is enough: the
        # detector may well have matched that one, and an unknown is not a
        # false positive.
        source = self.SOURCE + "synchronized (lock) { lock.notify(); }\n"
        self.assertEqual(
            detector_arity_overmatch_reason(self.SPEC, source), ""
        )

    def test_an_argument_carrying_wait_proves_nothing(self):
        source = "synchronized (lock) { lock.wait(500); }\n"
        self.assertEqual(
            detector_arity_overmatch_reason(self.SPEC, source), ""
        )

    def test_an_unverified_specification_can_never_claim_it(self):
        # An unverified specification's matching rule is a generated guess,
        # not the detector's documented behaviour.
        unverified = dict(self.SPEC, source_verified=False)
        self.assertEqual(
            detector_arity_overmatch_reason(unverified, self.SOURCE), ""
        )

    def test_a_rule_that_constrains_its_parameters_can_never_claim_it(self):
        # Without an unconstrained matcher the detector could not have
        # matched a call of a different arity in the first place.
        constrained = dict(self.SPEC, events=[
            dict(self.SPEC["events"][0],
                 condition="matching `call(* Object+.notify())`"),
        ])
        self.assertEqual(
            detector_arity_overmatch_reason(constrained, self.SOURCE), ""
        )

    def test_a_declaration_of_the_same_name_is_not_a_matched_call(self):
        source = "public void notify(int id, Notification n) { }\n"
        self.assertEqual(
            detector_arity_overmatch_reason(self.SPEC, source), ""
        )


class VerifiedDetectorSemanticsTests(unittest.TestCase):
    """What the detector matches must reach the stages that decide.

    In run_20260910_235224 it reached neither: the research request held no
    part of the specification and reported the detector's semantics as
    unestablished, and the adjudication request held none of it either and
    recorded the rule's matching logic as missing evidence -- while the
    verified rule sat in data/specifications quoting its own pointcut.
    """

    SPEC = DetectorArityOvermatchTests.SPEC

    def test_the_matching_rule_travels_with_its_source(self):
        semantics = verified_detector_semantics(self.SPEC)
        self.assertEqual(semantics["source_url"], self.SPEC["source_url"])
        self.assertIn(
            "call(* Object+.notify(..))", semantics["events"][0]["matches"]
        )
        self.assertEqual(
            semantics["events"][0]["api_patterns"], [".notify()", ".notifyAll()"]
        )

    def test_an_unverified_specification_carries_nothing(self):
        self.assertEqual(
            verified_detector_semantics(dict(self.SPEC, source_verified=False)),
            {},
        )

    def test_the_research_question_names_the_published_source(self):
        question = detector_matching_research_question(self.SPEC)
        self.assertIn(self.SPEC["source_url"], question)
        self.assertIn("parameter list", question)

    def test_no_research_question_without_a_verified_source(self):
        self.assertEqual(
            detector_matching_research_question(
                dict(self.SPEC, source_verified=False)
            ),
            "",
        )

    def test_no_research_question_without_a_url_to_point_at(self):
        self.assertEqual(
            detector_matching_research_question(dict(self.SPEC, source_url="")),
            "",
        )


class ConfirmedCauseProseTests(unittest.TestCase):
    """A negative confirmed_cause is not a confirmed cause.

    The adjudication fills confirmed_cause with prose whatever it concludes.
    agit's finding carried cause_status "unknown" beside "No source-level
    cause for an Object monitor-ownership violation is confirmed: ...", and
    the truthiness of that string labelled the finding
    CONFIRMED_CAUSE_ONLY_NO_SAFE_FIX while the preview rendered "Cause:
    unknown" two lines below -- and short-circuited past the false positive
    test for every finding the adjudication bothered to explain.
    """

    SPEC = DetectorArityOvermatchTests.SPEC
    SOURCE = DetectorArityOvermatchTests.SOURCE

    def test_prose_beside_an_unknown_cause_status_is_not_a_confirmation(self):
        analysis = {
            "cause_status": "unknown",
            "detector_violation": "not_confirmed",
            "confirmed_cause": (
                "No source-level cause for an Object monitor-ownership "
                "violation is confirmed: the reported method contains "
                "NotificationManager.notify(int, Notification)."
            ),
        }
        self.assertEqual(
            blocked_finding_review_status(
                analysis,
                spec_id="Object_MonitorOwner",
                specification_context=self.SPEC,
                source=self.SOURCE,
            ),
            "CONFIRMED_FALSE_POSITIVE",
        )

    def test_prose_beside_an_unknown_cause_status_never_confirms_a_cause(self):
        analysis = {
            "cause_status": "unknown",
            "detector_violation": "unknown",
            "confirmed_cause": "No cause is confirmed.",
        }
        self.assertEqual(
            blocked_finding_review_status(analysis), "UNCONFIRMED_FINDING"
        )

    def test_a_record_predating_cause_status_still_reads_its_prose(self):
        # Written before cause_status existed, where a non-empty
        # confirmed_cause was the only way to record a confirmed cause.
        self.assertEqual(
            blocked_finding_review_status({
                "detector_violation": "unknown",
                "confirmed_cause": "the initialisation flow is confirmed",
            }),
            "CONFIRMED_CAUSE_ONLY_NO_SAFE_FIX",
        )

    def test_an_explicitly_confirmed_cause_is_unaffected(self):
        self.assertEqual(
            blocked_finding_review_status({
                "cause_status": "confirmed",
                "detector_violation": "unknown",
                "confirmed_cause": "the initialisation flow is confirmed",
            }),
            "CONFIRMED_CAUSE_ONLY_NO_SAFE_FIX",
        )

    def test_a_nested_evidence_status_is_read_the_same_way(self):
        self.assertEqual(
            blocked_finding_review_status({
                "evidence_status": {"cause_status": "unknown"},
                "detector_violation": "unknown",
                "confirmed_cause": "No cause is confirmed.",
            }),
            "UNCONFIRMED_FINDING",
        )


class ManifestComponentEvidenceTests(unittest.TestCase):
    """Whether a component is reachable from outside decides the finding.

    ownCloud's FileContentProvider.delete was adjudicated with
    runtime_security_impact "unknown" over the words "provider exposure to
    an untrusted caller [not established]", while its manifest declared
    android:exported="false" three lines from the class name. The packet had
    discovered that file -- it listed the path under configuration_evidence
    and recorded that it matched the term "ContentProvider" -- and kept only
    the path, never the content.
    """

    MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.owncloud.android">
  <application>
    <provider
        android:name=".providers.FileContentProvider"
        android:authorities="@string/authority"
        android:enabled="true"
        android:exported="false" />
    <activity android:name="com.owncloud.android.ui.FileDisplay"
        android:exported="true" />
    <service android:name="Sync"
        android:permission="com.owncloud.PERMISSION" />
  </application>
</manifest>
"""

    def _repository(self, directory: str) -> Path:
        root = Path(directory)
        manifest = root / "app" / "src" / "main" / "AndroidManifest.xml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(self.MANIFEST, encoding="utf-8")
        return root

    def test_a_relative_declaration_is_matched_to_the_target_class(self):
        with tempfile.TemporaryDirectory() as directory:
            found = manifest_component_evidence(
                str(self._repository(directory)),
                "com.owncloud.android.providers.FileContentProvider",
            )

        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["component_tag"], "provider")
        self.assertEqual(found[0]["android:exported"], "false")
        self.assertEqual(
            found[0]["source_file_path"], "app/src/main/AndroidManifest.xml"
        )

    def test_a_fully_qualified_declaration_is_matched(self):
        with tempfile.TemporaryDirectory() as directory:
            found = manifest_component_evidence(
                str(self._repository(directory)),
                "com.owncloud.android.ui.FileDisplay",
            )

        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["component_tag"], "activity")
        self.assertEqual(found[0]["android:exported"], "true")

    ALIAS_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application>
    <activity-alias
        android:name=".features.Alias"
        android:exported="true"
        android:targetActivity="im.vector.app.features.MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
      </intent-filter>
    </activity-alias>
  </application>
</manifest>
"""

    def test_a_fixed_input_size_and_its_cipher_block_size_are_reported(self):
        """A weakness that needs repetition across blocks reads differently
        when the method refuses anything but one block. CableEid.encrypt
        requires EID_SIZE bytes, EID_SIZE is 16, and 16 is the AES block size;
        none of that reached the adjudication, which recorded
        runtime_security_impact "confirmed"."""
        body = (
            'fun encrypt(plaintextEid: ByteArray) {\n'
            '    require(plaintextEid.size == EID_SIZE) { "bad" }\n'
            '    Cipher.getInstance("AES/ECB/NoPadding").doFinal(plaintextEid)\n'
            '}'
        )
        catalog = [{
            "evidence_id": "SRC-001",
            "data": {"source_file_path": "CableEid.kt",
                     "content": "const val EID_SIZE = 16\n" + body},
        }]

        found = enforced_input_size_evidence(catalog, "encrypt", body)

        self.assertEqual(found["evidence_id"], "SIZE-001")
        self.assertEqual(found["data"]["enforced_input_sizes"], [{
            "operand": "plaintextEid", "comparison": "==",
            "size_expression": "EID_SIZE", "resolved_bytes": 16,
        }])
        self.assertEqual(
            found["data"]["named_cipher_block_sizes_bytes"], {"AES": 16},
        )
        self.assertEqual(found["data"]["corroborates_evidence_id"], "SRC-001")

    def test_a_literal_size_needs_no_constant_to_resolve(self):
        body = 'void f(byte[] b) { if (b.length != 16) throw new E(); }'
        found = enforced_input_size_evidence([], "f", body)
        self.assertEqual(
            found["data"]["enforced_input_sizes"][0]["resolved_bytes"], 16,
        )

    def test_a_method_constraining_nothing_reports_nothing(self):
        self.assertIsNone(enforced_input_size_evidence(
            [], "f", "void f(byte[] b) { cipher.doFinal(b); }",
        ))

    def test_an_unresolvable_constant_is_not_invented(self):
        """A size nobody can resolve establishes nothing and is left out."""
        body = 'fun f(b: ByteArray) { require(b.size == UNKNOWN_SIZE) }'
        self.assertIsNone(enforced_input_size_evidence([], "f", body))

    def test_it_states_facts_and_draws_no_conclusion(self):
        body = (
            'fun f(b: ByteArray) { require(b.size == 16); '
            'Cipher.getInstance("AES/ECB/NoPadding") }'
        )
        found = enforced_input_size_evidence([], "f", body)
        self.assertIn("draws no conclusion", found["data"]["bound"])
        self.assertNotIn("runtime_security_impact", json.dumps(found))

    def test_an_alias_exposing_the_target_is_found_by_its_target_activity(self):
        """Element Android declares MainActivity with no android:exported in
        one module and, from another module's manifest, an exported LAUNCHER
        alias pointing at it. Matching android:name alone walked past the
        declaration that decides reachability, and the adjudication of
        CVE-2024-26131 closed "effective exported state not established" over
        an answer the repository contained."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alias = root / "vector-app" / "src" / "main" / "AndroidManifest.xml"
            alias.parent.mkdir(parents=True)
            alias.write_text(self.ALIAS_MANIFEST, encoding="utf-8")

            found = manifest_component_evidence(
                str(root), "im.vector.app.features.MainActivity",
            )

        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["component_tag"], "activity-alias")
        self.assertTrue(found[0]["exposes_target_as_alias"])
        self.assertEqual(found[0]["android:exported"], "true")
        self.assertTrue(found[0]["declares_intent_filter"])
        self.assertEqual(
            found[0]["android:targetActivity"],
            "im.vector.app.features.MainActivity",
        )

    def test_the_component_itself_is_not_reported_as_its_own_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            found = manifest_component_evidence(
                str(self._repository(directory)),
                "com.owncloud.android.ui.FileDisplay",
            )

        self.assertEqual(len(found), 1)
        self.assertFalse(found[0]["exposes_target_as_alias"])
        self.assertIsNone(found[0]["android:targetActivity"])
        self.assertFalse(found[0]["declares_intent_filter"])

    def test_an_alias_for_a_different_activity_is_not_matched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alias = root / "app" / "src" / "main" / "AndroidManifest.xml"
            alias.parent.mkdir(parents=True)
            alias.write_text(
                self.ALIAS_MANIFEST.replace(
                    "im.vector.app.features.MainActivity",
                    "im.vector.app.features.OtherActivity",
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                manifest_component_evidence(
                    str(root), "im.vector.app.features.MainActivity",
                ),
                [],
            )

    def test_a_permission_guard_is_carried_even_without_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            found = manifest_component_evidence(
                str(self._repository(directory)), "com.example.Sync"
            )

        self.assertEqual(len(found), 1)
        self.assertIsNone(found[0]["android:exported"])
        self.assertEqual(
            found[0]["android:permission"], "com.owncloud.PERMISSION"
        )

    def test_a_class_declared_nowhere_yields_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                manifest_component_evidence(
                    str(self._repository(directory)), "com.example.NotAComponent"
                ),
                [],
            )

    def test_a_missing_or_unparseable_repository_is_survivable(self):
        # An empty path must not become Path("."): that would walk this
        # process's own working directory looking for manifests. The first
        # full suite run after this evidence was added hung on exactly that.
        for empty in ("", "   ", None):
            with self.subTest(repository_path=empty):
                self.assertEqual(
                    manifest_component_evidence(empty, "com.example.A"), []
                )
        self.assertEqual(
            manifest_component_evidence("/nonexistent", "com.example.A"), []
        )
        with tempfile.TemporaryDirectory() as directory:
            broken = Path(directory) / "AndroidManifest.xml"
            broken.write_text("<manifest>truncated", encoding="utf-8")
            self.assertEqual(
                manifest_component_evidence(directory, "com.example.A"), []
            )

    def test_generated_manifests_under_build_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            generated = root / "app" / "build" / "intermediates" / "AndroidManifest.xml"
            generated.parent.mkdir(parents=True)
            generated.write_text(self.MANIFEST, encoding="utf-8")
            found = manifest_component_evidence(
                str(root), "com.owncloud.android.providers.FileContentProvider"
            )

        self.assertEqual(len(found), 1)

    def test_the_declaration_reaches_the_evidence_packet(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            source = root / "app" / "src" / "main" / "java" / "Provider.kt"
            source.parent.mkdir(parents=True)
            source.write_text("class FileContentProvider", encoding="utf-8")
            packet = FindingEvidencePacketBuilder().build(
                {
                    "csv_class": "com.owncloud.android.providers.FileContentProvider",
                    "method_name": "delete",
                    "method_body": "db.delete(table, where, whereArgs)",
                    "source_file_path": "app/src/main/java/Provider.kt",
                    "repository_path": str(root),
                    "spec": "SQLInjectionSpec",
                },
                {"registry_version": "2.0", "specification": "SQLInjectionSpec",
                 "family": "generic", "common": {}, "family_policy": {}},
            )

        declarations = [item for item in packet["evidence_catalog"]
                        if item["kind"] == "component_declaration"]
        self.assertEqual(len(declarations), 1)
        self.assertTrue(declarations[0]["evidence_id"].startswith("MANIFEST-"))
        self.assertEqual(declarations[0]["data"]["android:exported"], "false")


if __name__ == "__main__":
    unittest.main()


class PublicationEligibilityGateTests(unittest.TestCase):
    """"eligible_after_validation" must not be a dead enum value.

    The gate rejected the state whenever any publication blocker remained,
    but the blockers ARE the pending validations, so the state its own name
    describes was unreachable for every finding that needed validating. Across
    54 stored adjudications none ever reached it. The easydiary Zip Slip run
    caught the failure mode exactly: the model answered
    eligible_after_validation with regression_validation and
    platform_and_contract_validation blockers, was rejected, and relabelled to
    blocked with those same two blockers -- one wasted LLM round trip that
    changed no substance. Eligibility now turns on whether this pipeline's own
    build/test/source-recheck discharges each blocker.
    """

    EXTRACTION = {"claims": [{"claim_id": "C-001"}]}

    def _adjudication(self, blockers, publication_status):
        return {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "generation_status": "supported_for_review",
            "publication_status": publication_status,
            "cause_status": "confirmed",
            "confirmed_cause": "entry name reaches the output stream",
            "detector_violation": "confirmed",
            "compatibility_status": "preserved",
            "decision_claim_ids": ["C-001"],
            "blocking_for_generation": [],
            "blocking_for_publication": blockers,
        }

    @staticmethod
    def _blocker(kind, discharged):
        return {
            "kind": kind, "description": kind,
            "supporting_claim_ids": ["C-001"],
            "discharged_by_pipeline_validation": discharged,
        }

    def _issues(self, adjudication):
        return [
            issue for issue in validate_adjudication(adjudication, self.EXTRACTION)
            if "publication" in issue
        ]

    def test_blockers_the_pipeline_discharges_allow_eligibility(self):
        adjudication = self._adjudication(
            [self._blocker("regression_validation", True),
             self._blocker("test_execution", True)],
            "eligible_after_validation",
        )
        self.assertEqual(self._issues(adjudication), [])

    def test_a_blocker_the_pipeline_cannot_discharge_still_forces_blocked(self):
        adjudication = self._adjudication(
            [self._blocker("regression_validation", True),
             self._blocker("endpoint_compatibility_validation", False)],
            "eligible_after_validation",
        )
        issues = self._issues(adjudication)
        self.assertTrue(issues)
        self.assertIn("endpoint_compatibility_validation", issues[0])

    def test_a_blocker_missing_the_field_is_treated_as_undischarged(self):
        """Stored adjudications predate the field; absence must not publish."""
        adjudication = self._adjudication(
            [{"kind": "compatibility", "description": "c",
              "supporting_claim_ids": ["C-001"]}],
            "eligible_after_validation",
        )
        self.assertTrue(self._issues(adjudication))

    def test_blocked_is_never_second_guessed(self):
        adjudication = self._adjudication(
            [self._blocker("endpoint_compatibility_validation", False)],
            "blocked",
        )
        self.assertEqual(self._issues(adjudication), [])


class AnalyzerAcceptanceTests(unittest.TestCase):
    """The reporting detector decides what it accepts (2026-10-29 review, P3).

    Fread's adjudication (tls_20261015) filed "the verified primary rule's
    exact selector whitelist still rejects the forward-compatible "TLS"
    selector" from a CrySL rule research had found, while RVSec's own message
    accepted TLSV1.2, TLSV1.3 and TLS.
    """

    FREAD = {"error_message": "expecting one of TLSV1.2,TLSV1.3,TLS but found SSL"}
    STRATEGY = ('Replace only SSLContext.getInstance("SSL") with the negotiating "TLS" '
                'selector; do not pin "TLSv1.3".')

    @staticmethod
    def _adjudication(category="analyzer_reconfirmation", kind="analyzer reconfirmation"):
        return {
            "blocking_for_generation": [],
            "blocking_for_publication": [
                {"kind": kind, "category": category,
                 "description": "the exact selector whitelist rejects TLS"},
                {"kind": "device behaviour", "category": "runtime_behavior",
                 "description": "check on a device"},
            ],
        }

    def test_a_value_in_the_reporters_allowlist_discharges_the_blocker(self):
        adjudication = self._adjudication()
        values = planned_replacement_values(self.FREAD, self.STRATEGY)
        self.assertEqual(values, ["TLS"])
        [discharged] = discharge_analyzer_acceptance(adjudication, self.FREAD, values)
        self.assertEqual(discharged["discharging_values"], ["TLS"])
        self.assertEqual(discharged["discharged_from"], "blocking_for_publication")
        self.assertEqual([item["category"] for item in adjudication["blocking_for_publication"]],
                         ["runtime_behavior"])
        self.assertEqual(adjudication["discharged_blockers"], [discharged])

    def test_a_value_outside_the_allowlist_keeps_the_blocker(self):
        found_tls = {"error_message": "expecting one of {TLSv1.2, TLSv1.3} but found TLS."}
        adjudication = self._adjudication()
        self.assertEqual(discharge_analyzer_acceptance(adjudication, found_tls, ["TLS"]), [])
        self.assertEqual(len(adjudication["blocking_for_publication"]), 2)
        # A message without an allowlist settles nothing either.
        self.assertEqual(discharge_analyzer_acceptance(
            self._adjudication(), {"error_message": "unknown"}, ["TLS"]), [])

    def test_a_joined_findings_allowlist_neither_discharges_nor_blocks(self):
        # Fread's joined SSLParametersSpec finding accepts TLSv1.2/TLSv1.3;
        # each finding is judged on its own list only.
        joined = {"error_message": "expecting one of {TLSv1.2, TLSv1.3} but found SSLv3",
                  "joint_findings": [{"error_message": "expecting one of TLSV1.2,TLSV1.3,TLS "
                                                       "but found SSL"}]}
        self.assertEqual(discharge_analyzer_acceptance(self._adjudication(), joined, ["TLS"]), [])
        primary = {**self.FREAD, "joint_findings": [
            {"error_message": "expecting one of {TLSv1.2, TLSv1.3} but found SSLv3"}]}
        self.assertEqual(len(discharge_analyzer_acceptance(
            self._adjudication(), primary, ["TLS"])), 1)

    def test_only_the_structured_category_or_exact_kind_matches(self):
        free_text = self._adjudication(category="other",
                                       kind="the analyzer may reconfirm this later")
        self.assertEqual(discharge_analyzer_acceptance(free_text, self.FREAD, ["TLS"]), [])
        detector_column = {"error_message": "unknown",
                           "detector_context": {"expected": "TLS, TLSv1.2"}}
        self.assertEqual(len(discharge_analyzer_acceptance(
            self._adjudication(), detector_column, ["tls"])), 1)

    def test_a_ruled_out_or_reported_value_is_not_planned(self):
        found_tls = {"error_message": "expecting one of {TLSv1.2, TLSv1.3} but found TLS."}
        self.assertEqual(planned_replacement_values(
            found_tls, 'Keep the "TLS" context instead of "TLSv1.2" and never pin "TLSv1.3".'),
            [])

    def test_the_category_is_in_the_adjudication_schema(self):
        blocker = adjudication_schema("tls")["properties"]["blocking_for_publication"]["items"]
        self.assertIn("analyzer_reconfirmation", blocker["properties"]["category"]["enum"])

class SingleRoundGenerationTests(unittest.TestCase):
    """A correct-use promotion gets one reviewed draft, not the retry loop."""

    REASON = ("SSLContext.init documents a null KeyManager[] as the platform "
              "default key managers.")

    def _run(self, single_round, review_correct_use="", code="UNINTENDED_BEHAVIOR_CHANGE"):
        import logging
        from cognalys.llm.coordinated_generation import CoordinatedGeneration

        class Generator(CoordinatedGeneration):
            def _generate_one_coordinated_attempt(inner, *args):
                inner.attempts += 1
                inner.feedback.append(args[-1])
                return {
                    "status": "invalid", "stage": "semantic_validation",
                    "issues": [code],
                    "semantic_validation": {"status": "invalid", "errors": [{
                        "code": code,
                        "message": "client certificates change",
                        "affected_paths": ["Factory.java"]}]},
                    "edits": [], "correct_use": review_correct_use,
                }

            def replan_after_regressions(inner, *args, **kwargs):
                inner.replans += 1
                return False

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Factory.java").write_text("class Factory {}\n", encoding="utf-8")
            generator = Generator()
            generator.output_dir = root / "out"
            generator.logger = logging.getLogger("test-single-round")
            generator.attempts = generator.replans = 0
            generator.feedback = []
            adjudication = {"current_code_is_correct_use": True,
                            "correct_use_reason": self.REASON}
            if single_round:
                adjudication["single_round"] = True
            error = {"repository_path": str(root), "evidence_analysis": {
                "coordinated_fix_plan": {"required_edits": [
                    {"source_file_path": "Factory.java"}]},
                "v2": {"adjudication": adjudication},
            }}
            result = generator.generate_coordinated_file_drafts(
                error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "a.apk", "<init>")
        return generator, result

    def test_one_reviewed_draft_and_no_replan(self):
        generator, result = self._run(True, review_correct_use=self.REASON)
        self.assertEqual(generator.attempts, 1)
        self.assertEqual(generator.replans, 0)
        self.assertEqual(result["correct_use"], self.REASON)

    def test_the_adjudication_reason_closes_a_draft_the_review_did_not_settle(self):
        _, result = self._run(True)
        self.assertEqual(result["correct_use"], self.REASON)

    def test_without_the_flag_the_loop_is_unchanged(self):
        generator, result = self._run(False)
        self.assertEqual(generator.attempts, 3)
        self.assertEqual(generator.replans, 1)
        self.assertEqual(result["correct_use"], "")

    def test_a_rename_only_failure_gets_one_attempt_on_the_non_rename_route(self):
        # A failed rename check regenerates with the rule explained; it never
        # ends a single-round draft, nor the last attempt of the full loop.
        for single_round, attempts in ((True, 2), (False, 4)):
            with self.subTest(single_round=single_round):
                generator, _ = self._run(single_round, code="RENAME_REFERENCES_NOT_UPDATED")
                self.assertEqual(generator.attempts, attempts)
                last = generator.feedback[-1]
                self.assertIn("Take the non-rename route now", last.get("rename_rule", ""))
                self.assertEqual([item["code"] for item in last["errors"]],
                                 ["RENAME_REFERENCES_NOT_UPDATED"])

    def test_a_name_left_stating_the_removed_behaviour_takes_the_rename_route(self):
        # BWT's decryptDES (2026-10-24) failed on NAME_CONTRADICTS_BEHAVIOR
        # alone at every attempt and was dropped without the extra attempt.
        from cognalys.llm.semantic_validation import rename_only_failure

        self.assertTrue(rename_only_failure([{"code": "NAME_CONTRADICTS_BEHAVIOR"}]))
        self.assertFalse(rename_only_failure([{"code": "NAME_CONTRADICTS_BEHAVIOR"},
                                              {"code": "UNINTENDED_BEHAVIOR_CHANGE"}]))
        generator, _ = self._run(False, code="NAME_CONTRADICTS_BEHAVIOR")
        self.assertEqual(generator.attempts, 4)
        self.assertIn("Take the non-rename route now",
                      generator.feedback[-1].get("rename_rule", ""))


class EarlyReplanAfterRegressionTests(unittest.TestCase):
    """V1 restricted (user's decision, 2026-11-09): the first plan is made
    again before its last draft only when two drafts in a row regress for a
    reason the plan causes; a slip of the draft is redrafted on the same plan
    (20 recorded units reached a clean review that way, 15 PR pronto). The
    new plan keeps every attempt and a unit is still planned again once in
    all."""

    UBC = "UNINTENDED_BEHAVIOR_CHANGE"
    PLAN = "UNINTENDED_BEHAVIOR_CHANGE:plan"
    PLAN_IN_NEW_TEST = "UNINTENDED_BEHAVIOR_CHANGE:plan:newtest"
    NO_EFFECT = "NO_EFFECT"

    def _run(self, codes_by_plan, replan_taken=True):
        """``codes_by_plan[plan]`` lists each attempt's failure code ("" = the
        draft completes; a ":plan" suffix gives the regression the plan as
        its source); the last one repeats."""
        import logging
        from cognalys.llm.coordinated_generation import CoordinatedGeneration

        class Generator(CoordinatedGeneration):
            def _generate_one_coordinated_attempt(inner, *args):
                codes = codes_by_plan[inner.plan]
                code = codes[min(inner.plan_attempts, len(codes) - 1)]
                inner.plan_attempts += 1
                inner.events.append((inner.plan, code or "complete"))
                if not code:
                    return {"status": "complete", "edits": []}
                if code == self.NO_EFFECT:
                    return {"status": "invalid", "stage": "behavior_review",
                            "issues": ["PATCH_HAS_NO_EFFECT"], "no_effect_reason": "same value",
                            "semantic_validation": {"status": "invalid", "errors": []},
                            "edits": []}
                name, _, rest = code.partition(":")
                source, _, where = rest.partition(":")
                return {
                    "status": "invalid", "stage": "semantic_validation", "issues": [name],
                    "semantic_validation": {"status": "invalid", "errors": [{
                        "code": name, "message": "first run throws",
                        "affected_paths": ["Factory.java"],
                        **({"regression_source": source} if source else {}),
                        **({"regression_in_new_test": True} if where else {})}]},
                    "edits": [],
                }

            def replan_after_regressions(inner, error, failures, *args, **kwargs):
                if error.get("_behavior_replanned"):
                    return False  # once per unit, as the real one
                inner.events.append(("replan", [item["code"] for item in failures]))
                error["_behavior_replanned"] = True
                error["previous_patch_regressions"] = ["first run throws"]
                if not replan_taken:
                    return False
                inner.plan += 1
                inner.plan_attempts = 0
                return True

            def replan_after_draft_failures(inner, *args, **kwargs):
                return False

            def replan_after_no_effect(inner, error, *args, **kwargs):
                from cognalys.llm.coordinated_generation import replanned_once

                inner.events.append(("no-effect replan asked", replanned_once(error),
                                     "previous_patch_regressions" in error))
                return False

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Factory.java").write_text("class Factory {}\n", encoding="utf-8")
            generator = Generator()
            generator.output_dir = root / "out"
            generator.logger = logging.getLogger("test-early-replan")
            generator.plan = generator.plan_attempts = 0
            generator.events = []
            error = {"repository_path": str(root), "evidence_analysis": {
                "coordinated_fix_plan": {"required_edits": [
                    {"source_file_path": "Factory.java"}]}}}
            result = generator.generate_coordinated_file_drafts(
                error, "MULTI_FILE_FIX_SUPPORTED", "a.apk", "save")
        return generator.events, result

    def test_two_plan_regressions_in_a_row_replan_and_the_new_plan_keeps_every_attempt(self):
        events, result = self._run([[self.PLAN, self.PLAN, ""], [self.UBC, self.UBC, ""]])
        self.assertEqual(events, [(0, self.PLAN), (0, self.PLAN), ("replan", [self.UBC]),
                                  (1, self.UBC), (1, self.UBC), (1, "complete")])
        self.assertEqual(result["status"], "complete")

    def test_a_slip_of_the_draft_is_redrafted_on_the_same_plan(self):
        # Trigger, Tokn, KeyPass, Grocy (2026-10-23 to 10-28): the redraft
        # fixed the slip the review named and the unit became PR pronto.
        events, result = self._run([[self.UBC, ""]])
        self.assertEqual(events, [(0, self.UBC), (0, "complete")])
        self.assertEqual(result["status"], "complete")
        events, _ = self._run([[self.UBC, self.UBC, ""]])
        self.assertEqual(events, [(0, self.UBC), (0, self.UBC), (0, "complete")])

    def test_one_plan_regression_is_not_enough(self):
        # Grocy's TLSSocketFactory (run_research_medium) and its keystore
        # load (run_v6): a draft did what the plan asked, the review objected,
        # and the next draft or review on the same plan passed.
        events, result = self._run([[self.PLAN, ""]])
        self.assertEqual(events, [(0, self.PLAN), (0, "complete")])
        self.assertEqual(result["status"], "complete")
        events, _ = self._run([[self.UBC, self.PLAN, ""]])
        self.assertEqual(events, [(0, self.UBC), (0, self.PLAN), (0, "complete")])
        events, _ = self._run([[self.PLAN, self.UBC, ""]])
        self.assertEqual(events, [(0, self.PLAN), (0, self.UBC), (0, "complete")])

    def test_regressions_on_every_attempt_replan_after_the_last_as_before(self):
        events, result = self._run([[self.UBC, self.PLAN, self.PLAN], [""]])
        self.assertEqual(events, [(0, self.UBC), (0, self.PLAN), (0, self.PLAN),
                                  ("replan", [self.UBC]), (1, "complete")])
        self.assertEqual(result["status"], "complete")

    def test_a_unit_is_planned_again_once_in_all(self):
        events, result = self._run([[self.PLAN], [self.PLAN]])
        self.assertEqual(events, [(0, self.PLAN), (0, self.PLAN), ("replan", [self.UBC]),
                                  (1, self.PLAN), (1, self.PLAN), (1, self.PLAN)])
        self.assertEqual(result["status"], "invalid")

    def test_when_the_new_plan_is_not_taken_the_first_plan_keeps_its_attempts(self):
        events, result = self._run([[self.PLAN, self.PLAN, ""]], replan_taken=False)
        self.assertEqual(events, [(0, self.PLAN), (0, self.PLAN), ("replan", [self.UBC]),
                                  (0, "complete")])
        self.assertEqual(result["status"], "complete")

    def test_plan_regressions_only_in_a_generated_test_reach_the_last_attempt(self):
        # LocalSend's loadOrCreateKeyStore (2026-10-29): the plan required the
        # androidTest, every review found its only regression there, and the
        # last attempt dropped the test and was reviewed clean (PR pronto).
        events, result = self._run([[self.PLAN_IN_NEW_TEST, self.PLAN_IN_NEW_TEST, ""]])
        self.assertEqual(events, [(0, self.PLAN_IN_NEW_TEST), (0, self.PLAN_IN_NEW_TEST),
                                  (0, "complete")])
        self.assertEqual(result["status"], "complete")
        from cognalys.llm.coordinated_generation import early_replan_after_regression

        in_test = {"code": self.UBC, "regression_source": "plan",
                   "regression_in_new_test": True}
        production = {"code": self.UBC, "regression_source": "plan"}
        self.assertFalse(early_replan_after_regression([in_test], [in_test]))
        self.assertTrue(early_replan_after_regression([in_test, production], [production]))

    def test_a_new_plan_not_taken_leaves_the_first_plan_its_other_replans(self):
        # Review of 9663308 (2026-11-09): the refused early replan still
        # counted as the unit's one replan, so a no-effect third draft (the
        # BlueGate run_v9 shape) closed without the replan that adds the
        # value's consumers.
        events, _ = self._run([[self.PLAN, self.PLAN, self.NO_EFFECT]], replan_taken=False)
        self.assertEqual(events, [(0, self.PLAN), (0, self.PLAN), ("replan", [self.UBC]),
                                  (0, self.NO_EFFECT), ("no-effect replan asked", False, False)])

    def test_a_draft_check_failure_between_breaks_the_run_of_plan_regressions(self):
        check = "UNNECESSARY_PUBLIC_API_EXPANSION"
        events, _ = self._run([[self.PLAN, check, self.UBC], [""]])
        self.assertEqual(events, [(0, self.PLAN), (0, check), (0, self.UBC),
                                  ("replan", [self.UBC]), (1, "complete")])
        # The second plan regression in a row on the last attempt replans
        # there, as every regression on the last attempt does.
        events, _ = self._run([[check, self.PLAN, self.PLAN], [""]])
        self.assertEqual(events, [(0, check), (0, self.PLAN), (0, self.PLAN),
                                  ("replan", [self.UBC]), (1, "complete")])

    def test_a_new_plan_not_taken_leaves_the_first_plans_artifacts_on_disk(self):
        # Review of 9663308 (2026-11-09): the refused replan overwrote
        # <index>_<method>_adjudication.json and _patch_plan.json, which
        # learning.retrospective and prs.impact_class read as the plan the
        # first plan's completed draft came from.
        import logging

        from cognalys.llm.coordinated_generation import (
            REPLANS_NOT_TAKEN_DIR, CoordinatedGeneration)

        class Generator(CoordinatedGeneration):
            def adjudicate_finding(inner, error, apk_name, method_name):
                for name in ("adjudication", "patch_plan", "external_research"):
                    (folder / f"3_save_{name}.json").write_text(
                        '{"plan": "second"}', encoding="utf-8")
                return inner.answer, {"plan": "second"}

        def run(answer):
            generator = Generator()
            generator.output_dir = root / "out"
            generator.logger = logging.getLogger("test-replan-artifacts")
            generator.answer = answer
            error = {"error_index": 3, "evidence_analysis": {"decision": "FIX_SUPPORTED"},
                     "v2_artifacts": {"plan": "first"}}
            return generator._take_new_plan(error, "a.apk", "save", "FIX_SUPPORTED",
                                            "behaviour regressions", "taken"), error

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "out" / "v2_artifacts" / "a.apk"
            folder.mkdir(parents=True)
            for name in ("adjudication", "patch_plan"):
                (folder / f"3_save_{name}.json").write_text('{"plan": "first"}',
                                                            encoding="utf-8")
            (folder / "13_save_adjudication.json").write_text("{}", encoding="utf-8")
            taken, error = run({"generation_status": "not_supported"})
            self.assertFalse(taken)
            self.assertEqual(error["v2_artifacts"], {"plan": "first"})
            for name in ("adjudication", "patch_plan"):
                self.assertEqual((folder / f"3_save_{name}.json").read_text(encoding="utf-8"),
                                 '{"plan": "first"}')
            # A file only the refused replan wrote is not left beside them.
            self.assertFalse((folder / "3_save_external_research.json").exists())
            self.assertEqual(sorted(path.name for path in (folder / REPLANS_NOT_TAKEN_DIR)
                                    .iterdir()),
                             ["3_save_adjudication_attempt1.json",
                              "3_save_external_research_attempt1.json",
                              "3_save_patch_plan_attempt1.json"])
            # Another finding's artifacts are untouched.
            self.assertEqual((folder / "13_save_adjudication.json").read_text(encoding="utf-8"),
                             "{}")
            # A plan taken stays.
            from unittest import mock

            from cognalys.llm import coordinated_generation

            with mock.patch.object(coordinated_generation, "_replan_refusal", return_value=""):
                taken, error = run({"generation_status": "supported",
                                    "decision": "FIX_SUPPORTED",
                                    "coordinated_fix_plan": {"required_edits": [
                                        {"source_file_path": "Factory.java"}]}})
            self.assertTrue(taken)
            self.assertEqual((folder / "3_save_adjudication.json").read_text(encoding="utf-8"),
                             '{"plan": "second"}')

    def test_the_predicate_needs_two_regressions_from_the_plan(self):
        from cognalys.llm.coordinated_generation import early_replan_after_regression

        plan = {"code": self.UBC, "regression_source": "plan"}
        self.assertTrue(early_replan_after_regression(
            [{"code": "SYMBOL_NOT_DECLARED_IN_REPOSITORY"}, plan],
            [plan, {"code": self.UBC, "regression_source": "draft"}]))
        self.assertFalse(early_replan_after_regression([plan]))
        self.assertFalse(early_replan_after_regression([plan], [{"code": self.UBC}]))
        self.assertFalse(early_replan_after_regression(
            [plan], [{"code": "UNNECESSARY_PUBLIC_API_EXPANSION", "regression_source": "plan"}]))
        self.assertFalse(early_replan_after_regression([], [plan]))

    def test_a_regression_is_the_plans_only_with_a_reason(self):
        from cognalys.llm.coordinated_generation import regression_source

        self.assertEqual(regression_source(
            {"source": " Plan ", "source_reason": "the plan removes TLSv1.1"}), "plan")
        self.assertEqual(regression_source({"source": "plan", "source_reason": " "}), "draft")
        # A contract-18 answer has no source: redrafted as before V1.
        self.assertEqual(regression_source({"scenario": "first run"}), "draft")
        self.assertEqual(regression_source({"source": "unclear", "source_reason": "x"}), "draft")
        self.assertEqual(regression_source("plan"), "draft")
