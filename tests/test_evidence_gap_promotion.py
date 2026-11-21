"""A reported violation blocked only on missing evidence is generated for review.

exp_final_20261019: FairEmail's getFingerprint (cause and violation confirmed,
the `hash` parameter's source missing), FreeOTP's encrypt (cause not
established from source, the violation observed by RVSec) and treehouses'
encrypt (the adjudicator found the report false) are the three shapes.
"""
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.pipeline_architecture import (  # noqa: E402
    promote_evidence_gap_to_review,
    validate_adjudication_of,
)

EXTRACTION = {"claims": [{"claim_id": "C-001"}]}
FINDING = {"error_message": "expecting one of SHA-256,SHA-384,SHA-512 but found SHA1"}


def blocked(*categories, **extra):
    base = {
        "decision": "NO_SAFE_FIX",
        "generation_status": "blocked",
        "publication_status": "blocked",
        "cause_status": "confirmed",
        "confirmed_cause": "SHA1 reaches MessageDigest.getInstance",
        "detector_violation": "confirmed",
        "scope_status": "incomplete",
        "decision_claim_ids": ["C-001"],
        "blocking_for_generation": [
            {"kind": f"k{index}", "category": category,
             "description": f"gap {index}", "supporting_claim_ids": ["C-001"]}
            for index, category in enumerate(categories)
        ],
        "blocking_for_publication": [],
    }
    base.update(extra)
    return base


class EvidenceGapPromotionTests(unittest.TestCase):
    def test_a_confirmed_violation_missing_evidence_becomes_a_review_patch(self):
        adjudication = blocked("code_evidence_missing", "target_unresolved")
        moved = promote_evidence_gap_to_review(adjudication, EXTRACTION, FINDING)
        self.assertEqual(moved, ["code_evidence_missing", "target_unresolved"])
        self.assertEqual(adjudication["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(adjudication["generation_status"], "supported_for_review")
        self.assertEqual(adjudication["publication_status"], "blocked")
        self.assertEqual(adjudication["blocking_for_generation"], [])
        self.assertEqual(len(adjudication["blocking_for_publication"]), 2)
        self.assertIn("right place", adjudication["review_assumptions"][-1])
        self.assertEqual(validate_adjudication_of(adjudication, EXTRACTION, FINDING), [])

    def test_gaps_mixed_with_human_decided_questions_are_promoted(self):
        adjudication = blocked("target_unresolved", "compatibility_contract")
        self.assertTrue(promote_evidence_gap_to_review(adjudication, EXTRACTION, FINDING))

    def test_an_unconfirmed_cause_needs_the_runtime_observation(self):
        unknown = {"cause_status": "unknown", "detector_violation": "unknown"}
        adjudication = blocked("cause_unconfirmed", **unknown)
        self.assertEqual(promote_evidence_gap_to_review(adjudication, EXTRACTION, FINDING), [])
        self.assertEqual(adjudication["decision"], "NO_SAFE_FIX")
        moved = promote_evidence_gap_to_review(
            adjudication, EXTRACTION, FINDING, runtime_observed=True)
        self.assertEqual(moved, ["cause_unconfirmed"])
        self.assertEqual(adjudication["cause_authority"], {"kind": "runtime_observation"})
        self.assertIn("found SHA1", adjudication["confirmed_cause"])
        self.assertTrue(any("runtime observation" in item
                            for item in adjudication["review_assumptions"]))

    def test_a_violation_found_false_is_never_promoted(self):
        adjudication = blocked("cause_unconfirmed", cause_status="inferred",
                               detector_violation="not_confirmed")
        self.assertEqual(promote_evidence_gap_to_review(
            adjudication, EXTRACTION, FINDING, runtime_observed=True), [])

    def test_only_human_decided_blockers_are_left_to_the_existing_rule(self):
        adjudication = blocked("compatibility_contract")
        self.assertEqual(promote_evidence_gap_to_review(adjudication, EXTRACTION, FINDING), [])

    def test_another_blocker_category_keeps_generation_blocked(self):
        adjudication = blocked("code_evidence_missing", "unsafe_behavior_change")
        self.assertEqual(promote_evidence_gap_to_review(adjudication, EXTRACTION, FINDING), [])

    def test_an_echo_takes_its_cause_from_the_producer_in_its_unit(self):
        """Salty's encode: CipherSpec upstream-refused, deriveKey's key reaches Cipher.init."""
        from cognalys.llm.generate_error_fixes import join_findings_of_one_sequence

        apk = Path("/runs/salty.apk/errors.json")
        common = {"_file_path": apk, "csv_class": "x.HashUtils", "source_file_path": "HashUtils.kt"}
        encode = {**common, "unique_error_id": "encode", "method_name": "encode",
                  "spec": "CipherSpec", "detector_context": {"label": "upstream-refused"},
                  "error_message": "the key given to Cipher.init was already reported by the "
                                   "specification that produced it",
                  "method_body": "fun encode(message: String, salt: String): String {\n"
                                 "    val key = deriveKey(salt)\n"
                                 "    val cipher = Cipher.getInstance(ALGORITHM)\n"
                                 "    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))\n"
                                 "    return encodeToString(cipher.doFinal(bytes))\n}"}
        derive = {**common, "unique_error_id": "derive", "method_name": "deriveKey",
                  "spec": "PBEKeySpecSpec", "detector_context": {"label": "not-observed"},
                  "error_message": "the second argument was not observed to come from a "
                                   "randomized source",
                  "method_body": "private fun deriveKey(userSalt: String): SecretKeySpec { }"}
        self.assertEqual(join_findings_of_one_sequence([encode, derive]), {"derive": "encode"})
        self.assertEqual(encode["echo_of"]["method"], "deriveKey")
        self.assertEqual(encode["echo_of"]["binding"], "key")

        unknown = {"cause_status": "unknown", "detector_violation": "unknown",
                   "confirmed_cause": "the formal cause of the key-provenance predicate is not settled"}
        adjudication = blocked("code_evidence_missing", "maintainer_decision", **unknown)
        finding = {"error_message": encode["error_message"]}
        moved = promote_evidence_gap_to_review(
            adjudication, EXTRACTION, finding, runtime_observed=True,
            echo_producer=encode["echo_of"])
        self.assertTrue(moved)
        self.assertEqual(adjudication["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(adjudication["cause_status"], "confirmed")
        self.assertEqual(adjudication["cause_authority"]["kind"], "producer_finding")
        self.assertIn("deriveKey", adjudication["confirmed_cause"])
        self.assertIn("randomized source", adjudication["confirmed_cause"])
        self.assertNotIn("code_evidence_missing", adjudication["evidence_gap_promoted"])
        self.assertEqual([item["category"] for item in adjudication["blocking_for_publication"]],
                         ["maintainer_decision"])
        self.assertEqual([item["category"] for item in adjudication["discharged_blockers"]],
                         ["code_evidence_missing"])
        self.assertFalse(any("lacked evidence" in item
                             for item in adjudication["review_assumptions"]))
        self.assertEqual(validate_adjudication_of(adjudication, EXTRACTION, finding), [])

    def test_a_joined_finding_brings_its_own_specification_context(self):
        """BlueGate run_v6/run_v7 (2026-10-31): generateNewKeyPair
        [KeyPairGeneratorSpec], joined into getOrCreateKeyPair [KeyPairSpec],
        reached the extraction and the adjudication as a name and a message,
        and both blocked on "the active KeyPairGenerator rule ... was not
        supplied"."""
        from cognalys.llm.evidence_packet import joint_specification_contexts
        from cognalys.llm.pipeline_architecture import FindingEvidencePacketBuilder, PolicyRegistry
        from cognalys.llm.generate_error_fixes import join_findings_of_one_sequence

        apk = Path("/runs/bluegate.apk/errors.json")
        common = {"_file_path": apk, "csv_class": "org.cleverfox.bluegate.KeyManager",
                  "source_file_path": "app/src/main/java/org/cleverfox/bluegate/KeyManager.kt"}

        def context(spec, governed):
            return {"status": "available", "spec_id": spec, "name": spec,
                    "source_verified": True, "applies_to_types": [governed],
                    "protocol": f"{spec} protocol",
                    "events": [{"name": "E", "api_patterns": [governed.rsplit(".", 1)[-1] + "("],
                                "condition": f"a call of {governed}"}]}

        generator = context("KeyPairGeneratorSpec", "java.security.KeyPairGenerator")
        primary = {**common, "unique_error_id": "pair", "method_name": "getOrCreateKeyPair",
                   "spec": "KeyPairSpec", "error_message": "no generator of the private key",
                   "specification_context": context("KeyPairSpec", "java.security.KeyPair"),
                   "method_body": "fun getOrCreateKeyPair(): KeyPair {\n"
                                  "    return generateNewKeyPair(alias)\n}"}
        joined = {**common, "unique_error_id": "gen", "method_name": "generateNewKeyPair",
                  "spec": "KeyPairGeneratorSpec",
                  "error_message": "no preparation of the AlgorithmParameterSpec",
                  "specification_context": generator,
                  "method_body": "private fun generateNewKeyPair(alias: String): KeyPair { }"}
        self.assertEqual(join_findings_of_one_sequence([primary, joined]), {"gen": "pair"})
        self.assertEqual(joint_specification_contexts(primary),
                         [("KeyPairGeneratorSpec", generator)])
        # The finding's own rule is never listed as a joint one.
        self.assertEqual(joint_specification_contexts(
            {"spec": "KeyPairGeneratorSpec",
             "joint_specification_contexts": primary["joint_specification_contexts"]}), [])
        # The packet carries both rules as citable specifications.
        policy = PolicyRegistry(Path(__file__).resolve().parents[1] / "data" / "llm_policies").select(
            "generic", "KeyPairSpec")
        packet = FindingEvidencePacketBuilder(60000).build(primary, policy)
        specifications = [item["data"].get("spec_id") for item in packet["evidence_catalog"]
                          if item["kind"] == "verified_specification"]
        self.assertEqual(specifications, ["KeyPairSpec", "KeyPairGeneratorSpec"])
        self.assertNotIn("specification_context", str(packet["finding"]["joint_findings"]))

    def test_an_echo_with_no_producer_in_its_unit_is_promoted_as_before(self):
        unknown = {"cause_status": "unknown", "detector_violation": "unknown"}
        adjudication = blocked("code_evidence_missing", **unknown)
        moved = promote_evidence_gap_to_review(
            adjudication, EXTRACTION, FINDING, runtime_observed=True, echo_producer=None)
        self.assertEqual(moved, ["code_evidence_missing"])
        self.assertEqual(adjudication["cause_authority"], {"kind": "runtime_observation"})
        self.assertEqual(adjudication["evidence_gap_promoted"], ["code_evidence_missing"])
        self.assertEqual([item["category"] for item in adjudication["blocking_for_publication"]],
                         ["code_evidence_missing"])

    def test_a_producer_whose_result_never_reaches_the_echo_is_no_link(self):
        from cognalys.llm.generate_error_fixes import returned_value_reaches_a_call

        self.assertEqual(returned_value_reaches_a_call(
            "fun f() {\n  val key = deriveKey(salt)\n  log(\"done\")\n}", "deriveKey"), {})
        self.assertEqual(returned_value_reaches_a_call(
            "fun f() { return deriveKey(salt) }", "deriveKey"), {})
        self.assertEqual(returned_value_reaches_a_call(
            "void f() { cipher.init(1, deriveKey(salt)); }", "deriveKey")["binding"], "")
        self.assertEqual(returned_value_reaches_a_call(
            "void f() {\n SecretKey k = derive(p);\n c.init(1, k);\n}", "derive")["binding"], "k")

    def test_a_correct_use_answer_is_promoted_for_a_single_round(self):
        adjudication = blocked(
            "code_evidence_missing", current_code_is_correct_use=True,
            correct_use_reason="init(null) selects the documented platform default")
        self.assertTrue(promote_evidence_gap_to_review(adjudication, EXTRACTION, FINDING))
        self.assertIs(adjudication["single_round"], True)
        self.assertEqual(validate_adjudication_of(adjudication, EXTRACTION, FINDING), [])

    def test_without_a_correct_use_answer_no_single_round_is_marked(self):
        adjudication = blocked("code_evidence_missing")
        self.assertTrue(promote_evidence_gap_to_review(adjudication, EXTRACTION, FINDING))
        self.assertNotIn("single_round", adjudication)

    def test_false_positive_shapes_and_dependencies_are_left_alone(self):
        # A matched shape is answered not_confirmed, and that is never promoted.
        self.assertEqual(promote_evidence_gap_to_review(
            dict(blocked("code_evidence_missing"), detector_violation="not_confirmed"),
            EXTRACTION, FINDING, runtime_observed=True), [])
        self.assertEqual(promote_evidence_gap_to_review(
            blocked("code_evidence_missing"), EXTRACTION, FINDING, family="dependency"), [])


if __name__ == "__main__":
    unittest.main()
