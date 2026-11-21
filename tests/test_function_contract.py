"""function_contract, "What the fix removes" and concern_verdicts (ESPEC_Q2Q3).

Input Leaf ServerScanner.discoverySslContext (agent_baseline_20261108): the
packet held the fingerprint-pinned session connection and a self-signed test
server in all 7 executions, the extraction never said who the discovery code
serves, and the review of the same platform-trust patch reported the lost
discovery of self-signed servers in 17 of 29 answers and passed it in 12.
"""
import json
import unittest
from copy import deepcopy
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm import adjudication_rules  # noqa: E402
from cognalys.llm.adjudication_rules import (  # noqa: E402
    FUNCTION_CONTRACT_MEANING, NEUTRAL_FUNCTION_CONTRACT, established_function_contract,
    extraction_for_adjudication, sanitize_evidence_extraction)
from cognalys.llm.llm_contracts import (  # noqa: E402
    FUNCTION_CONTRACT_ACTIVATIONS, FUNCTION_CONTRACT_COUNTERPARTS, FUNCTION_CONTRACT_DEPENDENCE,
    evidence_extraction_schema)

PINNED = ("class InputLeapConnection {\n"
          "    // The server presents a self-signed certificate; we pin its fingerprint.\n"
          "    val trust = FingerprintTrustManager(knownFingerprint)\n}\n")
PACKET = {
    "evidence_catalog": [
        {"evidence_id": "SRC-001", "kind": "target_source",
         "data": {"source_file_path": "app/ServerScanner.kt",
                  "content": "fun discoverySslContext() { trustAll() }"}},
        {"evidence_id": "SRC-002", "kind": "related_source",
         "data": {"source_file_path": "app/InputLeapConnection.kt", "content": PINNED}},
        {"evidence_id": "SPEC-001", "kind": "verified_specification",
         "data": {"content": "SPEC SSLContext ... the server presents a certificate"}},
        {"evidence_id": "FLOW-001", "kind": "dataflow",
         "data": {"path": "app/Server.kt", "edge": "scanner -> server on the local network"}},
    ],
    "external_evidence_catalog": [{"evidence_id": "WEB-001", "kind": "web"}],
}
QUOTE = "// The server presents a self-signed certificate; we pin its fingerprint."
CONTRACT = {
    "purpose": "Discovers Input Leap servers on the local network.",
    "counterpart": "user_operated_peer", "activation": "always",
    "depends_on_reported_behavior": "established",
    "dependence": "The user's own server presents a self-signed certificate the app pins.",
    "evidence_ids": ["SRC-002"], "quotes": [{"evidence_id": "SRC-002", "quote": QUOTE}],
}


def _extraction(contract=None, **extra):
    record = {"claims": [], "predicate_assessment": [], **extra}
    if contract is not None:
        record["function_contract"] = contract
    return record


class FunctionContractExtractionTests(unittest.TestCase):
    def test_every_family_schema_ends_with_the_function_contract(self):
        for family in ("tls", "message_digest", "cipher", "dependency", "key_generation", "generic"):
            with self.subTest(family=family):
                schema = evidence_extraction_schema(family)
                self.assertEqual(list(schema["properties"])[-1], "function_contract")
                self.assertIn("function_contract", schema["required"])
                contract = schema["properties"]["function_contract"]
                self.assertFalse(contract["additionalProperties"])
                props = contract["properties"]
                self.assertEqual(props["counterpart"]["enum"], list(FUNCTION_CONTRACT_COUNTERPARTS))
                self.assertEqual(props["activation"]["enum"], list(FUNCTION_CONTRACT_ACTIVATIONS))
                self.assertEqual(props["depends_on_reported_behavior"]["enum"],
                                 list(FUNCTION_CONTRACT_DEPENDENCE))
                quote = props["quotes"]["items"]
                self.assertEqual(quote["type"], "object")
                self.assertFalse(quote["additionalProperties"])
                self.assertEqual(sorted(quote["required"]), ["evidence_id", "quote"])

    def test_an_established_contract_quoting_another_repository_entry_is_kept(self):
        sanitized, notes = sanitize_evidence_extraction(_extraction(CONTRACT), PACKET)
        self.assertEqual(sanitized["function_contract"], CONTRACT)
        self.assertEqual(notes, [])

    def test_a_quote_not_in_its_entry_or_from_the_reported_source_is_dropped(self):
        cases = {
            "reported source": ("SRC-001", "fun discoverySslContext() { trustAll() }"),
            "specification": ("SPEC-001", "the server presents a certificate"),
            "not in the entry": ("SRC-002", "this sentence is nowhere in the file"),
        }
        for name, (evidence_id, quote) in cases.items():
            with self.subTest(name):
                contract = {**CONTRACT, "evidence_ids": [evidence_id],
                            "quotes": [{"evidence_id": evidence_id, "quote": quote}]}
                sanitized, notes = sanitize_evidence_extraction(_extraction(contract), PACKET)
                kept = sanitized["function_contract"]
                self.assertEqual(kept["quotes"], [])
                self.assertEqual(kept["depends_on_reported_behavior"], "not_established")
                self.assertIn("function_contract: dropped 1 quote(s) not found in a repository "
                              "entry other than the reported source and the specification", notes)
                self.assertIn("function_contract: depends_on_reported_behavior downgraded to "
                              "not_established (no verified quote)", notes)
        # A quote whose entry is not among its evidence_ids, a web entry, a
        # quote too short or too long, and more than three quotes.
        contract = {**CONTRACT, "evidence_ids": ["SRC-002", "WEB-001", "SRC-404"], "quotes": [
            {"evidence_id": "WEB-001", "quote": "a web page saying so"},
            {"evidence_id": "SRC-002", "quote": "pin"},
            {"evidence_id": "SRC-002", "quote": "x" * 401},
            *[{"evidence_id": "SRC-002", "quote": QUOTE}] * 4]}
        sanitized, notes = sanitize_evidence_extraction(_extraction(contract), PACKET)
        kept = sanitized["function_contract"]
        self.assertEqual(kept["evidence_ids"], ["SRC-002", "WEB-001"])
        self.assertEqual(len(kept["quotes"]), 3)
        self.assertEqual(kept["depends_on_reported_behavior"], "established")
        self.assertIn("function_contract: removed invalid evidence reference(s) ['SRC-404']", notes)
        self.assertIn("function_contract: dropped 4 quote(s) not found in a repository entry "
                      "other than the reported source and the specification", notes)

    def test_a_quote_matches_across_whitespace_and_in_structured_entries(self):
        spread = "// The server presents   a self-signed\ncertificate;  we pin its fingerprint."
        structured = '"edge": "scanner -> server on the local network"'
        contract = {**CONTRACT, "evidence_ids": ["SRC-002", "FLOW-001"], "quotes": [
            {"evidence_id": "SRC-002", "quote": spread},
            {"evidence_id": "FLOW-001", "quote": structured}]}
        sanitized, notes = sanitize_evidence_extraction(_extraction(contract), PACKET)
        self.assertEqual(len(sanitized["function_contract"]["quotes"]), 2)
        self.assertEqual(notes, [])

    def test_an_unknown_or_same_app_counterpart_or_an_empty_dependence_is_never_established(self):
        for change, reason in (({"counterpart": "unknown"}, "counterpart unknown"),
                               ({"counterpart": "same_app_or_device"},
                                "counterpart same_app_or_device"),
                               ({"dependence": "  "}, "empty dependence")):
            with self.subTest(reason):
                sanitized, notes = sanitize_evidence_extraction(
                    _extraction({**CONTRACT, **change}), PACKET)
                self.assertEqual(sanitized["function_contract"]["depends_on_reported_behavior"],
                                 "not_established")
                self.assertIn("function_contract: depends_on_reported_behavior downgraded to "
                              f"not_established ({reason})", notes)
        sanitized, notes = sanitize_evidence_extraction(
            _extraction({**CONTRACT, "counterpart": "a server", "activation": None}), PACKET)
        self.assertEqual(sanitized["function_contract"]["counterpart"], "unknown")
        self.assertEqual(sanitized["function_contract"]["activation"], "unknown")
        self.assertIn("function_contract: counterpart 'a server' is not a known value; set to "
                      "unknown", notes)

    def test_a_contract_that_is_not_an_object_becomes_neutral(self):
        sanitized, notes = sanitize_evidence_extraction(_extraction("established"), PACKET)
        self.assertEqual(sanitized["function_contract"], NEUTRAL_FUNCTION_CONTRACT)
        self.assertEqual(notes, ["function_contract: not an object; replaced by the neutral "
                                 "contract"])

    def test_an_extraction_without_the_field_stays_without_it(self):
        sanitized, notes = sanitize_evidence_extraction(_extraction(), PACKET)
        self.assertNotIn("function_contract", sanitized)
        self.assertEqual(notes, [])
        self.assertEqual(established_function_contract(_extraction(), PACKET), {})

    def test_only_an_established_contract_is_carried_with_its_quotes(self):
        carried = established_function_contract(_extraction(CONTRACT), PACKET)
        self.assertEqual(list(carried), ["purpose", "counterpart", "activation",
                                         "depends_on_reported_behavior", "dependence",
                                         "evidence", "meaning"])
        self.assertEqual(carried["evidence"], [{
            "evidence_id": "SRC-002", "kind": "related_source",
            "source_file_path": "app/InputLeapConnection.kt", "quote": QUOTE}])
        self.assertEqual(carried["meaning"], FUNCTION_CONTRACT_MEANING)
        self.assertEqual(established_function_contract(
            _extraction({**CONTRACT, "depends_on_reported_behavior": "not_established"}),
            PACKET), {})
        # A record nobody sanitized: its quote from the reported source does
        # not reach the review.
        unsanitized = {**CONTRACT, "evidence_ids": ["SRC-001"], "quotes": [
            {"evidence_id": "SRC-001", "quote": "fun discoverySslContext() { trustAll() }"}]}
        self.assertEqual(established_function_contract(_extraction(unsanitized), PACKET), {})

    def test_the_adjudication_reads_the_extraction_without_the_field(self):
        from cognalys.llm import finding_adjudication

        extraction = _extraction(CONTRACT, needs_more_evidence=False)
        before = deepcopy(extraction)
        read = extraction_for_adjudication(extraction)
        self.assertNotIn("function_contract", read)
        self.assertEqual(read, {key: value for key, value in before.items()
                                if key != "function_contract"})
        self.assertEqual(extraction, before)
        source = Path(finding_adjudication.__file__).read_text(encoding="utf-8")
        self.assertEqual(source.count("extraction_for_adjudication(extraction)"), 2)
        self.assertNotIn('"validated_evidence_extraction": extraction,', source)

    def test_the_analysis_record_carries_it_only_when_established(self):
        from cognalys.llm.adjudication import _analysis_record

        packet = {**PACKET, "finding": {"spec_family": "tls"}, "input_hashes": {}}
        for contract, expected in ((CONTRACT, True), (None, False),
                                   ({**CONTRACT, "counterpart": "unknown"}, False)):
            with self.subTest(expected=expected, contract=bool(contract)):
                record = _analysis_record({}, packet, {}, _extraction(contract), {}, {}, {})
                self.assertEqual("function_contract" in record["v2"], expected)
                if expected:
                    self.assertEqual(record["v2"]["function_contract"]["evidence"][0]["quote"],
                                     QUOTE)

    def test_the_extraction_prompt_states_the_field_once_after_the_intent_rule(self):
        from cognalys.llm import finding_adjudication
        from cognalys.llm.finding_adjudication import (
            _FUNCTION_CONTRACT_EXTRACTION_RULE, _REPORTED_BY_DETECTOR_EXTRACTION_RULE,
            evidence_extraction_system_prompt)

        for reported in (False, True):
            with self.subTest(reported=reported):
                system = evidence_extraction_system_prompt(reported)
                marker = "function_contract says who the reported code serves"
                self.assertEqual(system.count(marker), 1)
                self.assertLess(system.index("An INTENT deliberate_insecurity entry"),
                                system.index(marker))
                self.assertLess(system.index(marker),
                                system.index("Return only the requested structured output."))
                if reported:
                    self.assertLess(system.index(_REPORTED_BY_DETECTOR_EXTRACTION_RULE),
                                    system.index(marker))
                # Without the constant, the earlier text.
                original = system.replace(_FUNCTION_CONTRACT_EXTRACTION_RULE, "")
                self.assertTrue(original.endswith(
                    "the gate; it never refutes the reported violation. Return only the "
                    "requested structured output."))
        self.assertIn("evidence_extraction_system_prompt(bool(reported))",
                      Path(finding_adjudication.__file__).read_text(encoding="utf-8"))


class WhatTheFixRemovesReviewTests(unittest.TestCase):
    def _run(self, error_extra=None, review=None):
        from test_applied_edits_match_text import CLEAN_REVIEW, METHOD_EDIT, _coordinated_run

        return _coordinated_run(review or (lambda call: CLEAN_REVIEW), [METHOD_EDIT],
                                error_extra=error_extra)

    def test_the_review_payload_carries_an_established_contract_last(self):
        carried = established_function_contract(_extraction(CONTRACT), PACKET)
        extra = {"evidence_analysis": {
            "confirmed_cause": "cause",
            "coordinated_fix_plan": {"required_edits": [
                {"source_file_path": "src/Main.java", "symbol": "method"}]},
            "v2": {"function_contract": carried}}}
        _, provider, _, _ = self._run(extra)
        prompt = provider.review_prompt
        block = prompt[prompt.rfind("\n", 0, prompt.rfind("\n</patch_and_source>")) + 1:
                       prompt.rfind("\n</patch_and_source>")]
        payload = json.loads(block)
        self.assertEqual(list(payload)[-1], "function_contract")
        self.assertEqual(payload["function_contract"], carried)
        _, provider, _, _ = self._run()
        self.assertNotIn('"function_contract"', provider.review_prompt)

    def test_the_review_prompt_says_one_thing_about_what_the_fix_removes(self):
        from cognalys.llm.coordinated_generation import behavior_review_system_prompt

        system = behavior_review_system_prompt()
        self.assertEqual(system.count("What the fix removes:"), 1)
        for passage in ("Five things show that",
                        "other than the reported code itself",
                        "something deprecated or insecure (an old protocol version, a weak "
                        "algorithm, a certificate nothing verified)",
                        "data the app stored, plan_invariants and plan_forbidden_changes keep the "
                        "rules this prompt gives them",
                        "where 'What the fix removes' finds no one who depends on it"):
            self.assertIn(passage, system)
        self.assertNotIn("unless the evidence shows the app depends on it", system)
        self.assertNotIn("beyond the reported violation itself", system)

    def test_a_concern_about_removing_something_insecure_is_decided_by_that_rule(self):
        from cognalys.llm.coordinated_generation import behavior_review_system_prompt

        system = behavior_review_system_prompt()
        self.assertIn("except that a concern about no longer enabling, accepting or trusting "
                      "something deprecated or insecure is decided under 'What the fix "
                      "removes', above", system)
        self.assertIn("does what one of adjudication_concerns warns against is a regression",
                      system)

    def test_the_review_schema_asks_a_verdict_per_concern(self):
        from cognalys.llm.llm_schemas import behavior_review_schema

        schema = behavior_review_schema()
        names = list(schema["properties"])
        self.assertEqual(names[names.index("regressions") + 1], "concern_verdicts")
        self.assertIn("concern_verdicts", schema["required"])
        item = schema["properties"]["concern_verdicts"]["items"]
        self.assertFalse(item["additionalProperties"])
        self.assertEqual(item["properties"]["concern"]["type"], "integer")
        self.assertEqual(item["properties"]["verdict"]["enum"],
                         ["does_what_it_warns_against", "does_not", "asks_for_verification"])

    def test_verdicts_are_recorded_by_position_and_unknown_ones_dropped(self):
        from cognalys.llm.coordinated_generation import concern_verdicts

        answered = [{"concern": 1, "verdict": "does_not"},
                    {"concern": 3, "verdict": "does_not"},
                    {"concern": True, "verdict": "does_not"},
                    {"concern": 2, "verdict": "maybe"},
                    {"concern": "2", "verdict": "does_not"},
                    {"concern": 2, "verdict": "asks_for_verification"},
                    {"concern": 2, "verdict": "does_what_it_warns_against"},
                    {"concern": 1, "verdict": "does_what_it_warns_against"},
                    "does_not"]
        self.assertEqual(concern_verdicts(answered, 2), [
            {"concern": 1, "verdict": "does_not"},
            {"concern": 2, "verdict": "asks_for_verification"}])
        self.assertEqual(concern_verdicts(None, 2), [])
        self.assertEqual(concern_verdicts([{"concern": 1, "verdict": "does_not"}], 0), [])

    def test_a_does_what_it_warns_against_verdict_alone_is_not_a_regression(self):
        from test_applied_edits_match_text import CLEAN_REVIEW

        answer = {**CLEAN_REVIEW, "concern_verdicts": [
            {"concern": 1, "verdict": "does_what_it_warns_against"}]}
        extra = {"evidence_analysis": {
            "confirmed_cause": "cause", "blocking_for_publication": [
                {"kind": "compatibility", "description": "Self-signed servers stop working."}],
            "coordinated_fix_plan": {"required_edits": [
                {"source_file_path": "src/Main.java", "symbol": "method"}]}}}
        result, _, _, review_file = self._run(extra, lambda call: answer)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(review_file["concern_verdicts"],
                         [{"concern": 1, "verdict": "does_what_it_warns_against"}])
        self.assertEqual(review_file["regressions"], [])

    def test_a_forbidden_call_kept_only_for_earlier_data_is_a_change(self):
        from cognalys.llm.coordinated_generation import behavior_review_system_prompt
        from cognalys.llm.llm_schemas import behavior_review_schema

        system = behavior_review_system_prompt()
        self.assertIn("A forbidden call the patch keeps or moves is judged by what its result is "
                      "still used for", system)
        self.assertIn("the patch has an effect -- say in rationale where the forbidden call "
                      "remains and when it runs, and do not set patch_has_no_effect", system)
        description = behavior_review_schema()["properties"]["patch_has_no_effect"]["description"]
        self.assertIn("a forbidden call the patch keeps or moves only to find, read or migrate "
                      "what earlier versions produced, while what the app produces from now on "
                      "comes from an allowed value, does count as a change", description)

    def test_the_review_states_where_a_kept_call_remains_and_the_pr_text_says_it(self):
        from cognalys.llm import finding_adjudication
        from cognalys.llm.coordinated_generation import review_facts_for_text
        from cognalys.llm.llm_schemas import behavior_review_schema
        from test_applied_edits_match_text import CLEAN_REVIEW

        self.assertIn("forbidden_call_kept_for_earlier_data",
                      behavior_review_schema()["required"])
        where = "General.sha1 stays in the cache lookup for entries written before the update."
        answer = {**CLEAN_REVIEW, "forbidden_call_kept_for_earlier_data": where}
        result, _, _, review_file = self._run(review=lambda call: answer)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(review_file["forbidden_call_kept_for_earlier_data"], where)
        self.assertEqual(review_facts_for_text(review_file)["forbidden_call_kept_for_earlier_data"],
                         where)
        # A patch without effect, or a review never run, says nothing of it.
        self.assertNotIn("forbidden_call_kept_for_earlier_data", review_facts_for_text(
            {**review_file, "patch_has_no_effect": True}))
        self.assertNotIn("forbidden_call_kept_for_earlier_data", review_facts_for_text(
            {**review_file, "status": "not_run"}))
        rule = finding_adjudication.KEPT_CALL_TEXT_RULE
        self.assertIn("RVSec still reports it whenever that migration runs", rule)
        source = Path(finding_adjudication.__file__).read_text(encoding="utf-8")
        self.assertIn('(KEPT_CALL_TEXT_RULE if "forbidden_call_kept_for_earlier_data" in payload '
                      'else "")', source)

    def test_a_round_trip_that_hands_back_the_same_material_has_no_effect(self):
        """Session LogFile$Writer.writeEntry: the key bytes wrapped under a fresh
        AES key and unwrapped under it reached Cipher.init unchanged, and two
        reviews passed it as a platform key."""
        from cognalys.llm.coordinated_generation import behavior_review_system_prompt
        from cognalys.llm.llm_schemas import behavior_review_schema

        system = behavior_review_system_prompt()
        self.assertIn("What counts is the material that reaches the governed call, not the "
                      "objects made on the way to it: a value passed through a round trip that "
                      "hands back what went in -- encrypted or wrapped and then decrypted or "
                      "unwrapped under the same key, encoded and decoded, written and read back "
                      "-- is the same value even when the round trip uses a freshly generated key "
                      "or another class", system)
        # After the rule that a fresh generation is different material.
        self.assertLess(system.index("takes different material -- a freshly generated key"),
                        system.index("What counts is the material that reaches"))
        description = behavior_review_schema()["properties"]["patch_has_no_effect"]["description"]
        self.assertIn("a value passed through a round trip that hands back what went in", description)

    def test_versions_record_the_change(self):
        from cognalys.llm.coordinated_generation import REVIEW_CONTRACT_VERSION
        from cognalys.llm.pipeline_common import CONTEXT_BUILDER_VERSION

        self.assertGreaterEqual(REVIEW_CONTRACT_VERSION, 20)
        self.assertGreaterEqual(tuple(map(int, CONTEXT_BUILDER_VERSION.split("."))), (2, 19))


if __name__ == "__main__":
    unittest.main()
