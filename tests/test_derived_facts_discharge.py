"""A blocker whose question the checkout answered is not a blocker.

The adjudicator states what it could not settle as a generation blocker, and
the validator then refuses any supported decision that carries one. Three of
those questions -- who owns the reported class, whether the reported rule
governs this code, what the callers require -- are answered deterministically
in the packet's derived_facts. A blocker that survives its own answer ends a
finding for want of something it was given.

The refusals matter as much as the discharges: a fact that came back
unresolved settles nothing, and a blocker about something else entirely must
never be discharged by a fact that does not address it.
"""
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.pipeline_architecture import (  # noqa: E402
    discharge_blockers_answered_by_derived_facts,
)


def _facts(**statuses) -> dict:
    return {
        "status": "collected",
        "artifact_ownership": {"status": statuses.get("ownership", "unresolved")},
        "specification_applicability": {
            "status": statuses.get("applicability", "no_governed_api_matched")
        },
        "caller_contract": {"status": statuses.get("callers", "unresolved")},
        "call_binding": {"status": statuses.get("binding", "unresolved")},
    }


def _blocker(kind: str, description: str = "") -> dict:
    return {
        "kind": kind,
        "category": "cause_unconfirmed",
        "description": description or kind.replace("_", " "),
        "blocking_for_generation": True,
    }


class DischargeTests(unittest.TestCase):

    def test_an_answered_ownership_blocker_is_discharged(self):
        adjudication = {"blocking_for_generation": [
            _blocker("unresolved_ownership_and_version_of_the_reported_class"),
        ]}
        discharged = discharge_blockers_answered_by_derived_facts(
            adjudication, _facts(ownership="declared_dependency")
        )
        self.assertEqual(len(discharged), 1)
        self.assertEqual(adjudication["blocking_for_generation"], [])
        self.assertEqual(
            discharged[0]["discharging_fact"], "artifact_ownership"
        )
        # The record keeps it rather than deleting the history.
        self.assertEqual(len(adjudication["discharged_blockers"]), 1)

    def test_an_answered_applicability_blocker_is_discharged(self):
        adjudication = {"blocking_for_generation": [
            _blocker("reported_rule_applicability_is_unconfirmed"),
        ]}
        discharged = discharge_blockers_answered_by_derived_facts(
            adjudication, _facts(applicability="governed_api_matched")
        )
        self.assertEqual(len(discharged), 1)

    def test_the_reporting_detector_firing_settles_rule_applicability(self):
        # A detector-rule finding has no governed API in any specification;
        # the detector raising its own rule here is the rule's authority.
        adjudication = {"blocking_for_generation": [
            _blocker("reported_rule_applicability_is_unconfirmed"),
        ]}
        facts = {**_facts(),
                 "detector_reproduction": {"status": "alert_present"}}
        discharged = discharge_blockers_answered_by_derived_facts(
            adjudication, facts
        )
        self.assertEqual(len(discharged), 1)
        self.assertEqual(discharged[0]["discharging_fact"],
                         "detector_reproduction")

    def test_a_detector_that_could_not_run_settles_nothing(self):
        for status in ("no_detector_coverage", "detector_error",
                       "alert_absent", "not_exercised"):
            adjudication = {"blocking_for_generation": [
                _blocker("reported_rule_applicability_is_unconfirmed"),
            ]}
            facts = {**_facts(), "detector_reproduction": {"status": status}}
            self.assertEqual(
                discharge_blockers_answered_by_derived_facts(adjudication, facts),
                [], status,
            )

    def test_an_enumerated_caller_contract_discharges_its_blocker(self):
        searched = {"searched_declaring_file": True, "name_resolution": "direct"}
        for record in ({"status": "callers_enumerated"},
                       {"status": "no_callers_found", **searched}):
            adjudication = {"blocking_for_generation": [
                _blocker("incomplete_reachable_caller_contract"),
            ]}
            discharged = discharge_blockers_answered_by_derived_facts(
                adjudication, {**_facts(), "caller_contract": record}
            )
            self.assertEqual(len(discharged), 1, record)

    def test_no_callers_settles_nothing_unless_the_search_ran_where_they_are(self):
        # Amethyst MacInstance.<init>: two blockers were discharged on a "no
        # callers" that skipped the declaring file and searched `<init>(`.
        searched = {"status": "no_callers_found", "searched_declaring_file": True,
                    "name_resolution": "constructor"}
        for record in (
            {"status": "no_callers_found"},  # written before it said what it searched
            {**searched, "searched_declaring_file": False},
            {"status": "not_searchable", "name_resolution": "static_initializer"},
            # The packet's own catalog holds callers resolved to the class.
            {**searched, "catalog_callers_of_target": 23},
        ):
            adjudication = {"blocking_for_generation": [
                _blocker("incomplete_reachable_caller_contract"),
            ]}
            self.assertEqual(discharge_blockers_answered_by_derived_facts(
                adjudication, {**_facts(), "caller_contract": record}), [], record)
            self.assertEqual(len(adjudication["blocking_for_generation"]), 1)

    def test_only_catalog_callers_of_the_reported_class_contradict_no_callers(self):
        from cognalys.llm.evidence_packet import FindingEvidencePacketBuilder

        def caller(symbol: str) -> dict:
            return {"kind": "resolved_caller", "data": {"resolved_symbol_id": symbol}}

        error = {"csv_class": "com.vitorpamplona.quartz.MacInstance"}
        facts = {"status": "collected",
                 "caller_contract": {"status": "no_callers_found",
                                     "searched_declaring_file": True,
                                     "name_resolution": "constructor"}}
        other_class = FindingEvidencePacketBuilder._with_catalog_callers(
            {**facts, "caller_contract": dict(facts["caller_contract"])},
            [caller("com.other.Hasher#update(byte[])"),
             {"kind": "lexical_caller", "data": {"path": "x.kt"}}],
            error, "quartz/MacInstance.kt")
        self.assertEqual(other_class["caller_contract"]["catalog_callers_of_target"], 0)
        adjudication = {"blocking_for_generation": [
            _blocker("incomplete_reachable_caller_contract")]}
        self.assertEqual(len(discharge_blockers_answered_by_derived_facts(
            adjudication, {**_facts(), **other_class})), 1)

        same_class = FindingEvidencePacketBuilder._with_catalog_callers(
            {**facts, "caller_contract": dict(facts["caller_contract"])},
            [caller("com.vitorpamplona.quartz.MacInstance#MacInstance(String,byte[])"),
             caller("MacInstance#<init>")],
            error, "quartz/MacInstance.kt")
        self.assertEqual(same_class["caller_contract"]["catalog_callers_of_target"], 2)
        adjudication = {"blocking_for_generation": [
            _blocker("incomplete_reachable_caller_contract")]}
        self.assertEqual(discharge_blockers_answered_by_derived_facts(
            adjudication, {**_facts(), **same_class}), [])

    def test_catalog_callers_of_a_kotlin_top_level_function_count(self):
        # The semantic index writes a top-level function as `pkg.<top-level>`;
        # the bytecode names it FooKt, so its callers were never counted.
        from cognalys.llm.evidence_packet import FindingEvidencePacketBuilder

        def caller(symbol: str) -> dict:
            return {"kind": "resolved_caller", "data": {"resolved_symbol_id": symbol}}

        facts = {"status": "collected",
                 "caller_contract": {"status": "no_callers_found",
                                     "searched_declaring_file": True,
                                     "name_resolution": "direct"}}
        counted = FindingEvidencePacketBuilder._with_catalog_callers(
            {**facts, "caller_contract": dict(facts["caller_contract"])},
            [caller("app.crypto.<top-level>#deriveKey(String,ByteArray)"),
             caller("app.crypto.<top-level>#otherHelper()"),
             caller("app.other.<top-level>#deriveKey(String)")],
            {"csv_class": "app.crypto.KeysKt", "method_name": "deriveKey"},
            "app/src/main/java/app/crypto/Keys.kt")
        self.assertEqual(counted["caller_contract"]["catalog_callers_of_target"], 1)

    def test_a_provenance_blocker_is_not_discharged_by_a_caller_list(self):
        # The responder now answers "callers_or_byte_provenance" from source;
        # a caller list still does not say where the bytes come from.
        adjudication = {"blocking_for_generation": [
            _blocker("callers_or_byte_provenance"),
            _blocker("caller_key_producer_unestablished"),
        ]}
        self.assertEqual(discharge_blockers_answered_by_derived_facts(
            adjudication, _facts(callers="callers_enumerated")), [])
        self.assertEqual(len(adjudication["blocking_for_generation"]), 2)

    def test_a_settled_call_binding_discharges_the_target_confirmation(self):
        # slimbook setupWebView, run_20260920_175850, verbatim.
        blocker = _blocker(
            "Semantic target confirmation",
            "The source establishes only a lexical literal-true call. It does "
            "not establish that this call resolves to android.webkit.WebView."
            "setWebContentsDebuggingEnabled(boolean).",
        )
        adjudication = {"blocking_for_generation": [dict(blocker)]}
        discharged = discharge_blockers_answered_by_derived_facts(
            adjudication, _facts(binding="resolved_to_governed_type")
        )
        self.assertEqual(len(discharged), 1)
        self.assertEqual(discharged[0]["discharging_fact"], "call_binding")

        # A binding to some other type settles nothing.
        adjudication = {"blocking_for_generation": [dict(blocker)]}
        self.assertEqual(
            discharge_blockers_answered_by_derived_facts(
                adjudication, _facts(binding="resolved_elsewhere")
            ),
            [],
        )

    def test_an_unresolved_fact_discharges_nothing(self):
        adjudication = {"blocking_for_generation": [
            _blocker("unresolved_ownership_and_version_of_the_reported_class"),
        ]}
        discharged = discharge_blockers_answered_by_derived_facts(
            adjudication, _facts(ownership="unresolved")
        )
        self.assertEqual(discharged, [])
        self.assertEqual(len(adjudication["blocking_for_generation"]), 1)

    def test_an_undeclared_external_class_leaves_the_blocker_standing(self):
        adjudication = {"blocking_for_generation": [
            _blocker("unresolved_ownership_and_version_of_the_reported_class"),
        ]}
        self.assertEqual(
            discharge_blockers_answered_by_derived_facts(
                adjudication, _facts(ownership="undeclared_external")
            ),
            [],
        )

    def test_a_truncated_caller_scan_leaves_the_blocker_standing(self):
        adjudication = {"blocking_for_generation": [
            _blocker("incomplete_reachable_caller_contract"),
        ]}
        self.assertEqual(
            discharge_blockers_answered_by_derived_facts(
                adjudication, _facts(callers="callers_truncated")
            ),
            [],
        )

    def test_an_unrelated_blocker_is_never_discharged(self):
        adjudication = {"blocking_for_generation": [
            _blocker(
                "runtime_security_impact_unestablished",
                "No runtime observation establishes that the insecure "
                "protocol was negotiated.",
            ),
        ]}
        self.assertEqual(
            discharge_blockers_answered_by_derived_facts(
                adjudication,
                _facts(ownership="repository_class",
                       applicability="governed_api_matched",
                       callers="callers_enumerated"),
            ),
            [],
        )
        self.assertEqual(len(adjudication["blocking_for_generation"]), 1)

    def test_without_collected_facts_nothing_is_discharged(self):
        adjudication = {"blocking_for_generation": [
            _blocker("unresolved_ownership_and_version_of_the_reported_class"),
        ]}
        for facts in ({}, {"status": "unavailable"}, {"status": "no_checkout"}):
            self.assertEqual(
                discharge_blockers_answered_by_derived_facts(adjudication, facts),
                [],
            )


if __name__ == "__main__":
    unittest.main()
