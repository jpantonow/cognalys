import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.migration_policy import resolve_case_policy  # noqa: E402


FINDING = (
    "com.example.Store:::load:::KeyStoreSpec:::InvalidKeyStoreType:::"
    "expecting one of JCEKS,JKS but found BKS."
)


def _error(finding_id: str = FINDING, **overrides) -> dict:
    error = {
        "unique_error_id": finding_id,
        "spec": finding_id.split(":::")[2],
        "error_message": finding_id.split(":::")[-1],
    }
    error.update(overrides)
    return error


class CasePolicyResolutionTests(unittest.TestCase):
    """One authorisation should cover a shape, not a single finding.

    The file answered only to an exact `class:::method:::spec:::violation:::
    message` string, so it held one entry while the adjudication kept
    blocking on "No case-policy authorization was supplied". The 33
    application findings of the priority sample fall into 11 shapes and the
    five largest cover 27 of them, so a per-finding file could never keep up.
    """

    FAMILY = {
        "spec": "KeyStoreSpec",
        "violation": "InvalidKeyStoreType",
        "policy": {"authorized": True, "strategy": "family strategy"},
    }

    def test_the_legacy_flat_file_is_read_exactly_as_before(self):
        policies = {FINDING: {"authorized": True, "strategy": "exact"}}
        self.assertEqual(
            resolve_case_policy(policies, _error())["strategy"], "exact"
        )

    def test_an_unknown_finding_gets_no_authorisation(self):
        policies = {FINDING: {"authorized": True}}
        self.assertEqual(
            resolve_case_policy(policies, _error("a:::b:::X:::Y:::z")), {}
        )

    def test_a_family_covers_a_finding_never_written_down(self):
        other = (
            "com.other.Vault:::open:::KeyStoreSpec:::InvalidKeyStoreType:::"
            "expecting one of JCEKS,JKS but found PKCS11."
        )
        resolved = resolve_case_policy(
            {"findings": {}, "families": [self.FAMILY]}, _error(other)
        )
        self.assertEqual(resolved["strategy"], "family strategy")

    def test_an_exact_entry_overrides_the_family_it_falls_into(self):
        resolved = resolve_case_policy(
            {
                "findings": {FINDING: {"strategy": "exact", "scope": "narrow"}},
                "families": [self.FAMILY],
            },
            _error(),
        )
        self.assertEqual(resolved["strategy"], "exact")
        # Fields the exact entry does not restate still come from the family.
        self.assertTrue(resolved["authorized"])
        self.assertEqual(resolved["scope"], "narrow")

    def test_a_family_for_another_specification_does_not_match(self):
        family = dict(self.FAMILY, spec="SSLContextSpec")
        self.assertEqual(
            resolve_case_policy({"families": [family]}, _error()), {}
        )

    def test_a_family_for_another_violation_does_not_match(self):
        family = dict(self.FAMILY, violation="InvalidSequenceOfMethodCalls")
        self.assertEqual(
            resolve_case_policy({"families": [family]}, _error()), {}
        )

    def test_a_message_pattern_narrows_a_family(self):
        family = dict(self.FAMILY, message_pattern=r"found BKS")
        self.assertTrue(resolve_case_policy({"families": [family]}, _error()))
        other = FINDING.replace("found BKS.", "found PKCS11.")
        self.assertEqual(
            resolve_case_policy({"families": [family]}, _error(other)), {}
        )

    def test_a_family_naming_nothing_authorises_nothing(self):
        # Otherwise an empty entry would be a blanket authorisation over
        # every finding the pipeline ever reports.
        family = {"policy": {"authorized": True}}
        self.assertEqual(
            resolve_case_policy({"families": [family]}, _error()), {}
        )

    def test_an_invalid_message_pattern_matches_nothing(self):
        family = dict(self.FAMILY, message_pattern="([unclosed")
        self.assertEqual(
            resolve_case_policy({"families": [family]}, _error()), {}
        )

    def test_the_shipped_policy_file_still_resolves_its_own_entry(self):
        path = ROOT / "data" / "migration_policies.json"
        policies = json.loads(path.read_text(encoding="utf-8"))
        finding_id = next(iter(policies.get("findings", policies)))
        self.assertTrue(
            resolve_case_policy(policies, _error(finding_id))
        )


if __name__ == "__main__":
    unittest.main()
