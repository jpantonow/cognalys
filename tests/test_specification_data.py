import unittest


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.migration_policy import generic_migration_policy  # noqa: E402
from cognalys.llm.source_facts import classify_spec_family  # noqa: E402
from cognalys.specifications.generate_specifications import CURATED_FIELDS  # noqa: E402
from cognalys.utils import specification_data as data  # noqa: E402


class SpecificationDataTests(unittest.TestCase):
    """The 2026-10-17 audit moved per-specification recipes from code into data."""

    def test_the_remediation_entry_is_matched_by_its_own_condition(self):
        tls = {"spec": "SSLContextSpec", "unique_error_id": "C:::m:::SSLContextSpec:::UnsafeProtocol:::x",
               "error_message": "expecting one of {TLSv1.2, TLSv1.3} but found TLS."}
        self.assertTrue(data.remediation_entry(tls))
        self.assertEqual(generic_migration_policy(tls)["consumer_scope"],
                         "signature_preserving_internal_transport_change")
        # Same specification, another selector: the next entry, selector-only scope.
        self.assertEqual(generic_migration_policy({**tls, "error_message": "found SSLv3"})
                         ["consumer_scope"], "tls_selector_only")
        # A specification without an entry infers no policy.
        self.assertEqual(generic_migration_policy({"spec": "CipherSpec", "error_message": "found DES"}), {})

    def test_a_variant_applies_only_when_its_evidence_holds(self):
        finding = {"spec": "MessageDigestSpec", "error_message": "but found MD5"}
        self.assertEqual(generic_migration_policy(finding)["usage_classification"], "pending_evidence")
        body = ("public int hashCode() {\n try { return digest(); }\n"
                " catch (Exception e) { return super.hashCode(); }\n}")
        policy = generic_migration_policy({**finding, "method_body": body})
        self.assertEqual(policy["usage_classification"], "hashcode_override")
        self.assertTrue(policy["established_value_contract_evidence"]["is_hashcode_override"])

    def test_a_weak_named_function_may_give_way_to_a_new_correctly_named_one(self):
        # NotallyX's md5Hash had no correctly named sibling to switch to: the
        # base policy lets the patch add one, or rename the weak-named
        # function when the rename_safety check finds no hard blocker.
        policy = generic_migration_policy({"spec": "MessageDigestSpec",
                                           "error_message": "but found MD5"})
        rule = next(item for item in policy["forbidden_changes"]
                    if "name states the weak algorithm" in item)
        self.assertIn("a new one the patch adds", rule)
        # Every caller, not only the reported ones: a caller left on the
        # weak-named function keeps the weak digest running.
        self.assertIn("switch every caller of the weak-named function", rule)
        self.assertNotIn("an existing correctly named function", rule)
        self.assertRegex(rule, r"rename the weak-named function when rename_safety reports "
                               r"no hard blocker")
        self.assertIn("not a maintainer approval", rule)

    def test_no_policy_makes_rename_safety_an_authorization(self):
        # Orgzly's sha1 was held for a "rename_safety authorization" the
        # policy text asked for (2026-10-25): rename_safety is a check.
        import json

        from cognalys.workspace import library_data

        specifications = sorted(library_data("specifications").glob("*.json"))
        self.assertTrue(specifications)
        for path in specifications:
            text = json.dumps(json.loads(path.read_text(encoding="utf-8")))
            with self.subTest(path.name):
                self.assertNotRegex(
                    text, r"rename_safety[^\"]{0,40}authori[sz]ation"
                          r"|authori[sz]ation[^\"]{0,40}rename_safety")

    def test_resolved_policy_sets_and_appends_without_touching_the_entry(self):
        entry = {"policy": {"a": 1, "items": ["x"]},
                 "variants": [{"when_evidence": "flag", "set": {"a": 2}, "append": {"items": ["y"]}}]}
        self.assertEqual(data.resolved_policy(entry, {"flag": True}), {"a": 2, "items": ["x", "y"]})
        self.assertEqual(data.resolved_policy(entry, {}), {"a": 1, "items": ["x"]})
        self.assertEqual(entry["policy"], {"a": 1, "items": ["x"]})

    def test_the_family_comes_from_the_specification_not_its_name(self):
        self.assertEqual(classify_spec_family("SSLContextSpec"), "tls")
        self.assertEqual(classify_spec_family("MessageDigestSpec"), "message_digest")
        # An existing specification without analysis_family is generic, whatever its name.
        self.assertEqual(classify_spec_family("MacSpec"), "generic")
        # A rule with no specification falls back to its descriptive name.
        self.assertEqual(classify_spec_family("weak-cipher-algorithm"), "cipher")

    def test_keeping_the_literal_is_declared_by_the_specification(self):
        self.assertTrue(data.keeps_reported_literal("SSLContextSpec"))
        self.assertFalse(data.keeps_reported_literal("MessageDigestSpec"))

    def test_tls_entries_judge_filters_and_analyzer_acceptance_by_the_evidence(self):
        """2026-10-29 review (P2, P3, P10)."""
        entries = data.specification("SSLContextSpec")["remediation_policies"]
        found_tls = next(item for item in entries
                         if "TLS" in str((item.get("when") or {}).get("message_pattern", "")))
        self.assertIn("Legacy SSLv3, TLSv1 and TLSv1.1 names are removed.",
                      found_tls["policy"]["required_tests"])
        self.assertNotIn("TLSv1.0", " ".join(found_tls["policy"]["required_tests"]))
        found = next(item for item in entries
                     if (item.get("when") or {}).get("message_pattern") == "\\bfound\\b")
        self.assertIn("by the reporting detector's message", found["policy"]["review_fallback"])
        excludes = next(item for item in found["variants"]
                        if item["when_evidence"] == "client_excludes_deprecated_protocols")
        self.assertEqual(excludes["set"], {"filters_deprecated_protocols": False,
                                           "client_enforces_protocols": True})

    def test_curated_fields_survive_regeneration(self):
        for field in ("false_positive_triggers", "analysis_family", "remediation_policies"):
            self.assertIn(field, CURATED_FIELDS)


if __name__ == "__main__":
    unittest.main()
