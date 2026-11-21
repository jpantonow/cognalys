"""Finding-independent research is shared; what only the case raises is not."""
import unittest

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.research_questions import (  # noqa: E402
    CASE_CONTEXT_QUESTION, merge_research_parts, shared_research_scope,
)


def packet(app, message="found SHA-1", rule_events=("Get",)):
    return {
        "finding": {"finding_id": app + ":::x", "specification": "MessageDigestSpec",
                    "error_message": message, "reported_violation": "UnsafeAlgorithm",
                    "target": {"class": app + ".Helper", "method": "sha1"}},
        "specification_context": {
            "spec_id": "MessageDigestSpec", "applies_to_types": ["java.security.MessageDigest"],
            "events": [{"name": name} for name in rule_events],
            # Enriched per finding; must not make the scope unique.
            "observed_source_events": [{"event": "Get", "line": len(app)}],
        },
    }


class SharedScopeTests(unittest.TestCase):
    def test_two_apps_with_one_message_share_the_scope(self):
        self.assertEqual(shared_research_scope(packet("a.one"), {}),
                         shared_research_scope(packet("b.another"), {}))

    def test_the_scope_names_no_application(self):
        scope = shared_research_scope(packet("a.one"), {})
        self.assertNotIn("a.one", str(scope))

    def test_a_different_message_or_rule_is_researched_again(self):
        base = shared_research_scope(packet("a.one"), {})
        self.assertNotEqual(base, shared_research_scope(packet("a.one", "found MD5"), {}))
        self.assertNotEqual(base, shared_research_scope(
            packet("a.one", rule_events=("Get", "Update")), {}))

    def test_the_case_question_asks_for_an_external_standard(self):
        self.assertIn("protocol", CASE_CONTEXT_QUESTION)


class MergeTests(unittest.TestCase):
    def test_parts_are_concatenated_and_sources_deduplicated(self):
        merged = merge_research_parts(
            {"queries_performed": [], "sources": []},
            [{"part": "shared", "queries_performed": ["javadoc"],
              "sources": [{"url": "https://a"}, {"url": "https://b"}]},
             {"part": "case", "queries_performed": ["rfc 6238"],
              "sources": [{"url": "https://b"}, {"url": "https://rfc"}]}],
        )
        self.assertEqual(merged["queries_performed"], ["javadoc", "rfc 6238"])
        self.assertEqual([s["url"] for s in merged["sources"]],
                         ["https://a", "https://b", "https://rfc"])
        self.assertNotIn("status", merged)

    def test_one_failed_part_keeps_the_other(self):
        merged = merge_research_parts({}, [
            {"part": "shared", "status": "unavailable", "error": "timeout"},
            {"part": "case", "sources": [{"url": "https://rfc"}]},
        ])
        self.assertNotIn("status", merged)
        self.assertEqual(merged["parts"][0]["status"], "unavailable")
        self.assertEqual(len(merged["sources"]), 1)

    def test_every_part_failed_is_a_failed_record(self):
        merged = merge_research_parts({}, [
            {"part": "shared", "status": "refused_by_provider", "refusal": {"code": "x"}},
            {"part": "case", "status": "unavailable", "error": "e"},
        ])
        self.assertEqual(merged["status"], "refused_by_provider")
        self.assertEqual(merged["refusal"], {"code": "x"})


if __name__ == "__main__":
    unittest.main()
