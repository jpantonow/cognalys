"""Prompts carry compact JSON and the specification once."""
import json
import unittest

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.pipeline_common import (  # noqa: E402
    EXTERNAL_SOURCES_POINTER, packet_prompt_view, prompt_json,
    research_prompt_view, without_duplicate_specification, without_entry_hashes,
)

SPEC = {"spec_id": "IvParameterSpecSpec", "events": [{"name": "c1"}]}


class PromptJsonTests(unittest.TestCase):
    def test_it_is_compact_and_round_trips(self):
        value = {"b": [1, {"c": "ç"}], "a": "x"}
        text = prompt_json(value)
        self.assertNotIn("\n", text)
        self.assertNotIn(": ", text)
        self.assertIn("ç", text)
        self.assertEqual(json.loads(text), value)
        self.assertEqual(list(json.loads(text)), ["b", "a"])


class DuplicateSpecificationTests(unittest.TestCase):
    def packet(self, data):
        return {"specification_context": SPEC, "evidence_catalog": [
            {"evidence_id": "SRC-001", "data": {"content": "x"}},
            {"evidence_id": "SPEC-001", "data": data},
        ]}

    def test_an_identical_copy_points_at_the_catalog_entry(self):
        packet = self.packet(dict(SPEC))
        trimmed = without_duplicate_specification(packet)
        self.assertEqual(trimmed["specification_context"],
                         "identical to evidence_catalog SPEC-001 data")
        self.assertEqual(trimmed["evidence_catalog"][1]["data"], SPEC)
        self.assertEqual(packet["specification_context"], SPEC)

    def test_a_different_copy_is_kept(self):
        packet = self.packet({**SPEC, "extra": True})
        self.assertIs(without_duplicate_specification(packet), packet)

class PacketPromptViewTests(unittest.TestCase):
    """The prompt drops the audit hashes and the second policy copy."""

    POLICY = {"family": "cipher", "family_policy": {"rule": "x"}}

    def packet(self):
        return {
            "selected_policy": dict(self.POLICY),
            "specification_context": SPEC,
            "diagnostic_evidence": {"evidence_id": "DET-001", "sha256": "d" * 64,
                                    "data": {"sha256": "kept, it is data"}},
            "evidence_catalog": [
                {"evidence_id": "SRC-001", "sha256": "a" * 64, "data": {"content": "x"}},
                {"evidence_id": "SPEC-001", "sha256": "b" * 64, "data": dict(SPEC)},
            ],
            "external_evidence_catalog": [
                {"evidence_id": "WEB-001", "sha256": "c" * 64, "data": {"url": "u"}}],
            "input_hashes": {"packet_sha256": "e" * 64},
        }

    def test_hashes_and_the_duplicate_policy_leave_only_the_prompt(self):
        packet = self.packet()
        before = json.loads(json.dumps(packet))
        view = packet_prompt_view(packet, "stable_policy", self.POLICY)
        text = prompt_json(view)

        self.assertNotIn("input_hashes", view)
        self.assertNotIn("a" * 64, text)
        self.assertNotIn("c" * 64, text)
        self.assertNotIn("d" * 64, text)
        self.assertEqual(view["selected_policy"], "identical to stable_policy")
        self.assertEqual(view["specification_context"],
                         "identical to evidence_catalog SPEC-001 data")
        # Data inside an entry is the repository's, not an audit field.
        self.assertEqual(view["diagnostic_evidence"]["data"]["sha256"], "kept, it is data")
        self.assertEqual([item["evidence_id"] for item in view["evidence_catalog"]],
                         ["SRC-001", "SPEC-001"])
        # The packet itself, which is written to disk, keeps every field.
        self.assertEqual(packet, before)
        self.assertIsNot(view, packet)
        self.assertIsNot(view["evidence_catalog"], packet["evidence_catalog"])

    def test_a_policy_the_prompt_does_not_carry_stays_in_the_packet(self):
        view = packet_prompt_view(self.packet(), "stable_policy", {"family": "tls"})
        self.assertEqual(view["selected_policy"], self.POLICY)
        self.assertEqual(packet_prompt_view(self.packet())["selected_policy"], self.POLICY)

    def test_entry_hashes_go_and_anything_else_is_left(self):
        self.assertEqual(without_entry_hashes([{"evidence_id": "W", "sha256": "h"}, "x"]),
                         [{"evidence_id": "W"}, "x"])
        self.assertIsNone(without_entry_hashes(None))


class ResearchPromptViewTests(unittest.TestCase):
    """Each external source reaches the extraction once, with its WEB id."""

    SOURCES = [{"url": "https://a", "claim": "x", "evidence_id": "WEB-001"},
               {"url": "https://b", "claim": "y", "evidence_id": "WEB-002"}]

    def catalog(self, sources):
        return [{"evidence_id": source.get("evidence_id"), "sha256": "h",
                 "data": source} for source in sources]

    def test_sources_identical_to_the_catalog_point_at_it(self):
        research = {"queries_performed": ["q"], "sources": self.SOURCES}
        view = research_prompt_view(research, self.catalog(self.SOURCES))
        self.assertEqual(view["sources"], EXTERNAL_SOURCES_POINTER)
        self.assertEqual(view["queries_performed"], ["q"])
        self.assertEqual(research["sources"], self.SOURCES)

    def test_sources_the_catalog_does_not_match_are_kept(self):
        research = {"sources": [*self.SOURCES, "not an object"]}
        self.assertIs(research_prompt_view(research, self.catalog(self.SOURCES)), research)
        empty = {"sources": []}
        self.assertIs(research_prompt_view(empty, []), empty)



if __name__ == "__main__":
    unittest.main()
