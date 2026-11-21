"""A later evidence-extraction round appends to the earlier request.

Round 2 used to send the whole packet again with the fetched SUP entries
inside its catalog and the request record twice (in the packet and beside
it). The round-1 request was a prefix of round 2 up to the end of the
catalog in all 386 recorded pairs, yet only 1.1-1.4k tokens came back from
the prompt cache, because OpenAI looks a prefix up only at a request's part
boundaries. Round 2 (and the post-adjudication round) is now the previous
request byte for byte, a trusted note, and the new entries in an untrusted
block of their own, with a part boundary where the previous request ended.
"""
import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm import llm_providers  # noqa: E402
from cognalys.llm.finding_context import (  # noqa: E402
    ADJUDICATION_SUPPLEMENT_NOTE, SUPPLEMENT_NOTE,
)
from cognalys.llm.generate_error_fixes import FixGenerator  # noqa: E402
from cognalys.llm.pipeline_architecture import (  # noqa: E402
    FindingEvidencePacketBuilder,
    PolicyRegistry,
)


def _extraction(requested):
    return {
        "claims": [], "observed_events": [], "predicate_assessment": [],
        "confirmed_dataflows": [], "relations": [],
        "unresolved_questions": [], "needs_more_evidence": bool(requested),
        "requested_evidence": requested, "family_assessment": {},
    }


class _Provider:
    """Answers by trace_stage; keeps every extraction request in order."""

    provider_name = "test"
    model = "test-model"

    def __init__(self, blocked_adjudication=False):
        self.blocked_adjudication = blocked_adjudication
        self.extractions = []
        self.extraction_systems = []
        self.adjudications = []

    @staticmethod
    def get_token_usage():
        return {"input": 0, "output": 0}

    def generate(self, prompt, _system=None, **kwargs):
        stage = kwargs.get("trace_stage", "")
        if stage == "evidence_extraction":
            self.extractions.append(prompt)
            self.extraction_systems.append(_system)
            requested = [] if len(self.extractions) > 1 else [{
                "kind": "repository_source", "symbol": "Helper.derive",
                "reason": "where the key bytes come from",
            }]
            return json.dumps(_extraction(requested))
        if stage.startswith("adjudication"):
            self.adjudications.append(prompt)
        blocked = self.blocked_adjudication and stage == "adjudication"
        return json.dumps({
            "cause_status": "unknown", "confirmed_cause": "",
            "detector_violation": "unknown",
            "runtime_security_impact": "unknown",
            "compatibility_status": "unknown", "scope_status": "incomplete",
            "decision": "NO_SAFE_FIX", "decision_claim_ids": [],
            "blocking_for_generation": [{
                "kind": "source", "category": "code_evidence_missing",
                "description": "Store.keyBytes construction is not supplied",
                "supporting_claim_ids": [],
            }] if blocked else [],
            "blocking_for_publication": [],
            "generation_status": "blocked", "publication_status": "blocked",
            "required_edit_categories": [], "required_tests": [],
            "forward_compatibility_strategy": "",
            "authorized_behavior_change": {
                "authorized": False, "description": "", "policy_reference": "",
            },
            "review_assumptions": [],
        })


def _fetched(path):
    return {"entries": [{
        "kind": "repository_source", "trust_level": "repository_untrusted_source",
        "mandatory": False,
        "data": {"source_file_path": path, "content": f"{path}:1: class X {{}}"},
    }], "declined": [{"request": {"kind": "runtime"}, "reason": "runtime only"}]}


class ExtractionRoundsAppendTests(unittest.TestCase):
    def _generator(self, root: Path, provider) -> FixGenerator:
        generator = object.__new__(FixGenerator)
        generator.output_dir = root / "out"
        generator.provider = provider
        generator.web_search = False
        generator.architecture_version = "v2"
        generator.logger = logging.getLogger("extraction-rounds-append")
        generator.evidence_packet_builder = FindingEvidencePacketBuilder(
            repository_context_budget=140_000)
        generator.policy_registry = PolicyRegistry(root / "no_policies")
        return generator

    @staticmethod
    def _error(root: Path) -> dict:
        return {
            "spec": "CipherSpec", "method_name": "encrypt",
            "method_body": "Cipher.getInstance(\"AES\")", "imports": "",
            "repository_path": str(root / "repo"),
            "source_file_path": "src/Store.java", "csv_class": "x.Store",
            "error_message": "AES without mode",
            "specification_context": {"status": "unavailable"},
        }

    def _run(self, provider, fetched):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "repo" / "src").mkdir(parents=True)
            (root / "repo" / "src" / "Store.java").write_text(
                "class Store { byte[] keyBytes; }", encoding="utf-8")
            generator = self._generator(root, provider)
            with patch("cognalys.llm.finding_context.resolve_evidence_requests",
                       side_effect=fetched):
                generator.adjudicate_finding(self._error(root), "app.apk", "encrypt")
            return json.loads((root / "out" / "v2_artifacts" / "app.apk"
                               / "0_encrypt_evidence_packet.json").read_text(
                                   encoding="utf-8"))

    @staticmethod
    def _appendix(prompt: str, base: str, note: str) -> dict:
        tail = prompt[len(base):]
        head = "\n\n" + note + "\n\n<supplementary_repository_data untrusted_data=\"true\">\n"
        assert tail.startswith(head), tail[:200]
        assert tail.endswith("\n</supplementary_repository_data>")
        return json.loads(tail[len(head):-len("\n</supplementary_repository_data>")])

    def test_round_two_is_round_one_then_the_fetched_entries(self):
        provider = _Provider()
        self._run(provider, [_fetched("src/Helper.java")])

        first, second = provider.extractions
        self.assertTrue(second.startswith(first))
        self.assertEqual(second.cache_boundaries, (len(first),))
        appended = self._appendix(second, first, SUPPLEMENT_NOTE)
        self.assertEqual([item["evidence_id"] for item in
                          appended["supplementary_evidence_catalog"]], ["SUP-001"])
        # The request record is sent once, beside the entries.
        record = appended["previously_requested_evidence"]
        self.assertEqual(record["evidence_ids"], ["SUP-001"])
        self.assertEqual(second.count('"requests_answered_from_repository"'), 1)
        self.assertNotIn("SUP-001", first)
        # The packet in memory still holds the entry in its catalog, so
        # validation, adjudication and the plan read it.
        self.assertIn('"SUP-001"', provider.adjudications[0].split(
            '"valid_evidence_ids"')[1])

    def test_the_citation_rule_names_the_catalog_the_later_rounds_append(self):
        # The SUP and ADJ entries no longer sit in evidence_catalog, so the
        # system rule on what may be cited names their own key; it is the
        # same text in every round, so round 1's cached prefix still serves.
        provider = _Provider()
        self._run(provider, [_fetched("src/Helper.java")])

        first, second = provider.extraction_systems
        self.assertEqual(first, second)
        rule = first.split("must cite evidence IDs from ", 1)[1].split(" only.", 1)[0]
        for catalog in ("evidence_catalog", "supplementary_evidence_catalog",
                        "external_evidence_catalog"):
            self.assertIn(catalog, rule)

    def test_the_post_adjudication_round_appends_to_round_two(self):
        provider = _Provider(blocked_adjudication=True)
        self._run(provider, [_fetched("src/Helper.java"),
                             _fetched("src/Keys.java")])

        first, second, third = provider.extractions
        self.assertTrue(third.startswith(second))
        self.assertEqual(third.cache_boundaries, (len(first), len(second)))
        appended = self._appendix(third, second, ADJUDICATION_SUPPLEMENT_NOTE)
        self.assertEqual([item["evidence_id"] for item in
                          appended["supplementary_evidence_catalog"]], ["ADJ-001"])
        # Round 2 already carried the request record.
        self.assertNotIn("previously_requested_evidence", appended)
        valid = provider.adjudications[-1].split('"valid_evidence_ids"')[1]
        self.assertIn('"SUP-001"', valid)
        self.assertIn('"ADJ-001"', valid)

    def test_the_boundaries_cut_the_request_where_the_earlier_one_ended(self):
        provider = _Provider()
        self._run(provider, [_fetched("src/Helper.java")])
        first, second = provider.extractions

        request_input, cuts, breakpoints = llm_providers.prompt_cache_input(second)
        _, first_cuts, _ = llm_providers.prompt_cache_input(first)
        self.assertIn(len(first), cuts)
        self.assertIn(len(first), breakpoints)
        self.assertEqual([cut for cut in cuts if cut < len(first)], first_cuts)
        parts = request_input[0]["content"] if isinstance(request_input, list) else []
        self.assertEqual("".join(part["text"] for part in parts), second)

    def test_the_packet_on_disk_keeps_the_hashes_the_prompt_leaves_out(self):
        provider = _Provider()
        packet = self._run(provider, [_fetched("src/Helper.java")])

        self.assertIn("packet_sha256", packet["input_hashes"])
        self.assertTrue(all("sha256" in item for item in packet["evidence_catalog"]))
        self.assertIn("family", packet["selected_policy"])
        first = provider.extractions[0]
        self.assertNotIn("input_hashes", first)
        self.assertNotIn('"sha256"', first)
        self.assertNotIn('"sha256"', provider.extractions[1])
        self.assertIn('"selected_policy":"identical to stable_policy"', first)


if __name__ == "__main__":
    unittest.main()
