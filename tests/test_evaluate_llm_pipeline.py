"""The evaluator must not invent an answer the artifacts do not contain.

Every test here pins one of the four ways the previous evaluator flattered
the pipeline:

  * an empty or unrecognised decision normalized to a supported repair,
    because the repairability ladder ended in `else "supported"`;
  * a confirmed claim citing an evidence ID the packet never held passed the
    provenance check, which only tested that the list was non-empty;
  * a manifest case with no matching artifact contributed `0/0`, so it left
    the denominator entirely;
  * `rglob` over a directory of runs merged them, and `>=` on the rank let
    the last file of a kind win.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.evaluation import decisions as decision_vocabulary  # noqa: E402
from cognalys.evaluation.artifacts import load_run, resolve_run_root  # noqa: E402
from cognalys.evaluation.normalize import UNKNOWN, normalize  # noqa: E402
from cognalys.evaluation.scoring import (  # noqa: E402
    CASE_MISSING, MANIFEST_VERSION, MATCH, MISMATCH, OBSERVED_UNKNOWN,
    score_run, validate_manifest,
)


def _walk(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


class DecisionVocabularyTests(unittest.TestCase):

    def test_every_schema_decision_is_classified(self):
        """A decision added to the schema must be given a meaning here.

        The whole failure mode is a decision falling into a default branch,
        so the schema's own enum is the authority and this test fails when
        the two drift apart.
        """
        from cognalys.llm.llm_schemas import evidence_analysis_schema

        enums = [
            node["enum"] for node in _walk(evidence_analysis_schema())
            if isinstance(node, dict) and "enum" in node
            and "NO_SAFE_FIX" in node.get("enum", [])
        ]
        self.assertTrue(enums, "no decision enum found in the schema")
        unclassified = decision_vocabulary.unknown_decisions(enums[0])
        self.assertEqual(unclassified, [])

    def test_an_absent_decision_is_invalid_not_a_repair(self):
        for value in ("", "   ", None, 7, "SOMETHING_NEW"):
            self.assertEqual(
                decision_vocabulary.action_for(value),
                decision_vocabulary.INVALID,
                f"{value!r} must not be classified as an action",
            )
            self.assertFalse(decision_vocabulary.proposes_change(value))

    def test_a_confirmed_finding_with_no_client_fix_is_not_a_repair(self):
        self.assertEqual(
            decision_vocabulary.action_for(
                "EXTERNAL_DIGEST_CONTRACT_NO_CLIENT_ONLY_FIX"
            ),
            decision_vocabulary.CLASSIFY_NO_CHANGE,
        )

    def test_the_repair_and_review_families_are_distinguished(self):
        self.assertEqual(
            decision_vocabulary.action_for("FIX_SUPPORTED"),
            decision_vocabulary.REPAIR_UNATTENDED,
        )
        self.assertEqual(
            decision_vocabulary.action_for("MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"),
            decision_vocabulary.REPAIR_FOR_REVIEW,
        )
        self.assertEqual(
            decision_vocabulary.action_for("NO_SAFE_FIX"),
            decision_vocabulary.ABSTAIN,
        )


class NormalizationTests(unittest.TestCase):

    ADJUDICATION = {
        "decision": "FIX_SUPPORTED",
        "detector_violation": "confirmed",
        "runtime_security_impact": "not_established",
        "cause_status": "confirmed",
        "generation_status": "supported",
        "publication_status": "eligible",
    }

    def test_all_three_artifact_shapes_are_read(self):
        shapes = [
            {"evidence_analysis": {"v2": {"adjudication": self.ADJUDICATION}}},
            {"analysis": {"v2": {"adjudication": self.ADJUDICATION}}},
            dict(self.ADJUDICATION),
        ]
        for shape in shapes:
            normalized = normalize(shape)
            self.assertEqual(normalized["decision"], "FIX_SUPPORTED")
            self.assertEqual(normalized["detector_violation"], "confirmed")

    def test_an_absent_axis_is_unknown_and_not_guessed_from_prose(self):
        normalized = normalize({"analysis": {
            "decision": "NO_SAFE_FIX",
            "confirmed_cause": "the negotiated protocol remains "
                               "not established at runtime",
        }})
        self.assertEqual(normalized["runtime_security_impact"], UNKNOWN)
        self.assertEqual(normalized["detector_violation"], UNKNOWN)

    def test_scope_comes_from_the_plan(self):
        single = normalize({"analysis": {
            **self.ADJUDICATION,
            "coordinated_fix_plan": {"required_edits": [
                {"source_file_path": "a/A.java"},
            ]},
        }})
        multi = normalize({"analysis": {
            **self.ADJUDICATION,
            "coordinated_fix_plan": {"required_edits": [
                {"source_file_path": "a/A.java"},
                {"source_file_path": "b/B.java"},
            ]},
        }})
        self.assertEqual(single["scope"], "single_file")
        self.assertEqual(multi["scope"], "multi_file")

    def test_a_dangling_evidence_reference_is_reported(self):
        value = {
            "evidence_catalog": [{"evidence_id": "SRC-001"}],
            "claims": [{
                "claim_id": "C-1", "epistemic_status": "confirmed",
                "evidence_ids": ["does-not-exist"],
            }],
            "adjudication": {"decision": "FIX_SUPPORTED"},
        }
        provenance = normalize(value)["provenance"]
        self.assertTrue(provenance["catalog_available"])
        self.assertEqual(
            provenance["dangling_references"],
            [{"claim_id": "C-1", "unknown_evidence_ids": ["does-not-exist"]}],
        )
        # It cites something, so the old check would have passed it.
        self.assertEqual(provenance["unsupported_claim_ids"], [])

    def test_without_a_catalog_nothing_is_claimed_to_be_checked(self):
        provenance = normalize({
            "claims": [{
                "claim_id": "C-1", "epistemic_status": "confirmed",
                "evidence_ids": ["SRC-001"],
            }],
            "adjudication": {"decision": "FIX_SUPPORTED"},
        })["provenance"]
        self.assertFalse(provenance["catalog_available"])
        self.assertEqual(provenance["dangling_references"], [])


class ScoringTests(unittest.TestCase):

    MANIFEST = {
        "manifest_version": MANIFEST_VERSION,
        "cases": [
            {"finding_id": "present", "expected": {
                "action": "repair_unattended",
                "detector_violation": "confirmed",
            }},
            {"finding_id": "absent", "expected": {
                "action": "abstain",
                "detector_violation": "confirmed",
            }},
        ],
    }

    def test_a_missing_case_stays_in_the_denominator(self):
        report = score_run(self.MANIFEST, {"present": {"adjudication": {
            "decision": "FIX_SUPPORTED", "detector_violation": "confirmed",
        }}})
        self.assertEqual(report["axis_outcomes"][MATCH], 2)
        self.assertEqual(report["axis_outcomes"][CASE_MISSING], 2)
        self.assertEqual(report["axes_compared"], 4)
        self.assertEqual(report["score"], 0.5)
        self.assertEqual(report["case_coverage"], 0.5)
        self.assertEqual(report["cases_missing"], ["absent"])

    def test_silence_and_contradiction_are_counted_apart(self):
        report = score_run(
            {"manifest_version": MANIFEST_VERSION, "cases": [
                {"finding_id": "a", "expected": {
                    "detector_violation": "confirmed",
                    "cause_status": "confirmed",
                }},
            ]},
            {"a": {"adjudication": {
                "decision": "NO_SAFE_FIX",
                "detector_violation": "refuted",
            }}},
        )
        self.assertEqual(report["axis_outcomes"][MISMATCH], 1)
        self.assertEqual(report["axis_outcomes"][OBSERVED_UNKNOWN], 1)

    def test_a_version_one_manifest_is_refused(self):
        issues = validate_manifest({
            "manifest_version": 1,
            "cases": [{"finding_id": "a", "expected": {}}],
        })
        self.assertTrue(any("manifest_version" in issue for issue in issues))

    def test_a_legacy_repairability_value_is_refused(self):
        issues = validate_manifest({
            "manifest_version": MANIFEST_VERSION,
            "cases": [{"finding_id": "a", "expected": {
                "repairability": "supported",
            }}],
        })
        self.assertTrue(any("unknown axis" in issue for issue in issues))

    def test_text_checks_do_not_enter_the_score(self):
        report = score_run(
            {"manifest_version": MANIFEST_VERSION, "cases": [
                {"finding_id": "a", "expected": {
                    "action": "abstain",
                    "required_claims": ["never written"],
                }},
            ]},
            {"a": {"adjudication": {"decision": "NO_SAFE_FIX"}}},
        )
        self.assertEqual(report["score"], 1.0)
        self.assertEqual(report["text_checks_failed"], ["a:required:never written"])


class ArtifactLoadingTests(unittest.TestCase):

    def _run(self, root: Path, name: str) -> Path:
        run = root / name / "error_solutions" / "v2_artifacts" / "app.apk"
        run.mkdir(parents=True)
        return run

    def test_a_directory_of_runs_is_refused_rather_than_merged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._run(root, "run_20260101_000000")
            self._run(root, "run_20260102_000000")
            with self.assertRaises(ValueError):
                resolve_run_root(root)
            self.assertEqual(
                resolve_run_root(root, "run_20260102_000000").name,
                "run_20260102_000000",
            )

    def test_the_adjudication_wins_and_finds_its_id_from_its_packet(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._run(root, "run_20260101_000000")
            (run / "0_m_evidence_packet.json").write_text(json.dumps(
                {"finding": {"finding_id": "F:::m:::Spec:::x"}}
            ), encoding="utf-8")
            # Carries the verdict but no id of its own.
            (run / "0_m_adjudication.json").write_text(json.dumps(
                {"decision": "NO_SAFE_FIX", "detector_violation": "confirmed"}
            ), encoding="utf-8")
            reviews = root / "run_20260101_000000" / "error_solutions" / "evidence_reviews"
            reviews.mkdir(parents=True)
            (reviews / "0_m_evidence.json").write_text(json.dumps(
                {"error_id": "F:::m:::Spec:::x", "analysis": {"decision": ""}}
            ), encoding="utf-8")
            results = load_run(root, "run_20260101_000000")
        self.assertEqual(list(results), ["F:::m:::Spec:::x"])
        chosen = results["F:::m:::Spec:::x"]
        self.assertEqual(chosen["_eval_kind"], "adjudication")
        self.assertEqual(normalize(chosen)["decision"], "NO_SAFE_FIX")

    def test_earlier_attempts_are_recorded_and_never_chosen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self._run(root, "run_20260101_000000")
            (run / "0_m_evidence_packet.json").write_text(json.dumps(
                {"finding": {"finding_id": "F"}}
            ), encoding="utf-8")
            (run / "0_m_adjudication.json").write_text(json.dumps(
                {"error_id": "F", "decision": "FIX_SUPPORTED"}
            ), encoding="utf-8")
            (run / "0_m_evidence_extraction_round1.json").write_text(json.dumps(
                {"error_id": "F", "decision": "NO_SAFE_FIX"}
            ), encoding="utf-8")
            results = load_run(root, "run_20260101_000000")
        chosen = results["F"]
        self.assertEqual(normalize(chosen)["decision"], "FIX_SUPPORTED")
        kinds = {item["kind"] for item in chosen["_eval_attempts"]}
        self.assertIn("attempt", kinds)
        self.assertIn("adjudication", kinds)


if __name__ == "__main__":
    unittest.main()
