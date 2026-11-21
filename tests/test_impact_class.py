"""The security-impact class of a pull request (docs/BANCA_SIMULADA.md, M2).

The class is read from the adjudication's runtime_security_impact, recorded on
the PR record and its outcome, and counted by scripts/levantar_prs.py over the
incorporated pull requests. A PR without a recorded adjudication, or whose
adjudication did not assess the impact ("unknown"), is "não registrada", never
guessed from its specification.
"""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs.impact_class import (  # noqa: E402
    IMPACT_NOT_ESTABLISHED, NO_SECURITY_IMPACT, NOT_RECORDED, SECURITY_IMPACT,
    adjudication_of, impact_class, published_impact_class, recorded_impact_class,
)

ROOT = Path(__file__).resolve().parents[1]

APK = "org.example.app_7.apk"
FINDING = {"spec": "MessageDigestSpec", "csv_class": "org.example.Hasher",
           "method_name": "hash", "finding_id": "f-1",
           "repo_owner": "example", "repo_name": "app"}
URL = "https://github.com/example/app/pull/12"


def load_survey_script():
    """scripts/levantar_prs.py, with a placeholder token so no credential file is read."""
    spec = importlib.util.spec_from_file_location("levantar_prs", ROOT / "scripts" / "levantar_prs.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "placeholder"}):
        spec.loader.exec_module(module)
    return module


class ImpactClassMappingTests(unittest.TestCase):
    def test_each_adjudication_value_has_one_class(self):
        for value, expected in (("confirmed", SECURITY_IMPACT),
                                ("non_security", NO_SECURITY_IMPACT),
                                ("not_established", IMPACT_NOT_ESTABLISHED),
                                ("unknown", NOT_RECORDED),
                                ("", NOT_RECORDED),
                                ("something_new", NOT_RECORDED)):
            with self.subTest(value=value):
                self.assertEqual(impact_class({"runtime_security_impact": value}), expected)

    def test_no_adjudication_is_not_recorded_whatever_the_specification(self):
        self.assertEqual(impact_class({}), NOT_RECORDED)
        self.assertEqual(impact_class(None), NOT_RECORDED)
        # The specification and the algorithm are never read.
        self.assertEqual(impact_class({"spec": "MessageDigestSpec", "algorithm": "MD5"}), NOT_RECORDED)

    def test_the_adjudication_is_the_one_a_v2_evidence_analysis_carries(self):
        evidence = {"runtime_security_impact": "unknown",
                    "v2": {"adjudication": {"runtime_security_impact": "non_security"}}}
        self.assertEqual(impact_class(adjudication_of(evidence)), NO_SECURITY_IMPACT)
        self.assertEqual(adjudication_of({"decision": "FIX_SUPPORTED"}), {})
        self.assertEqual(adjudication_of(None), {})

    def test_a_record_keeps_only_a_known_class(self):
        self.assertEqual(recorded_impact_class({"impact_class": SECURITY_IMPACT}), SECURITY_IMPACT)
        self.assertEqual(recorded_impact_class({"impact_class": "high"}), NOT_RECORDED)
        self.assertEqual(recorded_impact_class({}), NOT_RECORDED)


class PublishedImpactClassTests(unittest.TestCase):
    """The class of a published PR: its record's, else the publishing run's adjudication."""

    def publish(self, run: Path, metadata: dict) -> Path:
        pulls = run / "pull_requests"
        pulls.mkdir(parents=True, exist_ok=True)
        stem = f"{APK}_hash_MessageDigestSpec"
        (pulls / f"{stem}_pr.json").write_text(json.dumps(metadata), encoding="utf-8")
        created = pulls / f"{stem}_pr_created.json"
        created.write_text(json.dumps({"html_url": URL, "number": 12}), encoding="utf-8")
        return created

    def solve(self, run: Path, evidence: dict, artifact=None) -> None:
        solutions = run / "error_solutions"
        (solutions / APK).mkdir(parents=True)
        (solutions / APK / "3_hash_solution.json").write_text(json.dumps({
            "solution_metadata": {key: FINDING[key] for key in ("spec", "csv_class", "method_name")},
            "evidence_analysis": evidence}), encoding="utf-8")
        if artifact is not None:
            (solutions / "v2_artifacts" / APK).mkdir(parents=True)
            (solutions / "v2_artifacts" / APK / "3_hash_adjudication.json").write_text(
                json.dumps(artifact), encoding="utf-8")

    def test_the_class_on_the_pr_record_is_used(self):
        with tempfile.TemporaryDirectory() as directory:
            created = self.publish(Path(directory) / "run",
                                   {**FINDING, "impact_class": NO_SECURITY_IMPACT})
            self.assertEqual(published_impact_class(created), NO_SECURITY_IMPACT)

    def test_an_older_record_reads_the_adjudication_artifact_of_its_run(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            created = self.publish(run, dict(FINDING))
            self.solve(run, {"v2": {"adjudication": {"runtime_security_impact": "unknown"}}},
                       artifact={"runtime_security_impact": "confirmed"})
            self.assertEqual(published_impact_class(created), SECURITY_IMPACT)

    def test_without_the_artifact_the_solution_files_adjudication_is_read(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            created = self.publish(run, dict(FINDING))
            self.solve(run, {"v2": {"adjudication": {"runtime_security_impact": "not_established"}}})
            self.assertEqual(published_impact_class(created), IMPACT_NOT_ESTABLISHED)

    def test_a_record_that_says_not_recorded_still_reads_the_run(self):
        """pr_generator writes the class even when its evidence lookup failed."""
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            created = self.publish(run, {**FINDING, "impact_class": NOT_RECORDED})
            self.assertEqual(published_impact_class(created), NOT_RECORDED)
            self.solve(run, {"decision": "FIX_SUPPORTED"},
                       artifact={"runtime_security_impact": "non_security"})
            self.assertEqual(published_impact_class(created), NO_SECURITY_IMPACT)

    def test_no_adjudication_in_the_run_is_not_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run"
            created = self.publish(run, dict(FINDING))
            self.assertEqual(published_impact_class(created), NOT_RECORDED)
            self.solve(run, {"decision": "FIX_SUPPORTED"})
            self.assertEqual(published_impact_class(created), NOT_RECORDED)


class OutcomeRecordTests(unittest.TestCase):
    def test_the_outcome_record_keeps_the_class_of_the_pr_record(self):
        from cognalys.prs.pr_outcomes import record_pr_outcome, responses_to_same_rule

        with tempfile.TemporaryDirectory() as directory:
            outcomes = Path(directory)
            path = record_pr_outcome({**FINDING, "impact_class": NO_SECURITY_IMPACT},
                                     {"html_url": URL}, {"status": "merged"},
                                     [{"author": "m", "kind": "comment", "body": "Thanks"}], outcomes)
            entry = json.loads(path.read_text(encoding="utf-8"))[0]
            self.assertEqual(entry["impact_class"], NO_SECURITY_IMPACT)
            self.assertEqual(entry["state"], "merged")
            # Not part of what reaches the model.
            response = responses_to_same_rule("MessageDigestSpec", outcomes)[0]
            self.assertNotIn("impact_class", response)

            path = record_pr_outcome(dict(FINDING), {"html_url": URL}, {"status": "closed"}, [], outcomes)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))[0]["impact_class"], NOT_RECORDED)


class SurveyCountTests(unittest.TestCase):
    def setUp(self):
        self.survey = load_survey_script()

    def test_incorporated_prs_are_counted_by_class(self):
        prs = [{"url": "https://github.com/a/b/pull/1", "category": "merged"},
               {"url": "https://github.com/a/b/pull/2", "category": "manual"},
               {"url": "https://github.com/A/B/pull/3", "category": "merged"},
               {"url": "https://github.com/a/b/pull/4", "category": "merged"},
               {"url": "https://github.com/a/b/pull/5", "category": "maintainer"},
               {"url": "https://github.com/a/b/pull/6", "category": "open"}]
        impacts = {"https://github.com/a/b/pull/1": [SECURITY_IMPACT],
                   "https://github.com/a/b/pull/2": [NO_SECURITY_IMPACT],
                   # Another run's record without a class does not hide this one's.
                   "https://github.com/a/b/pull/3": [NOT_RECORDED, NO_SECURITY_IMPACT],
                   "https://github.com/a/b/pull/5": [SECURITY_IMPACT],
                   "https://github.com/a/b/pull/6": [SECURITY_IMPACT]}
        self.assertEqual(self.survey.incorporated_by_impact(prs, impacts), {
            SECURITY_IMPACT: 1, NO_SECURITY_IMPACT: 2,
            IMPACT_NOT_ESTABLISHED: 0, NOT_RECORDED: 1})

    def test_records_that_disagree_are_not_settled_by_a_guess(self):
        with self.assertRaises(RuntimeError):
            self.survey.impact_of(URL, {URL: [SECURITY_IMPACT, NO_SECURITY_IMPACT]})

    def test_every_class_has_a_label(self):
        from cognalys.prs.impact_class import IMPACT_CLASSES

        self.assertEqual(set(self.survey.IMPACT_LABEL), set(IMPACT_CLASSES))


class SurveyStagesTests(unittest.TestCase):
    """origins() writes pr_impact.json and report-rvsec reads it, on a temp outputs/ tree."""

    STAMP = "20261108"

    def setUp(self):
        self.survey = load_survey_script()
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        reports = self.root / "outputs" / "prs_reports"
        self.out = reports / self.STAMP
        self.out.mkdir(parents=True)
        (self.root / "docs").mkdir()
        (self.root / "docs" / "relatorio_prs.md").write_text("", encoding="utf-8")
        for name, value in (("ROOT", self.root), ("REPORTS", reports), ("OUT", self.out),
                            ("STAMP", self.STAMP)):
            patcher = mock.patch.object(self.survey, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # Mixed-case owner, as GitHub returns it; the class is on the PR record.
        self.publish("run_a", APK, "hash", "https://github.com/Example/App/pull/12",
                     {**FINDING, "impact_class": SECURITY_IMPACT})
        # An older record, without the class and without any adjudication in its run.
        self.publish("run_b", "org.other.lib_3.apk", "digest", "https://github.com/Other/Lib/pull/3",
                     {**FINDING, "method_name": "digest"})
        rows = [self.row(1, "https://github.com/Example/App/pull/12"),
                self.row(2, "https://github.com/Other/Lib/pull/3")]
        (self.out / "search.json").write_text(json.dumps({"total_count": len(rows)}), encoding="utf-8")
        (self.out / "collection.json").write_text(json.dumps({"prs": rows, "failures": []}),
                                                  encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def publish(self, run: str, apk: str, method: str, url: str, metadata: dict) -> None:
        pulls = self.root / "outputs" / run / "pull_requests"
        pulls.mkdir(parents=True)
        stem = f"{apk}_{method}_MessageDigestSpec"
        (pulls / f"{stem}_pr.json").write_text(json.dumps(metadata), encoding="utf-8")
        (pulls / f"{stem}_pr_created.json").write_text(json.dumps({"html_url": url}), encoding="utf-8")
        results = self.root / "outputs" / run / "application_results"
        results.mkdir()
        (results / "execution_report.json").write_text(json.dumps({"per_solution_details": [
            {"apk_name": apk, "method_name": method, "tool": "ape"}]}), encoding="utf-8")

    @staticmethod
    def row(number: int, url: str) -> dict:
        return {"pr": {"id": number, "html_url": url, "title": "Fix", "state": "closed",
                       "merged": True, "merged_by": {"login": "maintainer"},
                       "created_at": f"2026-10-0{number}T00:00:00Z",
                       "merged_at": f"2026-10-1{number}T00:00:00Z",
                       "closed_at": f"2026-10-1{number}T00:00:00Z"},
                "events": [], "comments": [], "reviews": []}

    def test_report_rvsec_counts_the_classes_origins_recorded(self):
        self.survey.origins()
        impacts = json.loads((self.out / "pr_impact.json").read_text(encoding="utf-8"))
        self.assertEqual(impacts, {"https://github.com/example/app/pull/12": [SECURITY_IMPACT],
                                   "https://github.com/other/lib/pull/3": [NOT_RECORDED]})
        self.survey.report(rvsec_only=True)
        summary = json.loads((self.out / "summary_rvsec.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["incorporated_by_impact"], {
            SECURITY_IMPACT: 1, NO_SECURITY_IMPACT: 0, IMPACT_NOT_ESTABLISHED: 0, NOT_RECORDED: 1})
        text = (self.root / "docs" / f"relatorio_prs_rvsec_{self.STAMP}.md").read_text(encoding="utf-8")
        self.assertIn(f"| {self.survey.IMPACT_LABEL[SECURITY_IMPACT]} | 1 |", text)
        self.assertIn(f"| {self.survey.IMPACT_LABEL[NOT_RECORDED]} | 1 |", text)

    def test_report_rvsec_needs_the_origins_stage(self):
        self.survey.origins()
        (self.out / "pr_impact.json").unlink()
        with self.assertRaises(RuntimeError):
            self.survey.report(rvsec_only=True)


if __name__ == "__main__":
    unittest.main()
