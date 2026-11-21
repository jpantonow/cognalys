"""The paper's cost table must tell sent calls from answers that were not sent.

A run's retrospective counts every traced call, including the ones the
persistent cache answered and the ones a finding's own identical earlier
call answered (a replay). Both are reported apart, so a run without a cache
does not read as having sent its replays to the model.
"""
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.evaluation.paper_tables import cost_table, run_summary  # noqa: E402


def _run(directory: Path, per_stage: dict) -> Path:
    (directory / "retrospective").mkdir(parents=True)
    (directory / "retrospective" / "retrospective.json").write_text(
        json.dumps({"run_id": "r", "llm_performance": {"per_stage": per_stage}}),
        encoding="utf-8",
    )
    return directory


class CostTableTests(unittest.TestCase):

    def test_replays_are_summed_and_shown_beside_cache_hits(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = _run(Path(directory), {
                "adjudication": {"calls": 4, "cache_hits": 1, "replays": 2,
                                 "latency_ms": 60000},
                "planning": {"calls": 2, "cache_hits": 0, "replays": 0,
                             "latency_ms": 0},
            })
            summary = run_summary("no cache", run_dir)
        self.assertEqual((summary["model_calls"], summary["model_cache_hits"],
                          summary["model_replays"]), (6, 1, 2))
        latex, records = cost_table([summary])
        self.assertEqual(records[0]["Replays"], 2)
        self.assertEqual(records[0]["Cache hits"], 1)
        self.assertIn("Replays", latex)

    def test_a_retrospective_written_before_replays_reads_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = _run(Path(directory), {
                "adjudication": {"calls": 3, "cache_hits": 1, "latency_ms": 0},
            })
            summary = run_summary("older", run_dir)
        self.assertEqual(summary["model_replays"], 0)
        _latex, records = cost_table([summary])
        self.assertEqual(records[0]["Replays"], 0)

    def test_the_cost_table_is_unchanged_without_corpus_hits(self):
        from cognalys.evaluation.paper_tables import latex_table

        with tempfile.TemporaryDirectory() as directory:
            run_dir = _run(Path(directory), {
                "adjudication": {"calls": 4, "cache_hits": 1, "replays": 2,
                                 "latency_ms": 60000}})
            summary = run_summary("no corpus", run_dir)
        self.assertEqual(summary["model_corpus_hits"], 0)
        latex, records = cost_table([summary])
        header = ("Condition", "Model calls", "Cache hits", "Replays", "Model minutes",
                  "Minutes per finding")
        attributed = summary["coverage"]["findings_attributed"]
        rows = [("no corpus", 4, 1, 2, "1.0", f"{1.0 / attributed:.1f}" if attributed else "N/A")]
        expected = latex_table(
            "Model cost per condition.", "tab:cost", header, rows,
            note=("Cache hits and replays (a finding's identical request answered "
                  "by its own earlier call) are counted among the model calls but "
                  "were not sent to the model, and are reported separately."))
        self.assertEqual(latex, expected)
        self.assertEqual(tuple(key for key in records[0] if key != "source"), header)

    def test_the_cost_table_reports_corpus_hits_in_their_own_column(self):
        with tempfile.TemporaryDirectory() as directory:
            served = run_summary("corpus", _run(Path(directory) / "a", {
                "external_research": {"calls": 3, "cache_hits": 0, "replays": 0,
                                      "corpus_hits": 2, "latency_ms": 0}}))
            cold = run_summary("cold", _run(Path(directory) / "b", {
                "external_research": {"calls": 3, "cache_hits": 0, "latency_ms": 0}}))
        self.assertEqual(served["model_corpus_hits"], 2)
        latex, records = cost_table([cold, served])
        self.assertEqual([record["Research corpus"] for record in records], [0, 2])
        self.assertEqual(list(records[0])[:5], ["Condition", "Model calls", "Cache hits",
                                                "Replays", "Research corpus"])
        self.assertIn("answered from the research corpus", latex)


if __name__ == "__main__":
    unittest.main()
