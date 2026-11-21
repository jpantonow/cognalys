"""Every finding lands in exactly one counter, and the right ones fail the step."""
import logging
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.run_statistics import (  # noqa: E402
    FAILURE_KINDS, failure_kind, record_failure, record_input_invalid,
    record_llm_budget, record_solution, step_failures,
)

LOGGER = logging.getLogger("run-statistics-test")


def _stats():
    counters = ("failed_analysis", "crashed", "provider_refused",
                "provider_unavailable", "provider_auth_failed", "llm_budget_exhausted",
                "not_analyzable", "not_applicable", "successfully_analyzed",
                "fixes_generated", "coordinated_solutions", "high_confidence",
                "medium_confidence", "low_confidence")
    stats = {name: 0 for name in counters}
    stats["failures"] = []
    stats["llm_budget"] = {"findings": 0, "calls": 0, "failed_calls": 0,
                           "transport_retries": 0, "model_seconds": 0.0}
    return stats


def _result(outcome, cause="why"):
    return SimpleNamespace(outcome=outcome, failure_cause=cause,
                           decision="", llm_budget={"calls": 2})


ERROR = {"_file_path": Path("app.apk/1_m.json"), "method_name": "m",
         "unique_error_id": "id"}


class FailureTests(unittest.TestCase):

    def test_each_named_kind_has_its_own_counter(self):
        for kind in FAILURE_KINDS:
            stats = _stats()
            self.assertEqual(record_failure(stats, LOGGER, ERROR, _result(kind)), kind)
            self.assertEqual(stats[kind], 1)
            self.assertEqual(stats["failures"][0]["kind"], kind)

    def test_an_unnamed_outcome_is_a_failed_analysis(self):
        stats = _stats()
        record_failure(stats, LOGGER, ERROR, _result("failed"))
        self.assertEqual(stats["failed_analysis"], 1)
        self.assertEqual(failure_kind("something_new"), "failed")

    def test_only_operator_or_pipeline_causes_fail_the_step(self):
        stats = _stats()
        for kind in ("provider_refused", "not_analyzable", "not_applicable"):
            record_failure(stats, LOGGER, ERROR, _result(kind))
        self.assertEqual(step_failures(stats), 0)
        # provider_unavailable (a server fault or capacity failure outlasting
        # the call's resends) is left for a resume pass, as a crash is.
        for kind in ("crashed", "provider_unavailable", "provider_auth_failed",
                     "llm_budget_exhausted", "failed"):
            record_failure(stats, LOGGER, ERROR, _result(kind))
        self.assertEqual(step_failures(stats), 5)


class OtherCounterTests(unittest.TestCase):

    def test_budget_totals_accumulate(self):
        stats = _stats()
        record_llm_budget(stats, {"calls": 3, "failed_calls": 1,
                                  "transport_retries": 2, "model_seconds": 1.5})
        record_llm_budget(stats, None)
        record_llm_budget(stats, {"calls": 1, "model_seconds": 0.5})
        self.assertEqual(stats["llm_budget"]["findings"], 2)
        self.assertEqual(stats["llm_budget"]["calls"], 4)
        self.assertEqual(stats["llm_budget"]["model_seconds"], 2.0)

    def test_replayed_calls_are_summed_apart_from_sent_ones(self):
        stats = _stats()  # totals written before replays were counted
        record_llm_budget(stats, {"calls": 5, "replayed_calls": 4})
        record_llm_budget(stats, {"calls": 2})
        self.assertEqual(stats["llm_budget"]["calls"], 7)
        self.assertEqual(stats["llm_budget"]["replayed_calls"], 4)

    def test_a_loading_crash_counts_as_a_crash(self):
        stats = _stats()
        record_input_invalid(stats, [
            {"file": "a/x.json", "cause": "JSONDecodeError"},
            {"file": "a/y.json", "cause": "KeyError", "kind": "crashed"},
        ], LOGGER)
        self.assertEqual(stats["input_invalid"], 1)
        self.assertEqual(stats["crashed"], 1)
        self.assertEqual(step_failures(stats), 1)

    def test_confidence_bands(self):
        stats = _stats()
        for confidence in (80, 60, 10):
            record_solution(stats, {"llm_analysis": {"confidence_percent": confidence}})
        self.assertEqual((stats["high_confidence"], stats["medium_confidence"],
                          stats["low_confidence"]), (1, 1, 1))
        self.assertEqual(stats["fixes_generated"], 3)


if __name__ == "__main__":
    unittest.main()
