"""A pull request reached only after a redraft or a replan is marked to be read first.

The marker is read from the run's call traces and changes no outcome: the
statistics keep "PR pronto" and only its detail says "após ..."; the preview
adds a row and a line for the operator.
"""
import json
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm import generation_loops  # noqa: E402
from cognalys.llm.fix_artifacts import recorded_review_notes  # noqa: E402
from cognalys.llm.generation_loops import (  # noqa: E402
    finding_loop, generation_loops as loops_of, loop_depth_label, loop_depth_note,
)
from cognalys.prs import generate_github_previews as previews  # noqa: E402
from cognalys.reporting import finding_statistics as stats  # noqa: E402

FINDING = "a.Keys:::save:::KeyStoreSpec:::UnsatisfiedConstraint:::load not called"
OTHER = "a.Other:::run:::CipherSpec:::UnsatisfiedConstraint:::x"


def write_traces(directory: Path, calls) -> Path:
    """Traces as the provider client writes them:
    <time>_<us>_<pid>_<n>_<stage>_{metadata,request}.json.

    Each call is (stage, finding, retry) or (stage, finding, retry, pid,
    delivery); pid 1 and a call sent to the provider by default.
    """
    logs = directory / "application_results" / "openai_prompt_logs"
    logs.mkdir(parents=True)
    for number, call in enumerate(calls, 1):
        stage, finding, retry = call[:3]
        pid, delivery = (tuple(call[3:]) + (1, "sent_to_openai")[len(call) - 3:])[:2]
        stem = f"20261114T10{number // 60:02d}{number % 60:02d}_000000_{pid}_{number:04d}_{stage}"
        (logs / f"{stem}_metadata.json").write_text(
            json.dumps({"call_id": stem, "stage": stage, "finding_id": finding,
                        "delivery": delivery}), encoding="utf-8")
        # The payload is a JSON string inside the trace, its quotes escaped.
        payload = {"target_file": "a/Keys.kt"}
        if retry:
            payload["previous_validation_feedback"] = {
                "semantic_validation_retry": {"attempt": retry, "errors": []}}
        (logs / f"{stem}_request.json").write_text(
            json.dumps({"stage": stage, "input": json.dumps(payload)}), encoding="utf-8")
    return logs


DRAFT, PLAN = generation_loops.DRAFT_STAGE, generation_loops.PLAN_STAGE
REVIEW = "code_generation.behavior_review"
# Two files drafted, one redrafted after a refusal, then a new plan whose one
# file was redrafted twice; the other finding's drafts stood at once.
LOOPED = [
    (PLAN, FINDING, 0), (DRAFT, FINDING, 0), (DRAFT, FINDING, 0), (REVIEW, FINDING, 0),
    (DRAFT, FINDING, 1), (PLAN, OTHER, 0), (DRAFT, OTHER, 0), (REVIEW, OTHER, 0),
    (PLAN, FINDING, 0), (DRAFT, FINDING, 0), (DRAFT, FINDING, 1), (DRAFT, FINDING, 2),
]


class GenerationLoopTests(unittest.TestCase):
    def test_redrafts_and_replans_are_read_from_the_traces(self):
        with tempfile.TemporaryDirectory() as directory:
            logs = write_traces(Path(directory), LOOPED)
            self.assertEqual(loops_of(logs), {
                FINDING: {"redrafts": 3, "replans": 1},
                OTHER: {"redrafts": 0, "replans": 0},
            })
            self.assertEqual(finding_loop(logs, "a.Keys", "save", "KeyStoreSpec"),
                             {"redrafts": 3, "replans": 1})
            # A unit whose drafts stood at once, or that the traces never drafted.
            self.assertEqual(finding_loop(logs, "a.Other", "run", "CipherSpec"), {})
            self.assertEqual(finding_loop(logs, "a.Keys", "load", "KeyStoreSpec"), {})

    def test_a_plan_made_again_before_any_draft_is_not_a_replan(self):
        """A plan corrected before drafting (patch_planning twice) went round no loop."""
        with tempfile.TemporaryDirectory() as directory:
            logs = write_traces(Path(directory), [
                (PLAN, FINDING, 0), (PLAN, FINDING, 0), (DRAFT, FINDING, 0)])
            self.assertEqual(loops_of(logs), {FINDING: {"redrafts": 0, "replans": 0}})

    def test_a_resumed_step_is_not_a_replan(self):
        """einkbro hash (2026-10-22): four processes in one run folder, each
        planning the unit from the start, one from the cache, read as 6
        redrafts and 3 replans where no process replanned."""
        with tempfile.TemporaryDirectory() as directory:
            logs = write_traces(Path(directory), [
                (PLAN, FINDING, 0, 87507), (DRAFT, FINDING, 0, 87507), (DRAFT, FINDING, 1, 87507),
                (PLAN, FINDING, 0, 94556), (DRAFT, FINDING, 0, 94556),
                (DRAFT, FINDING, 1, 94556), (DRAFT, FINDING, 2, 94556),
                (PLAN, FINDING, 0, 98264, "cache_hit"),
                (DRAFT, FINDING, 0, 98264, "cache_hit"), (DRAFT, FINDING, 1, 98264),
            ])
            # The last process that drafted: one redraft on its one plan.
            self.assertEqual(loops_of(logs), {FINDING: {"redrafts": 1, "replans": 0}})

    def test_a_later_process_that_only_plans_keeps_the_drafting_process(self):
        """melox md5Hex (2026-11-05): the resumed process planned the unit
        from the cache and drafted nothing; the drafts are the first one's."""
        with tempfile.TemporaryDirectory() as directory:
            logs = write_traces(Path(directory), [
                (PLAN, FINDING, 0, 203021), (DRAFT, FINDING, 0, 203021),
                (DRAFT, FINDING, 0, 203021), (DRAFT, FINDING, 1, 203021),
                (PLAN, FINDING, 0, 1832, "cache_hit"),
            ])
            self.assertEqual(loops_of(logs), {FINDING: {"redrafts": 1, "replans": 0}})

    def test_a_replan_replayed_from_the_cache_in_one_process_is_still_one(self):
        """A resumed step replays a real replan from the cache: the plan after
        its own drafts is the replan the first process made."""
        with tempfile.TemporaryDirectory() as directory:
            logs = write_traces(Path(directory), [
                (PLAN, FINDING, 0, 5), (DRAFT, FINDING, 0, 5), (DRAFT, FINDING, 1, 5),
                (PLAN, FINDING, 0, 5), (DRAFT, FINDING, 0, 5),
                (PLAN, FINDING, 0, 6, "cache_hit"), (DRAFT, FINDING, 0, 6, "cache_hit"),
                (DRAFT, FINDING, 1, 6, "cache_hit"), (PLAN, FINDING, 0, 6, "cache_hit"),
                (DRAFT, FINDING, 0, 6), (DRAFT, FINDING, 1, 6),
            ])
            self.assertEqual(loops_of(logs), {FINDING: {"redrafts": 2, "replans": 1}})

    def test_a_run_without_traces_has_no_loops(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(loops_of(Path(directory) / "missing"), {})

    def test_the_labels(self):
        self.assertEqual(loop_depth_label({"redrafts": 2, "replans": 1}), "após 2 redrafts e replan")
        self.assertEqual(loop_depth_label({"redrafts": 1, "replans": 0}), "após 1 redraft")
        self.assertEqual(loop_depth_label({"redrafts": 0, "replans": 1}), "após replan")
        self.assertEqual(loop_depth_label({}), "")
        self.assertEqual(loop_depth_label(None), "")
        self.assertEqual(loop_depth_note({"redrafts": 1, "replans": 1}),
                         "1 redraft after a refusal and a new plan")

    def test_the_recorded_notes_carry_the_loop(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            write_traces(run, LOOPED)
            solutions = run / "error_solutions" / "app.apk"
            solutions.mkdir(parents=True)
            (solutions / "0_save_solution.json").write_text(json.dumps({"solution_metadata": {
                "csv_class": "a.Keys", "method_name": "save", "spec": "KeyStoreSpec"}}),
                encoding="utf-8")
            notes = recorded_review_notes(run / "error_solutions", "app.apk", "a.Keys",
                                          "save", "KeyStoreSpec")
            self.assertEqual(notes["generation_loop"], {"redrafts": 3, "replans": 1})


class LoopMarkerStatisticsTests(unittest.TestCase):
    def current(self):
        from cognalys.prs.publication_checks import current_review_contract_version

        return current_review_contract_version()

    def test_the_outcome_stays_and_the_detail_names_the_rounds_first(self):
        looped = {"pr_ready": True, "review_contract_version": self.current(),
                  "generation_loop": {"redrafts": 2, "replans": 1}}
        self.assertEqual(stats.final_outcome(looped), ("PR pronto", "após 2 redrafts e replan"))
        # A stale review is still matched at the end of the detail.
        stale = {"pr_ready": True, "generation_loop": {"redrafts": 1, "replans": 0}}
        outcome, detail = stats.final_outcome(stale)
        self.assertEqual(outcome, "PR pronto")
        self.assertEqual(detail, f"após 1 redraft; {stats.STALE_REVIEW_DETAIL}")
        self.assertEqual(stats.final_outcome(
            {"pr_ready": True, "review_contract_version": self.current()}), ("PR pronto", ""))

    def test_the_outcome_section_says_which_to_read_first(self):
        key = ("app.apk", "a.Keys", "save", "KeyStoreSpec")
        plain = ("app.apk", "a.Other", "run", "CipherSpec")
        records = {key: {"pr_ready": True, "review_contract_version": self.current(),
                         "generation_loop": {"redrafts": 1, "replans": 0}},
                   plain: {"pr_ready": True, "review_contract_version": self.current()}}
        text, rows = stats.outcome_section({key: {}, plain: {}}, records, [])
        self.assertIn("1 dos 2 PRs prontos só ficaram de pé depois de um redraft", text)
        self.assertIn([*key, "PR pronto", "após 1 redraft"], rows)
        self.assertIn([*plain, "PR pronto", ""], rows)


class LoopMarkerPreviewTests(unittest.TestCase):
    METADATA = {"finding_id": "f1", "publishable": True, "build_validation": {"status": "success"},
                "commit_hash": "abc123"}

    def test_a_looped_draft_is_marked_to_read_first(self):
        preview = previews.finding_review_preview(dict(
            self.METADATA, generation_loop={"redrafts": 2, "replans": 1}))
        self.assertIn("| Draft rounds | `2 redrafts after a refusal and a new plan` |", preview)
        self.assertIn("**Read this draft first:** it stood only after 2 redrafts", preview)

    def test_a_published_draft_keeps_the_row_without_the_banner(self):
        preview = previews.finding_review_preview(dict(
            self.METADATA, generation_loop={"redrafts": 1, "replans": 0},
            published_pull_request="https://github.com/o/r/pull/1"))
        self.assertIn("| Draft rounds | `1 redraft after a refusal` |", preview)
        self.assertNotIn("Read this draft first", preview)

    def test_a_draft_that_stood_at_once_is_unchanged(self):
        preview = previews.finding_review_preview(dict(self.METADATA))
        self.assertNotIn("Draft rounds", preview)
        self.assertNotIn("Read this draft first", preview)


if __name__ == "__main__":
    unittest.main()
