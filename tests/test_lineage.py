"""Which findings the numbers are about, from observation to pull request.

The corpus counts observations, the sample counts rows, and the pilot counts
decisions and patches. Nothing joined them, so a reader could not tell
whether the five patches were five of the eleven decisions, and an analysis
could not tell that one bundled-library defect reported in forty-four
applications is one finding rather than forty-four.

These tests pin the collapse (and that it is auditable: the applications
that shared a finding are kept), and pin that a link the artifacts do not
supply is reported as missing rather than filled in.
"""
import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.evaluation.lineage import (  # noqa: E402
    as_rows, build_lineage, collapse_observations, observation_identity,
    run_outcomes, totals,
)


CORPUS_COLUMNS = ("unique_msg", "spec", "apk", "class", "method", "message",
                  "repo_url", "apk_url")


def _corpus(path: Path, rows) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(CORPUS_COLUMNS))
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in CORPUS_COLUMNS})


def _row(identity: str, apk: str, repo: str = "", spec: str = "SpecA") -> dict:
    return {
        "unique_msg": identity, "spec": spec, "apk": apk,
        "class": "okhttp3.internal.platform.Platform",
        "method": "newSSLContext", "message": "unknown",
        "repo_url": repo, "apk_url": f"https://f-droid.org/repo/{apk}",
    }


def _retrospective(run_root: Path, run_id: str, findings) -> None:
    directory = run_root / "retrospective"
    directory.mkdir(parents=True)
    (directory / "retrospective.json").write_text(json.dumps({
        "run_id": run_id,
        "pipeline": {"commit": "abc1234", "uncommitted_changes": False},
        "findings": findings,
    }), encoding="utf-8")


class CollapseTests(unittest.TestCase):

    def test_one_defect_in_many_applications_is_one_finding(self):
        rows = [
            _row("okhttp-platform", "one_v1.apk", "https://x/one"),
            _row("okhttp-platform", "two_v1.apk", "https://x/two"),
            _row("okhttp-platform", "three_v1.apk", "https://x/three"),
            _row("other", "one_v1.apk", "https://x/one", spec="SpecB"),
        ]
        findings = collapse_observations(rows)
        self.assertEqual(len(findings), 2)
        shared = findings["okhttp-platform"]
        self.assertEqual(shared["observations"], 3)
        self.assertEqual(shared["apk_count"], 3)
        # The collapse stays auditable: the applications are listed.
        self.assertEqual(
            shared["apks"], ["one_v1.apk", "two_v1.apk", "three_v1.apk"]
        )
        self.assertEqual(shared["repository_count"], 3)

    def test_a_row_without_a_unique_message_still_has_an_identity(self):
        identity = observation_identity({
            "apk": "a.apk", "class": "C", "method": "m", "message": "x",
        })
        self.assertEqual(identity, "a.apk|C|m|x")

    def test_the_sharing_measure_names_the_widest_cluster(self):
        findings = collapse_observations([
            _row("shared", f"app{index}_v1.apk", f"https://x/{index}")
            for index in range(5)
        ] + [_row("alone", "solo_v1.apk", "https://x/solo")])
        for record in findings.values():
            record.setdefault("runs", [])
            record.setdefault("actions", [])
            record.setdefault("pull_requests", [])
        summary = totals(findings)
        self.assertEqual(summary["findings"], 2)
        self.assertEqual(summary["findings_shared_by_several_apks"], 1)
        self.assertEqual(summary["widest_shared_finding"]["apk_count"], 5)


class RunJoinTests(unittest.TestCase):

    def test_a_runs_conclusions_are_read_from_its_retrospective(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run_20260101_000000"
            _retrospective(run, "run_20260101_000000", [{
                "unique_error_id": "f-1",
                "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                "terminal_stage": "published",
                "signatures": [],
                "pull_request": "https://github.com/owner/repo/pull/7",
            }])
            outcomes = run_outcomes(run)
        self.assertEqual(outcomes["f-1"]["action"], "repair_for_review")
        self.assertEqual(outcomes["f-1"]["run_id"], "run_20260101_000000")
        self.assertEqual(outcomes["f-1"]["pipeline"]["commit"], "abc1234")

    def test_a_run_without_a_retrospective_contributes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(run_outcomes(Path(directory)), {})

    def test_the_chain_joins_corpus_runs_and_pull_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "corpus.csv"
            _corpus(corpus, [
                _row("f-1", "one_v1.apk", "https://x/one"),
                _row("f-2", "two_v1.apk", "https://x/two"),
            ])
            run = root / "run_20260101_000000"
            _retrospective(run, "run_20260101_000000", [
                {"unique_error_id": "f-1", "decision": "FIX_SUPPORTED",
                 "terminal_stage": "published",
                 "pull_request": "https://github.com/owner/repo/pull/7"},
                {"unique_error_id": "f-2", "decision": "NO_SAFE_FIX",
                 "terminal_stage": "adjudication", "pull_request": ""},
            ])
            lineage = build_lineage(
                corpus, [run], resolve_checkout_facts=False
            )

        summary = lineage["totals"]
        self.assertEqual(summary["findings"], 2)
        self.assertEqual(summary["findings_adjudicated"], 2)
        self.assertEqual(summary["findings_with_a_patch"], 1)
        self.assertEqual(summary["findings_published"], 1)
        rows = as_rows(lineage)
        published = [row for row in rows if row["pull_request"]]
        self.assertEqual(len(published), 1)
        self.assertEqual(published[0]["last_action"], "repair_unattended")

    def test_a_finding_only_a_run_knows_is_marked_as_outside_the_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "corpus.csv"
            _corpus(corpus, [_row("f-1", "one_v1.apk", "https://x/one")])
            run = root / "run_20260101_000000"
            _retrospective(run, "run_20260101_000000", [
                {"unique_error_id": "f-elsewhere", "decision": "NO_SAFE_FIX",
                 "terminal_stage": "adjudication", "pull_request": ""},
            ])
            lineage = build_lineage(corpus, [run], resolve_checkout_facts=False)

        self.assertTrue(
            lineage["findings"]["f-elsewhere"]["not_in_corpus"]
        )
        self.assertEqual(lineage["totals"]["findings"], 2)
        self.assertEqual(lineage["totals"]["findings_in_corpus"], 1)

    def test_checkout_facts_are_marked_not_collected_when_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "corpus.csv"
            _corpus(corpus, [_row("f-1", "one_v1.apk", "https://x/one")])
            lineage = build_lineage(corpus, [], resolve_checkout_facts=False)
        self.assertEqual(
            lineage["findings"]["f-1"]["checkout"]["status"], "not_collected"
        )


if __name__ == "__main__":
    unittest.main()
