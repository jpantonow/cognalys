"""What a maintainer needs to decide before merging, kept instead of lost.

hfut-schedule's getUpdate PR removed the app's only authentication for an
endpoint and never said so: the adjudicator's own blocking_for_publication
recorded "must be validated against applicable live service... before
publication" (category runtime_behavior) and "the supplied no-argument
caller is not semantically resolved" (category compatibility_contract), but
both were flattened away before reaching the solution record, and the PR
carried only the free-form review_assumptions text a later model call wrote
independently -- which a maintainer never sees at all, by design.

human_decided_publication_considerations reads the adjudicator's own
categorised list back out of evidence_analysis (where _analysis_record
already preserves it verbatim at v2.adjudication.blocking_for_publication)
and keeps only the categories HUMAN_DECIDED_BLOCKER_CATEGORIES names --
the same generic vocabulary already used elsewhere in this module, not a
per-specification list.
"""
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.pipeline_architecture import (  # noqa: E402
    HUMAN_DECIDED_BLOCKER_CATEGORIES,
    human_decided_publication_considerations,
)
from cognalys.utils.pr_text import title_from_edit_reasons  # noqa: E402


def _evidence_analysis(blocking_for_publication):
    return {"v2": {"adjudication": {"blocking_for_publication": blocking_for_publication}}}


class HumanDecidedPublicationConsiderationsTests(unittest.TestCase):
    def test_the_getupdate_shape_keeps_the_two_human_categories_and_drops_other(self):
        considerations = human_decided_publication_considerations(_evidence_analysis([
            {
                "category": "other",
                "description": "Compilation and the deterministic patched-source "
                "recheck can establish removal of the confirmed source-level predicate.",
            },
            {
                "category": "maintainer_decision",
                "description": "No supplied case policy selects or authorizes a "
                "replacement for the embedded default token flow.",
            },
            {
                "category": "compatibility_contract",
                "description": "The supplied no-argument caller is not semantically "
                "resolved and external consumers are outside the examined scope.",
            },
            {
                "category": "runtime_behavior",
                "description": "The selected replacement must be validated against "
                "applicable live service or deployment behavior.",
            },
        ]))
        self.assertEqual(
            [item["category"] for item in considerations],
            ["maintainer_decision", "compatibility_contract", "runtime_behavior"],
        )
        self.assertTrue(all(
            item["category"] in HUMAN_DECIDED_BLOCKER_CATEGORIES for item in considerations
        ))
        self.assertNotIn(
            "deterministic patched-source recheck",
            " ".join(item["description"] for item in considerations),
        )

    def test_categories_outside_the_generic_set_are_never_shown(self):
        for category in ("cause_unconfirmed", "code_evidence_missing", "target_unresolved", "", "unknown_future_category"):
            with self.subTest(category=category):
                self.assertEqual(
                    human_decided_publication_considerations(
                        _evidence_analysis([{"category": category, "description": "x"}])
                    ),
                    [],
                )

    def test_duplicate_descriptions_are_not_repeated(self):
        considerations = human_decided_publication_considerations(_evidence_analysis([
            {"category": "runtime_behavior", "description": "Validate against the live service."},
            {"category": "maintainer_decision", "description": "Validate against the live service."},
        ]))
        self.assertEqual(len(considerations), 1)

    def test_no_blockers_or_malformed_input_returns_empty_without_raising(self):
        self.assertEqual(human_decided_publication_considerations({}), [])
        self.assertEqual(human_decided_publication_considerations(None), [])
        self.assertEqual(human_decided_publication_considerations({"v2": {}}), [])
        self.assertEqual(
            human_decided_publication_considerations(_evidence_analysis([
                "not a dict", {"category": "runtime_behavior"},  # no description
                {"description": "no category"},
            ])),
            [],
        )

    def test_a_finding_with_no_open_question_is_unaffected(self):
        # BrowserAuthScreen's shape in the real run: no blocking_for_publication at all.
        self.assertEqual(human_decided_publication_considerations(_evidence_analysis([])), [])


class TitleFromEditReasonsTests(unittest.TestCase):
    """Every generated pull request had been titled "Fix <method>"."""

    def test_the_main_production_edit_names_the_change(self):
        self.assertEqual(title_from_edit_reasons([
            {"edit_kind": "declaration",
             "reason": "Imports the module BuildConfig needed to restrict debugging."},
            {"edit_kind": "method",
             "reason": "Enables WebView debugging only for debug builds, within "
                       "the existing Lollipop-only branch."},
        ]), "Enable WebView debugging only for debug builds")

    def test_an_edit_that_only_keeps_something_is_skipped(self):
        self.assertEqual(title_from_edit_reasons([
            {"edit_kind": "method",
             "reason": "Retain the existing getUpdate name and response type."},
            {"edit_kind": "delete",
             "reason": "Deletes the compiled-in Gitee credential so it is not shipped."},
        ]), "Delete the compiled-in Gitee credential")

    def test_a_long_clause_joining_two_actions_keeps_the_first(self):
        self.assertEqual(title_from_edit_reasons([
            {"edit_kind": "method",
             "reason": "Configures TLS only with the validating delegating manager "
                       "and removes the unconditional HostnameVerifier."},
        ]), "Configure TLS only with the validating delegating manager")

    def test_tests_and_overlong_reasons_give_no_title(self):
        self.assertEqual(title_from_edit_reasons([
            {"edit_kind": "create", "reason": "Adds regression coverage."},
            {"edit_kind": "method",
             "reason": "Parse all nine existing EditText values inside a local "
                       "NumberFormatException boundary before assigning fields."},
        ]), "")


class RealRunReplayTests(unittest.TestCase):
    """Replays the extraction against this run's actual on-disk solution files.

    Grounds the unit tests above in what generate_error_fixes.py really wrote,
    not just a hand-built fixture.
    """

    RUN = (
        Path("/mnt/c/Users/Antonow/Documents/tcc_v3/outputs/run_20260927_012948")
        / "error_solutions"
    )

    def _evidence_analysis(self, relative):
        path = self.RUN / relative
        if not path.is_file():
            self.skipTest(f"fixture run not present: {path}")
        return json.loads(path.read_text(encoding="utf-8")).get("evidence_analysis", {})

    def test_getupdate_keeps_exactly_its_two_human_blockers(self):
        considerations = human_decided_publication_considerations(
            self._evidence_analysis("com.hfut.schedule_2554.apk/1_getUpdate_solution.json")
        )
        self.assertEqual(
            sorted(item["category"] for item in considerations),
            ["compatibility_contract", "maintainer_decision", "runtime_behavior"],
        )
        for item in considerations:
            self.assertNotIn("deterministic patched-source recheck", item["description"])

    def test_oncreate_keeps_its_two_human_blockers(self):
        considerations = human_decided_publication_considerations(
            self._evidence_analysis("com.mine.autoshine_3.apk/2_onCreate_solution.json")
        )
        self.assertEqual(
            sorted(item["category"] for item in considerations),
            ["maintainer_decision", "runtime_behavior"],
        )

    def test_browserauthscreen_has_nothing_to_add(self):
        considerations = human_decided_publication_considerations(
            self._evidence_analysis("sh.hnet.comfychair_38.apk/0_BrowserAuthScreen_solution.json")
        )
        self.assertEqual(considerations, [])


class SummaryWordingTests(unittest.TestCase):
    def test_sentences_about_the_analysis_are_dropped_from_the_summary(self):
        from cognalys.utils.pr_text import plain_explanation

        text = (
            "DimensionActivity.onCreate enables WebView debugging outside a "
            "debug-build check. This satisfies the rule's static condition; it "
            "does not establish deployed release execution.\n\n"
            "Keep WebView debugging behind a debug-build check. This addresses "
            "the candidate without relying on undocumented detector behavior."
        )
        self.assertEqual(
            plain_explanation(text),
            "DimensionActivity.onCreate enables WebView debugging outside a "
            "debug-build check.\n\nKeep WebView debugging behind a debug-build check.",
        )


if __name__ == "__main__":
    unittest.main()
