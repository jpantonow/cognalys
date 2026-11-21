"""The late-blocked issue template asks a question that fits its reason, in plain words."""
import json
import logging
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.fix_generation_common import (  # noqa: E402
    MAX_ISSUE_WORDS,
    MAX_REGRESSION_WORDS,
    issue_words,
    plain_blocker_question,
    plain_blocker_reasons,
    plain_cause,
    plain_why_no_pr,
    post_validation_issue_candidate,
    recorded_review_regressions,
    regression_reason,
)

GENERIC = "every version I wrote changed what the app does in a case it handles today"
# The shape of InputLeaf's discovery regression (agent_baseline_20261108).
DISCOVERY = {
    "source_file_path": "app/src/main/java/a/ServerScanner.kt",
    "scenario": "A local server presents a self-signed certificate outside the platform "
                "trust store and serves its hello over TLS.",
    "before": "Discovery accepts the certificate, reads the hello and reports the server.",
    "after": "Platform certificate validation fails before the hello is read. The scan "
             "omits the server.",
    "source": "plan",
}


class PlainIssueFallbackTests(unittest.TestCase):
    def test_predicate_syntax_and_claim_ids_are_removed(self):
        cause = ("The key comes from a resource. This material is not random, violating "
                 "the rule's required preparedKeyMaterial[keyMaterial] || "
                 "randomized[keyMaterial] predicate (C-001, C-002).")
        self.assertEqual(plain_cause(cause),
                         "The key comes from a resource. This material is not random.")

    def test_bracketed_and_mixed_ids_are_removed(self):
        """DNS Toggle's and Tempus's issues, 2026-11-04."""
        self.assertEqual(
            plain_cause("The key may be all zeros [C1, C2, C5; RUN-001, SRC-001]."),
            "The key may be all zeros.")
        self.assertEqual(plain_cause("The array is built here (C1; SRC-001, WEB-005)."),
                         "The array is built here.")

    def test_the_confirmation_preamble_is_removed(self):
        self.assertEqual(
            plain_cause("The reported required-predicate violation is confirmed: the "
                        "service installs an accept-all manager."),
            "The service installs an accept-all manager.")

    def test_the_question_follows_the_reason(self):
        question, _ = plain_blocker_question(["SHIPPED_CIPHERTEXT_REMOVED"])
        self.assertIn("server", question)
        question, _ = plain_blocker_question(["SOMETHING_UNKNOWN"])
        self.assertNotIn("above", question)

    def test_the_v2_template_no_longer_points_at_a_missing_list(self):
        issue = post_validation_issue_candidate(
            None, ["CONSTANT_KEY_MATERIAL_KEPT"], "fetch", "SecretKeySpecSpec",
            "The key is a constant (C-001).", "v2")
        self.assertNotIn("above", issue["maintainer_question"])
        self.assertEqual(issue["finding_summary"], "The key is a constant.")


class RecordedRegressionReasonTests(unittest.TestCase):
    """The review's refusal names the case it recorded (issue previews, 2026-11-14)."""

    def test_the_issue_names_the_scenario_and_what_the_app_does_after(self):
        issue = post_validation_issue_candidate(
            None, ["UNINTENDED_BEHAVIOR_CHANGE"], "discover", "SSLContextSpec",
            "The scanner trusts every certificate.", "v3", regressions=[DISCOVERY])
        why = issue["why_no_pr"]
        self.assertTrue(why.startswith("I have not opened a pull request because " + GENERIC))
        self.assertIn("in the last one, a local server presents a self-signed certificate", why)
        # "Platform" is written in lower case elsewhere in the case; a word
        # that never is might be a name and keeps its capital.
        self.assertIn("over TLS: after the change, platform certificate validation fails "
                      "before the hello is read, and the scan omits the server.", why)
        # The before field is left out: the paragraph stays one sentence.
        self.assertNotIn("Discovery accepts", why)
        self.assertEqual(why.count(". "), 0)

    def test_a_recorded_case_keeps_the_issue_within_its_word_limit(self):
        """KeyPass encrypt (frozen run, 2026-11-14): scenario, before and
        after made why_no_pr 126 words and the four fields 160."""
        keypass = {
            "source_file_path": "common/src/main/java/com/yogeshpaliyal/common/utils/"
                                "CryptoManager.kt",
            "scenario": "A user repeatedly updates settings on a device with finite keystore "
                        "storage until the retained per-write keys consume the available "
                        "space.",
            "before": "Repeated writes reused the same keystore key and did not accumulate "
                      "a new persistent key entry for each update.",
            "after": "Every successful update retains at least a fresh data key and a marker "
                     "key. Eventually key creation fails when the accumulated entries exhaust "
                     "available storage, preventing the settings write.",
        }
        issue = post_validation_issue_candidate(
            None, ["UNINTENDED_BEHAVIOR_CHANGE"], "encrypt", "CipherSpec",
            "The dynamic analysis observed this violation while the app ran: no generator "
            "of the key given to Cipher.init was observed.", "v3", regressions=[keypass])
        why = issue["why_no_pr"]
        self.assertIn("in the last one, a user repeatedly updates settings", why)
        self.assertNotIn("after the change", why)
        self.assertLessEqual(issue_words(why), 60)
        self.assertLessEqual(issue_words(*(issue[field] for field in (
            "finding_summary", "why_no_pr", "maintainer_question", "proposed_next_step"))),
            MAX_ISSUE_WORDS)

    def test_with_no_room_left_the_general_sentence_stays(self):
        long_summary = "The key is a constant. " * 25
        issue = post_validation_issue_candidate(
            None, ["UNINTENDED_BEHAVIOR_CHANGE"], "discover", "SSLContextSpec",
            long_summary, "v3", regressions=[DISCOVERY])
        self.assertEqual(issue["why_no_pr"],
                         "I have not opened a pull request because " + GENERIC + ".")
        self.assertEqual(plain_why_no_pr(["UNINTENDED_BEHAVIOR_CHANGE"], regressions=[DISCOVERY],
                                         other_fields=("word " * 120,)),
                         "I have not opened a pull request because " + GENERIC + ".")
        # Room for the scenario but not for what follows it.
        shorter = plain_why_no_pr(["UNINTENDED_BEHAVIOR_CHANGE"], regressions=[DISCOVERY],
                                  other_fields=("word " * 100,))
        self.assertTrue(shorter.endswith("serves its hello over TLS."), shorter)
        self.assertLessEqual(issue_words(shorter, "word " * 100), MAX_ISSUE_WORDS)

    def test_without_a_recorded_regression_the_general_sentence_stays(self):
        for regressions in (None, [], [{"scenario": "", "before": "x", "after": "y"}]):
            self.assertEqual(
                plain_blocker_reasons(["UNINTENDED_BEHAVIOR_CHANGE"], regressions=regressions),
                [GENERIC])

    def test_only_the_reviews_refusal_takes_the_case(self):
        reasons = plain_blocker_reasons(
            ["STORED_DERIVED_VALUE_CHANGED"], regressions=[DISCOVERY])
        self.assertNotIn("in the last one", " ".join(reasons))

    def test_pipeline_words_keep_the_general_sentence(self):
        """Your Local Weather run_v4: "contrary to the plan invariant and forbidden changes"."""
        planned = {**DISCOVERY, "scenario": "The derivation uses 210,000 iterations, contrary "
                                            "to the plan invariant and forbidden changes."}
        governed = {**DISCOVERY, "scenario": "The governed call keeps its value."}
        cited = {**DISCOVERY, "scenario": "Discovery reports the server (C1; SRC-001)."}
        # redreader_sha1 run_sob3: the case of a draft that did not build.
        built = {**DISCOVERY, "scenario": "After the build error is corrected, a user adds "
                                          "a hostname and encryption fails."}
        for item in (planned, governed, cited, built):
            self.assertEqual(regression_reason([item]), "", item)

    def test_pipeline_words_after_the_change_leave_the_scenario_alone(self):
        planned = {**DISCOVERY, "after": "The derivation uses 210,000 iterations, contrary "
                                         "to the plan invariant and forbidden changes."}
        reason = regression_reason([planned])
        self.assertTrue(reason.endswith("serves its hello over TLS"), reason)
        self.assertNotIn("plan", reason)

    def test_a_later_plain_regression_is_used(self):
        building = {**DISCOVERY, "scenario": "Building the app after applying the patch."}
        self.assertIn("a local server presents", regression_reason([building, DISCOVERY]))

    def test_a_regression_in_a_test_file_is_not_the_apps(self):
        in_test = {**DISCOVERY, "source_file_path": "app/src/test/java/a/ScannerTest.kt"}
        self.assertEqual(regression_reason([in_test]), "")

    def test_an_overlong_case_is_shortened_to_its_scenario_or_left_out(self):
        long_after = {**DISCOVERY, "after": "The scan omits the server " * 20}
        reason = regression_reason([long_after])
        self.assertTrue(reason.endswith("serves its hello over TLS"), reason)
        self.assertLessEqual(issue_words(reason.split("in the last one, ", 1)[1]),
                             MAX_REGRESSION_WORDS)
        long_scenario = {**DISCOVERY, "scenario": "A local server presents a certificate " * 10}
        self.assertEqual(regression_reason([long_scenario]), "")

    def test_patch_reads_as_change_and_names_keep_their_capital(self):
        reason = regression_reason([{
            "source_file_path": "app/src/main/java/a/Keys.kt",
            "scenario": "Android kills the process after the patch renamed the file.",
            "before": "AndroidKeyStore keeps the key.",
            "after": "Eventually the patched code reads no key.",
        }])
        self.assertIn("in the last one, Android kills the process after the change "
                      "renamed the file: after the change, eventually the changed code "
                      "reads no key", reason)
        reason = regression_reason([{
            "source_file_path": "app/src/main/java/a/Keys.kt",
            "scenario": "Something else happens.",
            "after": "AndroidKeyStore holds no key.",
        }])
        self.assertIn("after the change, AndroidKeyStore holds no key", reason)

    def test_the_last_review_beside_the_drafts_is_read(self):
        with tempfile.TemporaryDirectory() as directory:
            draft_dir = Path(directory)
            self.assertEqual(recorded_review_regressions(draft_dir), [])
            (draft_dir / "behavior_review.json").write_text(
                json.dumps({"regressions": [DISCOVERY, "not a regression"]}), encoding="utf-8")
            self.assertEqual(recorded_review_regressions(draft_dir), [DISCOVERY])

    def test_the_persisted_issue_reads_the_findings_review(self):
        from cognalys.llm.generate_error_fixes import FixGenerator

        with tempfile.TemporaryDirectory() as directory:
            generator = FixGenerator.__new__(FixGenerator)
            generator.architecture_version = "v2"
            generator.output_dir = Path(directory)
            generator.logger = logging.getLogger("test-plain-issue")
            generator.pr_issue_style = "v2"
            draft_dir = Path(directory) / "coordinated_drafts" / "app.apk" / "3_discover"
            draft_dir.mkdir(parents=True)
            (draft_dir / "behavior_review.json").write_text(
                json.dumps({"regressions": [DISCOVERY]}), encoding="utf-8")
            evidence_file = Path(directory) / "review.json"
            evidence_file.write_text(json.dumps({"analysis": {}}), encoding="utf-8")
            error = {
                "error_index": 3, "repository_url": "https://github.com/owner/scanner",
                "source_file_path": "app/src/main/java/a/ServerScanner.kt",
                "csv_class": "a.ServerScanner", "spec": "SSLContextSpec", "tool": "rvsec",
                "error_message": "SSLContext.init: trust manager accepts all",
                "method_body": "ctx.init(null, arrayOf(TrustAll), null)",
                "unique_error_id": "a.ServerScanner:::discover:::SSLContextSpec:::0",
            }

            def analysis():
                return {
                    "decision": "NO_SAFE_FIX",
                    "confirmed_cause": "The scanner trusts every certificate.",
                    "predicate_assessment": [{
                        "status": "violated",
                        "evidence": "ctx.init(null, arrayOf(TrustAll), null)"}],
                    "issue_candidate": {"eligible": False},
                }

            path = generator.persist_blocked_issue_candidate(
                error, analysis(), evidence_file, "app.apk", "discover",
                ["UNINTENDED_BEHAVIOR_CHANGE"])
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("a local server presents", saved["issue_content"]["why_no_pr"])
            self.assertEqual(saved["review_regressions"], [DISCOVERY])
            # Another blocker leaves the review alone.
            path = generator.persist_blocked_issue_candidate(
                error, analysis(), evidence_file, "app.apk", "discover",
                ["STORED_DERIVED_VALUE_CHANGED"])
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn("a local server", saved["issue_content"]["why_no_pr"])
            self.assertNotIn("review_regressions", saved)


if __name__ == "__main__":
    unittest.main()
