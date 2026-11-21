import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm import fix_generation_common  # noqa: E402
from cognalys.prs import pr_outcomes  # noqa: E402


def record(url, state, spec, title, feedback=()):
    return {"pull_request": url, "state": state, "spec": spec, "title": title,
            "method_name": "m", "maintainer_feedback": [{"author": "x", "body": body}
                                                        for body in feedback]}


class SameRuleResponsesTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.outcomes = Path(self.directory.name)
        files = {
            "hiddenramblings__tagmo.json": [record(
                "https://github.com/HiddenRamblings/TagMo/pull/765", "closed",
                "WebViewDebuggingSpec", "Fix onCreate", ["The flag is enabled intentionally"])],
            "mretallack__slimbook.json": [record(
                "https://github.com/mretallack/SlimBook/pull/3", "merged",
                "WebViewDebuggingSpec", "Enable WebView debugging only in debug builds",
                ["Thanks for the pull request"])],
            "o__quiet.json": [record("https://github.com/o/quiet/pull/1", "open",
                                     "WebViewDebuggingSpec", "Still waiting")],
            "o__other.json": [record("https://github.com/o/other/pull/2", "closed",
                                     "MessageDigestSpec", "Use SHA-256", ["checksum"])],
        }
        for name, records in files.items():
            (self.outcomes / name).write_text(json.dumps(records), encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def test_decided_proposals_for_the_same_rule_come_first_with_the_maintainers_words(self):
        found = pr_outcomes.responses_to_same_rule("WebViewDebuggingSpec", self.outcomes)
        self.assertEqual([(item["repository"], item["outcome"]) for item in found],
                         [("HiddenRamblings/TagMo", "closed"), ("mretallack/SlimBook", "merged")])
        self.assertEqual(found[0]["maintainer_said"], "The flag is enabled intentionally")
        self.assertEqual(found[1]["proposal"], "Enable WebView debugging only in debug builds")

    def test_another_rule_or_no_rule_gives_nothing(self):
        self.assertEqual(pr_outcomes.responses_to_same_rule("CipherSpec", self.outcomes), [])
        self.assertEqual(pr_outcomes.responses_to_same_rule("", self.outcomes), [])

    def test_they_reach_generation_even_without_learned_knowledge(self):
        with patch("cognalys.learning.knowledge.load_knowledge", return_value={}), \
                patch.object(pr_outcomes, "OUTCOMES_DIR", self.outcomes):
            context = fix_generation_common.learning_context(
                {"spec": "WebViewDebuggingSpec"}, "some.app_1.apk")
        self.assertEqual(len(context["maintainer_responses_to_this_rule_elsewhere"]), 2)


class BalancedResponsesTests(unittest.TestCase):
    """2026-10-31 audit: MessageDigestSpec gave four closures, one of them a
    repository policy (summit#54), and never the merged AMARadio#122."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.outcomes = Path(self.directory.name)
        files = {
            "idunnololz__summit.json": [record(
                "https://github.com/idunnololz/summit/pull/54", "closed", "MessageDigestSpec",
                "Use SHA-256", ["Sorry I am not currently accepting PR requests."])],
            "omaawr__tuisku.json": [record(
                "https://github.com/omaawr/tuisku/pull/11", "closed", "MessageDigestSpec",
                "Use SHA-256", ["ai generated or assisted code/pull requests aren't allowed"])],
            "a__one.json": [record("https://github.com/a/one/pull/1", "closed",
                                   "MessageDigestSpec", "Use SHA-256", ["checksum only"])],
            "a__two.json": [record("https://github.com/a/two/pull/2", "closed",
                                   "MessageDigestSpec", "Use SHA-256", ["MD5 is sufficient"])],
            "a__three.json": [record("https://github.com/a/three/pull/3", "closed",
                                     "MessageDigestSpec", "Use SHA-256", ["not needed"])],
            "a__four.json": [record("https://github.com/a/four/pull/4", "closed",
                                    "MessageDigestSpec", "Use SHA-256", ["no gain"])],
            "ounben__amaradio.json": [record(
                "https://github.com/ounben/AMARadio/pull/122", "merged", "MessageDigestSpec",
                "Use SHA-256", ["Thank you for your help"])],
            "vitorpamplona__amethyst.json": [
                record("https://github.com/vitorpamplona/amethyst/pull/4642", "closed",
                       "GCMParameterSpecSpec", "Use a random IV",
                       ["The provider already generates the IV."]),
                record("https://github.com/vitorpamplona/amethyst/pull/4700", "open",
                       "CipherSpec", "Fix encrypt", ["Looking at it"])],
        }
        for name, records in files.items():
            (self.outcomes / name).write_text(json.dumps(records), encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def test_a_merged_response_is_kept_and_policy_closures_left_out(self):
        found = pr_outcomes.responses_to_same_rule("MessageDigestSpec", self.outcomes)
        repositories = [item["repository"] for item in found]
        self.assertEqual(len(found), 4)
        self.assertIn("ounben/AMARadio", repositories)
        self.assertNotIn("idunnololz/summit", repositories)
        self.assertNotIn("omaawr/tuisku", repositories)
        self.assertEqual([item["outcome"] for item in found],
                         ["closed", "closed", "closed", "merged"])

    def test_the_policy_predicate_reads_only_closures_stating_a_policy(self):
        self.assertTrue(pr_outcomes.repository_policy_closure(record(
            "u", "closed", "S", "t", ["We are not accepting pull requests from outside."])))
        self.assertFalse(pr_outcomes.repository_policy_closure(record(
            "u", "closed", "S", "t", ["MD5 is used here as a checksum, not as a security control"])))
        self.assertFalse(pr_outcomes.repository_policy_closure(record(
            "u", "merged", "S", "t", ["not accepting PRs normally, but merged"])))

    def test_this_repositorys_responses_for_other_rules_reach_generation(self):
        found = pr_outcomes.responses_in_same_repository(
            "https://github.com/vitorpamplona/amethyst.git", "CipherSpec", self.outcomes)
        self.assertEqual([(item["rule"], item["outcome"]) for item in found],
                         [("GCMParameterSpecSpec", "closed")])
        self.assertEqual(pr_outcomes.responses_in_same_repository("", "CipherSpec",
                                                                  self.outcomes), [])
        with patch("cognalys.learning.knowledge.load_knowledge", return_value={}), \
                patch.object(pr_outcomes, "OUTCOMES_DIR", self.outcomes):
            context = fix_generation_common.learning_context(
                {"spec": "CipherSpec",
                 "repository_url": "https://github.com/vitorpamplona/amethyst"}, "amethyst")
        self.assertEqual(context["maintainer_responses_in_this_repository"][0]["maintainer_said"],
                         "The provider already generates the IV.")


class SameRepositorySameRuleTests(unittest.TestCase):
    """InterTune run_v2 (2026-11-08): InterTune#52, closed for this very
    method, reached adjudication as what "maintainers of other projects"
    answered."""

    INTERTUNE = "https://github.com/ItzSkyeYT/InterTune"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.outcomes = Path(self.directory.name)
        closed = record("https://github.com/ItzSkyeYT/InterTune/pull/52", "closed",
                        "MessageDigestSpec", "Migrate widget artwork hashes to SHA-256",
                        ["This hash only names the widget's cached cover files."])
        closed["csv_class"] = "com.dd3boh.outertune.widget.WidgetStore"
        closed["method_name"] = "hash"
        files = {
            "itzskyeyt__intertune.json": [closed, record(
                "https://github.com/ItzSkyeYT/InterTune/pull/60", "merged", "CipherSpec",
                "Use AES/GCM", ["Thanks"])],
            "javalc6__rssreader.json": [record(
                "https://github.com/javalc6/rssreader/pull/9", "closed", "MessageDigestSpec",
                "Write file checksums with SHA-256", ["MD5 is only a checksum here."])],
        }
        for name, records in files.items():
            (self.outcomes / name).write_text(json.dumps(records), encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def test_this_repositorys_answer_for_the_rule_is_apart_from_other_projects(self):
        own = pr_outcomes.responses_to_this_rule_in_same_repository(
            self.INTERTUNE + ".git", "MessageDigestSpec", self.outcomes)
        self.assertEqual([(item["repository"], item["outcome"]) for item in own],
                         [("ItzSkyeYT/InterTune", "closed")])
        self.assertEqual(own[0]["changed_code"], "com.dd3boh.outertune.widget.WidgetStore.hash")
        elsewhere = pr_outcomes.responses_to_same_rule(
            "MessageDigestSpec", self.outcomes, excluding_repository_url=self.INTERTUNE)
        self.assertEqual([item["repository"] for item in elsewhere], ["javalc6/rssreader"])
        # Without a repository nothing is left out and nothing is "own".
        self.assertEqual(len(pr_outcomes.responses_to_same_rule(
            "MessageDigestSpec", self.outcomes)), 2)
        self.assertEqual(pr_outcomes.responses_to_this_rule_in_same_repository(
            "", "MessageDigestSpec", self.outcomes), [])
        self.assertEqual(pr_outcomes.responses_to_this_rule_in_same_repository(
            self.INTERTUNE, "", self.outcomes), [])

    def test_learning_context_gives_the_three_sections_without_overlap(self):
        with patch("cognalys.learning.knowledge.load_knowledge", return_value={}), \
                patch.object(pr_outcomes, "OUTCOMES_DIR", self.outcomes):
            context = fix_generation_common.learning_context(
                {"spec": "MessageDigestSpec", "repository_url": self.INTERTUNE}, "intertune")
            elsewhere_only = fix_generation_common.learning_context(
                {"spec": "MessageDigestSpec",
                 "repository_url": "https://github.com/o/unrelated"}, "unrelated")
        self.assertEqual([item["repository"] for item in
                          context["maintainer_responses_to_this_rule_in_this_repository"]],
                         ["ItzSkyeYT/InterTune"])
        self.assertEqual([item["repository"] for item in
                          context["maintainer_responses_to_this_rule_elsewhere"]],
                         ["javalc6/rssreader"])
        self.assertEqual([item["rule"] for item in
                          context["maintainer_responses_in_this_repository"]], ["CipherSpec"])
        self.assertNotIn("maintainer_responses_to_this_rule_in_this_repository", elsewhere_only)
        self.assertEqual(len(elsewhere_only["maintainer_responses_to_this_rule_elsewhere"]), 2)

    def test_the_holdout_withholds_only_the_findings_own_repository(self):
        """B13: --holdout-repository reruns a published finding without its
        maintainers' verdict; other repositories' answers stay."""
        import os
        knowledge = {"repositories": {"intertune": {"verified_imports": {
            "Hex": {"import": "import a.Hex;", "run": "r1"}}}}}
        error = {"spec": "MessageDigestSpec", "repository_url": self.INTERTUNE}
        with patch("cognalys.learning.knowledge.load_knowledge", return_value=knowledge), \
                patch.object(pr_outcomes, "OUTCOMES_DIR", self.outcomes):
            with patch.dict(os.environ, {fix_generation_common.HOLDOUT_REPOSITORY_VARIABLE: ""}):
                normal = fix_generation_common.learning_context(error, "intertune")
            with patch.dict(os.environ, {fix_generation_common.HOLDOUT_REPOSITORY_VARIABLE: "1"}):
                held = fix_generation_common.learning_context(error, "intertune")
        self.assertIn("verified_repository_imports", normal)
        self.assertIn("maintainer_responses_to_this_rule_in_this_repository", normal)
        self.assertIn("maintainer_responses_in_this_repository", normal)
        for key in ("verified_repository_imports",
                    "maintainer_responses_to_this_rule_in_this_repository",
                    "maintainer_responses_in_this_repository"):
            self.assertNotIn(key, held)
        self.assertEqual(held["maintainer_responses_to_this_rule_elsewhere"],
                         normal["maintainer_responses_to_this_rule_elsewhere"])

    def test_the_behaviour_review_reads_it_as_this_repositorys_answer(self):
        from cognalys.llm.generate_error_fixes import FixGenerator

        prompts = []

        class Provider:
            def generate(self, prompt, *args, **kwargs):
                prompts.append(prompt)
                return json.dumps({"regressions": [], "maintainer_decision_required": False,
                                   "maintainer_decision": "", "rationale": ""})

        generator = object.__new__(FixGenerator)
        generator.provider = Provider()
        with patch("cognalys.learning.knowledge.load_knowledge", return_value={}), \
                patch.object(pr_outcomes, "OUTCOMES_DIR", self.outcomes):
            generator.review_patch_behavior(
                {"spec": "MessageDigestSpec", "repository_url": self.INTERTUNE}, [], {})
            generator.review_patch_behavior(
                {"spec": "MessageDigestSpec", "repository_url": "https://github.com/o/x"}, [], {})
        self.assertIn('"maintainer_responses_to_this_rule_in_this_repository"', prompts[0])
        self.assertIn("cached cover files", prompts[0])
        self.assertNotIn('"maintainer_responses_to_this_rule_in_this_repository"', prompts[1])


class WholeAnswerTests(unittest.TestCase):
    """session-android#2241 (2026-11-10): the answer reached every prompt cut at
    400 characters, before "We'll hold off merging for now since it doesn't
    change anything functionally". The user's decision: the answer goes whole."""

    SESSION = ("Thanks for the PR. We had a look and the cipher is created once per writer "
               "and reinitialised with a fresh IV for each entry, which is how the JCE "
               "expects it to be used; the analyzer flags the reinitialisation but there is "
               "no reuse of an IV or of a key stream here. The log files are also only kept "
               "on the device and rotated after a few days, so the format change would need "
               "a migration we would rather not maintain for this. We'll hold off merging "
               "for now since it doesn't change anything functionally, but feel free to "
               "reopen if you find a concrete issue with how the logs are encrypted.")

    def _said(self, *bodies):
        merged = record("https://github.com/session-foundation/session-android/pull/2241",
                        "open", "SSLContextSpec", "t", bodies)
        return pr_outcomes._maintainer_response(merged, "x")["maintainer_said"]

    def test_an_answer_within_the_limit_is_given_whole(self):
        self.assertGreater(len(self.SESSION), 400)
        said = self._said(self.SESSION)
        self.assertEqual(said, self.SESSION)
        self.assertIn("doesn't change anything functionally", said)

    def test_a_longer_answer_is_given_whole_too(self):
        # Feeder#1210 (2,197 characters across three comments) is not cut either.
        bodies = [self.SESSION, self.SESSION + " Second.", "Third comment."]
        said = self._said(*bodies)
        self.assertGreater(len(said), 1000)
        self.assertEqual(said, " | ".join(bodies))
        self.assertNotIn("[...]", said)

    def test_a_short_answer_is_unchanged(self):
        self.assertEqual(self._said("Thanks,   merged."), "Thanks, merged.")


class BotCommentTests(unittest.TestCase):
    """paroj/DSub2000#160 (2026-11-10): four Copilot review comments reached
    every other repository's SSLContextSpec finding as what the maintainer said.
    The user's decision: they are review points, kept for planning and
    generation as automated review comments, never the maintainer's position."""

    DSUB = "https://github.com/paroj/DSub2000/pull/160"

    def _record(self):
        merged = record(self.DSUB, "merged", "SSLContextSpec", "Fix <init>")
        merged["maintainer_feedback"] = [
            {"author": "Copilot", "kind": "inline_review",
             "body": "getAcceptedIssuers may return null here."},
            {"author": "Copilot", "kind": "inline_review",
             "body": "The wrapper stacks on every call."}]
        return merged

    def test_a_bot_comment_is_not_what_the_maintainer_said(self):
        response = pr_outcomes._maintainer_response(self._record(), "paroj__dsub2000")
        self.assertEqual(response["outcome"], "merged")
        self.assertEqual(response["maintainer_said"], "")
        comments = response[pr_outcomes.AUTOMATED_REVIEW_KEY]
        self.assertEqual([item["author"] for item in comments], ["Copilot", "Copilot"])
        self.assertTrue(all(item["author_is_bot"] for item in comments))
        self.assertIn("getAcceptedIssuers", comments[0]["comment"])
        # The adjudication and the behaviour review read the position only.
        [position] = pr_outcomes.as_maintainer_position([response])
        self.assertNotIn(pr_outcomes.AUTOMATED_REVIEW_KEY, position)
        self.assertEqual((position["outcome"], position["maintainer_said"]), ("merged", ""))
        # An open pull request on which only a bot spoke is no position at all.
        opened = {**self._record(), "state": "open"}
        self.assertEqual(pr_outcomes.as_maintainer_position(
            [pr_outcomes._maintainer_response(opened, "x")]), [])

    def test_a_policy_closure_is_read_from_the_maintainers_words_only(self):
        closed = record("u", "closed", "S", "t")
        closed["maintainer_feedback"] = [
            {"author": "coderabbitai[bot]", "body": "This repo is not accepting pull requests."},
            {"author": "owner", "body": "MD5 is only a checksum here."}]
        self.assertFalse(pr_outcomes.repository_policy_closure(closed))
        closed["maintainer_feedback"][1]["body"] = "We are not accepting pull requests."
        self.assertTrue(pr_outcomes.repository_policy_closure(closed))

    def test_the_adjudication_gets_the_position_and_planning_the_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            outcomes = Path(directory)
            (outcomes / "paroj__dsub2000.json").write_text(
                json.dumps([self._record()]), encoding="utf-8")
            with patch("cognalys.learning.knowledge.load_knowledge", return_value={}), \
                    patch.object(pr_outcomes, "OUTCOMES_DIR", outcomes):
                context = fix_generation_common.learning_context(
                    {"spec": "SSLContextSpec", "repository_url": "https://github.com/o/app"}, "app")
        [elsewhere] = context["maintainer_responses_to_this_rule_elsewhere"]
        self.assertIn(pr_outcomes.AUTOMATED_REVIEW_KEY, elsewhere)
        from cognalys.prs.pr_github import KNOWN_BOT_ACCOUNTS, is_bot_login
        self.assertTrue(is_bot_login("Copilot"))
        self.assertTrue(is_bot_login("dependabot[bot]"))
        self.assertFalse(is_bot_login("paroj"))
        # feedback_from_pr keeps recording Copilot's comments (reclassified, not dropped).
        self.assertNotIn("copilot", KNOWN_BOT_ACCOUNTS)


if __name__ == "__main__":
    unittest.main()
