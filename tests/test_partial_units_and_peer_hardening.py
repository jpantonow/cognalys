"""Prompt rules from the frozen run of the published pull requests (2026-11-13).

meshcore#10, prim-ftpd#453 and localsend#58 had each fixed one finding of a
joined unit in the original run and planned nothing in the rerun, because the
plan had to resolve "this violation and every joint finding in one change";
prim-ftpd's plan also obeyed a refusal over peers nobody showed exist; and
BitBanana#184's early replan was triggered by a downgrade scenario and by the
version marker its own plan asked for.
"""
import inspect
import unittest

import _paths  # noqa: E402,F401  (project import paths)

from test_noop_and_protocol_gates import prompt_text  # noqa: E402


class PartialUnitTests(unittest.TestCase):
    def setUp(self):
        from cognalys.llm import finding_adjudication

        self.module = finding_adjudication
        self.source = prompt_text(inspect.getsource(finding_adjudication))

    def test_the_plan_no_longer_requires_every_joint_finding(self):
        self.assertNotIn("must resolve this violation and every joint finding in one change",
                         self.source)
        self.assertIn("resolves, in one change, every finding of the unit that a change "
                      "resolves", self.source)
        self.assertIn("It never empties required_edits while another finding of the unit "
                      "has an edit", self.source)
        self.assertIn("say which and why in behavioral_invariants", self.source)

    def test_the_adjudication_keeps_a_fix_for_part_of_the_unit(self):
        self.assertIn("The unit has a fix when a change resolves at least one of its findings",
                      self.source)
        self.assertIn("does not by itself make the decision NO_SAFE_FIX while another "
                      "finding of the unit has a fix", self.source)

    def test_prompt_versions_record_the_change(self):
        self.assertGreaterEqual(self.module.PLAN_PROMPT_VERSION, 13)
        self.assertGreaterEqual(self.module.ADJUDICATION_PROMPT_VERSION, 9)


class PeerHardeningTests(unittest.TestCase):
    def test_the_adjudication_and_the_plan_both_read_the_rule(self):
        from cognalys.llm import finding_adjudication
        from cognalys.llm.fix_generation_common import PEER_HARDENING_PLAN_GUIDANCE

        source = inspect.getsource(finding_adjudication)
        self.assertGreaterEqual(source.count("+ PEER_HARDENING_PLAN_GUIDANCE"), 2)
        self.assertIn("never by itself a reason for NO_SAFE_FIX", PEER_HARDENING_PLAN_GUIDANCE)
        # The same five signs the behaviour review reads ("What the fix removes").
        for sign in ("depends_on_reported_behavior established", "deliberate_insecurity",
                     "an option or setting in the code", "other code handling the same peer",
                     "this repository's maintainers"):
            self.assertIn(sign, PEER_HARDENING_PLAN_GUIDANCE)
        self.assertIn("a peer you would have to assume is not evidence",
                      PEER_HARDENING_PLAN_GUIDANCE)


class ReviewReachabilityTests(unittest.TestCase):
    def setUp(self):
        from cognalys.llm import coordinated_generation

        self.module = coordinated_generation
        self.source = prompt_text(inspect.getsource(coordinated_generation))

    def test_a_downgrade_is_a_note(self):
        self.assertIn("Installing an older build of the app over the patched one (a "
                      "downgrade) is such an outside step", self.source)
        self.assertIn("is a note in rationale, never a regression", self.source)

    def test_the_new_form_the_plan_asks_for_is_the_change(self):
        self.assertIn("is the change itself, not a regression; a regression is existing "
                      "data, callers or settings the change breaks", self.source)
        self.assertGreaterEqual(self.module.REVIEW_CONTRACT_VERSION, 21)


if __name__ == "__main__":
    unittest.main()


class PredictableGeneratorTests(unittest.TestCase):
    """Bookwyrm#29 (frozen run, 2026-11-13): a GCM IV built from java.util.Random
    selections was read as "derived from a randomized source" and dismissed."""

    def test_the_adjudication_reads_the_rule(self):
        from cognalys.llm import finding_adjudication
        from cognalys.llm.finding_adjudication import PREDICTABLE_GENERATOR_GUIDANCE

        self.assertIn("+ PREDICTABLE_GENERATOR_GUIDANCE +", inspect.getsource(finding_adjudication))
        for generator in ("java.util.Random", "kotlin.random.Random", "Math.random"):
            self.assertIn(generator, PREDICTABLE_GENERATOR_GUIDANCE)
        self.assertIn("detector_violation is confirmed", PREDICTABLE_GENERATOR_GUIDANCE)
        self.assertIn("never a reason for not_confirmed", PREDICTABLE_GENERATOR_GUIDANCE)
        self.assertGreaterEqual(finding_adjudication.ADJUDICATION_PROMPT_VERSION, 10)


class CheckerViewGuidanceTests(unittest.TestCase):
    """Frozen run (2026-11-13): TOTP's adjudication prescribed "a compatible
    SecretKey representation", Herald's plan an app-written KeyManagerFactory
    provider around the same MtlsKeyManager; both drafts reached PR pronto."""

    def test_the_adjudication_and_the_plan_read_the_rule(self):
        from cognalys.llm import finding_adjudication
        from cognalys.llm.fix_generation_common import CHECKER_VIEW_GUIDANCE

        self.assertEqual(inspect.getsource(finding_adjudication).count(
            "+ CHECKER_VIEW_GUIDANCE"), 2)
        self.assertTrue(CHECKER_VIEW_GUIDANCE.startswith(
            "A fix never takes the governed call out of the checker's view"))
        for shape in ("a factory, provider or service provider interface",
                      "a key class the app implements",
                      "the rule is evaded, not satisfied"):
            self.assertIn(shape, CHECKER_VIEW_GUIDANCE)
        self.assertGreaterEqual(finding_adjudication.ADJUDICATION_PROMPT_VERSION, 11)
        self.assertGreaterEqual(finding_adjudication.PLAN_PROMPT_VERSION, 14)
