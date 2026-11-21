import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.issues.issue_creator import IssueCreator  # noqa: E402
from cognalys.utils.finding_source import (  # noqa: E402
    is_analyzer_tool,
    is_dynamic_analysis_tool,
    is_runtime_monitor_tool,
)


class FindingSourceTests(unittest.TestCase):
    def test_ape_is_a_dynamic_analyzer(self):
        self.assertTrue(is_analyzer_tool("ape"))
        self.assertTrue(is_dynamic_analysis_tool("ape"))

    def test_a_manual_candidate_is_neither_an_analyzer_nor_a_dynamic_run(self):
        for tool in ("static:manual", "manual", "web_research", "", "unknown"):
            with self.subTest(tool=tool):
                self.assertFalse(is_analyzer_tool(tool))
                self.assertFalse(is_dynamic_analysis_tool(tool))

    def test_a_static_analyzer_is_named_but_not_called_dynamic(self):
        self.assertTrue(is_analyzer_tool("static:semgrep"))
        self.assertFalse(is_dynamic_analysis_tool("static:semgrep"))

    def test_only_a_runtime_monitor_or_its_explorer_is_a_runtime_monitor(self):
        for tool in ("rvsec", "RVSec", "javamop", "ape", "monkey:fast", " ape:sata "):
            with self.subTest(tool=tool):
                self.assertTrue(is_runtime_monitor_tool(tool))
        # Labels in findings under outputs/ (2026-10-30) that
        # is_dynamic_analysis_tool accepts but no monitor produced.
        for tool in ("manual_static_review", "external_advisory", "lint", "codeql",
                     "crash_analyzer", "static:semgrep", "static:manual", "", "unknown"):
            with self.subTest(tool=tool):
                self.assertFalse(is_runtime_monitor_tool(tool))


class IssueWordingTests(unittest.TestCase):
    def issue(self, tool: str, style: str = "v1") -> str:
        return IssueCreator.build_issue_body(
            "Hi!", "src/A.kt", spec="S", method_name="m", tool=tool,
            error_message="Static candidate (not executed): x.", style=style,
        )

    def test_a_manual_candidate_is_not_reported_by_an_analysis(self):
        for style in ("v1", "v2", "v3"):
            body = self.issue("static:manual", style)
            self.assertNotIn("analysis reported", body)
            self.assertNotIn("static:manual", body)
            self.assertIn(
                "While reading the code, I noticed `m`" if style == "v3"
                else "The reported finding:", body)

    def test_a_dynamic_analyzer_is_reported_as_such(self):
        body = self.issue("ape")
        self.assertIn("The dynamic analysis reported:", body)
        self.assertIn("**Analysis tool:** `RVSec`", body)

    def test_an_rvsec_finding_says_how_it_was_found(self):
        """session-android#2241 and the PRs after it named only the rule: the
        tool column read "ape:sata", the UI explorer, not RVSec."""
        from cognalys.utils.finding_source import analyzer_name, tool_and_spec_context

        # FreeOTP#524: an ARES-driven finding went out without RVSec's name.
        for tool in ("rvsec", "ape:sata", "monkey:fast", "ares", "droidbot:bfs_greedy"):
            text = tool_and_spec_context(tool, "MessageDigestSpec")
            self.assertIn("running the app under RVSec", text)
            # network-survey #154: "It only satisfies the CrySL rule"; the
            # rule id and "usage rules written in CrySL" are gone (2026-10-31).
            self.assertNotIn("MessageDigestSpec", text)
            self.assertNotIn("CrySL", text)
            self.assertNotIn("pipeline", text.lower())
            self.assertNotIn("automat", text.lower())
            self.assertEqual(analyzer_name(tool), "RVSec")
        self.assertEqual(tool_and_spec_context("static:semgrep", "CipherSpec"), "")
        self.assertEqual(analyzer_name("static:semgrep"), "static:semgrep")

if __name__ == "__main__":
    unittest.main()
