"""Web research can run at its own reasoning effort without touching the other stages."""
import os
import unittest
from types import SimpleNamespace
from unittest import mock

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.llm_providers import (  # noqa: E402
    RESEARCH_EFFORT_VARIABLE, research_reasoning_effort,
)


class ResearchEffortTests(unittest.TestCase):
    def test_the_effort_applies_inside_the_block_and_is_restored(self):
        provider = SimpleNamespace(provider_name="openai", reasoning_effort="high")
        with mock.patch.dict(os.environ, {RESEARCH_EFFORT_VARIABLE: "medium"}):
            with research_reasoning_effort(provider):
                self.assertEqual(provider.reasoning_effort, "medium")
        self.assertEqual(provider.reasoning_effort, "high")

    def test_without_the_variable_nothing_changes(self):
        provider = SimpleNamespace(provider_name="openai", reasoning_effort="high")
        with mock.patch.dict(os.environ, {}, clear=True):
            with research_reasoning_effort(provider):
                self.assertEqual(provider.reasoning_effort, "high")

    def test_anthropic_efforts_are_mapped(self):
        provider = SimpleNamespace(provider_name="anthropic", reasoning_effort="high")
        with research_reasoning_effort(provider, "minimal"):
            self.assertEqual(provider.reasoning_effort, "low")
        self.assertEqual(provider.reasoning_effort, "high")

    def test_the_effort_is_restored_after_an_error(self):
        provider = SimpleNamespace(provider_name="openai", reasoning_effort="high")
        with self.assertRaises(RuntimeError):
            with research_reasoning_effort(provider, "low"):
                raise RuntimeError("provider failed")
        self.assertEqual(provider.reasoning_effort, "high")


if __name__ == "__main__":
    unittest.main()
