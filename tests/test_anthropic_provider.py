"""The Anthropic provider keeps OpenAIProvider's contract.

No test reaches the API: the SDK client is replaced by one that records
each request and answers with prepared messages, shaped as the SDK's.
"""
import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm import llm_providers  # noqa: E402

try:
    import anthropic  # noqa: F401  (only whether it imports)
    HAVE_SDK = True
except ModuleNotFoundError:
    HAVE_SDK = False


def _message(text="{}", stop_reason="end_turn", citations=(), model="claude-opus-5-5",
             input_tokens=10, cached=0, written=0, output_tokens=5, stop_details=None,
             web_searches=None):
    block = SimpleNamespace(type="text", text=text, citations=[
        SimpleNamespace(url=url) for url in citations])
    thinking = SimpleNamespace(type="thinking", thinking="")
    usage = SimpleNamespace(input_tokens=input_tokens, cache_read_input_tokens=cached,
                            cache_creation_input_tokens=written, output_tokens=output_tokens)
    if web_searches is not None:
        # As the SDK gives it: the server tools a turn used.
        usage.server_tool_use = SimpleNamespace(web_search_requests=web_searches,
                                                web_fetch_requests=0)
    message = SimpleNamespace(content=[thinking, block], stop_reason=stop_reason, model=model,
                              usage=usage, id="msg_1", _request_id="req_1",
                              stop_details=stop_details)
    message.to_dict = lambda: {"id": "msg_1", "stop_reason": stop_reason}
    return message


class _Stream:
    def __init__(self, message):
        self.message = message

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def get_final_message(self):
        return self.message


class _FakeClient:
    def __init__(self, messages):
        self.messages = list(messages)
        self.requests = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self._stream))

    def with_options(self, **_):
        return self

    def _stream(self, **params):
        self.requests.append(params)
        return _Stream(self.messages.pop(0))


@unittest.skipUnless(HAVE_SDK, "anthropic SDK not installed")
class AnthropicProviderTests(unittest.TestCase):
    def provider(self, directory, messages, **kwargs):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            provider = llm_providers.AnthropicProvider(
                cache_dir=Path(directory) / "cache",
                prompt_log_dir=Path(directory) / "logs", **kwargs)
        provider.client = _FakeClient(messages)
        return provider

    def test_a_json_schema_request_and_its_accounting(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = self.provider(directory, [_message('{"a": 1}', cached=90, written=4)])
            schema = {"type": "object", "properties": {
                "a": {"type": "integer", "minimum": 0},
                "items": {"type": "array", "maxItems": 3, "minItems": 2,
                          "items": {"type": "string", "maxLength": 9}}},
                "required": ["a"]}
            text = provider.generate("prompt", "system", json_mode=True,
                                     json_schema=schema, trace_stage="adjudication")
            self.assertEqual(text, '{"a": 1}')
            request = provider.client.requests[0]
            self.assertEqual(request["model"], "claude-opus-5-5")
            self.assertEqual(request["thinking"], {"type": "adaptive"})
            self.assertEqual(request["output_config"]["effort"], "high")
            sent = request["output_config"]["format"]["schema"]
            self.assertFalse(sent["additionalProperties"])
            self.assertNotIn("minimum", sent["properties"]["a"])
            self.assertNotIn("maxItems", sent["properties"]["items"])
            self.assertNotIn("minItems", sent["properties"]["items"])
            self.assertNotIn("maxLength", sent["properties"]["items"]["items"])
            self.assertEqual(request["system"][0]["cache_control"], {"type": "ephemeral"})
            self.assertEqual(request["fallbacks"], "default")
            # Input is counted with the cache reads and writes, as OpenAI's is.
            self.assertEqual(provider.get_token_usage(), {"input": 104, "output": 5})
            metadata = json.loads(next((Path(directory) / "logs").glob(
                "*_metadata.json")).read_text(encoding="utf-8"))
            self.assertEqual(metadata["delivery"], "sent_to_anthropic")
            self.assertEqual(metadata["cached_input_tokens"], 90)

    def test_the_model_the_response_names_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = self.provider(directory, [_message("done", model="claude-test-20261101")])
            provider.generate("prompt", "system", trace_stage="adjudication")
            metadata = json.loads(next((Path(directory) / "logs").glob(
                "*_metadata.json")).read_text(encoding="utf-8"))
        self.assertEqual(metadata["model"], "claude-opus-5-5")
        self.assertEqual(metadata["response_model"], "claude-test-20261101")

    def test_a_repeated_request_is_answered_from_the_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = self.provider(directory, [_message("first")])
            self.assertEqual(provider.generate("p", "s"), "first")
            self.assertEqual(provider.generate("p", "s"), "first")
            self.assertEqual(len(provider.client.requests), 1)

    def test_without_a_cache_a_finding_replays_its_identical_call_but_not_a_truncated_one(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
                provider = llm_providers.AnthropicProvider(
                    cache_dir=None, prompt_log_dir=Path(directory) / "logs")
            provider.client = _FakeClient([
                _message("cut", stop_reason="max_tokens"), _message("whole")])
            with llm_providers.finding_replay_scope():
                self.assertEqual(provider.generate("p", "s"), "cut")
                self.assertEqual(provider.generate("p", "s"), "whole")
                self.assertEqual(provider.generate("p", "s"), "whole")
            self.assertEqual(len(provider.client.requests), 2)
            deliveries = sorted(
                json.loads(path.read_text(encoding="utf-8"))["delivery"]
                for path in (Path(directory) / "logs").glob("*_metadata.json"))
            self.assertEqual(deliveries, ["finding_replay", "sent_to_anthropic",
                                          "sent_to_anthropic"])

    def test_a_refusal_is_a_content_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            details = SimpleNamespace(category="cyber", explanation="declined")
            provider = self.provider(directory, [_message(
                "", stop_reason="refusal", stop_details=details)])
            with self.assertRaises(llm_providers.ProviderContentRefusal) as raised:
                provider.generate("p", "s")
            self.assertEqual(raised.exception.code, "cyber")

    def test_a_paused_research_turn_is_resumed_and_its_sources_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = self.provider(directory, [
                _message("Part one. ", stop_reason="pause_turn",
                         citations=["https://a.example/doc"]),
                _message("Part two.", citations=["https://b.example/doc"]),
            ])
            text = provider.generate("research", "s", web_search=True)
            self.assertTrue(text.startswith("Part one. Part two."))
            self.assertIn("- https://a.example/doc", text)
            self.assertIn("- https://b.example/doc", text)
            resumed = provider.client.requests[1]["messages"]
            self.assertEqual(resumed[1]["role"], "assistant")
            self.assertEqual(provider.client.requests[0]["tools"][0]["type"],
                             "web_search_20260209")

    def test_web_searches_are_recorded_and_charged_to_the_cost_guard(self):
        # frozen_runs_20261113 D arm (co_0a32f516feb2/r1 call 0001): the
        # message reported 16 web_search_requests, and neither the trace nor
        # the --max-cost guard counted their fee. A paused turn's searches
        # add up over its resumption.
        class _Guard:
            def __init__(self):
                self.added = []

            def check(self):
                pass

            def add(self, *tokens, cache_write_tokens=0, service_tier="", web_search_calls=0):
                self.added.append((tokens, web_search_calls))

        with tempfile.TemporaryDirectory() as directory:
            provider = self.provider(directory, [
                _message("Part one. ", stop_reason="pause_turn", web_searches=16),
                _message("Part two.", web_searches=3),
            ])
            provider._cost_guard = _Guard()
            provider.generate("research", "s", web_search=True)
            metadata = json.loads(next((Path(directory) / "logs").glob(
                "*_metadata.json")).read_text(encoding="utf-8"))
            self.assertEqual(metadata["web_search_calls"], 19)
            self.assertEqual(metadata["web_search_actions"], {"search": 19})
            self.assertEqual(provider._cost_guard.added, [((20, 0, 10), 19)])
            # A call that used no server tool records none.
            provider = self.provider(Path(directory) / "plain", [_message("{}")])
            provider._cost_guard = _Guard()
            provider.generate("p", "s")
            metadata = json.loads(next((Path(directory) / "plain" / "logs").glob(
                "*_metadata.json")).read_text(encoding="utf-8"))
            self.assertEqual(metadata["web_search_calls"], 0)
            self.assertEqual(provider._cost_guard.added, [((10, 0, 5), 0)])

    def test_a_response_holding_a_datetime_is_still_traced(self):
        with tempfile.TemporaryDirectory() as directory:
            message = _message("brief")
            message.to_dict = lambda: {"id": "msg_1", "retrieved_at": datetime(2026, 10, 19)}
            provider = self.provider(directory, [message])
            self.assertEqual(provider.generate("q", "s", web_search=True).split("\n")[0], "brief")
            response = next((Path(directory) / "logs").glob("*_response.json"), None)
            if response is not None:
                self.assertIn("2026-10-19", response.read_text(encoding="utf-8"))

    def test_json_with_web_search_researches_then_synthesizes(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = self.provider(directory, [_message("brief"), _message('{"ok": true}')])
            text = provider.generate("q", "s", json_mode=True, web_search=True,
                                     json_schema={"type": "object", "properties": {}})
            self.assertEqual(text, '{"ok": true}')
            first, second = provider.client.requests
            self.assertIn("tools", first)
            self.assertNotIn("tools", second)
            self.assertIn("WEB RESEARCH RESULT:\nbrief", second["messages"][0]["content"])

    def test_the_corpus_scope_reaches_the_shared_two_pass_branch(self):
        from cognalys.llm.research_corpus import ResearchCorpus

        answer = json.dumps({"sources": [{"url": "https://a.example/doc"}]})
        with tempfile.TemporaryDirectory() as directory:
            provider = self.provider(directory, [_message("brief"), _message(answer)])
            provider.research_corpus = ResearchCorpus(Path(directory) / "corpus")
            schema = {"type": "object", "properties": {}}
            for _ in range(2):
                self.assertEqual(provider.generate(
                    "q", "s", json_mode=True, web_search=True, json_schema=schema,
                    trace_stage="external_research",
                    research_corpus_scope={"kind": "governed_api_and_rule"}), answer)
            self.assertEqual(len(provider.client.requests), 2)
            (entry,) = (Path(directory) / "corpus").glob("*.json")
            stored = json.loads(entry.read_text(encoding="utf-8"))
            self.assertEqual(stored["request"]["provider"], "anthropic")
            self.assertEqual(stored["request"]["web_search_tool"],
                             llm_providers.AnthropicProvider.WEB_SEARCH_TOOL)
            research = json.loads(next((Path(directory) / "logs").glob(
                "*external_research.research_request.json")).read_text(encoding="utf-8"))
            self.assertEqual(research["web_search_tool"],
                             llm_providers.AnthropicProvider.WEB_SEARCH_TOOL)
            deliveries = sorted(json.loads(path.read_text(encoding="utf-8"))["delivery"]
                                for path in (Path(directory) / "logs").glob("*_metadata.json"))
            self.assertEqual(deliveries, ["research_corpus", "sent_to_anthropic",
                                          "sent_to_anthropic"])

    def test_an_openai_endpoint_and_effort_are_translated(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = self.provider(directory, [], endpoint="https://api.openai.com/v1",
                                     reasoning_effort="minimal")
            self.assertEqual(provider.endpoint, "https://api.anthropic.com")
            self.assertEqual(provider.reasoning_effort, "low")

    def test_a_missing_key_says_which_file_holds_it(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}):
            with self.assertRaisesRegex(RuntimeError, ".env.anthropic"):
                llm_providers.AnthropicProvider()


class RemoteProviderTests(unittest.TestCase):
    def test_the_pipeline_variable_wins_then_the_model_name(self):
        with patch.dict(os.environ, {llm_providers.PROVIDER_VARIABLE: "anthropic"}):
            self.assertEqual(llm_providers.remote_provider_name("gpt-5.6-terra"), "anthropic")
        with patch.dict(os.environ, {llm_providers.PROVIDER_VARIABLE: ""}):
            self.assertEqual(llm_providers.remote_provider_name("claude-opus-5-5"), "anthropic")
            self.assertEqual(llm_providers.remote_provider_name("gpt-5.6-terra"), "openai")

    def test_the_callers_openai_class_is_used(self):
        created = []

        class FakeOpenAI:
            def __init__(self, **kwargs):
                created.append(kwargs)

        with patch.dict(os.environ, {llm_providers.PROVIDER_VARIABLE: "openai"}):
            provider = llm_providers.remote_provider(openai_class=FakeOpenAI, model="gpt-x")
        self.assertIsInstance(provider, FakeOpenAI)
        self.assertEqual(created, [{"model": "gpt-x"}])


if __name__ == "__main__":
    unittest.main()
