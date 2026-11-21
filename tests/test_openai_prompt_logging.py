import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (scripts/ and src/ on sys.path)
from cognalys.llm import llm_providers  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "cognalys" / "llm" / "generate_error_fixes.py"
SPEC = importlib.util.spec_from_file_location("prompt_logging_generator", MODULE_PATH)
generator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = generator
SPEC.loader.exec_module(generator)


class OpenAIPromptLoggingTests(unittest.TestCase):
    def test_writes_prompt_without_credentials_or_response(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"OPENAI_API_KEY": "not-in-log"}):
                provider = generator.OpenAIProvider(
                    prompt_log_dir=Path(directory), cache_dir=None
                )
            provider._log_prompt(
                "user input", "system instructions", True, False,
                {"type": "object"}, "test_schema", "sent_to_openai",
            )
            records = list(Path(directory).glob("*_request.json"))
            self.assertEqual(len(records), 1)
            record = json.loads(records[0].read_text(encoding="utf-8"))
            self.assertEqual(record["input"], "user input")
            self.assertEqual(record["instructions"], "system instructions")
            self.assertEqual(record["delivery"], "sent_to_openai")
            self.assertNotIn("not-in-log", records[0].read_text(encoding="utf-8"))

    def test_generate_writes_paired_response_and_token_metadata(self):
        class Response:
            status_code = 200
            text = ""
            headers = {"x-request-id": "req-test"}

            @staticmethod
            def json():
                return {
                    "id": "resp-test", "output_text": "done",
                    "usage": {
                        "input_tokens": 12, "output_tokens": 3,
                        "input_tokens_details": {"cached_tokens": 5},
                    },
                }

        class Session:
            @staticmethod
            def post(*_args, **_kwargs):
                return Response()

        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"OPENAI_API_KEY": "not-in-log"}):
                provider = generator.OpenAIProvider(
                    prompt_log_dir=Path(directory), cache_dir=None
                )
            provider.session = Session()
            self.assertEqual(provider.generate(
                "input", "system", trace_stage="unit.stage",
                trace_context={"finding_id": "finding-1"},
            ), "done")
            requests = list(Path(directory).glob("*_request.json"))
            responses = list(Path(directory).glob("*_response.json"))
            metadata = list(Path(directory).glob("*_metadata.json"))
            self.assertEqual((len(requests), len(responses), len(metadata)), (1, 1, 1))
            meta = json.loads(metadata[0].read_text(encoding="utf-8"))
            self.assertEqual(meta["status"], "success")
            self.assertEqual(meta["input_tokens"], 12)
            self.assertEqual(meta["cached_input_tokens"], 5)
            # The response reports no cache writes.
            self.assertEqual(meta["cache_write_input_tokens"], 0)
            self.assertEqual(meta["request_id"], "req-test")

    def test_the_snapshot_that_answered_is_recorded_beside_the_model_asked_for(self):
        class Response:
            status_code = 200
            text = ""
            headers = {"x-request-id": "req-test"}

            @staticmethod
            def json():
                # A Responses API answer names the dated snapshot it ran on.
                return {
                    "id": "resp-test", "object": "response", "status": "completed",
                    "model": "gpt-test-2026-10-01", "output_text": "done",
                    "usage": {"input_tokens": 12, "output_tokens": 3},
                }

        class Session:
            @staticmethod
            def post(*_args, **_kwargs):
                return Response()

        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"OPENAI_API_KEY": "not-in-log"}):
                provider = generator.OpenAIProvider(
                    model="gpt-test", prompt_log_dir=Path(directory), cache_dir=None
                )
            provider.session = Session()
            provider.generate("input", "system", trace_stage="adjudication",
                              trace_context={"prompt_version": "p1",
                                             "context_builder_version": "c2",
                                             "semantic_resolver_version": "r3"})
            meta = json.loads(next(Path(directory).glob("*_metadata.json")).read_text(
                encoding="utf-8"))
        self.assertEqual(meta["model"], "gpt-test")
        self.assertEqual(meta["response_model"], "gpt-test-2026-10-01")
        self.assertEqual((meta["prompt_version"], meta["context_builder_version"],
                          meta["semantic_resolver_version"]), ("p1", "c2", "r3"))

    def test_cache_writes_are_recorded_and_charged_to_the_ceiling(self):
        from cognalys.llm import cost

        class Response:
            status_code = 200
            text = ""
            headers = {"x-request-id": "req-test"}

            @staticmethod
            def json():
                # The usage shape of a Responses API answer that wrote to the
                # prompt cache.
                return {
                    "id": "resp-test", "status": "completed", "output_text": "done",
                    "usage": {
                        "input_tokens": 1_000_000, "output_tokens": 0,
                        "input_tokens_details": {"cached_tokens": 0,
                                                 "cache_write_tokens": 400_000},
                        "output_tokens_details": {"reasoning_tokens": 0},
                        "total_tokens": 1_000_000,
                    },
                }

        class Session:
            @staticmethod
            def post(*_args, **_kwargs):
                return Response()

        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"OPENAI_API_KEY": "not-in-log"}):
                provider = generator.OpenAIProvider(
                    prompt_log_dir=Path(directory), cache_dir=None
                )
            provider.session = Session()
            provider._cost_guard = cost.RunCostGuard(
                10.0, "gpt-test", 0.0,
                {"gpt-test": {"input": 2.0, "cached_input": 0.5, "output": 10.0,
                              "cache_write_input": 2.5}})
            provider.generate("input", "system", trace_stage="unit.stage")
            meta = json.loads(next(Path(directory).glob("*_metadata.json")).read_text(
                encoding="utf-8"))
            self.assertEqual(meta["cache_write_input_tokens"], 400_000)
            # 600k plain * 2 + 400k written * 2.5
            self.assertAlmostEqual(provider._cost_guard.spent, 2.2)

    def test_the_served_tier_and_web_search_calls_are_recorded_and_charged(self):
        from cognalys.llm import cost

        class Response:
            status_code = 200
            text = ""
            headers = {}

            @staticmethod
            def json():
                # A research answer's output items, as the API records them.
                return {
                    "id": "resp-test", "status": "completed", "service_tier": "default",
                    "output": [
                        {"type": "web_search_call", "status": "completed",
                         "action": {"type": "search", "query": "a"}},
                        {"type": "web_search_call", "status": "completed",
                         "action": {"type": "open_page", "url": "https://x"}},
                        {"type": "web_search_call", "status": "completed",
                         "action": {"type": "search", "query": "b"}},
                        {"type": "web_search_call", "status": "completed",
                         "action": {"type": "find_in_page", "pattern": "c"}},
                        {"type": "message", "content": [
                            {"type": "output_text", "text": "brief"}]},
                    ],
                    "usage": {"input_tokens": 1_000_000, "output_tokens": 0},
                }

        class Session:
            @staticmethod
            def post(*_args, **_kwargs):
                return Response()

        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
                provider = generator.OpenAIProvider(
                    prompt_log_dir=Path(directory), cache_dir=None,
                    web_search_cache_ttl_seconds=0)
            provider.web_search_session = Session()
            provider._cost_guard = cost.RunCostGuard(
                10.0, "gpt-test", 0.0,
                {"gpt-test": {"input": 2.0, "cached_input": 0.5, "output": 10.0,
                              "web_search_per_1k_calls": 10.0}})
            self.assertEqual(provider.generate("q", "s", web_search=True), "brief")
            meta = json.loads(next(Path(directory).glob("*_metadata.json")).read_text(
                encoding="utf-8"))
        self.assertEqual(meta["service_tier"], "default")
        self.assertEqual(meta["web_search_actions"],
                         {"search": 2, "open_page": 1, "find_in_page": 1})
        self.assertEqual(meta["web_search_calls"], 2)
        # 1M input * 2 + 2 searches * US$ 0.01
        self.assertAlmostEqual(provider._cost_guard.spent, 2.02)


class PromptCacheBreakpointTests(unittest.TestCase):
    """Long prompts go in parts cut at fixed offsets, with cache breakpoints.

    The paid probe of 2026-11-09 showed OpenAI finds a cached prefix only at
    a boundary an earlier request also wrote, so every call is cut at the
    same multiples of the stride; a cut on a space before a letter left
    input_tokens unchanged, and prompt_cache_key partitioned the cache.
    """

    STRIDE = llm_providers.PROMPT_CACHE_BREAKPOINT_STRIDE_CHARS

    def setUp(self):
        # The switch a developer may have exported must not leak in.
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop(llm_providers.PROMPT_CACHE_BREAKPOINTS_VARIABLE, None)

    class _Response:
        def __init__(self, payload=None, status_code=200):
            self.status_code = status_code
            self._payload = payload if payload is not None else {
                "id": "resp-test", "status": "completed", "output_text": "done",
                "usage": {"input_tokens": 12, "output_tokens": 3},
            }
            self.text = json.dumps(self._payload)
            self.headers = {}

        def json(self):
            return self._payload

    class _Session:
        def __init__(self, answers=()):
            self.answers = list(answers)
            self.bodies = []

        def post(self, _url, **kwargs):
            self.bodies.append(json.loads(json.dumps(kwargs["json"])))
            if self.answers:
                return self.answers.pop(0)
            return PromptCacheBreakpointTests._Response()

    @staticmethod
    def _prompt(characters, seed="evidence"):
        """Text of exactly ``characters`` with words, commas and brackets."""
        words, size, index = [], 0, 0
        while size <= characters:
            word = f"{seed}{index % 97}, {{k: [v]}} line{index}"
            words.append(word)
            size += len(word) + 1
            index += 1
        return " ".join(words)[:characters]

    def _provider(self, directory, session):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
            provider = generator.OpenAIProvider(
                prompt_log_dir=Path(directory), cache_dir=None)
        provider.session = session
        provider.web_search_session = session
        return provider

    @staticmethod
    def _records(directory, suffix):
        return [json.loads(path.read_text(encoding="utf-8"))
                for path in sorted(Path(directory).glob(f"*_{suffix}.json"))]

    def test_parts_join_to_the_prompt_and_each_cut_precedes_a_space_before_a_letter(self):
        prompt = self._prompt(self.STRIDE * 4 + 1234)
        request_input, cuts, _ = llm_providers.prompt_cache_input(prompt)
        parts = request_input[0]["content"]

        self.assertEqual(request_input[0]["role"], "user")
        self.assertEqual("".join(part["text"] for part in parts), prompt)
        self.assertEqual(len(cuts), 4)
        for index, cut in enumerate(cuts, start=1):
            self.assertTrue(self.STRIDE * (index - 1) < cut <= self.STRIDE * index)
            self.assertEqual(prompt[cut], " ")
            self.assertFalse(prompt[cut - 1].isspace())
            self.assertTrue(prompt[cut + 1].isascii() and prompt[cut + 1].isalpha())
        # The space opens the next part.
        self.assertTrue(all(part["text"].startswith(" ") for part in parts[1:]))

    def test_breakpoints_go_on_the_parts_ending_at_the_last_three_cuts_only(self):
        prompt = self._prompt(self.STRIDE * 5 + 10)
        request_input, cuts, breakpoints = llm_providers.prompt_cache_input(prompt)
        parts = request_input[0]["content"]

        self.assertEqual(len(parts), 6)
        self.assertEqual(breakpoints, cuts[-3:])
        marked = [index for index, part in enumerate(parts)
                  if "prompt_cache_breakpoint" in part]
        self.assertEqual(marked, [2, 3, 4])
        self.assertEqual(parts[2]["prompt_cache_breakpoint"], {"mode": "explicit"})
        self.assertNotIn("prompt_cache_breakpoint", parts[-1])

    def test_an_offset_without_a_qualifying_space_gets_no_cut(self):
        # The second window holds no space before a letter; no cut is moved
        # into another window for it.
        prompt = (self._prompt(self.STRIDE) + "," * self.STRIDE
                  + self._prompt(self.STRIDE + 100))
        cuts = llm_providers.prompt_cache_cuts(prompt)

        self.assertEqual(len(cuts), 2)
        self.assertTrue(cuts[0] <= self.STRIDE)
        self.assertTrue(self.STRIDE * 2 < cuts[1] <= self.STRIDE * 3)

    def test_prompts_sharing_a_long_prefix_get_the_same_cuts_inside_it(self):
        shared = self._prompt(self.STRIDE * 3 + 500)
        first = shared + " first tail " + self._prompt(self.STRIDE, "alpha")
        second = shared + " second tail, longer " + self._prompt(self.STRIDE * 2, "beta")
        cuts_first = llm_providers.prompt_cache_cuts(first)
        cuts_second = llm_providers.prompt_cache_cuts(second)

        inside = [cut for cut in cuts_first if cut + 2 <= len(shared)]
        self.assertEqual(len(inside), 3)
        self.assertEqual(cuts_second[:3], inside)

    def test_a_long_prompt_is_sent_in_parts_and_logged_with_its_cuts(self):
        prompt = self._prompt(self.STRIDE * 2 + 700)
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session()
            provider = self._provider(directory, session)
            self.assertEqual(provider.generate(prompt, "system", json_mode=True,
                                               json_schema={"type": "object"}), "done")
            request = self._records(directory, "request")[0]
            meta = self._records(directory, "metadata")[0]

        body = session.bodies[0]
        parts = body["input"][0]["content"]
        self.assertEqual("".join(part["text"] for part in parts), prompt)
        self.assertEqual(body["instructions"], "system")
        self.assertNotIn("prompt_cache_key", body)
        self.assertNotIn("prompt_cache_options", body)
        # The log keeps the joined prompt and its hash, as before.
        self.assertEqual(request["input"], prompt)
        self.assertEqual(request["input_sha256"], hashlib.sha256(
            ("system\0" + prompt).encode("utf-8")).hexdigest())
        cuts = llm_providers.prompt_cache_cuts(prompt)
        self.assertEqual(len(cuts), 2)
        self.assertEqual(request["input_parts"], cuts)
        self.assertEqual(request["breakpoints"], cuts)
        self.assertEqual(meta["input_parts"], cuts)

    def test_a_prompt_below_the_stride_keeps_the_plain_string_request(self):
        prompt = self._prompt(self.STRIDE)
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session()
            provider = self._provider(directory, session)
            provider.generate(prompt, "system")
            request = self._records(directory, "request")[0]

        self.assertEqual(session.bodies[0]["input"], prompt)
        self.assertEqual((request["input_parts"], request["breakpoints"]), ([], []))
        self.assertNotIn("prompt_cache_breakpoints_off", request)

    def test_a_caller_boundary_keeps_the_earlier_request_cut_as_it_was(self):
        # Round 2 of an extraction appends to round 1: the part before the
        # boundary is cut as round 1 was, the boundary is a cut and takes a
        # breakpoint first, and the appendix is cut from its own start.
        first = self._prompt(self.STRIDE * 3 + 777)
        second = llm_providers.PromptWithCacheBoundaries(
            first + "\n\nnote " + self._prompt(self.STRIDE * 2 + 50, "sup"),
            [len(first)])
        first_input, first_cuts, first_breakpoints = llm_providers.prompt_cache_input(first)
        request_input, cuts, breakpoints = llm_providers.prompt_cache_input(second)
        parts = request_input[0]["content"]

        self.assertEqual("".join(part["text"] for part in parts), second)
        self.assertEqual(cuts[:4], [*first_cuts, len(first)])
        self.assertEqual([part["text"] for part in parts[:4]],
                         [part["text"] for part in first_input[0]["content"]])
        appendix_cuts = [len(first) + cut for cut in
                         llm_providers.prompt_cache_cuts(second[len(first):])]
        self.assertEqual(cuts[4:], appendix_cuts)
        self.assertEqual(len(appendix_cuts), 2)
        # The boundary, then the last stride cuts.
        self.assertEqual(breakpoints, [len(first), *appendix_cuts])
        self.assertEqual(len(first_breakpoints), 3)

    def test_boundaries_take_the_breakpoints_and_survive_without_stride_cuts(self):
        short = "word " * 100
        prompt = llm_providers.PromptWithCacheBoundaries(
            short + "\n\nmore " + short, [len(short), 0, len(short) * 10])
        self.assertEqual(prompt.cache_boundaries, (len(short),))
        request_input, cuts, breakpoints = llm_providers.prompt_cache_input(prompt)
        self.assertEqual((cuts, breakpoints), ([len(short)], [len(short)]))
        self.assertEqual(request_input[0]["content"][0]["text"], short)
        # A plain string built from it carries no boundary.
        self.assertEqual(llm_providers.prompt_cache_input(prompt + "x")[1], [])
        five = list(range(1, 6))
        _, cuts, breakpoints = llm_providers.prompt_cache_input(
            "a" * 10, boundaries=five)
        self.assertEqual((cuts, breakpoints), (five, five[-3:]))

    def test_a_prompt_with_boundaries_is_logged_with_them(self):
        first = self._prompt(self.STRIDE + 300)
        prompt = llm_providers.PromptWithCacheBoundaries(
            first + "\n\nappended data", [len(first)])
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session()
            provider = self._provider(directory, session)
            provider.generate(prompt, "system", json_mode=True,
                              json_schema={"type": "object"})
            request = self._records(directory, "request")[0]

        parts = session.bodies[0]["input"][0]["content"]
        self.assertEqual(parts[-1]["text"], "\n\nappended data")
        self.assertEqual(parts[-2]["prompt_cache_breakpoint"], {"mode": "explicit"})
        self.assertEqual(request["caller_boundaries"], [len(first)])
        self.assertEqual(request["input"], prompt)
        self.assertIn(len(first), request["input_parts"])

    def test_a_research_call_is_never_split(self):
        prompt = self._prompt(self.STRIDE * 3)
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session()
            provider = self._provider(directory, session)
            provider.generate(prompt, "system", web_search=True)
            request = self._records(directory, "request")[0]

        self.assertEqual(session.bodies[0]["input"], prompt)
        self.assertIn("tools", session.bodies[0])
        self.assertEqual(request["input_parts"], [])

    def test_the_synthesis_after_research_is_split_and_the_research_is_not(self):
        prompt = self._prompt(self.STRIDE * 2)
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session()
            provider = self._provider(directory, session)
            provider.generate(prompt, "system", json_mode=True, web_search=True,
                              json_schema={"type": "object"})

        research, synthesis = session.bodies
        self.assertIsInstance(research["input"], str)
        self.assertIsInstance(synthesis["input"], list)

    def test_the_environment_switch_sends_the_plain_string(self):
        prompt = self._prompt(self.STRIDE * 2 + 1)
        for value in ("0", "false", "No", " off "):
            with self.subTest(value=value):
                with tempfile.TemporaryDirectory() as directory:
                    session = self._Session()
                    provider = self._provider(directory, session)
                    with patch.dict(os.environ,
                                    {"TCC_LLM_PROMPT_CACHE_BREAKPOINTS": value}):
                        provider.generate(prompt, "system")
                    request = self._records(directory, "request")[0]

                self.assertEqual(session.bodies[0]["input"], prompt)
                self.assertEqual(request["input_parts"], [])
                self.assertEqual(request["prompt_cache_breakpoints_off"], "environment")

    def test_a_refused_breakpoint_is_resent_plain_once_and_remembered(self):
        refusal = self._Response({"error": {
            "message": "Unknown parameter: 'input[0].content[0].prompt_cache_breakpoint'.",
            "type": "invalid_request_error",
            "param": "input[0].content[0].prompt_cache_breakpoint",
            "code": "unknown_parameter",
        }}, status_code=400)
        first = self._prompt(self.STRIDE * 2 + 1)
        second = self._prompt(self.STRIDE * 3 + 1, "other")
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session([refusal])
            provider = self._provider(directory, session)
            with self.assertLogs("fix_analysis", level="WARNING") as logs:
                self.assertEqual(provider.generate(first, "system"), "done")
            provider.generate(second, "system")
            metas = self._records(directory, "metadata")
            requests_ = self._records(directory, "request")

        self.assertEqual(len(session.bodies), 3)
        self.assertIsInstance(session.bodies[0]["input"], list)
        self.assertEqual(session.bodies[1]["input"], first)
        self.assertEqual(session.bodies[2]["input"], second)
        self.assertTrue(any("prompt_cache_breakpoint" in line for line in logs.output))
        self.assertEqual(metas[0]["status"], "success")
        self.assertIn("unknown_parameter", metas[0]["prompt_cache_breakpoints_rejected"])
        self.assertNotIn("prompt_cache_breakpoints_rejected", metas[1])
        self.assertEqual(requests_[1]["prompt_cache_breakpoints_off"], "rejected")
        # The refused call's records describe the plain resend and keep the
        # refused cuts apart, so it never counts as a call sent in parts.
        planned = llm_providers.prompt_cache_cuts(first)
        self.assertEqual(len(planned), 2)
        for record in (metas[0], requests_[0]):
            self.assertEqual((record["input_parts"], record["breakpoints"]), ([], []))
            self.assertEqual(record["prompt_cache_breakpoints_off"], "rejected")
            self.assertEqual(record["planned_input_parts"], planned)
            self.assertEqual(record["planned_breakpoints"], planned)
        self.assertEqual(requests_[0]["input"], first)

    def test_another_client_error_is_not_resent(self):
        refusal = self._Response({"error": {"code": "invalid_request_error",
                                            "message": "bad schema"}}, status_code=400)
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session([refusal])
            provider = self._provider(directory, session)
            with self.assertRaises(RuntimeError):
                provider.generate(self._prompt(self.STRIDE * 2 + 1), "system")

        self.assertEqual(len(session.bodies), 1)
        self.assertEqual(provider._prompt_cache_breakpoints_rejected, "")

    def test_a_400_naming_the_input_parts_is_resent_plain_not_refused(self):
        # A shape rejection that does not spell out prompt_cache_breakpoint
        # read as a content refusal and the finding as "provider refused".
        rejections = (
            {"message": "Invalid type for 'input[0].content'.",
             "type": "invalid_request_error", "param": "input[0].content",
             "code": "invalid_type"},
            {"message": "Unsupported content part: input_text with this field.",
             "type": "invalid_request_error", "param": None,
             "code": "invalid_value"},
        )
        for error in rejections:
            with self.subTest(param=error["param"]):
                prompt = self._prompt(self.STRIDE * 2 + 1)
                with tempfile.TemporaryDirectory() as directory:
                    session = self._Session([self._Response({"error": error},
                                                            status_code=400)])
                    provider = self._provider(directory, session)
                    with self.assertLogs("fix_analysis", level="WARNING"):
                        self.assertEqual(provider.generate(prompt, "system"), "done")
                    provider.generate(self._prompt(self.STRIDE * 3, "other"), "system")
                    meta = self._records(directory, "metadata")[0]

                self.assertEqual(len(session.bodies), 3)
                self.assertIsInstance(session.bodies[0]["input"], list)
                self.assertEqual(session.bodies[1]["input"], prompt)
                self.assertIsInstance(session.bodies[2]["input"], str)
                self.assertEqual(meta["status"], "success")
                self.assertEqual(meta["prompt_cache_breakpoints_off"], "rejected")
                self.assertIn(error["code"], provider._prompt_cache_breakpoints_rejected)

    def test_a_content_refusal_to_a_request_in_parts_still_refuses(self):
        refusals = (
            {"code": "cyber_policy", "message": "flagged"},
            # Naming the input does not turn a verdict on it into a shape error.
            {"code": "invalid_prompt", "param": "input",
             "message": "Invalid prompt: your prompt was flagged."},
        )
        for error in refusals:
            with self.subTest(code=error["code"]):
                with tempfile.TemporaryDirectory() as directory:
                    session = self._Session([self._Response({"error": error},
                                                            status_code=400)])
                    provider = self._provider(directory, session)
                    with self.assertRaises(llm_providers.ProviderContentRefusal) as raised:
                        provider.generate(self._prompt(self.STRIDE * 2 + 1), "system")

                self.assertEqual(raised.exception.code, error["code"])
                self.assertEqual(len(session.bodies), 1)
                self.assertIsInstance(session.bodies[0]["input"], list)
                self.assertEqual(provider._prompt_cache_breakpoints_rejected, "")

    def test_parts_stay_on_when_the_plain_resend_is_rejected_the_same_way(self):
        # A 400 about the input itself (too long for the context window, or
        # a verdict under a code the provider has not used before) names
        # param "input" too; the plain resend meets it again, so the parts
        # were not its cause and later calls keep their breakpoints.
        errors = (
            {"message": "Your input exceeds the context window of this model.",
             "type": "invalid_request_error", "param": "input",
             "code": "context_length_exceeded"},
            {"message": "flagged", "param": "input", "code": "some_new_policy"},
        )
        for error in errors:
            with self.subTest(code=error["code"]):
                prompt = self._prompt(self.STRIDE * 2 + 1)
                with tempfile.TemporaryDirectory() as directory:
                    session = self._Session([
                        self._Response({"error": error}, status_code=400),
                        self._Response({"error": error}, status_code=400),
                    ])
                    provider = self._provider(directory, session)
                    with self.assertRaises(RuntimeError) as raised:
                        provider.generate(prompt, "system")
                    provider.generate(self._prompt(self.STRIDE * 3, "other"), "system")

                self.assertIn(error["code"], str(raised.exception))
                self.assertEqual(len(session.bodies), 3)
                self.assertIsInstance(session.bodies[0]["input"], list)
                self.assertEqual(session.bodies[1]["input"], prompt)
                self.assertIsInstance(session.bodies[2]["input"], list)
                self.assertEqual(provider._prompt_cache_breakpoints_rejected, "")

    def test_the_rejection_is_remembered_once_the_plain_resend_is_created(self):
        # A server fault on the plain resend is retried; the parts are
        # remembered as refused when that request is finally accepted.
        rejection = self._Response({"error": {
            "message": "Invalid type for 'input[0].content'.",
            "param": "input[0].content", "code": "invalid_type"}}, status_code=400)
        fault = self._Response({"error": {"message": "server"}}, status_code=500)
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session([rejection, fault])
            provider = self._provider(directory, session)
            provider._sleep = lambda _seconds: None
            with self.assertLogs("fix_analysis", level="WARNING"):
                self.assertEqual(
                    provider.generate(self._prompt(self.STRIDE * 2 + 1), "system"),
                    "done")

        self.assertEqual(len(session.bodies), 3)
        self.assertIsInstance(session.bodies[2]["input"], str)
        self.assertIn("invalid_type", provider._prompt_cache_breakpoints_rejected)

    def test_a_plain_request_naming_the_input_is_not_resent(self):
        error = {"code": "invalid_type", "param": "input", "message": "bad input"}
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session([self._Response({"error": error}, status_code=400)])
            provider = self._provider(directory, session)
            with self.assertRaises(RuntimeError):
                provider.generate("short prompt", "system")

        self.assertEqual(len(session.bodies), 1)
        self.assertEqual(provider._prompt_cache_breakpoints_rejected, "")

    def test_an_uncoded_client_error_stays_a_plain_runtime_error_sent_once(self):
        # Crash records name the exception's type; a 4xx unrelated to the
        # breakpoints keeps the name and message it had.
        missing = self._Response({"error": {"message": "x"}}, status_code=404)
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session([missing])
            provider = self._provider(directory, session)
            with self.assertRaises(RuntimeError) as raised:
                provider.generate(self._prompt(self.STRIDE * 2 + 1), "system")

        self.assertIs(type(raised.exception), RuntimeError)
        self.assertTrue(str(raised.exception).startswith("OpenAI API HTTP 404: "))
        self.assertEqual(len(session.bodies), 1)
        self.assertEqual(provider._prompt_cache_breakpoints_rejected, "")

    def test_a_plain_request_refused_for_the_field_is_not_resent(self):
        refusal = self._Response({"error": {
            "message": "Unknown parameter: 'prompt_cache_breakpoint'."}}, status_code=400)
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session([refusal])
            provider = self._provider(directory, session)
            with self.assertRaises(RuntimeError):
                provider.generate("short prompt", "system")

        self.assertEqual(len(session.bodies), 1)


if __name__ == "__main__":
    unittest.main()
