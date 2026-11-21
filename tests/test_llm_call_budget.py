"""Transient and deterministic provider failures, and the bound on both.

Transport retries, schema corrections, research and regeneration each have
their own limit; nothing bounded their product per finding, and a rejected
API key was retried by every finding in turn. No test here reaches a real
provider: the transport sequence is served by a local HTTP server so that
urllib3's own retry logic -- the part that honours Retry-After -- runs.
"""
import http.server
import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (scripts/ and src/ on sys.path)

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "cognalys" / "llm" / "generate_error_fixes.py"
SPEC = importlib.util.spec_from_file_location("budget_generator", MODULE_PATH)
generator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = generator
SPEC.loader.exec_module(generator)

from cognalys.llm import llm_providers  # noqa: E402  (on sys.path once the generator loads)


def _success_body(text="done"):
    return {"id": "resp", "output_text": text,
            "usage": {"input_tokens": 1, "output_tokens": 1}}


class _Response:
    def __init__(self, status, body=None, text=""):
        self.status_code = status
        self._body = body or {}
        self.text = text or json.dumps(self._body)
        self.headers = {}

    def json(self):
        return self._body


class _CountingSession:
    def __init__(self, response):
        self.response = response
        self.posts = 0

    def post(self, *_args, **_kwargs):
        self.posts += 1
        return self.response


def _provider(directory):
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
        return llm_providers.OpenAIProvider(
            prompt_log_dir=Path(directory), cache_dir=None,
        )


class _SequenceHandler(http.server.BaseHTTPRequestHandler):
    statuses = []

    def do_POST(self):  # noqa: N802 - http.server's naming
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        status = self.statuses.pop(0) if self.statuses else 200
        body = json.dumps(_success_body() if status == 200 else
                          {"error": {"code": "transient"}}).encode()
        self.send_response(status)
        # Retry-After: 0 so urllib3 waits the time the server asks for
        # (none) instead of its backoff curve.
        self.send_header("Retry-After", "0")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class TransportTests(unittest.TestCase):

    def test_429_then_503_then_success_is_one_call_with_two_retries(self):
        _SequenceHandler.statuses = [429, 503]
        server = http.server.HTTPServer(("127.0.0.1", 0), _SequenceHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                provider = _provider(directory)
                session = provider._build_session(total=2, respect_retry_after=True)
                session.mount("http://", session.adapters["https://"])
                provider.session = session
                provider.endpoint = f"http://127.0.0.1:{server.server_port}"
                with llm_providers.finding_budget(max_calls=5) as budget:
                    self.assertEqual(provider.generate("p", "s"), "done")
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(budget.calls, 1)
        self.assertEqual(budget.transport_retries, 2)
        self.assertEqual(budget.failed_calls, 0)


class AuthenticationTests(unittest.TestCase):

    def test_a_401_is_not_sent_again(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = _provider(directory)
            provider.session = _CountingSession(
                _Response(401, {"error": {"code": "invalid_api_key"}}),
            )
            for _ in range(3):
                with self.assertRaises(llm_providers.ProviderAuthenticationError):
                    provider.generate("p", "s")
        self.assertEqual(provider.session.posts, 1)


class BudgetTests(unittest.TestCase):

    def test_the_call_after_the_limit_is_refused_before_sending(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = _provider(directory)
            provider.session = _CountingSession(_Response(200, _success_body()))
            with llm_providers.finding_budget(max_calls=2) as budget:
                provider.generate("a", "s")
                provider.generate("b", "s")
                with self.assertRaises(llm_providers.CallBudgetExhausted):
                    provider.generate("c", "s")
        self.assertEqual(provider.session.posts, 2)
        self.assertIn("2 model calls", budget.summary()["exhausted"])

    def test_calls_outside_a_budget_are_not_limited(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = _provider(directory)
            provider.session = _CountingSession(_Response(200, _success_body()))
            for index in range(4):
                provider.generate(f"p{index}", "s")
        self.assertEqual(provider.session.posts, 4)

    def test_budgets_on_different_threads_do_not_share_calls(self):
        seen = {}

        def work(name):
            with llm_providers.finding_budget(max_calls=1) as budget:
                budget.charge()
                seen[name] = budget.calls

        threads = [threading.Thread(target=work, args=(n,)) for n in "ab"]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(seen, {"a": 1, "b": 1})

    def test_the_limits_are_read_from_the_environment(self):
        with patch.dict(os.environ, {"TCC_LLM_FINDING_MAX_CALLS": "7",
                                     "TCC_LLM_FINDING_MAX_MINUTES": "0"}):
            limits = llm_providers.budget_limits_from_environment()
        self.assertEqual(limits, {"max_calls": 7, "max_seconds": 0.0})


class FindingOutcomeTests(unittest.TestCase):
    """analyse_one names the stop instead of reporting a crash."""

    def _analysed(self, exception):
        fixer = generator.FixGenerator.__new__(generator.FixGenerator)
        fixer.logger = llm_providers.logging.getLogger("budget-test")

        def analyse(_error):
            raise exception

        fixer.process_finding = analyse
        _, result = fixer.analyse_one({"method_name": "m"})
        return result

    def test_an_exhausted_budget_is_its_own_outcome(self):
        result = self._analysed(llm_providers.CallBudgetExhausted("limit"))
        self.assertEqual(result.outcome, "llm_budget_exhausted")
        self.assertIsNotNone(result.llm_budget)

    def test_an_authentication_failure_is_its_own_outcome(self):
        result = self._analysed(llm_providers.ProviderAuthenticationError("401"))
        self.assertEqual(result.outcome, "provider_auth_failed")


if __name__ == "__main__":
    unittest.main()
