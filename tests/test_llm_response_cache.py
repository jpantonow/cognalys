import contextlib
import io
import itertools
import json
import logging
import os
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.generate_error_fixes import (  # noqa: E402
    FixGenerator,
    FindingOutcome,
    LLMResponseCache,
    OpenAIProvider,
)
from cognalys.llm import llm_providers as provider_module  # noqa: E402
from cognalys.llm.llm_providers import ProviderContentRefusal  # noqa: E402


class LLMResponseCacheTests(unittest.TestCase):
    def test_round_trip_and_stats(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = LLMResponseCache(Path(directory), logging.getLogger(__name__))
            request = {"model": "example", "prompt": "hello"}

            self.assertIsNone(cache.get(request))
            cache.put(request, "world")
            self.assertEqual(cache.get(request), "world")
            self.assertEqual(cache.stats(), {"hits": 1, "misses": 1, "replays": 0})

    def test_changed_request_does_not_reuse_response(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = LLMResponseCache(Path(directory), logging.getLogger(__name__))
            cache.put({"model": "a", "prompt": "same"}, "response")

            self.assertIsNone(cache.get({"model": "b", "prompt": "same"}))

    def test_disabled_cache_does_not_write_or_count_misses(self):
        cache = LLMResponseCache(None, logging.getLogger(__name__))
        request = {"prompt": "hello"}

        cache.put(request, "world")
        self.assertIsNone(cache.get(request))
        self.assertEqual(cache.stats(), {"hits": 0, "misses": 0, "replays": 0})

    def test_entry_within_ttl_is_served_and_an_older_one_is_refused(self):
        # Web research is cached under a TTL rather than excluded from the
        # cache: it was 64% of the pipeline's LLM wall time and repeated
        # verbatim across runs of the same finding.
        with tempfile.TemporaryDirectory() as directory:
            cache = LLMResponseCache(Path(directory), logging.getLogger(__name__))
            request = {"model": "example", "prompt": "hello", "web_search": True}
            cache.put(request, "researched")

            self.assertEqual(cache.get(request, ttl_seconds=3600), "researched")
            self.assertIsNone(cache.get(request, ttl_seconds=0))
            # No TTL at all still serves it: only the caller decides that its
            # content ages.
            self.assertEqual(cache.get(request), "researched")

    def test_entry_without_a_readable_timestamp_is_treated_as_expired(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = LLMResponseCache(Path(directory), logging.getLogger(__name__))
            request = {"prompt": "hello"}
            cache.put(request, "world")
            key = cache._key(request)
            path = Path(directory) / key[:2] / f"{key}.json"
            stored = json.loads(path.read_text(encoding="utf-8"))
            stored["created_at"] = "not a timestamp"
            path.write_text(json.dumps(stored), encoding="utf-8")

            self.assertIsNone(cache.get(request, ttl_seconds=86400))

    # The key of the request below as generate() stored it before prompts
    # were sent in parts (computed with that code and by hand): every entry
    # already on disk must keep answering.
    PINNED_KEY = "2818a3dcb038e8a3103743fed020ea449181e01a019a93b50ea35f24f436421d"

    def test_a_long_prompt_sent_in_parts_keeps_its_cache_key(self):
        class Response:
            status_code = 200
            text = ""
            headers = {}

            @staticmethod
            def json():
                return {"id": "r", "status": "completed", "output_text": "{}"}

        class Session:
            def __init__(self):
                self.bodies = []

            def post(self, _url, **kwargs):
                self.bodies.append(kwargs["json"])
                return Response()

        prompt = "evidence line " * 3000
        with tempfile.TemporaryDirectory() as directory:
            with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
                provider = OpenAIProvider(
                    endpoint="https://api.openai.com/v1", model="gpt-test",
                    max_output_tokens=32768, reasoning_effort="high",
                    cache_dir=Path(directory), prompt_log_dir=None)
            provider.session = Session()
            provider.generate(prompt, "system", json_mode=True,
                              json_schema={"type": "object"}, schema_name="unit_schema")
            stored = [path.stem for path in Path(directory).rglob("*.json")]

        self.assertIsInstance(provider.session.bodies[0]["input"], list)
        self.assertEqual(stored, [self.PINNED_KEY])


class FindingSchedulingTests(unittest.TestCase):
    """Two reorderings that cut cost without changing any decision.

    Findings of one specification share a policy prefix of tens of thousands
    of characters; analysed consecutively that prefix stays warm in the
    provider's prompt cache, and the runs of 2026-09-07 recorded 0 cached
    input tokens on the two largest stages because every run analysed one
    finding of a different specification. Findings are also independent
    analyses that spend nearly all their time waiting on the provider, so a
    worker pool multiplies throughput.
    """

    def _generator(self):
        generator = FixGenerator.__new__(FixGenerator)
        generator.logger = logging.getLogger("test-scheduling")
        generator._finding_state = threading.local()
        generator._stats_lock = threading.Lock()
        return generator

    def test_findings_are_grouped_by_specification_then_repository(self):
        findings = [
            {"spec": "CipherSpec", "repository_url": "b", "unique_error_id": "3"},
            {"spec": "KeyStoreSpec", "repository_url": "a", "unique_error_id": "1"},
            {"spec": "CipherSpec", "repository_url": "a", "unique_error_id": "2"},
            {"spec": "KeyStoreSpec", "repository_url": "a", "unique_error_id": "0"},
        ]
        ordered = self._generator().group_by_specification(findings)
        self.assertEqual(
            [(f["spec"], f["repository_url"], f["unique_error_id"]) for f in ordered],
            [
                ("CipherSpec", "a", "2"),
                ("CipherSpec", "b", "3"),
                ("KeyStoreSpec", "a", "0"),
                ("KeyStoreSpec", "a", "1"),
            ],
        )

    def test_workers_preserve_submission_order_and_per_finding_outcomes(self):
        generator = self._generator()
        findings = [{"method_name": f"m{index}"} for index in range(8)]

        def process_finding(error):
            # Every worker's conclusion travels in its own returned value,
            # so a slow neighbour cannot be read back in place of it.
            time.sleep(0.02 if error["method_name"] == "m0" else 0.0)
            return FindingOutcome(
                {"of": error["method_name"]}, True,
                f"outcome-{error['method_name']}",
                f"decision-{error['method_name']}",
            )

        generator.process_finding = process_finding
        results = list(generator.analyse_findings(findings, workers=4))

        self.assertEqual(
            [error["method_name"] for error, _ in results],
            [f"m{index}" for index in range(8)],
        )
        for error, result in results:
            name = error["method_name"]
            self.assertTrue(result.success)
            self.assertEqual(result.solution, {"of": name})
            self.assertEqual(result.outcome, f"outcome-{name}")
            self.assertEqual(result.decision, f"decision-{name}")

    def test_one_failing_finding_does_not_end_the_run(self):
        generator = self._generator()

        def process_finding(error):
            if error["method_name"] == "boom":
                raise RuntimeError("simulated")
            return FindingOutcome(None, False)

        generator.process_finding = process_finding
        results = list(generator.analyse_findings(
            [{"method_name": "boom"}, {"method_name": "fine"}], workers=2,
        ))

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][1].outcome, "crashed")
        self.assertIn("RuntimeError: simulated", results[0][1].failure_cause)


class WebSearchRetryBudgetTests(unittest.TestCase):
    """A retried research call re-runs the whole research pass.

    Across the runs of 2026-09-07, research calls that never retried averaged
    62s and those that retried averaged 693s, on 5 of 9 calls. Web search
    therefore gets its own, much smaller retry budget.
    """

    def _retries(self, provider, attribute):
        return getattr(provider, attribute).get_adapter(
            "https://api.openai.com"
        ).max_retries

    def test_web_search_session_retries_less_than_the_default_session(self):
        with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            provider = OpenAIProvider(prompt_log_dir=None)

        default_retries = self._retries(provider, "session")
        research_retries = self._retries(provider, "web_search_session")

        self.assertLess(research_retries.total, default_retries.total)
        self.assertTrue(research_retries.respect_retry_after_header)

    def test_ordinary_calls_also_get_a_small_budget_and_honour_retry_after(self):
        """A retry here re-runs a whole generation, not a cheap request.

        A single read failure on a WordPress evidence_extraction on
        2026-09-07 turned a call that took 37s on its second and larger run
        into 626s, under a budget of four blind retries.
        """
        with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            provider = OpenAIProvider(prompt_log_dir=None)

        default_retries = self._retries(provider, "session")
        self.assertEqual(default_retries.total, 2)
        self.assertTrue(default_retries.respect_retry_after_header)

    def test_the_budget_is_configurable(self):
        with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            provider = OpenAIProvider(prompt_log_dir=None, retries=0)

        self.assertEqual(self._retries(provider, "session").total, 0)


class BackgroundResponseTests(unittest.TestCase):
    """Long calls are created in the background and followed by short polls.

    run_20260917_140228 lost 20 minutes on its first call and ten more on
    each of three others: a non-streaming Responses call sends no byte until
    it is finished, so a silent network path costs the whole read timeout and
    the retry costs it again.
    """

    class _Response:
        def __init__(self, payload, status_code=200):
            self.status_code = status_code
            self._payload = payload
            self.text = json.dumps(payload)
            self.headers = {}

        def json(self):
            return self._payload

    class _Session:
        def __init__(self, polls, create=None):
            self.polls = list(polls)
            self.create = create
            self.payloads = []
            self.poll_urls = []
            self.cancelled = []

        def post(self, url, **kwargs):
            if url.endswith("/cancel"):
                self.cancelled.append(url)
                return BackgroundResponseTests._Response({})
            self.payloads.append(kwargs.get("json"))
            return BackgroundResponseTests._Response(
                self.create or {"id": "resp-1", "status": "queued"}
            )

        def get(self, url, **_kwargs):
            self.poll_urls.append(url)
            payload = self.polls.pop(0)
            if isinstance(payload, Exception):
                raise payload
            return BackgroundResponseTests._Response(payload)

    def _provider(self, session):
        with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
            provider = OpenAIProvider(prompt_log_dir=None, cache_dir=None)
        provider.session = session
        provider.web_search_session = session
        provider._sleep = lambda _seconds: None
        return provider

    def test_a_queued_response_is_polled_until_it_completes(self):
        session = self._Session([
            {"id": "resp-1", "status": "in_progress"},
            {"id": "resp-1", "status": "completed", "output_text": "done",
             "usage": {"input_tokens": 3, "output_tokens": 1}},
        ])
        provider = self._provider(session)

        self.assertEqual(provider.generate("input"), "done")
        self.assertIs(session.payloads[0]["background"], True)
        self.assertEqual(len(session.poll_urls), 2)
        self.assertTrue(session.poll_urls[0].endswith("/responses/resp-1"))

    def test_a_synchronous_answer_is_returned_without_polling(self):
        session = self._Session([], create={"id": "r", "output_text": "done"})
        provider = self._provider(session)

        self.assertEqual(provider.generate("input"), "done")
        self.assertEqual(session.poll_urls, [])

    def test_a_failed_poll_is_retried_instead_of_losing_the_call(self):
        session = self._Session([
            ConnectionError("connection reset"),
            {"id": "resp-1", "status": "completed", "output_text": "done"},
        ])
        provider = self._provider(session)

        self.assertEqual(provider.generate("input"), "done")

    def test_unbroken_poll_failures_give_up(self):
        session = self._Session([ConnectionError("reset")] * 12)
        provider = self._provider(session)

        with self.assertRaises(ConnectionError):
            provider.generate("input")

    def test_the_deadline_covers_the_whole_call_and_cancels_it(self):
        session = self._Session([{"id": "resp-1", "status": "in_progress"}] * 3)
        provider = self._provider(session)
        provider.timeout = 5
        # 99 s from the fourth reading on, the settling of the cancelled
        # response and the trace included.
        clock = itertools.chain([0.0, 1.0, 2.0], itertools.repeat(99.0))
        with unittest.mock.patch.object(
            provider_module.time, "monotonic", lambda: next(clock)
        ):
            with self.assertRaises(TimeoutError):
                provider.generate("input")

        self.assertTrue(session.cancelled)

    def test_a_failed_response_reports_its_content_verdict(self):
        session = self._Session([{
            "id": "resp-1", "status": "failed",
            "error": {"code": "cyber_policy", "message": "flagged"},
        }])
        provider = self._provider(session)

        with self.assertRaises(ProviderContentRefusal) as raised:
            provider.generate("input")
        self.assertEqual(raised.exception.code, "cyber_policy")

    def test_a_server_fault_is_sent_again_and_answered(self):
        session = self._Session([
            {"id": "resp-1", "status": "failed",
             "error": {"code": "server_error", "message": "boom"}},
            {"id": "resp-1", "status": "completed", "output_text": "done"},
        ])
        provider = self._provider(session)

        self.assertEqual(provider.generate("input"), "done")
        self.assertEqual(len(session.payloads), 2)

    def test_a_polled_failure_with_no_verdict_is_not_a_refusal(self):
        # agent_baseline_20261108 run_v4 (2026-11-09): server_is_overloaded on
        # the standard tier, and a failure without a code, are the service
        # failing to answer: sent again after the create waits, then a
        # ProviderTransientFailure, never a ProviderContentRefusal.
        attempts = len(OpenAIProvider.CREATE_RETRY_WAITS_SECONDS) + 1
        for code in ("server_is_overloaded", ""):
            with self.subTest(code=code):
                failed = {"id": "resp-1", "status": "failed",
                          "error": {"code": code, "message": "Our servers are overloaded."}}
                session = self._Session([failed] * attempts)
                provider = self._provider(session)

                with self.assertRaises(provider_module.ProviderTransientFailure) as raised:
                    provider.generate("input")
                self.assertNotIsInstance(raised.exception, ProviderContentRefusal)
                self.assertEqual(raised.exception.code, code)
                self.assertEqual(len(session.payloads), attempts)

    def test_a_code_no_list_knows_is_sent_once_more_then_rejects_the_request(self):
        # Review of 2026-11-09: resent with the whole budget, a verdict under
        # a new code would go 15 times (four resends in each of three
        # passes). Once more, and the same code again is the request's
        # rejection: a failed analysis, neither a refusal nor resumed.
        failed = {"id": "resp-1", "status": "failed",
                  "error": {"code": "some_new_code", "message": "no"}}
        session = self._Session([failed, failed, failed])
        provider = self._provider(session)

        with self.assertLogs("fix_analysis", level="WARNING") as logs, \
                self.assertRaises(provider_module.ProviderRequestRejected) as raised:
            provider.generate("input")
        self.assertNotIsInstance(raised.exception, provider_module.ProviderTransientFailure)
        self.assertNotIsInstance(raised.exception, ProviderContentRefusal)
        self.assertEqual(raised.exception.code, "some_new_code")
        self.assertEqual(len(session.payloads), 2)
        self.assertTrue(any("no list knows (some_new_code)" in line for line in logs.output))
        # Once is enough when the resend is answered.
        session = self._Session([failed, {"id": "resp-1", "status": "completed",
                                          "output_text": "done"}])
        with self.assertLogs("fix_analysis", level="WARNING"):
            self.assertEqual(self._provider(session).generate("input"), "done")

    def _poll_failure_session(self, failure, settled):
        """Six polls failing with ``failure`` (an exception, or an HTTP status), then ``settled``."""
        responses = BackgroundResponseTests._Response

        class _Session(BackgroundResponseTests._Session):
            def get(self, url, **_kwargs):
                self.poll_urls.append(url)
                if len(self.poll_urls) <= OpenAIProvider.MAX_CONSECUTIVE_POLL_FAILURES + 1:
                    if isinstance(failure, Exception):
                        raise failure
                    return responses({"error": {"code": "server_is_overloaded"}},
                                     status_code=failure)
                return responses(settled)

        return _Session([])

    def test_polls_failing_on_the_service_cancel_the_response_and_leave_the_finding(self):
        # Review of 2026-11-09: six 503 polls in a row re-raised a plain
        # RuntimeError, which external research read as "continuing with
        # repository evidence only", and the response kept running unseen
        # by the guard. Now it is cancelled, settled and charged, and the
        # call ends as a ProviderTransientFailure (provider_unavailable).
        import requests

        settled = {"id": "resp-1", "status": "cancelled",
                   "usage": {"input_tokens": 5, "output_tokens": 40}}
        for failure in (503, requests.exceptions.ConnectionError("reset"),
                        requests.exceptions.ReadTimeout("slow")):
            with self.subTest(failure=repr(failure)):
                session = self._poll_failure_session(failure, settled)
                provider = self._provider(session)
                provider._cost_guard = QueuedBackgroundResubmissionTests._Guard()
                with self.assertLogs("fix_analysis", level="WARNING"), \
                        self.assertRaises(provider_module.BackgroundPollFailed) as raised:
                    provider.generate("input")
                self.assertIsInstance(raised.exception, provider_module.ProviderTransientFailure)
                self.assertNotIsInstance(raised.exception, TimeoutError)
                self.assertEqual(raised.exception.response_id, "resp-1")
                self.assertEqual(len(session.payloads), 1)
                self.assertEqual(len(session.cancelled), 1)
                self.assertEqual(provider._cost_guard.added, [(5, 0, 40, 0)])

    def test_polls_failing_for_a_client_error_still_fail_as_before(self):
        session = self._poll_failure_session(404, {})
        with self.assertLogs("fix_analysis", level="WARNING"), \
                self.assertRaises(RuntimeError) as raised:
            self._provider(session).generate("input")
        self.assertNotIsInstance(raised.exception, provider_module.ProviderTransientFailure)
        self.assertIn("HTTP 404", str(raised.exception))
        self.assertEqual(session.cancelled, [])


class QueuedBackgroundResubmissionTests(unittest.TestCase):
    """A response OpenAI never started is sent again once, not lost.

    Tokn (rvsec_tokn_20261028/run_v5, 2026-10-31): an evidence extraction
    was still "queued" at the 600s deadline and the TimeoutError crashed the
    whole analysis (Analyzed 0/4); Grocy's research lost its web evidence the
    same way. A queued response produced and cost nothing, so one
    resubmission under a fresh deadline is safe; one seen "in_progress" ran
    and keeps the old timeout.
    """

    class _Session:
        """Each create gets the next id; each poll advances the clock 100s."""

        def __init__(self, polls_by_id, clock, cancel_answers=None):
            self.polls_by_id = {key: list(value) for key, value in polls_by_id.items()}
            self.clock = clock
            self.created = []
            self.cancelled = []
            # What each cancel answers, by response id; by default OpenAI's
            # confirmation that the response is now "cancelled".
            self.cancel_answers = dict(cancel_answers or {})

        def close(self):
            pass

        def post(self, url, **kwargs):
            if url.endswith("/cancel"):
                response_id = url.rsplit("/", 2)[-2]
                self.cancelled.append(response_id)
                answer = self.cancel_answers.get(
                    response_id, {"id": response_id, "status": "cancelled"},
                )
                if isinstance(answer, Exception):
                    raise answer
                if isinstance(answer, BackgroundResponseTests._Response):
                    return answer
                return BackgroundResponseTests._Response(answer)
            response_id = f"resp-{len(self.created) + 1}"
            self.created.append((response_id, kwargs.get("json")))
            return BackgroundResponseTests._Response(
                {"id": response_id, "status": "queued"}
            )

        def get(self, url, **_kwargs):
            self.clock[0] += 100.0
            response_id = url.rsplit("/", 1)[-1]
            payload = self.polls_by_id[response_id].pop(0)
            if isinstance(payload, Exception):
                raise payload
            return BackgroundResponseTests._Response(payload)

    class _Guard:
        def __init__(self):
            self.checks = 0
            self.added = []

        def check(self):
            self.checks += 1

        def add(self, *tokens, cache_write_tokens=0, service_tier="", web_search_calls=0):
            self.added.append(tokens + (cache_write_tokens,))
            self.billing = getattr(self, "billing", []) + [(service_tier, web_search_calls)]

    def _run(self, polls_by_id, web_search=False, cancel_answers=None):
        """generate() against ``polls_by_id`` with a 250s deadline; (result or exception, state)."""
        clock = [0.0]
        session = self._Session(polls_by_id, clock, cancel_answers)
        directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, directory, True)
        with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
            provider = OpenAIProvider(
                prompt_log_dir=Path(directory), cache_dir=None, timeout=250,
            )
        provider.session = session
        provider.web_search_session = session
        provider._sleep = lambda _seconds: None
        provider._cost_guard = self._Guard()
        outcome = None
        with unittest.mock.patch.object(
            provider_module.time, "monotonic", lambda: clock[0]
        ), provider_module.finding_budget() as budget:
            try:
                outcome = provider.generate("input", web_search=web_search)
            except Exception as exc:  # noqa: BLE001
                outcome = exc
        traces = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in Path(directory).glob("*_metadata.json")
        ]
        return outcome, session, provider, budget, traces, Path(directory)

    def test_a_response_never_started_is_resubmitted_and_its_answer_returned(self):
        completed = {"id": "resp-2", "status": "completed", "output_text": "done",
                     "usage": {"input_tokens": 7, "output_tokens": 2}}
        with self.assertLogs("fix_analysis", level="WARNING") as logs:
            outcome, session, provider, budget, traces, directory = self._run({
                "resp-1": [{"id": "resp-1", "status": "queued"}] * 3,
                "resp-2": [completed],
            })

        self.assertEqual(outcome, "done")
        self.assertEqual([item[0] for item in session.created], ["resp-1", "resp-2"])
        self.assertEqual(session.created[0][1], session.created[1][1])
        self.assertEqual(session.cancelled, ["resp-1"])
        self.assertTrue(any("resubmitted" in line and "resp-1" in line
                            for line in logs.output))
        # One call, charged once with the completed attempt's usage only.
        self.assertEqual(provider.token_usage, {"input": 7, "output": 2})
        self.assertEqual(provider._cost_guard.added, [(7, 0, 2, 0)])
        self.assertEqual((budget.calls, budget.failed_calls), (1, 0))
        self.assertEqual(len(traces), 1)
        self.assertEqual(traces[0]["status"], "success")
        self.assertEqual(traces[0]["queued_resubmissions"], 1)
        self.assertEqual(traces[0]["queued_cancelled_response_ids"], ["resp-1"])
        self.assertEqual(traces[0]["openai_response_id"], "resp-2")
        self.assertEqual(traces[0]["input_tokens"], 7)
        from cognalys.llm.cost import usage
        self.assertEqual(usage(directory, prices={})["calls"], 1)

    def test_a_polled_response_passes_its_cache_writes_to_the_guard(self):
        completed = {"id": "resp-1", "status": "completed", "output_text": "done",
                     "usage": {"input_tokens": 900, "output_tokens": 40,
                               "input_tokens_details": {"cached_tokens": 100,
                                                        "cache_write_tokens": 600}}}
        outcome, _, provider, _, traces, directory = self._run({
            "resp-1": [{"id": "resp-1", "status": "in_progress"}, completed],
        })

        self.assertEqual(outcome, "done")
        self.assertEqual(provider._cost_guard.added, [(900, 100, 40, 600)])
        self.assertEqual(traces[0]["cached_input_tokens"], 100)
        self.assertEqual(traces[0]["cache_write_input_tokens"], 600)
        from cognalys.llm.cost import usage
        self.assertEqual(usage(directory, prices={})["cache_write_input_tokens"], 600)

    def test_a_second_response_never_started_times_out_as_before(self):
        outcome, session, provider, budget, traces, _ = self._run({
            "resp-1": [{"id": "resp-1", "status": "queued"}] * 3,
            "resp-2": [{"id": "resp-2", "status": "queued"}] * 3,
        })

        self.assertIsInstance(outcome, TimeoutError)
        self.assertIn("resp-2 was still queued", str(outcome))
        self.assertIn("resubmitted after resp-1", str(outcome))
        self.assertEqual(len(session.created), 2)
        self.assertEqual(session.cancelled, ["resp-1", "resp-2"])
        self.assertEqual((budget.calls, budget.failed_calls), (1, 1))
        self.assertEqual(provider._cost_guard.added, [])
        self.assertEqual(len(traces), 1)
        self.assertEqual(traces[0]["status"], "timeout")
        self.assertEqual(traces[0]["queued_resubmissions"], 1)

    def test_a_response_that_ran_is_not_resubmitted(self):
        outcome, session, _, budget, traces, _ = self._run({
            "resp-1": [{"id": "resp-1", "status": "in_progress"}] * 3,
        })

        self.assertIsInstance(outcome, TimeoutError)
        self.assertNotIn("resubmitted", str(outcome))
        self.assertEqual(len(session.created), 1)
        self.assertEqual(session.cancelled, ["resp-1"])
        self.assertEqual((budget.calls, budget.failed_calls), (1, 1))
        self.assertEqual(traces[0]["queued_resubmissions"], 0)

    def test_a_response_seen_in_progress_once_is_not_resubmitted(self):
        # Back to "queued" after running is not "never started": it may
        # already be billed.
        outcome, session, _, _, _, _ = self._run({
            "resp-1": [
                {"id": "resp-1", "status": "in_progress"},
                {"id": "resp-1", "status": "queued"},
                {"id": "resp-1", "status": "queued"},
            ],
        })

        self.assertIsInstance(outcome, TimeoutError)
        self.assertEqual(len(session.created), 1)

    def test_a_queued_status_from_before_failing_polls_is_not_resubmitted(self):
        # The last answer was "queued" but the polls since then failed, so
        # the response may have started meanwhile.
        outcome, session, _, _, _, _ = self._run({
            "resp-1": [{"id": "resp-1", "status": "queued"},
                       {"id": "resp-1", "status": "queued"},
                       ConnectionError("reset")],
        })

        self.assertIsInstance(outcome, TimeoutError)
        self.assertEqual(len(session.created), 1)

    def test_a_response_whose_cancel_was_not_confirmed_is_not_resubmitted(self):
        # The cancel is best effort: when it fails, or OpenAI does not answer
        # "cancelled", the queued response may still start and be billed, and
        # a resubmission would run the same request twice with only one
        # counted by the cost guard.
        queued = [{"id": "resp-1", "status": "queued"}] * 3
        lost = {
            "connection error": ConnectionError("reset"),
            "HTTP 500": BackgroundResponseTests._Response(
                {"error": {"code": "server_error"}}, status_code=500),
            "started meanwhile": {"id": "resp-1", "status": "in_progress"},
            "completed meanwhile": {"id": "resp-1", "status": "completed",
                                    "output_text": "late"},
            "cancelled after it ran": {
                "id": "resp-1", "status": "cancelled",
                "usage": {"input_tokens": 900, "output_tokens": 40}},
        }
        for label, answer in lost.items():
            with self.subTest(label):
                outcome, session, provider, budget, traces, _ = self._run(
                    {"resp-1": list(queued)}, cancel_answers={"resp-1": answer},
                )

                self.assertIsInstance(outcome, TimeoutError)
                self.assertNotIn("resubmitted", str(outcome))
                self.assertEqual(len(session.created), 1)
                self.assertEqual((budget.calls, budget.failed_calls), (1, 1))
                self.assertEqual(traces[0]["queued_resubmissions"], 0)

    def test_a_cancel_confirmed_without_usage_allows_the_resubmission(self):
        # OpenAI's answer to cancelling a response it never started carries
        # no usage at all, or zero tokens.
        for usage in (None, {"input_tokens": 0, "output_tokens": 0}):
            with self.subTest(usage=usage):
                outcome, session, _, _, _, _ = self._run({
                    "resp-1": [{"id": "resp-1", "status": "queued"}] * 3,
                    "resp-2": [{"id": "resp-2", "status": "completed",
                                "output_text": "done"}],
                }, cancel_answers={"resp-1": {
                    "id": "resp-1", "status": "cancelled", "usage": usage}})

                self.assertEqual(outcome, "done")
                self.assertEqual(len(session.created), 2)

    def test_a_research_call_never_started_is_resubmitted_too(self):
        # Grocy's lost research (rvsec_grocy_20261022) was this case.
        outcome, session, _, _, _, _ = self._run({
            "resp-1": [{"id": "resp-1", "status": "queued"}] * 3,
            "resp-2": [{"id": "resp-2", "status": "completed",
                        "output_text": "brief"}],
        }, web_search=True)

        self.assertEqual(outcome, "brief")
        self.assertEqual(len(session.created), 2)
        self.assertIn("tools", session.created[1][1])


class CreateServerFaultRetryTests(unittest.TestCase):
    """A create POST that failed on OpenAI's side is sent again after a wait.

    Salty (rvsec_salty_20261022/run_v4, 2026-10-31 18:45): an HTTP 500 burst
    of about 50 s outlasted urllib3's two retries on an adjudication create,
    the RuntimeError crashed the joined unit and both findings ended "não
    analisado". A failed create made no response and costs nothing.
    """

    class _Retry:
        def __init__(self, status):
            self.status = status
            self.error = None

    class _Response(BackgroundResponseTests._Response):
        def __init__(self, payload, status_code=200, headers=None, history=()):
            super().__init__(payload, status_code)
            self.headers = dict(headers or {})
            self.raw = type("Raw", (), {"retries": type(
                "Retries", (), {"history": tuple(history)})()})()

    class _Session:
        def __init__(self, creates):
            self.creates = list(creates)
            self.posts = 0

        def close(self):
            pass

        def post(self, url, **_kwargs):
            self.posts += 1
            answer = self.creates.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

        def get(self, url, **_kwargs):
            raise AssertionError("no poll expected")

    def _run(self, creates):
        session = self._Session(creates)
        directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, directory, True)
        with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
            provider = OpenAIProvider(prompt_log_dir=Path(directory), cache_dir=None)
        provider.session = session
        provider.web_search_session = session
        waits = []
        provider._sleep = waits.append
        guard = QueuedBackgroundResubmissionTests._Guard()
        provider._cost_guard = guard
        try:
            outcome = provider.generate("input")
        except Exception as exc:  # noqa: BLE001
            outcome = exc
        traces = [json.loads(path.read_text(encoding="utf-8"))
                  for path in Path(directory).glob("*_metadata.json")]
        return outcome, session, waits, guard, traces

    def _fault(self, status=500, headers=None):
        return self._Response({"error": {"code": "server_error"}}, status_code=status,
                              headers=headers, history=(self._Retry(500), self._Retry(500)))

    def test_a_server_fault_on_create_is_sent_again_and_answered(self):
        done = self._Response({"id": "r", "status": "completed", "output_text": "done"})
        with self.assertLogs("fix_analysis", level="WARNING") as logs:
            outcome, session, waits, guard, traces = self._run(
                [self._fault(), self._fault(503), done])

        self.assertEqual(outcome, "done")
        self.assertEqual(session.posts, 3)
        self.assertEqual(len(waits), 2)
        self.assertTrue(15 <= waits[0] <= 15 * 1.25 and 30 <= waits[1] <= 30 * 1.25)
        # The ceiling is checked again before each resend.
        self.assertEqual(guard.checks, 3)
        self.assertTrue(any("sending the same request again" in line for line in logs.output))
        self.assertEqual(traces[0]["status"], "success")
        self.assertEqual([item["status"] for item in traces[0]["create_retries"]], [500, 503])
        self.assertEqual(traces[0]["retry_statuses"], [500] * 4)

    def test_a_connection_failure_on_create_is_sent_again(self):
        import requests
        done = self._Response({"id": "r", "status": "completed", "output_text": "done"})
        outcome, session, waits, _, traces = self._run(
            [requests.exceptions.ConnectionError("reset"), done])

        self.assertEqual(outcome, "done")
        self.assertEqual(len(waits), 1)
        self.assertEqual(traces[0]["create_retries"][0]["error"], "ConnectionError")

    def test_a_served_retry_after_is_respected_within_a_bound(self):
        done = self._Response({"id": "r", "status": "completed", "output_text": "done"})
        outcome, _, waits, _, _ = self._run([
            self._fault(headers={"Retry-After": "90"}),
            self._fault(headers={"Retry-After": "86400"}), done])

        self.assertEqual(outcome, "done")
        self.assertEqual(waits[0], 90.0)
        self.assertEqual(waits[1], OpenAIProvider.CREATE_RETRY_MAX_WAIT_SECONDS)

    def test_a_lasting_fault_ends_as_before_and_keeps_its_retries_in_the_trace(self):
        attempts = len(OpenAIProvider.CREATE_RETRY_WAITS_SECONDS) + 1
        outcome, session, waits, _, traces = self._run(
            [self._fault() for _ in range(attempts)])

        self.assertIsInstance(outcome, RuntimeError)
        self.assertIn("OpenAI API HTTP 500", str(outcome))
        self.assertEqual(session.posts, attempts)
        self.assertEqual(len(waits), attempts - 1)
        self.assertEqual(traces[0]["status"], "error")
        self.assertEqual(traces[0]["retry_statuses"], [500] * (2 * attempts))
        self.assertEqual(len(traces[0]["create_retries"]), attempts - 1)

    def test_a_client_error_on_create_is_not_sent_again(self):
        outcome, session, waits, _, _ = self._run([
            self._Response({"error": {"code": "invalid_request_error"}}, status_code=400)])

        # A coded 4xx that is no content verdict rejects the request: not a
        # refusal, not resumed (it was a refusal before 2026-11-09).
        self.assertIsInstance(outcome, provider_module.ProviderRequestRejected)
        self.assertNotIsInstance(outcome, ProviderContentRefusal)
        self.assertNotIsInstance(outcome, provider_module.ProviderTransientFailure)
        self.assertEqual(outcome.code, "invalid_request_error")
        self.assertEqual((session.posts, waits), (1, []))
        outcome, session, _, _, _ = self._run([
            self._Response({"error": {"code": None, "message": "bad"}}, status_code=400)])
        self.assertEqual(type(outcome), RuntimeError)
        self.assertEqual(session.posts, 1)

    def test_a_standard_429_is_sent_again_after_the_create_waits(self):
        # Review of 2026-11-09: a Flex capacity fallback sends concurrent
        # calls to the standard tier together, and a 429 there ended the
        # call at once (research without its web evidence, other stages
        # crashed). It waits as a create that failed on OpenAI's side does,
        # Retry-After honoured, and then ends as a ProviderTransientFailure.
        limited = self._Response({"error": {"code": "rate_limit_exceeded"}}, status_code=429,
                                 headers={"Retry-After": "40"})
        done = self._Response({"id": "r", "status": "completed", "output_text": "done"})
        with self.assertLogs("fix_analysis", level="WARNING"):
            outcome, session, waits, guard, traces = self._run([limited, done])
        self.assertEqual(outcome, "done")
        self.assertEqual(waits, [40.0])
        self.assertEqual(traces[0]["create_retries"][0]["status"], 429)
        self.assertEqual(guard.checks, 2)
        attempts = len(OpenAIProvider.CREATE_RETRY_WAITS_SECONDS) + 1
        with self.assertLogs("fix_analysis", level="WARNING"):
            outcome, session, waits, _, _ = self._run([limited] * attempts)
        self.assertIsInstance(outcome, provider_module.ProviderTransientFailure)
        self.assertIsInstance(outcome, provider_module.BackgroundCreateRateLimited)
        self.assertEqual((session.posts, len(waits)), (attempts, attempts - 1))

    def test_a_response_cancelled_outside_the_call_is_charged_once_it_settles(self):
        # Review of 2026-11-09: a "cancelled" response is now sent again, and
        # its usage arrives only after the cancel; one that never reports
        # any is charged the upper bound, recorded for the rebuilt guards.
        cancelled = self._Response({"id": "r1", "status": "cancelled"})
        done = self._Response({"id": "r2", "status": "completed", "output_text": "done",
                               "usage": {"input_tokens": 4, "output_tokens": 1}})
        with self.assertLogs("fix_analysis", level="WARNING"):
            outcome, session, waits, guard, traces = self._run([cancelled, done])
        self.assertEqual(outcome, "done")
        estimate = {"input_tokens": 3, "output_tokens": 32768}
        self.assertEqual(traces[0]["failed_responses"][0]["guard_usage_estimate"], estimate)
        self.assertEqual(guard.added, [(3, 0, 32768, 0), (4, 0, 1, 0)])
        # A failed response is charged what it reports, with no extra read.
        failed = self._Response({"id": "r1", "status": "failed",
                                 "error": {"code": "server_error", "message": "boom"}})
        outcome, _, _, guard, traces = self._run([failed, done])
        self.assertEqual(outcome, "done")
        self.assertNotIn("guard_usage_estimate", traces[0]["failed_responses"][0])
        self.assertEqual(guard.added, [(4, 0, 1, 0)])

    def test_a_failed_response_shares_the_create_retries_and_charges_its_usage(self):
        # A response that ran and failed reports what it was billed: the
        # guard is charged before the same request goes again, and the trace
        # keeps it for a guard rebuilt from the traces.
        failed = self._Response({"id": "r1", "status": "failed", "service_tier": "default",
                                 "error": {"code": "server_error", "message": "boom"},
                                 "usage": {"input_tokens": 40, "output_tokens": 9}})
        done = self._Response({"id": "r2", "status": "completed", "output_text": "done",
                               "usage": {"input_tokens": 40, "output_tokens": 3}})
        outcome, session, waits, guard, traces = self._run([self._fault(), failed, done])

        self.assertEqual(outcome, "done")
        self.assertEqual(session.posts, 3)
        self.assertEqual(len(waits), 2)
        self.assertEqual([item["status"] for item in traces[0]["create_retries"]],
                         [500, "failed"])
        self.assertEqual(traces[0]["create_retries"][1]["error"], "server_error")
        self.assertEqual(guard.added, [(40, 0, 9, 0), (40, 0, 3, 0)])
        self.assertEqual(traces[0]["failed_responses"], [{
            "response_id": "r1", "status": "failed", "code": "server_error",
            "service_tier": "default", "input_tokens": 40, "cached_input_tokens": 0,
            "cache_write_input_tokens": 0, "output_tokens": 9, "web_search_calls": 0}])

    def test_failed_responses_and_server_faults_share_one_limit(self):
        failed = self._Response({"id": "r", "status": "failed",
                                 "error": {"code": "server_is_overloaded", "message": "x"}})
        attempts = len(OpenAIProvider.CREATE_RETRY_WAITS_SECONDS) + 1
        outcome, session, waits, _, traces = self._run(
            [self._fault(), *[failed] * (attempts - 1)])

        self.assertIsInstance(outcome, provider_module.BackgroundResponseFailed)
        self.assertEqual(session.posts, attempts)
        self.assertEqual(len(waits), attempts - 1)
        self.assertEqual(traces[0]["status"], "error")
        self.assertEqual(traces[0]["error_code"], "server_is_overloaded")
        self.assertEqual(len(traces[0]["failed_responses"]), attempts - 1)


class ContentRefusalTests(unittest.TestCase):
    """A refusal of the request's content is not a transport error.

    On 2026-09-07 OpenAI answered HTTP 400 with code "cyber_policy" to the
    first call of an analysis run, after 10min26s of web search. The generic
    RuntimeError it became took the whole finding down and failed the
    pipeline step. The verdict is on the text, so it is identical on every
    retry: callers need to recognise it, record it, and continue.
    """

    class _Response:
        def __init__(self, status_code, payload, text=""):
            self.status_code = status_code
            self._payload = payload
            self.text = text or json.dumps(payload)
            self.headers = {}

        def json(self):
            if self._payload is None:
                raise ValueError("not json")
            return self._payload

    def _provider(self):
        with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
            return OpenAIProvider(prompt_log_dir=None)

    def test_a_flagged_request_is_reported_as_a_content_refusal(self):
        response = self._Response(400, {"error": {
            "code": "cyber_policy",
            "message": "This content was flagged for possible cybersecurity risk.",
        }})
        self.assertEqual(
            self._provider()._content_refusal_code(response), "cyber_policy"
        )

    def test_a_server_fault_stays_an_ordinary_retryable_error(self):
        response = self._Response(503, {"error": {"code": "overloaded"}})
        self.assertEqual(self._provider()._content_refusal_code(response), "")

    def test_a_4xx_and_a_failed_response_classify_a_code_alike(self):
        # One classification (provider_error_kind) for both paths: a code is a
        # refusal in a 400 exactly when it is one in a failed response.
        provider = self._provider()
        codes = sorted(provider_module.CONTENT_VERDICT_CODES) + [
            "server_is_overloaded", "resource_unavailable", "server_error",
            "context_length_exceeded", "some_new_code"]
        for code in codes:
            with self.subTest(code=code):
                verdict = provider_module.provider_error_kind(code) == "content_verdict"
                http = provider._content_refusal_code(
                    self._Response(400, {"error": {"code": code, "message": "m"}}))
                self.assertEqual(http, code if verdict else "")
                with self.assertRaises(RuntimeError) as raised:
                    provider._raise_for_failed_response(
                        {"id": "r", "status": "failed", "error": {"code": code, "message": "m"}})
                self.assertEqual(isinstance(raised.exception, ProviderContentRefusal), verdict)
                self.assertEqual(isinstance(raised.exception,
                                            provider_module.ProviderTransientFailure), not verdict)
        self.assertEqual(provider_module.provider_error_kind("server_is_overloaded"), "capacity")
        self.assertEqual(provider_module.provider_error_kind("resource_unavailable"), "capacity")
        self.assertEqual(provider_module.provider_error_kind("cyber_policy"), "content_verdict")
        self.assertEqual(provider_module.provider_error_kind(""), "transient")

    def test_a_non_json_client_error_is_not_mistaken_for_a_refusal(self):
        response = self._Response(400, None, text="<html>bad gateway</html>")
        self.assertEqual(self._provider()._content_refusal_code(response), "")

    def test_the_refusal_carries_its_code_for_the_caller_to_record(self):
        refusal = ProviderContentRefusal("refused", code="cyber_policy",
                                         status_code=400)
        self.assertIsInstance(refusal, RuntimeError)
        self.assertEqual(refusal.code, "cyber_policy")
        self.assertEqual(refusal.status_code, 400)


class PerFindingCacheBypassTests(unittest.TestCase):
    """One run reuses the cache for every finding but the ones being refreshed."""

    ERROR = {
        "unique_error_id": "com.example.AppModuleKt:::appModule$lambda$0$3:::MessageDigestSpec",
        "method_name": "appModule$lambda$0$3",
        "relative_method_file": "com.example_1.apk/app/src/main/AppModule.kt",
    }

    def test_bypassed_reads_miss_but_the_fresh_response_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = LLMResponseCache(Path(directory), logging.getLogger(__name__))
            request = {"model": "example", "prompt": "hello"}
            cache.put(request, "old")
            with provider_module.cache_reads_bypassed(True):
                self.assertIsNone(cache.get(request))
                cache.put(request, "new")
            self.assertEqual(cache.get(request), "new")

    def test_the_bypass_is_confined_to_its_thread(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = LLMResponseCache(Path(directory), logging.getLogger(__name__))
            request = {"prompt": "shared"}
            cache.put(request, "cached")
            seen = []
            with provider_module.cache_reads_bypassed(True):
                worker = threading.Thread(target=lambda: seen.append(cache.get(request)))
                worker.start()
                worker.join()
            self.assertEqual(seen, ["cached"])

    def test_patterns_match_the_id_method_or_apk(self):
        matches = provider_module.finding_bypasses_cache
        self.assertTrue(matches(self.ERROR, ["appModule$lambda$0$3"]))
        self.assertTrue(matches(self.ERROR, ["com.example_1.apk"]))
        self.assertFalse(matches(self.ERROR, ["appModule$lambda$0$4"]))
        self.assertFalse(matches(self.ERROR, []))

    def test_patterns_are_read_from_the_environment(self):
        with unittest.mock.patch.dict(os.environ, {
            "TCC_LLM_CACHE_BYPASS_FINDINGS": "other;\nappModule$lambda$0$3\n",
        }):
            self.assertEqual(provider_module.cache_bypass_patterns(),
                             ["other", "appModule$lambda$0$3"])
            self.assertTrue(provider_module.finding_bypasses_cache(self.ERROR))
        with unittest.mock.patch.dict(os.environ, {"TCC_LLM_CACHE_BYPASS_FINDINGS": ""}):
            self.assertFalse(provider_module.finding_bypasses_cache(self.ERROR))

    def test_analysing_a_listed_finding_bypasses_reads_only_while_it_runs(self):
        from cognalys.llm.finding_processing import FindingProcessing

        with tempfile.TemporaryDirectory() as directory:
            cache = LLMResponseCache(Path(directory), logging.getLogger(__name__))
            cache.put({"prompt": "p"}, "cached")
            stub = unittest.mock.Mock()
            stub.logger = logging.getLogger(__name__)
            stub._analyse_one_within_budget.side_effect = lambda error: (
                error, FindingOutcome(cache.get({"prompt": "p"}), True, "", "", ""),
            )
            with unittest.mock.patch.dict(os.environ, {
                "TCC_LLM_CACHE_BYPASS_FINDINGS": "appModule$lambda$0$3",
            }):
                _, listed = FindingProcessing.analyse_one(stub, dict(self.ERROR))
                _, other = FindingProcessing.analyse_one(
                    stub, {"unique_error_id": "x:::other", "method_name": "other"})
            self.assertIsNone(listed.solution)
            self.assertEqual(other.solution, "cached")


class FindingReplayTests(unittest.TestCase):
    """An identical request made again within one finding is answered by its first answer.

    A replan adjudicates the finding again, and in runs without a usable
    persistent cache its research, synthesis, extraction and adjudication
    were paid for a second time, about US$ 0.20 per replanned finding, and a
    new sample of each was what the new plan rested on.
    """

    class _Session:
        """Answers each create synchronously with the next payload (the last one repeats)."""

        def __init__(self, *answers):
            self.answers = list(answers)
            self.payloads = []

        def close(self):
            pass

        def post(self, url, **kwargs):
            self.payloads.append(kwargs.get("json"))
            answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
            return BackgroundResponseTests._Response(answer)

        def get(self, url, **_kwargs):
            raise AssertionError("no poll expected")

    DONE = {"id": "r", "status": "completed", "output_text": "answer",
            "usage": {"input_tokens": 100, "output_tokens": 10}}

    def _provider(self, session, cache_dir=None, **kwargs):
        logs = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, logs, True)
        with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
            provider = OpenAIProvider(prompt_log_dir=Path(logs), cache_dir=cache_dir,
                                      **kwargs)
        provider.session = session
        provider.web_search_session = session
        provider._sleep = lambda _seconds: None
        provider._cost_guard = QueuedBackgroundResubmissionTests._Guard()
        return provider

    def _traces(self, provider):
        return sorted(
            (json.loads(path.read_text(encoding="utf-8"))
             for path in provider.prompt_log_dir.glob("*_metadata.json")),
            key=lambda record: record["call_id"])

    def test_inside_a_scope_the_second_identical_call_is_replayed(self):
        session = self._Session(self.DONE)
        provider = self._provider(session)
        with provider_module.finding_budget() as budget, \
                provider_module.finding_replay_scope():
            first = provider.generate("input", "system", trace_stage="adjudication")
            second = provider.generate("input", "system", trace_stage="adjudication")

        self.assertEqual((first, second), ("answer", "answer"))
        self.assertEqual(len(session.payloads), 1)
        sent, replayed = self._traces(provider)
        self.assertEqual(sent["delivery"], "sent_to_openai")
        self.assertEqual((replayed["delivery"], replayed["status"]),
                         ("finding_replay", "finding_replay"))
        self.assertEqual(replayed["replayed_call_id"], sent["call_id"])
        self.assertEqual(replayed["input_tokens"], 0)
        # Nothing billed: one charge to the guard, one call to the budget.
        self.assertEqual(provider._cost_guard.added, [(100, 0, 10, 0)])
        self.assertEqual(provider.token_usage, {"input": 100, "output": 10})
        self.assertEqual((budget.calls, budget.replayed_calls), (1, 1))
        self.assertEqual(budget.summary()["replayed_calls"], 1)
        self.assertEqual(provider.get_cache_stats()["replays"], 1)

    def test_a_different_request_is_sent(self):
        session = self._Session(self.DONE)
        provider = self._provider(session)
        with provider_module.finding_replay_scope():
            provider.generate("input", "system")
            provider.generate("input changed", "system")
            provider.generate("input", "other system")
        self.assertEqual(len(session.payloads), 3)

    def test_outside_a_scope_and_after_it_every_call_is_sent(self):
        session = self._Session(self.DONE)
        provider = self._provider(session)
        provider.generate("input")
        provider.generate("input")
        self.assertEqual(len(session.payloads), 2)
        with provider_module.finding_replay_scope() as memo:
            provider.generate("input")
        self.assertIsNone(provider_module.active_replay_memo())
        self.assertEqual(memo._responses, {})
        provider.generate("input")
        self.assertEqual(len(session.payloads), 4)

    def test_another_finding_never_sees_the_answers(self):
        session = self._Session(self.DONE)
        provider = self._provider(session)
        with provider_module.finding_replay_scope():
            provider.generate("input")
        with provider_module.finding_replay_scope():
            provider.generate("input")
        self.assertEqual(len(session.payloads), 2)
        # Nor does a finding analysed at the same time on another thread.
        with provider_module.finding_replay_scope():
            provider.generate("shared")
            worker = threading.Thread(target=lambda: provider.generate("shared"))
            worker.start()
            worker.join()
        self.assertEqual(len(session.payloads), 4)

    def test_research_at_ttl_zero_is_replayed_and_not_stored(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session(self.DONE)
            provider = self._provider(session, cache_dir=Path(directory),
                                      web_search_cache_ttl_seconds=0)
            with provider_module.finding_replay_scope():
                provider.generate("question", web_search=True)
                self.assertEqual(provider.generate("question", web_search=True), "answer")
            self.assertEqual(len(session.payloads), 1)
            self.assertIn("tools", session.payloads[0])
            self.assertEqual(list(Path(directory).rglob("*.json")), [])
            self.assertEqual(self._traces(provider)[1]["delivery"], "finding_replay")

    def test_reads_bypassed_for_the_finding_still_replay_within_it(self):
        # The user's decision (2026-11-09): the bypass refreshes the
        # persistent cache; it does not re-ask what this analysis asked.
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session(self.DONE)
            provider = self._provider(session, cache_dir=Path(directory))
            provider.generate("input")  # stored in the persistent cache
            with provider_module.cache_reads_bypassed(True), \
                    provider_module.finding_replay_scope():
                provider.generate("input")
                provider.generate("input")
            self.assertEqual(len(session.payloads), 2)
            deliveries = [record["delivery"] for record in self._traces(provider)]
            self.assertEqual(deliveries, ["sent_to_openai", "sent_to_openai",
                                          "finding_replay"])

    def test_a_cached_run_records_cache_hits_as_before(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session(self.DONE)
            provider = self._provider(session, cache_dir=Path(directory))
            with provider_module.finding_budget() as budget, \
                    provider_module.finding_replay_scope():
                provider.generate("input")
                provider.generate("input")
                provider.generate("question", web_search=True)
                provider.generate("question", web_search=True)
            deliveries = [record["delivery"] for record in self._traces(provider)]
            self.assertEqual(deliveries, ["sent_to_openai", "cache_hit",
                                          "sent_to_openai", "cache_hit"])
            self.assertEqual(budget.replayed_calls, 0)
            self.assertEqual(provider.get_cache_stats()["replays"], 0)

    def test_a_failed_or_incomplete_response_is_not_replayed(self):
        failed = {"id": "r", "status": "failed",
                  "error": {"code": "server_error", "message": "boom"}}
        incomplete = {"id": "r", "status": "incomplete", "output_text": "trunc",
                      "incomplete_details": {"reason": "max_output_tokens"}}
        session = self._Session(failed, incomplete, self.DONE)
        provider = self._provider(session)
        with provider_module.finding_replay_scope():
            # The failed response is sent again within the call (no verdict
            # on the text), and the incomplete answer it got is not replayed.
            self.assertEqual(provider.generate("input"), "trunc")
            self.assertEqual(provider.generate("input"), "answer")
            self.assertEqual(provider.generate("input"), "answer")
        self.assertEqual(len(session.payloads), 3)

    def test_only_a_completed_response_is_remembered(self):
        # Any status but "completed" holds whatever text it reached, in
        # either place the answer can come in. (A "cancelled" or "failed"
        # answer raises wherever it comes from, so it returns no text.)
        cut = {"id": "r", "status": "incomplete", "output_text": "partial",
               "usage": {"input_tokens": 3, "output_tokens": 1}}
        unstated = {"id": "r", "output": [{"content": [
            {"type": "output_text", "text": "no status"}]}]}
        session = self._Session(cut, unstated, self.DONE)
        provider = self._provider(session)
        with provider_module.finding_budget() as budget, \
                provider_module.finding_replay_scope():
            self.assertEqual(provider.generate("input"), "partial")
            self.assertEqual(provider.generate("input"), "no status")
            self.assertEqual(provider.generate("input"), "answer")
            self.assertEqual(provider.generate("input"), "answer")
        self.assertEqual(len(session.payloads), 3)
        self.assertEqual((budget.calls, budget.replayed_calls), (3, 1))

    def test_research_and_synthesis_replay_in_cascade(self):
        # The replayed brief is the stored text byte for byte, so the
        # synthesis prompt built on it is identical and replays too.
        brief = {"id": "r1", "status": "completed", "output_text": "brief é \n"}
        synthesis = {"id": "r2", "status": "completed", "output_text": '{"ok": true}'}
        session = self._Session(brief, synthesis)
        provider = self._provider(session)
        schema = {"type": "object", "properties": {}}
        with provider_module.finding_replay_scope():
            first = provider.generate("q", "s", json_mode=True, web_search=True,
                                      json_schema=schema, trace_stage="external_research")
            second = provider.generate("q", "s", json_mode=True, web_search=True,
                                       json_schema=schema, trace_stage="external_research")
        self.assertEqual(first, second)
        self.assertEqual(len(session.payloads), 2)
        stages = [(record["stage"], record["delivery"]) for record in self._traces(provider)]
        self.assertEqual(stages, [
            ("external_research.research", "sent_to_openai"),
            ("external_research.synthesis", "sent_to_openai"),
            ("external_research.research", "finding_replay"),
            ("external_research.synthesis", "finding_replay"),
        ])

    def test_a_replay_is_counted_apart_and_never_billed_by_the_reports(self):
        from cognalys.llm import cost

        session = self._Session(self.DONE)
        provider = self._provider(session)
        context = {"finding_id": "a.B:::m:::CipherSpec:::0"}
        with provider_module.finding_replay_scope():
            provider.generate("input", trace_stage="adjudication", trace_context=context)
            provider.generate("input", trace_stage="adjudication", trace_context=context)
        prices = {provider.model: {"input": 1.0, "cached_input": 0.5, "output": 2.0}}
        report = cost.usage(provider.prompt_log_dir, prices)
        self.assertEqual((report["calls"], report["replays"], report["cache_hits"]), (1, 1, 0))
        self.assertEqual(report["input_tokens"], 100)
        self.assertEqual(report["by_stage"]["adjudication"]["replays"], 1)
        self.assertIn("1 replayed within their finding",
                      "\n".join(cost.summary_lines(report)))
        by_finding = cost.usage_by_finding(provider.prompt_log_dir, prices)
        self.assertEqual(by_finding[("a.B", "m", "CipherSpec")]["calls"], 1)
        self.assertNotIn(cost.REPLAY_DELIVERY, cost.PAID_DELIVERIES)

    def test_analysing_a_unit_opens_one_scope_for_it(self):
        from cognalys.llm.finding_processing import FindingProcessing

        session = self._Session(self.DONE)
        provider = self._provider(session)
        stub = unittest.mock.Mock()
        stub.logger = logging.getLogger(__name__)
        stub._analyse_one_within_budget.side_effect = lambda error: (
            error, FindingOutcome([provider.generate("input"), provider.generate("input")],
                                  True, "", "", ""),
        )
        _, first = FindingProcessing.analyse_one(stub, {"method_name": "a"})
        _, second = FindingProcessing.analyse_one(stub, {"method_name": "b"})
        self.assertEqual(len(session.payloads), 2)
        self.assertEqual(first.llm_budget["replayed_calls"], 1)
        self.assertEqual((second.llm_budget["calls"], second.llm_budget["replayed_calls"]),
                         (1, 1))
        self.assertIsNone(provider_module.active_replay_memo())

    def test_the_bypass_applies_to_a_listed_unit_and_its_replays_still_work(self):
        from cognalys.llm.finding_processing import FindingProcessing

        with tempfile.TemporaryDirectory() as directory:
            session = self._Session(self.DONE)
            provider = self._provider(session, cache_dir=Path(directory))
            provider.generate("input")
            stub = unittest.mock.Mock()
            stub.logger = logging.getLogger(__name__)
            stub._analyse_one_within_budget.side_effect = lambda error: (
                error, FindingOutcome([provider.generate("input"),
                                       provider.generate("input")], True, "", "", ""),
            )
            with unittest.mock.patch.dict(os.environ, {
                "TCC_LLM_CACHE_BYPASS_FINDINGS": "listed",
            }):
                _, result = FindingProcessing.analyse_one(stub, {"method_name": "listed"})
            self.assertEqual(len(session.payloads), 2)
            self.assertEqual((result.llm_budget["calls"], result.llm_budget["replayed_calls"]),
                             (1, 1))


class ResearchCorpusProviderTests(unittest.TestCase):
    """A shared research request served from, or stored in, the research corpus."""

    _Session = FindingReplayTests._Session
    BRIEF = {"id": "r1", "status": "completed", "output_text": "brief https://docs.example/a",
             "usage": {"input_tokens": 100, "output_tokens": 10}}
    ANSWER = json.dumps({"sources": [{"url": "https://docs.example/a"}]})
    SYNTHESIS = {"id": "r2", "status": "completed", "output_text": ANSWER,
                 "usage": {"input_tokens": 50, "output_tokens": 5}}
    SCHEMA = {"type": "object", "properties": {}}
    SCOPE = {"kind": "governed_api_and_rule", "specification": "CipherSpec"}

    def setUp(self):
        self.corpus_dir = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.corpus_dir, True)

    def _provider(self, session, corpus=True, **kwargs):
        from cognalys.llm.research_corpus import ResearchCorpus

        provider = FindingReplayTests._provider(self, session, **kwargs)
        if corpus:
            provider.research_corpus = ResearchCorpus(self.corpus_dir)
        return provider

    def _traces(self, provider):
        return FindingReplayTests._traces(self, provider)

    def _research(self, provider, scope="default", prompt="questions"):
        return provider.generate(prompt, "system", json_mode=True, web_search=True,
                                 json_schema=self.SCHEMA, schema_name="external_research_v2",
                                 trace_stage="external_research",
                                 research_corpus_scope=self.SCOPE if scope == "default" else scope)

    def test_without_a_corpus_the_two_passes_are_sent_as_before(self):
        session = self._Session(self.BRIEF, self.SYNTHESIS)
        provider = self._provider(session, corpus=False)
        self.assertEqual(self._research(provider), self.ANSWER)
        research, synthesis = session.payloads
        self.assertEqual(research["instructions"], (
            "system\n\nFor this research pass, use web search as needed. Return a factual "
            "research brief and include direct source URLs in the text. Do not omit "
            "uncertainty or source limits."))
        self.assertEqual(research["input"], "questions")
        self.assertEqual(research["tools"],
                         [{"type": "web_search_preview", "search_context_size": "medium"}])
        self.assertEqual(synthesis["instructions"], "system")
        self.assertEqual(synthesis["input"], (
            "questions\n\nWEB RESEARCH RESULT:\nbrief https://docs.example/a\n\nProduce the "
            "originally requested JSON using the research above as additional evidence. "
            "Preserve direct source URLs and do not add claims unsupported by either the "
            "original input or the research result."))
        self.assertNotIn("tools", synthesis)
        self.assertEqual(list(self.corpus_dir.iterdir()), [])

    def test_a_miss_researches_and_stores_and_the_next_request_is_served(self):
        session = self._Session(self.BRIEF, self.SYNTHESIS)
        provider = self._provider(session)
        with provider_module.finding_budget() as budget:
            self.assertEqual(self._research(provider), self.ANSWER)
            self.assertEqual(self._research(provider), self.ANSWER)
        self.assertEqual(len(session.payloads), 2)
        served = self._traces(provider)[-1]
        self.assertEqual((served["delivery"], served["status"]),
                         ("research_corpus", "research_corpus"))
        self.assertEqual(served["stage"], "external_research")
        self.assertEqual(served["input_tokens"], 0)
        self.assertEqual(served["research_corpus"]["origin"], "run")
        # One charge per pass sent, none for the served answer.
        self.assertEqual(len(provider._cost_guard.added), 2)
        self.assertEqual(budget.calls, 2)
        stats = provider.research_corpus.stats()
        self.assertEqual((stats["stored"], stats["hits"]), (1, 1))
        entry = json.loads(next(self.corpus_dir.glob("*.json")).read_text(encoding="utf-8"))
        self.assertEqual(entry["scope"], self.SCOPE)
        self.assertEqual(entry["research_text"], self.BRIEF["output_text"])
        self.assertEqual(entry["provenance"]["web_search_calls"], 0)

    def test_an_incomplete_research_answer_is_not_stored(self):
        session = self._Session({**self.BRIEF, "status": "incomplete"}, self.SYNTHESIS)
        provider = self._provider(session)
        self.assertEqual(self._research(provider), self.ANSWER)
        self.assertEqual(list(self.corpus_dir.glob("*.json")), [])

    def test_without_a_scope_the_corpus_is_not_consulted(self):
        session = self._Session(self.BRIEF, self.SYNTHESIS)
        provider = self._provider(session)
        self._research(provider, scope=None)
        self._research(provider, scope=None)
        self.assertEqual(len(session.payloads), 4)
        self.assertEqual(list(self.corpus_dir.glob("*.json")), [])

    def test_a_hit_does_not_depend_on_the_response_cache_or_its_ttl(self):
        self._research(self._provider(self._Session(self.BRIEF, self.SYNTHESIS)))
        for kwargs in ({"cache_dir": None, "web_search_cache_ttl_seconds": 0},
                       {"cache_dir": Path(tempfile.mkdtemp()),
                        "web_search_cache_ttl_seconds": 7 * 24 * 3600}):
            with self.subTest(**{key: str(value) for key, value in kwargs.items()}):
                session = self._Session(self.BRIEF)
                self.assertEqual(self._research(self._provider(session, **kwargs)), self.ANSWER)
                self.assertEqual(session.payloads, [])

    def test_another_effort_or_model_misses(self):
        self._research(self._provider(self._Session(self.BRIEF, self.SYNTHESIS)))
        for kwargs in ({"reasoning_effort": "medium"}, {"model": "gpt-other"},
                       {"max_output_tokens": 16000}):
            with self.subTest(**kwargs):
                session = self._Session(self.BRIEF, self.SYNTHESIS)
                self._research(self._provider(session, **kwargs))
                self.assertEqual(len(session.payloads), 2)
        effort = self._provider(self._Session(self.BRIEF, self.SYNTHESIS))
        session = effort.session
        with provider_module.research_reasoning_effort(effort, "low"):
            self._research(effort)
        self.assertEqual(len(session.payloads), 2)

    def test_passes_sent_at_another_effort_than_the_key_are_not_stored(self):
        # Another worker's research_reasoning_effort restores the shared
        # provider's effort between the key and the passes it sends.
        provider = self._provider(None)

        class Session(self._Session):
            def post(inner, url, **kwargs):
                provider.reasoning_effort = "medium"
                return super().post(url, **kwargs)

        session = Session(self.BRIEF, self.SYNTHESIS)
        provider.session = provider.web_search_session = session
        self.assertEqual(self._research(provider), self.ANSWER)
        self.assertEqual(len(session.payloads), 2)
        self.assertEqual(list(self.corpus_dir.glob("*.json")), [])

    def test_research_answered_by_the_ttl_cache_or_a_replay_is_not_stored(self):
        cache_dir = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, cache_dir, True)
        # Fill the response cache without a corpus, then ask with one.
        self._research(self._provider(self._Session(self.BRIEF, self.SYNTHESIS), corpus=False,
                                      cache_dir=cache_dir))
        session = self._Session(self.BRIEF)
        provider = self._provider(session, cache_dir=cache_dir)
        self.assertEqual(self._research(provider), self.ANSWER)
        self.assertEqual(session.payloads, [])
        self.assertEqual(list(self.corpus_dir.glob("*.json")), [])
        # A research pass the finding's per-call replay answered is not stored either.
        session = self._Session(self.BRIEF, self.SYNTHESIS)
        provider = self._provider(session)
        with provider_module.finding_replay_scope():
            provider.generate("questions", "system" + "\n\nFor this research pass, use web "
                              "search as needed. Return a factual research brief and include "
                              "direct source URLs in the text. Do not omit uncertainty or "
                              "source limits.", web_search=True,
                              trace_stage="external_research.research")
            self._research(provider)
        self.assertEqual(len(session.payloads), 2)
        self.assertEqual(list(self.corpus_dir.glob("*.json")), [])

    def test_a_frozen_experiment_is_served_and_stores_nothing(self):
        self._research(self._provider(self._Session(self.BRIEF, self.SYNTHESIS)))
        with unittest.mock.patch.dict(os.environ, {"TCC_FROZEN_EXPERIMENT": "1"}):
            session = self._Session(self.BRIEF, self.SYNTHESIS)
            self.assertEqual(self._research(self._provider(session)), self.ANSWER)
            self.assertEqual(session.payloads, [])
            # A miss is not researched (the synthesis reads an empty brief), nothing stored.
            session = self._Session(self.SYNTHESIS)
            self._research(self._provider(session), prompt="other questions")
            self.assertEqual(len(session.payloads), 1)
            self.assertNotIn("tools", session.payloads[0])
            self.assertEqual(len(list(self.corpus_dir.glob("*.json"))), 1)
            # With live research declared, a miss is researched and stored.
            with unittest.mock.patch.dict(os.environ, {"TCC_EXPERIMENT_LIVE_RESEARCH": "1"}):
                session = self._Session(self.BRIEF, self.SYNTHESIS)
                self._research(self._provider(session), prompt="other questions")
                self.assertEqual(len(session.payloads), 2)
            self.assertEqual(len(list(self.corpus_dir.glob("*.json"))), 2)

    def test_a_replan_reads_the_first_shared_answer_of_its_finding(self):
        from cognalys.llm.research_corpus import entry_key

        session = self._Session(self.BRIEF, self.SYNTHESIS)
        provider = self._provider(session)
        with provider_module.finding_replay_scope():
            first = self._research(provider)
            # Another run's answer lands in the corpus between the two passes.
            path = next(self.corpus_dir.glob("*.json"))
            entry = json.loads(path.read_text(encoding="utf-8"))
            other = json.dumps({"sources": [{"url": "https://other.example"}]})
            entry.update(response=other,
                         response_sha256=__import__("hashlib").sha256(other.encode()).hexdigest())
            path.write_text(json.dumps(entry), encoding="utf-8")
            self.assertEqual(path.stem, entry_key(entry["request"]))
            second = self._research(provider)
        self.assertEqual((first, second), (self.ANSWER, self.ANSWER))
        replayed = self._traces(provider)[-1]
        self.assertEqual((replayed["delivery"], replayed["status"]),
                         ("finding_replay", "finding_replay"))
        self.assertEqual(replayed["stage"], "external_research")
        # Outside the finding, the corpus answers.
        self.assertEqual(self._research(provider), other)

    def test_cache_reads_bypassed_skip_the_corpus_and_keep_the_entry(self):
        self._research(self._provider(self._Session(self.BRIEF, self.SYNTHESIS)))
        path = next(self.corpus_dir.glob("*.json"))
        before = path.read_bytes()
        later = json.dumps({"sources": [{"url": "https://later.example"}]})
        session = self._Session(self.BRIEF, {**self.SYNTHESIS, "output_text": later})
        provider = self._provider(session)
        with provider_module.cache_reads_bypassed(True):
            self.assertEqual(self._research(provider), later)
        self.assertEqual(len(session.payloads), 2)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(provider.research_corpus.stats()["kept"], 1)

    def test_a_research_trace_records_its_web_search_tool(self):
        provider = self._provider(self._Session(self.BRIEF, self.SYNTHESIS), corpus=False)
        self._research(provider)
        logs = provider.prompt_log_dir
        research = json.loads(next(logs.glob("*research_request.json")).read_text(encoding="utf-8"))
        synthesis = json.loads(next(logs.glob("*synthesis_request.json")).read_text(
            encoding="utf-8"))
        self.assertEqual(research["web_search_tool"],
                         {"type": "web_search_preview", "search_context_size": "medium"})
        self.assertNotIn("web_search_tool", synthesis)


class OllamaFindingReplayTests(unittest.TestCase):
    """The Ollama provider replays within a finding on the same terms.

    Its persistent cache already answers a repeated prompt, sampled or not,
    with the stored text; the memo does the same for a run without one, and
    keeps out an answer cut off at the output limit.
    """

    class _Response:
        status_code = 200
        reason = "OK"
        text = ""

        def __init__(self, payload):
            self.payload = payload

        def json(self):
            return self.payload

    class _Session:
        def __init__(self, *answers):
            self.answers = list(answers)
            self.payloads = []

        def post(self, url, **kwargs):
            self.payloads.append(kwargs.get("json"))
            answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
            return OllamaFindingReplayTests._Response(answer)

    DONE = {"response": "answer", "done_reason": "stop",
            "prompt_eval_count": 50, "eval_count": 5}

    def _provider(self, session, cache_dir=None):
        provider = provider_module.OllamaProvider(cache_dir=cache_dir,
                                                  logger=logging.getLogger(__name__))
        provider.session = session
        return provider

    def test_inside_a_scope_the_second_identical_call_is_replayed(self):
        session = self._Session(self.DONE)
        provider = self._provider(session)
        with provider_module.finding_budget() as budget, \
                provider_module.finding_replay_scope():
            first = provider.generate("input", "system")
            second = provider.generate("input", "system")
        self.assertEqual((first, second), ("answer", "answer"))
        self.assertEqual(len(session.payloads), 1)
        self.assertEqual((budget.calls, budget.replayed_calls), (1, 1))
        self.assertEqual(provider.token_usage, {"input": 50, "output": 5})
        self.assertEqual(provider.cache.stats()["replays"], 1)

    def test_outside_a_scope_every_call_is_sent(self):
        session = self._Session(self.DONE)
        provider = self._provider(session)
        with provider_module.finding_budget() as budget:
            provider.generate("input")
            provider.generate("input")
            self.assertEqual(len(session.payloads), 2)
            # Nor is an answer given inside a scope replayed after it ends.
            with provider_module.finding_replay_scope() as memo:
                provider.generate("input")
            self.assertEqual(memo._responses, {})
            provider.generate("input")
        self.assertEqual(len(session.payloads), 4)
        self.assertEqual((budget.calls, budget.replayed_calls), (4, 0))
        self.assertEqual(provider.cache.stats()["replays"], 0)

    def test_an_answer_cut_at_the_output_limit_is_sent_again(self):
        truncated = {"response": "trunc", "done_reason": "length"}
        session = self._Session(truncated, self.DONE)
        provider = self._provider(session)
        with provider_module.finding_budget() as budget, \
                provider_module.finding_replay_scope():
            self.assertEqual(provider.generate("input"), "trunc")
            self.assertEqual(provider.generate("input"), "answer")
            self.assertEqual(provider.generate("input"), "answer")
        self.assertEqual(len(session.payloads), 2)
        self.assertEqual((budget.calls, budget.replayed_calls), (2, 1))

    def test_a_cached_run_answers_from_the_persistent_cache_first(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self._Session(self.DONE)
            provider = self._provider(session, cache_dir=Path(directory))
            with provider_module.finding_replay_scope():
                provider.generate("input")
                provider.generate("input")
            self.assertEqual(len(session.payloads), 1)
            self.assertEqual(provider.cache.stats(),
                             {"hits": 1, "misses": 1, "replays": 0})


class FlexServiceTierTests(unittest.TestCase):
    """Calls ask for the Flex tier and fall back to the standard one.

    Flex bills tokens at half price but answers 429 when it lacks capacity
    (unbilled; OpenAI's guide says to resend on the standard tier) and may
    leave a response queued. Neither may cost the finding its analysis.
    """

    class _Session(QueuedBackgroundResubmissionTests._Session):
        """Creates answer ``creates`` in order first (an HTTP error, or a status)."""

        def __init__(self, polls_by_id, clock, creates=(), cancel_answers=None):
            super().__init__(polls_by_id, clock, cancel_answers)
            self.creates = list(creates)

        def post(self, url, **kwargs):
            if "json" in kwargs:
                # The provider edits its payload between attempts: keep
                # each one as it was sent.
                kwargs = {**kwargs, "json": json.loads(json.dumps(kwargs["json"]))}
            if not url.endswith("/cancel") and self.creates:
                answer = self.creates.pop(0)
                response_id = f"resp-{len(self.created) + 1}"
                self.created.append((response_id, kwargs.get("json")))
                if answer.status_code == 200:
                    answer._payload = {"id": response_id, **answer._payload}
                return answer
            return super().post(url, **kwargs)

    @staticmethod
    def _http(status, code, message="", param=None):
        error = {"code": code, "message": message or code, "param": param}
        return BackgroundResponseTests._Response({"error": error}, status_code=status)

    @staticmethod
    def _completed(tier="default"):
        return {"status": "completed", "output_text": "done", "service_tier": tier,
                "usage": {"input_tokens": 7, "output_tokens": 2}}

    def _run(self, polls_by_id=None, creates=(), tier="flex", timeout=250, cache_dir=None,
             clock=None, cancel_answers=None, sleep_advances_clock=False):
        clock = clock if clock is not None else [0.0]
        session = self._Session(polls_by_id or {}, clock, creates, cancel_answers)
        directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, directory, True)
        with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
            provider = OpenAIProvider(prompt_log_dir=Path(directory), cache_dir=cache_dir,
                                      timeout=timeout, service_tier=tier)
        provider.session = session
        provider.web_search_session = session
        # Every wait the call asked for, none of them slept.
        self.sleeps = []

        def sleep(seconds):
            self.sleeps.append(seconds)
            if sleep_advances_clock:
                clock[0] += seconds

        provider._sleep = sleep
        provider._cost_guard = QueuedBackgroundResubmissionTests._Guard()
        with unittest.mock.patch.object(provider_module.time, "monotonic", lambda: clock[0]), \
                provider_module.finding_budget() as budget:
            try:
                outcome = provider.generate("input")
            except Exception as exc:  # noqa: BLE001
                outcome = exc
        # The finding's CallBudget the call was charged to.
        self.budget = budget
        traces = [json.loads(path.read_text(encoding="utf-8"))
                  for path in Path(directory).glob("*_metadata.json")]
        return outcome, session, provider, traces

    def test_the_tier_is_configured_by_argument_then_environment_then_auto(self):
        with unittest.mock.patch.dict(os.environ, {provider_module.SERVICE_TIER_VARIABLE: "Flex"}):
            self.assertEqual(provider_module.configured_service_tier(), "flex")
            self.assertEqual(provider_module.configured_service_tier("default"), "default")
        with unittest.mock.patch.dict(os.environ, {provider_module.SERVICE_TIER_VARIABLE: ""}):
            self.assertEqual(provider_module.configured_service_tier(), "auto")
        with self.assertRaises(ValueError):
            provider_module.configured_service_tier("cheap")
        from cognalys.orchestration import run_pipeline
        self.assertEqual(run_pipeline.parse_args(["--llm-provider", "openai"]).llm_service_tier, "flex")
        self.assertEqual(run_pipeline.parse_args(
            ["--llm-provider", "openai", "--llm-service-tier", "auto"]).llm_service_tier, "auto")

    def test_flex_is_sent_beside_background_and_auto_sends_no_tier(self):
        outcome, session, provider, traces = self._run(
            creates=[BackgroundResponseTests._Response(self._completed("flex"))])
        self.assertEqual(outcome, "done")
        payload = session.created[0][1]
        self.assertEqual((payload["service_tier"], payload["background"]), ("flex", True))
        self.assertEqual(traces[0]["requested_service_tier"], "flex")
        self.assertEqual(traces[0]["service_tier"], "flex")
        self.assertEqual(traces[0]["service_tier_fallbacks"], [])
        self.assertEqual(provider._cost_guard.billing, [("flex", 0)])
        _, session, _, traces = self._run(
            creates=[BackgroundResponseTests._Response(self._completed())], tier="auto")
        self.assertNotIn("service_tier", session.created[0][1])
        self.assertEqual(traces[0]["requested_service_tier"], "")

    def test_the_tier_is_not_part_of_the_cache_key(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            self._run(creates=[BackgroundResponseTests._Response(self._completed("flex"))],
                      cache_dir=Path(cache_dir))
            outcome, session, _, traces = self._run(tier="auto", cache_dir=Path(cache_dir))
        self.assertEqual(outcome, "done")
        self.assertEqual(session.created, [])
        self.assertEqual(traces[0]["status"], "cache_hit")

    def test_a_429_to_a_flex_call_is_resent_on_the_standard_tier(self):
        with self.assertLogs("fix_analysis", level="WARNING") as logs:
            outcome, session, provider, traces = self._run(creates=[
                self._http(429, "resource_unavailable", "Resource Unavailable"),
                BackgroundResponseTests._Response(self._completed()),
            ])
        self.assertEqual(outcome, "done")
        first, second = (payload for _, payload in session.created)
        self.assertEqual(first["service_tier"], "flex")
        self.assertNotIn("service_tier", second)
        self.assertEqual({k: v for k, v in first.items() if k != "service_tier"}, second)
        self.assertTrue(any("standard tier" in line and "rate_limited" in line
                            for line in logs.output))
        self.assertEqual(traces[0]["status"], "success")
        self.assertEqual(traces[0]["service_tier_fallbacks"], [
            {"from": "flex", "reason": "rate_limited", "detail": "resource_unavailable"}])
        self.assertEqual(traces[0]["service_tier"], "default")
        # Charged once, at the tier that served it; the ceiling checked again.
        self.assertEqual(provider._cost_guard.added, [(7, 0, 2, 0)])
        self.assertEqual(provider._cost_guard.billing, [("default", 0)])
        self.assertEqual(provider._cost_guard.checks, 2)

    # agent_baseline_20261108 run_v4/run_v5 (2026-11-09): Flex responses
    # failed with server_is_overloaded seconds after their create, read whole
    # at the create (or its stream's terminal event) or by a poll.
    _OVERLOADED = {"status": "failed", "service_tier": "flex",
                   "error": {"code": "server_is_overloaded",
                             "message": "Our servers are currently overloaded. "
                                        "Please try again later."}}

    def _capacity_failures(self, failures, then, polled):
        """Creates and polls: ``failures`` Flex capacity failures, then ``then``."""
        if not polled:
            return [BackgroundResponseTests._Response(dict(self._OVERLOADED))
                    for _ in range(failures)] + [BackgroundResponseTests._Response(then)], {}
        creates = [BackgroundResponseTests._Response({"status": "queued"})
                   for _ in range(failures)] + [BackgroundResponseTests._Response(then)]
        polls = {f"resp-{index}": [{"id": f"resp-{index}", **self._OVERLOADED}]
                 for index in range(1, failures + 1)}
        return creates, polls

    def test_a_flex_response_failed_for_capacity_is_resent_on_flex_after_a_wait(self):
        # The C arm of 2026-11-13: 30 of 750 calls left Flex at once, and
        # another Flex call succeeded within 180 s for 26 of them.
        for polled in (False, True):
            with self.subTest(polled=polled):
                creates, polls = self._capacity_failures(1, self._completed("flex"), polled)
                with self.assertLogs("fix_analysis", level="WARNING") as logs:
                    outcome, session, provider, traces = self._run(
                        polls_by_id=polls, creates=creates)
                self.assertEqual(outcome, "done")
                self.assertEqual([payload["service_tier"] for _, payload in session.created],
                                 ["flex", "flex"])
                self.assertIn(60.0, self.sleeps)
                self.assertTrue(any("flex again in 60s" in line for line in logs.output))
                self.assertFalse(any("standard tier" in line for line in logs.output))
                self.assertEqual(traces[0]["status"], "success")
                self.assertEqual(traces[0]["service_tier_fallbacks"], [])
                self.assertEqual(traces[0]["flex_retries"], [
                    {"reason": "flex_retry", "detail": "server_is_overloaded",
                     "waited_s": 60.0, "response_id": "resp-1"}])
                self.assertEqual(traces[0]["service_tier"], "flex")
                # Not a create retry; the failed response charged nothing, the
                # answer at Flex; the ceiling checked again.
                self.assertEqual(traces[0]["create_retries"], [])
                self.assertEqual(traces[0]["failed_responses"][0]["code"], "server_is_overloaded")
                self.assertEqual(provider._cost_guard.added, [(7, 0, 2, 0)])
                self.assertEqual(provider._cost_guard.billing, [("flex", 0)])
                self.assertEqual(provider._cost_guard.checks, 2)

    def test_repeated_flex_capacity_failures_go_on_the_standard_tier_after_the_waits(self):
        for polled in (False, True):
            with self.subTest(polled=polled):
                creates, polls = self._capacity_failures(3, self._completed(), polled)
                with self.assertLogs("fix_analysis", level="WARNING") as logs:
                    outcome, session, provider, traces = self._run(
                        polls_by_id=polls, creates=creates)
                self.assertEqual(outcome, "done")
                self.assertEqual([payload.get("service_tier", "")
                                  for _, payload in session.created],
                                 ["flex", "flex", "flex", ""])
                self.assertEqual([wait for wait in self.sleeps if wait in (60.0, 120.0)],
                                 [60.0, 120.0])
                self.assertTrue(any("standard tier" in line and "overloaded" in line
                                    for line in logs.output))
                self.assertEqual([item["waited_s"] for item in traces[0]["flex_retries"]],
                                 [60.0, 120.0])
                self.assertEqual(traces[0]["service_tier_fallbacks"], [
                    {"from": "flex", "reason": "overloaded", "detail": "server_is_overloaded",
                     "response_id": "resp-3"}])
                self.assertEqual(traces[0]["service_tier"], "default")
                self.assertEqual(traces[0]["create_retries"], [])
                self.assertEqual(len(traces[0]["failed_responses"]), 3)
                self.assertEqual(provider._cost_guard.added, [(7, 0, 2, 0)])
                self.assertEqual(provider._cost_guard.checks, 4)

    def test_a_flex_wait_past_the_flex_deadline_is_not_made_and_is_not_model_time(self):
        # The call's time on Flex plus the next wait stays inside the Flex
        # deadline; the wait taken is capacity, not model time.
        creates, _ = self._capacity_failures(2, self._completed(), polled=False)
        with unittest.mock.patch.object(OpenAIProvider, "FLEX_DEADLINE_SECONDS", 100), \
                self.assertLogs("fix_analysis", level="WARNING"):
            outcome, session, _, traces = self._run(creates=creates, sleep_advances_clock=True)
        self.assertEqual(outcome, "done")
        self.assertEqual([payload.get("service_tier", "") for _, payload in session.created],
                         ["flex", "flex", ""])
        self.assertEqual(self.sleeps, [60.0])
        self.assertEqual(len(traces[0]["flex_retries"]), 1)
        self.assertEqual(traces[0]["service_tier_fallbacks"][0]["reason"], "overloaded")
        self.assertAlmostEqual(self.budget.seconds, 0.0)

    def test_a_content_refusal_is_never_resent_on_flex(self):
        # CAPACITY_ERROR_CODES stays apart from the content verdicts (the
        # defect of 2026-11-09 read a capacity failure as a refusal).
        self.assertFalse(provider_module.CAPACITY_ERROR_CODES
                         & provider_module.CONTENT_VERDICT_CODES)
        code = sorted(provider_module.CONTENT_VERDICT_CODES)[0]
        refused = {"status": "failed", "service_tier": "flex",
                   "error": {"code": code, "message": "flagged"}}
        for creates in ([BackgroundResponseTests._Response(refused)],
                        [self._http(400, code, "flagged")]):
            with self.subTest(creates=creates[0].status_code):
                outcome, session, _, traces = self._run(creates=list(creates))
                self.assertIsInstance(outcome, ProviderContentRefusal)
                self.assertEqual(len(session.created), 1)
                self.assertEqual(self.sleeps, [])
                self.assertEqual(traces[0]["flex_retries"], [])

    def test_a_capacity_failure_reporting_usage_is_charged_at_flex(self):
        overloaded = {"status": "failed", "service_tier": "flex",
                      "error": {"code": "resource_unavailable", "message": "busy"},
                      "usage": {"input_tokens": 11, "output_tokens": 5}}
        outcome, _, provider, traces = self._run(creates=[
            BackgroundResponseTests._Response(overloaded),
            BackgroundResponseTests._Response(self._completed())])
        self.assertEqual(outcome, "done")
        self.assertEqual(provider._cost_guard.added, [(11, 0, 5, 0), (7, 0, 2, 0)])
        self.assertEqual(provider._cost_guard.billing, [("flex", 0), ("default", 0)])
        self.assertEqual(traces[0]["failed_responses"][0]["service_tier"], "flex")

    def test_a_flex_server_fault_is_sent_again_on_flex(self):
        # Only a capacity failure leaves the tier; a server fault is resent
        # as a create that failed on OpenAI's side is.
        fault = {"status": "failed", "error": {"code": "server_error", "message": "boom"}}
        outcome, session, _, traces = self._run(creates=[
            BackgroundResponseTests._Response(fault),
            BackgroundResponseTests._Response(self._completed("flex"))])
        self.assertEqual(outcome, "done")
        self.assertEqual([payload["service_tier"] for _, payload in session.created],
                         ["flex", "flex"])
        self.assertEqual(traces[0]["service_tier_fallbacks"], [])
        self.assertEqual(traces[0]["create_retries"][0]["error"], "server_error")

    def test_a_research_call_failed_for_capacity_is_answered_on_the_standard_tier(self):
        # The research pass and its synthesis (web_search with json_mode) each
        # leave Flex on capacity failures that outlast the Flex waits;
        # neither ends as a refusal.
        overloaded = {"status": "failed", "service_tier": "flex",
                      "error": {"code": "server_is_overloaded", "message": "overloaded"}}
        failures = len(OpenAIProvider.FLEX_RETRY_WAITS_SECONDS) + 1
        session = self._Session({}, [0.0], creates=[
            BackgroundResponseTests._Response(dict(overloaded)) for _ in range(failures)] + [
            BackgroundResponseTests._Response(self._completed())] + [
            BackgroundResponseTests._Response(dict(overloaded)) for _ in range(failures)] + [
            BackgroundResponseTests._Response({**self._completed(), "output_text": "{}"})])
        with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
            provider = OpenAIProvider(prompt_log_dir=None, cache_dir=None, timeout=250,
                                      service_tier="flex")
        provider.session = session
        provider.web_search_session = session
        provider._sleep = lambda _seconds: None
        with self.assertLogs("fix_analysis", level="WARNING"):
            answer = provider.generate("question", json_mode=True, web_search=True,
                                       json_schema={"type": "object"})
        self.assertEqual(answer, "{}")
        tiers = [payload.get("service_tier", "") for _, payload in session.created]
        self.assertEqual(tiers, (["flex"] * failures + [""]) * 2)

    def test_an_exhausted_quota_is_not_resent_on_either_tier(self):
        # A standard 429 for any other code waits and is sent again
        # (CreateServerFaultRetryTests).
        for tier in ("flex", "default"):
            with self.subTest(tier=tier):
                outcome, session, _, traces = self._run(creates=[
                    self._http(429, "insufficient_quota")], tier=tier)
                self.assertIsInstance(outcome, RuntimeError)
                self.assertNotIsInstance(outcome, provider_module.ProviderTransientFailure)
                self.assertIn("HTTP 429", str(outcome))
                self.assertEqual(len(session.created), 1)
                self.assertEqual(traces[0]["status"], "error")

    def test_a_flex_create_answered_5xx_for_capacity_takes_the_flex_waits_not_the_create_ones(self):
        # Review of 2026-11-09: a 503 server_is_overloaded to a Flex create
        # stayed on Flex through the four create waits (about 5 minutes). It
        # takes the Flex waits instead: answered on Flex after one, or on the
        # standard tier after both.
        with self.assertLogs("fix_analysis", level="WARNING"):
            outcome, session, _, traces = self._run(creates=[
                self._http(503, "server_is_overloaded"),
                BackgroundResponseTests._Response(self._completed("flex"))])
        self.assertEqual(outcome, "done")
        self.assertEqual([payload.get("service_tier", "") for _, payload in session.created],
                         ["flex", "flex"])
        self.assertEqual(self.sleeps, [60.0])
        self.assertEqual(traces[0]["flex_retries"], [
            {"reason": "flex_retry", "detail": "server_is_overloaded", "waited_s": 60.0}])
        self.assertEqual(traces[0]["service_tier_fallbacks"], [])
        self.assertEqual(traces[0]["create_retries"], [])
        with self.assertLogs("fix_analysis", level="WARNING"):
            outcome, session, _, traces = self._run(creates=[
                self._http(503, "server_is_overloaded"),
                self._http(503, "server_is_overloaded"),
                self._http(503, "server_is_overloaded"),
                BackgroundResponseTests._Response(self._completed())])
        self.assertEqual(outcome, "done")
        self.assertEqual([payload.get("service_tier", "") for _, payload in session.created],
                         ["flex", "flex", "flex", ""])
        self.assertEqual(self.sleeps, [60.0, 120.0])
        self.assertEqual(traces[0]["service_tier_fallbacks"], [
            {"from": "flex", "reason": "overloaded", "detail": "server_is_overloaded"}])
        self.assertEqual(traces[0]["create_retries"], [])
        # On the standard tier, and for a server fault on Flex, the waits.
        for tier, code in (("default", "server_is_overloaded"), ("flex", "server_error")):
            with self.subTest(tier=tier, code=code):
                with self.assertLogs("fix_analysis", level="WARNING"):
                    outcome, session, _, traces = self._run(creates=[
                        self._http(503, code),
                        BackgroundResponseTests._Response(self._completed(tier))], tier=tier)
                self.assertEqual(outcome, "done")
                self.assertEqual(traces[0]["service_tier_fallbacks"], [])
                self.assertEqual(traces[0]["create_retries"][0]["status"], 503)

    def test_a_flex_response_still_queued_at_900s_goes_on_the_standard_tier(self):
        with self.assertLogs("fix_analysis", level="WARNING") as logs:
            outcome, session, provider, traces = self._run({
                "resp-1": [{"id": "resp-1", "status": "queued"}] * 12,
                "resp-2": [{"id": "resp-2", **self._completed()}],
            })
        self.assertEqual(outcome, "done")
        self.assertEqual(session.cancelled, ["resp-1"])
        self.assertEqual(session.created[0][1]["service_tier"], "flex")
        self.assertNotIn("service_tier", session.created[1][1])
        self.assertTrue(any("standard tier" in line and "queued" in line for line in logs.output))
        # Polled every 100 s up to the 900 s Flex deadline, not the 250 s timeout.
        self.assertEqual(traces[0]["background_polls"], 10)
        self.assertEqual(traces[0]["service_tier_fallbacks"], [
            {"from": "flex", "reason": "queued", "detail": "resp-1"}])
        self.assertEqual(traces[0]["queued_resubmissions"], 0)
        self.assertEqual(provider._cost_guard.added, [(7, 0, 2, 0)])

    def test_a_running_flex_response_gets_the_flex_deadline(self):
        outcome, session, _, traces = self._run({
            "resp-1": [{"id": "resp-1", "status": "in_progress"}] * 5
            + [{"id": "resp-1", **self._completed("flex")}],
        })
        self.assertEqual(outcome, "done")
        self.assertEqual(len(session.created), 1)
        self.assertEqual(traces[0]["service_tier"], "flex")

    def test_the_standard_resend_keeps_the_timeout_and_its_queued_resubmission(self):
        outcome, session, _, traces = self._run({
            "resp-1": [{"id": "resp-1", "status": "queued"}] * 12,
            "resp-2": [{"id": "resp-2", "status": "queued"}] * 3,
            "resp-3": [{"id": "resp-3", "status": "queued"}] * 3,
        })
        self.assertIsInstance(outcome, TimeoutError)
        self.assertEqual(session.cancelled, ["resp-1", "resp-2", "resp-3"])
        self.assertEqual(traces[0]["status"], "timeout")
        self.assertEqual(traces[0]["queued_resubmissions"], 1)
        self.assertEqual(len(traces[0]["service_tier_fallbacks"]), 1)

    def test_a_tier_the_api_refuses_is_dropped_for_this_and_later_calls(self):
        outcome, session, provider, traces = self._run(creates=[
            self._http(400, "invalid_value", "Unsupported value: 'service_tier'",
                       param="service_tier"),
            BackgroundResponseTests._Response(self._completed()),
        ])
        self.assertEqual(outcome, "done")
        self.assertNotIn("service_tier", session.created[1][1])
        self.assertEqual(traces[0]["service_tier_fallbacks"][0]["reason"], "rejected")
        session.creates = [BackgroundResponseTests._Response(self._completed())]
        provider.generate("another input")
        self.assertNotIn("service_tier", session.created[-1][1])

    def test_a_content_verdict_naming_the_tier_is_still_a_refusal(self):
        outcome, session, _, _ = self._run(creates=[
            self._http(400, "invalid_prompt", "service_tier flagged", param="service_tier")])
        self.assertIsInstance(outcome, ProviderContentRefusal)
        self.assertEqual(len(session.created), 1)

    def test_priority_is_not_offered_since_no_price_covers_it(self):
        from cognalys.orchestration import run_pipeline

        with self.assertRaises(ValueError):
            provider_module.configured_service_tier("priority")
        with self.assertRaises(SystemExit), \
                contextlib.redirect_stderr(io.StringIO()):
            run_pipeline.parse_args(["--llm-provider", "openai", "--llm-service-tier", "priority"])

    def test_the_run_exports_its_tier_to_openai_steps_only(self):
        from cognalys.orchestration import run_pipeline

        variable = provider_module.SERVICE_TIER_VARIABLE
        for argv, expected in ((["--llm-provider", "openai"], "flex"),
                               (["--llm-provider", "openai", "--llm-service-tier", "auto"],
                                "auto"),
                               (["--llm-provider", "anthropic"], None),
                               (["--llm-provider", "ollama"], None)):
            with self.subTest(argv=argv), unittest.mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop(variable, None)
                run_pipeline.export_service_tier(run_pipeline.parse_args(["--llm-provider", "openai", *argv]))
                self.assertEqual(os.environ.get(variable), expected)

    def test_a_flex_wait_abandoned_for_the_standard_tier_is_not_model_time(self):
        # 900 s queued on Flex, then 100 s on the standard tier: the
        # finding's budget is charged the standard attempt only.
        outcome, _, _, traces = self._run({
            "resp-1": [{"id": "resp-1", "status": "queued"}] * 12,
            "resp-2": [{"id": "resp-2", **self._completed()}],
        })
        self.assertEqual(outcome, "done")
        self.assertEqual(traces[0]["latency_ms"], 1_000_000)
        self.assertAlmostEqual(self.budget.seconds, 100.0)
        outcome, _, _, _ = self._run(creates=[
            self._http(429, "resource_unavailable"),
            BackgroundResponseTests._Response(self._completed()),
        ])
        self.assertEqual(outcome, "done")
        self.assertAlmostEqual(self.budget.seconds, 0.0)

    def test_a_flex_response_cancelled_at_its_deadline_is_charged_what_it_billed(self):
        running = [{"id": "resp-1", "status": "in_progress"}] * 12
        billed = {"id": "resp-1", "status": "cancelled", "service_tier": "flex",
                  "usage": {"input_tokens": 900, "output_tokens": 6000}}
        outcome, session, provider, traces = self._run(
            {"resp-1": list(running)}, cancel_answers={"resp-1": billed})
        self.assertIsInstance(outcome, TimeoutError)
        self.assertIn("timed out after 900s (the Flex tier's deadline)", str(outcome))
        self.assertEqual(session.cancelled, ["resp-1"])
        self.assertEqual(provider._cost_guard.added, [(900, 0, 6000, 0)])
        self.assertEqual(provider._cost_guard.billing, [("flex", 0)])
        self.assertEqual(traces[0]["status"], "timeout")
        self.assertEqual((traces[0]["input_tokens"], traces[0]["output_tokens"],
                          traces[0]["service_tier"]), (900, 6000, "flex"))
        # Without usage, after the settling reads, the guard charges the
        # upper bound and the trace keeps it for the guards rebuilt from it.
        outcome, _, provider, traces = self._run(
            {"resp-1": list(running)},
            cancel_answers={"resp-1": {"id": "resp-1", "status": "cancelled"}})
        self.assertIsInstance(outcome, TimeoutError)
        estimate = {"input_tokens": 3, "output_tokens": 32768}
        self.assertEqual(traces[0]["guard_usage_estimate"], estimate)
        self.assertEqual(provider._cost_guard.added, [(3, 0, 32768, 0)])
        self.assertEqual(provider._cost_guard.billing, [("flex", 0)])

    def test_a_standard_timeout_names_self_timeout(self):
        outcome, _, _, _ = self._run(
            {"resp-1": [{"id": "resp-1", "status": "in_progress"}] * 5}, tier="auto")
        self.assertIsInstance(outcome, TimeoutError)
        self.assertIn("timed out after 250s:", str(outcome))

    def test_a_stream_kept_alive_by_comments_still_reaches_the_flex_deadline(self):
        clock = [0.0]

        class _KeptAlive(DegenerateOutputTests._Stream):
            """A queued Flex stream that then sends only comment keepalives, 100 s apart."""

            def __init__(self):
                super().__init__([("response.created", {
                    "type": "response.created",
                    "response": {"id": "resp-1", "status": "queued"}})])
                self._payload = {}
                self.read = 0

            def iter_lines(self, decode_unicode=False):
                yield from self.lines
                while self.read < 1000:
                    self.read += 1
                    clock[0] += 100.0
                    yield ": keepalive"
                    yield ""

        stream = _KeptAlive()
        with self.assertLogs("fix_analysis", level="WARNING") as logs:
            outcome, session, _, traces = self._run(
                creates=[stream, BackgroundResponseTests._Response(self._completed())],
                clock=clock)
        self.assertEqual(outcome, "done")
        # Left at the 900 s deadline, not read on for ever.
        self.assertLessEqual(stream.read, 10)
        self.assertEqual(session.cancelled, ["resp-1"])
        self.assertTrue(any("standard tier" in line and "queued" in line for line in logs.output))
        self.assertEqual(traces[0]["service_tier_fallbacks"], [
            {"from": "flex", "reason": "queued", "detail": "resp-1"}])


class DegenerateOutputTests(unittest.TestCase):
    """A JSON answer streamed into whitespace is stopped, not run to max_output_tokens.

    Eight recorded code-generation answers reached the 32,768-token ceiling
    with 92-99% whitespace. The paid probes of 2026-11-09 showed a streamed
    background create (only a create with stream=true streams; a GET of one
    created without it sends keepalives only) and a cancel that stops the
    standard tier's billing at what was generated.
    """

    class _Stream:
        """A streamed create: server-sent events, then whatever the reader stops at."""

        def __init__(self, events, fail_after=None):
            self.status_code = 200
            self.headers = {"Content-Type": "text/event-stream; charset=utf-8"}
            self.text = ""
            self.lines = []
            for kind, data in events:
                self.lines += [f"event: {kind}", "data: " + json.dumps(data), ""]
            self.fail_after = fail_after
            self.closed = False

        def iter_lines(self, decode_unicode=False):
            for index, line in enumerate(self.lines):
                if self.fail_after is not None and index >= self.fail_after:
                    raise ConnectionError("stream reset")
                yield line

        def close(self):
            self.closed = True

        def json(self):
            raise ValueError("a stream has no JSON body")

    class _Session:
        def __init__(self, create, polls=(), cancel=None):
            self.create = create
            self.polls = list(polls)
            self.cancel = cancel
            self.posts = []
            self.cancelled = []
            self.poll_urls = []

        def close(self):
            pass

        def post(self, url, **kwargs):
            if url.endswith("/cancel"):
                self.cancelled.append(url)
                return BackgroundResponseTests._Response(
                    self.cancel or {"id": "resp-1", "status": "cancelled", "usage": None})
            self.posts.append(kwargs)
            return self.create

        def get(self, url, **_kwargs):
            self.poll_urls.append(url)
            return BackgroundResponseTests._Response(self.polls.pop(0))

    @staticmethod
    def _events(*deltas, terminal=None):
        events = [("response.created", {"type": "response.created",
                                        "response": {"id": "resp-1", "status": "queued"}}),
                  ("response.in_progress", {"type": "response.in_progress",
                                            "response": {"id": "resp-1",
                                                         "status": "in_progress"}})]
        events += [("response.output_text.delta",
                    {"type": "response.output_text.delta", "delta": delta}) for delta in deltas]
        if terminal:
            events.append((f"response.{terminal['status']}",
                           {"type": f"response.{terminal['status']}", "response": terminal}))
        return events

    def _run(self, session, json_mode=True, environment=None):
        from cognalys.llm import cost

        directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, directory, True)
        cache_dir = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, cache_dir, True)
        with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k", **(environment or {})}):
            provider = OpenAIProvider(prompt_log_dir=Path(directory), cache_dir=cache_dir,
                                      max_output_tokens=1000)
            provider.session = session
            provider._sleep = lambda _seconds: None
            provider._cost_guard = cost.RunCostGuard(
                100.0, "gpt-test", 0.0, {"gpt-test": {"input": 1.0, "cached_input": 0.1,
                                                      "output": 10.0}})
            outcome = provider.generate("x" * 4000, json_mode=json_mode,
                                        json_schema={"type": "object"} if json_mode else None)
        traces = [json.loads(path.read_text(encoding="utf-8"))
                  for path in Path(directory).glob("*_metadata.json")]
        return outcome, provider, traces, list(cache_dir.rglob("*.json"))

    def test_a_whitespace_run_is_cancelled_and_its_text_returned_for_the_shape_retry(self):
        limit = provider_module.DEGENERATE_WHITESPACE_CHARS
        # A run 100 characters past the threshold, of spaces and newlines.
        stream = self._Stream(self._events('{"edits": [', " " * (limit // 2), "\n" * (limit // 4),
                                           " " * (limit - limit // 2 - limit // 4 - 100),
                                           " " * 200))
        session = self._Session(stream, polls=[{
            "id": "resp-1", "status": "cancelled", "service_tier": "default",
            "usage": {"input_tokens": 2000, "output_tokens": 700}}])
        with self.assertLogs("fix_analysis", level="WARNING") as logs:
            outcome, provider, traces, cached = self._run(session)
        self.assertTrue(outcome.startswith('{"edits": ['))
        self.assertTrue(session.posts[0]["json"]["stream"])
        self.assertTrue(session.posts[0]["stream"])
        self.assertTrue(stream.closed)
        self.assertEqual(len(session.cancelled), 1)
        self.assertTrue(any(f"degenerated into {limit + 100} characters of whitespace" in line
                            for line in logs.output))
        self.assertEqual(traces[0]["degenerate_output_stopped"]["whitespace_run"], limit + 100)
        self.assertEqual(traces[0]["response_status"], "cancelled")
        # The tokens billed for the cancelled response are charged.
        self.assertEqual(traces[0]["output_tokens"], 700)
        self.assertAlmostEqual(provider._cost_guard.spent, 0.009)
        self.assertEqual(cached, [])

    def test_a_cancelled_response_without_usage_is_charged_an_upper_bound(self):
        stream = self._Stream(self._events(
            "{", " " * (provider_module.DEGENERATE_WHITESPACE_CHARS + 500)))
        none = {"id": "resp-1", "status": "cancelled", "usage": None}
        session = self._Session(stream, polls=[none] * 4)
        outcome, provider, traces, _ = self._run(session)
        self.assertTrue(outcome.startswith("{"))
        self.assertEqual(traces[0]["guard_usage_estimate"],
                         {"input_tokens": 2000, "output_tokens": 1000})
        self.assertAlmostEqual(provider._cost_guard.spent, 0.012)

    def test_an_answer_with_whitespace_in_its_strings_is_read_to_the_end(self):
        completed = {"id": "resp-1", "status": "completed", "service_tier": "default",
                     "output": [{"type": "message", "content": [
                         {"type": "output_text", "text": '{"a": "ok"}'}]}],
                     "usage": {"input_tokens": 10, "output_tokens": 5}}
        # One character short of the threshold, the space after the colon included.
        stream = self._Stream(self._events(
            '{"a": ', " " * (provider_module.DEGENERATE_WHITESPACE_CHARS - 2), '"ok"}',
            terminal=completed))
        session = self._Session(stream)
        outcome, _, traces, cached = self._run(session)
        self.assertEqual(outcome, '{"a": "ok"}')
        self.assertEqual(session.cancelled, [])
        self.assertEqual(session.poll_urls, [])
        self.assertNotIn("degenerate_output_stopped", traces[0])
        self.assertEqual(len(cached), 1)

    def test_a_streamed_failure_keeps_its_content_verdict_and_its_code(self):
        # A terminal response.failed read from the stream is a final answer
        # like a polled one: a content verdict stays ProviderContentRefusal
        # (the finding ends provider_refused, not crashed) and a server
        # fault keeps its code in the message.
        # Any other code (server_is_overloaded in the Flex replicates of
        # 2026-11-09) is sent again, the create retries' limit included,
        # and then ends as a ProviderTransientFailure.
        attempts = len(OpenAIProvider.CREATE_RETRY_WAITS_SECONDS) + 1
        for code, expected, posts in (
                ("cyber_policy", ProviderContentRefusal, 1),
                ("server_error", provider_module.ProviderTransientFailure, attempts),
                ("server_is_overloaded", provider_module.ProviderTransientFailure, attempts)):
            with self.subTest(code=code):
                failed = {"id": "resp-1", "status": "failed",
                          "error": {"code": code, "message": "stopped"}}
                session = self._Session(self._Stream(self._events('{"a"', terminal=failed)))
                with self.assertRaises(expected) as raised:
                    self._run(session)
                self.assertIn(f"({code})", str(raised.exception))
                if expected is not ProviderContentRefusal:
                    self.assertNotIsInstance(raised.exception, ProviderContentRefusal)
                self.assertEqual(len(session.posts), posts)
                self.assertEqual(session.cancelled, [])
                self.assertEqual(session.poll_urls, [])

    def test_a_streamed_failure_then_an_answer_returns_the_answer(self):
        failed = {"id": "resp-1", "status": "failed",
                  "error": {"code": "server_is_overloaded", "message": "overloaded"}}
        completed = {"id": "resp-2", "status": "completed", "service_tier": "default",
                     "output_text": '{"a": 1}', "usage": {"input_tokens": 3, "output_tokens": 1}}
        streams = [self._Stream(self._events('{"a"', terminal=failed)),
                   self._Stream(self._events('{"a": 1}', terminal=completed))]
        session = self._Session(None)
        session.post = lambda url, **kwargs: (session.posts.append(kwargs), streams.pop(0))[1]
        outcome, _, traces, _ = self._run(session)
        self.assertEqual(outcome, '{"a": 1}')
        self.assertEqual(traces[0]["failed_responses"][0]["code"], "server_is_overloaded")

    def test_a_broken_stream_is_followed_by_polls(self):
        stream = self._Stream(self._events('{"a": 1}'), fail_after=4)
        session = self._Session(stream, polls=[
            {"id": "resp-1", "status": "completed", "output_text": '{"a": 1}',
             "usage": {"input_tokens": 3, "output_tokens": 1}}])
        with self.assertLogs("fix_analysis", level="WARNING") as logs:
            outcome, _, traces, _ = self._run(session)
        self.assertEqual(outcome, '{"a": 1}')
        self.assertEqual(len(session.poll_urls), 1)
        self.assertTrue(any("following it by polls" in line for line in logs.output))
        self.assertEqual(traces[0]["status"], "success")

    def test_plain_text_calls_and_the_switch_send_no_stream(self):
        done = BackgroundResponseTests._Response(
            {"id": "r", "status": "completed", "output_text": "done"})
        session = self._Session(done)
        self.assertEqual(self._run(session, json_mode=False)[0], "done")
        self.assertNotIn("stream", session.posts[0]["json"])
        session = self._Session(BackgroundResponseTests._Response(
            {"id": "r", "status": "completed", "output_text": "{}"}))
        self._run(session, environment={provider_module.STREAM_WATCH_VARIABLE: "0"})
        self.assertNotIn("stream", session.posts[0]["json"])
        self.assertNotIn("stream", session.posts[0])

    def test_the_detector_counts_only_the_trailing_whitespace_run(self):
        detector = provider_module.WhitespaceRunDetector(threshold=10)
        self.assertFalse(detector.feed("abc   "))
        self.assertFalse(detector.feed("    x  "))
        self.assertEqual(detector.run, 2)
        self.assertFalse(detector.feed("\n\t   "))
        self.assertTrue(detector.feed("   "))
        self.assertEqual(provider_module.WhitespaceRunDetector.longest_run("a  b\n\n\n c"), 4)
        # Above the longest run in a recorded complete answer (25,525) and at
        # most the shortest in a recorded truncated one (56,896).
        self.assertTrue(25_525 < provider_module.DEGENERATE_WHITESPACE_CHARS <= 56_896)


class UnreportedUsageTests(unittest.TestCase):
    """An "incomplete" answer reporting no usage must not let the ceiling fall behind."""

    def _run(self, create, polls):
        from cognalys.llm import cost

        session = BackgroundResponseTests._Session(polls, create=create)
        directory = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, directory, True)
        with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
            provider = OpenAIProvider(prompt_log_dir=Path(directory), cache_dir=None,
                                      max_output_tokens=1000)
        provider.session = session
        provider._sleep = lambda _seconds: None
        provider._cost_guard = cost.RunCostGuard(
            100.0, "gpt-test", 0.0, {"gpt-test": {"input": 1.0, "cached_input": 0.1,
                                                  "output": 10.0}})
        outcome = provider.generate("x" * 4000)
        traces = [json.loads(path.read_text(encoding="utf-8"))
                  for path in Path(directory).glob("*_metadata.json")]
        return outcome, session, provider, traces

    def test_its_usage_is_read_once_more(self):
        outcome, session, provider, traces = self._run(
            {"id": "r", "status": "incomplete", "output_text": "part", "usage": None},
            [{"id": "r", "status": "incomplete", "output_text": "part",
              "usage": {"input_tokens": 1000, "output_tokens": 1000}}])
        self.assertEqual(outcome, "part")
        self.assertEqual(len(session.poll_urls), 1)
        self.assertEqual(traces[0]["input_tokens"], 1000)
        self.assertNotIn("guard_usage_estimate", traces[0])
        self.assertAlmostEqual(provider._cost_guard.spent, 0.011)

    def test_without_it_the_guard_charges_an_upper_bound(self):
        outcome, _, provider, traces = self._run(
            {"id": "r", "status": "incomplete", "output_text": "part", "usage": None},
            [{"id": "r", "status": "incomplete", "output_text": "part", "usage": None}])
        self.assertEqual(outcome, "part")
        self.assertEqual(traces[0]["input_tokens"], 0)
        # A token per two characters of input, and the whole output ceiling.
        self.assertEqual(traces[0]["guard_usage_estimate"],
                         {"input_tokens": 2000, "output_tokens": 1000})
        self.assertAlmostEqual(provider._cost_guard.spent, 0.012)


if __name__ == "__main__":
    unittest.main()
