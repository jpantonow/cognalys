import collections
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import cli  # noqa: E402
from cognalys.llm import cost  # noqa: E402
from cognalys.llm.llm_providers import CallBudgetExhausted  # noqa: E402

from _run_fixtures import KEY, run_directory, write  # noqa: E402

PRICES = {"gpt-test": {"input": 2.0, "cached_input": 0.5, "output": 10.0}}


def trace(directory: Path, name: str, **fields) -> None:
    record = {"model": "gpt-test", "stage": "fix_generation.draft", "status": "success",
              "delivery": "sent_to_openai", "input_tokens": 0, "cached_input_tokens": 0,
              "output_tokens": 0, **fields}
    (directory / f"{name}_metadata.json").write_text(json.dumps(record), encoding="utf-8")


def older_trace(directory: Path, name: str, response_usage=None, **fields) -> None:
    """A trace from before cache_write_input_tokens was recorded, and its response."""
    trace(directory, name, **fields)
    path = directory / f"{name}_metadata.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record.pop("cache_write_input_tokens", None)
    path.write_text(json.dumps(record), encoding="utf-8")
    if response_usage is not None:
        (directory / f"{name}_response.json").write_text(json.dumps(
            {"trace_version": 2, "call_id": name, "response": {"usage": response_usage}}),
            encoding="utf-8")


def _cost_output(argv) -> str:
    with contextlib.redirect_stdout(io.StringIO()) as out:
        code = cli.main(argv)
    assert code == 0, code
    return out.getvalue()


def _extracted(run: Path, apk: str, finding, index: int = 0) -> None:
    csv_class, method, spec = finding
    write(run / "error_methods" / apk / f"{index}_{method}.json", {
        "extraction_metadata": {"apk_name": apk, "csv_index": index,
                                "extraction_status": "success"},
        "error": {"csv_class": csv_class, "csv_method": method, "spec": spec},
    })


def outcome_run(root: Path) -> Path:
    """A run whose findings end PR-ready, as false positives and not analysed, with known costs."""
    run = run_directory(root)  # KEY: PR pronto
    apk = KEY[0]
    logs = cost.run_log_dir(run)
    logs.mkdir(parents=True)
    trace(logs, "pr_a", finding_id=f"{KEY[1]}:::{KEY[2]}:::{KEY[3]}:::0",
          input_tokens=1_000_000)  # US$ 2
    trace(logs, "pr_b", finding_id=f"{KEY[1]}:::{KEY[2]}:::{KEY[3]}:::0",
          output_tokens=100_000)  # US$ 1
    for index, (name, tokens) in enumerate((("A", 500_000), ("B", 1_500_000), ("C", 0)), 1):
        finding = (f"org.example.{name}", "run", "CipherSpec")
        _extracted(run, apk, finding, index)
        write(run / "error_solutions" / "evidence_reviews" / apk / f"{index}_run_evidence.json", {
            "apk_name": apk, "csv_class": finding[0], "method_name": "run", "spec": "CipherSpec",
            "analysis": {"decision": "", "detector_violation": "not_confirmed"}})
        if tokens:
            trace(logs, f"fp_{name}", finding_id=":::".join(finding), input_tokens=tokens)
    _extracted(run, apk, ("org.example.D", "run", "CipherSpec"), 4)
    trace(logs, "unanalysed", finding_id="org.example.D:::run:::CipherSpec",
          input_tokens=250_000)  # US$ 0.5
    trace(logs, "run_wide", finding_id="", input_tokens=500_000)  # US$ 1
    trace(logs, "hit", finding_id="org.example.D:::run:::CipherSpec", status="cache_hit")
    return run


class UsageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.logs = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_calls_are_summed_and_priced_per_stage(self):
        trace(self.logs, "a", input_tokens=1_000_000, cached_input_tokens=400_000, output_tokens=100_000)
        trace(self.logs, "b", stage="external_research.research", input_tokens=500_000)
        trace(self.logs, "c", status="cache_hit")
        trace(self.logs, "d", status="prepared")  # never sent
        report = cost.usage(self.logs, PRICES)
        self.assertEqual((report["calls"], report["cache_hits"]), (2, 1))
        # 600k uncached * 2 + 400k cached * 0.5 + 100k out * 10 = 1.2 + 0.2 + 1.0
        self.assertAlmostEqual(report["by_stage"]["fix_generation"]["cost_usd"], 2.4)
        self.assertAlmostEqual(report["cost_usd"], 3.4)
        self.assertIn("US$ 3.40", "\n".join(cost.summary_lines(report)))

    def test_a_corpus_hit_is_counted_apart_and_costs_nothing(self):
        finding = "a.B:::m:::CipherSpec:::0"
        trace(self.logs, "a", stage="external_research.research", finding_id=finding,
              input_tokens=1_000_000)  # US$ 2
        trace(self.logs, "b", stage="external_research", finding_id=finding,
              status=cost.RESEARCH_CORPUS_DELIVERY, delivery=cost.RESEARCH_CORPUS_DELIVERY,
              input_tokens=5_000_000)  # a served answer: never billed, whatever it says
        trace(self.logs, "c", status="cache_hit", delivery="cache_hit")
        report = cost.usage(self.logs, PRICES)
        self.assertEqual((report["calls"], report["cache_hits"], report["corpus_hits"]), (1, 1, 1))
        self.assertAlmostEqual(report["cost_usd"], 2.0)
        self.assertEqual(report["by_stage"]["external_research"]["corpus_hits"], 1)
        self.assertIn("1 served by the research corpus", "\n".join(cost.summary_lines(report)))
        by_finding = cost.usage_by_finding(self.logs, PRICES)
        self.assertEqual(by_finding[("a.B", "m", "CipherSpec")]["calls"], 1)
        with patch.dict(os.environ, {cost.MAX_COST_VARIABLE: "10"}), \
                patch.object(cost, "load_prices", return_value=PRICES):
            guard = cost.RunCostGuard.from_environment(self.logs, "gpt-test")
        self.assertAlmostEqual(guard.spent, 2.0)
        record = json.loads((self.logs / "a_metadata.json").read_text(encoding="utf-8"))
        self.assertAlmostEqual(cost.trace_call_cost(self.logs / "a_metadata.json", record, PRICES),
                               2.0)
        # A run without one reports as before.
        (self.logs / "b_metadata.json").unlink()
        report = cost.usage(self.logs, PRICES)
        self.assertNotIn("corpus_hits", report)
        self.assertNotIn("research corpus", "\n".join(cost.summary_lines(report)))

    def test_a_model_without_a_price_makes_the_cost_unknown_not_zero(self):
        trace(self.logs, "a", input_tokens=1000)
        trace(self.logs, "b", model="other-model", input_tokens=1000)
        report = cost.usage(self.logs, PRICES)
        self.assertIsNone(report["cost_usd"])
        self.assertEqual(report["unpriced_models"], ["other-model"])
        text = "\n".join(cost.summary_lines(report))
        self.assertIn("no price for other-model", text)
        self.assertNotIn("US$ 0.00", text.splitlines()[-2])

    def test_a_dated_model_takes_its_family_price(self):
        self.assertEqual(cost.price_of("gpt-test-2026-10-01", PRICES), PRICES["gpt-test"])
        self.assertIsNone(cost.price_of("gpt", PRICES))

    def test_the_prices_file_ignores_notes_and_incomplete_entries(self):
        path = self.logs / "prices.json"
        path.write_text(json.dumps({"_note": "x", "models": {
            "a": {"input": 1, "output": 2}, "b": {"input": 1}, "_c": {"input": 1, "output": 1}}}),
            encoding="utf-8")
        self.assertEqual(cost.load_prices(path), {"a": {"input": 1.0, "output": 2.0, "cached_input": 1.0}})

    def test_the_prices_file_keeps_a_write_price_only_where_given(self):
        path = self.logs / "prices.json"
        path.write_text(json.dumps({"models": {
            "a": {"input": 1, "output": 2, "cache_write_input": 1.25}}}), encoding="utf-8")
        self.assertEqual(cost.load_prices(path)["a"]["cache_write_input"], 1.25)

    def test_cache_writes_are_billed_at_the_write_price_when_one_is_given(self):
        priced = {"gpt-test": {**PRICES["gpt-test"], "cache_write_input": 2.5}}
        # 300k plain * 2 + 200k written * 2.5 + 500k cached * 0.5 + 100k out * 10
        self.assertAlmostEqual(cost.tokens_cost("gpt-test", 1_000_000, 500_000, 100_000, priced,
                                                cache_write_tokens=200_000), 2.35)
        trace(self.logs, "a", input_tokens=1_000_000, cached_input_tokens=500_000,
              cache_write_input_tokens=200_000, output_tokens=100_000)
        report = cost.usage(self.logs, priced)
        self.assertEqual(report["by_stage"]["fix_generation"]["cache_write_input_tokens"], 200_000)
        self.assertAlmostEqual(report["cost_usd"], 2.35)
        self.assertIn("500,000 cached, 200,000 written", "\n".join(cost.summary_lines(report)))

    def test_without_a_write_price_or_written_tokens_a_call_costs_what_it_did(self):
        # 500k uncached * 2 + 500k cached * 0.5 + 100k out * 10
        before = cost.tokens_cost("gpt-test", 1_000_000, 500_000, 100_000, PRICES)
        self.assertAlmostEqual(before, 2.25)
        self.assertEqual(cost.tokens_cost("gpt-test", 1_000_000, 500_000, 100_000, PRICES,
                                          cache_write_tokens=200_000), before)
        trace(self.logs, "a", input_tokens=1_000_000, cached_input_tokens=500_000,
              output_tokens=100_000)  # a trace from before writes were recorded
        report = cost.usage(self.logs, PRICES)
        self.assertAlmostEqual(report["cost_usd"], before)
        self.assertEqual(report["cache_write_input_tokens"], 0)


    def test_an_older_trace_reads_its_cache_writes_from_its_response(self):
        older_trace(self.logs, "a", input_tokens=12_455, cached_input_tokens=3_056,
                    output_tokens=4_371, response_usage={
                        "input_tokens": 12_455, "output_tokens": 4_371,
                        "input_tokens_details": {"cache_write_tokens": 9_396,
                                                 "cached_tokens": 3_056}})
        report = cost.usage(self.logs, PRICES)
        self.assertEqual(report["cache_write_input_tokens"], 9_396)
        self.assertEqual(report["cache_writes_not_recorded"], 0)
        self.assertIn("3,056 cached, 9,396 written", "\n".join(cost.summary_lines(report)))
        # Without a write price the call costs what it did.
        self.assertAlmostEqual(report["cost_usd"], cost.tokens_cost(
            "gpt-test", 12_455, 3_056, 4_371, PRICES))
        older_trace(self.logs, "b", finding_id="org.app.K:::load:::KeyStoreSpec:::x",
                    input_tokens=100, response_usage={
                        "input_tokens_details": {"cache_write_tokens": 40}})
        by_finding = cost.usage_by_finding(self.logs, PRICES)
        self.assertEqual(by_finding[("org.app.K", "load", "KeyStoreSpec")]
                         ["cache_write_input_tokens"], 40)

    def test_writes_neither_trace_nor_response_recorded_are_not_shown_as_zero(self):
        older_trace(self.logs, "a", input_tokens=1_000, cached_input_tokens=200)
        older_trace(self.logs, "b", input_tokens=1_000, response_usage={
            "input_tokens": 1_000, "input_tokens_details": {"cached_tokens": 0}})
        report = cost.usage(self.logs, PRICES)
        self.assertEqual(report["cache_writes_not_recorded"], 2)
        self.assertEqual(report["cache_write_input_tokens"], 0)
        text = "\n".join(cost.summary_lines(report))
        self.assertIn("200 cached, n/r written", text)
        self.assertNotIn(" 0 written", text)
        # A newer call beside them: its writes are counted, the others named.
        trace(self.logs, "c", input_tokens=1_000, cache_write_input_tokens=300)
        text = "\n".join(cost.summary_lines(cost.usage(self.logs, PRICES)))
        self.assertIn("200 cached, 300 written (n/r in 2 calls)", text)

    def test_an_older_failed_call_without_input_tokens_wrote_nothing(self):
        """A call that sent or billed no input wrote nothing to the cache: its 0 is known."""
        older_trace(self.logs, "a", input_tokens=1_000, response_usage={
            "input_tokens": 1_000, "input_tokens_details": {"cache_write_tokens": 400}})
        older_trace(self.logs, "b", status="error", error_type="ChunkedEncodingError")
        (self.logs / "b_response.json").write_text(json.dumps(
            {"trace_version": 2, "call_id": "b",
             "response": {"error": "ChunkedEncodingError"}}), encoding="utf-8")
        older_trace(self.logs, "c", status="timeout")  # no response recorded
        report = cost.usage(self.logs, PRICES)
        self.assertEqual(report["calls"], 3)
        self.assertEqual(report["cache_writes_not_recorded"], 0)
        text = "\n".join(cost.summary_lines(report))
        self.assertIn("0 cached, 400 written", text)
        self.assertNotIn("n/r", text)

    def test_the_prices_file_keeps_tier_prices_and_the_search_fee_only_where_whole(self):
        path = self.logs / "prices.json"
        path.write_text(json.dumps({"models": {
            "a": {"input": 1, "output": 2, "web_search_per_1k_calls": 10,
                  "flex": {"input": 0.5, "cached_input": 0.025, "output": 1}},
            "b": {"input": 1, "output": 2, "flex": {"input": 0.5}}}}), encoding="utf-8")
        prices = cost.load_prices(path)
        self.assertEqual(prices["a"]["flex"], {"input": 0.5, "cached_input": 0.025, "output": 1.0})
        self.assertEqual(prices["a"]["web_search_per_1k_calls"], 10.0)
        self.assertEqual(prices["b"], {"input": 1.0, "output": 2.0, "cached_input": 1.0})

    def test_the_shipped_prices_bill_writes_at_1_25_and_flex_at_half(self):
        prices = cost.load_prices(cost.library_data(cost.PRICES_FILE))
        for model, price in prices.items():
            if "cache_write_input" in price:
                self.assertAlmostEqual(price["cache_write_input"], 1.25 * price["input"], msg=model)
            if "flex" in price:
                for name, value in price["flex"].items():
                    self.assertAlmostEqual(value, price[name] / 2, msg=f"{model} {name}")
        self.assertIn("cache_write_input", prices["gpt-6.1-terra"])
        self.assertEqual(prices["gpt-6.1-terra"]["web_search_per_1k_calls"], 10.0)

    def test_only_search_actions_are_billed_and_an_unrecorded_action_is_billed(self):
        response = {"output": [
            {"type": "web_search_call", "action": {"type": "search"}},
            {"type": "web_search_call", "action": {"type": "open_page"}},
            {"type": "web_search_call", "action": {"type": "find_in_page"}},
            {"type": "web_search_call"},
            {"type": "message"}]}
        actions = cost.web_search_actions(response)
        self.assertEqual(actions, {"search": 1, "open_page": 1, "find_in_page": 1, "unknown": 1})
        self.assertEqual(cost.billed_web_search_calls(actions), 2)
        self.assertEqual(cost.web_search_actions(None), {})

    def test_a_flex_call_costs_half_its_tokens_and_the_full_search_fee(self):
        priced = {"gpt-test": {**PRICES["gpt-test"], "web_search_per_1k_calls": 10.0,
                               "flex": {"input": 1.0, "cached_input": 0.25, "output": 5.0}}}
        trace(self.logs, "a", input_tokens=1_000_000, service_tier="flex", web_search_calls=3)
        trace(self.logs, "b", input_tokens=1_000_000, service_tier="default")
        trace(self.logs, "c", input_tokens=1_000_000, service_tier="priority")  # no own prices
        report = cost.usage(self.logs, priced)
        # 1.0 + 0.03 fee, then 2.0 and 2.0 at the standard prices
        self.assertAlmostEqual(report["cost_usd"], 5.03)
        self.assertEqual(report["web_search_calls"], 3)
        self.assertEqual(report["service_tiers"], {"flex": 1, "default": 1, "priority": 1})
        text = "\n".join(cost.summary_lines(report))
        self.assertIn("3 web search calls billed", text)
        self.assertIn("served tiers default 1, flex 1, priority 1", text)

    def test_an_older_trace_reads_its_tier_and_searches_from_its_response(self):
        priced = {"gpt-test": {**PRICES["gpt-test"], "web_search_per_1k_calls": 10.0,
                               "flex": {"input": 1.0, "cached_input": 0.25, "output": 5.0}}}
        older_trace(self.logs, "a", input_tokens=1_000_000)
        (self.logs / "a_response.json").write_text(json.dumps({"response": {
            "service_tier": "flex", "usage": {},
            "output": [{"type": "web_search_call", "action": {"type": "search"}},
                       {"type": "web_search_call", "action": {"type": "open_page"}}]}}),
            encoding="utf-8")
        self.assertAlmostEqual(cost.usage(self.logs, priced)["cost_usd"], 1.01)
        # The guard's view reads no response: the trace's own fields only.
        self.assertAlmostEqual(cost.usage(self.logs, priced, read_responses=False)["cost_usd"], 2.0)

    def test_an_anthropic_trace_without_search_calls_reads_them_from_its_response(self):
        # frozen_runs_20261113 D arm, co_0a32f516feb2/r1 call 0001: a research
        # call whose trace recorded no web_search_calls, and whose message
        # reports 16 searches (web fetches carry no fee).
        priced = {"claude-test": {"input": 2.0, "cached_input": 0.1,
                                  "cache_write_input": 2.5, "output": 10.0,
                                  "web_search_per_1k_calls": 10.0}}
        trace(self.logs, "a", model="claude-test", delivery="sent_to_anthropic",
              stage="external_research.research", input_tokens=213825,
              cached_input_tokens=176336, cache_write_input_tokens=33735,
              output_tokens=8167)
        (self.logs / "a_response.json").write_text(json.dumps({"response": {
            "id": "msg_1", "type": "message", "stop_reason": "end_turn",
            "content": [{"type": "server_tool_use", "name": "web_search",
                         "input": {"query": "q"}}],
            "usage": {"input_tokens": 3754, "cache_read_input_tokens": 176336,
                      "cache_creation_input_tokens": 33735, "output_tokens": 8167,
                      "server_tool_use": {"web_fetch_requests": 2,
                                          "web_search_requests": 16},
                      "service_tier": "standard"}}}), encoding="utf-8")
        tokens = (3754 * 2.0 + 176336 * 0.1 + 33735 * 2.5 + 8167 * 10.0) / 1e6
        report = cost.usage(self.logs, priced)
        self.assertEqual(report["web_search_calls"], 16)
        self.assertAlmostEqual(report["cost_usd"], tokens + 0.16)
        # A trace that records the field (2026-11-14 on) is billed by it.
        record = json.loads((self.logs / "a_metadata.json").read_text(encoding="utf-8"))
        record["web_search_calls"] = 3
        (self.logs / "a_metadata.json").write_text(json.dumps(record), encoding="utf-8")
        self.assertAlmostEqual(cost.usage(self.logs, priced)["cost_usd"], tokens + 0.03)
        # An answer without server tools, or with none used, adds nothing.
        self.assertEqual(cost.web_search_actions({"usage": {"input_tokens": 1}}), {})
        self.assertEqual(cost.web_search_actions(
            {"usage": {"server_tool_use": {"web_search_requests": 0}}}), {})

    def test_anthropic_calls_are_counted_with_the_openai_ones(self):
        priced = {**PRICES, "claude-test": {"input": 3.0, "cached_input": 0.3, "output": 15.0}}
        trace(self.logs, "a", input_tokens=1_000_000)  # US$ 2
        trace(self.logs, "b", model="claude-test", delivery="sent_to_anthropic",
              finding_id="org.app.K:::load:::KeyStoreSpec:::x", input_tokens=1_000_000,
              cache_write_input_tokens=0)  # US$ 3
        trace(self.logs, "c", delivery="sent_to_anthropic", status="prepared")  # never answered
        report = cost.usage(self.logs, priced)
        self.assertEqual(report["calls"], 2)
        self.assertAlmostEqual(report["cost_usd"], 5.0)
        self.assertAlmostEqual(report["by_model"]["claude-test"]["cost_usd"], 3.0)
        by_finding = cost.usage_by_finding(self.logs, priced)
        self.assertAlmostEqual(by_finding[("org.app.K", "load", "KeyStoreSpec")]["cost_usd"], 3.0)
        # The OpenAI-only view the guard and the interrupted marking read.
        self.assertAlmostEqual(cost.usage(self.logs, priced,
                                          deliveries=cost.OPENAI_DELIVERIES)["cost_usd"], 2.0)
        self.assertEqual(cost.usage_by_finding(self.logs, priced,
                                               deliveries=cost.OPENAI_DELIVERIES), {})


class CeilingTests(unittest.TestCase):
    def test_the_guard_starts_from_what_the_run_already_spent(self):
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory)
            trace(logs, "a", input_tokens=1_000_000)  # US$ 2
            with patch.dict(os.environ, {cost.MAX_COST_VARIABLE: "3"}), \
                    patch.object(cost, "load_prices", return_value=PRICES):
                guard = cost.RunCostGuard.from_environment(logs, "gpt-test")
        guard.check()
        guard.add(600_000, 0, 0)  # US$ 1.2 more
        with self.assertRaises(CallBudgetExhausted) as raised:
            guard.check()
        self.assertIn("--max-cost", str(raised.exception))

    def test_the_guard_starts_from_what_cognalys_cost_reports(self):
        """A resumed run starts from every paid provider's traces, priced as
        `cognalys cost` prices them (PLANO_CORRECOES_DEFESA A6): it read the
        OpenAI traces' own fields only, so a run resumed after Anthropic
        calls started below what it had spent."""
        priced = {**PRICES, "gpt-test": {**PRICES["gpt-test"], "cache_write_input": 4.0},
                  "claude-test": {"input": 3.0, "cached_input": 0.3, "output": 15.0}}
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory)
            older_trace(logs, "a", input_tokens=1_000_000, response_usage={
                "input_tokens_details": {"cache_write_tokens": 1_000_000}})  # US$ 2 as before
            trace(logs, "b", model="claude-test", delivery="sent_to_anthropic",
                  input_tokens=1_000_000)
            with patch.dict(os.environ, {cost.MAX_COST_VARIABLE: "3"}), \
                    patch.object(cost, "load_prices", return_value=priced):
                guard = cost.RunCostGuard.from_environment(logs, "gpt-test")
            # Both providers, and the older trace's write at its price.
            self.assertAlmostEqual(cost.usage(logs, priced)["cost_usd"], 4.0 + 3.0)
            self.assertAlmostEqual(guard.spent, 4.0 + 3.0)
            with self.assertRaises(CallBudgetExhausted):
                guard.check()

    def test_the_guard_bills_cache_writes_at_their_price(self):
        guard = cost.RunCostGuard(10.0, "gpt-test", 0.0,
                                  {"gpt-test": {**PRICES["gpt-test"], "cache_write_input": 2.5}})
        guard.add(1_000_000, 0, 0, cache_write_tokens=1_000_000)
        self.assertAlmostEqual(guard.spent, 2.5)
        unpriced_writes = cost.RunCostGuard(10.0, "gpt-test", 0.0, PRICES)
        unpriced_writes.add(1_000_000, 0, 0, cache_write_tokens=1_000_000)
        self.assertAlmostEqual(unpriced_writes.spent, 2.0)  # the input price, as before

    def test_the_guard_bills_the_served_tier_and_the_search_fee(self):
        priced = {"gpt-test": {**PRICES["gpt-test"], "web_search_per_1k_calls": 10.0,
                               "flex": {"input": 1.0, "cached_input": 0.25, "output": 5.0}}}
        guard = cost.RunCostGuard(10.0, "gpt-test", 0.0, priced)
        guard.add(1_000_000, 0, 0, service_tier="flex", web_search_calls=5)
        self.assertAlmostEqual(guard.spent, 1.05)
        guard.add(1_000_000, 0, 0, service_tier="default")
        self.assertAlmostEqual(guard.spent, 3.05)
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory)
            trace(logs, "a", input_tokens=1_000_000, service_tier="flex", web_search_calls=5)
            with patch.dict(os.environ, {cost.MAX_COST_VARIABLE: "3"}), \
                    patch.object(cost, "load_prices", return_value=priced):
                self.assertAlmostEqual(
                    cost.RunCostGuard.from_environment(logs, "gpt-test").spent, 1.05)

    def test_a_recorded_upper_bound_is_billed_by_the_rebuilt_guard_and_the_report(self):
        """A call that ran without reporting usage was charged an upper bound by
        the guard of its own step; a later step's guard, rebuilt from the
        traces, and cognalys cost charge the same bound, never 0."""
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory)
            trace(logs, "a", status="timeout", service_tier="",
                  guard_usage_estimate={"input_tokens": 500_000, "output_tokens": 100_000})
            # Reported tokens win over a bound recorded beside them.
            trace(logs, "b", input_tokens=1_000_000,
                  guard_usage_estimate={"input_tokens": 9_000_000, "output_tokens": 0})
            with patch.dict(os.environ, {cost.MAX_COST_VARIABLE: "30"}), \
                    patch.object(cost, "load_prices", return_value=PRICES):
                guard = cost.RunCostGuard.from_environment(logs, "gpt-test")
            # 0.5M x 2 + 0.1M x 10 = US$ 2, plus b's US$ 2.
            self.assertAlmostEqual(guard.spent, 4.0)
            report = cost.usage(logs, PRICES)
            self.assertAlmostEqual(report["cost_usd"], 4.0)
            self.assertEqual(report["usage_estimated"], 1)
            self.assertEqual((report["input_tokens"], report["output_tokens"]),
                             (1_500_000, 100_000))
            self.assertIn("1 calls reported no usage and are billed at an upper bound",
                          cost.summary_lines(report)[-1])

    def test_the_usage_a_failed_response_reported_is_billed_as_no_extra_call(self):
        """A response that failed after it ran was charged by the guard of its
        own step before the call was sent again; the rebuilt guard, the
        report and the per-finding report charge it too, at its own tier."""
        priced = {"gpt-test": {**PRICES["gpt-test"],
                               "flex": {"input": 1.0, "cached_input": 0.25, "output": 5.0}}}
        failed = {"response_id": "r1", "status": "failed", "code": "server_error",
                  "service_tier": "flex", "input_tokens": 1_000_000, "cached_input_tokens": 0,
                  "cache_write_input_tokens": 0, "output_tokens": 100_000,
                  "web_search_calls": 0}
        nothing = {**failed, "response_id": "r2", "code": "server_is_overloaded",
                   "input_tokens": 0, "output_tokens": 0}
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory)
            trace(logs, "a", input_tokens=1_000_000, service_tier="default",
                  finding_id="C:::m:::Spec:::x", failed_responses=[failed, nothing])
            with patch.dict(os.environ, {cost.MAX_COST_VARIABLE: "30"}), \
                    patch.object(cost, "load_prices", return_value=priced):
                guard = cost.RunCostGuard.from_environment(logs, "gpt-test")
            # US$ 2 for the answer; 1M x 1 + 0.1M x 5 = US$ 1.5 at Flex.
            self.assertAlmostEqual(guard.spent, 3.5)
            report = cost.usage(logs, priced)
            self.assertAlmostEqual(report["cost_usd"], 3.5)
            self.assertEqual(report["calls"], 1)
            self.assertEqual(report["failed_responses_billed"], 1)
            self.assertEqual(report["input_tokens"], 2_000_000)
            by_finding = cost.usage_by_finding(logs, priced)
            self.assertAlmostEqual(by_finding[("C", "m", "Spec")]["cost_usd"], 3.5)

    def test_a_cancelled_response_billed_at_its_bound_is_billed_so_from_the_traces(self):
        """Review of 2026-11-09: a response cancelled outside the call that
        reported no usage was charged 0 while the provider billed it."""
        priced = {"gpt-test": {**PRICES["gpt-test"],
                               "flex": {"input": 1.0, "cached_input": 0.25, "output": 5.0}}}
        cancelled = {"response_id": "r1", "status": "cancelled", "code": "",
                     "service_tier": "flex", "input_tokens": 0, "cached_input_tokens": 0,
                     "cache_write_input_tokens": 0, "output_tokens": 0, "web_search_calls": 0,
                     "guard_usage_estimate": {"input_tokens": 1_000_000,
                                              "output_tokens": 100_000}}
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory)
            trace(logs, "a", input_tokens=1_000_000, service_tier="default",
                  finding_id="C:::m:::Spec:::x", failed_responses=[cancelled])
            with patch.dict(os.environ, {cost.MAX_COST_VARIABLE: "30"}), \
                    patch.object(cost, "load_prices", return_value=priced):
                guard = cost.RunCostGuard.from_environment(logs, "gpt-test")
            # US$ 2 for the answer; 1M x 1 + 0.1M x 5 = US$ 1.5 at Flex.
            self.assertAlmostEqual(guard.spent, 3.5)
            report = cost.usage(logs, priced)
            self.assertAlmostEqual(report["cost_usd"], 3.5)
            self.assertEqual(report["failed_responses_billed"], 1)
            self.assertAlmostEqual(cost.usage_by_finding(logs, priced)[("C", "m", "Spec")]
                                   ["cost_usd"], 3.5)

    def test_no_ceiling_means_no_guard(self):
        with patch.dict(os.environ, {cost.MAX_COST_VARIABLE: ""}):
            self.assertIsNone(cost.RunCostGuard.from_environment(None, "gpt-test"))

    def test_a_ceiling_without_a_price_is_refused(self):
        with patch.dict(os.environ, {cost.MAX_COST_VARIABLE: "5"}), \
                patch.object(cost, "load_prices", return_value={}):
            with self.assertRaises(ValueError):
                cost.RunCostGuard.from_environment(None, "gpt-test")


class CommandTests(unittest.TestCase):
    def test_cognalys_cost_reads_a_run(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run_x"
            logs = cost.run_log_dir(run)
            logs.mkdir(parents=True)
            trace(logs, "a", input_tokens=1_000_000)
            with patch.object(cost, "load_prices", return_value=PRICES), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                code = cli.main(["cost", str(run)])
        self.assertEqual(code, 0)
        self.assertIn("US$ 2.00", out.getvalue())

    def test_calls_are_charged_to_the_finding_they_were_made_for(self):
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory)
            trace(logs, "a", finding_id="org.app.Keys:::load:::KeyStoreSpec:::x:::msg",
                  input_tokens=1_000_000)
            trace(logs, "b", finding_id="org.app.Keys:::load:::KeyStoreSpec:::x:::msg",
                  output_tokens=100_000)
            trace(logs, "c", finding_id="", input_tokens=5)  # a run-wide call
            trace(logs, "d", finding_id="org.app.Keys:::load:::KeyStoreSpec", status="cache_hit")
            usage = cost.usage_by_finding(logs, PRICES)
        self.assertEqual(list(usage), [("org.app.Keys", "load", "KeyStoreSpec")])
        entry = usage[("org.app.Keys", "load", "KeyStoreSpec")]
        self.assertEqual(entry["calls"], 2)
        self.assertAlmostEqual(entry["cost_usd"], 3.0)
        self.assertEqual(cost.short_usage(entry), "2 calls, 1.1M tokens, US$ 3.00")
        self.assertIn("shared by 3 findings", cost.short_usage({**entry, "shared_by": 3}))

    def test_cost_by_outcome_groups_a_run_by_where_its_findings_ended(self):
        """M1 of BANCA_SIMULADA: the outcomes `cognalys results` shows, and
        the run's whole cost over its PR-ready drafts."""
        with tempfile.TemporaryDirectory() as directory:
            run = outcome_run(Path(directory))
            with patch.object(cost, "load_prices", return_value=PRICES):
                plain = _cost_output(["cost", str(run)])
                text = _cost_output(["cost", str(run), "--by-outcome"])
                report = json.loads(_cost_output(["cost", str(run), "--by-outcome", "--json"]))
                expected = "\n".join([str(run), *cost.summary_lines(cost.usage(
                    cost.run_log_dir(run), PRICES))]) + "\n"
        # The default report is the per-step one, as before.
        self.assertEqual(plain, expected)
        view = report[str(run)]
        self.assertEqual(list(view["by_outcome"]),
                         ["falso positivo reconhecido", "PR pronto", "não analisado"])
        positives = view["by_outcome"]["falso positivo reconhecido"]
        # US$ 1, 3 and 0 (no call): total 4, mean 4/3, median 1.
        self.assertEqual(positives["findings"], 3)
        self.assertAlmostEqual(positives["total_usd"], 4.0)
        self.assertAlmostEqual(positives["mean_usd"], 4 / 3)
        self.assertAlmostEqual(positives["median_usd"], 1.0)
        self.assertAlmostEqual(view["by_outcome"]["PR pronto"]["total_usd"], 3.0)
        self.assertAlmostEqual(view["by_outcome"]["não analisado"]["median_usd"], 0.5)
        # The run-wide call is reported apart, and counts in the per-PR figure.
        self.assertAlmostEqual(view["not_attributed_usd"], 1.0)
        self.assertAlmostEqual(view["total_usd"], 8.5)
        self.assertEqual((view["pr_ready_drafts"], view["pr_ready_findings"]), (1, 1))
        self.assertAlmostEqual(view["per_pr_ready_usd"], 8.5)
        self.assertIn("1 PR-ready draft(s): US$ 8.50 per PR-ready draft", text)
        self.assertIn("calls charged to no listed finding", text)
        self.assertRegex(text, r"falso positivo reconhecido\s+3\s+US\$ 4\.00\s+US\$ 1\.33\s+US\$ 1\.00")

    def test_without_a_ready_draft_the_count_is_given_not_a_division(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run_y"
            logs = cost.run_log_dir(run)
            logs.mkdir(parents=True)
            # One library class in two APKs: one record, theirs together.
            for apk in ("one_1.apk", "two_1.apk"):
                _extracted(run, apk, ("org.lib.Keys", "load", "KeyStoreSpec"))
            trace(logs, "a", finding_id="org.lib.Keys:::load:::KeyStoreSpec:::x",
                  input_tokens=1_000_000)  # US$ 2
            with patch.object(cost, "load_prices", return_value=PRICES):
                text = _cost_output(["cost", str(run), "--by-outcome"])
                report = json.loads(_cost_output(["cost", str(run), "--by-outcome", "--json"]))
        view = report[str(run)]
        self.assertEqual(view["by_outcome"]["não analisado"]["findings"], 2)
        self.assertAlmostEqual(view["by_outcome"]["não analisado"]["total_usd"], 2.0)
        self.assertAlmostEqual(view["by_outcome"]["não analisado"]["median_usd"], 1.0)
        self.assertAlmostEqual(view["not_attributed_usd"], 0.0)
        self.assertIsNone(view["per_pr_ready_usd"])
        self.assertIn("run total US$ 2.00; 0 PR-ready drafts", text)

    def test_findings_joined_into_one_draft_are_one_draft(self):
        """join_findings_of_one_sequence: two findings, one unit, one pull request."""
        with tempfile.TemporaryDirectory() as directory:
            run = run_directory(Path(directory))  # KEY: PR pronto
            apk, csv_class, _method, spec = KEY
            _extracted(run, apk, (csv_class, "init", spec), 1)
            write(run / "error_solutions" / "joint_findings.json", [{
                "joined": {"apk_name": apk, "csv_class": csv_class, "method_name": "init",
                           "spec": spec},
                "into": {"apk_name": apk, "csv_class": csv_class, "method_name": KEY[2],
                         "spec": spec}}])
            logs = cost.run_log_dir(run)
            logs.mkdir(parents=True)
            trace(logs, "a", finding_id=f"{csv_class}:::{KEY[2]}:::{spec}:::0",
                  input_tokens=1_000_000)  # US$ 2
            with patch.object(cost, "load_prices", return_value=PRICES):
                text = _cost_output(["cost", str(run), "--by-outcome"])
                report = json.loads(_cost_output(["cost", str(run), "--by-outcome", "--json"]))
        view = report[str(run)]
        self.assertEqual(view["by_outcome"]["PR pronto"]["findings"], 2)
        self.assertEqual((view["pr_ready_drafts"], view["pr_ready_findings"]), (1, 2))
        self.assertAlmostEqual(view["per_pr_ready_usd"], 2.0)
        self.assertIn("1 PR-ready draft(s) (2 findings): US$ 2.00 per PR-ready draft", text)

    def test_the_run_option_is_known(self):
        from cognalys.orchestration import run_pipeline

        self.assertEqual(run_pipeline.parse_args(["--llm-provider", "openai", "--max-cost", "12.5"]).max_cost, 12.5)

    def test_a_command_line_that_names_no_provider_stops_at_parsing(self):
        # A9 adjustment (the user, 2026-11-12): nothing runs, clones or spends
        # until llm-provider is named, on the command line or in the TOML.
        import contextlib
        from cognalys.orchestration import run_pipeline

        error = io.StringIO()
        with self.assertRaises(SystemExit) as stopped, contextlib.redirect_stderr(error):
            run_pipeline.parse_args([])
        self.assertEqual(stopped.exception.code, 2)
        self.assertIn("set llm-provider (openai, anthropic or ollama)", error.getvalue())

    def test_a_named_provider_runs_with_the_production_defaults(self):
        # PLANO_CORRECOES_DEFESA A9: the defaults were Ollama, codellama:7b,
        # no output cap and no ceiling, while every run set openai, the
        # production model, 32768 and a US$ 10 ceiling in its TOML.
        from cognalys.orchestration import run_pipeline

        args = run_pipeline.parse_args(["--llm-provider", "openai"])
        self.assertEqual((args.llm_provider, args.llm_model, args.llm_endpoint),
                         ("openai", "gpt-6.1-terra", "https://api.openai.com/v1"))
        self.assertEqual((args.llm_max_output_tokens, args.max_cost), (32768, 10.0))
        self.assertEqual(run_pipeline.requested_service_tier(args), "flex")
        self.assertEqual(run_pipeline.parse_args(["--llm-provider", "openai", "--max-cost", "0"]).max_cost, 0.0)
        # Ollama is one option away, with its own model and endpoint.
        ollama = run_pipeline.parse_args(["--llm-provider", "ollama"])
        self.assertEqual((ollama.llm_model, ollama.llm_endpoint),
                         ("codellama:7b", "http://localhost:11434"))
        anthropic = run_pipeline.parse_args(["--llm-provider", "anthropic", "--llm-model", "claude-x"])
        self.assertEqual((anthropic.llm_model, anthropic.llm_endpoint),
                         ("claude-x", "https://api.anthropic.com"))


class RecordedVersionTests(unittest.TestCase):
    def test_the_traces_versions_and_answering_snapshots_are_listed_once_each(self):
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory)
            trace(logs, "a", prompt_version="v3", schema_version="s2",
                  context_builder_version="c5", response_model="gpt-test-2026-10-01")
            trace(logs, "b", prompt_version="issue-text-v1", schema_version="s2",
                  response_model="gpt-test-2026-10-01")
            trace(logs, "c", status="cache_hit", prompt_version="v3")
            trace(logs, "old")  # written before the fields were recorded
            versions = cost.recorded_versions(logs)
        self.assertEqual(versions, {
            "prompt_version": ["issue-text-v1", "v3"], "schema_version": ["s2"],
            "context_builder_version": ["c5"], "response_model": ["gpt-test-2026-10-01"]})

    def test_the_analysis_summary_lists_them_after_the_model(self):
        from types import SimpleNamespace

        from cognalys.llm.generate_error_fixes import FixGenerator

        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory) / "logs"
            logs.mkdir()
            trace(logs, "a", prompt_version="v3", response_model="gpt-test-2026-10-01")
            generator = FixGenerator.__new__(FixGenerator)
            generator.output_dir = Path(directory)
            generator.logger = SimpleNamespace(info=lambda *_: None)
            generator.provider = SimpleNamespace(model="gpt-test", provider_name="openai",
                                                 endpoint="https://example.invalid",
                                                 prompt_log_dir=logs)
            generator.stats = collections.defaultdict(int)
            generator._write_summary_report()
            text = (Path(directory) / "analysis_summary.txt").read_text(encoding="utf-8")
        self.assertIn("Model: gpt-test\n", text)
        self.assertIn("RECORDED VERSIONS\n", text)
        self.assertIn("prompt_version: v3\n", text)
        self.assertIn("response_model: gpt-test-2026-10-01\n", text)
        self.assertLess(text.index("Model: gpt-test"), text.index("RECORDED VERSIONS"))

    def test_the_stage_artifacts_prompt_versions_are_read_from_the_run(self):
        with tempfile.TemporaryDirectory() as directory:
            solutions = Path(directory)
            for index, (adjudication, plan) in enumerate(((4, 10), (4, 9), (None, None))):
                artifacts = solutions / "v2_artifacts" / "app_1.apk"
                write(artifacts / f"{index}_run_adjudication.json", {
                    "decision": "FIX_SUPPORTED",
                    **({"adjudication_prompt_version": adjudication} if adjudication else {})})
                write(artifacts / f"{index}_run_patch_plan.json", {
                    "decision": "FIX_SUPPORTED",
                    **({"plan_prompt_version": plan} if plan else {})})
            write(solutions / "coordinated_drafts" / "app_1.apk" / "0_run" / "behavior_review.json",
                  {"regressions": [], "review_contract_version": 17})
            self.assertEqual(cost.recorded_artifact_versions(solutions), {
                "adjudication_prompt_version": ["4"], "plan_prompt_version": ["9", "10"],
                "review_contract_version": ["17"]})

    def test_a_run_whose_artifacts_recorded_none_lists_none(self):
        """Never the current constant: an older run would be mislabeled."""
        with tempfile.TemporaryDirectory() as directory:
            solutions = Path(directory)
            write(solutions / "v2_artifacts" / "app_1.apk" / "0_run_adjudication.json",
                  {"decision": "FIX_SUPPORTED"})
            self.assertEqual(cost.recorded_artifact_versions(solutions), {})
            self.assertEqual(cost.recorded_artifact_versions(solutions / "absent"), {})

    def test_the_analysis_summary_lists_the_artifacts_versions_too(self):
        from types import SimpleNamespace

        from cognalys.llm.generate_error_fixes import FixGenerator

        with tempfile.TemporaryDirectory() as directory:
            write(Path(directory) / "v2_artifacts" / "app_1.apk" / "0_run_adjudication.json",
                  {"adjudication_prompt_version": 3})
            write(Path(directory) / "v2_artifacts" / "app_1.apk" / "0_run_patch_plan.json",
                  {"plan_prompt_version": 8})
            generator = FixGenerator.__new__(FixGenerator)
            generator.output_dir = Path(directory)
            generator.logger = SimpleNamespace(info=lambda *_: None)
            generator.provider = SimpleNamespace(model="gpt-test", provider_name="openai",
                                                 endpoint="https://example.invalid",
                                                 prompt_log_dir=None)
            generator.stats = collections.defaultdict(int)
            generator._write_summary_report()
            text = (Path(directory) / "analysis_summary.txt").read_text(encoding="utf-8")
        self.assertIn("RECORDED VERSIONS\n", text)
        self.assertIn("adjudication_prompt_version: 3\n", text)
        self.assertIn("plan_prompt_version: 8\n", text)
        self.assertNotIn("review_contract_version", text)


class CallReservationTests(unittest.TestCase):
    """B9: a call goes only when its most still fits under the ceiling."""

    def test_a_call_that_could_pass_the_ceiling_is_refused(self):
        guard = cost.RunCostGuard(1.0, "gpt-test", 0.95, PRICES)
        # 10,000 output tokens at US$ 10 a million: a reserve of US$ 0.10.
        self.assertAlmostEqual(guard.call_bound(0, 10_000), 0.10, places=4)
        guard.check()  # what was spent is still under the ceiling
        with self.assertRaises(CallBudgetExhausted):
            guard.reserve(0, 10_000)
        self.assertEqual(guard.reserved, 0.0)

    def test_a_call_that_fits_is_held_until_it_is_charged(self):
        guard = cost.RunCostGuard(1.0, "gpt-test", 0.80, PRICES)
        guard.reserve(0, 10_000)
        self.assertAlmostEqual(guard.reserved, 0.10, places=4)
        guard.add(0, 0, 5_000)
        self.assertEqual(guard.reserved, 0.0)
        self.assertAlmostEqual(guard.spent, 0.85, places=4)

    def test_a_reserve_left_by_a_failed_call_is_freed_by_the_next(self):
        guard = cost.RunCostGuard(1.0, "gpt-test", 0.80, PRICES)
        guard.reserve(0, 10_000)  # its call failed: nothing was charged
        guard.reserve(0, 10_000)  # the same thread's next call
        self.assertAlmostEqual(guard.reserved, 0.10, places=4)

    def test_other_workers_reserves_count(self):
        import threading
        guard = cost.RunCostGuard(1.0, "gpt-test", 0.75, PRICES)
        worker = threading.Thread(target=guard.reserve, args=(0, 10_000))
        worker.start()
        worker.join()
        guard.reserve(0, 10_000)
        refused = []

        def third():
            try:
                guard.reserve(0, 10_000)
            except CallBudgetExhausted as exc:
                refused.append(exc)

        thread = threading.Thread(target=third)
        thread.start()
        thread.join()
        # 0.75 spent and two calls of 0.10 held: a third would reach 1.05.
        self.assertEqual(len(refused), 1)

    def test_input_output_ceiling_and_searches_make_the_reserve(self):
        priced = {"gpt-test": {**PRICES["gpt-test"], "web_search_per_1k_calls": 10.0}}
        guard = cost.RunCostGuard(10.0, "gpt-test", 0.0, priced)
        characters = int(1_000_000 * cost.RESERVATION_CHARS_PER_TOKEN)
        self.assertAlmostEqual(guard.call_bound(characters, 0, web_search=True),
                               2.0 + cost.UNBOUNDED_OUTPUT_RESERVATION * 10 / 1e6
                               + cost.RESERVED_WEB_SEARCH_CALLS * 0.01, places=4)


if __name__ == "__main__":
    unittest.main()
