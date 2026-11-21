import contextlib
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (project import paths)

from cognalys import cli  # noqa: E402
from cognalys.evaluation import decision_replay as replaying  # noqa: E402
from cognalys.llm import cost  # noqa: E402
from cognalys.llm.llm_providers import OpenAIProvider, trace_input_sha256  # noqa: E402

PRICES = {"gpt-test": {"input": 2.0, "cached_input": 0.5, "output": 10.0,
                       "flex": {"input": 1.0, "cached_input": 0.25, "output": 5.0}}}
FINDING = "org.example.Hasher:::digest:::MessageDigestSpec:::ForbiddenMethod:::SHA-1"
SCHEMA = {"type": "object", "properties": {"decision": {"type": "string"},
                                           "current_code_is_correct_use": {"type": "boolean"}},
          "required": ["decision", "current_code_is_correct_use"]}


def tracing_provider(log_dir: Path, model: str = "gpt-test") -> OpenAIProvider:
    """An OpenAIProvider that writes traces as a run does, without a key or a session."""
    provider = object.__new__(OpenAIProvider)
    provider.prompt_log_dir = log_dir
    provider.prompt_log_sequence = 0
    provider._state_lock = threading.Lock()
    provider.endpoint = "https://api.openai.com/v1"
    provider.model = model
    provider.timeout = 600
    provider.max_output_tokens = 32768
    provider.reasoning_effort = "high"
    provider.logger = __import__("logging").getLogger("test-decision-replay")
    return provider


def recorded_call(run: Path, stage: str, answer: dict, finding: str = FINDING,
                  prompt: str = "Adjudicate this bounded finding.\n{\"finding\": 1}",
                  usage=(100_000, 2_000), system: str = "You adjudicate a security finding.",
                  schema_name: str = "cipher_adjudication_v2") -> Path:
    """One call of ``stage`` recorded in ``run``'s traces as the provider records it."""
    log_dir = cost.run_log_dir(run)
    provider = tracing_provider(log_dir)
    call_id = provider._start_trace(
        prompt, system, True, False, SCHEMA,
        schema_name, "sent_to_openai", stage,
        {"finding_id": finding, "stage": stage}, request_fields={"input_parts": []})
    provider._finish_trace(call_id, {"status": "completed", "output": [{
        "type": "message", "content": [{"type": "output_text", "text": json.dumps(answer)}]}]},
        {"status": "success", "delivery": "sent_to_openai", "input_tokens": usage[0],
         "cached_input_tokens": 0, "output_tokens": usage[1]})
    return log_dir / f"{call_id}_request.json"


class FakeProvider:
    """Answers in turn and records each request; writes its trace like the real one."""

    def __init__(self, answers, log_dir: Path, usage=(100_000, 2_000)):
        self.answers = list(answers)
        self.sent = []
        self.usage = usage
        self.tracer = tracing_provider(log_dir)
        self._cost_guard = None

    def generate(self, prompt, system_prompt=None, json_mode=False, web_search=False,
                 json_schema=None, schema_name="pipeline_response", trace_stage="",
                 trace_context=None, parent_call_id=""):
        self._cost_guard.check()
        self.sent.append({"prompt": prompt, "system": system_prompt, "schema": json_schema,
                          "schema_name": schema_name, "json_mode": json_mode,
                          "stage": trace_stage, "context": trace_context})
        self.tracer._start_trace(prompt, system_prompt, json_mode, web_search, json_schema,
                                 schema_name, "sent_to_openai", trace_stage, trace_context)
        self._cost_guard.add(self.usage[0], 0, self.usage[1], service_tier="flex")
        return json.dumps(self.answers.pop(0))


class DecisionReplayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.run = Path(self.directory.name) / "run_v3"

    def tearDown(self):
        self.directory.cleanup()

    def _replay(self, answers, samples=3, max_cost=1.0, stage="adjudication", **kwargs):
        request = replaying.select_request(self.run, stage, "Hasher:::digest")
        providers = []

        def factory(request, log_dir, tier):
            providers.append(FakeProvider(answers, log_dir))
            return providers[0]

        report = replaying.replay(request, stage, samples, max_cost, "flex",
                                  Path(self.directory.name) / "out", prices=PRICES,
                                  provider_factory=factory, **kwargs)
        return report, (providers[0] if providers else None), request

    def test_the_recorded_request_is_sent_again_unchanged_and_its_decisions_compared(self):
        recorded_call(self.run, "adjudication",
                      {"decision": "NO_SAFE_FIX", "current_code_is_correct_use": False})
        report, provider, request = self._replay([
            {"decision": "NO_SAFE_FIX", "current_code_is_correct_use": False},
            {"decision": "FIX_SUPPORTED", "current_code_is_correct_use": False},
            {"decision": "NO_SAFE_FIX", "current_code_is_correct_use": True}])
        self.assertEqual(report["input_sha256"], request.rebuilt_sha256)
        self.assertEqual(len(provider.sent), 3)
        for sent in provider.sent:
            self.assertEqual(sent["prompt"], request.input)
            self.assertEqual(sent["system"], request.instructions)
            self.assertEqual(sent["schema"], SCHEMA)
            self.assertEqual(sent["schema_name"], "cipher_adjudication_v2")
            self.assertTrue(sent["json_mode"])
            self.assertEqual(sent["stage"], "decision_replay.adjudication")
            self.assertEqual(sent["context"]["decision_replay_of"], request.call_id)
        decision = report["summary"]["decision"]
        self.assertEqual(decision["recorded"], "NO_SAFE_FIX")
        self.assertEqual(decision["samples"], {'"NO_SAFE_FIX"': 2, '"FIX_SUPPORTED"': 1})
        self.assertTrue(decision["varies"])
        self.assertEqual(decision["same_as_recorded"], 2)
        # 2 of 3 as recorded: Wilson 95% 0.21-0.94; 1 of 3 pairs agree.
        self.assertEqual(decision["same_as_recorded_share"],
                         {"share": 0.6667, "samples": 3, "wilson95": [0.2077, 0.9385]})
        self.assertEqual(decision["agreement"], {"pairwise": 0.3333, "entropy_bits": 0.9183})
        self.assertIn("2/3 as recorded (95% CI 0.21-0.94); pairwise agreement 0.33",
                      "\n".join(replaying.report_lines(report)))
        self.assertTrue(report["summary"]["current_code_is_correct_use"]["varies"])
        # 100k input and 2k output on Flex: US$ 0.11 a sample.
        self.assertAlmostEqual(report["cost_usd"], 0.33, places=6)
        written = json.loads((Path(report["output_dir"]) / replaying.REPORT_FILE)
                             .read_text(encoding="utf-8"))
        self.assertEqual(written["summary"], report["summary"])
        # The samples' traces stay out of the run's own call logs.
        self.assertEqual(len(list(cost.run_log_dir(self.run).glob("*_request.json"))), 1)

    def test_a_record_whose_input_no_longer_hashes_to_its_digest_is_not_sent(self):
        path = recorded_call(self.run, "adjudication", {"decision": "NO_SAFE_FIX"})
        record = json.loads(path.read_text(encoding="utf-8"))
        record["input"] += " "
        path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "input_sha256"):
            self._replay([{"decision": "NO_SAFE_FIX"}])

    def test_the_ceiling_stops_before_a_sample_it_cannot_pay(self):
        recorded_call(self.run, "adjudication", {"decision": "NO_SAFE_FIX"})
        # US$ 0.11 a sample on Flex, bounded at the standard 0.22.
        report, provider, _ = self._replay([{"decision": "NO_SAFE_FIX"}] * 5, samples=5,
                                           max_cost=0.35)
        self.assertEqual(len(provider.sent), 2)
        self.assertIn("--max-cost", report["stopped"])
        self.assertLessEqual(report["cost_usd"], 0.35)
        self.assertAlmostEqual(report["cost_bound_per_sample_usd"], 0.22, places=6)

    def test_a_flex_sample_resent_on_the_standard_tier_stays_under_the_ceiling(self):
        # Flex answers 429 or leaves the request queued past its deadline, and
        # the provider sends it again on the standard tier at twice the price.
        recorded_call(self.run, "adjudication", {"decision": "NO_SAFE_FIX"})
        request = replaying.select_request(self.run, "adjudication", "Hasher:::digest")

        class StandardProvider(FakeProvider):
            def generate(self, *args, **kwargs):
                answer = super().generate(*args, **kwargs)
                self._cost_guard.add(self.usage[0], 0, self.usage[1], service_tier="")
                self._cost_guard.spent -= 0.11  # replaces the Flex charge
                return answer

        for ceiling, sent in ((0.15, 0), (0.30, 1), (0.50, 2)):
            with self.subTest(ceiling=ceiling):
                providers = []

                def factory(request, log_dir, tier):
                    providers.append(StandardProvider([{"decision": "NO_SAFE_FIX"}] * 5,
                                                      log_dir))
                    return providers[0]

                report = replaying.replay(request, "adjudication", 5, ceiling, "flex",
                                          Path(self.directory.name) / f"out{ceiling}",
                                          prices=PRICES, provider_factory=factory)
                self.assertEqual(len(providers[0].sent), sent)
                self.assertLessEqual(report["cost_usd"], ceiling)
                self.assertIn("--max-cost", report["stopped"])

    def test_a_sample_whose_trace_differs_or_is_missing_stops_and_is_not_counted(self):
        recorded_call(self.run, "adjudication", {"decision": "NO_SAFE_FIX"})
        request = replaying.select_request(self.run, "adjudication", "Hasher:::digest")

        class OtherEffort(FakeProvider):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.tracer.reasoning_effort = "medium"

        class Untraced(FakeProvider):
            def generate(self, prompt, system_prompt=None, json_mode=False, **kwargs):
                self._cost_guard.check()
                self.sent.append({"prompt": prompt})
                self._cost_guard.add(self.usage[0], 0, self.usage[1], service_tier="flex")
                return json.dumps(self.answers.pop(0))

        for cls, stopped in ((OtherEffort, "differs from the recorded one in reasoning_effort"),
                             (Untraced, "wrote no request trace")):
            with self.subTest(cls.__name__):
                providers = []

                def factory(request, log_dir, tier):
                    providers.append(cls([{"decision": "FIX_SUPPORTED"}] * 3, log_dir))
                    return providers[0]

                report = replaying.replay(request, "adjudication", 3, 1.0, "flex",
                                          Path(self.directory.name) / cls.__name__,
                                          prices=PRICES, provider_factory=factory)
                self.assertEqual(len(providers[0].sent), 1)
                self.assertIn(stopped, report["stopped"])
                self.assertTrue(report["samples"][0]["request_differs"])
                # Paid, but not a replay of the recorded request.
                self.assertAlmostEqual(report["cost_usd"], 0.11, places=6)
                self.assertEqual(report["summary"]["decision"]["samples"], {})

    def test_samples_and_a_ceiling_must_be_given(self):
        recorded_call(self.run, "adjudication", {"decision": "NO_SAFE_FIX"})
        for samples, ceiling in ((0, 1.0), (3, 0.0)):
            with self.subTest(samples=samples, ceiling=ceiling), \
                    self.assertRaises(ValueError):
                self._replay([{"decision": "NO_SAFE_FIX"}], samples=samples, max_cost=ceiling)
        base = ["decision-replay", str(self.run), "--finding", "Hasher", "--stage",
                "adjudication"]
        for argv in (base + ["--max-cost", "1"], base + ["--samples", "3"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                cli.main(argv)

    def test_a_dry_run_checks_and_estimates_and_sends_nothing(self):
        recorded_call(self.run, "adjudication", {"decision": "NO_SAFE_FIX"})
        report, provider, _ = self._replay([], dry_run=True)
        self.assertIsNone(provider)
        self.assertEqual(report["samples"], [])
        self.assertAlmostEqual(report["estimated_cost_per_sample_usd"], 0.11, places=6)
        with patch.object(replaying, "default_provider", side_effect=AssertionError("sent")), \
                patch.object(replaying, "load_prices", return_value=PRICES), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(["decision-replay", str(self.run), "--finding", "Hasher:::digest",
                             "--stage", "adjudication", "--samples", "3", "--max-cost", "1",
                             "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("dry run: nothing sent", out.getvalue())
        self.assertIn("decision: recorded \"NO_SAFE_FIX\"", out.getvalue())

    def test_the_review_verdicts_are_compared(self):
        clean = {"regressions": [], "patch_has_no_effect": False,
                 "maintainer_decision_required": False, "current_code_is_correct_use": False}
        regression = {**clean, "regressions": [{"scenario": "first run throws"}]}
        recorded_call(self.run, "code_generation.behavior_review", regression)
        report, _, _ = self._replay([clean, regression, {**clean, "patch_has_no_effect": True}],
                                    stage="behavior_review")
        verdict = report["summary"]["verdict"]
        self.assertEqual(verdict["recorded"], "regression")
        self.assertEqual(verdict["samples"],
                         {'"clean"': 1, '"regression"': 1, '"no_effect"': 1})
        self.assertEqual(report["summary"]["regressions"]["recorded"], 1)
        self.assertNotIn("concern_verdicts", report["summary"])

    def test_one_finding_is_replayed_and_its_last_call_by_default(self):
        recorded_call(self.run, "adjudication", {"decision": "NO_SAFE_FIX"})
        later = recorded_call(self.run, "adjudication", {"decision": "FIX_SUPPORTED"},
                              prompt="Adjudicate again.")
        self.assertEqual(replaying.select_request(self.run, "adjudication", "Hasher").path,
                         later)
        recorded_call(self.run, "adjudication", {"decision": "NO_SAFE_FIX"},
                      finding="org.example.Hasher:::digestAll:::MessageDigestSpec")
        with self.assertRaisesRegex(ValueError, "names 2 findings"):
            replaying.select_request(self.run, "adjudication", "Hasher:::digest")
        self.assertEqual(replaying.select_request(self.run, "adjudication", FINDING).path, later)
        with self.assertRaisesRegex(ValueError, "no recorded"):
            replaying.select_request(self.run, "behavior_review", FINDING)

    def test_the_trace_digest_is_the_one_the_replay_rebuilds(self):
        path = recorded_call(self.run, "adjudication", {"decision": "NO_SAFE_FIX"})
        record = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(record["input_sha256"],
                         trace_input_sha256(record["instructions"], record["input"]))
        self.assertTrue(replaying.load_request(path).matches_record)

    # --current-prompt and --add-section (ESPEC_Q2Q3 3.8).

    REVIEW_PAYLOAD = {"finding": {"specification": "SSLContextSpec"}, "edits": [],
                      "adjudication_concerns": [{"kind": "x", "description": "Review servers"}]}

    def _recorded_review(self, payload=None):
        from cognalys.llm.pipeline_common import prompt_json

        clean = {"regressions": [], "patch_has_no_effect": False}
        prompt = ("Review this patch.\n\n<patch_and_source untrusted_data=\"true\">\n"
                  + prompt_json(payload or self.REVIEW_PAYLOAD) + "\n</patch_and_source>")
        return recorded_call(self.run, "code_generation.behavior_review", clean, prompt=prompt,
                             system="An earlier review prompt.", schema_name="behavior_review")

    def _recorded_extraction(self, answer, system="An earlier extraction prompt.",
                             schema_name="tls_evidence_extraction_v2"):
        prompt = ("Extract claims, events, predicates, flows and unresolved relations for the "
                  "tls family.\n\n<repository_and_web_data untrusted_data=\"true\">\n"
                  "{\"stable_policy\":{}}\n</repository_and_web_data>")
        return recorded_call(self.run, "evidence_extraction", answer, prompt=prompt,
                             system=system, schema_name=schema_name)

    def test_the_current_prompt_replays_the_recorded_input_under_this_codes_instructions_and_schema(self):
        from cognalys.llm.coordinated_generation import behavior_review_system_prompt
        from cognalys.llm.llm_schemas import behavior_review_schema

        self._recorded_review()
        recorded = replaying.select_request(self.run, "behavior_review", "Hasher:::digest")
        variant = replaying.current_prompt_request(recorded, "behavior_review")
        self.assertEqual(variant.input, recorded.input)
        self.assertEqual(variant.instructions, behavior_review_system_prompt())
        self.assertEqual(variant.json_schema, behavior_review_schema())
        self.assertEqual(variant.schema_name, "behavior_review")
        self.assertEqual((variant.model, variant.reasoning_effort, variant.max_output_tokens),
                         (recorded.model, recorded.reasoning_effort, recorded.max_output_tokens))
        self.assertTrue(variant.matches_record)
        self.assertNotEqual(variant.recorded_sha256, recorded.recorded_sha256)
        self.assertEqual(variant.variant, {"of_input_sha256": recorded.recorded_sha256,
                                           "prompt": "current", "added_sections": []})
        # The record itself is left as it was.
        self.assertEqual(recorded.instructions, "An earlier review prompt.")

    def test_an_extraction_replay_takes_the_family_and_the_detector_rule_from_the_record(self):
        from cognalys.llm.finding_adjudication import (
            _REPORTED_BY_DETECTOR_EXTRACTION_RULE, evidence_extraction_system_prompt)
        from cognalys.llm.llm_contracts import (
            evidence_extraction_schema, schema_name_by_content)

        for reported in (False, True):
            with self.subTest(reported=reported):
                self.tearDown()
                self.setUp()
                system = "Earlier. " + (_REPORTED_BY_DETECTOR_EXTRACTION_RULE if reported else "")
                self._recorded_extraction({}, system=system,
                                          schema_name="message_digest_evidence_extraction_v2")
                recorded = replaying.select_request(self.run, "evidence_extraction", "Hasher")
                variant = replaying.current_prompt_request(recorded, "evidence_extraction")
                self.assertEqual(variant.instructions, evidence_extraction_system_prompt(reported))
                self.assertEqual(variant.json_schema, evidence_extraction_schema("message_digest"))
                # The name this code sends today for that schema.
                self.assertEqual(variant.schema_name, schema_name_by_content(
                    "evidence_extraction", evidence_extraction_schema("message_digest")))
                self.assertEqual(variant.input, recorded.input)
        # A record named by content: the family is the one its request names.
        self.tearDown()
        self.setUp()
        self._recorded_extraction({}, schema_name="evidence_extraction_0123456789abcdef")
        recorded = replaying.select_request(self.run, "evidence_extraction", "Hasher")
        variant = replaying.current_prompt_request(recorded, "evidence_extraction")
        self.assertEqual(variant.json_schema, evidence_extraction_schema("tls"))
        self.assertEqual(variant.schema_name, schema_name_by_content(
            "evidence_extraction", evidence_extraction_schema("tls")))
        self.tearDown()
        self.setUp()
        self._recorded_extraction({}, schema_name="cipher_adjudication_v2")
        recorded = replaying.select_request(self.run, "evidence_extraction", "Hasher")
        with self.assertRaisesRegex(ValueError, "extraction family"):
            replaying.current_prompt_request(recorded, "evidence_extraction")

    def test_an_added_section_is_spliced_last_into_the_recorded_data_block(self):
        from cognalys.llm.pipeline_common import prompt_json

        self._recorded_review()
        recorded = replaying.select_request(self.run, "behavior_review", "Hasher")
        contract = {"purpose": "Scans the LAN for servers", "counterpart": "user_operated_peer",
                    "evidence": [{"evidence_id": "SRC-004", "quote": "pinned \"fp\"\nline"}]}
        variant = replaying.current_prompt_request(
            recorded, "behavior_review", [("function_contract", contract)])
        # The bytes review_patch_behavior writes when it adds the key last.
        expected = ("Review this patch.\n\n<patch_and_source untrusted_data=\"true\">\n"
                    + prompt_json({**self.REVIEW_PAYLOAD, "function_contract": contract})
                    + "\n</patch_and_source>")
        self.assertEqual(variant.input, expected)
        self.assertEqual(variant.variant["added_sections"], ["function_contract"])
        self.assertTrue(variant.matches_record)

    def test_a_section_already_in_the_payload_a_stage_without_a_builder_or_a_record_that_does_not_rebuild_is_refused(self):
        path = self._recorded_review()
        recorded = replaying.select_request(self.run, "behavior_review", "Hasher")
        with self.assertRaisesRegex(ValueError, "already has a section 'edits'"):
            replaying.current_prompt_request(recorded, "behavior_review", [("edits", [])])
        with self.assertRaisesRegex(ValueError, "only"):
            replaying.current_prompt_request(recorded, "adjudication")
        self._recorded_extraction({})
        extraction = replaying.select_request(self.run, "evidence_extraction", "Hasher")
        with self.assertRaisesRegex(ValueError, "behavior_review request only"):
            replaying.current_prompt_request(extraction, "evidence_extraction", [("x", 1)])
        broken = replaying.load_request(path)
        broken.input = broken.input.replace("}\n</patch_and_source>", "]\n</patch_and_source>")
        broken.recorded_sha256 = broken.rebuilt_sha256
        with self.assertRaisesRegex(ValueError, "does not end in a JSON object"):
            replaying.current_prompt_request(broken, "behavior_review", [("x", 1)])
        record = json.loads(path.read_text(encoding="utf-8"))
        record["input"] += " "
        path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not rebuild"):
            replaying.current_prompt_request(replaying.load_request(path), "behavior_review")

    def test_a_variant_is_checked_against_its_own_digest_and_reports_what_it_is_a_variant_of(self):
        self._recorded_review()
        recorded = replaying.select_request(self.run, "behavior_review", "Hasher")
        variant = replaying.current_prompt_request(recorded, "behavior_review",
                                                   [("function_contract", {"purpose": "p"})])
        providers = []

        def factory(request, log_dir, tier):
            providers.append(FakeProvider([{"regressions": [], "patch_has_no_effect": False}] * 2,
                                          log_dir))
            return providers[0]

        report = replaying.replay(variant, "behavior_review", 2, 1.0, "flex",
                                  Path(self.directory.name) / "variant", prices=PRICES,
                                  provider_factory=factory)
        self.assertEqual([sent["prompt"] for sent in providers[0].sent], [variant.input] * 2)
        self.assertEqual(providers[0].sent[0]["system"], variant.instructions)
        self.assertFalse(any(sample.get("request_differs") for sample in report["samples"]))
        self.assertEqual(report["summary"]["verdict"]["samples"], {'"clean"': 2})
        self.assertEqual(report["variant"]["of_input_sha256"], recorded.recorded_sha256)
        text = "\n".join(replaying.report_lines(report))
        self.assertIn(f"variant: this code's instructions and schema on the recorded input "
                      f"(recorded input_sha256 {recorded.recorded_sha256[:12]}; added sections "
                      "function_contract); the recorded answer was given under the earlier prompt",
                      text)

    def test_an_extraction_replay_compares_the_contract_and_the_violated_predicates(self):
        recorded_answer = {"predicate_assessment": [{"status": "violated"}, {"status": "confirmed"},
                                                    {"status": "violated"}],
                           "needs_more_evidence": False, "requested_evidence": []}
        self._recorded_extraction(recorded_answer)
        established = {**recorded_answer, "predicate_assessment": [{"status": "violated"}],
                       "requested_evidence": [{"kind": "source"}],
                       "function_contract": {"depends_on_reported_behavior": "established",
                                             "counterpart": "user_operated_peer",
                                             "activation": "always"}}
        recorded = replaying.select_request(self.run, "evidence_extraction", "Hasher")
        variant = replaying.current_prompt_request(recorded, "evidence_extraction")
        providers = []

        def factory(request, log_dir, tier):
            providers.append(FakeProvider([established], log_dir))
            return providers[0]

        report = replaying.replay(variant, "evidence_extraction", 1, 1.0, "flex",
                                  Path(self.directory.name) / "x", prices=PRICES,
                                  provider_factory=factory)
        summary = report["summary"]
        self.assertEqual(summary["violated_predicates"]["recorded"], 2)
        self.assertEqual(summary["violated_predicates"]["samples"], {"1": 1})
        self.assertEqual(summary["function_contract"]["samples"],
                         {'"established/user_operated_peer/always"': 1})
        self.assertIsNone(summary["function_contract"]["recorded"])
        self.assertEqual(summary["requested_evidence"]["samples"], {"1": 1})
        self.assertEqual(summary["needs_more_evidence"]["same_as_recorded"], 1)
        # One sample: the share is 1 and its interval wide; no pair to agree.
        self.assertEqual(summary["needs_more_evidence"]["same_as_recorded_share"]["wilson95"],
                         [0.2065, 1.0])
        self.assertEqual(summary["needs_more_evidence"]["agreement"],
                         {"pairwise": None, "entropy_bits": 0.0})

    def test_add_section_without_current_prompt_exits_2(self):
        self._recorded_review()
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = cli.main(["decision-replay", str(self.run), "--finding", "Hasher",
                             "--stage", "behavior_review", "--samples", "1", "--max-cost", "1",
                             "--dry-run", "--add-section", "function_contract=x.json"])
        self.assertEqual(code, 2)
        self.assertIn("decision-replay: --add-section needs --current-prompt", err.getvalue())
        section = Path(self.directory.name) / "contract.json"
        section.write_text(json.dumps({"purpose": "p"}), encoding="utf-8")
        with patch.object(replaying, "load_prices", return_value=PRICES), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(["decision-replay", str(self.run), "--finding", "Hasher",
                             "--stage", "behavior_review", "--samples", "1", "--max-cost", "1",
                             "--dry-run", "--current-prompt", "--add-section",
                             f"function_contract={section}", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["variant"]["added_sections"],
                         ["function_contract"])

    def test_without_the_new_options_the_request_and_report_are_unchanged(self):
        self._recorded_review()
        recorded = replaying.select_request(self.run, "behavior_review", "Hasher")
        self.assertEqual(recorded.variant, {})
        report, provider, request = self._replay(
            [{"regressions": [], "patch_has_no_effect": False}], samples=1,
            stage="behavior_review")
        self.assertEqual(provider.sent[0]["prompt"], request.input)
        self.assertEqual(provider.sent[0]["system"], "An earlier review prompt.")
        self.assertNotIn("variant", report)
        self.assertFalse(any("variant" in line for line in replaying.report_lines(report)))


if __name__ == "__main__":
    unittest.main()
