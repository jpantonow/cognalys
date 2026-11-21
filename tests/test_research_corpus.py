"""The research corpus: shared research answers kept per request across runs (ESPEC_K3)."""
import json
import os
import shutil
import tempfile
import unittest
import unittest.mock
from datetime import datetime, timedelta
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm import llm_providers as provider_module  # noqa: E402
from cognalys.llm import research_corpus as corpus_module  # noqa: E402
from cognalys.llm.llm_providers import OpenAIProvider  # noqa: E402
from cognalys.llm.research_corpus import (  # noqa: E402
    IDENTITY_FIELDS, ResearchCorpus, corpus_digest, entry_key, import_runs, listing,
    pass_completed, recorded_pass_identity, request_identity, storable,
)

ANSWER = json.dumps({"sources": [{"url": "https://docs.example/api", "title": "API"}],
                     "externally_confirmed_facts": ["a fact"]})


def identity(**changes):
    fields = {
        "provider": "openai", "endpoint": "https://api.openai.com/v1", "model": "gpt-6.1-terra",
        "reasoning_effort": "high", "max_output_tokens": 32768, "system_prompt": "system",
        "prompt": "questions", "json_schema": {"type": "object", "properties": {}},
        "schema_name": "external_research_v2",
        "research_instructions": corpus_module.RESEARCH_PASS_INSTRUCTIONS,
        "synthesis_header": corpus_module.SYNTHESIS_RESULT_HEADER,
        "synthesis_instructions": corpus_module.SYNTHESIS_PASS_INSTRUCTIONS,
        "web_search_tool": {"type": "web_search_preview", "search_context_size": "medium"},
    }
    fields.update(changes)
    return request_identity(**fields)


SCOPE = {"kind": "governed_api_and_rule", "specification": "CipherSpec", "rule_sha256": "ab"}


class ResearchCorpusTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory, True)

    def test_round_trip_serves_the_stored_text_byte_for_byte(self):
        corpus = ResearchCorpus(self.directory)
        text = json.dumps({"sources": [{"url": "https://a.example"}], "note": "é ü"},
                          ensure_ascii=False) + "\n  "
        self.assertEqual(corpus.put(identity(), SCOPE, text, "brief", {"cost_usd": 0.05}),
                         "stored")
        entry = corpus.get(identity())
        self.assertEqual(entry["response"], text)
        self.assertEqual(entry["research_text"], "brief")
        self.assertEqual(entry["scope"], SCOPE)
        self.assertEqual(corpus.stats()["hits"], 1)
        self.assertTrue((self.directory / f"{entry_key(identity())}.json").is_file())

    def test_any_changed_request_field_is_another_key(self):
        base = identity()
        changes = {"provider": "anthropic", "endpoint": "https://other", "model": "gpt-other",
                   "reasoning_effort": "medium", "max_output_tokens": 16000,
                   "system_prompt": "system.", "prompt": "questions.",
                   "json_schema": {"type": "object"}, "schema_name": "other",
                   "research_instructions": "x", "synthesis_header": "y",
                   "synthesis_instructions": "z", "web_search_tool": {"type": "web_search"}}
        self.assertEqual(set(changes), set(IDENTITY_FIELDS))
        corpus = ResearchCorpus(self.directory)
        corpus.put(base, SCOPE, ANSWER, "brief", {})
        for name, value in changes.items():
            with self.subTest(field=name):
                changed = identity(**{name: value})
                self.assertNotEqual(entry_key(changed), entry_key(base))
                self.assertIsNone(corpus.get(changed))
        with self.assertRaises(TypeError):
            request_identity(provider="openai")

    def test_a_schema_holding_a_tuple_still_hits_after_storing(self):
        schema = {"type": "object", "required": ("a", "b")}
        corpus = ResearchCorpus(self.directory)
        corpus.put(identity(json_schema=schema), SCOPE, ANSWER, "brief", {})
        self.assertIsNotNone(ResearchCorpus(self.directory).get(identity(json_schema=schema)))

    def test_an_entry_older_than_the_maximum_age_is_refused_and_zero_never_expires(self):
        old = (datetime.now() - timedelta(days=91)).isoformat(timespec="seconds")
        ResearchCorpus(self.directory).put(identity(), SCOPE, ANSWER, "brief", {},
                                           created_at=old)
        aged = ResearchCorpus(self.directory, max_age_days=90)
        self.assertIsNone(aged.get(identity()))
        self.assertEqual((aged.stats()["misses"], aged.stats()["expired"]), (1, 1))
        self.assertIsNotNone(ResearchCorpus(self.directory, max_age_days=0).get(identity()))
        self.assertIsNotNone(ResearchCorpus(self.directory, max_age_days=92).get(identity()))
        # An unreadable date counts as expired.
        path = self.directory / f"{entry_key(identity())}.json"
        entry = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps({**entry, "created_at": "yesterday"}), encoding="utf-8")
        self.assertIsNone(ResearchCorpus(self.directory).get(identity()))

    def test_an_entry_whose_text_was_edited_is_refused(self):
        corpus = ResearchCorpus(self.directory)
        corpus.put(identity(), SCOPE, ANSWER, "brief", {})
        path = self.directory / f"{entry_key(identity())}.json"
        entry = json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps({**entry, "response": ANSWER + " "}), encoding="utf-8")
        self.assertIsNone(corpus.get(identity()))
        path.write_text(json.dumps({**entry, "request": identity(prompt="other")}),
                        encoding="utf-8")
        self.assertIsNone(corpus.get(identity()))

    def test_a_valid_entry_is_never_replaced_and_an_expired_one_is_superseded(self):
        corpus = ResearchCorpus(self.directory)
        other = json.dumps({"sources": [{"url": "https://other.example"}]})
        self.assertEqual(corpus.put(identity(), SCOPE, ANSWER, "first", {}), "stored")
        self.assertEqual(corpus.put(identity(), SCOPE, other, "second", {}), "kept")
        self.assertEqual(corpus.get(identity())["response"], ANSWER)
        old = (datetime.now() - timedelta(days=100)).isoformat(timespec="seconds")
        self.assertEqual(corpus.put(identity(), SCOPE, ANSWER, "old", {}, created_at=old,
                                    replace=True), "stored")
        self.assertEqual(corpus.put(identity(), SCOPE, other, "new", {}), "stored")
        self.assertEqual(corpus.get(identity())["response"], other)
        superseded = list((self.directory / corpus_module.SUPERSEDED_DIRECTORY).glob("*.json"))
        self.assertEqual(len(superseded), 2)
        self.assertTrue(any(stamp in path.name for path in superseded
                            for stamp in [datetime.fromisoformat(old).strftime("%Y%m%dT%H%M%S")]))
        self.assertEqual(corpus.stats()["kept"], 1)

    def test_an_answer_without_a_source_or_that_is_not_json_is_not_stored(self):
        corpus = ResearchCorpus(self.directory)
        for answer in ("not json", "[]", json.dumps({"sources": []}),
                       json.dumps({"sources": [{"url": ""}]}), json.dumps({"facts": []})):
            with self.subTest(answer=answer):
                self.assertFalse(storable(answer))
                self.assertEqual(corpus.put(identity(), SCOPE, answer, "brief", {}), "refused")
        self.assertEqual(list(self.directory.glob("*.json")), [])
        self.assertTrue(storable(ANSWER))

    def test_pass_completed_reads_openai_status_anthropic_stop_reason_and_degenerate_stops(self):
        self.assertTrue(pass_completed({"delivery": "sent_to_openai", "response_status": "completed"}))
        self.assertFalse(pass_completed({"delivery": "sent_to_openai",
                                         "response_status": "incomplete"}))
        self.assertFalse(pass_completed({"delivery": "sent_to_openai", "response_status": "completed",
                                         "degenerate_output_stopped": {"whitespace_run": 9}}))
        self.assertTrue(pass_completed({"delivery": "sent_to_anthropic", "stop_reason": "end_turn"}))
        self.assertFalse(pass_completed({"delivery": "sent_to_anthropic",
                                         "stop_reason": "max_tokens"}))
        self.assertTrue(pass_completed({"delivery": "cache_hit"}))
        self.assertTrue(pass_completed({"delivery": "finding_replay"}))
        self.assertFalse(pass_completed({"status": "error"}))

    def test_entries_are_listed_with_scope_age_sources_and_cost(self):
        corpus = ResearchCorpus(self.directory)
        stamp = (datetime.now() - timedelta(days=3)).isoformat(timespec="seconds")
        corpus.put(identity(), SCOPE, ANSWER, "brief", {"cost_usd": 0.0573}, origin="import",
                   created_at=stamp)
        (row,) = listing(self.directory)
        self.assertEqual((row["origin"], row["scope"], row["sources"], row["cost_usd"]),
                         ("import", SCOPE, 1, 0.0573))
        self.assertAlmostEqual(row["age_days"], 3.0, places=1)
        self.assertEqual(row["created_at"], stamp)

    def test_the_digest_depends_on_keys_and_texts_only(self):
        self.assertEqual(corpus_digest(self.directory / "absent"),
                         {"path": str(self.directory / "absent"), "entries": 0, "sha256": ""})
        first = ResearchCorpus(self.directory / "a")
        second = ResearchCorpus(self.directory / "b")
        first.put(identity(), SCOPE, ANSWER, "brief", {"cost_usd": 1}, created_at="2026-11-01T00:00:00")
        second.put(identity(), {"other": "scope"}, ANSWER, "other brief", {}, origin="import")
        self.assertEqual(corpus_digest(self.directory / "a")["sha256"],
                         corpus_digest(self.directory / "b")["sha256"])
        second.put(identity(prompt="another"), SCOPE, ANSWER, "brief", {})
        self.assertNotEqual(corpus_digest(self.directory / "a")["sha256"],
                            corpus_digest(self.directory / "b")["sha256"])
        self.assertEqual(corpus_digest(self.directory / "b")["entries"], 2)


class _Response:
    def __init__(self, payload):
        self.status_code = 200
        self._payload = payload
        self.text = json.dumps(payload)
        self.headers = {}

    def json(self):
        return self._payload


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
        return _Response(answer)

    def get(self, url, **_kwargs):
        raise AssertionError("no poll expected")


class _Guard:
    def __init__(self):
        self.added = []

    def check(self):
        pass

    def add(self, *tokens, **_kwargs):
        self.added.append(tokens)


BRIEF = {"id": "r1", "status": "completed", "output_text": "brief https://docs.example/api",
         "usage": {"input_tokens": 100, "output_tokens": 10}}
SYNTHESIS = {"id": "r2", "status": "completed", "output_text": ANSWER,
             "usage": {"input_tokens": 50, "output_tokens": 5}}
SCHEMA = {"type": "object", "properties": {}}


def recording_provider(logs: Path, session, **kwargs) -> OpenAIProvider:
    with unittest.mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
        provider = OpenAIProvider(prompt_log_dir=logs, cache_dir=None, **kwargs)
    provider.session = session
    provider.web_search_session = session
    provider._sleep = lambda _seconds: None
    provider._cost_guard = _Guard()
    return provider


def research(provider, part="shared", prompt="questions", scope=None):
    return provider.generate(prompt, "system", json_mode=True, web_search=True,
                             json_schema=SCHEMA, schema_name="external_research_v2",
                             trace_stage="external_research",
                             trace_context={"finding_id": "a.B:::m:::CipherSpec",
                                            "stage": f"external_research.{part}"},
                             research_corpus_scope=scope)


class ResearchCorpusImportTests(unittest.TestCase):
    """Entries built from the traces an OpenAIProvider wrote, as a recorded run's."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)

    def record(self, name, *answers, part="shared", prompt="questions", **kwargs):
        logs = self.root / name / "application_results" / "openai_prompt_logs"
        provider = recording_provider(logs, _Session(*answers), **kwargs)
        research(provider, part, prompt)
        return self.root / name, provider

    def test_an_imported_pass_is_served_to_the_run_that_asks_the_same_request(self):
        run, _ = self.record("run", BRIEF, SYNTHESIS)
        report = import_runs(self.root / "corpus", [run])
        self.assertEqual((report["passes_seen"], report["passes_importable"], report["keys"],
                          report["stored"]), (1, 1, 1, 1))
        session = _Session(BRIEF)
        provider = recording_provider(self.root / "logs2", session)
        provider.research_corpus = ResearchCorpus(self.root / "corpus")
        self.assertEqual(research(provider, scope=SCOPE), ANSWER)
        self.assertEqual(session.payloads, [])
        entry = listing(self.root / "corpus")[0]
        self.assertEqual(entry["origin"], "import")
        stored = json.loads((self.root / "corpus" / f"{entry['key']}.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["research_text"], BRIEF["output_text"])
        self.assertEqual(stored["provenance"]["source"],
                         str(run / "application_results" / "openai_prompt_logs"))

    def test_the_most_recent_pass_of_a_key_is_kept_across_paths_of_one_call(self):
        first, _ = self.record("run_a", BRIEF, SYNTHESIS)
        later_answer = json.dumps({"sources": [{"url": "https://later.example"}]})
        second, _ = self.record("run_b", BRIEF, {**SYNTHESIS, "output_text": later_answer})
        logs_b = second / "application_results" / "openai_prompt_logs"
        for path in logs_b.glob("*synthesis_metadata.json"):
            record = json.loads(path.read_text(encoding="utf-8"))
            path.write_text(json.dumps({**record, "completed_at": "2099-01-01T00:00:00"}),
                            encoding="utf-8")
        # The same call given twice (run folder and its log folder) counts once.
        report = import_runs(self.root / "corpus", [second, first, logs_b], max_age_days=0)
        self.assertEqual((report["passes_seen"], report["keys"], report["stored"]), (2, 1, 1))
        (entry,) = listing(self.root / "corpus")
        self.assertEqual(entry["created_at"], "2099-01-01T00:00:00")

    def test_case_passes_failed_passes_and_cache_hits_are_not_imported(self):
        case, _ = self.record("case", BRIEF, SYNTHESIS, part="case")
        failed, _ = self.record("failed", BRIEF, SYNTHESIS)
        for path in failed.rglob("*synthesis_metadata.json"):
            record = json.loads(path.read_text(encoding="utf-8"))
            path.write_text(json.dumps({**record, "status": "timeout"}), encoding="utf-8")
        cached_logs = self.root / "cached" / "application_results" / "openai_prompt_logs"
        with tempfile.TemporaryDirectory() as cache_dir:
            provider = recording_provider(cached_logs, _Session(BRIEF, SYNTHESIS))
            provider.cache = provider_module.LLMResponseCache(Path(cache_dir))
            research(provider)
            research(provider)  # answered by the cache: both passes cache hits
        report = import_runs(self.root / "corpus", [case, failed, self.root / "cached"])
        self.assertEqual(report["skipped"].get("not_shared"), 1)
        self.assertEqual(report["skipped"].get("failed"), 1)
        self.assertEqual(report["skipped"].get("not_paid"), 1)
        self.assertEqual(report["passes_importable"], 1)  # the cached run's first, paid pass

    def test_an_incomplete_pass_is_not_imported(self):
        run, _ = self.record("run", {**BRIEF, "status": "incomplete"}, SYNTHESIS)
        report = import_runs(self.root / "corpus", [run])
        self.assertEqual(report["skipped"], {"not_completed": 1})
        self.assertEqual(report["stored"], 0)

    def test_an_existing_entry_is_kept_unless_replace(self):
        run, _ = self.record("run", BRIEF, SYNTHESIS)
        self.assertEqual(import_runs(self.root / "corpus", [run])["stored"], 1)
        self.assertEqual(import_runs(self.root / "corpus", [run])["kept"], 1)
        replaced = import_runs(self.root / "corpus", [run], replace=True)
        self.assertEqual((replaced["stored"], replaced["kept"]), (1, 0))
        self.assertEqual(len(list((self.root / "corpus" / "superseded").glob("*.json"))), 1)

    def test_a_dry_run_writes_nothing(self):
        run, _ = self.record("run", BRIEF, SYNTHESIS)
        report = import_runs(self.root / "corpus", [run], dry_run=True)
        self.assertEqual(report["stored"], 1)
        self.assertFalse((self.root / "corpus").exists())
        with self.assertRaises(ValueError):
            import_runs(self.root / "corpus", [self.root / "absent"])

    def test_a_trace_without_the_tool_field_takes_the_tool_of_its_time(self):
        run, provider = self.record("run", BRIEF, SYNTHESIS)
        logs = run / "application_results" / "openai_prompt_logs"
        for path in logs.glob("*research_request.json"):
            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(record.pop("web_search_tool"), provider.WEB_SEARCH_TOOL)
            path.write_text(json.dumps(record), encoding="utf-8")
        import_runs(self.root / "corpus", [run])
        expected = provider._research_identity("questions", "system", SCHEMA,
                                               "external_research_v2")
        self.assertIsNotNone(ResearchCorpus(self.root / "corpus").get(expected))
        research_request = json.loads(next(logs.glob("*research_request.json")).read_text(
            encoding="utf-8"))
        synthesis_request = json.loads(next(logs.glob("*synthesis_request.json")).read_text(
            encoding="utf-8"))
        self.assertIsNone(recorded_pass_identity(research_request, synthesis_request,
                                                 {"delivery": "cache_hit"}))
        identified, text = recorded_pass_identity(research_request, synthesis_request,
                                                  {"delivery": "sent_to_anthropic"})
        self.assertEqual(identified["web_search_tool"],
                         corpus_module.TOOL_BEFORE_TRACE_FIELD["anthropic"])
        self.assertEqual(text, BRIEF["output_text"])


class RunOptionTests(unittest.TestCase):
    def test_the_corpus_options_reach_the_llm_step_only_when_given(self):
        from cognalys.orchestration import run_pipeline

        root = Path("/workspace")
        paths = run_pipeline.PipelinePaths(
            root=root, input_csv_file=root / "in.csv", csv_file=root / "out.csv",
            cloned_projects_dir=root / "cloned", extracted_methods_dir=root / "extracted",
            build_output_dir=root / "build", error_solutions_dir=root / "solutions",
            application_results_dir=root / "results", worktrees_dir=root / "worktrees",
            pull_requests_dir=root / "prs", issues_dir=root / "issues",
            previews_dir=root / "previews")
        without = run_pipeline._command_llm("llm", run_pipeline.parse_args(["--llm-provider", "openai"]), paths, "python")
        self.assertNotIn("--research-corpus-dir", without)
        given = run_pipeline._command_llm("llm", run_pipeline.parse_args(["--llm-provider", "openai", 
            "--llm-research-corpus-dir", "outputs/research_corpus",
            "--llm-research-corpus-max-age-days", "30"]), paths, "python")
        index = given.index("--research-corpus-dir")
        self.assertEqual(given[index:index + 4], [
            "--research-corpus-dir", str(Path("/workspace/outputs/research_corpus")),
            "--research-corpus-max-age-days", "30.0"])
        self.assertEqual([item for item in given if item not in given[index:index + 4]], without)


if __name__ == "__main__":
    unittest.main()
