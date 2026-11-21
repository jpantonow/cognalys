"""External research is supplementary, and must behave like it.

On 2026-09-07 an analysis run died on its first LLM call. The provider
answered HTTP 400 with code "cyber_policy" -- a verdict on the prompt's
content -- after 10min26s of web search, and the generic RuntimeError that
became took the whole finding down and failed the pipeline step, even though
the repository evidence packet was already built and stands on its own.

The prompt that was refused was also unanswerable. Its questions were
templated around the specification's governed API type, and the
specification in play, SQLInjectionSpec, had no verified source and named
"com.owncloud.android.providers.SQLInjection" -- a class that does not
exist. Research built from that asks the open web to confirm a fictional
type and to assess a named product's runtime behaviour, while the same
prompt forbids inspecting the repository that could settle it.

Both halves are covered here: research that cannot be answered is not
requested, and research that is refused does not cost the finding.
"""
import json
import logging
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.generate_error_fixes import FixGenerator  # noqa: E402
from cognalys.llm.llm_providers import (  # noqa: E402
    BackgroundResponseFailed, ProviderContentRefusal, ProviderTransientFailure,
)
from cognalys.llm.pipeline_architecture import (  # noqa: E402
    FindingEvidencePacketBuilder,
    PolicyRegistry,
    advisory_identifiers,
)


class _StageProvider:
    """Answers by trace_stage and records the order it was asked."""

    provider_name = "test"
    model = "test-model"

    def __init__(self, refuse_research=False, research_sources=None, failures=None):
        self.refuse_research = refuse_research
        self.research_sources = research_sources or []
        # stage -> the exception that stage raises (the provider's own
        # resends already spent).
        self.failures = dict(failures or {})
        self.calls = []
        self.prompts = {}

    @staticmethod
    def get_token_usage():
        return {"input": 0, "output": 0}

    def generate(self, _prompt, _system=None, **kwargs):
        stage = kwargs.get("trace_stage", "")
        self.calls.append(stage)
        self.prompts.setdefault(stage, _prompt)
        if stage in self.failures:
            raise self.failures[stage]
        if stage == "external_research":
            if self.refuse_research:
                raise ProviderContentRefusal(
                    "OpenAI refused this request's content (cyber_policy)",
                    code="cyber_policy", status_code=400,
                )
            return json.dumps({
                "queries_performed": [], "sources": self.research_sources,
                "externally_confirmed_facts": [],
                "externally_unresolved_questions": [],
            })
        if stage == "evidence_extraction":
            return json.dumps({
                "claims": [], "observed_events": [], "predicate_assessment": [],
                "confirmed_dataflows": [], "relations": [],
                "unresolved_questions": [], "needs_more_evidence": False,
                "requested_evidence": [], "family_assessment": {},
            })
        # Anything later abstains, which is enough: the point is that the
        # finding reached these stages at all.
        return json.dumps({
            "cause_status": "unknown", "confirmed_cause": "",
            "detector_violation": "unknown",
            "runtime_security_impact": "unknown",
            "compatibility_status": "unknown", "scope_status": "incomplete",
            "decision": "NO_SAFE_FIX", "decision_claim_ids": [],
            "blocking_for_generation": [], "blocking_for_publication": [],
            "generation_status": "blocked", "publication_status": "blocked",
            "required_edit_categories": [], "required_tests": [],
            "forward_compatibility_strategy": "",
            "authorized_behavior_change": {
                "authorized": False, "description": "", "policy_reference": "",
            },
            "review_assumptions": [],
        })


def _error(specification_context: dict) -> dict:
    return {
        "spec": "SQLInjectionSpec",
        "method_name": "delete",
        "method_body": "db.delete(table, where, whereArgs)",
        "imports": "",
        "source_file_path": (
            "owncloudApp/src/main/java/com/owncloud/android/providers/"
            "FileContentProvider.kt"
        ),
        "csv_class": "com.owncloud.android.providers.FileContentProvider",
        "error_message": (
            "expecting ContentProvider SQL predicates to be parameterized"
        ),
        "specification_context": specification_context,
    }


UNANCHORED = {
    # SQLInjectionSpec exactly as it was generated: the CrySL source_url
    # answered 404, so source_verified stayed false, and the governed type
    # is a placeholder built out of the reported class's own package.
    "status": "available",
    "source_verified": False,
    "source_url": (
        "https://raw.githubusercontent.com/CROSSINGTUD/Crypto-API-Rules/"
        "refs/heads/master/JavaCryptographicArchitecture/src/SQLInjection.crysl"
    ),
    "applies_to_types": ["com.owncloud.android.providers.SQLInjection"],
}

ANCHORED = {
    "status": "available",
    "source_verified": True,
    "source_url": "https://example.invalid/Cipher.crysl",
    "applies_to_types": ["javax.crypto.Cipher"],
}


class ExternalResearchResilienceTests(unittest.TestCase):

    def _generator(self, root: Path, provider) -> FixGenerator:
        generator = object.__new__(FixGenerator)
        generator.output_dir = root / "out"
        generator.provider = provider
        generator.web_search = True
        generator.architecture_version = "v2"
        generator.logger = logging.getLogger("external-research-resilience")
        generator.evidence_packet_builder = FindingEvidencePacketBuilder(
            repository_context_budget=140_000
        )
        generator.policy_registry = PolicyRegistry(root / "no_policies")
        return generator

    def test_an_unanchored_specification_asks_the_web_nothing(self):
        provider = _StageProvider()
        with tempfile.TemporaryDirectory() as directory:
            generator = self._generator(Path(directory), provider)
            generator.adjudicate_finding(
                _error(UNANCHORED), "owncloud.apk", "delete"
            )

        self.assertNotIn("external_research", provider.calls)
        # The finding is still analysed on repository evidence.
        self.assertIn("evidence_extraction", provider.calls)

    def test_an_advisory_is_researched_even_without_an_anchored_spec(self):
        """A published advisory is an authority the finding already names.

        com.amaze.filemanager's FtpReceiver reported CVE-2020-35173 and its
        specification was an invented CrySL type, so no question was built
        from either source and external_research.json recorded zero queries --
        while the adjudication blocked generation on exactly the semantics
        the advisory states.
        """
        provider = _StageProvider()
        error = _error(UNANCHORED)
        error["error_message"] = (
            "External finding (CVE-2020-35173): onReceive starts or stops "
            "FtpService in response to external broadcast actions."
        )
        with tempfile.TemporaryDirectory() as directory:
            generator = self._generator(Path(directory), provider)
            generator.adjudicate_finding(error, "amaze.apk", "onReceive")

        self.assertIn("external_research", provider.calls)
        self.assertIn("CVE-2020-35173", provider.prompts["external_research"])

    def test_the_adjudicator_is_given_the_external_sources_and_their_ids(self):
        """Research that stops at the extraction changes no decision.

        FtpReceiver's research resolved CVE-2020-35173 to the fix commit, the
        released manifest and the pull request stating the compatibility
        consequence; the extraction cited those as WEB-004 and WEB-005, and
        the adjudication was handed neither the sources nor their ids -- so
        it listed the question they answer as unknown.
        """
        provider = _StageProvider(research_sources=[{
            "url": "https://github.com/TeamAmaze/AmazeFileManager/commit/e0aaf70",
            "authority": "primary",
            "claim": "The merged fix applies android:permission to FtpReceiver.",
            "relevance": "Primary documentation of the released remediation.",
            "limitations": "No comprehensive compatibility guide.",
        }])
        error = _error(UNANCHORED)
        error["error_message"] = "External finding (CVE-2020-35173): onReceive"
        with tempfile.TemporaryDirectory() as directory:
            generator = self._generator(Path(directory), provider)
            generator.adjudicate_finding(error, "amaze.apk", "onReceive")

        adjudication = provider.prompts["adjudication"]
        self.assertIn("WEB-001", adjudication)
        self.assertIn("commit/e0aaf70", adjudication)

    def test_only_the_shared_part_names_its_corpus_scope_and_only_with_a_corpus(self):
        class Recording(_StageProvider):
            def generate(self, prompt, system=None, **kwargs):
                if kwargs.get("trace_stage") == "external_research":
                    self.research_kwargs = getattr(self, "research_kwargs", []) + [kwargs]
                return super().generate(prompt, system, **kwargs)

        for corpus in (None, object()):
            with self.subTest(corpus=corpus is not None):
                provider = Recording()
                if corpus is not None:
                    provider.research_corpus = corpus
                with tempfile.TemporaryDirectory() as directory:
                    generator = self._generator(Path(directory), provider)
                    generator.adjudicate_finding(_error(ANCHORED), "app.apk", "encrypt")
                parts = {kwargs["trace_context"]["stage"]: kwargs
                         for kwargs in provider.research_kwargs}
                self.assertEqual(set(parts), {"external_research.shared",
                                              "external_research.case"})
                self.assertNotIn("research_corpus_scope", parts["external_research.case"])
                shared = parts["external_research.shared"]
                if corpus is None:
                    self.assertNotIn("research_corpus_scope", shared)
                else:
                    self.assertEqual(shared["research_corpus_scope"]["kind"],
                                     "governed_api_and_rule")

    def test_the_extraction_reads_each_source_once_with_its_web_id(self):
        provider = _StageProvider(research_sources=[{
            "url": "https://example.invalid/javadoc/Cipher.html",
            "authority": "primary", "claim": "AES defaults to ECB.",
            "relevance": "r", "limitations": "l",
        }])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generator = self._generator(root, provider)
            generator.adjudicate_finding(_error(ANCHORED), "app.apk", "encrypt")
            research = json.loads(
                (root / "out" / "v2_artifacts" / "app.apk"
                 / "0_encrypt_external_research.json").read_text(encoding="utf-8"))

        extraction = provider.prompts["evidence_extraction"]
        self.assertEqual(extraction.count("javadoc/Cipher.html"), 1)
        self.assertIn('"evidence_id":"WEB-001"', extraction)
        # The research on disk keeps its sources.
        self.assertEqual(research["sources"][0]["evidence_id"], "WEB-001")

    def test_a_finding_naming_no_advisory_still_asks_the_web_nothing(self):
        provider = _StageProvider()
        with tempfile.TemporaryDirectory() as directory:
            generator = self._generator(Path(directory), provider)
            generator.adjudicate_finding(
                _error(UNANCHORED), "owncloud.apk", "delete"
            )

        self.assertNotIn("external_research", provider.calls)

    def test_an_anchored_specification_still_researches(self):
        provider = _StageProvider()
        with tempfile.TemporaryDirectory() as directory:
            generator = self._generator(Path(directory), provider)
            generator.adjudicate_finding(
                _error(ANCHORED), "app.apk", "encrypt"
            )

        self.assertIn("external_research", provider.calls)

    def test_a_refused_research_pass_does_not_cost_the_finding(self):
        provider = _StageProvider(refuse_research=True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generator = self._generator(root, provider)
            generator.adjudicate_finding(_error(ANCHORED), "app.apk", "encrypt")

            research = json.loads(
                (root / "out" / "v2_artifacts" / "app.apk"
                 / "0_encrypt_external_research.json").read_text(
                     encoding="utf-8")
            )

        self.assertEqual(research["status"], "refused_by_provider")
        self.assertEqual(research["refusal"]["code"], "cyber_policy")
        # The refusal is recorded and the analysis continues; it is not
        # retried, because the verdict is on the text and would not change.
        # One call per part: the shared research and the case research.
        self.assertEqual(provider.calls.count("external_research"), 2)
        self.assertEqual([part["part"] for part in research["parts"]],
                         ["shared", "case"])
        self.assertIn("evidence_extraction", provider.calls)

    def test_a_provider_failing_to_answer_the_research_is_not_a_refusal(self):
        # agent_baseline_20261108 run_v4/run_v5 (2026-11-09): Flex answered
        # research with server_is_overloaded, read as a refusal, and three
        # findings went on without the research they would have had. The
        # provider resends such a failure itself (OpenAIProvider tests);
        # when that is spent the finding stops, for a resume pass, instead
        # of being analysed on repository evidence only.
        overloaded = BackgroundResponseFailed(
            "OpenAI background response failed (server_is_overloaded): "
            "Our servers are currently overloaded.", code="server_is_overloaded")
        provider = _StageProvider(failures={"external_research": overloaded})
        with tempfile.TemporaryDirectory() as directory:
            generator = self._generator(Path(directory), provider)
            with self.assertRaises(ProviderTransientFailure):
                generator.adjudicate_finding(_error(ANCHORED), "app.apk", "encrypt")

        self.assertEqual(provider.calls, ["external_research"])

    def test_an_extraction_the_provider_failed_to_answer_stops_the_finding(self):
        overloaded = BackgroundResponseFailed(
            "OpenAI background response failed (server_is_overloaded): overloaded",
            code="server_is_overloaded")
        provider = _StageProvider(failures={"evidence_extraction": overloaded})
        with tempfile.TemporaryDirectory() as directory:
            generator = self._generator(Path(directory), provider)
            with self.assertRaises(ProviderTransientFailure) as raised:
                generator.adjudicate_finding(_error(UNANCHORED), "owncloud.apk", "delete")

        self.assertNotIsInstance(raised.exception, ProviderContentRefusal)
        self.assertNotIn("adjudication", provider.calls)

    def test_the_packet_records_whether_its_specification_was_anchored(self):
        provider = _StageProvider()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generator = self._generator(root, provider)
            generator.adjudicate_finding(
                _error(UNANCHORED), "owncloud.apk", "delete"
            )
            packet = json.loads(
                (root / "out" / "v2_artifacts" / "owncloud.apk"
                 / "0_delete_evidence_packet.json").read_text(encoding="utf-8")
            )

        anchoring = packet["specification_anchoring"]
        self.assertFalse(anchoring["externally_anchored"])
        self.assertFalse(anchoring["source_verified"])
        self.assertEqual(
            anchoring["governed_api_types"],
            ["com.owncloud.android.providers.SQLInjection"],
        )


class ReplanReplayTests(unittest.TestCase):
    """A replan sends again only what changed (llm_providers.finding_replay_scope).

    _take_new_plan and replan_after_no_effect adjudicate the finding again.
    With no persistent cache to answer, the research, synthesis, extraction
    and adjudication requests of the second pass are those of the first and
    were paid for again; the planning request carries the previous patch's
    regressions, so it is a new one.
    """

    TARGET = "app/src/main/java/x/IOExtensions.kt"
    CALLER = "app/src/main/java/x/backup/ExportExtensions.kt"
    TARGET_SOURCE = ("package x\n\ninternal fun File.md5Hash(): ByteArray {\n"
                     "    return MessageDigest.getInstance(\"MD5\").digest(readBytes())\n}\n")
    CALLER_SOURCE = ("package x.backup\n\nimport x.md5Hash\n\n"
                     "fun same(a: File, b: File) = a.md5Hash().contentEquals(b.md5Hash())\n")

    class _Session:
        """The OpenAI endpoint, answering each create by the request's schema."""

        def __init__(self, target):
            self.target = target
            self.created = 0

        def close(self):
            pass

        def post(self, url, **kwargs):
            self.created += 1
            payload = kwargs["json"]
            schema = ((payload.get("text") or {}).get("format") or {}).get("name", "")
            if payload.get("tools"):
                answer = "Research brief: https://example.invalid/doc"
            elif schema == "external_research_v2":
                answer = json.dumps({
                    "queries_performed": [], "sources": [], "externally_confirmed_facts": [],
                    "externally_unresolved_questions": []})
            elif schema.startswith("evidence_extraction_"):
                answer = json.dumps({
                    "claims": [{"claim_id": "CLM-001", "statement": "MD5 is passed",
                                "epistemic_status": "confirmed", "evidence_ids": ["SRC-001"]}],
                    "observed_events": [], "predicate_assessment": [],
                    "confirmed_dataflows": [], "relations": [], "unresolved_questions": [],
                    "needs_more_evidence": False, "requested_evidence": [],
                    "family_assessment": {"summary": "s", "evidence_ids": []}})
            elif schema.startswith("adjudication_"):
                answer = json.dumps({
                    "cause_status": "confirmed", "confirmed_cause": "MD5 is passed",
                    "detector_violation": "confirmed", "runtime_security_impact": "unknown",
                    "compatibility_status": "unknown", "scope_status": "complete",
                    "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                    "decision_claim_ids": ["CLM-001"], "blocking_for_generation": [],
                    "blocking_for_publication": [], "generation_status": "supported_for_review",
                    "publication_status": "blocked", "required_edit_categories": [],
                    "required_tests": [], "forward_compatibility_strategy": "",
                    "authorized_behavior_change": {"authorized": False, "description": "",
                                                   "policy_reference": ""},
                    "review_assumptions": []})
            elif schema == "patch_plan_v2":
                answer = json.dumps({
                    "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                    "required_edits": [{
                        "source_file_path": self.target, "create_new_file": False,
                        "supporting_claim_ids": ["CLM-001"], "symbol": "md5Hash",
                        "edit_category": "e", "reason": "r"}],
                    "required_tests": [], "behavioral_invariants": [], "allowed_apis": [],
                    "forbidden_changes": [], "generation_blockers": [],
                    "publication_blockers": []})
            else:
                answer = "{}"
            return _Created({"id": f"resp-{self.created}", "status": "completed",
                             "output_text": answer,
                             "usage": {"input_tokens": 10, "output_tokens": 2}})

        def get(self, url, **_kwargs):
            raise AssertionError("no poll expected")

    def _setup(self, directory: Path, cache_dir=None):
        import os
        from unittest.mock import patch

        from cognalys.llm.llm_providers import OpenAIProvider

        root = directory / "repo"
        for relative, source in ((self.TARGET, self.TARGET_SOURCE),
                                 (self.CALLER, self.CALLER_SOURCE)):
            (root / Path(relative).parent).mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(source, encoding="utf-8")
        with patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
            provider = OpenAIProvider(prompt_log_dir=directory / "logs", cache_dir=cache_dir)
        provider.session = provider.web_search_session = self._Session(self.TARGET)
        provider._sleep = lambda _seconds: None
        generator = object.__new__(FixGenerator)
        generator.output_dir = directory / "out"
        generator.provider = provider
        generator.web_search = True
        generator.architecture_version = "v2"
        generator.logger = logging.getLogger("replan-replay")
        generator.evidence_packet_builder = FindingEvidencePacketBuilder(
            repository_context_budget=140_000)
        generator.policy_registry = PolicyRegistry(directory / "no_policies")
        error = {
            "spec": "MessageDigestSpec", "method_name": "md5Hash",
            "csv_class": "x.IOExtensionsKt", "method_body": self.TARGET_SOURCE,
            "imports": "", "error_index": 0, "source_file_path": self.TARGET,
            "repository_path": str(root),
            "error_message": "expecting one of {SHA-256} but found MD5",
            "specification_context": ANCHORED,
            "expanded_repository_context": {"multi_file_impact": {
                "status": "available",
                "exact_candidate_sources": [{"source_file_path": self.TARGET,
                                             "content": self.TARGET_SOURCE}],
                "coverage_requirements": {},
                "scope_completeness": {"status": "complete", "reasons": []},
            }},
        }
        return generator, provider, error, root

    @staticmethod
    def _sent_and_replayed(provider, since=0):
        """stage -> [sent, replayed] over the traces after the first ``since``."""
        records = sorted(
            (json.loads(path.read_text(encoding="utf-8"))
             for path in provider.prompt_log_dir.glob("*_metadata.json")),
            key=lambda record: record["call_id"])[since:]
        counts: dict = {}
        for record in records:
            entry = counts.setdefault(record["stage"], [0, 0])
            if record["delivery"] == "sent_to_openai":
                entry[0] += 1
            elif record["delivery"] == "finding_replay":
                entry[1] += 1
        return counts, len(records)

    def test_a_second_pass_sends_only_the_new_plan(self):
        from cognalys.llm.llm_providers import finding_replay_scope

        with tempfile.TemporaryDirectory() as directory:
            generator, provider, error, _ = self._setup(Path(directory))
            with finding_replay_scope():
                first, _ = generator.adjudicate_finding(error, "app.apk", "md5Hash")
                _, seen = self._sent_and_replayed(provider)
                # What the behaviour review found, as replan_after_regressions
                # hands it to the planner.
                error["previous_patch_regressions"] = [{
                    "scenario": "an old backup is read with the new digest"}]
                second, _ = generator.adjudicate_finding(error, "app.apk", "md5Hash")
                counts, _ = self._sent_and_replayed(provider, since=seen)
                overall, _ = self._sent_and_replayed(provider)

        # Over both passes: extraction and adjudication sent once, planning twice.
        self.assertEqual(overall["evidence_extraction"], [1, 1])
        self.assertEqual(overall["adjudication"], [1, 1])
        self.assertEqual(overall["patch_planning"], [2, 0])
        self.assertEqual(overall["external_research.research"][0],
                         overall["external_research.research"][1])
        self.assertTrue(first["coordinated_fix_plan"]["required_edits"])
        self.assertEqual(first["decision"], second["decision"])
        for stage in ("external_research.research", "external_research.synthesis",
                      "evidence_extraction", "adjudication"):
            self.assertIn(stage, counts)
            self.assertEqual(counts[stage][0], 0, stage)
            self.assertGreaterEqual(counts[stage][1], 1, stage)
        self.assertEqual(counts["patch_planning"], [1, 0])

    def test_caller_sources_added_by_the_replan_send_the_extraction_again(self):
        from cognalys.extraction.multi_file_context import require_caller_sources
        from cognalys.llm.llm_providers import finding_replay_scope

        with tempfile.TemporaryDirectory() as directory:
            generator, provider, error, root = self._setup(Path(directory))
            with finding_replay_scope():
                generator.adjudicate_finding(error, "app.apk", "md5Hash")
                _, seen = self._sent_and_replayed(provider)
                # As replan_after_no_effect does for consumers outside the plan.
                self.assertEqual(require_caller_sources(
                    error["expanded_repository_context"]["multi_file_impact"], root,
                    [self.CALLER]), [self.CALLER])
                generator.adjudicate_finding(error, "app.apk", "md5Hash")
                counts, _ = self._sent_and_replayed(provider, since=seen)

        self.assertEqual(counts["evidence_extraction"][0], 1)
        self.assertEqual(counts["patch_planning"][0], 1)

    def test_a_cached_run_answers_the_second_pass_from_the_cache_as_before(self):
        from cognalys.llm.llm_providers import finding_replay_scope

        with tempfile.TemporaryDirectory() as directory:
            generator, provider, error, _ = self._setup(
                Path(directory), cache_dir=Path(directory) / "cache")
            with finding_replay_scope():
                generator.adjudicate_finding(error, "app.apk", "md5Hash")
                generator.adjudicate_finding(error, "app.apk", "md5Hash")
            deliveries = {json.loads(path.read_text(encoding="utf-8"))["delivery"]
                          for path in provider.prompt_log_dir.glob("*_metadata.json")}

        self.assertEqual(deliveries, {"sent_to_openai", "cache_hit"})


class _Created:
    """An HTTP response as OpenAIProvider reads it."""

    status_code = 200
    headers: dict = {}

    def __init__(self, payload):
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class AdvisoryIdentifierTests(unittest.TestCase):
    def test_a_cve_is_read_out_of_the_finding_message(self):
        self.assertEqual(
            advisory_identifiers({
                "error_message": "External finding (CVE-2020-35173): onReceive"
            }),
            ["CVE-2020-35173"],
        )

    def test_ghsa_and_osv_identifiers_are_read_too(self):
        self.assertEqual(
            advisory_identifiers({
                "error_message": "see GHSA-6mvq-4c5v-jwrx and OSV-2021-889",
            }),
            ["GHSA-6MVQ-4C5V-JWRX", "OSV-2021-889"],
        )

    def test_github_security_lab_advisories_are_read_too(self):
        self.assertEqual(
            advisory_identifiers({
                "error_message": "External finding (GHSL-2022-046): saveResult",
            }),
            ["GHSL-2022-046"],
        )

    def test_the_same_advisory_is_reported_once(self):
        self.assertEqual(
            advisory_identifiers({
                "error_message": "CVE-2020-35173 ...",
                "unique_error_id": "x:::cve-2020-35173",
            }),
            ["CVE-2020-35173"],
        )

    def test_a_finding_naming_no_advisory_reports_none(self):
        self.assertEqual(advisory_identifiers({}), [])
        self.assertEqual(
            advisory_identifiers({
                "error_message": "expecting an authenticated transformation",
            }),
            [],
        )


class ConnectionAfterWakeTests(unittest.TestCase):
    """SMSecure (2026-10-29): the resumed step met a network still reconnecting."""

    class _Provider:
        def __init__(self, answers):
            self.answers = list(answers)

        def test_connection(self):
            return self.answers.pop(0)

    def test_a_failed_test_is_tried_again_before_giving_up(self):
        from cognalys.llm.generate_error_fixes import wait_for_connection

        slept = []
        provider = self._Provider([False, False, True])
        self.assertTrue(wait_for_connection(
            provider, logging.getLogger("test-connection"), "OpenAI",
            waits=(10, 20, 40), sleep=slept.append))
        self.assertEqual(slept, [10, 20])

    def test_it_gives_up_after_the_last_wait(self):
        from cognalys.llm.generate_error_fixes import wait_for_connection

        slept = []
        provider = self._Provider([False] * 4)
        self.assertFalse(wait_for_connection(
            provider, logging.getLogger("test-connection"), "OpenAI",
            waits=(1, 2, 3), sleep=slept.append))
        self.assertEqual(slept, [1, 2, 3])
        self.assertEqual(provider.answers, [])

    def test_a_working_connection_costs_no_wait(self):
        from cognalys.llm.generate_error_fixes import wait_for_connection

        slept = []
        self.assertTrue(wait_for_connection(
            self._Provider([True]), logging.getLogger("test-connection"),
            sleep=slept.append))
        self.assertEqual(slept, [])


class ProviderUnavailableAfterAdjudicationTests(unittest.TestCase):
    """A provider failing to answer after adjudication is no verdict either.

    Review of 2026-11-09: the behaviour review returned not_run for such a
    failure, so the draft was saved and held for good ("no behaviour review
    judged this draft") as a concluded finding no resume revisits; both
    replans read it as "new plan not taken" and ended on the first plan.
    """

    @staticmethod
    def _overloaded():
        return BackgroundResponseFailed(
            "OpenAI background response failed (server_is_overloaded): overloaded",
            code="server_is_overloaded")

    def test_the_behaviour_review_raises_it_instead_of_running_without_a_review(self):
        class Provider:
            def __init__(self, failure):
                self.failure = failure

            def generate(self, *_args, **_kwargs):
                raise self.failure

        generator = object.__new__(FixGenerator)
        generator.logger = logging.getLogger("provider-unavailable-review")
        generator.provider = Provider(self._overloaded())
        with self.assertRaises(ProviderTransientFailure):
            generator.review_patch_behavior({}, [], {})
        # Any other failure of the review is still an extra check not run.
        generator.provider = Provider(RuntimeError("no answer"))
        with self.assertLogs("provider-unavailable-review", level="WARNING"):
            review = generator.review_patch_behavior({}, [], {})
        self.assertEqual(review["status"], "not_run")

    def test_a_coordinated_draft_whose_review_fails_so_is_not_completed(self):
        from test_applied_edits_match_text import METHOD_EDIT, _coordinated_run

        def review(_call):
            raise self._overloaded()

        with self.assertRaises(ProviderTransientFailure):
            _coordinated_run(review, [METHOD_EDIT])

    def _generator(self, folder: Path, failure):
        from cognalys.llm.coordinated_generation import CoordinatedGeneration

        class Generator(CoordinatedGeneration):
            def adjudicate_finding(inner, error, apk_name, method_name):
                (folder / "3_save_adjudication.json").write_text(
                    '{"plan": "second"}', encoding="utf-8")
                raise failure

        generator = Generator()
        generator.output_dir = folder.parents[1]
        generator.logger = logging.getLogger("provider-unavailable-replan")
        return generator

    def test_both_replans_leave_the_finding_to_a_resume_and_restore_the_first_plan(self):
        for path in ("regressions", "no_effect"):
            for failure, raises in ((self._overloaded(), True),
                                    (RuntimeError("bad answer"), False)):
                with self.subTest(path=path, failure=type(failure).__name__), \
                        tempfile.TemporaryDirectory() as directory:
                    folder = Path(directory) / "out" / "v2_artifacts" / "a.apk"
                    folder.mkdir(parents=True)
                    (folder / "3_save_adjudication.json").write_text(
                        '{"plan": "first"}', encoding="utf-8")
                    generator = self._generator(folder, failure)
                    error = {"error_index": 3, "evidence_analysis": {"decision": "FIX_SUPPORTED"},
                             "v2_artifacts": {"plan": "first"},
                             "typed_value_consumers": {"consumers": [
                                 {"path": "Other.java", "line": 3, "kind": "call",
                                  "declaration": "Key key()"}]}}
                    if path == "regressions":
                        def replan():
                            return generator._take_new_plan(
                                error, "a.apk", "save", "FIX_SUPPORTED",
                                "behaviour regressions", "taken")
                    else:
                        def replan():
                            return generator.replan_after_no_effect(
                                error, {"no_effect_reason": "same value", "drafts": []},
                                ["Main.java"], "a.apk", "save", "FIX_SUPPORTED")
                    if raises:
                        with self.assertRaises(ProviderTransientFailure):
                            replan()
                    else:
                        with self.assertLogs("provider-unavailable-replan", level="WARNING"):
                            self.assertFalse(replan())
                    self.assertEqual(
                        (folder / "3_save_adjudication.json").read_text(encoding="utf-8"),
                        '{"plan": "first"}')
                    self.assertEqual(error["v2_artifacts"], {"plan": "first"})


if __name__ == "__main__":
    unittest.main()
