"""An issue's text that fails its checks is rewritten from the facts, not only held."""
import argparse
import io
import json
import logging
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.issues.issue_creator import IssueCreator  # noqa: E402
from cognalys.issues.issue_text import (  # noqa: E402
    issue_text_problems,
    rewrite_issue_text,
)
from cognalys.llm.fix_generation_common import post_validation_issue_candidate  # noqa: E402
from cognalys.llm.generate_error_fixes import FixGenerator  # noqa: E402

# DNS Toggle's cause sentence (2026-11-04), which reached the issue as its
# summary and held it for evidence ids and the analyzer's vocabulary.
DNS_TOGGLE_CAUSE = (
    "Cipher.init received a key for which the monitor observed no admitted "
    "producer; the actual runtime branch is unknown. Independently, getKey can "
    "supply a fixed all-zero AES key when AndroidKeyStore is unavailable. The "
    "joint KeyStore finding is caused by loading and reading with getEntry "
    "without the getKey event required by its rule; that read sequence is "
    "non-security usage. [C1, C2, C5; RUN-001, SRC-001, SPEC-001, SPEC-002].")

CLEAN = {
    "finding_summary": (
        "`getKey` falls back to a fixed all-zero AES key when the Android "
        "Keystore is unavailable, so anything encrypted with it can be read by "
        "anyone who has the app."),
    "why_no_pr": (
        "I didn't open a pull request because I could not find a change that "
        "keeps the current behaviour intact."),
    "maintainer_question": (
        "Is the all-zero key fallback intended, or would you rather the app "
        "stop when the Keystore is unavailable?"),
    "proposed_next_step": "With your answer I can prepare a change and send it for review.",
}


class FakeProvider:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.prompts = []

    def generate(self, prompt, system, **kwargs):
        self.prompts.append((prompt, system, kwargs))
        return json.dumps(self.responses.pop(0))


def candidate(cause: str = DNS_TOGGLE_CAUSE) -> dict:
    return {
        "issue_kind": "generation_blocked",
        "repo_host": "github.com", "repo_owner": "owner", "repo_name": "dnstoggle",
        "finding_id": "a.Crypto:::getKey:::CipherSpec:::0",
        "method_name": "getKey", "csv_class": "a.Crypto", "source_file": "app/Crypto.kt",
        "spec": "CipherSpec", "tool": "rvsec", "error_message": "Cipher.init: key not generated",
        "generation_blockers": ["UNINTENDED_BEHAVIOR_CHANGE"],
        "confirmed_cause": cause,
        "issue_content": post_validation_issue_candidate(
            None, ["UNINTENDED_BEHAVIOR_CHANGE"], "getKey", "CipherSpec", cause, "v3"),
    }


class IssueTextRewriteTests(unittest.TestCase):
    def test_the_deterministic_template_over_the_cause_sentence_fails_the_checks(self):
        self.assertTrue(any("pipeline vocabulary" in item for item in issue_text_problems(candidate())))

    def test_a_failing_text_is_rewritten_and_the_fixed_sentences_stay(self):
        metadata = candidate()
        provider = FakeProvider(CLEAN)
        self.assertEqual(rewrite_issue_text(provider, None, metadata, {}), [])
        self.assertEqual(len(provider.prompts), 1)
        prompt, system, kwargs = provider.prompts[0]
        # The facts reach the model, with what was wrong and the rule id it
        # must not write; the work is never described as automated.
        self.assertIn("all-zero AES key", prompt)
        self.assertIn("pipeline vocabulary", prompt)
        self.assertIn('"analyzer_rule_id_never_written":"CipherSpec"', prompt)
        self.assertIn("never describe the work as automated", system)
        self.assertEqual(kwargs["trace_stage"], "issue_text_rewrite")
        self.assertEqual(kwargs["trace_context"]["finding_id"], metadata["finding_id"])
        content = metadata["issue_content"]
        for field, text in CLEAN.items():
            self.assertEqual(content[field], text)
        # The title is the template's; the earlier text is kept for comparison.
        self.assertEqual(content["title"], "Question about the Cipher use in getKey")
        self.assertIn("admitted producer", metadata["issue_text_rewrite"]["text_before"]["finding_summary"])
        body = IssueCreator.build_no_safe_fix_body("Hi!", metadata, style="v3")
        self.assertIn("While running the app under RVSec", body)
        self.assertTrue(body.endswith("Thanks!"))
        self.assertEqual(issue_text_problems(metadata), [])

    def test_a_rewrite_that_still_fails_is_retried_once_then_the_text_stays(self):
        metadata = candidate()
        before = dict(metadata["issue_content"])
        dirty = {**CLEAN, "finding_summary": "The predicate on `Crypto$1` is not met."}
        provider = FakeProvider(dirty, dirty)
        remaining = rewrite_issue_text(provider, logging.getLogger("test"), metadata, {})
        self.assertTrue(remaining)
        self.assertEqual(len(provider.prompts), 2)
        # The retry is told what was wrong with the first rewrite.
        retry = provider.prompts[1][0]
        self.assertIn("previous_attempt", retry)
        self.assertIn("pipeline vocabulary: predicate", retry)
        self.assertEqual(metadata["issue_content"], before)
        self.assertEqual(metadata["issue_text_rewrite"]["problems_after"], remaining)

    def test_a_clean_text_or_a_collateral_issue_costs_no_call(self):
        provider = FakeProvider()
        clean = candidate("getKey falls back to a fixed all-zero AES key.")
        self.assertEqual(rewrite_issue_text(provider, None, clean, {}), [])
        collateral = {**candidate(), "issue_kind": "collateral_constraint_violation"}
        self.assertEqual(rewrite_issue_text(provider, None, collateral, {}), [])
        self.assertEqual(provider.prompts, [])
        self.assertNotIn("issue_text_rewrite", clean)

    def test_a_provider_failure_keeps_the_text(self):
        class Failing:
            def generate(self, *args, **kwargs):
                raise RuntimeError("cost ceiling")
        metadata = candidate()
        before = dict(metadata["issue_content"])
        self.assertTrue(rewrite_issue_text(Failing(), logging.getLogger("test"), metadata, {}))
        self.assertEqual(metadata["issue_content"], before)


class IssueStepRewriteTests(unittest.TestCase):
    def _creator(self, directory: Path, **kwargs) -> IssueCreator:
        return IssueCreator(str(directory / "prs"), str(directory / "candidates"),
                            str(directory / "issues"), "Title", "Hi!", style="v3", **kwargs)

    def _write(self, directory: Path) -> Path:
        path = directory / "candidates" / "app.apk" / "0_getKey_issue.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(candidate()), encoding="utf-8")
        return path

    def test_the_issue_step_rewrites_and_saves_instead_of_holding(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            path = self._write(directory)
            creator = self._creator(directory, text_model={"model": "m"})
            creator._text_client = FakeProvider(CLEAN)
            with redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(creator.process(path), "success")
            self.assertIn("REWRITTEN", printed.getvalue())
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(saved["issue_content"]["finding_summary"], CLEAN["finding_summary"])
            record = json.loads((directory / "issues" / "0_getKey_issue_issue_created.json")
                                .read_text(encoding="utf-8"))
            self.assertTrue(record["dry_run"])
            self.assertIn("all-zero AES key", record["body"])

    def test_without_a_model_the_hold_is_as_before(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            path = self._write(directory)
            with redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(self._creator(directory).process(path), "blocked")
            self.assertIn("pipeline vocabulary", printed.getvalue())


class PersistedCandidateRewriteTests(unittest.TestCase):
    def test_the_llm_step_writes_the_rewritten_text(self):
        with tempfile.TemporaryDirectory() as directory:
            generator = FixGenerator.__new__(FixGenerator)
            generator.architecture_version = "v2"
            generator.output_dir = Path(directory)
            generator.logger = logging.getLogger("test-issue-text")
            generator.pr_issue_style = "v3"
            generator.provider = FakeProvider(CLEAN)
            evidence_file = Path(directory) / "review.json"
            evidence_file.write_text(json.dumps({"analysis": {}}), encoding="utf-8")
            error = {
                "error_index": 0, "repository_url": "https://github.com/owner/dnstoggle",
                "source_file_path": "app/Crypto.kt", "csv_class": "a.Crypto",
                "spec": "CipherSpec", "tool": "rvsec",
                "error_message": "Cipher.init: key not generated",
                "method_body": "Cipher.init(ENCRYPT_MODE, getKey())",
                "unique_error_id": "a.Crypto:::getKey:::CipherSpec:::0",
            }
            analysis = {
                "decision": "NO_SAFE_FIX", "confirmed_cause": DNS_TOGGLE_CAUSE,
                "predicate_assessment": [{"status": "violated",
                                          "evidence": "Cipher.init(ENCRYPT_MODE, getKey())"}],
                "issue_candidate": {"eligible": False},
            }
            path = generator.persist_blocked_issue_candidate(
                error, analysis, evidence_file, "app.apk", "getKey",
                ["UNINTENDED_BEHAVIOR_CHANGE"])
            self.assertIsNotNone(path)
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(saved["issue_content"]["finding_summary"], CLEAN["finding_summary"])
            self.assertEqual(analysis["issue_candidate"], saved["issue_content"])


class IssueStepCommandTests(unittest.TestCase):
    def test_the_model_is_passed_only_where_it_rewrites(self):
        from cognalys.orchestration import run_pipeline

        def command(**overrides):
            args = argparse.Namespace(
                issue_title="T", issue_body="B", pr_issue_style="v3", limit=0, project="",
                approve_reviewed_finding=[], dry_run=False, reprocess_existing=False,
                llm_provider="openai", llm_model="gpt", llm_endpoint="https://e",
                llm_timeout=600, llm_max_output_tokens=32768, llm_reasoning_effort="high",
                openai_prompt_log_dir="")
            vars(args).update(overrides)
            root = Path(tempfile.gettempdir())
            paths = argparse.Namespace(
                root=root, pull_requests_dir=root / "pr", error_solutions_dir=root / "es",
                issues_dir=root / "is", application_results_dir=root / "ar")
            return run_pipeline._command_issues("issues", args, paths, "python")

        self.assertIn("--model", command())
        self.assertNotIn("--model", command(pr_issue_style="v1"))
        self.assertNotIn("--model", command(llm_provider="ollama"))
        self.assertNotIn("--model", command(dry_run=True))

    def test_the_pr_text_rewrite_is_traced_with_the_run_s_calls(self):
        # PLANO_CORRECOES_DEFESA A6: the prs step's rewrite provider had no
        # prompt-log folder, so its calls were in no trace cognalys cost read.
        from unittest import mock

        from cognalys.orchestration import run_pipeline
        from cognalys.prs import run_prs

        args = argparse.Namespace(
            pr_issue_style="v3", limit=0, project="", dry_run=False,
            llm_model="gpt", llm_endpoint="https://e", llm_timeout=600,
            llm_max_output_tokens=32768, llm_reasoning_effort="high",
            openai_prompt_log_dir="", publish_without_build_validation=[])
        root = Path(tempfile.gettempdir())
        paths = argparse.Namespace(
            root=root, pull_requests_dir=root / "pr", error_solutions_dir=root / "es",
            application_results_dir=root / "ar")
        command = run_pipeline._command_prs("prs", args, paths, "python")
        logs = command[command.index("--prompt-log-dir") + 1]
        self.assertEqual(Path(logs), run_pipeline.openai_prompt_log_dir(args, paths))

        seen = {}

        class Generator:
            def __init__(self, **kwargs):
                seen.update(kwargs)

            def generate_prs(self):
                return {"failed": 0}

        with mock.patch.object(run_prs, "PrGenerator", Generator),                 mock.patch("sys.argv", ["run_prs", *command[3:]]):
            run_prs.main()
        self.assertEqual(seen["text_model"]["prompt_log_dir"], Path(logs))


class ContactIssueTitleTests(unittest.TestCase):
    """267 recorded contact-issue previews said "Potential security issue
    found"; only 3 of their records carry impact_class security_impact
    (2026-11-10), and Gallery#1146, BombusMod#317 and wwwjdic#116 were opened
    with that title."""

    SECURITY = "Potential security issue found — would you be open to a pull request?"

    def _title(self, **metadata):
        from cognalys.issues.issue_text import (
            DEFAULT_TITLE_WITHOUT_SECURITY_IMPACT, contact_issue_title)

        record = {"spec": "SSLContextSpec", "method_name": "tlsContext",
                  "csv_class": "a.b.Network", **metadata}
        return contact_issue_title(record, self.SECURITY, DEFAULT_TITLE_WITHOUT_SECURITY_IMPACT)

    def test_a_draft_without_confirmed_security_impact_gets_the_neutral_contact_title(self):
        for impact in ("no_security_impact", "impact_not_established", "not_recorded"):
            self.assertEqual(
                self._title(impact_class=impact),
                "Question about the SSLContext use in tlsContext — would you be open to a pull request?")

    def test_a_security_impact_draft_keeps_the_configured_title(self):
        self.assertEqual(self._title(impact_class="security_impact"), self.SECURITY)

    def test_a_constructor_or_lambda_is_named_by_its_outer_class(self):
        cases = {("<init>", "a.b.DownloadTask$Inner"): "DownloadTask",
                 ("lambda$downloadModels$10", "org.x.Downloader"): "Downloader",
                 ("invokeSuspend", "org.x.ConnectionUtilKt$connect$1"): "ConnectionUtil",
                 ("discoverySslContext$app", "com.y.ServerScanner$Companion"): "ServerScanner"}
        for (method, csv_class), location in cases.items():
            title = self._title(method_name=method, csv_class=csv_class)
            self.assertIn(f" use in {location} — ", title)
            self.assertNotRegex(title, r"[$<]|lambda")

    def test_a_record_without_impact_class_gets_the_neutral_title(self):
        self.assertTrue(self._title().startswith("Question about the SSLContext use in tlsContext"))

    def test_the_issue_step_titles_a_pull_request_draft_by_its_impact(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory / "prs").mkdir()
            record = {"repo_host": "github.com", "repo_owner": "owner", "repo_name": "app",
                      "spec": "SSLContextSpec",
                      "method_name": "tlsContext", "csv_class": "a.b.Network",
                      "source_file": "app/Network.kt", "error_message": "m",
                      "impact_class": "no_security_impact"}
            path = directory / "prs" / "app_tlsContext_SSLContextSpec_pr.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            creator = IssueCreator(str(directory / "prs"), None, str(directory / "issues"),
                                   self.SECURITY, "Hi!", style="v1")
            with redirect_stdout(io.StringIO()):
                creator.process(path)
            created = json.loads(next((directory / "issues").glob("*.json")).read_text(
                encoding="utf-8"))
        self.assertTrue(created["title"].startswith("Question about the SSLContext use in tlsContext"))


if __name__ == "__main__":
    unittest.main()
