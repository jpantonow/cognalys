"""Defects run_20260913_140913 exposed.

Eight research and synthesis calls each hung for the full 600 s timeout on a
dead pooled connection; Gallery's supported class-level AsyncTask plan was
sent to the single-method generator, which cannot edit a class; and the files
TowerCollector and NetworkSurvey had to migrate were withheld as exact source
for being larger than a build file.
"""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.llm_providers import OpenAIProvider  # noqa: E402
from cognalys.llm.pipeline_architecture import migration_contract_sources  # noqa: E402
from cognalys.llm.semantic_validation import minimum_planned_files, plan_edits_beyond_method  # noqa: E402


class FakeSession:
    def __init__(self):
        self.closed = 0

    def close(self):
        self.closed += 1


class IdleConnectionTests(unittest.TestCase):
    def _provider(self, directory):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            return OpenAIProvider(cache_dir=Path(directory) / "cache")

    def test_an_idle_session_drops_its_pooled_connections_before_sending(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = self._provider(directory)
            session = FakeSession()
            provider._before_request(session)
            provider._after_request(session)
            self.assertEqual(session.closed, 0)
            provider._session_last_used[id(session)] = (
                time.monotonic() - provider.IDLE_CONNECTION_SECONDS - 5
            )
            provider._before_request(session)
            provider._after_request(session)
            self.assertEqual(session.closed, 1)

    def test_a_recent_or_busy_session_is_left_alone(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = self._provider(directory)
            session = FakeSession()
            provider._after_request(session)
            provider._before_request(session)
            self.assertEqual(session.closed, 0)
            # Another call still in flight on the same session: closing the
            # pool would break it, however long ago the last call ended.
            provider._session_last_used[id(session)] = time.monotonic() - 3600
            provider._before_request(session)
            self.assertEqual(session.closed, 0)


class SingleMethodRoutingTests(unittest.TestCase):
    TARGET = "app/src/main/kotlin/org/fossify/gallery/asynctasks/GetMediaAsynctask.kt"

    def test_a_class_level_edit_is_beyond_the_single_method_generator(self):
        plan = {"required_edits": [{"source_file_path": self.TARGET, "symbol": "GetMediaAsynctask"}]}
        self.assertEqual(
            plan_edits_beyond_method(plan, self.TARGET, ("doInBackground",)),
            [f"{self.TARGET}:GetMediaAsynctask"],
        )

    def test_the_reported_method_alone_stays_on_the_single_method_path(self):
        for symbol in ("doInBackground", "GetMediaAsynctask.doInBackground",
                       "GetMediaAsynctask#doInBackground(Void)"):
            with self.subTest(symbol):
                plan = {"required_edits": [{"source_file_path": self.TARGET, "symbol": symbol}]}
                self.assertEqual(plan_edits_beyond_method(plan, self.TARGET, ("doInBackground",)), [])

    def test_an_edit_to_another_file_is_beyond_it(self):
        plan = {"required_edits": [
            {"source_file_path": self.TARGET, "symbol": "doInBackground"},
            {"source_file_path": "app/src/main/kotlin/SearchActivity.kt", "symbol": "startAsyncTask"},
        ]}
        self.assertEqual(len(plan_edits_beyond_method(plan, self.TARGET, ("doInBackground",))), 1)

    def test_the_review_decision_it_is_routed_to_accepts_one_file(self):
        self.assertEqual(minimum_planned_files("MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"), 1)


class ContractSourceSizeTests(unittest.TestCase):
    def test_a_large_file_that_uses_the_deprecated_api_is_still_exact_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = "app/src/main/java/org/example/MainActivity.java"
            (root / relative).parent.mkdir(parents=True)
            (root / relative).write_text(
                "class MainActivity {\n" + "    // filler\n" * 7000
                + "    void check() { new UpdateCheckAsyncTask(this, 1).execute(url); }\n}\n",
                encoding="utf-8",
            )
            contract = {"contracts": [{"production_files": [relative]}]}
            sources = migration_contract_sources(str(root), contract, set())
        self.assertEqual([item["source_file_path"] for item in sources], [relative])
        self.assertGreater(len(sources[0]["content"]), 60_000)


class ReplacementBehaviourValidationTests(unittest.TestCase):
    """Gallery's AsyncTask replacement: exceptions lost in an unread Future,
    and callers renamed to start() while execute() still delegated to it."""

    SUBMIT = (
        "internal fun start() {\n"
        "    submittedWork = EXECUTOR.submit {\n"
        "        val media = fetchMedia()\n"
        "        mainHandler.post { callback(media) }\n"
        "    }\n"
        "}\n"
        "private companion object { val EXECUTOR = Executors.newCachedThreadPool() }\n"
    )

    def test_submitting_to_an_executor_without_observing_failure_is_rejected(self):
        from cognalys.llm.semantic_validation import executor_submit_discards_exceptions

        self.assertTrue(executor_submit_discards_exceptions("", self.SUBMIT))
        caught = self.SUBMIT.replace(
            "val media = fetchMedia()",
            "val media = try { fetchMedia() } catch (e: Exception) { Log.e(TAG, \"scan\", e); return@submit }",
        )
        self.assertFalse(executor_submit_discards_exceptions("", caught))
        executed = self.SUBMIT.replace("EXECUTOR.submit {", "EXECUTOR.execute {")
        self.assertFalse(executor_submit_discards_exceptions("", executed))

    def test_a_caller_edit_that_only_renames_to_a_new_alias_is_rejected(self):
        from cognalys.llm.semantic_validation import redundant_caller_renames

        target = {
            "source_file_path": "app/src/main/kotlin/GetMediaAsynctask.kt",
            "original_code": "class GetMediaAsynctask : AsyncTask<Void, Void, Unit>() {}",
            "corrected_code": (
                "class GetMediaAsynctask {\n"
                "    internal fun start() { }\n"
                "    internal fun execute() {\n        start()\n    }\n}\n"
            ),
        }
        rename_only = {
            "source_file_path": "app/src/main/kotlin/ViewPagerActivity.kt",
            "original_code": "GetMediaAsynctask(context, dir) { gotMedia(it) }.execute()",
            "corrected_code": "GetMediaAsynctask(context, dir) { gotMedia(it) }.start()",
        }
        real_change = {
            "source_file_path": "app/src/main/kotlin/MediaActivity.kt",
            "original_code": "task.execute()",
            "corrected_code": "task.start(priority = HIGH)",
        }
        issues = redundant_caller_renames([target, rename_only, real_change])
        self.assertEqual([item["path"] for item in issues],
                         ["app/src/main/kotlin/ViewPagerActivity.kt"])
        self.assertEqual(issues[0]["code"], "REDUNDANT_CALLER_RENAME")
        # Once the old entry point is gone, switching callers is required.
        target_without_alias = {**target, "corrected_code": "class GetMediaAsynctask {\n    internal fun start() { }\n}\n"}
        self.assertEqual(redundant_caller_renames([target_without_alias, rename_only]), [])


class _NoChangeDraftProvider:
    """Edits the target; declares the caller unchanged (or the target too)."""

    def __init__(self, target_unchanged=False):
        self.target_unchanged = target_unchanged

    def generate(self, prompt, *_args, **_kwargs):
        import json

        relative = json.JSONDecoder().raw_decode(
            prompt.split('"target_file":', 1)[1].lstrip())[0]
        unchanged = relative == "src/Caller.java" or self.target_unchanged
        return json.dumps({
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "source_file_path": relative,
            "explanation": (
                "No edit is required: the caller already uses the kept execute() entry point."
                if unchanged else "Replaces the deprecated base class."
            ),
            "edits": [] if unchanged else [{
                "source_file_path": relative, "symbol": "getUrl", "edit_kind": "method",
                "original_code": "        return url;", "corrected_code": "        return this.url;",
                "reason": "migration",
            }],
            "no_change_required": unchanged,
            "provided_contracts": [], "required_contracts": [], "required_tests": [],
            "manual_review_required": True, "review_assumptions": [], "confidence": "high",
        })


class UnchangedPlannedFileTests(unittest.TestCase):
    """run_20260913_223438: ViewPagerActivity needed no change, said so, and
    the empty draft discarded a complete migration of the other files."""

    def _run(self, provider):
        import logging
        from cognalys.llm.generate_error_fixes import FixGenerator

        root = Path(tempfile.mkdtemp())
        repo = root / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "src/Task.java").write_text(
            "class Task {\n    String url;\n    String getUrl() {\n        return url;\n    }\n}\n",
            encoding="utf-8",
        )
        (repo / "src/Caller.java").write_text(
            "class Caller {\n    void go(Task task) {\n        task.getUrl();\n    }\n}\n",
            encoding="utf-8",
        )
        generator = object.__new__(FixGenerator)
        generator.output_dir = root / "out"
        generator.provider = provider
        generator.web_search = False
        generator.logger = logging.getLogger("unchanged-planned-file-test")
        error = {
            "repository_path": str(repo), "error_index": 1,
            "source_file_path": "src/Task.java",
            "case_migration_policy": {},
            "evidence_analysis": {
                "confirmed_cause": "cause",
                "coordinated_fix_plan": {"required_edits": [
                    {"source_file_path": "src/Task.java", "symbol": "Task"},
                    {"source_file_path": "src/Caller.java", "symbol": "go"},
                ]},
            },
        }
        return generator.generate_coordinated_file_drafts(
            error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "doInBackground",
        )

    def test_a_caller_declared_unchanged_does_not_discard_the_migration(self):
        result = self._run(_NoChangeDraftProvider())
        self.assertEqual(result["status"], "complete", result.get("issues"))
        self.assertEqual(result["unchanged_files"], ["src/Caller.java"])
        self.assertEqual({edit["source_file_path"] for edit in result["edits"]}, {"src/Task.java"})

    def test_the_reported_target_can_never_be_declared_unchanged(self):
        result = self._run(_NoChangeDraftProvider(target_unchanged=True))
        self.assertNotEqual(result["status"], "complete")
        self.assertIn("file draft contains no edits", result.get("issues", []))


class PathNamedEvidenceRequestTests(unittest.TestCase):
    """run_20260913_222256: a request naming Context.kt by path was declined."""

    CONTEXT = "app/src/main/kotlin/org/example/extensions/Context.kt"
    REQUEST = {
        "kind": "callsite_lifecycle_context",
        "symbol": "app/src/main/kotlin/org/example/extensions/Context.kt GetMediaAsynctask call site",
        "reason": "Its exact source body is not included.",
    }

    def _repo(self, root: Path) -> None:
        path = root / self.CONTEXT
        path.parent.mkdir(parents=True)
        path.write_text(
            "package org.example.extensions\n"
            + "// filler line to push the call site past the entry cap\n" * 800
            + "fun Context.rescanFolderMediaSync(path: String) {\n"
            + "    GetMediaAsynctask(applicationContext, path) { }.execute()\n}\n",
            encoding="utf-8",
        )
        task = root / "app/src/main/kotlin/org/example/GetMediaAsynctask.kt"
        task.write_text("class GetMediaAsynctask\n", encoding="utf-8")

    def test_a_file_named_by_path_is_supplied_around_the_requested_symbol(self):
        from cognalys.llm.evidence_requests import resolve_evidence_requests

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._repo(root)
            result = resolve_evidence_requests(
                root, [self.REQUEST], {"app/src/main/kotlin/org/example/GetMediaAsynctask.kt"},
            )
        self.assertEqual(result["declined"], [])
        data = result["entries"][0]["data"]
        self.assertEqual(data["source_file_path"], self.CONTEXT)
        self.assertIn("GetMediaAsynctask(applicationContext, path)", data["content"])
        self.assertGreater(data["excerpt_starts_at_line"], 1)

    def test_a_named_file_already_in_the_packet_is_declined_as_such(self):
        from cognalys.llm.evidence_requests import resolve_evidence_requests

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._repo(root)
            result = resolve_evidence_requests(
                root, [self.REQUEST],
                {self.CONTEXT, "app/src/main/kotlin/org/example/GetMediaAsynctask.kt"},
            )
        self.assertEqual(result["entries"], [])
        self.assertEqual(result["declined"][0]["reason"], f"already in the evidence packet: {self.CONTEXT}")


class PatchPlanRepairTests(unittest.TestCase):
    """run_20260913_204821: a supported Gallery plan discarded for tests the
    repository had nowhere to put, padded with comment-only caller edits."""

    PLAN = {
        "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
        "required_edits": [
            {"source_file_path": "app/src/main/kotlin/GetMediaAsynctask.kt",
             "edit_category": "deprecated_api_replacement", "supporting_claim_ids": ["C-001"]},
            {"source_file_path": "app/src/main/kotlin/MediaActivity.kt",
             "edit_category": "caller_contract_documentation", "supporting_claim_ids": ["C-003"]},
        ],
        "required_tests": ["Unit test that stopFetching suppresses delivery."],
        "generation_blockers": [
            "Required deterministic unit-test edits cannot be planned: "
            "established_test_source_roots is empty."
        ],
        "publication_blockers": ["Device review is required."],
    }

    def test_without_a_test_source_set_tests_become_a_checklist_and_padding_goes(self):
        from cognalys.llm.semantic_validation import repair_patch_plan

        repaired, repairs = repair_patch_plan(self.PLAN, repository_has_test_roots=False)
        self.assertEqual([item["source_file_path"] for item in repaired["required_edits"]],
                         ["app/src/main/kotlin/GetMediaAsynctask.kt"])
        self.assertEqual(repaired["required_tests"], [])
        self.assertEqual(repaired["generation_blockers"], [])
        self.assertTrue(any("Reviewer checklist" in item and "stopFetching" in item
                            for item in repaired["publication_blockers"]))
        self.assertEqual(len(repairs), 2)

    def test_a_repository_with_tests_keeps_its_test_requirements_and_other_blockers(self):
        from cognalys.llm.semantic_validation import repair_patch_plan

        plan = {**self.PLAN, "generation_blockers": [
            *self.PLAN["generation_blockers"], "The backend contract is unknown.",
        ]}
        repaired, _repairs = repair_patch_plan(plan, repository_has_test_roots=True)
        self.assertEqual(repaired["required_tests"], plan["required_tests"])
        self.assertEqual(len(repaired["generation_blockers"]), 2)
        no_tests, _ = repair_patch_plan(plan, repository_has_test_roots=False)
        self.assertEqual(no_tests["generation_blockers"], ["The backend contract is unknown."])

    def test_test_source_sets_on_disk_are_found_and_accepted_by_the_validator(self):
        from cognalys.llm.semantic_validation import _validate_patch_plan, repository_test_source_roots

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app/src/test/java/org/example").mkdir(parents=True)
            (root / "app/src/main/java/org/example").mkdir(parents=True)
            self.assertEqual(repository_test_source_roots(str(root)), ["app/src/test/java"])
            self.assertEqual(repository_test_source_roots(str(root / "missing")), [])
        packet = {"evidence_catalog": [{
            "trust_level": "repository_exact_source",
            "data": {"source_file_path": "app/src/main/java/org/example/Task.java"},
        }]}
        adjudication = {"decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                        "generation_status": "supported_for_review",
                        "_validated_claims": [{"claim_id": "C-001"}]}
        plan = {"decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "required_tests": ["t"],
                "required_edits": [
                    {"source_file_path": "app/src/main/java/org/example/Task.java",
                     "supporting_claim_ids": ["C-001"]},
                    {"source_file_path": "app/src/test/java/org/example/TaskTest.java",
                     "create_new_file": True, "supporting_claim_ids": ["C-001"]},
                ]}
        self.assertIn("planned path lacks exact source evidence: app/src/test/java/org/example/TaskTest.java",
                      _validate_patch_plan(plan, packet, adjudication))
        self.assertEqual(_validate_patch_plan(plan, packet, adjudication, ["app/src/test/java"]), [])


class ExactSourcePromotionTests(unittest.TestCase):
    def test_a_ranked_candidate_that_a_plan_needs_is_promoted_not_skipped(self):
        from cognalys.llm.pipeline_architecture import _EvidenceItem, _promote_or_add_exact_sources

        search = "app/src/main/kotlin/SearchActivity.kt"
        related = _EvidenceItem(
            "SRC", "related_source", "repository_exact_source",
            {"source_file_path": search, "content": "class SearchActivity"}, False, 55,
        )
        candidates = [related]
        _promote_or_add_exact_sources(candidates, [
            {"source_file_path": search, "content": "class SearchActivity"},
            {"source_file_path": "app/src/main/kotlin/PickMediumDialog.kt", "content": "class Pick"},
        ], "deprecated_usage_source", True, 94)
        # The existing candidate is kept once, now mandatory; the other is added.
        self.assertEqual(len(candidates), 2)
        self.assertTrue(related.mandatory)
        self.assertEqual(related.priority, 94)
        self.assertTrue(candidates[1].mandatory)
        self.assertEqual(candidates[1].kind, "deprecated_usage_source")

    def test_an_excerpt_of_the_file_does_not_cover_it(self):
        from cognalys.llm.pipeline_architecture import _EvidenceItem, _promote_or_add_exact_sources

        context = "app/src/main/kotlin/org/fossify/gallery/extensions/Context.kt"
        callee = _EvidenceItem(
            "CALLEE", "callee_definition", "repository_exact_source",
            {"source_file_path": context, "definition": "fun Context.getCachedMedia() {}"}, True, 90,
        )
        candidates = [callee]
        full = "fun Context.rescanFolderMediaSync(path: String) { GetMediaAsynctask(this).execute() }\n" * 20
        _promote_or_add_exact_sources(candidates, [
            {"source_file_path": context, "content": full},
        ], "deprecated_usage_source", True, 94)
        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[1].kind, "deprecated_usage_source")
        self.assertIn("GetMediaAsynctask", candidates[1].payload["content"])

    def test_an_optional_source_does_not_promote_an_existing_candidate(self):
        from cognalys.llm.pipeline_architecture import _EvidenceItem, _promote_or_add_exact_sources

        related = _EvidenceItem(
            "SRC", "related_source", "repository_exact_source",
            {"source_file_path": "app/build.gradle.kts"}, False, 55,
        )
        candidates = [related]
        _promote_or_add_exact_sources(
            candidates, [{"source_file_path": "app/build.gradle.kts"}],
            "dependency_declaration_source", False, 95,
        )
        self.assertEqual(len(candidates), 1)
        self.assertFalse(related.mandatory)


class FamilyDecisionEnumTests(unittest.TestCase):
    def test_digest_only_decisions_are_offered_to_digest_findings_alone(self):
        from cognalys.llm.pipeline_architecture import DIGEST_ONLY_DECISIONS, adjudication_schema

        def offered(family):
            return set(adjudication_schema(family)["properties"]["decision"]["enum"])

        for family in ("api_migration", "generic", "cipher", "key_generation"):
            with self.subTest(family):
                self.assertFalse(offered(family) & DIGEST_ONLY_DECISIONS)
                self.assertIn("MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", offered(family))
        self.assertTrue(DIGEST_ONLY_DECISIONS <= offered("message_digest"))


class DeprecationPullRequestTitleTests(unittest.TestCase):
    def test_a_deprecation_finding_is_titled_by_the_api_it_replaces(self):
        sys.path.insert(0, str(ROOT / "src" / "cognalys" / "prs"))
        from cognalys.prs.pr_generator import PrGenerator

        result = {
            "method_name": "doInBackground", "spec": "DeprecatedApiSpec",
            "csv_class": "info.zamojski.soft.towercollector.tasks.UpdateCheckAsyncTask",
            "error_message": ("android.os.AsyncTask is deprecated. Use "
                              "java.util.concurrent or Kotlin Coroutines."),
        }
        self.assertEqual(
            PrGenerator.descriptive_title(result, "Fix doInBackground"),
            "Replace deprecated AsyncTask in UpdateCheckAsyncTask",
        )
        other = {**result, "error_message": "expecting one of PKIX,SunX509 but found ."}
        self.assertEqual(PrGenerator.descriptive_title(other, "Fix doInBackground"),
                         "Fix doInBackground")

    def test_an_initializer_finding_is_titled_by_its_class(self):
        sys.path.insert(0, str(ROOT / "src" / "cognalys" / "prs"))
        from cognalys.prs.pr_generator import PrGenerator

        result = {
            "method_name": "<init>", "spec": "SSLContextSpec",
            "csv_class": "se.bitcraze.crazyfliecontrol.bootloader.TLSSocketFactory",
            "error_message": "expecting one of {TLSv1.2, TLSv1.3} but found TLS.",
        }
        self.assertEqual(
            PrGenerator.descriptive_title(result, "Fix <init>"),
            "Address SSLContextSpec finding in TLSSocketFactory constructor",
        )
        nested = {**result, "method_name": "<clinit>", "csv_class": "a.Outer$Inner"}
        self.assertEqual(
            PrGenerator.descriptive_title(nested, "Fix <clinit>"),
            "Address SSLContextSpec finding in Inner static initializer",
        )


class ExplanationSourceTests(unittest.TestCase):
    def test_a_row_gathered_by_research_is_not_described_as_a_dynamic_analysis_run(self):
        from cognalys.llm.fix_artifacts import coordinated_fix_explanation

        error = {
            "error_message": "android.os.AsyncTask is deprecated.",
            "tool": "web_research", "spec": "DeprecatedApiSpec",
            "method_name": "doInBackground", "csv_class": "org.example.Task",
            "evidence_analysis": {"confirmed_cause": "The class subclasses AsyncTask."},
        }
        text = coordinated_fix_explanation(error, [], [], [])
        self.assertNotIn("dynamic-analysis", text)
        self.assertNotIn("web_research", text)
        # The cause carries the substance; a candidate's own message only
        # restates it, so it is not quoted once a cause is known.
        self.assertIn("The class subclasses AsyncTask.", text)
        self.assertNotIn("android.os.AsyncTask is deprecated.", text)
        no_cause = coordinated_fix_explanation(
            {**error, "evidence_analysis": {}}, [], [], [],
        )
        self.assertIn("Reported finding (`DeprecatedApiSpec`)", no_cause)
        self.assertIn("in `Task.doInBackground`", no_cause)
        self.assertIn("android.os.AsyncTask is deprecated.", no_cause)
        detector = coordinated_fix_explanation({**error, "tool": "ape"}, [], [], [])
        self.assertIn("The dynamic-analysis run by `ape` reported", detector)


if __name__ == "__main__":
    unittest.main()
