"""The retrospective that closes each run, and the knowledge it leaves behind."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.learning.knowledge import (  # noqa: E402
    finding_history,
    finding_key_for,
    load_knowledge,
    verified_imports,
)
from cognalys.learning.retrospective import (  # noqa: E402
    collect_finding_outcomes,
    known_positive,
    normalize_detail,
    run_retrospective,
    verdict_changes,
)


GALLERY = "org.fossify.gallery_28.apk"
UNIQUE = "org.fossify.gallery.asynctasks.GetMediaAsynctask:::doInBackground:::DeprecatedApiSpec:::deprecated"


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) if not isinstance(value, str) else value, encoding="utf-8")


def evidence(run: Path, apk: str, prefix: str, unique: str, decision: str,
             method: str = "doInBackground") -> None:
    write(run / "error_solutions/evidence_reviews" / apk / f"{prefix}_evidence.json", {
        "status": decision, "error_id": unique, "apk_name": apk, "method_name": method,
        "spec": "DeprecatedApiSpec", "analysis": {"decision": decision, "cause_status": "confirmed"},
    })


def run_with_empty_draft(run: Path) -> None:
    evidence(run, GALLERY, "3_doInBackground", UNIQUE, "MULTI_FILE_FIX_SUPPORTED")
    v2 = run / "error_solutions/v2_artifacts" / GALLERY
    write(v2 / "3_doInBackground_adjudication.json", {
        "cause_status": "confirmed", "generation_status": "supported", "blocking_for_generation": [],
    })
    write(v2 / "3_doInBackground_patch_plan.json", {
        "decision": "MULTI_FILE_FIX_SUPPORTED", "generation_blockers": [],
        "required_edits": [{"source_file_path": "a.kt"}],
    })
    drafts = run / "error_solutions/coordinated_drafts" / GALLERY / "3_doInBackground"
    write(drafts / "manifest.json", {"status": "generating", "failed_files": ["b/ViewPagerActivity.kt"]})
    write(drafts / "04_ViewPagerActivity.kt.json", {
        "source_file_path": "b/ViewPagerActivity.kt", "status": "invalid",
        "validation_issues": ["file draft contains no edits"],
    })


def run_with_passing_build(run: Path) -> None:
    evidence(run, GALLERY, "3_doInBackground", UNIQUE, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
    write(run / "error_solutions" / GALLERY / "3_doInBackground_solution.json", {})
    write(run / "application_results/execution_report.json", {"per_solution_details": [{
        "finding_id": finding_key_for({"unique_error_id": UNIQUE}), "apk_name": GALLERY,
        "status": "SUCCESS", "build_validation": {"status": "success"},
        "coordinated_edits": [{
            "original_code": "import org.fossify.commons.extensions.ensureBackgroundThread",
            "corrected_code": (
                "import org.fossify.commons.helpers.ensureBackgroundThread\n"
                "import android.os.Handler"
            ),
        }],
    }]})


class NormalizationTests(unittest.TestCase):
    def test_identifiers_paths_literals_and_numbers_are_masked(self):
        self.assertEqual(
            normalize_detail("planned path lacks exact source evidence: app/src/Main.java [CLM-004]"),
            "planned path lacks exact source evidence: <path> <id>",
        )
        self.assertEqual(
            normalize_detail("Unresolved reference 'ensureBackgroundThread' at line 41"),
            "unresolved reference <x> at line <n>",
        )


class KnownPositiveTests(unittest.TestCase):
    def test_an_advisory_at_its_pinned_revision_is_a_known_positive(self):
        self.assertEqual(
            known_positive({
                "error": {"error_message": "External finding (GHSL-2022-046): x"},
                "extraction_metadata": {"pinned_revision": "f7a357f"},
            }),
            {"advisories": ["GHSL-2022-046"], "pinned_revision": "f7a357f"},
        )

    def test_an_advisory_read_at_the_current_branch_is_not(self):
        # The project may already carry the fix there.
        self.assertEqual(
            known_positive({
                "error": {"error_message": "External finding (CVE-2023-41898): x"},
                "extraction_metadata": {"pinned_revision": ""},
            }),
            {},
        )


class OutcomeTests(unittest.TestCase):
    def test_an_empty_draft_is_the_terminal_generation_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run_1"
            run_with_empty_draft(run)
            outcomes = collect_finding_outcomes(run)
        self.assertEqual(len(outcomes), 1)
        outcome = outcomes[0]
        self.assertEqual(outcome["terminal_stage"], "generation")
        self.assertEqual(outcome["signatures"], ["generation:file draft contains no edits"])
        self.assertTrue(outcome["reached"]["plan_valid"])
        self.assertFalse(outcome["reached"]["generated"])
        self.assertIn("04_ViewPagerActivity.kt.json", outcome["signals"][0]["artifact"])

    def test_a_solution_that_was_never_applied_is_named(self):
        # run_20260927_175748 applied one project with --project; another's
        # generated solution stopped with no signature at all.
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run_1"
            evidence(run, GALLERY, "3_doInBackground", UNIQUE,
                     "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
            write(run / "error_solutions" / GALLERY / "3_doInBackground_solution.json", {})
            outcome = collect_finding_outcomes(run)[0]
        self.assertEqual(outcome["terminal_stage"], "generated")
        self.assertEqual(outcome["signatures"], ["apply:not_run"])

    def test_an_adjudicated_finding_stopped_by_the_provider_ends_at_that_failure(self):
        # Review of 2026-11-09: the tracking failure of an analysed finding
        # was skipped, so a draft lost to server_is_overloaded read as the
        # stage its evidence review recorded.
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run_1"
            evidence(run, GALLERY, "3_doInBackground", UNIQUE,
                     "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
            write(run / "error_solutions/solutions_tracking.json", {"failures": [{
                "apk_name": GALLERY, "method_name": "doInBackground", "finding_id": UNIQUE,
                "kind": "provider_unavailable",
                "cause": "BackgroundResponseFailed: overloaded"}]})
            outcome = collect_finding_outcomes(run)[0]
            self.assertEqual(outcome["terminal_stage"], "provider_unavailable")
            self.assertTrue(outcome["reached"]["analysed"])
            self.assertEqual(outcome["signatures"],
                             ["provider_unavailable:backgroundresponsefailed: overloaded"])
            # A finding whose solution exists keeps its own stage.
            write(run / "error_solutions" / GALLERY / "3_doInBackground_solution.json", {})
            self.assertEqual(collect_finding_outcomes(run)[0]["terminal_stage"], "generated")

    def test_a_blocked_adjudication_names_its_blocker_kinds(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run_1"
            evidence(run, GALLERY, "3_doInBackground", UNIQUE, "NO_SAFE_FIX")
            write(run / "error_solutions/v2_artifacts" / GALLERY / "3_doInBackground_adjudication.json", {
                "cause_status": "confirmed", "generation_status": "blocked",
                "blocking_for_generation": [{"kind": "replacement_semantics_unselected", "description": "x"}],
            })
            outcome = collect_finding_outcomes(run)[0]
        self.assertEqual(outcome["terminal_stage"], "adjudication")
        self.assertEqual(outcome["signatures"], ["adjudication:replacement_semantics_unselected"])

    def _published_constructor_run(self, run: Path) -> None:
        evidence(run, GALLERY, "1_init", UNIQUE, "FIX_SUPPORTED", method="<init>")
        pr = {"html_url": "https://github.com/o/r/pull/1"}
        # PrGenerator writes "<init>" as "init" in artifact filenames.
        write(run / "pull_requests" / f"{GALLERY}_init_pr.json", {})
        write(run / "pull_requests" / f"{GALLERY}_init_pr_created.json", pr)

    def test_a_published_constructor_pull_request_counts_as_published(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run_1"
            self._published_constructor_run(run)
            outcome = collect_finding_outcomes(run)[0]
        self.assertTrue(outcome["reached"]["published"])
        self.assertEqual(outcome["terminal_stage"], "published")

    def test_unaddressed_review_feedback_ends_at_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run_1"
            self._published_constructor_run(run)
            write(run / "application_results/fix_prs_report.json", {"results": [{
                "project": GALLERY, "method_name": "<init>", "status": "NO_SAFE_FIX",
                "llm_revision": {"explanation": "callers are not editable"},
            }]})
            outcome = collect_finding_outcomes(run)[0]
        self.assertEqual(outcome["terminal_stage"], "revision")
        self.assertEqual(outcome["signatures"], ["revision:no_safe_fix"])


class RetrospectiveAcrossRunsTests(unittest.TestCase):
    def test_a_rerun_records_progress_resolution_and_verified_knowledge(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            learning = base / "learning"
            first, second = base / "run_20260913_223438", base / "run_20260914_090000"
            run_with_empty_draft(first)
            run_with_passing_build(second)
            with mock.patch("cognalys.learning.retrospective.pipeline_commit", return_value={}):
                one = run_retrospective(first, learning)
                again = run_retrospective(first, learning)
                two = run_retrospective(second, learning)
            ledger = json.loads((learning / "failure_ledger.json").read_text(encoding="utf-8"))
            knowledge = load_knowledge(learning)
            markdown = Path(two["markdown_path"]).read_text(encoding="utf-8")

        self.assertEqual(one["comparison"]["new"], ["generation:file draft contains no edits"])
        # Recording the same run twice does not double-count it.
        self.assertEqual(again["ledger_signatures"]["generation:file draft contains no edits"]["occurrences"], 1)
        self.assertEqual([run["run_id"] for run in ledger["runs"]],
                         ["run_20260913_223438", "run_20260914_090000"])
        self.assertEqual(two["findings"][0]["terminal_stage"], "validated")
        self.assertEqual(two["comparison"]["resolved_for_rerun_findings"][0]["signature"],
                         "generation:file draft contains no edits")
        self.assertEqual(two["comparison"]["finding_progress"][0]["stages"], ["generation", "validated"])
        self.assertEqual(two["funnel"]["build_passed"], 1)
        # Only the non-platform import a passing build contained is verified.
        self.assertEqual(verified_imports(knowledge, GALLERY), [{
            "symbol": "ensureBackgroundThread",
            "import": "import org.fossify.commons.helpers.ensureBackgroundThread",
            "verified_in_run": "run_20260914_090000",
        }])
        history = finding_history(knowledge, finding_key_for({"unique_error_id": UNIQUE}))
        self.assertEqual([item["ended_at"] for item in history], ["generation", "validated"])
        self.assertIn("generation → validated", markdown)

    def test_a_failed_build_verifies_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            run = base / "run_1"
            run_with_passing_build(run)
            report = json.loads((run / "application_results/execution_report.json").read_text())
            report["per_solution_details"][0]["build_validation"] = {
                "status": "failed", "compiler_diagnostics": [{"message": "Unresolved reference 'x'."}],
            }
            write(run / "application_results/execution_report.json", report)
            with mock.patch("cognalys.learning.retrospective.pipeline_commit", return_value={}):
                result = run_retrospective(run, base / "learning")
            knowledge = load_knowledge(base / "learning")
        self.assertEqual(result["findings"][0]["terminal_stage"], "build")
        self.assertEqual(result["findings"][0]["signatures"], ["build:unresolved reference <x>"])
        self.assertEqual(verified_imports(knowledge, GALLERY), [])


TASKS = "org.tasks.debug_151202.apk"


def tasks_report(build_status: str = "success") -> dict:
    """Tasks.org (run, 2026-10-25): the patch declared CustomCertManagerProvider
    in cert4android and imported it in the app, and the build passed."""
    return {"per_solution_details": [{
        "finding_id": "d2fe5d5ac47b", "apk_name": TASKS,
        "build_validation": {"status": build_status},
        "coordinated_edits": [
            {"original_code": "class CustomCertManager(\n) {\n}\n",
             "corrected_code": ("class CustomCertManager(\n) {\n}\n"
                                "// the provider class below registers the factory\n"
                                "class CustomCertManagerProvider : Provider(\"x\", \"1\", \"y\")\n"
                                "enum class Mode { A }\n")},
            {"original_code": "import at.bitfire.cert4android.CustomCertManager",
             "corrected_code": ("import at.bitfire.cert4android.CustomCertManager\n"
                                "import at.bitfire.cert4android.CustomCertManagerProvider\n"
                                "import at.bitfire.cert4android.Mode as CertMode\n"
                                "import okhttp3.ConnectionSpec")},
        ],
    }]}


class LlmPerformanceTests(unittest.TestCase):
    def test_a_corpus_hit_is_counted_apart_in_llm_performance(self):
        from cognalys.learning.retrospective import llm_performance

        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory) / "application_results" / "openai_prompt_logs"
            logs.mkdir(parents=True)
            for name, status in (("a", "success"), ("b", "research_corpus"),
                                 ("c", "cache_hit"), ("d", "error")):
                (logs / f"{name}_metadata.json").write_text(json.dumps(
                    {"stage": "external_research", "status": status, "latency_ms": 10}),
                    encoding="utf-8")
            performance = llm_performance(Path(directory))
        entry = performance["per_stage"]["external_research"]
        self.assertEqual((entry["calls"], entry["corpus_hits"], entry["cache_hits"],
                          entry["failed"]), (4, 1, 1, 1))
        # The served answer is not read as a failed call.
        self.assertEqual([signal["detail"] for signal in performance["signals"]], ["1 call(s)"])


class PatchDeclaredImportTests(unittest.TestCase):
    """Tasks.org run_v2 (2026-10-29) was told to use exactly
    `import at.bitfire.cert4android.CustomCertManagerProvider`, a class only
    the earlier, unmerged patch declared, and failed with Unresolved reference."""

    def test_an_import_of_a_class_the_same_patch_declares_is_not_verified(self):
        from cognalys.learning.retrospective import harvest_knowledge

        knowledge, added = harvest_knowledge({}, "run", [], tasks_report())
        self.assertEqual([item["symbol"] for item in verified_imports(knowledge, TASKS)],
                         ["ConnectionSpec"])
        self.assertEqual(added, [f"{TASKS}: import okhttp3.ConnectionSpec"])

    def test_entries_the_same_findings_patch_declared_are_purged(self):
        from cognalys.learning.retrospective import harvest_knowledge, purge_patch_declared_imports

        def stored(finding_key):
            return {"import": "import at.bitfire.cert4android.CustomCertManagerProvider",
                    "run": "run", "finding_key": finding_key, "build_status": "success"}

        knowledge = {"repositories": {TASKS: {"verified_imports": {
            "CustomCertManagerProvider": stored("d2fe5d5ac47b")}}}}
        removed = purge_patch_declared_imports(knowledge, tasks_report("failed"))
        self.assertEqual(removed, [f"{TASKS}: import at.bitfire.cert4android.CustomCertManagerProvider"])
        self.assertEqual(verified_imports(knowledge, TASKS), [])
        # Another finding's entry is left alone: its patch is not this one.
        knowledge = {"repositories": {TASKS: {"verified_imports": {
            "CustomCertManagerProvider": stored("other")}}}}
        knowledge, _ = harvest_knowledge(knowledge, "run_v3", [], tasks_report("failed"))
        self.assertEqual([item["symbol"] for item in verified_imports(knowledge, TASKS)],
                         ["CustomCertManagerProvider"])

    def test_an_entry_a_later_run_verified_is_not_purged_by_the_earlier_run(self):
        # Once the earlier patch is merged, a later run of the same finding
        # imports the type from the checkout, and that import is verified.
        from cognalys.learning.retrospective import harvest_knowledge

        knowledge = {"repositories": {TASKS: {"verified_imports": {
            "CustomCertManagerProvider": {
                "import": "import at.bitfire.cert4android.CustomCertManagerProvider",
                "run": "run_v3", "finding_key": "d2fe5d5ac47b", "build_status": "success"}}}}}
        knowledge, added = harvest_knowledge(knowledge, "run", [], tasks_report())
        self.assertEqual(sorted(item["symbol"] for item in verified_imports(knowledge, TASKS)),
                         ["ConnectionSpec", "CustomCertManagerProvider"])
        self.assertFalse(any(item.startswith("removed") for item in added))

    def test_the_purge_runs_over_stored_runs_without_touching_the_rest(self):
        from cognalys.learning.retrospective import main

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            run = base / "run"
            write(run / "application_results/execution_report.json", tasks_report())
            learning = base / "learning"
            write(learning / "verified_knowledge.json", {"format_version": 1, "repositories": {
                TASKS: {"verified_imports": {
                    "CustomCertManagerProvider": {
                        "import": "import at.bitfire.cert4android.CustomCertManagerProvider",
                        "run": "run", "finding_key": "d2fe5d5ac47b"},
                    "ConnectionSpec": {"import": "import okhttp3.ConnectionSpec",
                                       "run": "run", "finding_key": "d2fe5d5ac47b"}}}},
                "findings": {"k": {"attempts": []}}})
            self.assertEqual(main(["purge-patch-declared-imports", "--learning-dir",
                                   str(learning), str(run)]), 0)
            knowledge = json.loads((learning / "verified_knowledge.json").read_text(encoding="utf-8"))
        self.assertEqual([item["symbol"] for item in verified_imports(knowledge, TASKS)],
                         ["ConnectionSpec"])
        self.assertEqual(knowledge["findings"], {"k": {"attempts": []}})


def run_that_abstains(run: Path, context_sha256: str) -> None:
    evidence(run, GALLERY, "3_doInBackground", UNIQUE, "NO_SAFE_FIX")
    write(run / "error_solutions/v2_artifacts" / GALLERY / "3_doInBackground_adjudication.json", {
        "cause_status": "unknown", "generation_status": "blocked", "confirmed_cause": "not confirmed",
    })
    write(
        run / "error_solutions/finding_context" / GALLERY / "3_doInBackground/manifest.json",
        {"context_sha256": context_sha256},
    )


class FindingsIndexTests(unittest.TestCase):
    def test_the_index_points_at_the_artifacts_that_exist_relative_to_the_run(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            run = base / "run_20260926_191812"
            run_that_abstains(run, "aaa")
            with mock.patch("cognalys.learning.retrospective.pipeline_commit", return_value={}):
                run_retrospective(run, base / "learning")
            index = json.loads((run / "findings_index.json").read_text(encoding="utf-8"))
        self.assertEqual(index["schema_version"], 1)
        [finding] = index["findings"]
        self.assertEqual(finding["terminal_stage"], "adjudication")
        self.assertEqual(finding["evidence_fingerprint"], "aaa")
        artifacts = finding["artifacts"]
        self.assertEqual(
            artifacts["adjudication"],
            f"error_solutions/v2_artifacts/{GALLERY}/3_doInBackground_adjudication.json",
        )
        self.assertIn("evidence_review", artifacts)
        self.assertNotIn("solution", artifacts)
        self.assertNotIn("pull_request_created", artifacts)


class VerdictChangeTests(unittest.TestCase):
    """The same evidence produced a patch in one run and an abstention in the next."""

    def flip(self, second_context: str) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            first, second = base / "run_20260925_122741", base / "run_20260925_164154"
            run_with_passing_build(first)
            write(first / "error_solutions/finding_context" / GALLERY / "3_doInBackground/manifest.json",
                  {"context_sha256": "aaa"})
            run_that_abstains(second, second_context)
            with mock.patch("cognalys.learning.retrospective.pipeline_commit", return_value={}):
                run_retrospective(first, base / "learning")
                result = run_retrospective(second, base / "learning")
            result["markdown"] = Path(result["markdown_path"]).read_text(encoding="utf-8")
        return result

    def test_a_flip_on_identical_evidence_is_reported_as_model_variance(self):
        result = self.flip("aaa")
        [change] = result["comparison"]["verdict_changes"]
        self.assertEqual((change["was"], change["now"]), ("proposed", "abstained"))
        self.assertEqual(change["previous_stage"], "validated")
        self.assertEqual(change["now_stage"], "adjudication")
        self.assertIs(change["same_evidence"], True)
        self.assertIn("## Verdict changed since an earlier run", result["markdown"])
        self.assertIn("identical evidence", result["markdown"])

    def test_a_flip_after_the_evidence_changed_says_so(self):
        [change] = self.flip("bbb")["comparison"]["verdict_changes"]
        self.assertIs(change["same_evidence"], False)

    def test_an_unrecorded_fingerprint_is_unknown_not_assumed_equal(self):
        earlier = [{"run_id": "r1", "findings": [
            {"finding_key": "k", "terminal_stage": "published"},
        ]}]
        [change] = verdict_changes(
            [{"finding_key": "k", "terminal_stage": "adjudication", "apk": "a", "method": "m",
              "evidence_fingerprint": "aaa"}], earlier,
        )
        self.assertIsNone(change["same_evidence"])

    def test_an_unchanged_verdict_or_an_unrelated_stage_is_not_a_change(self):
        earlier = [{"run_id": "r1", "findings": [
            {"finding_key": "k", "terminal_stage": "adjudication"},
            {"finding_key": "j", "terminal_stage": "published"},
        ]}]
        self.assertEqual(verdict_changes([
            {"finding_key": "k", "terminal_stage": "plan"},
            {"finding_key": "j", "terminal_stage": "not_analyzable"},
        ], earlier), [])


class ConsumerTests(unittest.TestCase):
    def test_the_finding_key_matches_the_worktree_finding_id(self):
        from cognalys.solutions.worktree_manager import WorktreeManager

        solution = {"unique_error_id": UNIQUE}
        self.assertEqual(finding_key_for(solution), WorktreeManager.finding_id(solution))

    def test_the_generator_reads_verified_imports_and_attempts(self):
        from cognalys.llm.generate_error_fixes import learning_context

        with tempfile.TemporaryDirectory() as directory:
            learning = Path(directory)
            key = finding_key_for({"unique_error_id": UNIQUE})
            write(learning / "verified_knowledge.json", {
                "repositories": {GALLERY: {"verified_imports": {"ensureBackgroundThread": {
                    "import": "import org.fossify.commons.helpers.ensureBackgroundThread", "run": "r1",
                }}}},
                "findings": {key: {"attempts": [
                    {"run": "r1", "terminal_stage": "generation", "signatures": ["generation:x"], "details": []},
                ]}},
            })
            with mock.patch.dict("os.environ", {"TCC_LEARNING_DIR": str(learning)}):
                context = learning_context({"unique_error_id": UNIQUE}, GALLERY)
                empty = learning_context({"unique_error_id": "other"}, "other.apk")
        self.assertEqual(context["verified_repository_imports"][0]["symbol"], "ensureBackgroundThread")
        self.assertEqual(context["previous_attempts_of_this_finding"][0]["ended_at"], "generation")
        self.assertEqual(empty, {})

    def test_rename_failures_learned_under_older_rename_rules_are_not_fed_back(self):
        """NotallyX's rerun was told adjudication:rename_safety_authorization_missing."""
        from cognalys.extraction.rename_safety import RENAME_RULES_VERSION

        knowledge = {"findings": {"k": {"attempts": [
            {"run": "r1", "terminal_stage": "adjudication",
             "signatures": ["adjudication:rename_safety_authorization_missing"],
             "details": [{"signature": "adjudication:rename_safety_authorization_missing",
                          "detail": "rename authorization not supplied"}]},
            {"run": "r2", "terminal_stage": "generation",
             "signatures": ["generation:empty_draft", "semantic:UNAUTHORIZED_RENAME"],
             "details": []},
            {"run": "r3", "terminal_stage": "generation", "rename_rules_version": RENAME_RULES_VERSION,
             "signatures": ["semantic:RENAME_REFERENCES_NOT_UPDATED"], "details": []},
        ]}}}
        history = finding_history(knowledge, "k")
        self.assertEqual([item["run"] for item in history], ["r2", "r3"])
        self.assertEqual(history[0]["failure_signatures"], ["generation:empty_draft"])
        # A signature recorded under the current rules is kept.
        self.assertEqual(history[1]["failure_signatures"], ["semantic:RENAME_REFERENCES_NOT_UPDATED"])

    def test_validated_drafts_never_push_the_failures_out(self):
        """BlueGate (2026-10-31): run_v9's planner saw one of the three build lessons."""
        from cognalys.extraction.rename_safety import RENAME_RULES_VERSION

        mismatch = {"signature": "build:argument type mismatch",
                    "detail": "app/src/main/java/b/MainActivity.kt:288: Argument type mismatch: "
                              "actual type is 'KeyStore.PrivateKeyEntry', but 'KeyPair' was expected."}
        attempts = [{"run": f"run_v{number}", "terminal_stage": "repair",
                     "rename_rules_version": RENAME_RULES_VERSION,
                     "signatures": ["build:argument type mismatch"], "details": [mismatch]}
                    for number in (4, 5, 6)]
        attempts += [{"run": f"run_v{number}", "terminal_stage": "validated",
                      "rename_rules_version": RENAME_RULES_VERSION, "signatures": [],
                      "details": [], "draft_title": "Return the stored key entry",
                      "draft_files": ["KeyManager.kt", "Authenticator.kt"]}
                     for number in (7, 8)]
        attempts.append({"run": "run_v9", "terminal_stage": "generation",
                         "rename_rules_version": RENAME_RULES_VERSION,
                         "signatures": ["generation:incomplete"], "details": []})
        history = finding_history({"findings": {"k": {"attempts": attempts}}}, "k")
        self.assertEqual([item["run"] for item in history],
                         ["run_v5", "run_v6", "run_v7", "run_v8", "run_v9"])
        self.assertIn("MainActivity.kt:288", history[0]["details"][0]["detail"])
        self.assertEqual(history[2]["validated_draft"],
                         {"title": "Return the stored key entry",
                          "files": ["KeyManager.kt", "Authenticator.kt"]})
        self.assertNotIn("validated_draft", history[0])

    def test_attempts_that_stopped_before_a_patch_are_not_fed_back(self):
        """CometOTP run_v6..v8 (2026-11-10): dismissals of earlier adjudications
        reached the planner; Melox run_v4's was told the provider refused."""
        attempts = [{"run": f"r_{stage}", "terminal_stage": stage,
                     "signatures": [f"{stage}:x"], "details": []}
                    for stage in ("adjudication", "plan", "analysis", "crashed",
                                  "provider_refused", "generation")]
        history = finding_history({"findings": {"k": {"attempts": attempts}}}, "k")
        self.assertEqual([item["run"] for item in history], ["r_generation"])

    def test_the_window_is_taken_before_the_patch_filter(self):
        """Three later stops at the adjudication leave no room for an older build lesson."""
        attempts = [{"run": "r1", "terminal_stage": "build", "signatures": ["build:x"],
                     "details": []}]
        attempts += [{"run": f"r{number}", "terminal_stage": "adjudication",
                      "signatures": ["adjudication:x"], "details": []} for number in (2, 3, 4)]
        self.assertEqual(finding_history({"findings": {"k": {"attempts": attempts}}}, "k"), [])

    def test_a_refusal_a_changed_check_can_affect_is_not_fed_back(self):
        from cognalys.learning import knowledge

        signature = "generation:semantic:x_code"
        constructor = {"signature": signature, "detail": "the patch changes Ctor(a), which is stored"}
        factory = {"signature": signature, "detail": "the patch changes Api.getInstance(a), stored"}

        def attempt(run, details, **extra):
            return {"run": run, "terminal_stage": "generation", "signatures": [signature],
                    "details": details, **extra}

        attempts = [attempt("unstamped", [constructor, factory]),
                    attempt("stamped", [constructor, factory], draft_check_rules_version=2),
                    attempt("emptied", [constructor])]
        with mock.patch.dict(knowledge.DRAFT_CHECK_CHANGES, {"X_CODE": {
                "changed_at": 2, "detail": r"the patch changes [A-Za-z_$][\w$]*\("}}):
            history = finding_history({"findings": {"k": {"attempts": attempts}}}, "k")
        self.assertEqual([item["run"] for item in history], ["unstamped", "stamped"])
        self.assertEqual(history[0]["details"], [factory])
        self.assertEqual(history[0]["failure_signatures"], [signature])
        self.assertEqual(history[1]["details"], [constructor, factory])

    def test_a_retired_refusal_takes_its_signature_when_no_detail_of_it_remains(self):
        from cognalys.learning import knowledge

        signature = "generation:semantic:x_code"
        attempts = [{"run": "r1", "terminal_stage": "generation",
                     "signatures": [signature, "generation:other"],
                     "details": [{"signature": signature, "detail": "the patch changes Ctor(a)"}]}]
        with mock.patch.dict(knowledge.DRAFT_CHECK_CHANGES, {"X_CODE": {
                "changed_at": 2, "detail": r"the patch changes [A-Za-z_$][\w$]*\("}}):
            history = finding_history({"findings": {"k": {"attempts": attempts}}}, "k")
        self.assertEqual(history[0]["failure_signatures"], ["generation:other"])
        self.assertEqual(history[0]["details"], [])

    def test_each_change_of_a_check_retires_only_refusals_recorded_before_it(self):
        """STORED_DERIVED_VALUE_CHANGED changed at 2 (constructors fed random
        material) and at 3 (a literal given only to a random generator)."""
        signature = "generation:semantic:stored_derived_value_changed"
        constructor = {"signature": signature,
                       "detail": "the patch changes SecretKeySpec(raw,\"AES\"), and the value"}
        generator = {"signature": signature,
                     "detail": 'the patch changes the algorithm literal "HmacSHA1", and the value'}
        digest = {"signature": signature,
                  "detail": 'the patch changes the algorithm literal "SHA-1", and the value'}

        def attempt(run, **extra):
            return {"run": run, "terminal_stage": "generation", "signatures": [signature],
                    "details": [constructor, generator, digest], **extra}

        history = finding_history({"findings": {"k": {"attempts": [
            attempt("v1"), attempt("v2", draft_check_rules_version=2),
            attempt("v3", draft_check_rules_version=3)]}}}, "k")
        self.assertEqual([item["details"] for item in history],
                         [[digest], [constructor, digest], [constructor, generator, digest]])

    def test_a_recorded_attempt_carries_the_draft_check_rules_version(self):
        from cognalys.learning.knowledge import DRAFT_CHECK_RULES_VERSION
        from cognalys.learning.retrospective import harvest_knowledge

        knowledge, _ = harvest_knowledge({}, "run_1", [{
            "finding_key": "f", "apk": "a", "method": "m", "terminal_stage": "generation",
            "signals": [], "signatures": []}], {})
        attempt = knowledge["findings"]["f"]["attempts"][0]
        self.assertEqual(attempt["draft_check_rules_version"], DRAFT_CHECK_RULES_VERSION)

    def test_a_seeded_store_holds_imports_and_no_attempts(self):
        from cognalys.learning.knowledge import seeded_store

        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "shared", Path(directory) / "run" / "learning"
            imports = {GALLERY: {"verified_imports": {"x": {"import": "import a.x", "run": "r"}}}}
            write(source / "verified_knowledge.json", {
                "repositories": imports,
                "findings": {"k": {"attempts": [{"run": "r", "terminal_stage": "build"}]}}})
            self.assertEqual(seeded_store(source, target), target)
            seeded = json.loads((target / "verified_knowledge.json").read_text(encoding="utf-8"))
            self.assertEqual(seeded, {"repositories": imports, "findings": {}})
            # A resumed execution keeps what it recorded.
            write(target / "verified_knowledge.json", {"repositories": {}, "findings": {"j": {}}})
            seeded_store(source, target)
            kept = json.loads((target / "verified_knowledge.json").read_text(encoding="utf-8"))
        self.assertEqual(kept["findings"], {"j": {}})

    def test_a_build_failure_keeps_every_place_with_its_line(self):
        from cognalys.learning.retrospective import located_diagnostics

        worktree = "/home/u/work/wt/16e0fde005ac/ab8d283f07"
        diagnostics = [
            {"path": f"{worktree}/app/src/main/java/b/AdminDashboardActivity.kt", "line": 244,
             "message": "Argument type mismatch: actual type is 'KeyStore.PrivateKeyEntry', "
                        "but 'KeyPair' was expected.",
             "source_line": "val authenticator = Authenticator(this, bleManager, keyEntry)"},
            {"path": f"{worktree}/app/src/main/java/b/MainActivity.kt", "line": 288,
             "message": "Argument type mismatch: actual type is 'KeyStore.PrivateKeyEntry', "
                        "but 'KeyPair' was expected."},
            {"message": "Unresolved reference 'x'."}]
        located = located_diagnostics(diagnostics, worktree)
        self.assertTrue(located[0].startswith("app/src/main/java/b/AdminDashboardActivity.kt:244: "
                                              "Argument type mismatch"))
        self.assertIn("(val authenticator = Authenticator(this, bleManager, keyEntry))", located[0])
        self.assertTrue(located[1].startswith("app/src/main/java/b/MainActivity.kt:288: "))
        self.assertEqual(located[2], "Unresolved reference 'x'.")

    def test_a_validated_run_records_its_draft_title_and_files(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            run = base / "run_1"
            run_with_passing_build(run)
            from cognalys.utils.artifact_names import finding_artifact_stem

            write(run / "pull_requests" / (finding_artifact_stem(
                GALLERY, "doInBackground", "DeprecatedApiSpec") + "_pr.json"),
                {"title": "Use the helpers import", "changed_files": ["src/A.kt"]})
            with mock.patch("cognalys.learning.retrospective.pipeline_commit", return_value={}):
                run_retrospective(run, base / "learning")
            knowledge = load_knowledge(base / "learning")
        history = finding_history(knowledge, finding_key_for({"unique_error_id": UNIQUE}))
        self.assertEqual(history[-1]["validated_draft"],
                         {"title": "Use the helpers import", "files": ["src/A.kt"]})

    def test_the_store_keeps_failures_apart_from_validated_runs(self):
        """Review of batch 13 (2026-10-31): the store kept the last five attempts of
        any kind, so validated runs still dropped the build lessons."""
        from cognalys.learning.retrospective import harvest_knowledge

        def outcome(stage, detail=""):
            signals = [{"signature": f"{stage}:x", "detail": detail}] if detail else []
            return {"finding_key": "f", "apk": "a", "method": "m", "terminal_stage": stage,
                    "signals": signals, "signatures": [item["signature"] for item in signals],
                    **({"draft": {"title": "t", "files": ["A.kt"]}}
                       if stage == "validated" else {})}

        knowledge = {}
        sequence = [("run_v5", outcome("repair", "PrivateKeyEntry but KeyPair expected")),
                    ("run_v6", outcome("repair", "PrivateKeyEntry but KeyPair expected")),
                    ("run_v7", outcome("validated")), ("run_v8", outcome("validated")),
                    ("run_v9", outcome("generation", "no effect")),
                    ("run_v10", outcome("validated")), ("run_v11", outcome("validated"))]
        for run, item in sequence:
            knowledge, _ = harvest_knowledge(knowledge, run, [item], {})
        history = finding_history(knowledge, "f")
        self.assertEqual([entry["run"] for entry in history if entry["ended_at"] != "validated"],
                         ["run_v5", "run_v6", "run_v9"])
        # A run harvested again stays where it stands, never read as the newest.
        knowledge, _ = harvest_knowledge(knowledge, "run_v5", [sequence[0][1]], {})
        self.assertEqual([entry["run"] for entry in finding_history(knowledge, "f")],
                         ["run_v5", "run_v6", "run_v8", "run_v9", "run_v10", "run_v11"])

    def test_one_failed_build_is_one_signal_with_every_place(self):
        """Review of batch 13 (2026-10-31): one signal per place counted one failed
        build three times in the failure ledger."""
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run_1"
            run_with_passing_build(run)
            worktree = "/home/u/work/wt/1/2"
            message = "Argument type mismatch: actual type is 'KeyStore.PrivateKeyEntry'."
            write(run / "application_results/execution_report.json", {"per_solution_details": [{
                "finding_id": finding_key_for({"unique_error_id": UNIQUE}), "apk_name": GALLERY,
                "status": "SUCCESS", "build_validation": {
                    "status": "failed", "worktree_path": worktree, "compiler_diagnostics": [
                        {"path": f"{worktree}/app/A.kt", "line": 244, "message": message},
                        {"path": f"{worktree}/app/M.kt", "line": 288, "message": message},
                        {"path": f"{worktree}/app/X.kt", "line": 9, "message": message}]}}]})
            outcomes = collect_finding_outcomes(run)
        build = [item for item in outcomes[0]["signals"] if item["signature"].startswith("build:")]
        self.assertEqual(len(build), 1)
        self.assertTrue(build[0]["detail"].startswith("app/A.kt:244: Argument type mismatch"))
        self.assertIn("; also at app/M.kt:288; also at app/X.kt:9", build[0]["detail"])

    def test_a_pull_request_attributed_to_a_joint_finding_is_not_this_findings_draft(self):
        """Review of batch 13 (2026-10-31): a unit whose reported finding had no
        effect recorded that finding as validated, with the joint finding's patch
        as its draft, while the statistics said "sem impacto"."""
        from cognalys.utils.artifact_names import finding_artifact_stem

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "run_1"
            run_with_passing_build(run)
            write(run / "pull_requests" / (finding_artifact_stem(
                GALLERY, "doInBackground", "DeprecatedApiSpec") + "_pr.json"), {
                "title": "Store the entry", "changed_files": ["src/A.kt"],
                "method_name": "doInBackground", "spec": "KeyStoreSpec",
                "analysed_finding": {"method_name": "doInBackground",
                                     "spec": "DeprecatedApiSpec"},
                "joint_findings_without_effect": [{
                    "method": "doInBackground", "specification": "DeprecatedApiSpec",
                    "reason": "the same generator output"}]})
            outcome = collect_finding_outcomes(run)[0]
        self.assertEqual(outcome["terminal_stage"], "generation")
        self.assertNotIn("draft", outcome)
        self.assertEqual(outcome["signals"][0]["signature"],
                         "generation:reported_finding_without_effect")
        self.assertIn("KeyStoreSpec", outcome["signals"][0]["detail"])
        self.assertIn("the same generator output", outcome["signals"][0]["detail"])


class PipelineIntegrationTests(unittest.TestCase):
    def test_the_retrospective_runs_after_steps_ran_and_never_fails_the_run(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("run_pipeline_learning", ROOT / "src/cognalys/orchestration/run_pipeline.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        paths = mock.Mock(root=ROOT, error_solutions_dir=Path("/nonexistent/run_x/error_solutions"),
                          application_results_dir=Path("/nonexistent/run_x/application_results"),
                          pull_requests_dir=Path("/nonexistent/run_x/pull_requests"))
        args = mock.Mock(no_retrospective=False, learning_dir="unused")
        with mock.patch("cognalys.learning.retrospective.run_retrospective", side_effect=RuntimeError("boom")) as called:
            module.run_retrospective_safely(paths, args, ["llm"])
            module.run_retrospective_safely(paths, args, [])
            args.no_retrospective = True
            module.run_retrospective_safely(paths, args, ["llm"])
        self.assertEqual(called.call_count, 1)


if __name__ == "__main__":
    unittest.main()
