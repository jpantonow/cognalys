"""Grounding for deprecated-API and outdated-dependency findings.

run_20260913_004434 analysed five such findings and abstained on all of them:
research ran with zero queries, the adjudications blocked on "no replacement
selected" and "effective version unknown", and a confirmed migration could
never become a reviewable patch. These tests pin each piece added in response,
on repositories shaped like Fossify Gallery, NetworkSurvey and the RxJava 2
projects.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction import dependency_finding  # noqa: E402
from cognalys.extraction.dependency_finding import (  # noqa: E402
    collect_dependency_finding,
    migration_scale,
    package_prefixes,
    parse_finding_message,
)
from cognalys.extraction.migration_grounding import (  # noqa: E402
    contract_files,
    deprecated_usage_contract,
    repository_replacement_idioms,
)
from cognalys.llm.migration_policy import promote_grounded_api_migration_review  # noqa: E402
from cognalys.llm.pipeline_architecture import (  # noqa: E402
    lifecycle_research_questions,
    migration_contract_sources,
)


ASYNCTASK = ("android.os.AsyncTask is deprecated. Use java.util.concurrent or "
             "Kotlin Coroutines.")
BROADCAST = ("androidx.localbroadcastmanager.content.LocalBroadcastManager is "
             "deprecated. Use LiveData or Flow.")
RXJAVA = "Using RxJava 2.2.9 which is EOL. Update to RxJava 3.x."

TASK = "app/src/main/kotlin/org/example/gallery/GetMediaAsynctask.kt"
ACTIVITY = "app/src/main/kotlin/org/example/gallery/SearchActivity.kt"
TASK_KT = """package org.example.gallery

import android.os.AsyncTask

class GetMediaAsynctask(val context: Context, val callback: (List<String>) -> Unit) :
    AsyncTask<Void, Void, List<String>>() {

    override fun doInBackground(vararg params: Void): List<String> {
        return emptyList()
    }

    override fun onPostExecute(media: List<String>) {
        super.onPostExecute(media)
        callback(media)
    }

    fun stopFetching() {
        cancel(true)
    }
}
"""
ACTIVITY_KT = """package org.example.gallery

class SearchActivity : SimpleActivity() {
    private var mCurrAsyncTask: GetMediaAsynctask? = null

    private fun startAsyncTask() {
        mCurrAsyncTask?.stopFetching()
        mCurrAsyncTask = GetMediaAsynctask(applicationContext) { media -> show(media) }
        mCurrAsyncTask!!.execute()
    }

    override fun onDestroy() {
        super.onDestroy()
        mCurrAsyncTask?.stopFetching()
    }

    private fun refresh() {
        ensureBackgroundThread {
            reload()
        }
    }
}
"""
HELPER_KT = """package org.example.gallery

import org.example.commons.helpers.ensureBackgroundThread

fun Context.reloadAll() {
    ensureBackgroundThread {
        mediaDB.clear()
    }
}
"""


def write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def gallery_like(root: Path) -> dict:
    write(root, TASK, TASK_KT)
    write(root, ACTIVITY, ACTIVITY_KT)
    write(root, "app/src/main/kotlin/org/example/gallery/Context.kt", HELPER_KT)
    return {**parse_finding_message(ASYNCTASK), "status": "confirmed"}


class LifecycleResearchQuestionTests(unittest.TestCase):
    def test_a_deprecated_api_asks_for_its_notice_replacement_and_contract(self):
        finding = {**parse_finding_message(ASYNCTASK), "status": "confirmed"}
        questions = lifecycle_research_questions(finding)
        self.assertEqual(len(questions), 1)
        self.assertIn("android.os.AsyncTask", questions[0])
        self.assertIn("cancellation", questions[0])

    def test_an_outdated_dependency_asks_for_its_support_status_and_migration_guide(self):
        finding = {
            **parse_finding_message(RXJAVA), "status": "confirmed",
            "matched_declarations": [{"group": "io.reactivex.rxjava2", "artifact": "rxjava"}],
        }
        questions = lifecycle_research_questions(finding)
        self.assertEqual(len(questions), 1)
        self.assertIn("RxJava 2.x release line", questions[0])
        self.assertIn("io.reactivex.rxjava2", questions[0])
        self.assertIn("migration guide", questions[0])

    def test_two_patch_releases_of_one_line_ask_the_same_question(self):
        # The same question is a research cache hit for the second project.
        declarations = {"matched_declarations": [
            {"group": "io.reactivex.rxjava2", "artifact": "rxjava"},
        ]}
        amaze = lifecycle_research_questions({
            **parse_finding_message(RXJAVA), "status": "confirmed", **declarations,
        })
        commons = lifecycle_research_questions({
            **parse_finding_message(RXJAVA.replace("2.2.9", "2.2.3")),
            "status": "confirmed",
            "matched_declarations": [
                {"group": "io.reactivex.rxjava2", "artifact": "rxjava"},
                {"group": "io.reactivex.rxjava2", "artifact": "rxandroid"},
            ],
        })
        self.assertEqual(amaze, commons)

    def test_nothing_to_research_when_the_checkout_does_not_have_it(self):
        finding = {**parse_finding_message(RXJAVA), "status": "not_found"}
        self.assertEqual(lifecycle_research_questions(finding), [])
        self.assertEqual(lifecycle_research_questions({}), [])


class ReplacementIdiomTests(unittest.TestCase):
    def test_the_repositorys_own_background_helper_is_found_first(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = gallery_like(root)
            write(root, "app/src/main/java/org/example/Work.java",
                  "import java.util.concurrent.Executors;\nclass Work {}\n")
            result = repository_replacement_idioms(root, finding)
        self.assertEqual(result["status"], "found")
        mechanisms = result["by_deprecated_type"][0]["mechanisms"]
        self.assertEqual(mechanisms[0]["mechanism"], "project background-thread helper")
        self.assertEqual(mechanisms[0]["production_files"], 2)
        # The import that makes the helper resolvable, as the repository
        # writes it, so a patch does not have to guess its package.
        self.assertEqual(mechanisms[0]["imports"],
                         ["import org.example.commons.helpers.ensureBackgroundThread"])
        self.assertIn("java.util.concurrent (named by the finding)",
                      [item["mechanism"] for item in mechanisms])
        self.assertEqual(
            result["by_deprecated_type"][0]["roles"][0]["role"],
            "background_work_with_main_thread_result",
        )

    def test_a_non_migration_finding_has_no_idioms(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(repository_replacement_idioms(Path(directory), {"kind": "dependency_version"}), {})


ENSURE_BACKGROUND_THREAD_JAVAP = """  public static final void ensureBackgroundThread(kotlin.jvm.functions.Function0<kotlin.Unit>);
    Code:
       0: aload_0
       1: ldc           #121                // String callback
       3: invokestatic  #125                // Method kotlin/jvm/internal/Intrinsics.checkNotNullParameter:(Ljava/lang/Object;Ljava/lang/String;)V
       6: invokestatic  #127                // Method isOnMainThread:()Z
       9: ifeq          31
      12: new           #129                // class java/lang/Thread
      15: dup
      16: aload_0
      17: invokedynamic #146,  0            // InvokeDynamic #0:run:(Lkotlin/jvm/functions/Function0;)Ljava/lang/Runnable;
      22: invokespecial #150                // Method java/lang/Thread."<init>":(Ljava/lang/Runnable;)V
      25: invokevirtual #153                // Method java/lang/Thread.start:()V
      28: goto          38
      31: aload_0
      32: invokeinterface #159,  1          // InterfaceMethod kotlin/jvm/functions/Function0.invoke:()Ljava/lang/Object;
      37: pop
      38: return
"""


class ImplementationBehaviourTests(unittest.TestCase):
    """org.fossify.commons.helpers.ensureBackgroundThread, as javap prints it."""

    def test_the_fossify_helper_is_read_as_running_inline_off_the_main_thread(self):
        from cognalys.extraction.migration_grounding import behaviour_consequences, summarize_bytecode_behaviour

        facts = summarize_bytecode_behaviour(ENSURE_BACKGROUND_THREAD_JAVAP)
        self.assertEqual(facts, {
            "checks_main_thread": True, "starts_new_thread": True,
            "runs_callback_inline": True, "uses_executor": False,
            "posts_to_handler": False, "uses_coroutines": False,
        })
        guarantees, caveats = behaviour_consequences(facts)
        self.assertEqual(guarantees, [])
        self.assertIn("synchronously on the caller's thread", caveats[0])
        self.assertIn("no ordering", caveats[1])

    def test_a_helper_declared_in_the_repository_is_read_from_its_source(self):
        from cognalys.extraction.migration_grounding import implementation_behaviour

        sources = {
            "commons/src/main/kotlin/org/example/helpers/Threads.kt": (
                "package org.example.helpers\n\n"
                "fun ensureBackgroundThread(callback: () -> Unit) {\n"
                "    if (isOnMainThread()) {\n"
                "        Thread { callback() }.start()\n"
                "    } else {\n"
                "        callback()\n"
                "    }\n"
                "}\n"
            ),
        }
        behaviour = implementation_behaviour(
            Path("."), "import org.example.helpers.ensureBackgroundThread", sources, [],
        )
        self.assertEqual(behaviour["basis"], "repository_source")
        self.assertTrue(behaviour["facts"]["runs_callback_inline"])
        self.assertTrue(behaviour["facts"]["checks_main_thread"])
        self.assertEqual(behaviour["derived_guarantees"], [])
        # Platform types and classes are not read.
        self.assertEqual(implementation_behaviour(Path("."), "import android.os.Handler", sources, []), {})
        self.assertEqual(implementation_behaviour(Path("."), "import org.example.Worker", sources, []), {})


class MechanismRecommendationTests(unittest.TestCase):
    def test_invariants_pick_an_executor_and_a_handler_over_the_popular_helper(self):
        from cognalys.extraction.migration_grounding import recommend_mechanisms

        idioms = {"by_deprecated_type": [{
            "deprecated_type": "android.os.AsyncTask",
            "mechanisms": [
                {"mechanism": "project background-thread helper", "production_files": 22,
                 "guarantees": [], "platform": False,
                 "implementation_behaviour": [{"derived_guarantees": [], "caveats": [
                     "runs the work synchronously on the caller's thread when called off the main thread"]}]},
                {"mechanism": "main-thread Handler or runOnUiThread", "production_files": 20,
                 "guarantees": ["main_thread_dispatch"], "platform": True},
                {"mechanism": "Kotlin coroutines", "production_files": 2, "platform": False,
                 "guarantees": ["cancellation_handle", "main_thread_dispatch", "off_caller_thread"]},
                {"mechanism": "java.util.concurrent executor", "production_files": 0, "platform": True,
                 "guarantees": ["serial_execution", "cancellation_handle", "isolated_interrupts",
                                "off_caller_thread"]},
            ],
        }]}
        contract = {"contracts": [{"deprecated_type": "android.os.AsyncTask", "invariants": [
            {"when": "execute", "requires": ["serial_execution"]},
            {"when": "doInBackground", "requires": ["off_caller_thread"]},
            {"when": "onPostExecute", "requires": ["main_thread_dispatch"]},
            {"when": "cancel", "requires": ["cancellation_handle", "isolated_interrupts"]},
        ]}]}
        recommendation = recommend_mechanisms(idioms, contract)["by_deprecated_type"][0]["recommendation"]
        self.assertEqual(
            [item["mechanism"] for item in recommendation["recommended"]],
            ["java.util.concurrent executor", "main-thread Handler or runOnUiThread"],
        )
        self.assertEqual(recommendation["uncovered_requirements"], [])
        rejected = {item["mechanism"]: item for item in recommendation["not_recommended"]}
        self.assertIn("serial_execution", rejected["project background-thread helper"]["missing"])
        self.assertTrue(rejected["project background-thread helper"]["caveats"])

    def test_the_contract_carries_what_each_invariant_requires(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = gallery_like(root)
            result = deprecated_usage_contract(root, finding, source_file_path=TASK)
        requires = {item["when"]: item["requires"] for item in result["contracts"][0]["invariants"]}
        self.assertEqual(requires["onPostExecute"], ["main_thread_dispatch"])
        self.assertIn("isolated_interrupts", requires["cancel"])


class UsageContractTests(unittest.TestCase):
    def test_subclass_callbacks_and_every_start_and_cancel_are_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = gallery_like(root)
            result = deprecated_usage_contract(root, finding)
        contract = result["contracts"][0]
        self.assertEqual(contract["subclasses"][0]["name"], "GetMediaAsynctask")
        self.assertEqual(contract["subclasses"][0]["overridden_members"],
                         ["doInBackground", "onPostExecute"])
        self.assertEqual(contract["members_called"].get("stopFetching"), 2)
        self.assertEqual(contract["members_called"].get("execute"), 1)
        self.assertEqual(contract["production_files"], sorted([ACTIVITY, TASK]))
        self.assertEqual(contract_files(result), sorted([ACTIVITY, TASK]))

    def test_the_documented_behaviour_of_what_the_code_uses_is_attached(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = gallery_like(root)
            result = deprecated_usage_contract(root, finding, source_file_path=TASK)
        whens = {item["when"] for item in result["contracts"][0]["invariants"]}
        # execute() is called by SearchActivity, doInBackground/onPostExecute
        # are overridden, and cancel(true) is called unqualified inside
        # stopFetching(); executeOnExecutor is used nowhere.
        self.assertTrue({"execute", "doInBackground", "onPostExecute", "cancel"} <= whens)
        self.assertNotIn("executeOnExecutor", whens)
        serial = next(item for item in result["contracts"][0]["invariants"]
                      if item["when"] == "execute" and "one at a time" in item["invariant"])
        self.assertTrue(serial["source"].startswith("https://developer.android.com/"))

    def test_the_reported_subclass_bounds_the_scope_and_its_callbacks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = gallery_like(root)
            # A second class after the task in the same file, and a second
            # AsyncTask subclass elsewhere that is a separate finding.
            write(root, TASK, TASK_KT + "\nobject Ticker : Runnable {\n    override fun run() {}\n}\n")
            write(root, "app/src/main/java/org/example/MapFragment.java",
                  "public class MapFragment {\n"
                  "    private class LoaderTask extends AsyncTask<Void, Void, Void> {\n"
                  "        @Override\n        protected Void doInBackground(Void... v) { return null; }\n"
                  "    }\n"
                  "    void load() { new LoaderTask().execute(); }\n"
                  "    String tag() { return GetMediaAsynctask.class.getSimpleName(); }\n"
                  "}\n")
            result = deprecated_usage_contract(root, finding, source_file_path=TASK)
        contract = result["contracts"][0]
        self.assertEqual([item["name"] for item in contract["subclasses"]], ["GetMediaAsynctask"])
        self.assertEqual(contract["subclasses"][0]["overridden_members"],
                         ["doInBackground", "onPostExecute"])
        self.assertEqual([item["name"] for item in contract["other_subclasses_not_in_scope"]],
                         ["LoaderTask"])
        self.assertNotIn("getSimpleName", contract["members_called"])
        self.assertEqual(contract["members_called"].get("execute"), 1)
        self.assertIn(ACTIVITY, contract["production_files"])

    def test_a_local_broadcast_sender_and_its_receivers_are_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "app/src/main/java/org/example/SimChangeReceiver.java",
                  "import androidx.localbroadcastmanager.content.LocalBroadcastManager;\n"
                  "public class SimChangeReceiver extends BroadcastReceiver {\n"
                  "    @Override\n"
                  "    public void onReceive(Context context, Intent intent) {\n"
                  "        LocalBroadcastManager.getInstance(context).sendBroadcast(simIntent);\n"
                  "    }\n}\n")
            write(root, "app/src/main/java/org/example/MainActivity.java",
                  "public class MainActivity {\n"
                  "    void onResume() {\n"
                  "        LocalBroadcastManager.getInstance(this).registerReceiver(receiver, filter);\n"
                  "    }\n"
                  "    void onPause() {\n"
                  "        LocalBroadcastManager.getInstance(this).unregisterReceiver(receiver);\n"
                  "    }\n}\n")
            finding = {**parse_finding_message(BROADCAST), "status": "confirmed"}
            result = deprecated_usage_contract(root, finding)
            sources = migration_contract_sources(str(root), result, set())
        members = result["contracts"][0]["members_called"]
        self.assertEqual(members["getInstance"], 3)
        self.assertEqual(members["sendBroadcast"], 1)
        self.assertEqual(members["registerReceiver"], 1)
        self.assertEqual(members["unregisterReceiver"], 1)
        self.assertEqual(len(sources), 2)
        self.assertIn("LocalBroadcastManager", sources[0]["content"])


class DependencyInventoryTests(unittest.TestCase):
    CATALOG = (
        "[versions]\nrxJava = \"2.2.9\"\n\n[libraries]\n"
        "rxjava = { module = \"io.reactivex.rxjava2:rxjava\", version.ref = \"rxJava\" }\n"
    )

    def test_imports_are_counted_through_the_group_parent_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, "gradle/libs.versions.toml", self.CATALOG)
            write(root, "app/build.gradle", "dependencies { implementation libs.rxjava }\n")
            for name in ("A", "B", "C"):
                write(root, f"app/src/main/java/org/example/{name}.java",
                      "import io.reactivex.Observable;\nimport io.reactivex.schedulers.Schedulers;\n"
                      f"class {name} {{}}\n")
            write(root, "app/src/test/java/org/example/ATest.java",
                  "import io.reactivex.plugins.RxJavaPlugins;\nclass ATest {}\n")
            result = collect_dependency_finding(root, RXJAVA, "app/src/main/java/org/example/A.java")
        inventory = result["usage_inventory"]
        self.assertIn("io.reactivex", inventory["package_prefixes"])
        self.assertEqual(inventory["production_files"], 3)
        self.assertEqual(inventory["test_files"], 1)
        self.assertEqual(inventory["import_lines"], 7)
        self.assertEqual(result["migration_scale"], "bounded")
        self.assertEqual(result["effective_resolution"]["status"], "unavailable")

    def test_a_parent_shared_with_another_library_is_not_used(self):
        parsed = parse_finding_message("Using okhttp3 v3.12.0. Update to v4.10.0 or higher.")
        matched = [{"group": "com.squareup.okhttp3", "artifact": "okhttp"}]
        declarations = [*matched, {"group": "com.squareup.retrofit2", "artifact": "retrofit"}]
        self.assertEqual(package_prefixes(parsed, matched, declarations), ["com.squareup.okhttp3"])

    def test_migration_scale(self):
        self.assertEqual(migration_scale("major", {"production_files": 182}), "large")
        self.assertEqual(migration_scale("major", {"production_files": 3}), "bounded")
        self.assertEqual(migration_scale("minor", {"production_files": 182}), "not_a_major_change")

    def test_effective_resolution_reads_the_resolved_graph(self):
        graph = {"status": "available", "nodes": [
            {"group": "io.reactivex.rxjava2", "artifact": "rxjava", "version_expression": "2.2.21",
             "direct": False, "dependency_path": ["io.reactivex.rxjava2:rxandroid", "io.reactivex.rxjava2:rxjava"]},
            {"group": "com.other", "artifact": "lib", "version_expression": "1.0"},
        ]}
        matched = [{"group": "io.reactivex.rxjava2", "artifact": "rxjava"}]
        with mock.patch.object(dependency_finding, "resolve_dependency_graph", return_value=graph), \
                mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TCC_SKIP_GRADLE_RESOLUTION", None)
            result = dependency_finding.effective_resolution(Path("."), matched)
        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["selected"][0]["version"], "2.2.21")
        self.assertEqual(dependency_finding.effective_resolution(Path("."), []),
                         {"status": "not_applicable"})


class PromotionTests(unittest.TestCase):
    def _error(self, files=(TASK, ACTIVITY), mechanisms=True):
        return {
            "source_file_path": TASK,
            "dependency_finding": {"kind": "api_migration", "status": "confirmed"},
            "repository_replacement_idioms": {"status": "found", "by_deprecated_type": [{
                "deprecated_type": "android.os.AsyncTask",
                "mechanisms": [{"mechanism": "project background-thread helper",
                                "production_files": 25, "occurrences": 140}] if mechanisms else [],
            }]},
            "deprecated_usage_contract": {"status": "found", "contracts": [{
                "deprecated_type": "android.os.AsyncTask", "production_files": list(files),
            }]},
        }

    def _adjudication(self, blocker_kind="replacement_selection_and_platform_contract"):
        return {
            "cause_status": "confirmed", "detector_violation": "confirmed",
            "scope_status": "complete", "decision": "NO_SAFE_FIX",
            "decision_claim_ids": ["CLM-001"], "generation_status": "blocked",
            "publication_status": "blocked",
            "blocking_for_generation": [{"kind": blocker_kind, "description": "x",
                                         "supporting_claim_ids": ["CLM-001"]}],
            "blocking_for_publication": [{"kind": "lifecycle", "description": "y",
                                          "supporting_claim_ids": ["CLM-001"],
                                          "discharged_by_pipeline_validation": False}],
            "authorized_behavior_change": {"authorized": False, "description": "", "policy_reference": ""},
            "review_assumptions": [],
        }

    def test_a_confirmed_grounded_migration_becomes_a_review_only_patch(self):
        adjudication = self._adjudication()
        record = promote_grounded_api_migration_review(self._error(), adjudication, {}, "api_migration")
        self.assertIsNotNone(record)
        self.assertEqual(adjudication["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(adjudication["generation_status"], "supported_for_review")
        self.assertEqual(adjudication["publication_status"], "blocked")
        self.assertEqual(adjudication["blocking_for_generation"], [])
        kinds = [item["kind"] for item in adjudication["blocking_for_publication"]]
        self.assertIn("replacement_selection_and_platform_contract", kinds)
        self.assertIn("runtime_behaviour_requires_human_review", kinds)
        self.assertTrue(adjudication["authorized_behavior_change"]["authorized"])
        self.assertTrue(adjudication["authorized_behavior_change"]["policy_reference"])

    def test_a_complete_recommendation_grounds_the_replacement(self):
        error = self._error(mechanisms=False)
        error["repository_replacement_idioms"]["by_deprecated_type"][0]["recommendation"] = {
            "requirements": ["serial_execution", "main_thread_dispatch"],
            "recommended": [
                {"mechanism": "java.util.concurrent executor", "production_files": 0},
                {"mechanism": "main-thread Handler or runOnUiThread", "production_files": 20},
            ],
            "uncovered_requirements": [],
        }
        adjudication = self._adjudication("replacement_semantics_unselected")
        record = promote_grounded_api_migration_review(error, adjudication, {}, "api_migration")
        self.assertIsNotNone(record)
        self.assertIn("java.util.concurrent executor", record["repository_mechanisms"])
        incomplete = self._error(mechanisms=False)
        incomplete["repository_replacement_idioms"]["by_deprecated_type"][0]["recommendation"] = {
            "recommended": [{"mechanism": "java.util.concurrent executor"}],
            "uncovered_requirements": ["main_thread_dispatch"],
        }
        self.assertIsNone(promote_grounded_api_migration_review(
            incomplete, self._adjudication(), {}, "api_migration"))

    def test_official_sources_alone_ground_the_replacement(self):
        adjudication = self._adjudication()
        research = {"externally_confirmed_facts": ["AsyncTask was deprecated in API level 30."]}
        self.assertIsNotNone(promote_grounded_api_migration_review(
            self._error(mechanisms=False), adjudication, research, "api_migration"))

    def test_what_is_never_promoted(self):
        cases = {
            "no grounding": (self._error(mechanisms=False), self._adjudication(), {}),
            "single file": (self._error(files=(TASK,)), self._adjudication(), {}),
            "deterministic failure": (self._error(), self._adjudication("deterministic_validation"), {}),
        }
        for name, (error, adjudication, research) in cases.items():
            with self.subTest(name):
                self.assertIsNone(promote_grounded_api_migration_review(
                    error, adjudication, research, "api_migration"))
                self.assertEqual(adjudication["decision"], "NO_SAFE_FIX")
        inferred = self._adjudication()
        inferred["cause_status"] = "inferred"
        self.assertIsNone(promote_grounded_api_migration_review(self._error(), inferred, {}, "api_migration"))
        dependency = self._adjudication()
        self.assertIsNone(promote_grounded_api_migration_review(
            {**self._error(), "dependency_finding": {"kind": "dependency_version"}},
            dependency, {}, "dependency"))


if __name__ == "__main__":
    unittest.main()
