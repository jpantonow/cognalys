import logging
import unittest


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.coordinated_generation import CoordinatedGeneration  # noqa: E402

PRODUCTION = {
    "source_file_path": "app/src/main/java/com/foss/aihub/ui/webview/WebChromeClient.kt",
    "edit_kind": "replace", "symbol": "onCreateWindow",
    "original_code": "mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW",
    "corrected_code": "mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW",
    "reason": "secure pages must not load insecure content",
}
NEW_TEST = "app/src/test/java/com/foss/aihub/ui/webview/WebViewMixedContentPolicyTest.kt"
TEST = {
    "source_file_path": NEW_TEST, "edit_kind": "create", "symbol": "WebViewMixedContentPolicyTest",
    "original_code": "",
    "corrected_code": 'val s = File("src/main/java/com/foss/aihub/ui/webview/WebChromeClient.kt")',
    "reason": "regression test",
}


class _Generator(CoordinatedGeneration):
    """Only what _without_rejected_new_tests touches."""

    def __init__(self):
        self.logger = logging.getLogger("dropped-generated-tests")
        self.pr_issue_style = "v1"


def _failed(code, path=NEW_TEST, edits=(PRODUCTION, TEST)):
    return {"status": "invalid", "stage": "semantic_validation", "manifest": "m.json",
            "semantic_validation": {"status": "invalid",
                                    "errors": [{"code": code, "path": path, "details": ["x"]}]},
            "edits": [dict(edit) for edit in edits], "required_tests": ["t"],
            "review_assumptions": []}


ERROR = {"repository_path": "", "method_name": "onCreateWindow", "spec": "WebViewMixedContentSpec",
         "source_file_path": PRODUCTION["source_file_path"],
         "evidence_analysis": {"confirmed_cause": "MIXED_CONTENT_ALWAYS_ALLOW"}}


class DroppedTestTests(unittest.TestCase):
    """AI Hub's onCreateWindow: a correct fix lost to a test that tested nothing."""

    def _salvage(self, failed, new_paths=(NEW_TEST,)):
        return _Generator()._without_rejected_new_tests(
            ERROR, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", failed, list(new_paths), [],
            "onCreateWindow")

    def test_the_production_change_ships_without_the_test(self):
        result = self._salvage(_failed("TEST_READS_PRODUCTION_SOURCE"))
        self.assertEqual(result["status"], "complete")
        self.assertEqual([edit["source_file_path"] for edit in result["edits"]],
                         [PRODUCTION["source_file_path"]])
        self.assertEqual(result["required_tests"], [])
        self.assertEqual(result["dropped_generated_tests"], [NEW_TEST])
        self.assertIn("no automated test", result["review_assumptions"][-1])

    def test_a_production_error_is_never_salvaged(self):
        self.assertIsNone(self._salvage(_failed("STORED_DERIVED_VALUE_CHANGED",
                                                path=PRODUCTION["source_file_path"])))

    def test_the_projects_own_tests_are_never_dropped(self):
        """Only a test file this patch created; never an edit to an existing one."""
        self.assertIsNone(self._salvage(_failed("TEST_ASSERTS_ONLY_CONSTANTS"), new_paths=()))

    def test_a_test_in_another_module_is_dropped(self):
        result = self._salvage(_failed("TEST_IN_OTHER_MODULE"))
        self.assertEqual(result["dropped_generated_tests"], [NEW_TEST])

    def test_a_visibility_widened_for_a_test_goes_with_that_test(self):
        """The production file is named, but the test is what made it an error."""
        failed = _failed("TEST_SEAM_VISIBILITY_WIDENED", path=PRODUCTION["source_file_path"])
        failed["semantic_validation"]["errors"][0]["test_paths"] = [NEW_TEST]
        result = self._salvage(failed)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["dropped_generated_tests"], [NEW_TEST])
        # A widening for one of the project's own tests is not salvaged.
        self.assertIsNone(self._salvage(failed, new_paths=()))

    def test_nothing_is_left_without_a_production_change(self):
        self.assertIsNone(self._salvage(_failed("TEST_READS_PRODUCTION_SOURCE", edits=(TEST,))))


MAIN = "src/main/java/a/Store.java"
STORE_TEST = "src/test/java/a/StoreTest.java"
STORE = ("package a;\nclass Store {\n    int load() { int value = 1; return value; }\n}\n")
STORE_TEST_SOURCE = ("package a;\n\nimport org.junit.Test;\nimport static org.junit.Assert.assertEquals;\n\n"
                     "public class StoreTest {\n    @Test\n    public void keepsTheStore() {\n"
                     "        assertEquals(2, new Store().load());\n    }\n}\n")


def _regression(path):
    return {"source_file_path": path, "scenario": "s", "before": "b", "after": "a"}


def _store_run(review):
    """One coordinated generation of Store.java plus the new StoreTest.java.

    ``review(prompt)`` answers each behaviour review. Returns the result,
    the review prompts, the number of test drafts and behavior_review.json.
    """
    import json
    import tempfile
    from pathlib import Path

    from cognalys.llm.generate_error_fixes import FixGenerator

    class Provider:
        def __init__(self):
            self.review_prompts, self.test_drafts = [], 0

        def generate(self, prompt, *args, **kwargs):
            if kwargs.get("schema_name") == "behavior_review":
                # The review is asked about the edits it is shown; the plan it
                # also reads (plan_required_edits, contract 19) names the test
                # file whether or not the draft still carries it.
                head, _, rest = prompt.partition("\n{")
                body, _, tail = rest.rpartition("}\n")
                payload = json.loads("{" + body + "}")
                payload.pop("plan_required_edits", None)
                prompt = head + "\n" + json.dumps(payload) + "\n" + tail
                self.review_prompts.append(prompt)
                return json.dumps(review(prompt))
            if f'"target_file":"{STORE_TEST}"' in prompt:
                self.test_drafts += 1
                edit = {"source_file_path": STORE_TEST, "edit_kind": "create",
                        "symbol": "StoreTest", "original_code": "",
                        "corrected_code": STORE_TEST_SOURCE, "reason": "test"}
            else:
                edit = {"source_file_path": MAIN, "edit_kind": "declaration", "symbol": "load",
                        "original_code": "int value = 1;", "corrected_code": "int value = 2;",
                        "reason": "r"}
            return json.dumps({
                "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                "source_file_path": edit["source_file_path"], "explanation": "e",
                "edits": [edit], "no_change_required": False, "provided_contracts": [],
                "required_contracts": [], "required_tests": ["StoreTest.keepsTheStore"],
                "manual_review_required": True, "review_assumptions": [], "confidence": "high"})

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "repo" / MAIN).parent.mkdir(parents=True)
        (root / "repo" / MAIN).write_text(STORE, encoding="utf-8")
        generator = object.__new__(FixGenerator)
        generator.output_dir = root / "out"
        generator.provider = Provider()
        generator.web_search = False
        generator.logger = logging.getLogger("test")
        error = {"repository_path": str(root / "repo"), "error_index": 0,
                 "source_file_path": MAIN, "method_name": "load",
                 "evidence_analysis": {"confirmed_cause": "cause", "coordinated_fix_plan": {
                     "required_edits": [
                         {"source_file_path": MAIN, "symbol": "load"},
                         {"source_file_path": STORE_TEST, "symbol": "StoreTest",
                          "create_new_file": True}]}}}
        result = generator.generate_coordinated_file_drafts(
            error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "load")
        written = root / "out/coordinated_drafts/app.apk/0_load/behavior_review.json"
        review_file = json.loads(written.read_text(encoding="utf-8")) if written.is_file() else {}
    return result, generator.provider, review_file


class RegressionOnlyInGeneratedTestTests(unittest.TestCase):
    """LocalSend's loadOrCreateKeyStore (2026-10-29): three reviews called the
    KeyStore change correct and found their only regression in the androidTest
    the draft created (a ContextWrapper(null) NPE); the whole change was lost."""

    CLEAN = {"regressions": [], "maintainer_decision_required": False,
             "maintainer_decision": "", "rationale": ""}

    def test_the_test_goes_and_the_draft_is_reviewed_again_without_it(self):
        def review(prompt):
            if STORE_TEST in prompt:
                return {**self.CLEAN, "regressions": [_regression(STORE_TEST)]}
            return self.CLEAN

        result, provider, review_file = _store_run(review)
        self.assertEqual(result["status"], "complete")
        self.assertEqual([edit["source_file_path"] for edit in result["edits"]], [MAIN])
        self.assertEqual(result["dropped_generated_tests"], [STORE_TEST])
        self.assertEqual(result["required_tests"], [])
        self.assertIn("fails on its own", result["dropped_generated_tests_reason"])
        # Regenerated with the scenario first; dropped only on the last attempt.
        self.assertEqual(provider.test_drafts, 3)
        # The draft that ships was reviewed: the result is current, not salvaged.
        self.assertNotIn(STORE_TEST, provider.review_prompts[-1])
        self.assertTrue(result["review_contract_version"])
        self.assertEqual(review_file["regressions"], [])
        self.assertIn("carries no automated test", result["review_assumptions"][-1])

    def test_the_fresh_review_checks_the_scenario_the_test_was_dropped_for(self):
        """Review (2026-10-29): the scenario the last review found through the
        test may be production's; without it, the fresh review never checks it."""
        reviews = []

        def review(prompt):
            reviews.append(prompt)
            if STORE_TEST in prompt:
                return {**self.CLEAN, "regressions": [{
                    **_regression(STORE_TEST),
                    "scenario": f"review {len(reviews)}: load() throws on a missing store"}]}
            return self.CLEAN

        result, provider, _ = _store_run(review)
        self.assertEqual(result["status"], "complete")
        last_with_test = len(provider.review_prompts) - 1
        self.assertIn(f"review {last_with_test}: load() throws on a missing store",
                      provider.review_prompts[-1])

    def test_plan_labelled_regressions_only_in_the_test_still_reach_the_drop(self):
        """Review of 9663308 (2026-11-09): LocalSend's plan required the
        androidTest, so a review may name the plan as the source of the
        test's regression; two such reviews must not replan before the last
        attempt drops the test."""
        from unittest import mock

        from cognalys.llm.generate_error_fixes import FixGenerator

        asked = []

        def review(prompt):
            if STORE_TEST in prompt:
                return {**self.CLEAN, "regressions": [{
                    **_regression(STORE_TEST), "source": "plan",
                    "source_reason": "the plan requires StoreTest"}]}
            return self.CLEAN

        def replan(generator, error, failures, *args, **kwargs):
            asked.append([item.get("regression_in_new_test") for item in failures])
            return False

        with mock.patch.object(FixGenerator, "replan_after_regressions", replan):
            result, provider, _ = _store_run(review)
        self.assertEqual(asked, [])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["dropped_generated_tests"], [STORE_TEST])
        self.assertEqual(provider.test_drafts, 3)

    def test_a_regression_the_fresh_review_finds_in_production_still_fails(self):
        """Review (2026-10-29): the test called the changed code, so its
        scenario may be production's; the review of the shipped draft decides."""
        def review(prompt):
            path = STORE_TEST if STORE_TEST in prompt else MAIN
            return {**self.CLEAN, "regressions": [_regression(path)]}

        result, _, review_file = _store_run(review)
        self.assertNotEqual(result["status"], "complete")
        self.assertEqual(result["issues"], ["UNINTENDED_BEHAVIOR_CHANGE"])
        self.assertEqual(result["semantic_validation"]["errors"][0]["affected_paths"], [MAIN])
        self.assertEqual(review_file["regressions"][0]["source_file_path"], MAIN)

    def test_a_regression_naming_production_never_drops_the_test(self):
        result, provider, _ = _store_run(
            lambda prompt: {**self.CLEAN, "regressions": [
                _regression(STORE_TEST), _regression(MAIN)]})
        self.assertNotEqual(result["status"], "complete")
        self.assertNotIn("dropped_generated_tests", result)
        self.assertTrue(all(STORE_TEST in prompt for prompt in provider.review_prompts))

    def test_a_rename_check_left_to_review_stays_left_once_the_test_goes(self):
        """Merge of 2026-10-29: the non-rename attempt leaves a stale name to
        review, and its only regression is in the generated test; the draft
        without the test is validated with the same demotion, not refused."""
        from unittest import mock
        from cognalys.llm import coordinated_generation

        named = {"code": "NAME_CONTRADICTS_BEHAVIOR", "path": MAIN, "name": "load",
                 "removed_behavior": "one", "details": ["load still states 'one'"]}
        real = coordinated_generation.validate_coordinated_semantics

        def validate(error, edits):
            result = real(error, edits)
            return {**result, "status": "invalid", "errors": [*result["errors"], named]}

        def review(prompt):
            if STORE_TEST in prompt:
                return {**self.CLEAN, "regressions": [_regression(STORE_TEST)]}
            return self.CLEAN

        with mock.patch.object(coordinated_generation, "validate_coordinated_semantics",
                               side_effect=validate):
            result, provider, _ = _store_run(review)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["dropped_generated_tests"], [STORE_TEST])
        self.assertNotIn(STORE_TEST, provider.review_prompts[-1])
        self.assertTrue(any(item.get("rename_check_left_to_review")
                            for item in result["semantic_validation"]["warnings"]))

    def test_only_new_test_files_holding_every_regression_qualify(self):
        from cognalys.llm.coordinated_generation import regressions_only_in_new_tests

        review = {"regressions": [_regression(STORE_TEST)]}
        self.assertEqual(regressions_only_in_new_tests(review, [STORE_TEST]), [STORE_TEST])
        # A project test, a production file, no file, or no regression at all.
        self.assertEqual(regressions_only_in_new_tests(review, []), [])
        self.assertEqual(regressions_only_in_new_tests(
            {"regressions": [_regression(MAIN)]}, [MAIN]), [])
        self.assertEqual(regressions_only_in_new_tests(
            {"regressions": [_regression("")]}, [STORE_TEST]), [])
        self.assertEqual(regressions_only_in_new_tests({"regressions": []}, [STORE_TEST]), [])


if __name__ == "__main__":
    unittest.main()
