import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.config.apply_solutions_config import ApplySolutionsConfig  # noqa: E402
from cognalys.llm.research_questions import verified_detector_semantics  # noqa: E402
from cognalys.solutions.solution_applicator import SolutionApplicator  # noqa: E402
from cognalys.solutions.solution_mapper import SolutionMapper  # noqa: E402
from cognalys.validation import applied_solutions as vas  # noqa: E402

APP_BUILD = """plugins {
    id("com.android.application")
}
android {
    flavorDimensions += "store"
    productFlavors {
        create("intern") { dimension = "store" }
        create("extern") { dimension = "store" }
    }
}
dependencies {
    implementation(project(":licensing"))
}
"""


def _write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class ProductionBuildTaskTests(unittest.TestCase):
    """A flavored app builds one variant, as long as that compiles the patch."""

    def _project(self, root: Path) -> Path:
        _write(root, "settings.gradle.kts", 'include(":app", ":licensing", ":other")\n')
        _write(root, "build.gradle.kts",
               'plugins { id("com.android.application") version "8.0" apply false }\n')
        _write(root, "app/build.gradle.kts", APP_BUILD)
        _write(root, "licensing/build.gradle", "apply plugin: 'com.android.library'\n")
        _write(root, "other/build.gradle", "apply plugin: 'com.android.library'\n")
        return root

    def test_one_flavored_application_module_builds_one_variant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._project(Path(directory))
            self.assertEqual(
                vas.production_build_tasks(root, "debug", ["app/src/main/A.kt"]),
                [":app:assembleExternDebug"],
            )

    def test_an_edit_in_a_module_the_app_depends_on_is_still_compiled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._project(Path(directory))
            self.assertEqual(
                vas.production_build_tasks(root, "debug", ["licensing/src/L.java"]),
                [":app:assembleExternDebug"],
            )

    def test_an_edit_in_a_module_the_app_does_not_use_builds_everything(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._project(Path(directory))
            self.assertIsNone(
                vas.production_build_tasks(root, "debug", ["other/src/O.java"]))

    def test_a_project_without_flavors_keeps_the_plain_task(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(root, "settings.gradle", "include ':app'\n")
            _write(root, "app/build.gradle", "apply plugin: 'com.android.application'\n")
            self.assertIsNone(vas.production_build_tasks(root, "debug", []))

    def test_a_settings_file_one_level_down_is_the_gradle_root(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            self._project(project / "Android")
            self.assertEqual(
                vas.production_build_tasks(project, "debug", []),
                [":app:assembleExternDebug"],
            )


class TimeoutAttributionTests(unittest.TestCase):
    def test_a_build_timeout_is_not_blamed_on_the_patch(self):
        self.assertFalse(vas.failure_is_the_patch(
            {"status": "timeout", "failure_attribution": "build_timeout"}))


class NonSecurityViolationShapeTests(unittest.TestCase):
    def test_the_shapes_reach_the_rule_semantics_apart_from_false_positives(self):
        semantics = verified_detector_semantics({
            "source_verified": True, "spec_id": "S", "events": [],
            "known_false_positive_shapes": ["misread"],
            "non_security_violation_shapes": ["MD5 as a cache key"],
            # Reviewed, so its shapes are the rule's known false positives.
            "generation_evidence": {
                "false_positive_shape_review": {"version": 1, "moved": []}},
        })
        self.assertEqual(semantics["known_false_positive_shapes"], ["misread"])
        self.assertEqual(
            semantics["non_security_violation_shapes"], ["MD5 as a cache key"])


class RebaseOntoBaseTests(unittest.TestCase):
    """Edits written against the analysed revision, merged onto a moved base."""

    METHOD = (
        "    fun context(): Context {\n"
        "        // build the context\n"
        "        log(\"start\")\n"
        "        return get(\"SSL\")\n"
        "    }\n"
    )
    ANALYSED = "class A {\n" + METHOD + "}\n"

    def _git(self, root: Path, *args: str) -> str:
        return subprocess.run(["git", "-C", str(root), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def _apply(self, base_text: str):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clone = root / "clone"
            clone.mkdir()
            self._git(clone, "init", "-q")
            self._git(clone, "config", "user.email", "t@example.com")
            self._git(clone, "config", "user.name", "t")
            _write(clone, "A.kt", self.ANALYSED)
            self._git(clone, "add", "-A")
            self._git(clone, "commit", "-q", "-m", "analysed")
            worktree = root / "worktree"
            _write(worktree, "A.kt", base_text)
            applicator = SolutionApplicator(ApplySolutionsConfig(
                error_solutions_dir=str(root / "s"), cloned_projects_dir=str(root),
                output_dir=str(root / "r"), worktrees_dir=str(root / "w"),
                save_backups=False,
            ))
            solution = {"fix_scope": "dependency", "coordinated_edits": [{
                "source_file_path": "A.kt", "symbol": "context", "edit_kind": "method",
                "original_code": self.METHOD,
                "corrected_code": self.METHOD.replace('"SSL"', '"TLSv1.3"'),
                "reason": "pin the protocol",
            }]}
            mapper = SolutionMapper(str(root / "s"), str(root))
            ok, _, error = applicator._apply_coordinated_edits(solution, mapper, worktree)
            rebased = None if ok else applicator._apply_rebased_coordinated_edits(
                solution, mapper, worktree, clone)
            return ok, error, rebased, (worktree / "A.kt").read_text(encoding="utf-8")

    def test_an_edit_whose_neighbourhood_moved_is_merged_onto_the_base(self):
        base = self.ANALYSED.replace("// build the context", "// build the TLS context")
        ok, error, rebased, text = self._apply(base)
        self.assertFalse(ok)
        self.assertTrue(error.startswith("ORIGINAL_CODE_NOT_FOUND"))
        self.assertIsNotNone(rebased)
        self.assertTrue(rebased[0]["rebased_onto_base"])
        self.assertIn('return get("TLSv1.3")', text)
        self.assertIn("// build the TLS context", text)

    def test_a_conflicting_change_on_the_base_leaves_the_worktree_alone(self):
        base = self.ANALYSED.replace('return get("SSL")', "return getDefault()")
        _, _, rebased, text = self._apply(base)
        self.assertIsNone(rebased)
        self.assertEqual(text, base)


KMP_FRAMEWORK_BUILD = """plugins {
    kotlin("multiplatform")
    id("com.android.library")
}
kotlin {
    androidTarget()
    sourceSets {
        androidUnitTest.dependencies { implementation("junit:junit:4.13.2") }
    }
}
"""
FRAMEWORK_CLIENT = "framework/src/androidMain/kotlin/com/fread/GlobalOkHttpClient.kt"


class KotlinMultiplatformTestPlacementTests(unittest.TestCase):
    """Fread (2026-10-15): framework's androidUnitTest set was invisible, so the
    only test root offered was plugins/bluesky's and its task built the test."""

    def _repository(self, directory: str) -> Path:
        root = Path(directory)
        _write(root, "settings.gradle.kts", 'include(":framework", ":plugins:x")\n')
        _write(root, "framework/build.gradle.kts", KMP_FRAMEWORK_BUILD)
        _write(root, FRAMEWORK_CLIENT, "package com.fread\n")
        _write(root, "framework/src/androidUnitTest/kotlin/com/fread/ExistingTest.kt",
               "package com.fread\n")
        _write(root, "plugins/x/build.gradle.kts", 'plugins { id("com.android.library") }\n')
        _write(root, "plugins/x/src/test/kotlin/com/x/XTest.kt", "package com.x\n")
        return root

    def test_only_the_production_modules_unit_root_is_offered(self):
        from cognalys.extraction.test_classpath import module_test_classpath
        from cognalys.llm.semantic_validation import repository_test_source_roots
        from cognalys.utils.test_source_sets import test_roots_for_production

        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            roots = repository_test_source_roots(str(root))
            self.assertEqual(roots, ["framework/src/androidUnitTest/kotlin",
                                     "plugins/x/src/test/kotlin"])
            offered = test_roots_for_production(roots, FRAMEWORK_CLIENT)
            self.assertEqual(offered, ["framework/src/androidUnitTest/kotlin"])
            classpath = module_test_classpath(str(root), offered)
            self.assertEqual(classpath["module_build_file"], "framework/build.gradle.kts")
            self.assertIn("junit:junit", classpath["declared_dependencies"])

    def test_common_code_also_gets_common_test(self):
        from cognalys.utils.test_source_sets import test_roots_for_production

        roots = ["framework/src/androidUnitTest/kotlin", "framework/src/commonTest/kotlin",
                 "framework/src/jvmTest/kotlin", "plugins/x/src/test/kotlin"]
        self.assertEqual(
            test_roots_for_production(roots, "framework/src/commonMain/kotlin/A.kt"),
            ["framework/src/androidUnitTest/kotlin", "framework/src/commonTest/kotlin"])
        self.assertEqual(test_roots_for_production(roots, FRAMEWORK_CLIENT),
                         ["framework/src/androidUnitTest/kotlin"])
        # Code the APK never contains has no test root to offer.
        self.assertEqual(test_roots_for_production(roots, "framework/src/jvmMain/kotlin/A.kt"), [])

    def test_a_plain_android_module_keeps_its_unit_test_root(self):
        from cognalys.utils.test_source_sets import test_roots_for_production

        roots = ["app/src/androidTest/java", "app/src/test/java", "lib/src/test/java"]
        self.assertEqual(
            test_roots_for_production(roots, "app/src/main/java/org/example/A.java"),
            ["app/src/test/java"])
        # A path with no src/<set>/ layout keeps every root, as before.
        self.assertIsNone(test_roots_for_production(roots, "A.java"))

    def test_a_new_test_in_another_module_is_a_test_error(self):
        from cognalys.llm.semantic_validation import tests_in_other_modules

        production = {"source_file_path": FRAMEWORK_CLIENT, "edit_kind": "method",
                      "original_code": "a", "corrected_code": "b"}
        elsewhere = {"source_file_path": "plugins/x/src/test/kotlin/com/fread/ClientTest.kt",
                     "edit_kind": "create", "original_code": "", "corrected_code": "class T"}
        issues = tests_in_other_modules({}, [production, elsewhere])
        self.assertEqual([issue["code"] for issue in issues], ["TEST_IN_OTHER_MODULE"])
        self.assertEqual(issues[0]["path"], elsewhere["source_file_path"])
        own = dict(elsewhere, source_file_path=(
            "framework/src/androidUnitTest/kotlin/com/fread/ClientTest.kt"))
        self.assertEqual(tests_in_other_modules({}, [production, own]), [])

    def test_a_plan_creating_a_test_in_another_module_is_invalid(self):
        from cognalys.llm.semantic_validation import _validate_patch_plan

        packet = {"evidence_catalog": [{
            "trust_level": "repository_exact_source",
            "data": {"source_file_path": FRAMEWORK_CLIENT},
        }]}
        adjudication = {"decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                        "generation_status": "supported_for_review",
                        "_validated_claims": [{"claim_id": "C-001"}]}

        def plan(test_path):
            return {"decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "required_edits": [
                {"source_file_path": FRAMEWORK_CLIENT, "supporting_claim_ids": ["C-001"]},
                {"source_file_path": test_path, "create_new_file": True,
                 "supporting_claim_ids": ["C-001"]},
            ]}
        roots = ["framework/src/androidUnitTest/kotlin", "plugins/x/src/test/kotlin"]
        other = _validate_patch_plan(
            plan("plugins/x/src/test/kotlin/com/fread/ClientTest.kt"), packet, adjudication, roots)
        self.assertTrue(any("in module 'plugins/x'" in issue for issue in other), other)
        self.assertEqual(_validate_patch_plan(
            plan("framework/src/androidUnitTest/kotlin/com/fread/ClientTest.kt"),
            packet, adjudication, roots), [])

    def test_the_build_runs_the_modules_own_unit_test_task(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            _write(root, "shared/build.gradle.kts",
                   'plugins { id("com.android.kotlin.multiplatform.library") }\n')
            paths = ["framework/src/androidUnitTest/kotlin/com/fread/ClientTest.kt",
                     "shared/src/commonTest/kotlin/S.kt",
                     "framework/src/androidInstrumentedTest/kotlin/com/fread/D.kt"]
            android, unit = vas.changed_test_modules(paths)
            self.assertEqual((android, unit), ({"framework"}, {"framework", "shared"}))
            tasks = vas.changed_unit_test_tasks(root, paths)
            self.assertEqual(tasks, {"framework": ["testDebugUnitTest"],
                                     "shared": ["testAndroidHostTest"]})
            self.assertEqual(
                vas.module_test_task(root, root, "shared", tasks["shared"][0]),
                ":shared:testAndroidHostTest")
            self.assertTrue(vas.is_test_source(paths[0]))
            self.assertFalse(vas.is_test_source(FRAMEWORK_CLIENT))


class TestSeamVisibilityTests(unittest.TestCase):
    """A declaration made public only so a test can reach it is a production error."""

    ORIGINAL = "    fun buildSSLFactory(): SSLSocketFactory {\n        return f()\n    }\n}\n"

    def _issues(self, declaration: str, test_code: str = "ProtocolFilteringSSLSocketFactory(x)"):
        from cognalys.llm.semantic_validation import test_seam_visibility

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(root, FRAMEWORK_CLIENT,
                   "package com.fread\n\nobject GlobalOkHttpClient {\n" + self.ORIGINAL)
            corrected = (
                "    fun buildSSLFactory(): SSLSocketFactory {\n"
                "        return ProtocolFilteringSSLSocketFactory(f())\n    }\n}\n\n"
                + declaration + " ProtocolFilteringSSLSocketFactory(d: SSLSocketFactory) {\n}\n"
            )
            edits = [
                {"source_file_path": FRAMEWORK_CLIENT, "edit_kind": "method",
                 "original_code": self.ORIGINAL, "corrected_code": corrected},
                {"source_file_path": "framework/src/androidUnitTest/kotlin/com/fread/PTest.kt",
                 "edit_kind": "create", "original_code": "", "corrected_code": test_code},
            ]
            return test_seam_visibility({"repository_path": str(root)}, edits)

    def test_a_public_top_level_class_used_only_by_a_test_is_flagged(self):
        for declaration in ("public class", "class"):
            issues = self._issues(declaration)
            self.assertEqual([issue["code"] for issue in issues],
                             ["TEST_SEAM_VISIBILITY_WIDENED"], declaration)
            self.assertEqual(issues[0]["path"], FRAMEWORK_CLIENT)
            self.assertEqual(issues[0]["test_paths"],
                             ["framework/src/androidUnitTest/kotlin/com/fread/PTest.kt"])

    def test_an_internal_class_or_one_no_test_uses_is_not_flagged(self):
        self.assertEqual(self._issues("internal class"), [])
        self.assertEqual(self._issues("class", test_code="assertTrue(true)"), [])


if __name__ == "__main__":
    unittest.main()
