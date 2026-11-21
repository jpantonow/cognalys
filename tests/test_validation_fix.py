import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (src/ on sys.path)


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "cognalys" / "validation" / "repair.py"
SPEC = importlib.util.spec_from_file_location("repair_validation_failures", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class UnresolvedImportRepairTests(unittest.TestCase):
    """Gallery's patch imported ensureBackgroundThread from the wrong package.

    The repair deleted that import and was rejected for the empty
    replacement, and it could not have known the right package: nothing told
    it how the rest of the repository imports the symbol.
    """

    def _worktree(self, root: Path) -> Path:
        broken = root / "app/src/main/kotlin/org/example/Task.kt"
        broken.parent.mkdir(parents=True)
        broken.write_text(
            "package org.example\n\n"
            "import org.example.commons.extensions.ensureBackgroundThread\n\n"
            "class Task { fun start() { ensureBackgroundThread { } } }\n",
            encoding="utf-8",
        )
        for name in ("A", "B"):
            (root / f"app/src/main/kotlin/org/example/{name}.kt").write_text(
                "package org.example\n\n"
                "import org.example.commons.helpers.ensureBackgroundThread\n\n"
                f"class {name} {{ fun go() {{ ensureBackgroundThread {{ }} }} }}\n",
                encoding="utf-8",
            )
        return broken

    def test_the_repositorys_own_import_of_an_unresolved_symbol_is_supplied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            hints = MODULE.unresolved_symbol_imports(
                root,
                [{"message": "Unresolved reference 'ensureBackgroundThread'.",
                  "source_line": "ensureBackgroundThread {"}],
                {"app/src/main/kotlin/org/example/Task.kt"},
            )
        self.assertEqual(hints, [{
            "symbol": "ensureBackgroundThread",
            "imports": [{"import": "import org.example.commons.helpers.ensureBackgroundThread",
                         "files": 2}],
        }])

    def test_a_java_cannot_find_symbol_diagnostic_is_read_too(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src/Other.java").write_text(
                "import com.example.util.Strings;\nclass Other {}\n", encoding="utf-8",
            )
            hints = MODULE.unresolved_symbol_imports(
                root, [{"message": "cannot find symbol\n  symbol:   class Strings"}], set(),
            )
        self.assertEqual(hints[0]["imports"][0]["import"], "import com.example.util.Strings")

    def test_deleting_a_wrong_import_line_is_a_valid_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            broken = self._worktree(root)
            relative = "app/src/main/kotlin/org/example/Task.kt"
            ok, edits, error = MODULE.validate_and_apply(root, {
                "decision": "REPAIR",
                "edits": [
                    {"source_file_path": relative, "symbol": "imports",
                     "original_code": "import org.example.commons.extensions.ensureBackgroundThread\n",
                     "corrected_code": "", "reason": "wrong package"},
                    {"source_file_path": relative, "symbol": "imports",
                     "original_code": "package org.example\n\n",
                     "corrected_code": "package org.example\n\nimport org.example.commons.helpers.ensureBackgroundThread\n",
                     "reason": "the repository's import"},
                ],
            }, {relative}, False)
            self.assertTrue(ok, error)
            text = broken.read_text(encoding="utf-8")
            self.assertNotIn("commons.extensions", text)
            self.assertIn("import org.example.commons.helpers.ensureBackgroundThread", text)
            self.assertEqual(len(edits), 2)

    def test_a_repair_that_deletes_a_test_annotation_is_rejected(self):
        # HomeApp's test compiled once @Test was gone, and ran nothing.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = "app/src/test/java/app/SslTest.kt"
            test_file = root / relative
            test_file.parent.mkdir(parents=True)
            source = (
                "package app\n\nimport kotlin.test.Test\n\n"
                "class SslTest {\n    @Test\n    fun cancels() {}\n}\n"
            )
            test_file.write_text(source, encoding="utf-8")
            ok, _edits, error = MODULE.validate_and_apply(root, {
                "decision": "REPAIR",
                "edits": [
                    {"source_file_path": relative, "symbol": "Test",
                     "original_code": "import kotlin.test.Test\n",
                     "corrected_code": "", "reason": "unresolved"},
                    {"source_file_path": relative, "symbol": "Test",
                     "original_code": "    @Test\n",
                     "corrected_code": "", "reason": "unresolved"},
                ],
            }, {relative}, False)
            self.assertFalse(ok)
            self.assertIn("repair_removes_test_cases", error)
            self.assertEqual(test_file.read_text(encoding="utf-8"), source)

    def test_swapping_the_test_annotation_import_is_still_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = "app/src/test/java/app/SslTest.kt"
            test_file = root / relative
            test_file.parent.mkdir(parents=True)
            test_file.write_text(
                "package app\n\nimport kotlin.test.Test\n\n"
                "class SslTest {\n    @Test\n    fun cancels() {}\n}\n",
                encoding="utf-8",
            )
            ok, _edits, error = MODULE.validate_and_apply(root, {
                "decision": "REPAIR",
                "edits": [{"source_file_path": relative, "symbol": "Test",
                           "original_code": "import kotlin.test.Test\n",
                           "corrected_code": "import org.junit.Test\n",
                           "reason": "junit is declared"}],
            }, {relative}, False)
            self.assertTrue(ok, error)

    def test_emptying_a_whole_file_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            broken = self._worktree(root)
            relative = "app/src/main/kotlin/org/example/Task.kt"
            ok, _edits, error = MODULE.validate_and_apply(root, {
                "decision": "REPAIR",
                "edits": [{"source_file_path": relative, "symbol": "Task",
                           "original_code": broken.read_text(encoding="utf-8"),
                           "corrected_code": "", "reason": "drop it"}],
            }, {relative}, False)
        self.assertFalse(ok)
        self.assertIn("file_deletion_not_allowed", error)


class OccurrenceContractTests(unittest.TestCase):
    """run_20260914_141852: identical calls in a test could not be repaired.

    The exact-once contract rejected the only faithful edit, and a block the
    model assembled from separate locations was reported as "not unique"
    when it did not occur at all.
    """

    SOURCE = (
        "class T {\n"
        "    void a() {\n"
        "        send(new Intent(Old.ACTION));\n"
        "    }\n"
        "    void b() {\n"
        "        send(new Intent(Old.ACTION));\n"
        "    }\n"
        "}\n"
    )
    RELATIVE = "app/src/test/T.java"

    def _apply(self, directory: str, edit: dict):
        root = Path(directory)
        source = root / self.RELATIVE
        source.parent.mkdir(parents=True)
        source.write_text(self.SOURCE, encoding="utf-8")
        result = MODULE.validate_and_apply(root, {
            "decision": "REPAIR",
            "edits": [dict(
                {"source_file_path": self.RELATIVE, "symbol": "T",
                 "reason": "unavailable constant"},
                **edit,
            )],
        }, {self.RELATIVE}, False)
        return result, source.read_text(encoding="utf-8")

    def test_declared_occurrences_replace_every_identical_block(self):
        with tempfile.TemporaryDirectory() as directory:
            (ok, edits, error), text = self._apply(directory, {
                "original_code": "new Intent(Old.ACTION)",
                "corrected_code": "new Intent(\"action\")",
                "occurrences": 2,
            })
        self.assertTrue(ok, error)
        self.assertNotIn("Old.ACTION", text)
        self.assertEqual(text.count("new Intent(\"action\")"), 2)
        self.assertEqual(edits[0]["occurrences"], 2)

    def test_a_repeated_block_declared_once_is_refused_with_its_count(self):
        with tempfile.TemporaryDirectory() as directory:
            (ok, _edits, error), text = self._apply(directory, {
                "original_code": "new Intent(Old.ACTION)",
                "corrected_code": "new Intent(\"action\")",
                "occurrences": 1,
            })
        self.assertFalse(ok)
        self.assertEqual(
            error, "original_not_unique:app/src/test/T.java:expected=1:found=2")
        self.assertEqual(text, self.SOURCE)

    def test_a_block_joined_from_separate_locations_is_not_found(self):
        with tempfile.TemporaryDirectory() as directory:
            (ok, _edits, error), text = self._apply(directory, {
                "original_code": (
                    "send(new Intent(Old.ACTION));\n\n"
                    "send(new Intent(Old.ACTION));"
                ),
                "corrected_code": "send(new Intent(\"action\"));",
                "occurrences": 1,
            })
        self.assertFalse(ok)
        self.assertEqual(error, "original_not_found:app/src/test/T.java")
        self.assertEqual(text, self.SOURCE)

    def test_a_wrong_declared_count_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            (ok, _edits, error), _text = self._apply(directory, {
                "original_code": "new Intent(Old.ACTION)",
                "corrected_code": "new Intent(\"action\")",
                "occurrences": 3,
            })
        self.assertFalse(ok)
        self.assertTrue(error.startswith("occurrence_count_mismatch:"))

    def test_an_edit_without_a_count_keeps_the_exact_once_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            (ok, _edits, error), _text = self._apply(directory, {
                "original_code": "    void a() {\n        send(new Intent(Old.ACTION));",
                "corrected_code": "    void a() {\n        send(new Intent(\"action\"));",
            })
        self.assertTrue(ok, error)


class RepairCorrectionTests(unittest.TestCase):
    """A repair rejected while applying gets one correction, not the end."""

    def test_the_application_error_goes_back_for_one_correction(self):
        import cognalys.validation.repair as repair
        relative = "app/src/test/T.java"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worktree = root / "worktree"
            source = worktree / relative
            source.parent.mkdir(parents=True)
            source.write_text(OccurrenceContractTests.SOURCE, encoding="utf-8")
            report_path = root / "execution_report.json"
            report_path.write_text(json.dumps({"per_solution_details": [{
                "status": "SUCCESS", "finding_id": "abc", "apk_name": "x.apk",
                "worktree_path": str(worktree),
                "build_validation": {
                    "status": "failed",
                    "failure_attribution": "generated_patch",
                    "compiler_diagnostics": [{
                        "path": str(source), "line": 3,
                        "message": "cannot find symbol",
                        "source_line": "send(new Intent(Old.ACTION));",
                    }],
                },
            }]}), encoding="utf-8")
            joined = {
                "decision": "REPAIR", "explanation": "unavailable constant",
                "remaining_uncertainties": [],
                "edits": [{
                    "source_file_path": relative, "symbol": "T",
                    "original_code": (
                        "send(new Intent(Old.ACTION));\n\n"
                        "send(new Intent(Old.ACTION));"
                    ),
                    "occurrences": 1,
                    "corrected_code": "send(new Intent(\"action\"));",
                    "reason": "use the accepted action",
                }],
            }
            counted = dict(joined, edits=[dict(
                joined["edits"][0],
                original_code="new Intent(Old.ACTION)",
                corrected_code="new Intent(\"action\")",
                occurrences=2,
            )])
            calls = []

            class FakeProvider:
                def __init__(self, **_kwargs):
                    pass

                def generate(self, prompt, _system, **kwargs):
                    calls.append((prompt, kwargs.get("trace_stage")))
                    return json.dumps(joined if len(calls) == 1 else counted)

            argv = ["repair", "--execution-report", str(report_path),
                    "--output-dir", str(root / "out")]
            with patch.object(repair, "OpenAIProvider", FakeProvider), \
                    patch.object(repair, "commit_repair", return_value="c0ffee"), \
                    patch.object(repair, "_verified_imports", return_value=[]), \
                    patch.object(sys, "argv", argv):
                code = repair.main()
            artifact = json.loads(
                (root / "out" / "abc_validation_fix.json").read_text(encoding="utf-8"))
            text = source.read_text(encoding="utf-8")

        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][1], "validation_fix.compiler_repair.correction")
        self.assertIn("original_not_found", calls[1][0])
        self.assertEqual(artifact["status"], "success")
        self.assertEqual(
            artifact["rejected_attempts"][0]["error"],
            "original_not_found:app/src/test/T.java",
        )
        self.assertNotIn("Old.ACTION", text)

    def test_the_correction_budget_is_bounded(self):
        import cognalys.validation.repair as repair
        self.assertEqual(repair.MAX_REPAIR_CORRECTIONS, 1)


class ValidationFixTests(unittest.TestCase):
    def test_applies_only_exact_replacements_in_diagnosed_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app/src/androidTest/LegacyTest.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "class LegacyTest { void x() { Old.api(); } }\n",
                encoding="utf-8",
            )
            generated = {
                "decision": "REPAIR",
                "edits": [{
                    "source_file_path": "app/src/androidTest/LegacyTest.java",
                    "symbol": "LegacyTest.x",
                    "original_code": "Old.api();",
                    "corrected_code": "Current.api();",
                    "reason": "use current API",
                }],
            }
            ok, edits, error = MODULE.validate_and_apply(
                root, generated, {"app/src/androidTest/LegacyTest.java"}, False
            )
            self.assertTrue(ok, error)
            self.assertEqual(edits[0]["edit_kind"], "validation_repair")
            self.assertIn("Current.api()", source.read_text(encoding="utf-8"))

    def test_accepts_an_absolute_path_that_resolves_inside_the_diagnosed_file(self):
        # Reproduces a real repair failure: compiler_diagnostics() and the
        # payload built from it exposed both an absolute "path" and a
        # relative "source_file_path" for the same diagnostic, and the model
        # copied the absolute one into edits[].source_file_path. That is a
        # legitimate reference to the exact diagnosed file, not a path-safety
        # violation, and should not waste the whole repair attempt.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app/src/androidTest/LegacyTest.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "class LegacyTest { void x() { Old.api(); } }\n",
                encoding="utf-8",
            )
            generated = {
                "decision": "REPAIR",
                "edits": [{
                    "source_file_path": str(source.resolve()),
                    "symbol": "LegacyTest.x",
                    "original_code": "Old.api();",
                    "corrected_code": "Current.api();",
                    "reason": "use current API",
                }],
            }
            ok, edits, error = MODULE.validate_and_apply(
                root, generated, {"app/src/androidTest/LegacyTest.java"}, False
            )
            self.assertTrue(ok, error)
            self.assertEqual(
                edits[0]["source_file"], "app/src/androidTest/LegacyTest.java"
            )
            self.assertIn("Current.api()", source.read_text(encoding="utf-8"))

    def test_rejects_an_absolute_path_outside_the_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "worktree"
            root.mkdir()
            outside = Path(directory) / "outside" / "Evil.java"
            outside.parent.mkdir(parents=True)
            outside.write_text("class Evil {}\n", encoding="utf-8")
            ok, _edits, error = MODULE.validate_and_apply(root, {
                "decision": "REPAIR",
                "edits": [{
                    "source_file_path": str(outside.resolve()),
                    "symbol": "Evil", "original_code": "class Evil",
                    "corrected_code": "public class Evil", "reason": "shortcut",
                }],
            }, {"Evil.java"}, False)
            self.assertFalse(ok)
            self.assertIn("repair_outside_diagnosed_files", error)

    def test_rejects_edit_to_supporting_read_only_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app/src/main/Current.java"
            source.parent.mkdir(parents=True)
            source.write_text("class Current {}\n", encoding="utf-8")
            ok, _edits, error = MODULE.validate_and_apply(root, {
                "decision": "REPAIR",
                "edits": [{
                    "source_file_path": "app/src/main/Current.java",
                    "symbol": "Current", "original_code": "class Current",
                    "corrected_code": "public class Current", "reason": "shortcut",
                }],
            }, {"app/src/androidTest/LegacyTest.java"}, False)
            self.assertFalse(ok)
            self.assertIn("repair_outside_diagnosed_files", error)


class DiagnosedPathNormalizationTests(unittest.TestCase):
    """The diagnosed set and the edit guard must agree on path shape.

    In run_20260906_080507 the repair itself was correct -- the model read
    Schedule.java, saw the no-argument constructor and rewrote the test
    around it -- and was then discarded with
    repair_outside_diagnosed_files. relative_diagnostic_path returned the
    absolute path, because `worktree / absolute` is the absolute path under
    pathlib and so the whole-path candidate matched on the first iteration.
    The diagnosed set was keyed absolute; validate_and_apply normalized the
    model's echo back to relative; the two never met.
    """

    def _worktree(self, root: Path) -> Path:
        test_file = root / "app/src/test/java/net/gaast/giggity/ScheduleTest.java"
        test_file.parent.mkdir(parents=True)
        test_file.write_text(
            "class ScheduleTest { Schedule s = new Schedule(url); }\n",
            encoding="utf-8",
        )
        return root

    def test_an_absolute_diagnostic_path_is_returned_relative(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._worktree(Path(directory))
            absolute = root / "app/src/test/java/net/gaast/giggity/ScheduleTest.java"
            self.assertEqual(
                MODULE.relative_diagnostic_path(root, str(absolute)),
                "app/src/test/java/net/gaast/giggity/ScheduleTest.java",
            )

    def test_a_compiler_path_from_another_checkout_is_still_matched(self):
        # javac may report the path of a differently rooted copy; the
        # longest trailing run that names a file here is the answer.
        with tempfile.TemporaryDirectory() as directory:
            root = self._worktree(Path(directory))
            foreign = (
                "/build/agent/checkout/app/src/test/java/net/gaast/giggity"
                "/ScheduleTest.java"
            )
            self.assertEqual(
                MODULE.relative_diagnostic_path(root, foreign),
                "app/src/test/java/net/gaast/giggity/ScheduleTest.java",
            )

    def test_a_path_outside_the_worktree_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._worktree(Path(directory))
            self.assertEqual(
                MODULE.relative_diagnostic_path(root, "/etc/passwd"), ""
            )

    def test_the_guard_accepts_the_absolute_path_the_model_echoes_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._worktree(Path(directory))
            absolute = root / "app/src/test/java/net/gaast/giggity/ScheduleTest.java"
            # Build the allowed set exactly the way main() does, rather than
            # asserting the relative form by hand: that hand-written set is
            # what let the production disagreement go unnoticed.
            diagnostics, sources = MODULE.diagnosed_context(
                root,
                [{"path": str(absolute), "line": 1,
                  "message": "constructor Schedule cannot be applied",
                  "source_line": "Schedule s = new Schedule(url);"}],
            )
            allowed = set(sources)
            self.assertEqual(
                diagnostics[0]["source_file_path"],
                "app/src/test/java/net/gaast/giggity/ScheduleTest.java",
            )
            ok, edits, error = MODULE.validate_and_apply(
                root,
                {"decision": "REPAIR", "edits": [{
                    "source_file_path": str(absolute),
                    "symbol": "ScheduleTest",
                    "original_code": "new Schedule(url)",
                    "corrected_code": "new Schedule()",
                    "reason": "no-argument constructor",
                }]},
                allowed,
                True,
            )
            self.assertTrue(ok, error)
            self.assertEqual(len(edits), 1)
            self.assertEqual(
                edits[0]["source_file"],
                "app/src/test/java/net/gaast/giggity/ScheduleTest.java",
            )

    def test_the_guard_still_rejects_an_undiagnosed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._worktree(Path(directory))
            other = root / "app/src/main/java/net/gaast/giggity/Schedule.java"
            other.parent.mkdir(parents=True)
            other.write_text("class Schedule { }\n", encoding="utf-8")
            _, sources = MODULE.diagnosed_context(
                root,
                [{"path": str(
                    root / "app/src/test/java/net/gaast/giggity/ScheduleTest.java"
                ), "line": 1, "message": "m", "source_line": "s"}],
            )
            ok, _, error = MODULE.validate_and_apply(
                root,
                {"decision": "REPAIR", "edits": [{
                    "source_file_path": str(other),
                    "symbol": "Schedule",
                    "original_code": "class Schedule { }",
                    "corrected_code": "class Schedule { int x; }",
                    "reason": "unrelated",
                }]},
                set(sources),
                True,
            )
            self.assertFalse(ok)
            self.assertTrue(error.startswith("repair_outside_diagnosed_files"))


class SupportingDeclarationTests(unittest.TestCase):
    """A diagnostic names the type it could not resolve in its message.

    The repair stage used to collect candidate type names only from the
    offending source line, and only where they appeared as . That
    missed  entirely, so the model was asked to repair a
    constructor call without ever seeing the constructor.
    """

    def _worktree(self, root: Path) -> Path:
        production = root / "app/src/main/java/net/gaast/giggity"
        production.mkdir(parents=True)
        (production / "Schedule.java").write_text(
            "package net.gaast.giggity;\n"
            "public class Schedule {\n"
            "    public Schedule() { }\n"
            "}\n",
            encoding="utf-8",
        )
        return root

    def test_collects_type_named_only_in_a_constructor_call(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._worktree(Path(directory))
            supporting = MODULE.supporting_declarations(
                root,
                ["        Schedule schedule = new Schedule(url);"],
                {"app/src/test/java/net/gaast/giggity/ScheduleTest.java"},
            )
            paths = [item["source_file_path"] for item in supporting]
            self.assertIn(
                "app/src/main/java/net/gaast/giggity/Schedule.java", paths
            )

    def test_collects_type_named_only_in_the_diagnostic_message(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._worktree(Path(directory))
            supporting = MODULE.supporting_declarations(
                root,
                ["constructor Schedule in class Schedule cannot be applied "
                 "to given types;"],
                {"app/src/test/java/net/gaast/giggity/ScheduleTest.java"},
            )
            paths = [item["source_file_path"] for item in supporting]
            self.assertIn(
                "app/src/main/java/net/gaast/giggity/Schedule.java", paths
            )

    def test_does_not_supply_the_diagnosed_file_itself(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._worktree(Path(directory))
            supporting = MODULE.supporting_declarations(
                root,
                ["Schedule schedule = new Schedule(url);"],
                {"app/src/main/java/net/gaast/giggity/Schedule.java"},
            )
            self.assertEqual(supporting, [])


if __name__ == "__main__":
    unittest.main()


class RepairSemanticGateTests(unittest.TestCase):
    """A repair is generated by a call no generation-time gate looked at.

    hfut-schedule's repair reintroduced reflection in a test -- the construct
    REFLECTION_ONLY_TEST_SEAM had rejected while the patch was generated.
    """

    RELATIVE = "app/src/androidTest/java/app/ContractTest.kt"
    BROKEN = (
        "class ContractTest {\n"
        "    fun t() {\n"
        "        assertTrue(Service.missingSeam().isEmpty())\n"
        "    }\n"
        "}\n"
    )

    def _repair(self, corrected: str) -> dict:
        return {"decision": "REPAIR", "edits": [{
            "source_file_path": self.RELATIVE, "symbol": "ContractTest.t",
            "original_code": "        assertTrue(Service.missingSeam().isEmpty())\n",
            "corrected_code": corrected, "reason": "the seam does not exist",
        }]}

    def _worktree(self, root: Path) -> Path:
        path = root / self.RELATIVE
        path.parent.mkdir(parents=True)
        path.write_text(self.BROKEN, encoding="utf-8")
        return path

    def test_a_repair_the_gates_reject_is_refused_before_anything_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self._worktree(root)
            reflection = (
                "        assertTrue(Service::class.java.getDeclaredMethod(\"get\")"
                ".parameterAnnotations.isEmpty())\n"
            )
            ok, edits, error = MODULE.validate_and_apply(
                root, self._repair(reflection), {self.RELATIVE}, False,
                lambda repair_edits: MODULE.semantic_regressions(root, {}, repair_edits),
            )
            self.assertFalse(ok)
            self.assertEqual(edits, [])
            self.assertTrue(error.startswith("repair_violates_semantic_gates:"), error)
            self.assertIn("REFLECTION_ONLY_TEST_SEAM", error)
            self.assertEqual(path.read_text(encoding="utf-8"), self.BROKEN)

    def test_a_clean_repair_is_applied_and_no_check_means_no_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self._worktree(root)
            clean = "        assertTrue(true)\n"
            ok, _edits, error = MODULE.validate_and_apply(
                root, self._repair(clean), {self.RELATIVE}, False,
                lambda repair_edits: MODULE.semantic_regressions(root, {}, repair_edits),
            )
            self.assertTrue(ok, error)
            self.assertIn("assertTrue(true)", path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            ok, _edits, _error = MODULE.validate_and_apply(
                root, self._repair("        assertTrue(x.getDeclaredMethod(\"a\"))\n"),
                {self.RELATIVE}, False,
            )
            self.assertTrue(ok)

    def test_the_gates_read_the_finding_context_and_never_crash_the_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            edit = {"source_file": self.RELATIVE, "original_code": "a", "corrected_code": "b"}
            self.assertEqual(MODULE.semantic_regressions(root, {"error_message": "x"}, [edit]), [])
            self.assertEqual(MODULE.semantic_regressions(root, None or {}, []), [])


class PatchConsequenceDeclarationTests(unittest.TestCase):
    """BlueGate (run, run_v4, run_v5; 2026-10-29/30).

    The KeyPairSpec patch made getOrCreateKeyPair return
    KeyStore.PrivateKeyEntry and updated both callers, which pass it to
    Authenticator(...) -- same app module, outside the plan -- whose
    constructor still takes a KeyPair. The repair was told supporting
    declarations are read-only and abstained three times.
    """

    PACKAGE = "app/src/main/java/org/example/gate"
    CALLER = f"{PACKAGE}/MainActivity.kt"
    AUTHENTICATOR = (
        "package org.example.gate\n\n"
        "import java.security.KeyPair\n\n"
        "class Authenticator(private val keyPair: KeyPair, private val raw: ByteArray) {\n"
        "    fun sign(data: ByteArray): ByteArray = signWith(keyPair.private, data)\n"
        "}\n"
    )
    BASE_CALLER = (
        "package org.example.gate\n\n"
        "class MainActivity {\n"
        "    fun authenticate(keyPair: KeyPair) {\n"
        "        val authenticator = Authenticator(keyPair, raw)\n"
        "    }\n"
        "}\n"
    )
    PATCHED_CALLER = (
        "package org.example.gate\n\n"
        "class MainActivity {\n"
        "    fun authenticate(keyEntry: KeyStore.PrivateKeyEntry) {\n"
        "        val authenticator = Authenticator(keyEntry, raw)\n"
        "    }\n"
        "}\n"
    )
    PATCH_EDITS = [
        {"source_file": f"{PACKAGE}/KeyManager.kt",
         "original_code": "fun getOrCreateKeyPair(): KeyPair {",
         "corrected_code": "fun getOrCreateKeyPair(): KeyStore.PrivateKeyEntry {"},
        {"source_file": CALLER,
         "original_code": "    fun authenticate(keyPair: KeyPair) {\n"
                          "        val authenticator = Authenticator(keyPair, raw)\n",
         "corrected_code": "    fun authenticate(keyEntry: KeyStore.PrivateKeyEntry) {\n"
                           "        val authenticator = Authenticator(keyEntry, raw)\n"},
    ]
    DIAGNOSTIC = {
        "path": CALLER, "line": 3,
        "message": "Argument type mismatch: actual type is "
                   "'java.security.KeyStore.PrivateKeyEntry', but "
                   "'java.security.KeyPair' was expected.",
        "source_line": "val authenticator = Authenticator(keyEntry, raw)",
        "attribution": "generated_or_replaced_code",
    }

    def _worktree(self, root: Path, declaration: str = "") -> Path:
        (root / "settings.gradle.kts").write_text('include(":app")\n', encoding="utf-8")
        (root / "app").mkdir()
        (root / "app/build.gradle.kts").write_text("", encoding="utf-8")
        caller = root / self.CALLER
        caller.parent.mkdir(parents=True)
        caller.write_text(self.PATCHED_CALLER, encoding="utf-8")
        target = root / (declaration or f"{self.PACKAGE}/Authenticator.kt")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.AUTHENTICATOR, encoding="utf-8")
        return target

    def _editable(self, root: Path, diagnostic=None, edits=None, base=None) -> list:
        base = self.BASE_CALLER if base is None else base
        return MODULE.patch_consequence_declarations(
            root, [dict(diagnostic or self.DIAGNOSTIC)], {self.CALLER},
            self.PATCH_EDITS if edits is None else edits,
            lambda path: base if path == self.CALLER else "")

    def test_an_owned_declaration_the_replaced_type_reaches_is_editable_with_its_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            editable = self._editable(root)
        self.assertEqual([item["source_file_path"] for item in editable],
                         [f"{self.PACKAGE}/Authenticator.kt"])
        self.assertTrue(editable[0]["editable"])
        reason = editable[0]["editable_reason"]
        self.assertIn("the patch replaced KeyPair with PrivateKeyEntry", reason)
        self.assertIn(f"{self.CALLER}:3", reason)

    def test_a_call_the_patch_invented_in_a_file_the_base_lacked_widens_nothing(self):
        # einkbro (2026-09-17): the generated test called an instance method
        # as static; BackupUnit must not be bent around it.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            self.assertEqual(self._editable(root, base=""), [])

    def test_a_type_the_patch_still_uses_is_a_call_site_mistake(self):
        # RedReader (2026-10-19): byte[] passed to the existing
        # General.sha256(String); the patch had not moved away from String.
        kept = [dict(self.PATCH_EDITS[1], corrected_code=(
            self.PATCH_EDITS[1]["corrected_code"] + "        val old: KeyPair? = null\n"))]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            self.assertEqual(self._editable(root, edits=kept), [])

    def test_a_diagnostic_the_base_already_had_widens_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            old = dict(self.DIAGNOSTIC, attribution="preexisting_code_outside_generated_edits")
            self.assertEqual(self._editable(root, diagnostic=old), [])

    def test_a_message_naming_no_types_widens_nothing(self):
        # Review of 2026-10-31: a wrong arity, an invented member, an
        # overload miss and javac's "cannot be applied to given types" (whose
        # required/found lines the recorded diagnostic drops; RedReader's
        # byte[] -> General.sha256(String) in Java) name no type, so they
        # cannot tell the patch's new type reaching a declaration from a call
        # the patch wrote wrong -- each made the existing class editable.
        line = "val authenticator = Authenticator(keyEntry, raw)"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            for message in ("Too many arguments for 'constructor(keyPair: KeyPair, raw: ByteArray)'.",
                            "No value passed for parameter 'raw'.",
                            "None of the following candidates is applicable:",
                            "Unresolved reference 'keyEntry'.",
                            "Unresolved reference 'signGcm'.",
                            "constructor Authenticator in class Authenticator cannot be "
                            "applied to given types;"):
                with self.subTest(message=message):
                    self.assertEqual(self._editable(root, diagnostic=dict(
                        self.DIAGNOSTIC, message=message, source_line=line)), [])

    def test_a_mismatch_with_the_lines_own_declaration_or_a_generic_widens_nothing(self):
        # Review of 2026-10-31: K2's "expected 'X', actual 'Y'" forms are
        # against a declaration of the diagnosed file itself, and a generic
        # differs only in type arguments a simple name cannot compare.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            for message, line in (
                    ("Initializer type mismatch: expected 'java.security.KeyPair', "
                     "actual 'java.security.KeyStore.PrivateKeyEntry'.", None),
                    ("Return type mismatch: expected 'java.security.KeyPair', "
                     "actual 'java.security.KeyStore.PrivateKeyEntry'.", None),
                    ("Argument type mismatch: actual type is 'kotlin.collections.Map<kotlin.String, "
                     "java.security.KeyStore.PrivateKeyEntry>', but 'kotlin.collections.Map<"
                     "kotlin.String, java.security.KeyPair>' was expected.", None),
                    # K1 names both, but KeyPair is the line's own annotation.
                    ("Type mismatch: inferred type is KeyStore.PrivateKeyEntry but KeyPair was expected",
                     "val pair: KeyPair = Authenticator.unwrap(keyEntry)")):
                with self.subTest(message=message):
                    diagnostic = dict(self.DIAGNOSTIC, message=message)
                    if line:
                        diagnostic["source_line"] = line
                    self.assertEqual(self._editable(root, diagnostic=diagnostic), [])

    def test_only_a_source_set_the_apk_compiles_is_editable(self):
        # Review of 2026-10-31: the unselected gplay flavour and the release
        # and debug build types were admitted; the validation build never
        # compiles the first, and the published APK lacks the other two.
        flavours = ('android {\n  flavorDimensions += "store"\n  productFlavors {\n'
                    '    create("fdroid") { dimension = "store" }\n'
                    '    create("gplay") { dimension = "store" }\n  }\n}\n')
        for source_set, expected in (("gplay", False), ("release", False), ("debug", False),
                                     ("fdroidRelease", False), ("fdroid", True)):
            declaration = f"app/src/{source_set}/java/org/example/gate/Authenticator.kt"
            with self.subTest(source_set=source_set), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._worktree(root, declaration)
                (root / "app/build.gradle.kts").write_text(flavours, encoding="utf-8")
                self.assertEqual([item["source_file_path"] for item in self._editable(root)],
                                 [declaration] if expected else [])
        # With a gplay copy too, adapting only fdroid's would leave the gplay
        # variant calling the old constructor, a build nothing here runs.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root, "app/src/fdroid/java/org/example/gate/Authenticator.kt")
            gplay = root / "app/src/gplay/java/org/example/gate/Authenticator.kt"
            gplay.parent.mkdir(parents=True)
            gplay.write_text(self.AUTHENTICATOR, encoding="utf-8")
            (root / "app/build.gradle.kts").write_text(flavours, encoding="utf-8")
            self.assertEqual(self._editable(root), [])

    def test_only_the_declaration_the_call_resolves_to_is_editable(self):
        # Review of 2026-10-31: declarations were matched by simple name, so
        # another package's Authenticator and a :wear application's copy
        # became editable too.
        legacy = "app/src/main/java/org/example/legacy/Authenticator.kt"
        wear = "wear/src/main/java/org/example/gate/Authenticator.kt"
        core = "core/src/main/java/org/example/gate/Authenticator.kt"
        gate = f"{self.PACKAGE}/Authenticator.kt"

        def editable(declaration, settings, app_build="", caller=None):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._worktree(root)
                (root / gate).unlink()
                target = root / declaration
                target.parent.mkdir(parents=True, exist_ok=True)
                package = ".".join(declaration.split("/java/")[1].split("/")[:-1])
                target.write_text(self.AUTHENTICATOR.replace(
                    "package org.example.gate", f"package {package}"), encoding="utf-8")
                module = declaration.split("/src/")[0]
                (root / module / "build.gradle.kts").write_text("", encoding="utf-8")
                (root / "settings.gradle.kts").write_text(settings, encoding="utf-8")
                (root / "app/build.gradle.kts").write_text(app_build, encoding="utf-8")
                if caller:
                    (root / self.CALLER).write_text(caller, encoding="utf-8")
                return [item["source_file_path"] for item in self._editable(root)]

        both = 'include(":app", ":wear", ":core")\n'
        self.assertEqual(editable(legacy, both), [])
        self.assertEqual(editable(legacy, both, caller=self.PATCHED_CALLER.replace(
            "class MainActivity", "import org.example.legacy.Authenticator\n\nclass MainActivity")),
            [legacy])
        self.assertEqual(editable(wear, both), [])
        self.assertEqual(editable(core, both), [])
        self.assertEqual(editable(core, both, 'dependencies { implementation(project(":core")) }\n'),
                         [core])
        self.assertEqual(editable(core, both, "dependencies { implementation(projects.core) }\n"),
                         [core])
        # Two owned copies the call could reach: which one is not decidable.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            other = root / self.PACKAGE / "more/Authenticator.kt"
            other.parent.mkdir(parents=True)
            other.write_text(self.AUTHENTICATOR, encoding="utf-8")
            self.assertEqual(self._editable(root), [])

    def test_a_file_the_patch_or_its_plan_edits_is_never_editable(self):
        # Review of 2026-10-31: in Authenticator(KeyManager.getOrCreateKeyPair(), raw)
        # the patched KeyManager.kt became editable, and a repair "adapting"
        # it could revert the correction with no review reading it again.
        key_manager = (
            "package org.example.gate\n\nimport java.security.KeyPair\nimport java.security.KeyStore\n\n"
            "object KeyManager {\n    fun getOrCreateKeyPair(): KeyStore.PrivateKeyEntry {\n"
            "        TODO()\n    }\n    fun describe(pair: KeyPair): String = pair.public.algorithm\n}\n")
        line = "val authenticator = Authenticator(KeyManager.getOrCreateKeyPair(), raw)"
        base = self.BASE_CALLER.replace("Authenticator(keyPair, raw)",
                                        "Authenticator(KeyManager.getOrCreateKeyPair(), raw)")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            (root / self.PACKAGE / "KeyManager.kt").write_text(key_manager, encoding="utf-8")
            diagnostic = dict(self.DIAGNOSTIC, source_line=line)
            editable = self._editable(root, diagnostic=diagnostic, edits=self.PATCH_EDITS[:1],
                                      base=base)
            self.assertEqual([item["source_file_path"] for item in editable],
                             [f"{self.PACKAGE}/Authenticator.kt"])
            # A planned file the patch's edits do not name stays read-only too.
            planned = MODULE.patch_consequence_declarations(
                root, [diagnostic], {self.CALLER}, self.PATCH_EDITS, lambda path: base,
                planned_files=[f"{self.PACKAGE}/Authenticator.kt"])
            self.assertEqual(planned, [])

    # BlueGate run_v6 (2026-10-31): the patch kept the entry in a property and
    # passed `keyEntry.privateKey`; kotlinc named PrivateKey, a type Kotlin
    # inferred and no line of the patch spells.
    INFERRED_MESSAGE = ("Argument type mismatch: actual type is 'java.security.PrivateKey!', "
                        "but 'java.security.KeyPair' was expected.")
    KEY_MANAGER_EDIT = {"source_file": f"{PACKAGE}/KeyManager.kt",
                        "original_code": "fun getOrCreateKeyPair(): KeyPair {",
                        "corrected_code": "fun getOrCreatePrivateKeyEntry(): KeyStore.PrivateKeyEntry {"}
    FIELD_EDIT = {"source_file": CALLER,
                  "original_code": "    private lateinit var keyPair: KeyPair\n",
                  "corrected_code": "    private lateinit var keyEntry: KeyStore.PrivateKeyEntry\n"}

    def _inferred(self, root: Path, old_call: str, new_call: str, extra=(), base=None,
                  source_line=None, **diagnostic) -> list:
        edits = [self.KEY_MANAGER_EDIT, self.FIELD_EDIT, *extra,
                 {"source_file": self.CALLER, "original_code": f"        {old_call}\n",
                  "corrected_code": f"        {new_call}\n"}]
        return [item["source_file_path"] for item in self._editable(
            root, diagnostic=dict(self.DIAGNOSTIC, message=self.INFERRED_MESSAGE,
                                  source_line=source_line or new_call.strip(), **diagnostic),
            edits=edits, base=self.BASE_CALLER if base is None else base)]

    def test_a_value_whose_type_the_compiler_inferred_is_read_like_a_spelled_one(self):
        authenticator = f"{self.PACKAGE}/Authenticator.kt"
        for old_call, new_call in (
                ("val authenticator = Authenticator(keyPair, raw)",
                 "val authenticator = Authenticator(keyEntry.privateKey, raw)"),
                # A method's return, the method declared by the patch.
                ("val authenticator = Authenticator(KeyManager.getOrCreateKeyPair(), raw)",
                 "val authenticator = Authenticator("
                 "KeyManager.getOrCreatePrivateKeyEntry().privateKey, raw)"),
                # A named argument.
                ("val authenticator = Authenticator(keyPair = keyPair, raw = raw)",
                 "val authenticator = Authenticator(keyPair = keyEntry.privateKey, raw = raw)")):
            with self.subTest(new_call=new_call), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._worktree(root)
                self.assertEqual(self._inferred(root, old_call, new_call), [authenticator])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            editable = self._editable(root, diagnostic=dict(
                self.DIAGNOSTIC, message=self.INFERRED_MESSAGE,
                source_line="val authenticator = Authenticator(keyEntry.privateKey, raw)"),
                edits=[self.KEY_MANAGER_EDIT, self.FIELD_EDIT, {
                    "source_file": self.CALLER,
                    "original_code": "        val authenticator = Authenticator(keyPair, raw)\n",
                    "corrected_code": "        val authenticator = "
                                      "Authenticator(keyEntry.privateKey, raw)\n"}])
        self.assertIn("the patch replaced KeyPair with PrivateKey", editable[0]["editable_reason"])

    def test_an_inferred_value_initialised_from_the_replaced_producer_is_the_patchs(self):
        authenticator = f"{self.PACKAGE}/Authenticator.kt"
        for label, local in (
                ("an untyped val from the producer",
                 "        val entry = keyManager.getOrCreatePrivateKeyEntry()\n"),
                ("a val typed with the producer's new type",
                 "        val entry: KeyStore.PrivateKeyEntry = load()\n")):
            with self.subTest(label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._worktree(root)
                self.assertEqual(self._inferred(
                    root, "val authenticator = Authenticator(keyPair, raw)",
                    "val authenticator = Authenticator(entry?.privateKey, raw)",
                    [{"source_file": self.CALLER, "original_code": "        prepare()\n",
                      "corrected_code": local}]), [authenticator])
        # Java: `var` and a getter, the producer a Java method.
        java_caller = f"{self.PACKAGE}/MainActivity.java"
        java_base = ("package org.example.gate;\n\nclass MainActivity {\n    private KeyPair keyPair;\n"
                     "    void a() {\n        Authenticator a = new Authenticator(keyPair, raw);\n"
                     "    }\n}\n")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            (root / java_caller).write_text("package org.example.gate;\n", encoding="utf-8")
            line = "Authenticator a = new Authenticator(entry.getPrivateKey(), raw);"
            editable = MODULE.patch_consequence_declarations(
                root, [{"path": java_caller, "line": 6, "attribution": "generated_or_replaced_code",
                        "message": "incompatible types: PrivateKey cannot be converted to KeyPair",
                        "source_line": line}], {java_caller},
                [{"source_file": f"{self.PACKAGE}/KeyManager.java",
                  "original_code": "    public KeyPair getOrCreateKeyPair() {",
                  "corrected_code": "    public KeyStore.PrivateKeyEntry getOrCreatePrivateKeyEntry() {"},
                 {"source_file": java_caller,
                  "original_code": "    private KeyPair keyPair;\n"
                                   "        Authenticator a = new Authenticator(keyPair, raw);\n",
                  "corrected_code": "        var entry = keyManager.getOrCreatePrivateKeyEntry();\n"
                                    f"        {line}\n"}],
                lambda path: java_base if path == java_caller else "")
        self.assertEqual([item["source_file_path"] for item in editable], [authenticator])

    def test_an_inferred_value_the_line_does_not_show_as_the_patchs_widens_nothing(self):
        call = "val authenticator = Authenticator(keyPair, raw)"
        for label, old_call, new_call, extra, line, attribution in (
                ("a value the patch did not declare", call,
                 "val authenticator = Authenticator(signer.privateKey, raw)", (), None, None),
                ("the replaced value was not of the expected type",
                 "val authenticator = Authenticator(load() as KeyPair, raw)",
                 "val authenticator = Authenticator(keyEntry.privateKey, raw)", (), None, None),
                ("two arguments changed", call,
                 "val authenticator = Authenticator(keyEntry.privateKey, keyEntry.certificate)",
                 (), None, None),
                ("another argument names what the patch declares",
                 "val authenticator = Authenticator(keyPair, rawKey)",
                 "val authenticator = Authenticator(keyEntry.privateKey, rawKey)",
                 [{"source_file": self.CALLER, "original_code": "        val rawKey = raw()\n",
                   "corrected_code": "        val rawKey = keyEntry.certificate.publicKey.encoded\n"}],
                 None, None),
                ("the mismatch may be an inner call's",
                 "val authenticator = Authenticator(wrap(keyPair), raw)",
                 "val authenticator = Authenticator(wrap(keyEntry.privateKey), raw)", (), None, None),
                ("the call continues on the next line",
                 "val authenticator = Authenticator(keyPair,",
                 "val authenticator = Authenticator(keyEntry.privateKey,", (), None, None),
                ("a line the patch did not write", call, call, (),
                 "val authenticator = Authenticator(keyEntry.privateKey, raw)",
                 "caller_of_changed_symbol")):
            with self.subTest(label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._worktree(root)
                diagnostic = {"attribution": attribution} if attribution else {}
                self.assertEqual(self._inferred(root, old_call, new_call, extra,
                                                source_line=line, **diagnostic), [])

    def test_a_value_only_named_like_the_patchs_widens_nothing(self):
        # Review of 2026-10-31: the first inferred-value test took any name
        # declared on any line the patch wrote, in any file, as the patch's
        # value -- a parameter it only wrote again, a name in a comment, a
        # member named like another file's local -- and any name on a removed
        # line naming the expected type as the replaced value.
        call = "val authenticator = Authenticator(keyPair, raw)"
        resources = ("Argument type mismatch: actual type is 'android.content.res.Resources!', "
                     "but 'java.security.KeyPair' was expected.")
        certificate = ("Argument type mismatch: actual type is 'java.security.cert.Certificate!', "
                       "but 'java.security.KeyPair' was expected.")
        signer_call = "val authenticator = Authenticator(signer.privateKey, raw)"

        def caller(original, corrected):
            return {"source_file": self.CALLER, "original_code": original,
                    "corrected_code": corrected}

        cases = (
            ("an existing parameter on a signature the patch rewrote", resources, [
                self.KEY_MANAGER_EDIT, caller(
                    "    fun authenticate(context: Context, keyPair: KeyPair) {\n"
                    f"        {call}\n",
                    "    fun authenticate(context: Context, keyEntry: KeyStore.PrivateKeyEntry) {\n"
                    "        val authenticator = Authenticator(context.resources, raw)\n")],
             "val authenticator = Authenticator(context.resources, raw)",
             self.BASE_CALLER.replace("(keyPair: KeyPair)", "(context: Context, keyPair: KeyPair)")),
            ("a name the patch declares in another file", self.INFERRED_MESSAGE, [
                {"source_file": f"{self.PACKAGE}/KeyManager.kt",
                 "original_code": "fun getOrCreateKeyPair(): KeyPair {\n    return generate()\n",
                 "corrected_code": "fun getOrCreatePrivateKeyEntry(): KeyStore.PrivateKeyEntry {\n"
                                   "    val signer = load()\n    return generate()\n"},
                self.FIELD_EDIT, caller(f"        {call}\n", f"        {signer_call}\n")],
             signer_call, None),
            ("a member named like a value the patch declares", self.INFERRED_MESSAGE, [
                self.KEY_MANAGER_EDIT, self.FIELD_EDIT,
                {"source_file": f"{self.PACKAGE}/KeyManager.kt",
                 "original_code": "    val pair = load()\n",
                 "corrected_code": "    val privateKey: KeyStore.PrivateKeyEntry = load()\n"},
                caller(f"        {call}\n", f"        {signer_call}\n")],
             signer_call, None),
            ("a new val holding an existing value", resources, [
                self.KEY_MANAGER_EDIT, self.FIELD_EDIT, caller(
                    f"        {call}\n",
                    "        val signingKey = context.resources\n"
                    "        val authenticator = Authenticator(signingKey, raw)\n")],
             "val authenticator = Authenticator(signingKey, raw)", None),
            ("an untyped lambda parameter, whose type the line does not show",
             self.INFERRED_MESSAGE, [self.KEY_MANAGER_EDIT, caller(
                 f"        keys.forEach {{ pair: KeyPair -> use(pair) }}\n        {call}\n",
                 "        keys.forEach { entry -> use(entry) }\n"
                 "        val authenticator = Authenticator(entry.privateKey, raw)\n")],
             "val authenticator = Authenticator(entry.privateKey, raw)", None),
            ("no producer moved off the expected type", self.INFERRED_MESSAGE, [
                self.FIELD_EDIT, caller(
                    f"        {call}\n",
                    "        val authenticator = Authenticator(keyEntry.privateKey, raw)\n")],
             "val authenticator = Authenticator(keyEntry.privateKey, raw)", None),
            ("the replaced value only shares a removed line with the expected type",
             certificate, [
                 {"source_file": f"{self.PACKAGE}/KeyManager.kt",
                  "original_code": "    private fun generateNewKeyPair(alias: String): KeyPair {",
                  "corrected_code": "    private fun generateNewEntry(alias: String): "
                                    "KeyStore.PrivateKeyEntry {"},
                 caller("        val authenticator = Authenticator(cache.pairFor(alias), raw)\n",
                        "        val authenticator = "
                        "Authenticator(cache.certificateFor(alias), raw)\n")],
             "val authenticator = Authenticator(cache.certificateFor(alias), raw)",
             self.BASE_CALLER.replace("Authenticator(keyPair, raw)",
                                      "Authenticator(cache.pairFor(alias), raw)")),
        )
        # Text that only reads like a declaration of `signer`.
        either = "val authenticator = Authenticator(if (ok) signer.privateKey else null, raw)"
        cases += tuple(
            (f"`{name}` named in {label}", self.INFERRED_MESSAGE, [
                self.KEY_MANAGER_EDIT, self.FIELD_EDIT,
                caller(f"        {call}\n", f"        {text}\n        {line}\n")],
             line, None)
            for label, text, name, line in (
                ("a comment", "// signer: KeyStore.PrivateKeyEntry from the store",
                 "signer", signer_call),
                ("a string", 'Log.d(TAG, "signer: KeyStore.PrivateKeyEntry")', "signer",
                 signer_call),
                ("a when branch", "when (mode) { signer -> Unit }", "signer", signer_call),
                ("a when branch", "when (mode) { else -> sign() }", "else", either)))
        for label, message, edits, line, base in cases:
            with self.subTest(label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._worktree(root)
                self.assertEqual(self._editable(
                    root, diagnostic=dict(self.DIAGNOSTIC, message=message, source_line=line),
                    edits=edits, base=base), [])

    def test_an_inferred_value_handed_to_an_unchanged_type_is_a_call_site_mistake(self):
        # RedReader's shape with Kotlin's inference: a ByteArray the patch made
        # passed to the existing General.sha256(String). The patch stopped
        # naming String, but the value it replaced (`text as String`) was not
        # one the patch moved off String: General must stay read-only.
        general = (f"package org.example.gate\n\nobject General {{\n"
                   "    fun sha256(text: String): String = text\n}\n")
        base = self.BASE_CALLER.replace("val authenticator = Authenticator(keyPair, raw)",
                                        "val digest = General.sha256(text as String)")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            (root / self.PACKAGE / "General.kt").write_text(general, encoding="utf-8")
            editable = self._editable(root, diagnostic=dict(
                self.DIAGNOSTIC, source_line="val digest = General.sha256(bytes)",
                message="Argument type mismatch: actual type is 'kotlin.ByteArray', "
                        "but 'kotlin.String' was expected."),
                edits=[{"source_file": self.CALLER,
                        "original_code": "        val digest = General.sha256(text as String)\n",
                        "corrected_code": "        val bytes = text.toByteArray()\n"
                                          "        val digest = General.sha256(bytes)\n"}],
                base=base)
        self.assertEqual(editable, [])
        # Review of 2026-10-31: the same mistake where the patch also replaced
        # the String parameter (`text: String` -> `user: User`). A parameter
        # moved off the expected type reads exactly like BlueGate's property;
        # no producer moved off String, so General stays read-only.
        base = self.BASE_CALLER.replace(
            "    fun authenticate(keyPair: KeyPair) {\n"
            "        val authenticator = Authenticator(keyPair, raw)\n",
            "    fun cacheKey(text: String) {\n        val digest = General.sha256(text)\n")
        for label, corrected, line in (
                ("through a new val",
                 "        val bytes = user.name.toByteArray()\n"
                 "        val digest = General.sha256(bytes)\n",
                 "val digest = General.sha256(bytes)"),
                ("inline", "        val digest = General.sha256(user.name.toByteArray())\n",
                 "val digest = General.sha256(user.name.toByteArray())")):
            with self.subTest(label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._worktree(root)
                (root / self.PACKAGE / "General.kt").write_text(general, encoding="utf-8")
                self.assertEqual(self._editable(root, diagnostic=dict(
                    self.DIAGNOSTIC, source_line=line,
                    message="Argument type mismatch: actual type is 'kotlin.ByteArray', "
                            "but 'kotlin.String' was expected."),
                    edits=[{"source_file": self.CALLER,
                            "original_code": "    fun cacheKey(text: String) {\n"
                                             "        val digest = General.sha256(text)\n",
                            "corrected_code": "    fun cacheKey(user: User) {\n" + corrected}],
                    base=base), [])

    def test_generated_source_committed_under_src_stays_read_only(self):
        # Review of 2026-10-31: protobuf, AIDL or greenDAO output committed
        # under src/main/java was admitted by its path alone.
        for header in ("// Generated by the protocol buffer compiler.  DO NOT EDIT!\n",
                       "/*\n * This file is auto-generated.  DO NOT MODIFY.\n */\n",
                       "@javax.annotation.Generated(\"dagger\")\n"):
            with self.subTest(header=header), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = self._worktree(root)
                target.write_text(header + self.AUTHENTICATOR, encoding="utf-8")
                self.assertEqual(self._editable(root), [])

    def test_a_single_method_patch_is_read_like_a_coordinated_one(self):
        # Review of 2026-10-31: a single-method row records its patch as
        # original/corrected_method_body with no coordinated edits, so the
        # widened scope never applied to it and a re-review of its repaired
        # patch would have judged the repair edits alone.
        import logging

        from cognalys.llm import coordinated_generation

        single = {"finding_id": "f", "base_commit": "base", "fix_scope": "single_method",
                  "method_name": "authenticate", "source_file": self.CALLER,
                  "changed_files": [self.CALLER],
                  "original_method_body": self.PATCH_EDITS[1]["original_code"],
                  "corrected_method_body": self.PATCH_EDITS[1]["corrected_code"],
                  "build_validation": {"compiler_diagnostics": [self.DIAGNOSTIC]}}
        authenticator = f"{self.PACKAGE}/Authenticator.kt"
        reviewed = []

        def review(_self, _error, review_edits, _sources):
            reviewed.extend((edit["source_file_path"], edit["corrected_code"])
                            for edit in review_edits)
            return {"status": "reviewed", "regressions": [], "review_contract_version": 1}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            with patch.object(MODULE, "_file_at", lambda _repo, _commit, path: self.BASE_CALLER
                              if path == self.CALLER else ""), \
                    patch.object(MODULE, "_verified_imports", return_value=[]):
                request = MODULE.repair_request(root, single)
            repaired = dict(single, coordinated_edits=[{
                "source_file": authenticator, "edit_kind": "validation_repair",
                "repair_scope": "patch_consequence_declaration",
                "original_code": "private val keyPair: KeyPair",
                "corrected_code": "private val keyEntry: KeyStore.PrivateKeyEntry"}])
            with patch.object(coordinated_generation.CoordinatedGeneration,
                              "review_patch_behavior", review), \
                    patch.object(MODULE, "_file_at", lambda *_args: ""), \
                    patch("cognalys.llm.fix_artifacts._solution_files",
                          lambda *_args: iter([(root, {"evidence_analysis": {}})])):
                MODULE.review_repaired_patch(repaired, root, None, logging.getLogger("t"),
                                             root / "error_solutions")
        self.assertEqual(sorted(request["widened"]), [authenticator])
        self.assertEqual([path for path, _ in reviewed], [self.CALLER, authenticator])
        self.assertIn("Authenticator(keyEntry, raw)", reviewed[0][1])

    def test_library_test_generated_and_unbuilt_declarations_stay_read_only(self):
        for declaration, extra in (
                ("libs/auth/src/main/java/org/example/gate/Authenticator.kt", "nested"),
                ("app/src/test/java/org/example/gate/Authenticator.kt", ""),
                ("app/build/generated/source/org/example/gate/Authenticator.kt", ""),
                ("other/src/main/java/org/example/gate/Authenticator.kt", "unbuilt")):
            with self.subTest(declaration=declaration), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._worktree(root, declaration)
                module = root / declaration.split("/src/")[0]
                if extra:
                    (module / "build.gradle").write_text("", encoding="utf-8")
                if extra == "nested":
                    (root / "libs/auth/.git").write_text("gitdir: x\n", encoding="utf-8")
                    (root / "settings.gradle.kts").write_text(
                        'include(":app", ":libs:auth")\n', encoding="utf-8")
                self.assertEqual(self._editable(root), [])

    def test_the_request_names_the_editable_file_and_keeps_the_read_only_text_otherwise(self):
        solution = {"finding_id": "f", "base_commit": "base",
                    "coordinated_edits": self.PATCH_EDITS,
                    "build_validation": {"compiler_diagnostics": [self.DIAGNOSTIC]}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._worktree(root)
            with patch.object(MODULE, "_file_at",
                              lambda _repo, _commit, path: self.BASE_CALLER
                              if path == self.CALLER else ""), \
                    patch.object(MODULE, "_verified_imports", return_value=[]):
                widened = MODULE.repair_request(root, solution)
            with patch.object(MODULE, "_file_at", lambda *_args: ""), \
                    patch.object(MODULE, "_verified_imports", return_value=[]):
                plain = MODULE.repair_request(root, solution)
        authenticator = f"{self.PACKAGE}/Authenticator.kt"
        self.assertEqual(widened["allowed"], {self.CALLER, authenticator})
        self.assertIn(authenticator, widened["widened"])
        first = widened["payload"]["supporting_current_api_sources"][0]
        self.assertEqual((first["source_file_path"], first["editable"]), (authenticator, True))
        self.assertIn("Never satisfy the old declaration by building the old type",
                      MODULE.repair_prompt(widened["payload"]))
        self.assertNotIn(MODULE._READ_ONLY_CONSTRAINT, widened["payload"]["constraints"])
        # Without a widened declaration the prompt is what it was.
        self.assertEqual(plain["allowed"], {self.CALLER})
        self.assertEqual(plain["widened"], {})
        self.assertIn(MODULE._READ_ONLY_CONSTRAINT, plain["payload"]["constraints"])
        self.assertNotIn("editable", MODULE.repair_prompt(plain["payload"]))

    def test_an_edit_of_the_editable_declaration_carries_its_scope_and_reason(self):
        authenticator = f"{self.PACKAGE}/Authenticator.kt"
        generated = {"decision": "REPAIR", "edits": [
            {"source_file_path": authenticator, "symbol": "Authenticator",
             "original_code": "private val keyPair: KeyPair",
             "corrected_code": "private val keyEntry: KeyStore.PrivateKeyEntry",
             "reason": "accept the entry"},
            {"source_file_path": self.CALLER, "symbol": "MainActivity",
             "original_code": "Authenticator(keyEntry, raw)",
             "corrected_code": "Authenticator(keyEntry, raw.copyOf())",
             "reason": "unchanged call"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = self._worktree(root)
            refused = MODULE.validate_and_apply(root, generated, {self.CALLER}, True)
            ok, edits, error = MODULE.validate_and_apply(
                root, generated, {self.CALLER, authenticator}, False,
                widened_paths={authenticator: "the reason"})
            text = target.read_text(encoding="utf-8")
        self.assertEqual(refused[2], f"repair_outside_diagnosed_files:{authenticator}")
        self.assertTrue(ok, error)
        self.assertEqual((edits[0]["repair_scope"], edits[0]["repair_scope_reason"]),
                         ("patch_consequence_declaration", "the reason"))
        self.assertNotIn("repair_scope", edits[1])
        self.assertIn("KeyStore.PrivateKeyEntry", text)
        self.assertEqual(MODULE.files_beyond_plan([self.CALLER], edits), [authenticator])
        self.assertEqual(MODULE.files_beyond_plan([self.CALLER, authenticator], edits), [])


class RepairedPatchReviewTests(unittest.TestCase):
    """A repair that reached a file the plan did not include is reviewed again.

    The behaviour review judged BlueGate's coordinated draft before
    validation; its Authenticator edit (2026-10-30) would otherwise reach the
    pull request with no review having read it.
    """

    def _record(self) -> dict:
        from cognalys.llm.coordinated_generation import REVIEW_CONTRACT_VERSION

        return {
            "build_validation": {"status": "success"}, "commit_hash": "c0ffee",
            "decision": "MULTI_FILE_FIX_SUPPORTED", "behavior_review_recorded": True,
            "review_contract_version": REVIEW_CONTRACT_VERSION,
            "publication_blocker_record": {"behavior_review": {
                "status": "reviewed", "review_contract_version": REVIEW_CONTRACT_VERSION,
                "regression_count": 0}},
        }

    def test_a_review_that_did_not_run_blocks_publication(self):
        from cognalys.utils.disposition import publication_after_validation

        record = self._record()
        self.assertTrue(publication_after_validation(record)["publishable"])
        MODULE.record_repair_review(record, {"status": "not_run", "regressions": []},
                                    ["app/Authenticator.kt"])
        verdict = publication_after_validation(record)
        self.assertFalse(verdict["publishable"])
        self.assertTrue(any("repair_scope_unreviewed" in block and "app/Authenticator.kt" in block
                            for block in verdict["blocks"]), verdict["blocks"])
        self.assertTrue(record["summary_stale"])

    def test_the_repaired_patchs_review_is_the_one_publication_reads(self):
        from cognalys.llm.coordinated_generation import REVIEW_CONTRACT_VERSION
        from cognalys.utils.disposition import publication_after_validation

        clean = self._record()
        MODULE.record_repair_review(clean, {
            "status": "reviewed", "review_contract_version": REVIEW_CONTRACT_VERSION,
            "regressions": []}, ["app/Authenticator.kt"])
        self.assertTrue(publication_after_validation(clean)["publishable"])
        self.assertEqual(clean["repair_behavior_review"]["files_beyond_plan"],
                         ["app/Authenticator.kt"])
        regressed = self._record()
        MODULE.record_repair_review(regressed, {
            "status": "reviewed", "review_contract_version": REVIEW_CONTRACT_VERSION,
            "regressions": [{"scenario": "the signer reads a null key"}]},
            ["app/Authenticator.kt"])
        self.assertIn("the behaviour review found 1 regression(s)",
                      publication_after_validation(regressed)["blocks"])

    def test_the_review_texts_reach_the_notes_and_a_missing_record_is_not_a_review(self):
        # Review of 2026-10-31: only the counts were kept, so a regression
        # scenario or a maintainer question about the repaired patch never
        # reached the PR notes.
        import logging

        from cognalys.llm.coordinated_generation import REVIEW_CONTRACT_VERSION

        record = self._record()
        MODULE.record_repair_review(record, {
            "status": "reviewed", "review_contract_version": REVIEW_CONTRACT_VERSION,
            "regressions": [{"scenario": "the signer reads a null key"}],
            "maintainer_decision_required": True,
            "maintainer_decision": "whether the entry may leave the key store"},
            ["app/Authenticator.kt"])
        notes = record["repair_review_notes"]
        self.assertTrue(any("app/Authenticator.kt" in line and "null key" in line
                            for line in notes["review_blockers"]), notes)
        self.assertTrue(any("leave the key store" in line
                            for line in notes["publication_considerations"]), notes)
        with tempfile.TemporaryDirectory() as directory:
            review = MODULE.review_repaired_patch(
                {"apk_name": "gate.apk", "coordinated_edits": []}, Path(directory), None,
                logging.getLogger("t"), Path(directory) / "error_solutions")
        self.assertEqual(review["status"], "not_run")

    def test_a_review_the_provider_failed_to_answer_is_recorded_as_not_run(self):
        # Review of 2026-11-09: the behaviour review now raises a provider
        # that failed to answer, for process_finding; this step records it.
        import logging

        from cognalys.llm import coordinated_generation
        from cognalys.llm.llm_providers import BackgroundResponseFailed

        def review(*_args):
            raise BackgroundResponseFailed("failed (server_is_overloaded)",
                                           code="server_is_overloaded")

        repaired = {"apk_name": "gate.apk", "coordinated_edits": [{
            "source_file": "app/A.kt", "edit_kind": "validation_repair",
            "original_code": "a", "corrected_code": "b"}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(coordinated_generation.CoordinatedGeneration,
                              "review_patch_behavior", review), \
                    patch.object(MODULE, "_file_at", lambda *_args: ""), \
                    patch("cognalys.llm.fix_artifacts._solution_files",
                          lambda *_args: iter([(root, {"evidence_analysis": {}})])), \
                    self.assertLogs("t", level="WARNING"):
                review_result = MODULE.review_repaired_patch(
                    repaired, root, None, logging.getLogger("t"), root / "error_solutions")
        self.assertEqual(review_result, {"regressions": [], "status": "not_run",
                                         "reason": "provider_unavailable"})

    def test_the_solution_file_of_the_patchs_own_revision_is_read(self):
        # Review of 2026-10-31: the first file in name order need not be the
        # revision that produced the patch.
        from cognalys.llm.fix_artifacts import recorded_solution

        identity = {"csv_class": "a.C", "method_name": "m", "spec": "S"}
        with tempfile.TemporaryDirectory() as directory:
            solutions = Path(directory)
            (solutions / "app.apk").mkdir()
            for index, code in ((1, "old()"), (2, "new()")):
                (solutions / "app.apk" / f"{index}_m_solution.json").write_text(json.dumps({
                    "solution_metadata": identity, "revision": index,
                    "corrected_implementation": {"coordinated_edits": [
                        {"corrected_code": code}]}}), encoding="utf-8")
            pick = lambda code: recorded_solution(solutions, "app.apk", "a.C", "m", "S",
                                                  patch_code=code).get("revision")
            self.assertEqual(pick(["new()"]), 2)
            self.assertEqual(pick(["old()"]), 1)
            self.assertIsNone(pick(["other()"]))
            self.assertEqual(recorded_solution(solutions, "app.apk", "a.C", "m", "S")["revision"], 1)

    def test_the_step_reviews_a_repair_that_reached_an_unplanned_file(self):
        import cognalys.validation.repair as repair

        case = PatchConsequenceDeclarationTests
        authenticator = f"{case.PACKAGE}/Authenticator.kt"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worktree = root / "worktree"
            worktree.mkdir()
            case._worktree(case(), worktree)
            solutions = root / "error_solutions" / "gate.apk"
            solutions.mkdir(parents=True)
            (solutions / "1_getOrCreateKeyPair_solution.json").write_text(json.dumps({
                "solution_metadata": {"csv_class": "org.example.gate.KeyManager",
                                      "method_name": "getOrCreateKeyPair", "spec": "KeyPairSpec"},
                "evidence_analysis": {"v2": {"patch_plan": {
                    "behavioral_invariants": ["authentication still signs the challenge"]}}},
            }), encoding="utf-8")
            report_path = root / "application_results" / "execution_report.json"
            report_path.parent.mkdir()
            report_path.write_text(json.dumps({"per_solution_details": [{
                "status": "SUCCESS", "finding_id": "gate", "apk_name": "gate.apk",
                "csv_class": "org.example.gate.KeyManager", "method_name": "getOrCreateKeyPair",
                "spec": "KeyPairSpec", "worktree_path": str(worktree), "base_commit": "base",
                "changed_files": [f"{case.PACKAGE}/KeyManager.kt", case.CALLER],
                "coordinated_edits": case.PATCH_EDITS,
                "build_validation": {"status": "failed", "failure_attribution": "generated_patch",
                                     "compiler_diagnostics": [case.DIAGNOSTIC]},
            }]}), encoding="utf-8")
            repair_answer = {"decision": "REPAIR", "explanation": "accept the entry",
                             "remaining_uncertainties": [], "edits": [{
                                 "source_file_path": authenticator, "symbol": "Authenticator",
                                 "original_code": "private val keyPair: KeyPair",
                                 "corrected_code": "private val keyEntry: KeyStore.PrivateKeyEntry",
                                 "reason": "accept the entry the corrected callers pass"}]}
            calls = []

            class FakeProvider:
                def __init__(self, **_kwargs):
                    pass

                def generate(self, prompt, _system, **kwargs):
                    calls.append((kwargs.get("schema_name"), prompt))
                    if kwargs.get("schema_name") == "behavior_review":
                        return json.dumps({"regressions": [], "rationale": "same behaviour"})
                    return json.dumps(repair_answer)

            argv = ["repair", "--execution-report", str(report_path),
                    "--output-dir", str(root / "out")]
            with patch.object(repair, "OpenAIProvider", FakeProvider), \
                    patch.object(repair, "commit_repair", return_value="c0ffee"), \
                    patch.object(repair, "_verified_imports", return_value=[]), \
                    patch.object(repair, "_file_at", lambda _repo, _commit, path: {
                        case.CALLER: case.BASE_CALLER,
                        authenticator: case.AUTHENTICATOR}.get(path, "")), \
                    patch.object(sys, "argv", argv):
                code = repair.main()
            artifact = json.loads((root / "out" / "gate_validation_fix.json").read_text(
                encoding="utf-8"))
            solution = json.loads(report_path.read_text(encoding="utf-8"))[
                "per_solution_details"][0]

        self.assertEqual(code, 0)
        self.assertEqual([name for name, _ in calls],
                         ["validation_compiler_repair", "behavior_review"])
        self.assertIn("authentication still signs the challenge", calls[1][1])
        self.assertIn("class Authenticator(private val keyPair: KeyPair", calls[1][1])
        self.assertEqual(artifact["status"], "success")
        self.assertEqual(artifact["files_beyond_plan"], [authenticator])
        self.assertEqual(artifact["editable_declarations"][0]["source_file_path"], authenticator)
        self.assertEqual(artifact["applied_edits"][0]["repair_scope"],
                         "patch_consequence_declaration")
        self.assertEqual(artifact["behavior_review_after_repair"]["status"], "reviewed")
        self.assertIn(authenticator, solution["changed_files"])
        self.assertTrue(solution["summary_stale"])
        self.assertEqual(
            solution["publication_blocker_record"]["behavior_review"]["status"], "reviewed")
