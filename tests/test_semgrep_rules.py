"""The Semgrep oracles: each rule against a vulnerable and a repaired method.

Every rule in data/detector_rules/semgrep is run on the fixtures listed in
tests/fixtures/detector_rules/cases.json: the vulnerable version must fire
in the reported method and the usual repair must not. A repair that still
fired would be scored `unchanged`, and the patch `incorrect`, so the repaired
fixtures matter as much as the vulnerable ones -- including one with the
repair inside `try { }`, where Semgrep's own Kotlin matching was too weak.

The rule tests need semgrep and are skipped without it; the method-span
and method-condition tests do not.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.validation import semgrep_rules  # noqa: E402
from cognalys.validation.detector_replay import (  # noqa: E402
    adapter_for_finding, declares_method,
)

FIXTURES = ROOT / "tests" / "fixtures" / "detector_rules"
CASES = json.loads((FIXTURES / "cases.json").read_text(encoding="utf-8"))["cases"]


@unittest.skipUnless(semgrep_rules.find_semgrep(), "semgrep is not installed")
class RuleCaseTests(unittest.TestCase):

    def test_every_case(self):
        for case in CASES:
            with self.subTest(file=case["file"]):
                result = semgrep_rules.replay(
                    FIXTURES / case["file"], case["spec"], case["method"],
                )
                self.assertEqual(result["status"], case["expect"],
                                 result.get("detail"))
                self.assertEqual(result["match_scope"], "method")

    def test_every_rule_has_a_vulnerable_and_a_repaired_case(self):
        covered = {case["spec"]: set() for case in CASES}
        for case in CASES:
            covered[case["spec"]].add(case["expect"])
        for path in semgrep_rules.rule_files():
            with self.subTest(rule=path.stem):
                self.assertEqual(covered.get(path.stem),
                                 {"alert_present", "alert_absent"})

    def test_a_repaired_patch_is_credited_through_the_adapter(self):
        adapter = adapter_for_finding("static:manual", "ZipSlipSpec")
        pair = adapter.replay_pair(
            FIXTURES / "ZipSlipSpec/positive_in_try.kt",
            FIXTURES / "ZipSlipSpec/fixed_in_try.kt",
            "ZipSlipSpec", "restore",
        )
        self.assertEqual(pair["outcome"], "repaired")

    def test_an_unrepaired_patch_is_unchanged(self):
        adapter = adapter_for_finding("static:manual", "WebViewDebuggingSpec")
        pair = adapter.replay_pair(
            FIXTURES / "WebViewDebuggingSpec/positive.kt",
            FIXTURES / "WebViewDebuggingSpec/positive.kt",
            "WebViewDebuggingSpec", "setupWebView",
        )
        self.assertEqual(pair["outcome"], "unchanged")


class AdapterTests(unittest.TestCase):

    def test_a_tool_with_its_own_adapter_keeps_it(self):
        self.assertEqual(adapter_for_finding("pmd", "ZipSlipSpec").tool, "pmd")

    def test_a_specification_with_a_rule_gets_semgrep(self):
        self.assertEqual(adapter_for_finding("static:manual", "ZipSlipSpec").tool,
                         "semgrep")

    def test_a_specification_without_a_rule_gets_nothing(self):
        self.assertIsNone(adapter_for_finding("static:manual", "HardcodedSecretSpec"))

    def test_a_path_like_specification_name_is_refused(self):
        self.assertIsNone(semgrep_rules.rule_file("../../etc/passwd"))


class MethodSpanTests(unittest.TestCase):

    def test_a_kotlin_block_body(self):
        source = "class A {\n    fun f(x: Int): Int {\n        return x\n    }\n}\n"
        self.assertEqual(semgrep_rules.method_span(source, "f", ".kt"), (2, 4))

    def test_a_kotlin_expression_body_with_a_lambda_default(self):
        source = ("class A {\n"
                  "    suspend fun f(cb: () -> Unit = {}): Int = run {\n"
                  "        1\n"
                  "    }\n"
                  "    fun g() {}\n"
                  "}\n")
        self.assertEqual(semgrep_rules.method_span(source, "f", ".kt"), (2, 4))

    def test_braces_in_strings_do_not_end_the_method(self):
        source = ('class A {\n    void f() {\n        String s = "}";\n'
                  '        call();\n    }\n}\n')
        self.assertEqual(semgrep_rules.method_span(source, "f", ".java"), (2, 5))

    def test_an_unknown_method_is_none(self):
        self.assertIsNone(semgrep_rules.method_span("class A {}", "g", ".kt"))

    def test_a_numbered_anonymous_class_is_the_nth_of_its_class(self):
        """ToFShare (2026-10-31): MaintenanceActivity$8.onClick was replayed on
        the first onClick of the file."""
        source = ("public class A extends Activity {\n"
                  "    void onCreate() {\n"
                  "        b1.setOnClickListener(new View.OnClickListener() {\n"
                  "            public void onClick(View v) {\n"
                  "                new Thread() { public void run() {} }.start();\n"
                  "            }\n"
                  "        });\n"
                  "        b2.setOnClickListener(new View.OnClickListener() {\n"
                  "            public void onClick(View v) {\n"
                  "                SSLContext.getInstance(\"TLS\");\n"
                  "            }\n"
                  "        });\n"
                  "    }\n"
                  "    class Inner { void onClick(View v) {} }\n"
                  "}\n")
        span = semgrep_rules.method_span
        self.assertEqual(span(source, "onClick", ".java", "x.A$2"), (9, 11))
        self.assertEqual(span(source, "onClick", ".java", "x.A$1"), (4, 6))
        self.assertEqual(span(source, "onClick", ".java", "x.A$Inner"), (14, 14))
        self.assertIsNone(span(source, "onClick", ".java", "x.A$3"))
        self.assertEqual(span(source, "onClick", ".java"), (4, 6))


class MethodConditionTests(unittest.TestCase):

    CURSOR = {"beginline": "1", "endline": "1", "metadata": {
        "bind": r"val\s+(?P<C>\w+)\s*=",
        "method_excludes_any": [r"\b{{C}}\s*\??\s*\.\s*use\s*\{"],
    }}

    def test_an_exclusion_bound_to_the_matched_variable(self):
        source = "val cursor = dm.query(q)\ncursor.use { }\n"
        holds, _ = semgrep_rules.method_conditions_hold(self.CURSOR, source, source)
        self.assertFalse(holds)

    def test_another_variable_does_not_exclude_the_match(self):
        source = "val cursor = dm.query(q)\nother.use { }\n"
        holds, _ = semgrep_rules.method_conditions_hold(self.CURSOR, source, source)
        self.assertTrue(holds)

    def test_an_unbound_placeholder_never_excludes(self):
        violation = {"beginline": "1", "metadata": {
            "method_excludes_any": [r"{{MISSING}}"],
        }}
        holds, _ = semgrep_rules.method_conditions_hold(violation, "anything", "x")
        self.assertTrue(holds)


class KotlinDeclarationTests(unittest.TestCase):
    """A Kotlin method is not reported as removed because it is Kotlin."""

    def test_a_kotlin_function_is_declared(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "A.kt"
            path.write_text("class A {\n  private fun setupWebView(): Unit {\n  }\n}\n",
                            encoding="utf-8")
            self.assertTrue(declares_method(path, "setupWebView"))
            path.write_text("class A {\n}\n", encoding="utf-8")
            self.assertFalse(declares_method(path, "setupWebView"))


class ConstraintOracleTests(unittest.TestCase):
    """The replay checks the kind of constraint the finding reported.

    PassNotes and Feeder (exp_final_20261019) reported an app-defined
    TrustManager; the SSLContextSpec rule checks the protocol literal, which
    the correct patch kept as "TLS", and the pair read as unchanged.
    """

    def test_rules_declare_the_kinds_they_check(self):
        checks = semgrep_rules.rule_checks("SSLContextSpec")
        self.assertEqual(checks, {"sslcontext-disallowed-protocol-or-default":
                                  frozenset({"PROTO", "ALG"})})
        self.assertEqual(semgrep_rules.rule_checks("NoSuchSpec"), {})

    def test_the_kind_comes_from_the_detector_code_or_context(self):
        kind = semgrep_rules.constraint_kind
        self.assertEqual(kind({"detector_code": "SSLCONTEXT-NOBS-03"}), "NOBS")
        self.assertEqual(kind({"detector_context": {"site_kind": "ALG: not allowed"}}), "ALG")
        self.assertEqual(kind({"detector_context": {"code": "MESSAGEDIGEST-ALG-02"}}), "ALG")
        self.assertEqual(kind({}), "")

    def test_a_kind_no_rule_checks_is_no_oracle_not_an_unchanged_pair(self):
        from cognalys.validation.detector_replay import CONSTRAINT_NOT_COVERED, replay_pair

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Client.kt"
            source.write_text('fun build() { SSLContext.getInstance("TLS") }\n', encoding="utf-8")
            pair = replay_pair(source, source, "SSLContextSpec", "build",
                               replay_fn=semgrep_rules.replay, constraint_kind="NOBS")
        self.assertEqual(pair["outcome"], CONSTRAINT_NOT_COVERED)

    def test_patch_correctness_reports_the_missing_oracle(self):
        from cognalys.evaluation.patch_correctness import assess

        result = assess({"status": "success",
                         "detector_replay": {"outcome": "constraint_not_covered"}})
        self.assertIn("no_executable_oracle_for_this_constraint", result["missing"])
        self.assertNotEqual(result["verdict"], "incorrect")


class EnumConstantBodyTests(unittest.TestCase):
    """javac numbers a top-level enum's constant bodies Outer$1, ... (2026-11-01 review)."""

    def test_an_enum_with_constant_bodies_is_not_followed(self):
        source = ("public enum Mode {\n  A { void run() { } },\n  B;\n"
                  "  void x() { Runnable r = new Runnable() { public void run() { int a = 1; } }; }\n}\n")
        self.assertIsNone(semgrep_rules.method_span(source, "run", ".java", "com.x.Mode$1"))

    def test_an_enum_without_constant_bodies_numbers_its_anonymous_classes(self):
        source = ("public enum Mode {\n  A, B;\n"
                  "  void x() { Runnable r = new Runnable() { public void run() { int a = 1; } }; }\n}\n")
        self.assertEqual(semgrep_rules.method_span(source, "run", ".java", "com.x.Mode$1"), (3, 3))


if __name__ == "__main__":
    unittest.main()
