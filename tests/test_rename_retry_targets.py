"""A rename whose callers disagree regenerates the callers with the declaration."""
import unittest

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.semantic_validation import semantic_validation_retry_targets  # noqa: E402

GENERAL = "src/main/java/org/example/General.kt"
MANAGER = "src/main/java/org/example/SubredditManager.java"
TEST = "src/test/java/org/example/SubredditManagerTest.java"


class RenameRetryTargetTests(unittest.TestCase):
    def test_the_unchanged_caller_is_regenerated_with_the_declaration(self):
        errors = [{"code": "RENAME_REFERENCES_NOT_UPDATED", "path": GENERAL,
                   "details": [MANAGER], "retry_paths": [GENERAL, MANAGER]}]
        self.assertEqual(semantic_validation_retry_targets(errors, [GENERAL, MANAGER, TEST]),
                         {GENERAL, MANAGER})

    def test_a_path_only_error_still_targets_its_file_alone(self):
        errors = [{"code": "RENAME_TARGET_ALREADY_DECLARED", "path": GENERAL,
                   "details": ["legacyDigest is already declared"]}]
        self.assertEqual(semantic_validation_retry_targets(errors, [GENERAL, MANAGER, TEST]),
                         {GENERAL})

    def test_every_reference_file_is_regenerated_and_told_its_stale_lines(self):
        import tempfile
        from pathlib import Path

        from cognalys.llm.semantic_validation import rename_issues

        importer = "src/main/java/org/example/Importer.kt"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path, text in {
                GENERAL: "package org.example\n\nfun md5(b: ByteArray) = d(b, \"MD5\")\n",
                MANAGER: "class SubredditManager { String k() { return GeneralKt.md5(x); } }\n",
                importer: "package org.other\n\nimport org.example.md5\n\nval h = md5(y)\n",
            }.items():
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(text, encoding="utf-8")
            error = {"repository_path": str(root), "rename_safety": {
                "allowed": True, "symbol": "md5", "hard_blockers": [],
                "declaration": {"path": GENERAL, "line": 3},
                "declarations": [{"path": GENERAL, "line": 3}],
                "references": [{"path": MANAGER, "line": 1, "kind": "call"},
                               {"path": importer, "line": 3, "kind": "import"},
                               {"path": importer, "line": 5, "kind": "call"}]}}
            edits = [
                {"source_file_path": GENERAL, "original_code": "fun md5(b: ByteArray) = d(b, \"MD5\")\n",
                 "corrected_code": "fun sha256(b: ByteArray) = d(b, \"SHA-256\")\n"},
                {"source_file_path": importer, "original_code": "val h = md5(y)\n",
                 "corrected_code": "val h = sha256(y)\n"},
            ]
            errors, _ = rename_issues(error, edits)
        self.assertEqual(errors[0]["code"], "RENAME_REFERENCES_NOT_UPDATED")
        self.assertEqual(semantic_validation_retry_targets(errors, [GENERAL, MANAGER, importer]),
                         {GENERAL, MANAGER, importer})
        self.assertIn(f"{importer}:3: import org.example.md5", errors[0]["details"])
        self.assertIn(f"{MANAGER}:1:", errors[0]["hint"])

    def test_the_retry_takes_the_non_rename_route_when_the_rename_cannot_be_made(self):
        from cognalys.llm.semantic_validation import rename_retry_guidance

        outside = [{"code": "RENAME_REFERENCES_NOT_UPDATED", "path": GENERAL,
                    "retry_paths": [GENERAL, MANAGER]}]
        guidance = rename_retry_guidance(outside, [GENERAL], last_attempt=False)
        self.assertIn(f"not part of this change: {MANAGER}", guidance)
        self.assertIn("never a maintainer approval", guidance)
        hard = [{"code": "UNAUTHORIZED_RENAME", "path": GENERAL, "retry_paths": [GENERAL]}]
        self.assertIn("Take the non-rename route now",
                      rename_retry_guidance(hard, [GENERAL], last_attempt=False))
        # A retry that can still rename is told the rule, not the fallback.
        fixable = [{"code": "RENAME_REFERENCES_NOT_UPDATED", "path": GENERAL,
                    "retry_paths": [GENERAL, MANAGER]}]
        self.assertNotIn("non-rename route",
                         rename_retry_guidance(fixable, [GENERAL, MANAGER], last_attempt=False))
        self.assertIn("Take the non-rename route now",
                      rename_retry_guidance(fixable, [GENERAL, MANAGER], last_attempt=True))
        self.assertEqual(rename_retry_guidance([{"code": "OTHER"}], [GENERAL], True), "")

    def test_only_what_the_build_or_a_reader_settles_is_left_to_review(self):
        """BlueGate (2026-10-29): the non-rename attempt failed a rename check
        again and the draft became an issue."""
        import tempfile
        from pathlib import Path

        from cognalys.llm.semantic_validation import (
            demote_rename_checks_left_to_review, rename_check_left_to_review)

        jvm = "shared/src/jvmMain/kotlin/org/example/General.kt"
        unit_test = "src/test/java/org/example/GeneralTest.kt"
        with tempfile.TemporaryDirectory() as directory:
            error = {"repository_path": directory}
            edits = [{"source_file_path": GENERAL}]

            def left(item, edited=edits):
                return rename_check_left_to_review(error, item, edited)

            stale = {"code": "RENAME_REFERENCES_NOT_UPDATED", "path": GENERAL,
                     "details": [f"{GENERAL}: 1 reference(s) to md5 must move to sha256"],
                     "stale_paths": [GENERAL]}
            self.assertTrue(left(stale))
            # A source set the debug build does not compile proves nothing.
            self.assertFalse(left({**stale, "stale_paths": [GENERAL, jvm]}))
            # A test file is compiled only once the patch edits it.
            self.assertFalse(left({**stale, "stale_paths": [unit_test]}))
            self.assertTrue(left({**stale, "stale_paths": [unit_test]},
                                 [*edits, {"source_file_path": unit_test}]))
            self.assertFalse(left({**stale, "stale_paths": []}))
            self.assertTrue(left({"code": "RENAME_PARTIAL_FAMILY", "path": GENERAL}))
            named = {"code": "NAME_CONTRADICTS_BEHAVIOR", "path": GENERAL, "name": "decryptDES",
                     "removed_behavior": "des", "details": ["decryptDES still states des"]}
            self.assertTrue(left(named))
            # An accept-all selector whose branch now validates is behaviour.
            self.assertFalse(left({"code": "NAME_CONTRADICTS_BEHAVIOR", "name": "trustAllCerts"}))
            for code in ("UNAUTHORIZED_RENAME", "RENAME_CALL_REBINDS",
                         "RENAME_TARGET_ALREADY_DECLARED"):
                self.assertFalse(left({**stale, "code": code}))
            self.assertFalse(rename_check_left_to_review({}, stale, edits))

            validation = {"status": "invalid", "errors": [stale, named],
                          "warnings": [{"code": "API_21_RUNTIME_VALIDATION_REQUIRED"}]}
            demoted = demote_rename_checks_left_to_review(error, validation, edits)
            self.assertEqual(demoted["status"], "valid")
            self.assertEqual(demoted["errors"], [])
            self.assertEqual([item["code"] for item in demoted["warnings"]],
                             ["API_21_RUNTIME_VALIDATION_REQUIRED",
                              "RENAME_REFERENCES_NOT_UPDATED", "NAME_CONTRADICTS_BEHAVIOR"])
            self.assertTrue(all(item["maintainer_decides"] for item in demoted["warnings"][1:]))
            mixed = {"status": "invalid", "errors": [stale, {"code": "UNINTENDED_BEHAVIOR_CHANGE"}]}
            self.assertIs(demote_rename_checks_left_to_review(error, mixed, edits), mixed)

    def test_the_publication_verdict_names_what_the_rename_check_left(self):
        from cognalys.llm.coordinated_generation import REVIEW_CONTRACT_VERSION
        from cognalys.utils.disposition import publication_after_validation

        verdict = publication_after_validation({
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "build_validation": {"status": "passed"}, "commit_hash": "abc",
            "review_contract_version": REVIEW_CONTRACT_VERSION,
            "semantic_validation": {"status": "valid", "errors": [], "warnings": [{
                "code": "NAME_CONTRADICTS_BEHAVIOR", "details": ["decryptDES still states des"],
                "maintainer_decides": True, "rename_check_left_to_review": True}]},
        })
        self.assertIn("rename check left to review: NAME_CONTRADICTS_BEHAVIOR: "
                      "decryptDES still states des", verdict["notes"])

    def test_a_kept_variable_or_selector_is_not_told_to_keep_its_name(self):
        """The non-rename route governs functions; a variable's own message
        says to rename it (review of D, 2026-10-29)."""
        from cognalys.llm.semantic_validation import (
            accept_all_name_contradictions, rename_only_failure, rename_retry_guidance,
            validate_coordinated_semantics, variable_name_contradictions)

        variable = variable_name_contradictions(
            'val md5Key = digest("MD5")', 'val md5Key = digest("SHA-256")')
        self.assertEqual([item["subject"] for item in variable], ["variable"])
        selector = accept_all_name_contradictions(
            "if (trustAllCerts) { return object : X509TrustManager {\n"
            "  override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}\n"
            "} }\n",
            "if (trustAllCerts) { return TrustManagerFactory.getInstance(\"X509\") }\n")
        for item in [*variable, *selector]:
            self.assertTrue(rename_only_failure([item]))
            self.assertEqual(rename_retry_guidance([item], [GENERAL], last_attempt=True), "")
        function = {"code": "NAME_CONTRADICTS_BEHAVIOR", "name": "decryptDES",
                    "removed_behavior": "des"}
        self.assertIn("Take the non-rename route now",
                      rename_retry_guidance([*variable, function], [GENERAL], True))
        # validate_coordinated_semantics carries the subject onto its error.
        # An empty repository of its own: without repository_path the checks
        # read the working directory, which in the main checkout holds every
        # cloned app under outputs/ (2026-10-30: the test failed there only).
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            validation = validate_coordinated_semantics({"repository_path": directory}, [{
                "source_file_path": GENERAL, "symbol": "key",
                "original_code": 'fun key() {\n    val md5Key = digest("MD5")\n}\n',
                "corrected_code": 'fun key() {\n    val md5Key = digest("SHA-256")\n}\n'}])
        named = [item for item in validation["errors"]
                 if item.get("code") == "NAME_CONTRADICTS_BEHAVIOR"]
        self.assertEqual([item.get("subject") for item in named], ["variable"])

    def test_the_port_gate_does_not_refuse_what_the_draft_left_to_review(self):
        """A port to the base tip runs the generation's gates again; a kept
        md5Hex now computing SHA-256, left to review by the draft, was
        refused there and the port became an issue (review of D, 2026-10-29)."""
        import tempfile
        from pathlib import Path

        from cognalys.llm.semantic_validation import (
            demote_rename_checks_left_to_review, validate_coordinated_semantics)
        from cognalys.validation.repair import semantic_regressions

        original = ('    fun md5Hex(data: ByteArray): String {\n'
                    '        val digest = MessageDigest.getInstance("MD5")\n'
                    '        return digest.digest(data).toString()\n'
                    '    }')
        corrected = original.replace('"MD5"', '"SHA-256"')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / GENERAL).parent.mkdir(parents=True)
            (root / GENERAL).write_text(
                "package org.example\n\nobject General {\n" + original + "\n}\n",
                encoding="utf-8")
            edit = {"source_file_path": GENERAL, "symbol": "md5Hex", "edit_kind": "method",
                    "original_code": original, "corrected_code": corrected}
            error = {"repository_path": directory, "method_name": "md5Hex",
                     "source_file_path": GENERAL}
            validation = validate_coordinated_semantics(error, [edit])
            self.assertEqual([item["code"] for item in validation["errors"]],
                             ["NAME_CONTRADICTS_BEHAVIOR"])
            left = demote_rename_checks_left_to_review(error, validation, [edit])
            self.assertEqual(left["status"], "valid")
            ported = [{"source_file": GENERAL, "symbol": "md5Hex",
                       "original_code": original, "corrected_code": corrected}]
            solution = {"method_name": "md5Hex", "source_file_path": GENERAL,
                        "changed_files": [GENERAL]}
            self.assertEqual([item["code"] for item in semantic_regressions(
                root, solution, ported)], ["NAME_CONTRADICTS_BEHAVIOR"])
            self.assertEqual(semantic_regressions(
                root, {**solution, "semantic_validation": left}, ported), [])
            # From the execution report, where the warnings are review_blockers.
            self.assertEqual(semantic_regressions(
                root, {**solution, "review_blockers": left["warnings"]}, ported), [])
            # Another name is the port's own objection.
            other = [{**item, "name": "sha1Hex"} for item in left["warnings"]]
            self.assertEqual([item["code"] for item in semantic_regressions(
                root, {**solution, "review_blockers": other}, ported)],
                ["NAME_CONTRADICTS_BEHAVIOR"])

    def test_retry_paths_outside_the_plan_are_ignored(self):
        errors = [{"code": "RENAME_REFERENCES_NOT_UPDATED", "path": GENERAL,
                   "details": ["Other.java"], "retry_paths": [GENERAL, "Other.java"]}]
        self.assertEqual(semantic_validation_retry_targets(errors, [GENERAL, MANAGER]),
                         {GENERAL})


class RedraftedBehaviourTakesTestsTests(unittest.TestCase):
    """A production file redrafted to behave otherwise takes the planned
    tests with it: they were written for the draft being replaced (Session
    writeEntry, 2026-11-10)."""

    def test_a_production_regression_regenerates_the_planned_tests(self):
        errors = [{"code": "UNINTENDED_BEHAVIOR_CHANGE", "affected_paths": [MANAGER]}]
        self.assertEqual(semantic_validation_retry_targets(errors, [GENERAL, MANAGER, TEST]),
                         {MANAGER, TEST})

    def test_a_joint_edit_without_effect_regenerates_the_planned_tests(self):
        log_file = "app/src/main/java/org/thoughtcrime/securesms/logging/LogFile.java"
        log_test = ("app/src/test/java/org/thoughtcrime/securesms/logging/"
                    "LogFileKeyEncodingRegressionTest.java")
        errors = [{"code": "JOINT_FINDING_EDIT_WITHOUT_EFFECT", "affected_paths": [log_file]}]
        self.assertEqual(semantic_validation_retry_targets(errors, [log_file, log_test]),
                         {log_file, log_test})

    def test_a_dropped_input_or_a_wider_explicit_default_regenerates_the_planned_tests(self):
        for code in ("DROPPED_INPUT_NO_LONGER_CONTRIBUTES",
                     "EXPLICIT_DEFAULT_CHANGE_TOUCHES_MORE"):
            with self.subTest(code=code):
                errors = [{"code": code, "affected_paths": [GENERAL]}]
                self.assertEqual(
                    semantic_validation_retry_targets(errors, [GENERAL, MANAGER, TEST]),
                    {GENERAL, TEST})

    def test_a_regression_only_in_the_test_regenerates_the_test_alone(self):
        errors = [{"code": "UNINTENDED_BEHAVIOR_CHANGE", "affected_paths": [TEST]}]
        self.assertEqual(semantic_validation_retry_targets(errors, [GENERAL, MANAGER, TEST]),
                         {TEST})

    def test_a_compile_fix_keeps_the_tests(self):
        errors = [{"code": "SYMBOL_NOT_DECLARED_IN_REPOSITORY", "path": MANAGER}]
        self.assertEqual(semantic_validation_retry_targets(errors, [GENERAL, MANAGER, TEST]),
                         {MANAGER})

    def test_a_production_file_named_like_a_test_is_production(self):
        attestation = ("platform/android/src/main/kotlin/org/example/attestation/"
                       "AndroidAttestation.kt")
        attestation_test = ("platform/android/src/test/kotlin/org/example/attestation/"
                            "AttestationVerifierTest.kt")
        errors = [{"code": "UNINTENDED_BEHAVIOR_CHANGE", "affected_paths": [attestation]}]
        self.assertEqual(semantic_validation_retry_targets(errors, [attestation, attestation_test]),
                         {attestation, attestation_test})
        self.assertEqual(semantic_validation_retry_targets(errors, [attestation]), {attestation})

    def test_every_code_the_reviewed_draft_returns_is_classified(self):
        """A new code returned to the retry loop must decide whether it takes
        the planned tests."""
        import inspect
        import re

        from cognalys.llm import coordinated_generation
        from cognalys.llm.semantic_validation import _REDRAFTED_BEHAVIOUR_CODES

        codes = set(re.findall(r'"code": "([A-Z_]+)"', inspect.getsource(coordinated_generation)))
        self.assertEqual(codes, set(_REDRAFTED_BEHAVIOUR_CODES))


if __name__ == "__main__":
    unittest.main()
