import json
import os
import sys
import tempfile
import unittest
import logging
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

# Import each name from the module that owns it, not from the
# generate_error_fixes shim. The shim re-exports ~50 names purely so
# older callers keep working; addressing it here would leave the extracted
# modules with no test that names them, and would silently no-op any future
# patch of a collaborator that now resolves inside one of them.
from cognalys.llm.code_quality import coordinated_quality_metrics  # noqa: E402
from cognalys.llm.fix_artifacts import (  # noqa: E402
    compact_evidence_context,
    coordinated_fix_explanation,
    format_elapsed_time,
    persist_context_snapshot,
)
from cognalys.llm import evidence_requests  # noqa: E402
from cognalys.llm import semantic_validation  # noqa: E402
from cognalys.llm.evidence_requests import (  # noqa: E402
    catalog_supplement,
    classify_evidence_request,
    requested_type_names,
    resolve_evidence_requests,
)
from cognalys.llm.generate_error_fixes import (  # noqa: E402
    ISSUE_PRESENTATION_FIELDS,
    FixGenerator,
    post_validation_issue_candidate,
)
from cognalys.llm.llm_providers import OpenAIProvider  # noqa: E402
from cognalys.llm.llm_schemas import (  # noqa: E402
    coordinated_fix_schema,
    evidence_analysis_schema,
)
from cognalys.llm.migration_policy import (  # noqa: E402
    generic_migration_policy,
    nondigest_fallback_evidence,
    promote_bounded_digest_discriminator_review,
    promote_policy_authorized_tls_review,
    promote_validation_repair_sources,
)
from cognalys.llm.pipeline_architecture import (  # noqa: E402
    FindingEvidencePacketBuilder,
    PolicyRegistry,
)
from cognalys.llm.prompt_builders import declared_api_surface  # noqa: E402
from cognalys.llm.semantic_validation import (  # noqa: E402
    _validate_patch_plan,
    minimum_planned_files,
    normalize_coordinated_edit,
    repository_has_test_infrastructure,
    semantic_validation_retry_targets,
    validate_coordinated_edit_shape,
    identity_equality_assertions,
    unresolvable_constructor_calls,
    unresolved_repository_symbols,
    validate_coordinated_semantics,
    validate_multi_file_scope,
)
from cognalys.llm.adjudication import _analysis_record  # noqa: E402


class _Response:
    status_code = 200
    text = ""

    @staticmethod
    def json():
        return {"output_text": '{"decision":"NO_SAFE_FIX"}', "usage": {}}


class _Session:
    def __init__(self):
        self.payloads = []

    def post(self, _url, **kwargs):
        self.payloads.append(kwargs["json"])
        return _Response()


class _DraftProvider:
    context_length = 16384

    def generate(self, prompt, *_args, **_kwargs):
        import json
        marker = '"target_file":'
        relative = json.JSONDecoder().raw_decode(
            prompt.split(marker, 1)[1].lstrip())[0]
        return json.dumps({
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "source_file_path": relative,
            "explanation": "file edit",
            "edits": [{
                "source_file_path": relative, "symbol": "value",
                "edit_kind": "test" if "Test" in relative else "declaration",
                "original_code": "int value = 1;",
                "corrected_code": "int value = 2;", "reason": "coordinated",
            }],
            "provided_contracts": [relative + ":value"],
            "required_contracts": [], "required_tests": ["round trip"],
            "manual_review_required": True,
            "review_assumptions": ["review lifecycle"],
            "confidence": "medium",
        })


class ProcessErrorEvidencePersistenceTests(unittest.TestCase):
    def test_review_only_decision_initializes_detector_context_before_persisting(self):
        class _TokenProvider:
            provider_name = "test"

            @staticmethod
            def get_token_usage():
                return {"input": 0, "output": 0}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            source = repo / "src" / "PwsFile.java"
            source.parent.mkdir(parents=True)
            source.write_text("class PwsFile {}", encoding="utf-8")
            input_file = root / "app.apk" / "2_getCipher.json"
            input_file.parent.mkdir()

            generator = FixGenerator(
                input_dir=input_file.parent,
                output_dir=root / "out",
                provider=_TokenProvider(),
                logger=logging.getLogger("review-only-regression"),
                api_logger=logging.getLogger("review-only-regression-api"),
            )
            analysis = {
                "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                "confirmed_cause": "AES/CTR does not authenticate ciphertext",
                "cause_status": "confirmed",
                "detector_violation": "confirmed",
                "scope_assessment": {"status": "complete"},
                "coordinated_fix_plan": {"required_edits": []},
            }
            error = {
                "_file_path": input_file,
                "repository_path": str(repo),
                "source_file_path": "src/PwsFile.java",
                "method_name": "getCipher",
                "csv_class": "org.pwsafe.lib.file.PwsFile",
                "method_body": "Cipher.getInstance(\"AES/CTR/NoPadding\")",
                "spec": "CipherSpec",
                "error_message": "authenticated encryption required",
                "unique_error_id": (
                    "org.pwsafe.lib.file.PwsFile:::getCipher:::CipherSpec:::"
                    "UnsafeAlgorithm:::authenticated encryption required"
                ),
                "expanded_repository_context": {"multi_file_impact": {}},
            }

            with (
                patch.object(
                    generator, "adjudicate_finding",
                    return_value=(analysis, {}),
                ),
                patch.object(
                    generator, "generate_coordinated_file_drafts",
                    return_value={"status": "failed", "issues": ["stop after persistence"]},
                ),
                patch.object(generator, "persist_blocked_issue_candidate"),
            ):
                result = generator.process_finding(error)

            self.assertIsNone(result.solution)
            self.assertFalse(result.success)
            self.assertEqual(result.outcome, "abstained")
            evidence_file = (
                root / "out" / "evidence_reviews" / "app.apk"
                / "0_getCipher_evidence.json"
            )
            persisted = json.loads(evidence_file.read_text(encoding="utf-8"))
            self.assertEqual(persisted["status"], "PROPOSED_FIX_REQUIRES_REVIEW")
            self.assertEqual(persisted["reported_violation"], "UnsafeAlgorithm")
            self.assertEqual(persisted["observed_unmodelled_calls"], [])


class RepositoryHasTestInfrastructureTests(unittest.TestCase):
    def test_false_for_a_repository_with_no_test_directory_or_file(self):
        with tempfile.TemporaryDirectory() as directory:
            repo_root = Path(directory)
            (repo_root / "src").mkdir()
            (repo_root / "src" / "Client.java").write_text("class Client {}")
            self.assertFalse(repository_has_test_infrastructure(repo_root))

    def test_true_for_an_existing_test_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            repo_root = Path(directory)
            (repo_root / "app" / "src" / "androidTest").mkdir(parents=True)
            self.assertTrue(repository_has_test_infrastructure(repo_root))

    def test_true_for_an_existing_test_file_without_a_test_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            repo_root = Path(directory)
            (repo_root / "src").mkdir()
            (repo_root / "src" / "ClientTest.kt").write_text("class ClientTest")
            self.assertTrue(repository_has_test_infrastructure(repo_root))

    def test_false_for_a_missing_repository_path(self):
        self.assertFalse(repository_has_test_infrastructure(Path("")))


class MinimumPlannedFilesTests(unittest.TestCase):
    def test_review_only_decisions_need_only_one_file(self):
        for decision in (
            "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "BACKEND_MIGRATION_REQUIRED_REVIEW_ONLY",
            "MULTI_REPOSITORY_MIGRATION_SUPPORTED",
        ):
            self.assertEqual(minimum_planned_files(decision), 1)

    def test_auto_apply_multi_file_decision_still_needs_two(self):
        self.assertEqual(minimum_planned_files("MULTI_FILE_FIX_SUPPORTED"), 2)


class ValidateMultiFileScopeTests(unittest.TestCase):
    @staticmethod
    def _error():
        return {
            "case_migration_policy": {},
            "expanded_repository_context": {"multi_file_impact": {
                "status": "available",
                "multi_file_candidate": True,
                "coverage_requirements": {},
                "scope_completeness": {"status": "complete"},
            }},
        }

    @staticmethod
    def _analysis(decision: str, paths: list) -> dict:
        return {
            "decision": decision,
            "scope_assessment": {
                "status": "complete",
                "local_code_scope": "complete",
                "unresolved_relations": [],
                "reviewed_files": [],
                "multi_file_change_required": True,
            },
            "coordinated_fix_plan": {"required_edits": [
                {"source_file_path": path} for path in paths
            ]},
        }

    def test_review_only_decision_accepts_a_single_correctly_scoped_file(self):
        # Regression test: a real finding (crazyfliecontrol2's TLSSocketFactory)
        # had a fully evidenced, correctly-scoped one-file fix rejected here
        # purely because MULTI_FILE_FIX_PROPOSED_FOR_REVIEW was treated as
        # requiring two files, even though the decision is always reviewed
        # by a human before merge regardless of file count.
        issues = validate_multi_file_scope(
            self._error(),
            self._analysis(
                "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                ["src/TLSSocketFactory.java"],
            ),
        )
        self.assertEqual(issues, [])

    def test_auto_apply_decision_still_requires_two_files(self):
        issues = validate_multi_file_scope(
            self._error(),
            self._analysis(
                "MULTI_FILE_FIX_SUPPORTED", ["src/TLSSocketFactory.java"],
            ),
        )
        self.assertTrue(
            any("at least two distinct files" in issue for issue in issues)
        )

    def test_auto_apply_decision_accepts_two_files(self):
        issues = validate_multi_file_scope(
            self._error(),
            self._analysis("MULTI_FILE_FIX_SUPPORTED", [
                "src/TLSSocketFactory.java", "src/FirmwareDownloader.java",
            ]),
        )
        self.assertEqual(issues, [])


class UnrelatedTestPlacementGateTests(unittest.TestCase):
    """The deterministic gate every edit set passes, whoever planned it.

    Fixing the TLS planner alone would not stop the model from naming an
    unrelated test file in its own patch plan, so the guarantee has to live in
    validate_coordinated_semantics, where nothing can route around it.
    """

    TARGET = "app/src/main/java/com/nononsenseapps/jsonfeed/OkHttpBuilderExtensions.kt"

    def _error(self):
        return {"source_file_path": self.TARGET, "method_name": "trustAllCerts"}

    def _codes(self, edits):
        return [
            item["code"] for item in
            validate_coordinated_semantics(self._error(), edits)["errors"]
        ]

    def test_rejects_assertions_appended_to_an_unrelated_test(self):
        codes = self._codes([{
            "source_file_path":
                "app/src/androidTest/java/com/nononsenseapps/feeder/DateFormattingTest.kt",
            "edit_kind": "test",
            "original_code": "class DateFormattingTest { fun formats() {} }",
            "corrected_code": "fun tlsFiltering() {}",
        }])
        self.assertIn("TEST_PLACED_IN_UNRELATED_FILE", codes)

    def test_accepts_a_dedicated_new_test_file(self):
        codes = self._codes([{
            "source_file_path":
                "app/src/androidTest/java/com/nononsenseapps/jsonfeed/"
                "OkHttpBuilderExtensionsTlsProtocolTest.kt",
            "edit_kind": "create",
            "original_code": "",
            "corrected_code": "class OkHttpBuilderExtensionsTlsProtocolTest",
        }])
        self.assertNotIn("TEST_PLACED_IN_UNRELATED_FILE", codes)

    def test_accepts_a_test_named_after_the_target(self):
        codes = self._codes([{
            "source_file_path":
                "app/src/androidTest/java/com/nononsenseapps/feeder/"
                "OkHttpBuilderExtensionsTest.kt",
            "edit_kind": "test",
            "original_code": "class OkHttpBuilderExtensionsTest",
            "corrected_code": "fun tls() {}",
        }])
        self.assertNotIn("TEST_PLACED_IN_UNRELATED_FILE", codes)

    def test_accepts_a_test_in_the_targets_package(self):
        codes = self._codes([{
            "source_file_path":
                "app/src/androidTest/java/com/nononsenseapps/jsonfeed/NetworkTest.kt",
            "edit_kind": "test",
            "original_code": "class NetworkTest",
            "corrected_code": "fun tls() {}",
        }])
        self.assertNotIn("TEST_PLACED_IN_UNRELATED_FILE", codes)

    def test_accepts_a_test_that_already_exercises_the_target(self):
        codes = self._codes([{
            "source_file_path":
                "app/src/androidTest/java/com/nononsenseapps/feeder/StackTest.kt",
            "edit_kind": "test",
            "original_code": "fun existing() { builder.trustAllCerts() }",
            "corrected_code": "fun tls() {}",
        }])
        self.assertNotIn("TEST_PLACED_IN_UNRELATED_FILE", codes)

    def test_reads_the_persisted_source_file_key(self):
        """PR metadata renames source_file_path to source_file."""
        codes = self._codes([{
            "source_file":
                "app/src/androidTest/java/com/nononsenseapps/feeder/DateFormattingTest.kt",
            "edit_kind": "test",
            "original_code": "class DateFormattingTest",
            "corrected_code": "fun tls() {}",
        }])
        self.assertIn("TEST_PLACED_IN_UNRELATED_FILE", codes)

    def test_production_edits_are_untouched_by_the_gate(self):
        codes = self._codes([{
            "source_file_path": self.TARGET,
            "edit_kind": "method",
            "original_code": "fun trustAllCerts() {}",
            "corrected_code": "fun trustAllCerts() { filter() }",
        }])
        self.assertNotIn("TEST_PLACED_IN_UNRELATED_FILE", codes)

    def test_retry_regenerates_only_the_offending_test_file(self):
        offending = ("app/src/androidTest/java/com/nononsenseapps/feeder/"
                     "DateFormattingTest.kt")
        targets = semantic_validation_retry_targets(
            [{"code": "TEST_PLACED_IN_UNRELATED_FILE", "details": []}],
            [self.TARGET, offending],
        )
        self.assertEqual(targets, {offending})


class TlsTestPlacementTests(unittest.TestCase):
    """TLS assertions must land in a test that actually covers the target.

    Regression for spacecowboy/Feeder PR #1210: the selector took the first
    test file in the exact-candidate set, so protocol-filtering assertions were
    planned into DateFormattingTest.kt. That file compiles them happily, so no
    downstream gate objected -- the nonsense was only visible to a human.
    """

    TARGET = "app/src/main/java/com/nononsenseapps/jsonfeed/OkHttpBuilderExtensions.kt"

    def _error(self, test_sources: list[dict]):
        policy = generic_migration_policy({
            "spec": "SSLContextSpec",
            "error_message": "expecting one of {TLSv1.2, TLSv1.3} but found TLS.",
            "unique_error_id": "x:::UnsafeProtocol:::found TLS.",
        })
        return {
            "case_migration_policy": policy,
            "csv_class": "com.nononsenseapps.jsonfeed.OkHttpBuilderExtensionsKt",
            "method_name": "trustAllCerts",
            "expanded_repository_context": {"multi_file_impact": {
                "target": {"source_file_path": self.TARGET},
                "scope_completeness": {"status": "complete"},
                "exact_candidate_sources": [
                    {"source_file_path": self.TARGET, "content": "fun trustAllCerts() {}"},
                    *test_sources,
                ],
            }},
        }

    def _plan(self, error):
        promoted = promote_policy_authorized_tls_review(error, {
            "decision": "NO_SAFE_FIX", "predicate_assessment": [],
            "migration_assessment": {},
            "scope_assessment": {"unresolved_relations": []},
        })
        return promoted.get("coordinated_fix_plan", {}).get("required_edits", [])

    def _test_edit(self, edits):
        return next(
            item for item in edits
            if item.get("symbol") == "TLS protocol filtering tests"
        )

    def test_unrelated_test_file_does_not_host_the_tls_tests(self):
        error = self._error([{
            "source_file_path":
                "app/src/androidTest/java/com/nononsenseapps/feeder/DateFormattingTest.kt",
            "content": "class DateFormattingTest { fun formatsDates() {} }",
        }])
        edit = self._test_edit(self._plan(error))
        self.assertNotIn("DateFormatting", edit["source_file_path"])
        self.assertTrue(edit["create_new_file"])
        self.assertTrue(
            edit["source_file_path"].endswith(
                "OkHttpBuilderExtensionsTlsProtocolTest.kt"
            ),
            edit["source_file_path"],
        )

    def test_dedicated_test_is_created_in_the_targets_package(self):
        error = self._error([{
            "source_file_path":
                "app/src/androidTest/java/com/nononsenseapps/feeder/DateFormattingTest.kt",
            "content": "class DateFormattingTest",
        }])
        edit = self._test_edit(self._plan(error))
        self.assertEqual(
            edit["source_file_path"],
            "app/src/androidTest/java/com/nononsenseapps/jsonfeed/"
            "OkHttpBuilderExtensionsTlsProtocolTest.kt",
        )

    def test_name_matched_existing_test_is_reused(self):
        path = ("app/src/androidTest/java/com/nononsenseapps/jsonfeed/"
                "OkHttpBuilderExtensionsTest.kt")
        error = self._error([{"source_file_path": path, "content": "class X"}])
        edit = self._test_edit(self._plan(error))
        self.assertEqual(edit["source_file_path"], path)
        self.assertFalse(edit["create_new_file"])

    def test_existing_test_referencing_the_target_is_reused(self):
        path = ("app/src/androidTest/java/com/nononsenseapps/feeder/"
                "NetworkStackTest.kt")
        error = self._error([{
            "source_file_path": path,
            "content": "import ...OkHttpBuilderExtensions\nclass NetworkStackTest",
        }])
        edit = self._test_edit(self._plan(error))
        self.assertEqual(edit["source_file_path"], path)
        self.assertFalse(edit["create_new_file"])

    def test_existing_test_exercising_the_method_is_reused(self):
        path = ("app/src/androidTest/java/com/nononsenseapps/feeder/"
                "HttpClientBehaviourTest.kt")
        error = self._error([{
            "source_file_path": path,
            "content": "fun check() { builder.trustAllCerts() }",
        }])
        edit = self._test_edit(self._plan(error))
        self.assertEqual(edit["source_file_path"], path)
        self.assertFalse(edit["create_new_file"])


GIGGITY_HASHCODE = """\
\t\tpublic int hashCode() {
\t\t\t// I'm using this for notification + alarm IDs now so use all 32 bits.
\t\t\ttry {
\t\t\t\tMessageDigest md5 = MessageDigest.getInstance("MD5");
\t\t\t\tmd5.update(getUrl().getBytes());
\t\t\t\tbyte[] raw = md5.digest();
\t\t\t\treturn ByteBuffer.wrap(raw, 0, 4).getInt();
\t\t\t} catch (NoSuchAlgorithmException e) {
\t\t\t\te.printStackTrace();
\t\t\t\treturn super.hashCode();
\t\t\t}
\t\t}
"""


class PrimaryEditSelectionTests(unittest.TestCase):
    """The published method_body must come from an edit that carries code.

    On net.gaast.giggity the first edit matching the target path was a
    `delete`, whose corrected_code is empty by definition, so the solution was
    written with an empty method_body and SolutionMapper then dropped it.
    This pins the ranking that picks a substantive edit instead. It mirrors
    the expression in generate_error_fixes.process_finding.
    """

    TARGET = "app/src/main/java/p/Item.java"
    SUBSTANTIVE = {"method", "declaration", "constant", "create"}

    def _rank(self, item):
        same_file = str(item.get("source_file_path", "")) == self.TARGET
        kind = str(item.get("edit_kind", ""))
        has_code = bool(str(item.get("corrected_code", "")).strip())
        return (not has_code, not same_file, kind not in self.SUBSTANTIVE,
                kind != "method")

    def _primary(self, edits):
        return min(edits, key=self._rank)

    def test_a_delete_never_wins_over_a_method_in_the_same_file(self):
        edits = [
            {"source_file_path": self.TARGET, "edit_kind": "delete",
             "corrected_code": ""},
            {"source_file_path": self.TARGET, "edit_kind": "method",
             "corrected_code": "int hashCode() { return Objects.hash(url); }"},
        ]
        primary = self._primary(edits)
        self.assertEqual(primary["edit_kind"], "method")
        self.assertTrue(primary["corrected_code"])

    def test_the_target_file_still_outranks_another_file(self):
        edits = [
            {"source_file_path": "app/src/test/java/p/ItemTest.java",
             "edit_kind": "create", "corrected_code": "class ItemTest {}"},
            {"source_file_path": self.TARGET, "edit_kind": "method",
             "corrected_code": "int hashCode() { return 1; }"},
        ]
        self.assertEqual(
            self._primary(edits)["source_file_path"], self.TARGET
        )

    def test_falls_back_to_another_file_when_the_target_only_deletes(self):
        edits = [
            {"source_file_path": self.TARGET, "edit_kind": "delete",
             "corrected_code": ""},
            {"source_file_path": "app/src/test/java/p/ItemTest.java",
             "edit_kind": "create", "corrected_code": "class ItemTest {}"},
        ]
        primary = self._primary(edits)
        self.assertEqual(primary["edit_kind"], "create")
        self.assertTrue(primary["corrected_code"])

    def test_empty_corrected_code_falls_through_to_the_original_body(self):
        """`.get(key, default)` does not cover a present-but-empty value."""
        edit = {"corrected_code": ""}
        self.assertEqual(edit.get("corrected_code", "fallback"), "")
        self.assertEqual(edit.get("corrected_code") or "fallback", "fallback")


class UnreviewedCoverageTests(unittest.TestCase):
    """Unreviewed consumers stop a review-only patch, or get documented.

    On net.gaast.giggity the adjudication reported generation supported for
    review, publication blocked and no generation-blocking relation, yet the
    analysis was failed for not reviewing seven consumer files. The three
    sibling scope checks are already waived in exactly that situation; this
    one was the odd one out. Waiving it silently would be worse, so the
    unexamined files are recorded for the human who approves the patch.
    """

    COVERAGE = ["app/src/main/java/p/Reminder.java", "app/src/main/java/p/Db.java"]

    def _error(self):
        return {
            "expanded_repository_context": {"multi_file_impact": {
                "status": "available",
                "multi_file_candidate": True,
                "scope_completeness": {"status": "incomplete"},
                "coverage_requirements": {
                    "caller_files": [self.COVERAGE[0]],
                    "flow_consumer_files": [self.COVERAGE[1]],
                },
            }},
            "case_migration_policy": {},
        }

    def _analysis(self, decision, generation_status, publication_status):
        return {
            "decision": decision,
            "architecture_version": "v2",
            "v2": {"adjudication": {
                "generation_status": generation_status,
                "publication_status": publication_status,
                "blocking_for_generation": [],
            }},
            "scope_assessment": {
                "status": "incomplete",
                "local_code_scope": "incomplete",
                "multi_file_change_required": True,
                "unresolved_relations": [],
                "reviewed_files": [
                    {"source_file_path": "app/src/main/java/p/Target.java",
                     "action": "edit"},
                ],
            },
            "coordinated_fix_plan": {"required_edits": [
                {"source_file_path": "app/src/main/java/p/Target.java"},
            ]},
        }

    def test_review_only_records_the_unreviewed_files_instead_of_failing(self):
        analysis = self._analysis(
            "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "supported_for_review", "blocked"
        )
        issues = validate_multi_file_scope(self._error(), analysis)
        self.assertNotIn(
            "scope assessment did not review required files: "
            + ", ".join(sorted(self.COVERAGE)),
            issues,
        )
        self.assertEqual(
            analysis["scope_assessment"]["unreviewed_coverage_files"],
            sorted(self.COVERAGE),
        )

    def test_an_auto_apply_decision_still_fails_on_unreviewed_files(self):
        analysis = self._analysis(
            "MULTI_FILE_FIX_SUPPORTED", "supported", "allowed"
        )
        issues = validate_multi_file_scope(self._error(), analysis)
        self.assertTrue(
            any("did not review required files" in issue for issue in issues),
            issues,
        )
        self.assertNotIn(
            "unreviewed_coverage_files", analysis["scope_assessment"]
        )

    def test_a_generation_blocking_relation_still_fails_review_only(self):
        analysis = self._analysis(
            "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "supported_for_review", "blocked"
        )
        analysis["v2"]["adjudication"]["blocking_for_generation"] = [
            {"kind": "local_caller", "description": "unresolved dispatch"},
        ]
        issues = validate_multi_file_scope(self._error(), analysis)
        self.assertTrue(
            any("did not review required files" in issue for issue in issues),
            issues,
        )


class UsageKindVocabularyTests(unittest.TestCase):
    """The legacy projection must not discard a V2 classification.

    The V2 extraction enum offers security/identifier/external_contract, none
    of which existed in the legacy allowed set, so a precise answer was
    rewritten to "unknown". net.gaast.giggity's hashCode finding was
    classified "identifier" and reached the migration assessment as "unknown".
    """

    def _projected(self, usage_kind: str) -> str:
        analysis = _analysis_record(
            {"case_migration_policy": {}},
            {"finding": {"spec_family": "message_digest"}},
            {"sources": []},
            {"claims": [], "family_assessment": {"usage_kind": usage_kind}},
            {"decision": "NO_SAFE_FIX"},
            {"required_edits": []},
            {"eligible": False},
        )
        return analysis["migration_assessment"]["usage_kind"]

    def test_every_v2_value_survives_the_projection(self):
        for value in ("security", "cache", "identifier",
                      "runtime_discriminator", "external_contract", "unknown"):
            with self.subTest(usage_kind=value):
                self.assertEqual(self._projected(value), value)

    def test_an_unmodelled_value_still_degrades_to_unknown(self):
        self.assertEqual(self._projected("something_invented"), "unknown")

    def test_widening_does_not_let_identifier_promote(self):
        """The gate must still accept only cache and runtime_discriminator."""
        error = {
            "case_migration_policy": {
                "consumer_scope": "internal_recomputed_digest_value"
            },
            "source_file_path": "app/src/main/java/p/Item.java",
            "method_name": "hashCode",
        }
        analysis = {
            "decision": "NO_SAFE_FIX", "confirmed_cause": "MD5 is disallowed",
            "migration_assessment": {"usage_kind": "identifier"},
            "digest_contract_assessment": {
                "contract_kind": "internal", "backend_change_required": False,
            },
            "review_assumptions": [],
        }
        self.assertEqual(
            promote_bounded_digest_discriminator_review(error, analysis)["decision"],
            "NO_SAFE_FIX",
        )


class NondigestFallbackEvidenceTests(unittest.TestCase):
    """A non-digest fallback answers the value-contract objection from source."""

    def test_detects_the_identity_hash_fallback(self):
        evidence = nondigest_fallback_evidence({"method_body": GIGGITY_HASHCODE})
        self.assertTrue(evidence["observed"])
        self.assertEqual(evidence["fallback_expressions"], ["super.hashCode()"])
        self.assertTrue(evidence["returns_identity_hash"])
        self.assertTrue(evidence["is_hashcode_override"])
        self.assertIn("differs on every process run", evidence["established_fact"])

    def test_silent_without_a_catch_block(self):
        self.assertEqual(nondigest_fallback_evidence({
            "method_body": 'int h() { return digest("MD5"); }'
        }), {})

    def test_silent_when_the_fallback_is_still_digest_derived(self):
        """A fallback that recomputes a digest proves nothing about the contract."""
        self.assertEqual(nondigest_fallback_evidence({
            "method_body": (
                "int h() { try { return md5.digest()[0]; } "
                "catch (Exception e) { return shaDigest[0]; } }"
            )
        }), {})

    def test_silent_without_a_method_body(self):
        self.assertEqual(nondigest_fallback_evidence({}), {})


class HashCodeDesignRepairPolicyTests(unittest.TestCase):
    """A hashCode override should be repaired, not merely re-algorithmed.

    Substituting SHA-256 for MD5 inside hashCode() satisfies the allow-list
    while keeping a cryptographic digest in a hash bucket, the provider lookup
    per call, and the NoSuchAlgorithmException plumbing.
    """

    def _policy(self, body: str) -> dict:
        return generic_migration_policy({
            "spec": "MessageDigestSpec",
            "error_message": (
                "expecting one of {SHA-256, SHA-384, SHA-512} but found MD5."
            ),
            "unique_error_id": "p.Item:::hashCode:::MessageDigestSpec",
            "method_body": body,
        })

    def test_hashcode_override_is_directed_at_the_design(self):
        policy = self._policy(GIGGITY_HASHCODE)
        self.assertEqual(policy["usage_classification"], "hashcode_override")
        self.assertIn("Objects.hash", policy["strategy"])
        self.assertNotIn("replace the weak algorithm", policy["strategy"].lower())
        self.assertTrue(any(
            "MessageDigest" in item and "hashCode" in item
            for item in policy["forbidden_changes"]
        ))
        self.assertTrue(any(
            "consistent with equals" in item for item in policy["required_tests"]
        ))

    def test_hashcode_policy_carries_the_fallback_evidence(self):
        policy = self._policy(GIGGITY_HASHCODE)
        evidence = policy["established_value_contract_evidence"]
        self.assertTrue(evidence["returns_identity_hash"])

    def test_an_ordinary_digest_still_gets_the_algorithm_substitution(self):
        policy = self._policy(
            'String f(String s) { MessageDigest m = '
            'MessageDigest.getInstance("MD5"); return hex(m.digest()); }'
        )
        self.assertNotEqual(
            policy.get("usage_classification"), "hashcode_override"
        )
        self.assertIn("governed algorithm", policy["strategy"])
        self.assertNotIn("Objects.hash", policy["strategy"])


class StructuralHashCodePromotionTests(unittest.TestCase):
    """A hashCode override with an identity-hash fallback settles the gate.

    net.gaast.giggity's adjudication blocked on usage_classification_unresolved
    and value_contract_unresolved. Both are answered by the method's own
    structure, so the promotion must not depend on the model reclassifying.
    """

    def _error(self, body: str, **overrides):
        error = {
            "spec": "MessageDigestSpec",
            "error_message": (
                "expecting one of {SHA-256, SHA-384, SHA-512} but found MD5."
            ),
            "unique_error_id": "net.gaast.giggity.Schedule$Item:::hashCode",
            "csv_class": "net.gaast.giggity.Schedule$Item",
            "method_name": "hashCode",
            "method_body": body,
            "source_file_path": "app/src/main/java/net/gaast/giggity/Schedule.java",
        }
        error["case_migration_policy"] = generic_migration_policy(error)
        error.update(overrides)
        return error

    def _analysis(self, **overrides):
        # Deliberately the weak classification the real run produced.
        analysis = {
            "decision": "NO_SAFE_FIX",
            "confirmed_cause": (
                "Schedule.Item.hashCode acquires a MessageDigest using MD5."
            ),
            "migration_assessment": {"usage_kind": "identifier"},
            "digest_contract_assessment": {
                "contract_kind": "unknown", "backend_change_required": False,
            },
            "review_assumptions": [],
        }
        analysis.update(overrides)
        return analysis

    def test_promotes_despite_identifier_and_unknown_contract(self):
        promoted = promote_bounded_digest_discriminator_review(
            self._error(GIGGITY_HASHCODE), self._analysis()
        )
        self.assertEqual(
            promoted["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"
        )
        self.assertEqual(
            promoted["migration_assessment"]["usage_kind"], "runtime_discriminator"
        )
        self.assertIn("Objects.hash", promoted["migration_assessment"]["safe_strategy"])

    def test_surfaces_the_persisted_identifier_risk_for_review(self):
        promoted = promote_bounded_digest_discriminator_review(
            self._error(GIGGITY_HASHCODE), self._analysis()
        )
        assumptions = " ".join(promoted["review_assumptions"])
        self.assertIn("identity hash", assumptions)
        self.assertIn("alarm ID", assumptions)

    def test_hashcode_without_a_fallback_is_not_structurally_settled(self):
        """The Java contract alone is normative; real code violates it."""
        body = (
            "public int hashCode() {\n"
            '  MessageDigest md5 = MessageDigest.getInstance("MD5");\n'
            "  return ByteBuffer.wrap(md5.digest(), 0, 4).getInt();\n"
            "}\n"
        )
        promoted = promote_bounded_digest_discriminator_review(
            self._error(body), self._analysis()
        )
        self.assertEqual(promoted["decision"], "NO_SAFE_FIX")

    def test_a_backend_contract_still_blocks_the_structural_path(self):
        analysis = self._analysis(digest_contract_assessment={
            "contract_kind": "external_backend", "backend_change_required": True,
        })
        promoted = promote_bounded_digest_discriminator_review(
            self._error(GIGGITY_HASHCODE), analysis
        )
        self.assertEqual(promoted["decision"], "NO_SAFE_FIX")

    def test_an_unconfirmed_cause_still_blocks_the_structural_path(self):
        promoted = promote_bounded_digest_discriminator_review(
            self._error(GIGGITY_HASHCODE), self._analysis(confirmed_cause="")
        )
        self.assertEqual(promoted["decision"], "NO_SAFE_FIX")

    def test_the_plan_targets_the_declaring_file(self):
        promoted = promote_bounded_digest_discriminator_review(
            self._error(GIGGITY_HASHCODE), self._analysis()
        )
        edits = promoted["coordinated_fix_plan"]["required_edits"]
        self.assertEqual(
            [item["source_file_path"] for item in edits],
            ["app/src/main/java/net/gaast/giggity/Schedule.java"],
        )


class BoundedDigestDiscriminatorPromotionTests(unittest.TestCase):
    """Cover the internal-digest promotion added for the orgzly SHA-1 case.

    The shapes here mirror run_20260903_000250: a confirmed MessageDigestSpec
    violation whose value is recomputed and compared inside one process.
    """

    def _error(self, **overrides):
        error = {
            "spec": "MessageDigestSpec",
            "error_message": (
                "expecting one of {SHA-256, SHA-384, SHA-512} but found SHA-1."
            ),
            "unique_error_id": "com.orgzly.android.util.MiscUtils:::sha1",
            "csv_class": "com.orgzly.android.util.MiscUtils",
            "method_name": "sha1",
            "source_file_path": "app/src/main/java/com/orgzly/android/util/MiscUtils.java",
        }
        error["case_migration_policy"] = generic_migration_policy(error)
        error.update(overrides)
        return error

    def _analysis(self, **overrides):
        analysis = {
            "decision": "NO_SAFE_FIX",
            "confirmed_cause": (
                "MiscUtils.sha1 constructs a MessageDigest with the literal "
                "\"SHA-1\", outside the governed allow-list."
            ),
            "migration_assessment": {"usage_kind": "runtime_discriminator"},
            "digest_contract_assessment": {
                "contract_kind": "internal",
                "backend_change_required": False,
            },
            "review_assumptions": [],
        }
        analysis.update(overrides)
        return analysis

    def test_policy_is_supplied_for_a_weak_digest_finding(self):
        policy = generic_migration_policy(self._error())
        self.assertEqual(
            policy["consumer_scope"], "internal_recomputed_digest_value"
        )
        self.assertTrue(policy["authorization_conditions"])
        self.assertTrue(policy["required_tests"])

    def test_policy_is_not_supplied_for_a_governed_algorithm(self):
        self.assertEqual(generic_migration_policy({
            "spec": "MessageDigestSpec",
            "error_message": "expecting one of {SHA-256} but found SHA-256.",
        }), {})

    def test_internal_recomputed_digest_is_promoted_to_review(self):
        promoted = promote_bounded_digest_discriminator_review(
            self._error(), self._analysis()
        )
        self.assertEqual(
            promoted["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"
        )
        self.assertTrue(promoted["migration_assessment"]["policy_authorized"])
        self.assertFalse(
            promoted["migration_assessment"]["legacy_compatibility_required"]
        )
        edits = promoted["coordinated_fix_plan"]["required_edits"]
        self.assertEqual(len(edits), 1)
        self.assertEqual(
            edits[0]["source_file_path"],
            "app/src/main/java/com/orgzly/android/util/MiscUtils.java",
        )
        # The upgrade-boundary caveat must survive into the review artifacts.
        self.assertTrue(any(
            "upgrade" in item for item in promoted["review_assumptions"]
        ))

    def test_persisted_or_external_digest_is_not_promoted(self):
        for contract in ("external_backend", "multi_repository", "unknown"):
            with self.subTest(contract=contract):
                analysis = self._analysis(digest_contract_assessment={
                    "contract_kind": contract, "backend_change_required": False,
                })
                self.assertEqual(
                    promote_bounded_digest_discriminator_review(
                        self._error(), analysis
                    )["decision"],
                    "NO_SAFE_FIX",
                )

    def test_non_discriminator_usage_is_not_promoted(self):
        for usage in ("persistence", "protocol", "public_api", "fingerprint"):
            with self.subTest(usage=usage):
                analysis = self._analysis(
                    migration_assessment={"usage_kind": usage}
                )
                self.assertEqual(
                    promote_bounded_digest_discriminator_review(
                        self._error(), analysis
                    )["decision"],
                    "NO_SAFE_FIX",
                )

    def test_unconfirmed_cause_is_not_promoted(self):
        analysis = self._analysis(confirmed_cause="")
        self.assertEqual(
            promote_bounded_digest_discriminator_review(
                self._error(), analysis
            )["decision"],
            "NO_SAFE_FIX",
        )

    def test_promotion_requires_the_policy_marker(self):
        error = self._error(case_migration_policy={})
        self.assertEqual(
            promote_bounded_digest_discriminator_review(
                error, self._analysis()
            )["decision"],
            "NO_SAFE_FIX",
        )

    def test_a_backend_change_requirement_blocks_promotion(self):
        analysis = self._analysis(digest_contract_assessment={
            "contract_kind": "internal", "backend_change_required": True,
        })
        self.assertEqual(
            promote_bounded_digest_discriminator_review(
                self._error(), analysis
            )["decision"],
            "NO_SAFE_FIX",
        )

    def test_an_already_supported_decision_is_left_alone(self):
        analysis = self._analysis(decision="MULTI_FILE_FIX_SUPPORTED")
        self.assertEqual(
            promote_bounded_digest_discriminator_review(
                self._error(), analysis
            )["decision"],
            "MULTI_FILE_FIX_SUPPORTED",
        )


class StructuredOutputTests(unittest.TestCase):
    def test_coordinated_summary_mentions_specific_dynamic_error(self):
        text = coordinated_fix_explanation({
            "error_message": "expected TLSv1.2 but found TLS",
            "tool": "ape", "spec": "SSLContextSpec",
            "method_name": "build", "csv_class": "p.Client.Builder",
            "evidence_analysis": {
                "confirmed_cause": "Legacy protocols remain selectable.",
                "migration_assessment": {"safe_strategy": "Filter sockets."},
            },
        }, [{
            "source_file_path": "src/Client.kt", "reason": "Wrap sockets."
        }], ["Reject TLSv1.1"], [])
        self.assertIn("dynamic-analysis", text)
        self.assertIn("expected TLSv1.2 but found TLS", text)
        self.assertIn("Legacy protocols remain selectable", text)
        self.assertIn("src/Client.kt", text)

    def test_semantic_gate_rejects_exception_message_contract_mismatch(self):
        result = validate_coordinated_semantics({}, [{
            "source_file_path": "src/Client.kt", "edit_kind": "method",
            "symbol": "filter", "original_code": "fun filter() {}",
            "corrected_code": 'throw SSLException("enabled")',
            "reason": "fail closed",
        }, {
            "source_file_path": "src/ClientTest.java", "edit_kind": "test",
            "symbol": "testFilter", "original_code": "void oldTest() {}",
            "corrected_code": (
                'assertEquals("remain", exception.getMessage());'
            ), "reason": "assert failure",
        }])
        codes = {item["code"] for item in result["errors"]}
        self.assertIn("EXCEPTION_MESSAGE_CONTRACT_MISMATCH", codes)

    def test_comment_ellipsis_before_if_does_not_fake_a_declaration(self):
        # Regression test for a real false positive: declaration_pattern's
        # "type" token accepts "." (for generics/qualified return types), so
        # a comment ending "...." immediately before an `if` statement was
        # captured as a declared method named "if" with an empty throws
        # set. That bogus entry alone was enough to make `called` non-empty
        # for any method containing an unrelated `if`, which then flagged
        # every checked exception it legitimately caught as obsolete.
        result = validate_coordinated_semantics({}, [{
            "source_file_path": "src/Downloader.java",
            "edit_kind": "method", "symbol": "download",
            "original_code": "void download() {}",
            "corrected_code": (
                "private String download() {\n"
                "    try {\n"
                "        connect(new TLSSocketFactory());\n"
                "    } catch (KeyManagementException e) {\n"
                "        e.printStackTrace();\n"
                "    } catch (NoSuchAlgorithmException e) {\n"
                "        e.printStackTrace();\n"
                "    }\n"
                "    int total = 0;\n"
                "    // publishing the progress....\n"
                "    if (total > 0) {\n"
                "        report(total);\n"
                "    }\n"
                "    return null;\n"
                "}"
            ),
            "reason": "attach filtered factory",
        }])
        codes = {item["code"] for item in result["errors"]}
        self.assertNotIn("OBSOLETE_CHECKED_EXCEPTION_CATCH", codes)

    def test_constructor_throws_clause_is_tracked_across_files(self):
        # TLSSocketFactory()'s constructor declares no return type, so
        # declaration_pattern alone can never see its throws clause. When a
        # coordinated edit to a *different* file also edits that
        # constructor, the cross-file check must still recognize its
        # checked exceptions as required, not obsolete.
        result = validate_coordinated_semantics({}, [{
            "source_file_path": "src/TLSSocketFactory.java",
            "edit_kind": "method", "symbol": "TLSSocketFactory()",
            "original_code": "public TLSSocketFactory() {}",
            "corrected_code": (
                "public TLSSocketFactory() throws NoSuchAlgorithmException, "
                "KeyManagementException {\n"
                "    SSLContext context = SSLContext.getInstance(\"TLS\");\n"
                "    context.init(null, null, null);\n"
                "}"
            ),
            "reason": "unchanged constructor contract",
        }, {
            "source_file_path": "src/Downloader.java",
            "edit_kind": "method", "symbol": "download",
            "original_code": "void download() {}",
            "corrected_code": (
                "private String download() {\n"
                "    try {\n"
                "        connect(new TLSSocketFactory());\n"
                "    } catch (KeyManagementException e) {\n"
                "        e.printStackTrace();\n"
                "    } catch (NoSuchAlgorithmException e) {\n"
                "        e.printStackTrace();\n"
                "    }\n"
                "    return null;\n"
                "}"
            ),
            "reason": "attach filtered factory",
        }])
        codes = {item["code"] for item in result["errors"]}
        self.assertNotIn("OBSOLETE_CHECKED_EXCEPTION_CATCH", codes)
        self.assertNotIn("CHECKED_EXCEPTION_NOT_PROPAGATED", codes)

    def test_genuinely_obsolete_checked_exception_catch_is_still_flagged(self):
        # The keyword filter and constructor recovery must not make the
        # check toothless: a catch for an exception no longer thrown by any
        # tracked method in this same coordinated patch is still obsolete.
        result = validate_coordinated_semantics({}, [{
            "source_file_path": "src/Client.java",
            "edit_kind": "method", "symbol": "connect",
            "original_code": (
                "void connect() throws java.io.IOException {}"
            ),
            "corrected_code": "void connect() {}",
            "reason": "no longer throws",
        }, {
            "source_file_path": "src/Caller.java",
            "edit_kind": "method", "symbol": "run",
            "original_code": "void run() {}",
            "corrected_code": (
                "void run() {\n"
                "    try {\n"
                "        connect();\n"
                "    } catch (IOException e) {\n"
                "        e.printStackTrace();\n"
                "    }\n"
                "}"
            ),
            "reason": "call the no-longer-throwing method",
        }])
        codes = {item["code"] for item in result["errors"]}
        self.assertIn("OBSOLETE_CHECKED_EXCEPTION_CATCH", codes)

    def test_generic_tls_policy_preserves_future_protocol_negotiation(self):
        policy = generic_migration_policy({
            "spec": "SSLContextSpec",
            "error_message": (
                "expecting one of {TLSv1.2, TLSv1.3} but found TLS."
            ),
            "unique_error_id": "x:::UnsafeProtocol:::found TLS.",
        })
        self.assertTrue(policy["authorized"])
        self.assertIn("provider-enabled protocols", policy["strategy"])
        self.assertEqual(
            policy["consumer_scope"],
            "signature_preserving_internal_transport_change",
        )
        self.assertIn("future TLS", " ".join(policy["required_tests"]))
        self.assertIn("TLSv1.3", " ".join(policy["forbidden_changes"]))

    def test_tls_semantic_gate_rejects_version_pinning(self):
        error = {
            "case_migration_policy": generic_migration_policy({
                "spec": "SSLContextSpec",
                "error_message": (
                    "expecting one of {TLSv1.2, TLSv1.3} but found TLS."
                ),
                "unique_error_id": "x:::UnsafeProtocol:::found TLS.",
            }),
        }
        result = validate_coordinated_semantics(error, [{
            "source_file_path": "src/Client.kt",
            "edit_kind": "method",
            "symbol": "createContext",
            "original_code": 'SSLContext.getInstance("TLS")',
            "corrected_code": 'SSLContext.getInstance("TLSv1.3")',
            "reason": "pin protocol",
        }])
        codes = {item["code"] for item in result["errors"]}
        self.assertIn("TLS_CONTEXT_VERSION_PINNED", codes)
        self.assertIn("TLS_LEGACY_PROTOCOL_FILTER_MISSING", codes)

    def test_tls_semantic_gate_accepts_unknown_future_protocol_literal(self):
        error = {
            "case_migration_policy": generic_migration_policy({
                "spec": "SSLContextSpec",
                "error_message": (
                    "expecting one of {TLSv1.2, TLSv1.3} but found TLS."
                ),
                "unique_error_id": "x:::UnsafeProtocol:::found TLS.",
            }),
        }
        result = validate_coordinated_semantics(error, [{
            "source_file_path": "src/Client.kt",
            "edit_kind": "method",
            "symbol": "filterProtocols",
            "original_code": "fun filterProtocols() = Unit",
            "corrected_code": (
                'val permitted = socket.enabledProtocols.filterNot { '
                'it == "TLSv1" || it == "TLSv1.1" }'
            ),
            "reason": "filter provider protocols",
        }, {
            "source_file_path": "src/test/ClientTest.kt",
            "edit_kind": "test",
            "symbol": "preservesUnknownFutureProtocol",
            "original_code": "fun oldTest() = Unit",
            "corrected_code": (
                'val provider = arrayOf("TLSv1", "TLSv1.0", "TLSv1.1", '
                '"TLSv1.2", "TLSv1.3", "TLSv9.7")\n'
                'assertArrayEquals(arrayOf("TLSv1.2", "TLSv1.3", '
                '"TLSv9.7"), filter(provider))\n'
                'assertFailsWith<IOException> { filter(arrayOf("TLSv1")) }'
            ),
            "reason": "cover legacy, current, unknown future, and empty sets",
        }])
        codes = {item["code"] for item in result["errors"]}
        self.assertNotIn("TLS_PROTOCOL_FILTER_CONTRACT_NOT_TESTED", codes)

    def test_tls_filter_by_exclusion_is_recognized_without_the_word_filter(self):
        # Regression test for a real false positive: a correct filter
        # implementation that builds its result by testing each protocol
        # with a negated comparison (!protocol.equals("TLSv1"),
        # !protocol.startsWith("SSL")) never spells out the literal word
        # "filter" or "remove" anywhere in the source, so the keyword-only
        # check rejected functionally correct, policy-compliant code.
        error = {
            "case_migration_policy": generic_migration_policy({
                "spec": "SSLContextSpec",
                "error_message": (
                    "expecting one of {TLSv1.2, TLSv1.3} but found TLS."
                ),
                "unique_error_id": "x:::UnsafeProtocol:::found TLS.",
            }),
        }
        result = validate_coordinated_semantics(error, [{
            "source_file_path": "src/TLSSocketFactory.java",
            "edit_kind": "method", "symbol": "enableTLSOnSocket",
            "original_code": "void enableTLSOnSocket() {}",
            "corrected_code": (
                "Socket enableTLSOnSocket(Socket socket) throws IOException {\n"
                "    String[] enabledProtocols = sslSocket.getEnabledProtocols();\n"
                "    int acceptableProtocolCount = 0;\n"
                "    for (String protocol : enabledProtocols) {\n"
                "        if (protocol != null\n"
                "                && !protocol.startsWith(\"SSL\")\n"
                "                && !protocol.equals(\"TLSv1\")\n"
                "                && !protocol.equals(\"TLSv1.0\")\n"
                "                && !protocol.equals(\"TLSv1.1\")) {\n"
                "            acceptableProtocolCount++;\n"
                "        }\n"
                "    }\n"
                "    if (acceptableProtocolCount == 0) {\n"
                "        throw new IOException(\"No acceptable TLS protocols\");\n"
                "    }\n"
                "    return socket;\n"
                "}"
            ),
            "reason": "exclude legacy protocol names by negated comparison",
        }])
        codes = {item["code"] for item in result["errors"]}
        self.assertNotIn("TLS_LEGACY_PROTOCOL_FILTER_MISSING", codes)

    def test_tls_filter_missing_is_still_flagged_when_genuinely_absent(self):
        error = {
            "case_migration_policy": generic_migration_policy({
                "spec": "SSLContextSpec",
                "error_message": (
                    "expecting one of {TLSv1.2, TLSv1.3} but found TLS."
                ),
                "unique_error_id": "x:::UnsafeProtocol:::found TLS.",
            }),
        }
        result = validate_coordinated_semantics(error, [{
            "source_file_path": "src/TLSSocketFactory.java",
            "edit_kind": "method", "symbol": "enableTLSOnSocket",
            "original_code": "void enableTLSOnSocket() {}",
            "corrected_code": (
                "Socket enableTLSOnSocket(Socket socket) {\n"
                "    return socket;\n"
                "}"
            ),
            "reason": "no actual filtering logic",
        }])
        codes = {item["code"] for item in result["errors"]}
        self.assertIn("TLS_LEGACY_PROTOCOL_FILTER_MISSING", codes)

    def test_tls_contract_downgrades_to_warning_without_test_infrastructure(self):
        with tempfile.TemporaryDirectory() as directory:
            repo_root = Path(directory)
            (repo_root / "src").mkdir()
            (repo_root / "src" / "Client.java").write_text(
                "class Client {}", encoding="utf-8",
            )
            error = {
                "repository_path": str(repo_root),
                "case_migration_policy": generic_migration_policy({
                    "spec": "SSLContextSpec",
                    "error_message": (
                        "expecting one of {TLSv1.2, TLSv1.3} but found TLS."
                    ),
                    "unique_error_id": "x:::UnsafeProtocol:::found TLS.",
                }),
            }
            result = validate_coordinated_semantics(error, [{
                "source_file_path": "src/Client.kt",
                "edit_kind": "method", "symbol": "filterProtocols",
                "original_code": "fun filterProtocols() = Unit",
                "corrected_code": (
                    'val permitted = socket.enabledProtocols.filterNot { '
                    'it == "TLSv1" || it == "TLSv1.1" }'
                ),
                "reason": "filter provider protocols",
            }])
            self.assertEqual(result["status"], "valid")
            self.assertEqual(result["errors"], [])
            warning_codes = {item["code"] for item in result["warnings"]}
            self.assertIn("TLS_PROTOCOL_FILTER_CONTRACT_NOT_TESTED", warning_codes)

    def test_tls_contract_is_a_reviewer_note_when_test_infrastructure_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            repo_root = Path(directory)
            (repo_root / "src" / "test").mkdir(parents=True)
            error = {
                "repository_path": str(repo_root),
                "case_migration_policy": generic_migration_policy({
                    "spec": "SSLContextSpec",
                    "error_message": (
                        "expecting one of {TLSv1.2, TLSv1.3} but found TLS."
                    ),
                    "unique_error_id": "x:::UnsafeProtocol:::found TLS.",
                }),
            }
            result = validate_coordinated_semantics(error, [{
                "source_file_path": "src/Client.kt",
                "edit_kind": "method", "symbol": "filterProtocols",
                "original_code": "fun filterProtocols() = Unit",
                "corrected_code": (
                    'val permitted = socket.enabledProtocols.filterNot { '
                    'it == "TLSv1" || it == "TLSv1.1" }'
                ),
                "reason": "filter provider protocols",
            }])
            # Tests are optional (2026-10-15): the missing contract test is
            # reported to the reviewer and does not drop the fix.
            error_codes = {item["code"] for item in result["errors"]}
            self.assertNotIn("TLS_PROTOCOL_FILTER_CONTRACT_NOT_TESTED", error_codes)
            self.assertIn("TLS_PROTOCOL_FILTER_CONTRACT_NOT_TESTED",
                          {item["code"] for item in result["warnings"]})

    def test_complete_tls_context_promotes_abstention_to_review_patch(self):
        policy = generic_migration_policy({
            "spec": "SSLContextSpec",
            "error_message": "expecting one of {TLSv1.2, TLSv1.3} but found TLS.",
            "unique_error_id": "x:::UnsafeProtocol:::found TLS.",
        })
        error = {
            "case_migration_policy": policy,
            "csv_class": "p.HttpClient.Builder", "method_name": "build",
            "expanded_repository_context": {"multi_file_impact": {
                "target": {"source_file_path": "src/HttpClient.kt"},
                "scope_completeness": {"status": "complete"},
                "exact_candidate_sources": [
                    {"source_file_path": "src/HttpClient.kt", "content": "source"},
                    {"source_file_path": "src/test/HttpClientTest.kt", "content": "test"},
                ],
            }},
        }
        promoted = promote_policy_authorized_tls_review(error, {
            "decision": "NO_SAFE_FIX", "predicate_assessment": [],
            "migration_assessment": {},
            "scope_assessment": {"unresolved_relations": [{
                "kind": "external_protocol", "blocking_for_generation": True,
                "blocking_for_publication": True, "description": "endpoint",
            }]},
        })
        self.assertEqual(
            promoted["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"
        )
        self.assertEqual(promoted["scope_assessment"]["status"], "complete")
        self.assertFalse(
            promoted["scope_assessment"]["unresolved_relations"][0]
            ["blocking_for_generation"]
        )
        self.assertEqual(
            len(promoted["coordinated_fix_plan"]["required_edits"]), 2
        )
        incomplete_review = promote_policy_authorized_tls_review(error, {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "confirmed_cause": "", "predicate_assessment": [],
            "migration_assessment": {},
            "scope_assessment": {"unresolved_relations": []},
        })
        self.assertTrue(incomplete_review["confirmed_cause"])
        self.assertEqual(
            len(incomplete_review["coordinated_fix_plan"]["required_edits"]), 2
        )

    def test_tls_review_plans_dedicated_test_when_only_weak_test_exists(self):
        policy = generic_migration_policy({
            "spec": "SSLContextSpec",
            "error_message": "expecting one of {TLSv1.2, TLSv1.3} but found TLS.",
            "unique_error_id": "x:::UnsafeProtocol:::found TLS.",
        })
        error = {
            "case_migration_policy": policy,
            "csv_class": "p.HttpClient.Builder", "method_name": "build",
            "expanded_repository_context": {
                "tests": [{
                    "path": "app/src/androidTest/java/p/UnrelatedDavTest.java",
                    "edit_target_recommended": False,
                }],
                "multi_file_impact": {
                    "target": {
                        "source_file_path": "app/src/main/java/p/HttpClient.kt"
                    },
                    "scope_completeness": {"status": "complete"},
                    "exact_candidate_sources": [{
                        "source_file_path": "app/src/main/java/p/HttpClient.kt",
                        "content": "source",
                    }],
                },
            },
        }
        promoted = promote_policy_authorized_tls_review(error, {
            "decision": "NO_SAFE_FIX", "predicate_assessment": [],
            "migration_assessment": {},
            "scope_assessment": {"unresolved_relations": []},
        })
        test_edit = promoted["coordinated_fix_plan"]["required_edits"][1]
        self.assertEqual(
            test_edit["source_file_path"],
            "app/src/androidTest/java/p/HttpClientTlsProtocolTest.java",
        )
        self.assertTrue(test_edit["create_new_file"])

    def test_validation_debt_promotes_diagnosed_test_and_referenced_api(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            test_file = root / "app/src/androidTest/java/p/LegacyTest.java"
            api_file = root / "app/src/main/java/p/App.kt"
            test_file.parent.mkdir(parents=True)
            api_file.parent.mkdir(parents=True)
            test_file.write_text(
                "class LegacyTest { void x() { App.Companion.getLog(); } }",
                encoding="utf-8",
            )
            api_file.write_text("object App { val logger = 1 }", encoding="utf-8")
            error = {
                "repository_path": str(root),
                "previous_validation_feedback": {
                    "failure_attribution": "verified_preexisting_test_debt",
                    "compiler_diagnostics": [{
                        "path": "/worktree/rev/app/src/androidTest/java/p/LegacyTest.java",
                        "message": "cannot find symbol",
                        "source_line": "App.Companion.getLog();",
                    }],
                },
                "expanded_repository_context": {
                    "multi_file_impact": {"exact_candidate_sources": []},
                },
            }
            promote_validation_repair_sources(error)
            impact = error["expanded_repository_context"]["multi_file_impact"]
            self.assertEqual(impact["validation_repair_sources"], [
                "app/src/androidTest/java/p/LegacyTest.java"
            ])
            exact = {
                item["source_file_path"]
                for item in impact["exact_candidate_sources"]
            }
            self.assertIn("app/src/main/java/p/App.kt", exact)

    def test_delete_edit_is_explicit_and_legacy_import_deletion_is_normalized(self):
        schema = coordinated_fix_schema()
        kinds = (
            schema["properties"]["edits"]["items"]
            ["properties"]["edit_kind"]["enum"]
        )
        self.assertIn("delete", kinds)
        edit = normalize_coordinated_edit({
            "source_file_path": "Source.kt", "symbol": "digest import",
            "edit_kind": "declaration",
            "original_code": "import java.security.MessageDigest\n",
            "corrected_code": "", "reason": "unused",
        })
        self.assertEqual(edit["edit_kind"], "delete")
        self.assertEqual(validate_coordinated_edit_shape(edit), [])
        truncated = dict(edit, edit_kind="method")
        self.assertIn(
            "replacement edit requires non-empty corrected_code",
            validate_coordinated_edit_shape(truncated),
        )

    def test_create_edit_requires_empty_original_and_complete_content(self):
        schema = coordinated_fix_schema()
        kinds = (
            schema["properties"]["edits"]["items"]
            ["properties"]["edit_kind"]["enum"]
        )
        self.assertIn("create", kinds)
        created = {
            "source_file_path": "app/src/test/java/example/TlsTest.java",
            "symbol": "TlsTest", "edit_kind": "create",
            "original_code": "",
            "corrected_code": "package example; class TlsTest {}\n",
            "reason": "dedicated regression test",
        }
        self.assertEqual(validate_coordinated_edit_shape(created), [])
        self.assertIn(
            "create edit must have exactly empty original_code",
            validate_coordinated_edit_shape(dict(created, original_code="old")),
        )

    def test_runtime_discriminator_rejects_unverified_production_mapping_literal(self):
        error = {
            "csv_class": "example.Selector",
            "expanded_repository_context": {
                "runtime_discriminator_assessment": {
                    "supported": True, "unmapped_accepted_constants": ["TYPE2"],
                },
                "android_build_variants": {
                    "known_application_ids": ["com.example.app"],
                },
            },
        }
        edits = [{
            "source_file_path": "src/Selector.kt", "edit_kind": "declaration",
            "symbol": "mapping", "reason": "direct mapping",
            "original_code": "const val TYPE1 = 1",
            "corrected_code": (
                'const val APP = "com.example.app"\n'
                'const val LEGACY = "com.example.app.LEGACY"'
            ),
        }, {
            "source_file_path": "src/test/SelectorTest.kt", "edit_kind": "test",
            "symbol": "mapping test", "reason": "coverage",
            "original_code": "fun old() {}",
            "corrected_code": 'fun test() { check("com.example.app".isNotEmpty()) }',
        }]
        result = validate_coordinated_semantics(error, edits)
        codes = {item["code"] for item in result["errors"]}
        self.assertIn("UNVERIFIED_BEHAVIORAL_MAPPING_LITERAL", codes)

    def test_kotlin_migration_helper_must_not_expand_public_api_implicitly(self):
        error = {"csv_class": "example.Selector", "case_migration_policy": {}}
        edits = [{
            "source_file_path": "src/Constants.kt", "edit_kind": "declaration",
            "symbol": "helper", "reason": "shared mapping",
            "original_code": "const val TYPE1 = 1",
            "corrected_code": "const val TYPE1 = 1\nfun applicationType(id: String) = TYPE1",
        }]
        result = validate_coordinated_semantics(error, edits)
        codes = {item["code"] for item in result["errors"]}
        self.assertIn("UNNECESSARY_PUBLIC_API_EXPANSION", codes)

    def test_a_local_function_inside_a_method_is_not_public_api(self):
        # InterTune (2026-10-27): a helper declared inside a private method's
        # body cannot be called from outside it.
        edits = [{
            "source_file_path": "app/src/main/java/a/WidgetStore.kt",
            "edit_kind": "replace", "symbol": "decoded", "reason": "migrate",
            "original_code": (
                "    private fun decoded(id: String): Int {\n"
                "        return id.length\n"
                "    }"),
            "corrected_code": (
                "    private fun decoded(id: String): Int {\n"
                "        fun migrateArtwork(px: Int) {\n"
                "            listOf(true).forEach { println(px) }\n"
                "        }\n"
                "        migrateArtwork(1)\n"
                "        return id.length\n"
                "    }"),
        }]
        result = validate_coordinated_semantics({}, edits)
        codes = {item["code"] for item in result["errors"]}
        self.assertNotIn("UNNECESSARY_PUBLIC_API_EXPANSION", codes)

    def test_a_new_member_function_beside_a_method_is_still_public_api(self):
        self.assertEqual(
            semantic_validation.implicitly_public_kotlin_functions(
                "    private fun a() {\n        fun local() {}\n    }\n"
                "    fun added() { }\n"
                "    companion object {\n        fun alsoAdded() = 1\n    }\n"),
            {"added", "alsoAdded"},
        )

    def test_members_of_a_private_or_internal_type_are_not_public_api(self):
        # InterTune run_v3 (2026-11-09): the abstract functions of an
        # `internal interface` test seam, which cannot be made private, failed
        # two of three attempts as a public-API expansion.
        self.assertEqual(
            semantic_validation.implicitly_public_kotlin_functions(
                "internal fun currentKey(id: String): String = id\n\n"
                "internal interface FileOps {\n"
                "    fun createStagingLink(legacy: File): File\n"
                "    fun moveStagingLink(staging: File, destination: File)\n"
                "}\n\n"
                "private object AndroidFileOps : FileOps {\n"
                "    override fun createStagingLink(legacy: File): File = legacy\n"
                "    fun helper() = 1\n"
                "}\n\n"
                "@Suppress(\"unused\")\n"
                "private class Holder(val id: String) {\n"
                "    class Nested {\n        fun deep() = 2\n    }\n"
                "}\n\n"
                "class Open {\n"
                "    private companion object {\n        fun hidden() = 3\n    }\n"
                "    fun visible() = 4\n"
                "}\n"),
            {"visible"},
        )

    def test_a_member_of_a_public_type_or_an_anonymous_object_stays_public_api(self):
        # Only a declaration line's own modifiers bound its members: an object
        # expression returned by an internal function, a public interface and
        # a header this reader cannot read as a declaration keep counting.
        self.assertEqual(
            semantic_validation.implicitly_public_kotlin_functions(
                "interface PublicOps {\n    fun open(): Int\n}\n"
                "internal fun ops() = object : PublicOps {\n"
                "    override fun open() = 1\n    fun extra() = 2\n}\n"
                "private val type = Holder::class\n"
                "data class Point(val x: Int) {\n    fun norm() = x\n}\n"),
            {"open", "extra", "norm"},
        )

    def test_the_public_api_error_says_how_to_clear_it(self):
        edits = [{
            "source_file_path": "src/Constants.kt", "edit_kind": "declaration",
            "symbol": "helper", "reason": "shared mapping",
            "original_code": "const val TYPE1 = 1",
            "corrected_code": "const val TYPE1 = 1\nfun applicationType(id: String) = TYPE1",
        }]
        result = validate_coordinated_semantics(
            {"csv_class": "example.Selector", "case_migration_policy": {}}, edits)
        error = next(item for item in result["errors"]
                     if item["code"] == "UNNECESSARY_PUBLIC_API_EXPANSION")
        self.assertEqual(error["details"], ["applicationType"])
        self.assertIn("applicationType", error["message"])
        self.assertIn("private, or internal", error["message"])

    def test_declaration_nested_inside_class_but_called_from_new_test_is_rejected(self):
        # Reproduces the HttpClient.kt regression: a `declaration` edit
        # anchored on a block nested inside a class introduces a helper meant
        # to be called unqualified from a sibling test file. The applier
        # splices it in as an instance member, so the reference cannot
        # resolve -- this must be caught before the patch is ever applied.
        error = {}
        edits = [{
            "source_file_path": "src/HttpClient.kt", "edit_kind": "declaration",
            "symbol": "filterLegacyTlsProtocols", "reason": "add protocol filter",
            "original_code": (
                "    private object UserAgentInterceptor : Interceptor {\n"
                "        private val userAgent = \"x\"\n"
                "    }"
            ),
            "corrected_code": (
                "    internal fun filterLegacyTlsProtocols("
                "protocols: Array<String>): Array<String> = protocols\n\n"
                "    private object UserAgentInterceptor : Interceptor {\n"
                "        private val userAgent = \"x\"\n"
                "    }"
            ),
        }, {
            "source_file_path": "src/androidTest/HttpClientTest.kt",
            "edit_kind": "create", "symbol": "HttpClientTest", "reason": "test",
            "original_code": "",
            "corrected_code": (
                "class HttpClientTest {\n"
                "    fun test() { filterLegacyTlsProtocols(arrayOf(\"TLSv1\")) }\n"
                "}\n"
            ),
        }]
        result = validate_coordinated_semantics(error, edits)
        codes = {item["code"] for item in result["errors"]}
        self.assertEqual(result["status"], "invalid")
        self.assertIn("DECLARATION_SCOPE_MISMATCH", codes)

    def test_a_nested_type_calls_a_new_member_of_an_object_unqualified(self):
        # InterTune (2026-10-27): helpers spliced into `object WidgetStore`
        # are reachable from its nested data class without an instance.
        import tempfile
        with tempfile.TemporaryDirectory() as repo:
            path = Path(repo) / "app/WidgetStore.kt"
            path.parent.mkdir(parents=True)
            anchor = "    private fun artFile(id: String): String = id"
            path.write_text("object WidgetStore {\n" + anchor + "\n}\n", encoding="utf-8")
            edits = [{
                "source_file_path": "app/WidgetStore.kt", "edit_kind": "declaration",
                "symbol": "artFile", "reason": "migrate",
                "original_code": anchor,
                "corrected_code": (
                    anchor + "\n"
                    "    private fun legacyName(id: String): String = id\n"
                    "    private data class ArtworkFiles(val id: String) {\n"
                    "        val legacy = legacyName(id)\n"
                    "    }"),
            }]
            codes = {item["code"] for item in validate_coordinated_semantics(
                {"repository_path": repo}, edits)["errors"]}
            self.assertNotIn("DECLARATION_SCOPE_MISMATCH", codes)
            path.write_text("class WidgetStore {\n" + anchor + "\n}\n", encoding="utf-8")
            codes = {item["code"] for item in validate_coordinated_semantics(
                {"repository_path": repo}, edits)["errors"]}
            self.assertIn("DECLARATION_SCOPE_MISMATCH", codes)

    def test_declaration_anchored_at_file_top_level_is_accepted(self):
        error = {}
        edits = [{
            "source_file_path": "src/HttpClient.kt", "edit_kind": "declaration",
            "symbol": "filterLegacyTlsProtocols", "reason": "add protocol filter",
            "original_code": "import java.io.IOException",
            "corrected_code": (
                "import java.io.IOException\n\n"
                "internal fun filterLegacyTlsProtocols("
                "protocols: Array<String>): Array<String> = protocols"
            ),
        }, {
            "source_file_path": "src/androidTest/HttpClientTest.kt",
            "edit_kind": "create", "symbol": "HttpClientTest", "reason": "test",
            "original_code": "",
            "corrected_code": (
                "class HttpClientTest {\n"
                "    fun test() { filterLegacyTlsProtocols(arrayOf(\"TLSv1\")) }\n"
                "}\n"
            ),
        }]
        result = validate_coordinated_semantics(error, edits)
        codes = {item["code"] for item in result["errors"]}
        self.assertNotIn("DECLARATION_SCOPE_MISMATCH", codes)

    def test_coordinated_quality_metrics_is_independent_of_confidence(self):
        # A "high" self-reported confidence must not make quality_score high
        # too -- they come from different signals now (this used to be the
        # same {"high": 90, ...} lookup relabeled under two field names).
        edits = [{
            "edit_kind": "method", "original_code": "fun f() = 1",
            "corrected_code": "fun f() = { ownsObjectMonitor(",  # hallucinated + unbalanced
        }]
        metrics = coordinated_quality_metrics(edits)
        self.assertFalse(metrics["is_syntactically_valid"])
        self.assertLess(metrics["quality_score"], 50)
        self.assertTrue(metrics["issues"])

    def test_coordinated_quality_metrics_accepts_well_formed_edits(self):
        edits = [{
            "edit_kind": "declaration", "original_code": "val x = 1",
            "corrected_code": "internal fun helper(): Int = 2",
        }]
        metrics = coordinated_quality_metrics(edits)
        self.assertTrue(metrics["is_syntactically_valid"])
        self.assertEqual(metrics["quality_score"], 100)
        self.assertEqual(metrics["issues"], [])

    def test_coordinated_quality_metrics_ignores_delete_edits(self):
        edits = [{"edit_kind": "delete", "original_code": "import x", "corrected_code": ""}]
        metrics = coordinated_quality_metrics(edits)
        self.assertTrue(metrics["is_syntactically_valid"])
        self.assertEqual(metrics["quality_score"], 100)

    def test_coordinated_quality_metrics_is_dragged_down_by_the_worst_edit(self):
        edits = [
            {
                "edit_kind": "method", "original_code": "fun a() = 1",
                "corrected_code": "internal fun a(): Int = 1",
            },
            {
                # Hallucinated API plus an unmatched brace and paren: enough
                # to cross the is_valid threshold, not just dent the score.
                "edit_kind": "method", "original_code": "fun b() = 2",
                "corrected_code": (
                    "internal fun b(): Int { ownsObjectMonitor( return 2"
                ),
            },
        ]
        metrics = coordinated_quality_metrics(edits)
        self.assertFalse(metrics["is_syntactically_valid"])
        self.assertLess(metrics["quality_score"], 100)
        self.assertTrue(any("brace" in issue.lower() for issue in metrics["issues"]))

    def test_coordinated_quality_metrics_defaults_for_no_checkable_edits(self):
        metrics = coordinated_quality_metrics([])
        self.assertTrue(metrics["is_syntactically_valid"])
        self.assertEqual(metrics["quality_score"], 100)
        self.assertEqual(metrics["issues"], [])

    def test_review_assumptions_never_reach_the_maintainer_text(self):
        """Both headings that carried them were removed from what a maintainer
        reads. The assumptions stay in the solution and execution JSON, where
        the operator reviews them before publishing."""
        for style in ("v1", "v2"):
            text = coordinated_fix_explanation(
                {}, [], [], ["An unresolved assumption."], style=style,
            )
            self.assertNotIn("Residual review requirements", text)
            self.assertNotIn("An unresolved assumption.", text)

    def test_compose_maintainer_summary_falls_back_when_the_model_call_fails(self):
        generator = object.__new__(FixGenerator)
        generator.logger = logging.getLogger("maintainer-summary-test")

        class _FailingProvider:
            def generate(self, *args, **kwargs):
                raise RuntimeError("network down")

        generator.provider = _FailingProvider()
        summary = generator.compose_maintainer_summary(
            {
                "error_message": "expecting TLSv1.2 but found TLS.",
                "tool": "ape", "spec": "SSLContextSpec",
            },
            [{
                "source_file_path": "src/Client.kt",
                "reason": "Filters legacy protocols.",
            }],
            ["Reject TLSv1.1."], ["An unresolved assumption."],
        )
        self.assertIn("The dynamic-analysis run by `ape` reported", summary)
        # The v2 fallback must not duplicate review_assumptions either.
        self.assertNotIn("An unresolved assumption.", summary)

    def test_compose_maintainer_summary_uses_a_valid_model_response(self):
        generator = object.__new__(FixGenerator)
        generator.logger = logging.getLogger("maintainer-summary-test-2")

        class _FakeProvider:
            def generate(self, *args, **kwargs):
                return '{"summary": "I reviewed this code and found a gap."}'

        generator.provider = _FakeProvider()
        summary = generator.compose_maintainer_summary(
            {"spec": "SSLContextSpec"}, [], [], [],
        )
        self.assertEqual(summary, "I reviewed this code and found a gap.")

    def test_generation_blocker_persists_confirmed_issue_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            generator = object.__new__(FixGenerator)
            generator.output_dir = Path(directory)
            generator.logger = logging.getLogger("blocked-issue-test")
            evidence_file = Path(directory) / "evidence.json"
            evidence_file.write_text("{}", encoding="utf-8")
            error = {
                "error_index": 2, "repository_url": "https://github.com/o/r",
                "method_body": 'MessageDigest.getInstance("SHA-1");',
                "error_message": "SHA-1", "spec": "MessageDigestSpec",
            }
            analysis = {
                "decision": "BACKEND_MIGRATION_REQUIRED_REVIEW_ONLY",
                "confirmed_cause": "literal SHA-1",
                "predicate_assessment": [{
                    "status": "violated",
                    "evidence": 'MessageDigest.getInstance("SHA-1") violates the rule',
                }],
                "issue_candidate": {
                    "eligible": True, "title": "Migrate digest",
                    "finding_summary": "Confirmed use.",
                    "why_no_pr": "Backend rollout is unknown.",
                    "maintainer_question": "Which rollout is supported?",
                    "proposed_next_step": "Coordinate backend and client.",
                },
            }
            result = generator.persist_blocked_issue_candidate(
                error, analysis, evidence_file, "app.apk", "hash",
                ["generated draft invalid"],
            )
            self.assertIsNotNone(result)
            record = __import__("json").loads(result.read_text(encoding="utf-8"))
            self.assertEqual(record["issue_kind"], "generation_blocked")
            self.assertEqual(record["generation_blockers"], ["generated draft invalid"])

    def test_formats_llm_elapsed_time_like_pipeline(self):
        self.assertEqual(format_elapsed_time(207.7), "00h 03m 28s")
        self.assertEqual(format_elapsed_time(90061), "25h 01m 01s")

    def test_openai_responses_payload_uses_strict_json_schema(self):
        schema = coordinated_fix_schema()
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test"}):
            provider = OpenAIProvider(cache_dir=None)
        provider.session = _Session()

        provider.generate(
            "fix it", json_mode=True, json_schema=schema,
            schema_name="coordinated_fix",
        )

        output_format = provider.session.payloads[0]["text"]["format"]
        self.assertEqual(output_format["type"], "json_schema")
        self.assertEqual(output_format["name"], "coordinated_fix")
        self.assertIs(output_format["strict"], True)
        self.assertEqual(output_format["schema"], schema)

    def test_every_object_is_closed_and_requires_every_property(self):
        def assert_strict(schema):
            if schema.get("type") == "object":
                self.assertIs(schema.get("additionalProperties"), False)
                self.assertEqual(
                    set(schema.get("required", [])),
                    set(schema.get("properties", {})),
                )
                for child in schema["properties"].values():
                    assert_strict(child)
            elif schema.get("type") == "array":
                assert_strict(schema["items"])

        for schema in (
            evidence_analysis_schema(), coordinated_fix_schema(),
        ):
            assert_strict(schema)

    def test_evidence_schema_supports_ephemeral_reviewable_fixes(self):
        schema = evidence_analysis_schema()
        decisions = schema["properties"]["decision"]["enum"]
        usage_kinds = (
            schema["properties"]["migration_assessment"]
            ["properties"]["usage_kind"]["enum"]
        )
        self.assertIn("MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", decisions)
        self.assertIn("ephemeral_sensitive", usage_kinds)
        self.assertIn("runtime_discriminator", usage_kinds)

    def test_runtime_discriminator_semantics_require_digest_removal_and_variant_tests(self):
        error = {
            "csv_class": "example.Selector",
            "expanded_repository_context": {
                "runtime_discriminator_assessment": {
                    "supported": True, "unresolved_constants": ["TYPE2"],
                },
                "android_build_variants": {
                    "known_application_ids": [
                        "com.example.app", "com.example.app.BETA",
                    ],
                },
            },
        }
        edits = [{
            "source_file_path": "src/Selector.kt", "edit_kind": "method",
            "original_code": "fun select() = 1",
            "corrected_code": 'fun select() = MessageDigest.getInstance("MD5")',
        }, {
            "source_file_path": "src/test/SelectorTest.kt", "edit_kind": "test",
            "original_code": "fun oldTest() {}",
            "corrected_code": 'fun test() { check("com.example.app".isNotEmpty()) }',
        }]
        result = validate_coordinated_semantics(error, edits)
        codes = {item["code"] for item in result["errors"]}
        self.assertIn("RUNTIME_DISCRIMINATOR_STILL_USES_DIGEST", codes)
        # Tests are optional (2026-10-15): incomplete variant coverage is a
        # reviewer note, not a blocker.
        warning_codes = {item["code"] for item in result["warnings"]}
        self.assertIn("KNOWN_APPLICATION_VARIANTS_NOT_TESTED", warning_codes)
        self.assertNotIn("KNOWN_APPLICATION_VARIANTS_NOT_TESTED", codes)

    def test_evidence_schema_classifies_digest_contract_migrations(self):
        schema = evidence_analysis_schema()
        decisions = schema["properties"]["decision"]["enum"]
        contract = schema["properties"]["digest_contract_assessment"]
        self.assertIn("SAFE_INTERNAL_DIGEST_MIGRATION", decisions)
        self.assertIn("BACKEND_MIGRATION_REQUIRED_REVIEW_ONLY", decisions)
        self.assertIn("EXTERNAL_DIGEST_CONTRACT_NO_CLIENT_ONLY_FIX", decisions)
        self.assertIn("NON_SECURITY_HASH_USAGE", decisions)
        self.assertIn(
            "external_backend",
            contract["properties"]["contract_kind"]["enum"],
        )
        self.assertEqual(
            contract["properties"]["security_relevance"]["enum"],
            ["confirmed", "plausible", "not_established", "false"],
        )

    def test_backend_digest_review_schema_cannot_abstain(self):
        schema = coordinated_fix_schema(
            "BACKEND_MIGRATION_REQUIRED_REVIEW_ONLY"
        )
        self.assertEqual(
            schema["properties"]["decision"]["enum"],
            ["BACKEND_MIGRATION_REQUIRED_REVIEW_ONLY"],
        )

    def test_review_only_generation_schema_cannot_abstain(self):
        schema = coordinated_fix_schema(
            "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"
        )
        properties = schema["properties"]
        self.assertEqual(
            properties["decision"]["enum"],
            ["MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"],
        )
        self.assertIn("manual_review_required", properties)
        self.assertIn("review_assumptions", properties)

    def test_coordinated_generation_persists_one_json_per_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            output = root / "out"
            for relative in ("src/Main.java", "test/MainTest.java"):
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("class X { int value = 1; }", encoding="utf-8")
            generator = object.__new__(FixGenerator)
            generator.output_dir = output
            generator.provider = _DraftProvider()
            generator.web_search = False
            error = {
                "repository_path": str(repo), "error_index": 2,
                "case_migration_policy": {"required_tests": ["round trip"]},
                "evidence_analysis": {
                    "confirmed_cause": "cause",
                    "coordinated_fix_plan": {"required_edits": [
                        {"source_file_path": "src/Main.java", "symbol": "value"},
                        {"source_file_path": "test/MainTest.java", "symbol": "value"},
                    ], "required_tests": ["round trip"]},
                },
            }
            result = generator.generate_coordinated_file_drafts(
                error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "method"
            )
            draft_dir = output / "coordinated_drafts" / "app.apk" / "2_method"
            manifest = __import__("json").loads(
                (draft_dir / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result["status"], "complete")
            self.assertEqual(len(result["edits"]), 2)
            self.assertEqual(manifest["status"], "complete")
            self.assertEqual(len(list(draft_dir.glob("[0-9][0-9]_*.json"))), 2)

    def test_a_mechanically_invalid_draft_is_retried_once(self):
        """run_20260917_140228 lost two of six findings to shape alone.

        Seadroid's draft labelled an empty corrected_code "declaration"
        instead of "delete"; einkbro's review-only draft omitted
        manual_review_required. Both models had already described a coherent
        fix, and both findings were abandoned without being asked again.
        """
        import json as json_module

        class _FirstDraftIsMalformed(_DraftProvider):
            def __init__(self):
                self.attempts = 0
                self.prompts = []

            def generate(self, prompt, *args, **kwargs):
                self.attempts += 1
                self.prompts.append(prompt)
                payload = json_module.loads(
                    super().generate(prompt, *args, **kwargs)
                )
                if self.attempts == 1:
                    payload["manual_review_required"] = False
                    payload["edits"][0]["corrected_code"] = ""
                return json_module.dumps(payload)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            (repo / "src").mkdir(parents=True)
            (repo / "src/Main.java").write_text(
                "class X { int value = 1; }", encoding="utf-8"
            )
            generator = object.__new__(FixGenerator)
            generator.output_dir = root / "out"
            generator.provider = _FirstDraftIsMalformed()
            generator.web_search = False
            error = {
                "repository_path": str(repo), "error_index": 2,
                "case_migration_policy": {"required_tests": ["round trip"]},
                "evidence_analysis": {
                    "confirmed_cause": "cause",
                    "coordinated_fix_plan": {
                        "required_edits": [
                            {"source_file_path": "src/Main.java", "symbol": "value"},
                        ],
                        "required_tests": ["round trip"],
                    },
                },
            }

            result = generator.generate_coordinated_file_drafts(
                error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "method"
            )

        self.assertEqual(result["status"], "complete")
        # Two drafts, then the behaviour review of the finished patch, which
        # this stub cannot answer and which is therefore asked twice (B4).
        self.assertEqual(generator.provider.attempts, 4)
        # The retry has to carry what was wrong, or it is just a second guess.
        # The review flag follows from the decision, so it is set rather than
        # reported as a defect of the draft.
        self.assertNotIn("manual review flag is required", generator.provider.prompts[1])
        self.assertTrue(result["manual_review_required"])
        self.assertIn(
            "replacement edit requires non-empty corrected_code",
            generator.provider.prompts[1],
        )

    def test_a_review_only_draft_that_omits_the_flag_is_not_rejected(self):
        """GeoNotes and Easer, run_20260929_231422: both attempts said false."""
        import json as json_module

        class _NeverFlags(_DraftProvider):
            def __init__(self):
                self.attempts = 0

            def generate(self, prompt, *args, **kwargs):
                self.attempts += 1
                payload = json_module.loads(super().generate(prompt, *args, **kwargs))
                payload["manual_review_required"] = False
                return json_module.dumps(payload)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            (repo / "src").mkdir(parents=True)
            (repo / "src/Main.java").write_text(
                "class X { int value = 1; }", encoding="utf-8"
            )
            generator = object.__new__(FixGenerator)
            generator.output_dir = root / "out"
            generator.provider = _NeverFlags()
            generator.web_search = False
            error = {
                "repository_path": str(repo), "error_index": 2,
                "evidence_analysis": {
                    "confirmed_cause": "cause",
                    "coordinated_fix_plan": {
                        "required_edits": [
                            {"source_file_path": "src/Main.java", "symbol": "value"},
                        ],
                    },
                },
            }
            result = generator.generate_coordinated_file_drafts(
                error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "method"
            )

        self.assertEqual(result["status"], "complete")
        # One draft, then the behaviour review of the finished patch, which
        # this stub cannot answer and which is therefore asked twice (B4).
        self.assertEqual(generator.provider.attempts, 3)
        self.assertTrue(result["manual_review_required"])

    def test_a_draft_that_stays_invalid_is_not_retried_forever(self):
        class _AlwaysMalformed(_DraftProvider):
            def __init__(self):
                self.attempts = 0

            def generate(self, prompt, *args, **kwargs):
                import json as json_module
                self.attempts += 1
                payload = json_module.loads(
                    super().generate(prompt, *args, **kwargs)
                )
                payload["edits"][0]["corrected_code"] = ""
                return json_module.dumps(payload)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            (repo / "src").mkdir(parents=True)
            (repo / "src/Main.java").write_text(
                "class X { int value = 1; }", encoding="utf-8"
            )
            generator = object.__new__(FixGenerator)
            generator.output_dir = root / "out"
            generator.provider = _AlwaysMalformed()
            generator.web_search = False
            error = {
                "repository_path": str(repo), "error_index": 2,
                "case_migration_policy": {"required_tests": ["round trip"]},
                "evidence_analysis": {
                    "confirmed_cause": "cause",
                    "coordinated_fix_plan": {
                        "required_edits": [
                            {"source_file_path": "src/Main.java", "symbol": "value"},
                        ],
                        "required_tests": ["round trip"],
                    },
                },
            }

            result = generator.generate_coordinated_file_drafts(
                error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "method"
            )

        self.assertEqual(result["status"], "invalid")
        self.assertEqual(generator.provider.attempts, 2)

    def test_semantic_validation_retry_targets_classifies_known_error_codes(self):
        generation_paths = ["src/Client.java", "test/ClientTest.java"]
        self.assertEqual(
            semantic_validation_retry_targets(
                [{"code": "TLS_PROTOCOL_FILTER_CONTRACT_NOT_TESTED"}],
                generation_paths,
            ),
            {"test/ClientTest.java"},
        )
        self.assertEqual(
            semantic_validation_retry_targets(
                [{"code": "TLS_LEGACY_PROTOCOL_FILTER_MISSING"}],
                generation_paths,
            ),
            {"src/Client.java"},
        )
        self.assertEqual(
            semantic_validation_retry_targets(
                [{"code": "PUBLIC_API_CONTRACT_CHANGED", "path": "src/Client.java"}],
                generation_paths,
            ),
            {"src/Client.java"},
        )
        self.assertEqual(
            semantic_validation_retry_targets(
                [{"code": "SOME_UNKNOWN_FUTURE_CODE"}],
                generation_paths,
            ),
            set(generation_paths),
        )

    def test_coordinated_generation_retries_only_the_file_that_failed_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            output = root / "out"
            (repo / "src").mkdir(parents=True)
            (repo / "test").mkdir(parents=True)
            (repo / "src/Client.java").write_text(
                "class Client { void connect() { int value = 1; } }",
                encoding="utf-8",
            )
            (repo / "test/ClientTest.java").write_text(
                "class ClientTest { void check() { int value = 1; } }",
                encoding="utf-8",
            )

            import json as json_module

            class _SelfCorrectingProvider:
                context_length = 16384

                def __init__(self):
                    self.calls = {}

                def generate(self, prompt, *_args, **_kwargs):
                    prefix = (
                        "Persisted file-format behavior is outside the "
                        "authorized change.\n\n"
                    )
                    payload_text = prompt.split(prefix, 1)[1].split(
                        "\n\nREQUIRED JSON SCHEMA:\n", 1
                    )[0]
                    payload = json_module.loads(payload_text)
                    relative = payload["target_file"]
                    self.calls[relative] = self.calls.get(relative, 0) + 1
                    is_retry = bool(
                        payload.get("previous_validation_feedback", {})
                        .get("semantic_validation_retry")
                    )
                    if relative == "src/Client.java":
                        corrected = (
                            "class Client { void connect() { "
                            "String[] enabledProtocols = filterProtocols(raw); "
                            # On its own line: a "//" comment runs to the end
                            # of its line, and braces after it would be in it.
                            "// remove \"TLSv1\" legacy support\n"
                            " } }"
                        )
                    elif not is_retry:
                        # First attempt: an incomplete test that will fail
                        # the TLS contract-coverage semantic check.
                        corrected = (
                            "class ClientTest { void check() { assertTrue(true); } }"
                        )
                    else:
                        # Retry: a test that satisfies every requirement
                        # listed in the semantic_validation_retry feedback.
                        corrected = (
                            "class ClientTest { void check() {"
                            " assertThrows(IOException.class, () -> connect(\"TLSv1\"));"
                            " assertThrows(IOException.class, () -> connect(\"TLSv1.0\"));"
                            " assertThrows(IOException.class, () -> connect(\"TLSv1.1\"));"
                            " assertTrue(supports(\"TLSv1.2\"));"
                            " assertTrue(supports(\"TLSv1.3\"));"
                            " assertThrows(IOException.class, () -> connect(\"TLSv1.4\"));"
                            " } }"
                        )
                    return json_module.dumps({
                        "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                        "source_file_path": relative,
                        "explanation": "file edit",
                        "edits": [{
                            "source_file_path": relative, "symbol": "value",
                            "edit_kind": "test" if "test" in relative.lower()
                            else "declaration",
                            "original_code": "int value = 1;",
                            "corrected_code": corrected, "reason": "coordinated",
                        }],
                        "provided_contracts": [relative + ":value"],
                        "required_contracts": [], "required_tests": ["round trip"],
                        "manual_review_required": True,
                        "review_assumptions": ["review lifecycle"],
                        "confidence": "medium",
                    })

            generator = object.__new__(FixGenerator)
            generator.output_dir = output
            provider = _SelfCorrectingProvider()
            generator.provider = provider
            generator.web_search = False
            generator.logger = logging.getLogger("test")
            error = {
                "repository_path": str(repo), "error_index": 3,
                "case_migration_policy": {
                    "required_tests": ["future TLS protocol"],
                },
                "evidence_analysis": {
                    "confirmed_cause": "cause",
                    "coordinated_fix_plan": {"required_edits": [
                        {"source_file_path": "src/Client.java", "symbol": "value"},
                        {"source_file_path": "test/ClientTest.java", "symbol": "value"},
                    ], "required_tests": ["round trip"]},
                },
            }
            result = generator.generate_coordinated_file_drafts(
                error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "method"
            )
            self.assertEqual(result["status"], "complete")
            # The production file was accepted on the first attempt and
            # must not be regenerated just because the test file failed.
            self.assertEqual(provider.calls["src/Client.java"], 1)
            # The thin first test no longer fails validation (a missing contract
            # test is a warning), so nothing is retried at all.
            self.assertEqual(provider.calls["test/ClientTest.java"], 1)

    def test_semantic_gate_rejects_api_lifecycle_and_reflection_hazards(self):
        error = {
            "csv_class": "example.PwsFile",
            "case_migration_policy": {
                "strategy": "AES/GCM authenticated encryption",
                "platform_constraints": {"must_support_api_21": True},
            },
            "expanded_repository_context": {
                "platform_context": {"android_min_sdk": 21},
            },
        }
        edits = [{
            "source_file_path": "PwsPassword.java",
            "edit_kind": "method", "symbol": "seal",
            "original_code": "public SealedObject seal(Cipher cipher) { return null; }",
            "corrected_code": "public Value seal(PwsFile file) { return null; }",
        }, {
            "source_file_path": "Field.java",
            "edit_kind": "declaration", "symbol": "owner",
            "original_code": "private Cipher cipher;",
            "corrected_code": "private final PwsFile file;",
        }, {
            "source_file_path": "FileTest.java",
            "edit_kind": "test", "symbol": "tamper",
            "original_code": "void testOld() {}",
            "corrected_code": (
                "void testTamper() { x.setAccessible(true); try { invoke(); } "
                "catch (InvocationTargetException expected) {} }"
            ),
        }]
        result = validate_coordinated_semantics(error, edits)
        codes = {item["code"] for item in result["errors"]}
        self.assertEqual(result["status"], "invalid")
        self.assertIn("PUBLIC_API_CONTRACT_CHANGED", codes)
        # A missing dispose test is a reviewer note now (tests are optional).
        self.assertNotIn("OWNER_LIFECYCLE_NOT_TESTED", codes)
        self.assertIn("OWNER_LIFECYCLE_NOT_TESTED",
                      {item["code"] for item in result["warnings"]})
        self.assertIn("REFLECTION_ONLY_TEST_SEAM", codes)
        self.assertIn("AUTH_FAILURE_CAUSE_NOT_ASSERTED", codes)
        self.assertIn(
            "API_21_RUNTIME_VALIDATION_REQUIRED",
            {item["code"] for item in result["warnings"]},
        )

    def test_persists_reproducible_expanded_context_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            error = {
                "error_index": 2,
                "unique_error_id": "finding",
                "expanded_repository_context": {
                    "status": "available",
                    "multi_file_impact": {"exact_candidate_sources": [{
                        "source_file_path": "Source.java",
                        "content": "class Source {}",
                    }]},
                },
            }
            path = persist_context_snapshot(
                Path(directory), error, "app.apk", "method"
            )
            data = __import__("json").loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["snapshot_version"], 1)
            self.assertEqual(
                data["exact_source_manifest"][0]["source_file_path"],
                "Source.java",
            )
            self.assertEqual(
                data["expanded_repository_context"]["status"], "available"
            )
            workspace = Path(data["finding_workspace_manifest"])
            manifest = __import__("json").loads(
                workspace.read_text(encoding="utf-8")
            )
            self.assertEqual(len(manifest["sources"]), 1)
            persisted_source = __import__("json").loads(
                Path(manifest["sources"][0]["artifact"]).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(persisted_source["content"], "class Source {}")
            self.assertTrue(Path(manifest["relationships_artifact"]).is_file())

    def test_the_context_fingerprint_ignores_how_long_collection_took(self):
        # Identical evidence gathered twice must hash the same, or the
        # retrospective cannot tell a verdict change from an evidence change.
        import json

        def snapshot(directory, seconds):
            error = {"error_index": 1, "unique_error_id": "finding",
                     "expanded_repository_context": {
                         "status": "available",
                         "repository_index": {"elapsed_seconds": seconds,
                                              "source_files": 3}}}
            path = persist_context_snapshot(Path(directory), error, "app.apk", "method")
            return json.loads(path.read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as first, \
                tempfile.TemporaryDirectory() as second:
            fast, slow = snapshot(first, 1.2), snapshot(second, 55.9)
        self.assertEqual(fast["context_sha256"], slow["context_sha256"])
        # The snapshot itself still records the measurement.
        self.assertEqual(
            slow["expanded_repository_context"]["repository_index"]["elapsed_seconds"], 55.9)

    def test_compact_context_keeps_exact_source_once(self):
        context = {"repository_call_sites": [{
            "path": "A.java", "line": 3, "snippet": "duplicate source",
        }], "multi_file_impact": {"exact_candidate_sources": [{
            "source_file_path": "A.java", "content": "class A {}",
        }]}}
        compact, sources = compact_evidence_context(context)
        self.assertEqual(sources[0]["content"], "class A {}")
        self.assertNotIn("exact_candidate_sources", compact["multi_file_impact"])
        self.assertNotIn("snippet", compact["repository_call_sites"][0])

    def test_v2_patch_plan_without_a_test_file_is_still_valid(self):
        generator = FixGenerator.__new__(FixGenerator)
        packet = {"evidence_catalog": [{
            "evidence_id": "SRC-001", "kind": "target_source",
            "trust_level": "repository_exact_source",
            "data": {"source_file_path": "app/src/main/java/p/Client.kt"},
        }, {
            "evidence_id": "TEST-001", "kind": "test_context",
            "trust_level": "repository_semantic_relation",
            "data": {
                "source_file_path": (
                    "app/src/androidTest/java/p/ExistingTest.java"
                )
            },
        }]}
        adjudication = {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "generation_status": "supported_for_review",
            "_validated_claims": [{"claim_id": "C1"}],
        }
        incomplete = {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "required_edits": [{
                "source_file_path": "app/src/main/java/p/Client.kt",
                "supporting_claim_ids": ["C1"],
            }],
            "required_tests": ["exercise protocol filtering"],
            "generation_blockers": [],
        }
        issues = _validate_patch_plan(
            incomplete, packet, adjudication
        )
        # A *_PROPOSED_FOR_REVIEW decision is always human-reviewed before
        # merge, so one correctly-scoped file is not itself a defect -- and
        # since tests are optional (2026-10-15) neither is the missing test.
        self.assertFalse(any("two planned paths" in issue for issue in issues))
        self.assertFalse(any("concrete" in issue for issue in issues))

        complete = {
            **incomplete,
            "required_edits": [
                *incomplete["required_edits"],
                {
                    "source_file_path": (
                        "app/src/androidTest/java/p/ClientTlsTest.java"
                    ),
                    "create_new_file": True,
                    "supporting_claim_ids": ["C1"],
                },
            ],
        }
        self.assertEqual(
            _validate_patch_plan(
                complete, packet, adjudication
            ),
            [],
        )

    def test_v2_patch_plan_accepts_one_file_for_review_when_no_test_required(self):
        generator = FixGenerator.__new__(FixGenerator)
        packet = {"evidence_catalog": [{
            "evidence_id": "SRC-001", "kind": "target_source",
            "trust_level": "repository_exact_source",
            "data": {
                "source_file_path": (
                    "src/se/bitcraze/crazyfliecontrol/bootloader/"
                    "TLSSocketFactory.java"
                )
            },
        }]}
        adjudication = {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "generation_status": "supported_for_review",
            "_validated_claims": [{"claim_id": "C1"}],
        }
        plan = {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "required_edits": [{
                "source_file_path": (
                    "src/se/bitcraze/crazyfliecontrol/bootloader/"
                    "TLSSocketFactory.java"
                ),
                "supporting_claim_ids": ["C1"],
            }],
            "required_tests": [],
            "generation_blockers": [],
        }
        self.assertEqual(
            _validate_patch_plan(plan, packet, adjudication), []
        )

    def test_v2_adapter_accounts_for_semantic_ambiguity_without_editing_it(self):
        generator = FixGenerator.__new__(FixGenerator)
        packet = {
            "finding": {"spec_family": "tls"},
            "versions": {}, "input_hashes": {},
            "evidence_catalog": [{
                "evidence_id": "EDGE-001", "kind": "ambiguous_relation",
                "data": {
                    "path": "src/OtherBuilder.kt", "name": "build",
                },
            }],
            "external_evidence_catalog": [],
        }
        extraction = {
            "claims": [], "observed_events": [],
            "predicate_assessment": [], "unresolved_questions": [],
            "family_assessment": {
                "generic_context_observed": True,
                "effective_enabled_protocols": "unknown",
                "negotiated_protocol": "unknown",
                "detector_runtime_equivalent": False,
                "evidence_ids": [],
            },
        }
        adjudication = {
            "confirmed_cause": "literal mismatch",
            "compatibility_status": "regression_risk",
            "required_edit_categories": [], "decision_claim_ids": [],
            "forward_compatibility_strategy": "preserve negotiation",
            "blocking_for_generation": [], "blocking_for_publication": [],
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "scope_status": "incomplete",
        }
        plan = {
            "required_edits": [{
                "source_file_path": "src/Client.kt", "symbol": "build",
                "reason": "filter", "create_new_file": False,
                "edit_category": "transport", "supporting_claim_ids": [],
            }, {
                "source_file_path": "src/test/ClientTest.kt",
                "symbol": "ClientTest", "reason": "regression",
                "create_new_file": True, "edit_category": "test",
                "supporting_claim_ids": [],
            }],
            "required_tests": [],
        }
        result = _analysis_record(
            {}, packet, {"sources": []}, extraction, adjudication, plan,
            {"eligible": False},
        )
        accounted = next(
            item for item in result["scope_assessment"]["reviewed_files"]
            if item["source_file_path"] == "src/OtherBuilder.kt"
        )
        self.assertEqual(accounted["action"], "semantic_ambiguity_accounted")
        self.assertNotIn(
            "src/OtherBuilder.kt",
            {
                item["source_file_path"]
                for item in result["coordinated_fix_plan"]["required_edits"]
            },
        )

    def test_the_adjudication_reads_each_joint_findings_own_rule(self):
        """BlueGate run_v6/run_v7 (2026-10-31): the joined generateNewKeyPair
        [KeyPairGeneratorSpec] reached the adjudication as a name and a
        message, which blocked on "the active KeyPairGenerator rule ... was
        not supplied"; reported_by_rule held only KeyPairSpec."""
        import json as json_module

        class _Stop(Exception):
            pass

        class _Provider:
            context_length = 16384
            provider_name = "openai"

            def __init__(self):
                self.prompts = {}

            def generate(self, prompt, system_prompt=None, **kwargs):
                stage = kwargs.get("trace_stage")
                self.prompts[stage] = (prompt, system_prompt or "")
                if stage == "evidence_extraction":
                    return json_module.dumps({
                        "claims": [], "observed_events": [], "predicate_assessment": [],
                        "confirmed_dataflows": [], "relations": [],
                        "unresolved_questions": [], "needs_more_evidence": False,
                        "requested_evidence": [],
                        "family_assessment": {"summary": "s", "evidence_ids": []},
                    })
                raise _Stop(stage)

        def rule(spec, governed):
            return {"status": "available", "spec_id": spec, "name": spec,
                    "source_verified": True, "applies_to_types": [governed],
                    "protocol": f"{spec} protocol",
                    "events": [{"name": "E", "api_patterns": [governed.rsplit(".", 1)[-1] + "("],
                                "condition": f"a call of {governed}"}]}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generator = object.__new__(FixGenerator)
            generator.output_dir = root / "out"
            generator.provider = _Provider()
            generator.web_search = False
            generator.architecture_version = "v2"
            generator.logger = logging.getLogger("test")
            generator.evidence_packet_builder = FindingEvidencePacketBuilder(
                repository_context_budget=140_000)
            generator.policy_registry = PolicyRegistry(root / "no_policies")
            error = {
                "spec": "KeyPairSpec", "method_name": "getOrCreateKeyPair",
                "error_message": "no generator of the private key given to the KeyPair "
                                 "constructor was observed",
                "method_body": "return KeyPair(entry.certificate.publicKey, entry.privateKey)",
                "imports": "import java.security.KeyPair",
                "source_file_path": "app/src/main/java/KeyManager.kt", "csv_class": "KeyManager",
                "specification_context": rule("KeyPairSpec", "java.security.KeyPair"),
                "joint_findings": [{"unique_error_id": "gen", "specification": "KeyPairGeneratorSpec",
                                    "class": "KeyManager", "method": "generateNewKeyPair",
                                    "error_message": "no preparation of the AlgorithmParameterSpec"}],
                "joint_specification_contexts": {
                    "KeyPairGeneratorSpec": rule("KeyPairGeneratorSpec",
                                                 "java.security.KeyPairGenerator")},
            }
            try:
                generator.adjudicate_finding(error, "app.apk", "getOrCreateKeyPair")
            except _Stop:
                pass
            joined = generator.provider
            # Review of 2026-10-31: a finding with no joint rule gets no new
            # sentence, so its adjudication prompt stays as it was.
            alone = generator.provider = _Provider()
            generator.output_dir = root / "out_alone"
            try:
                generator.adjudicate_finding(
                    {key: value for key, value in error.items()
                     if key not in {"joint_findings", "joint_specification_contexts"}},
                    "app.apk", "getOrCreateKeyPair")
            except _Stop:
                pass
        self.assertNotIn("joint_findings_rules", alone.prompts["adjudication"][1])
        self.assertNotIn("joint_findings_rules", alone.prompts["adjudication"][0])
        extraction_prompt, _ = joined.prompts["evidence_extraction"]
        self.assertIn("KeyPairGeneratorSpec protocol", extraction_prompt)
        prompt, system = joined.prompts["adjudication"]
        data = json_module.loads(prompt.split("<adjudication_data untrusted_data=\"true\">", 1)[1]
                                 .rsplit("</adjudication_data>", 1)[0])
        self.assertEqual(data["reported_by_rule"]["specification"], "KeyPairSpec")
        self.assertEqual([item["specification"] for item in data["joint_findings_rules"]],
                         ["KeyPairGeneratorSpec"])
        self.assertIn("joint_findings_rules, when present, are the verified rules", system)

    def test_only_an_unadmitted_origin_record_reaches_extraction_and_adjudication(self):
        """CometOTP EncryptionHelper.loadOrGenerateWrappedKey
        (agent_baseline_20261108): seven adjudications dismissed RVSec's
        random-key-material report on the published rule's "randomized"
        alternative, which the checker that ran recorded and does not admit.
        The analyzer's record and the two sentences are given only for a
        report kind data/detector_labels.json flags; every other finding's
        prompts stay byte-identical to those built without them."""
        import contextlib
        import json as json_module
        from unittest import mock

        import cognalys.llm.finding_adjudication as adjudication_module
        from cognalys.llm.finding_adjudication import (
            ADJUDICATION_PROMPT_VERSION, _REPORTED_BY_DETECTOR_ADJUDICATION_RULE,
            _REPORTED_BY_DETECTOR_EXTRACTION_RULE)
        from cognalys.llm.pipeline_common import CONTEXT_BUILDER_VERSION

        class _Stop(Exception):
            pass

        class _Provider:
            context_length = 16384
            provider_name = "openai"

            def __init__(self):
                self.prompts = {}

            def generate(self, prompt, system_prompt=None, **kwargs):
                stage = kwargs.get("trace_stage")
                self.prompts[stage] = (prompt, system_prompt or "")
                if stage == "evidence_extraction":
                    return json_module.dumps({
                        "claims": [], "observed_events": [], "predicate_assessment": [],
                        "confirmed_dataflows": [], "relations": [],
                        "unresolved_questions": [], "needs_more_evidence": False,
                        "requested_evidence": [],
                        "family_assessment": {"summary": "s", "evidence_ids": []},
                    })
                raise _Stop(stage)

        rule = {"status": "available", "spec_id": "SecretKeySpecSpec",
                "name": "SecretKeySpecSpec", "source_verified": True,
                "applies_to_types": ["javax.crypto.spec.SecretKeySpec"],
                "protocol": "SecretKeySpecSpec protocol",
                "events": [{"name": "c1", "api_patterns": ["SecretKeySpec("],
                            "condition": "a call of javax.crypto.spec.SecretKeySpec"}]}
        base = {
            "spec": "SecretKeySpecSpec", "method_name": "loadOrGenerateWrappedKey",
            "error_message": "the key material was not prepared",
            "method_body": "val raw = ByteArray(32); SecureRandom().nextBytes(raw); "
                           "return SecretKeySpec(raw, \"AES\")",
            "imports": "import javax.crypto.spec.SecretKeySpec",
            "source_file_path": "app/src/main/java/EncryptionHelper.kt",
            "csv_class": "EncryptionHelper", "tool": "rvsec",
            "specification_context": rule,
        }
        records = {
            "flagged": {"code": "SECRETKEYSPEC-NOBS-03", "label": "random-key-material",
                        "label_meaning": "stored", "expected": "prepared key material"},
            "not_observed": {"code": "SECRETKEYSPEC-NOBS-00", "label": "not-observed",
                             "label_meaning": "stored", "expected": "prepared key material"},
            "no_record": None,
        }

        def run(name, record, output_dir, without_record=False):
            generator = object.__new__(FixGenerator)
            generator.output_dir = output_dir
            generator.provider = _Provider()
            generator.web_search = False
            generator.architecture_version = "v2"
            generator.logger = logging.getLogger("test")
            generator.evidence_packet_builder = FindingEvidencePacketBuilder(
                repository_context_budget=140_000)
            generator.policy_registry = PolicyRegistry(output_dir / "no_policies")
            error = dict(base, **({"detector_context": dict(record)} if record else {}))
            patch = (mock.patch.object(adjudication_module, "reported_by_detector",
                                       lambda error: {})
                     if without_record else contextlib.nullcontext())
            with patch:
                try:
                    generator.adjudicate_finding(error, "app.apk", "loadOrGenerateWrappedKey")
                except _Stop:
                    pass
            return generator.provider.prompts

        def adjudication_data(prompt):
            return json_module.loads(
                prompt.split("<adjudication_data untrusted_data=\"true\">", 1)[1]
                .rsplit("</adjudication_data>", 1)[0])

        prompts, before = {}, {}
        for name, record in records.items():
            with tempfile.TemporaryDirectory() as directory:
                prompts[name] = run(name, record, Path(directory) / "out")
            if name == "flagged":
                continue
            # The same finding with the record forced off: the prompts every
            # finding got before reported_by_detector existed.
            with tempfile.TemporaryDirectory() as directory:
                before[name] = run(name, record, Path(directory) / "out", without_record=True)

        flagged = prompts["flagged"]
        extraction_prompt, extraction_system = flagged["evidence_extraction"]
        self.assertIn("\"reported_by_detector\"", extraction_prompt)
        self.assertIn(_REPORTED_BY_DETECTOR_EXTRACTION_RULE, extraction_system)
        adjudication_prompt, adjudication_system = flagged["adjudication"]
        [listed] = adjudication_data(adjudication_prompt)["reported_by_detector"]
        self.assertEqual((listed["specification"], listed["report"], listed["code"]),
                         ("SecretKeySpecSpec", "unadmitted_origin", "SECRETKEYSPEC-NOBS-03"))
        self.assertIn("does not admit", listed["meaning"])
        self.assertIn(_REPORTED_BY_DETECTOR_ADJUDICATION_RULE, adjudication_system)

        for name in ("not_observed", "no_record"):
            for stage in ("evidence_extraction", "adjudication"):
                prompt, system = prompts[name][stage]
                self.assertNotIn("reported_by_detector", prompt, (name, stage))
                self.assertNotIn("reported_by_detector", system, (name, stage))
                # Byte-identical to the prompts built without the record.
                self.assertEqual(prompts[name][stage], before[name][stage], (name, stage))
        # The flagged finding's system prompts are the others' plus one sentence.
        for stage, sentence in (("evidence_extraction", _REPORTED_BY_DETECTOR_EXTRACTION_RULE),
                                ("adjudication", _REPORTED_BY_DETECTOR_ADJUDICATION_RULE)):
            self.assertEqual(prompts["not_observed"][stage][1], prompts["no_record"][stage][1])
            self.assertEqual(flagged[stage][1].replace(sentence, "", 1),
                             prompts["not_observed"][stage][1], stage)
        self.assertGreaterEqual(tuple(map(int, CONTEXT_BUILDER_VERSION.split("."))), (2, 18))
        self.assertGreaterEqual(ADJUDICATION_PROMPT_VERSION, 6)

    def test_a_joint_findings_flagged_record_keeps_the_decision_on_the_reported_section(self):
        """Session LogFile$Writer.writeEntry (rvsec_tls_20261015): a CipherSpec
        InvalidSequenceOfMethodCalls joined with a SecretKeySpecSpec
        random-key-material record. The joint finding's record is listed with
        its own specification and method, and the sentence keeps
        detector_violation and cause_status on the reported finding's own
        (order) requirement, so the cause-section check accepts a cause stated
        for that section."""
        import json as json_module

        from cognalys.llm.adjudication_rules import cause_rule_section_issues
        from cognalys.llm.finding_adjudication import _REPORTED_BY_DETECTOR_ADJUDICATION_RULE

        class _Stop(Exception):
            pass

        class _Provider:
            context_length = 16384
            provider_name = "openai"

            def __init__(self):
                self.prompts = {}

            def generate(self, prompt, system_prompt=None, **kwargs):
                stage = kwargs.get("trace_stage")
                self.prompts[stage] = (prompt, system_prompt or "")
                if stage == "evidence_extraction":
                    return json_module.dumps({
                        "claims": [], "observed_events": [], "predicate_assessment": [],
                        "confirmed_dataflows": [], "relations": [],
                        "unresolved_questions": [], "needs_more_evidence": False,
                        "requested_evidence": [],
                        "family_assessment": {"summary": "s", "evidence_ids": []},
                    })
                raise _Stop(stage)

        def rule(spec, governed):
            return {"status": "available", "spec_id": spec, "name": spec,
                    "source_verified": True, "applies_to_types": [governed],
                    "protocol": f"{spec} protocol",
                    "events": [{"name": "E", "api_patterns": [governed.rsplit(".", 1)[-1] + "("],
                                "condition": f"a call of {governed}"}]}

        flagged = {"code": "SECRETKEYSPEC-NOBS-03", "label": "random-key-material",
                   "label_meaning": "stored", "expected": "prepared key material",
                   "codes": "SECRETKEYSPEC-NOBS-00 [not-observed] (4), "
                            "SECRETKEYSPEC-NOBS-03 [random-key-material] (3)"}
        error = {
            "spec": "CipherSpec", "method_name": "writeEntry",
            "unique_error_id": ("org.thoughtcrime.securesms.logging.LogFile$Writer:::"
                                "writeEntry:::CipherSpec:::InvalidSequenceOfMethodCalls:::"
                                "unknown"),
            "error_message": "the Cipher was initialised again after doFinal",
            "method_body": "SecretKeySpec key = new SecretKeySpec(secret, \"AES\"); "
                           "cipher.init(Cipher.ENCRYPT_MODE, key, iv); cipher.doFinal(entry);",
            "imports": "import javax.crypto.Cipher;",
            "source_file_path": "app/src/main/java/LogFile.java",
            "csv_class": "org.thoughtcrime.securesms.logging.LogFile$Writer", "tool": "rvsec",
            "detector_context": {"code": "CIPHER-ORDER-03", "label": "reuse-after-final"},
            "specification_context": rule("CipherSpec", "javax.crypto.Cipher"),
            "joint_findings": [{"unique_error_id": "key", "specification": "SecretKeySpecSpec",
                                "class": "org.thoughtcrime.securesms.logging.LogFile$Writer",
                                "method": "writeEntry",
                                "error_message": "the key material was not prepared"}],
            "joint_specification_contexts": {
                "SecretKeySpecSpec": rule("SecretKeySpecSpec", "javax.crypto.spec.SecretKeySpec")},
            "joint_detector_contexts": {"key": flagged},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generator = object.__new__(FixGenerator)
            generator.output_dir = root / "out"
            generator.provider = _Provider()
            generator.web_search = False
            generator.architecture_version = "v2"
            generator.logger = logging.getLogger("test")
            generator.evidence_packet_builder = FindingEvidencePacketBuilder(
                repository_context_budget=140_000)
            generator.policy_registry = PolicyRegistry(root / "no_policies")
            try:
                generator.adjudicate_finding(error, "app.apk", "writeEntry")
            except _Stop:
                pass
        prompt, system = generator.provider.prompts["adjudication"]
        data = json_module.loads(prompt.split("<adjudication_data untrusted_data=\"true\">", 1)[1]
                                 .rsplit("</adjudication_data>", 1)[0])
        [listed] = data["reported_by_detector"]
        self.assertEqual((listed["specification"], listed["method"], listed["code"],
                          listed["report"]),
                         ("SecretKeySpecSpec", "writeEntry", "SECRETKEYSPEC-NOBS-03",
                          "unadmitted_origin"))
        # The codes summary, which also counts not-observed reports, is not listed.
        self.assertNotIn("codes", listed)
        self.assertIn(_REPORTED_BY_DETECTOR_ADJUDICATION_RULE, system)
        self.assertIn("finding.reported_violation_section", system)
        finding = data["finding"]
        self.assertEqual(finding["reported_violation_section"], "order")
        # A cause stated for the primary's own (order) section is accepted; the
        # joint record's requirement is a predicate, not the reported section.
        self.assertEqual(cause_rule_section_issues(
            {"cause_status": "confirmed", "cause_rule_section": "order"}, finding), [])
        self.assertTrue(cause_rule_section_issues(
            {"cause_status": "confirmed", "cause_rule_section": "required_predicate"}, finding))

    def test_adjudication_retries_after_deterministic_rejection(self):
        import json as json_module

        class _AdjudicationRetryProvider:
            context_length = 16384
            provider_name = "openai"

            def __init__(self):
                self.calls = []
                self.schema_names = {}

            @staticmethod
            def _adjudication(cause_status):
                return {
                    "cause_status": cause_status,
                    "confirmed_cause": (
                        "SSLContext.getInstance(\"TLS\") requests generic "
                        "provider negotiation outside the detector's literal "
                        "whitelist."
                    ),
                    "detector_violation": "confirmed",
                    "runtime_security_impact": "not_established",
                    "compatibility_status": "preserved",
                    "scope_status": "complete",
                    "decision": "FIX_SUPPORTED",
                    "decision_claim_ids": ["C1"],
                    "blocking_for_generation": [],
                    "blocking_for_publication": [],
                    "generation_status": "blocked",
                    "publication_status": "blocked",
                    "required_edit_categories": [],
                    "required_tests": [],
                    "forward_compatibility_strategy": "",
                    "authorized_behavior_change": {
                        "authorized": False, "description": "",
                        "policy_reference": "",
                    },
                    "review_assumptions": [],
                }

            def generate(self, prompt, system_prompt=None, **kwargs):
                stage = kwargs.get("trace_stage")
                self.calls.append(stage)
                self.schema_names[stage] = kwargs.get("schema_name")
                if stage == "evidence_extraction":
                    return json_module.dumps({
                        "claims": [{
                            "claim_id": "C1",
                            "statement": (
                                "SSLContext.getInstance(\"TLS\") is used."
                            ),
                            "epistemic_status": "confirmed",
                            "evidence_ids": ["SRC-001"],
                        }],
                        "observed_events": [],
                        "predicate_assessment": [{
                            "predicate": (
                                "requested-protocol literal is TLSv1.2 or "
                                "TLSv1.3"
                            ),
                            "status": "violated",
                            "evidence_ids": ["SRC-001"],
                            "explanation": (
                                "The literal is TLS, not an allowed version."
                            ),
                        }],
                        "confirmed_dataflows": [],
                        "relations": [],
                        "unresolved_questions": [],
                        "needs_more_evidence": False,
                        "requested_evidence": [],
                        "family_assessment": {
                            "generic_context_observed": True,
                            "effective_enabled_protocols": "unknown",
                            "negotiated_protocol": "unknown",
                            "detector_runtime_equivalent": False,
                            "evidence_ids": ["SRC-001"],
                        },
                    })
                if stage == "adjudication":
                    # First attempt: everything else is solid, but
                    # cause_status does not literally say "confirmed" --
                    # exactly the deterministic rejection seen in production.
                    return json_module.dumps(self._adjudication("inferred"))
                if stage == "adjudication.correction":
                    return json_module.dumps(self._adjudication("confirmed"))
                if stage == "issue_presentation":
                    return json_module.dumps({
                        "eligible": True,
                        "title": "Review requested",
                        "finding_summary": "confirmed cause",
                        "why_no_pr": "generation is blocked",
                        "maintainer_question": "can you confirm scope?",
                        "proposed_next_step": "clarify and rerun",
                    })
                raise AssertionError(f"unexpected trace_stage {stage}")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generator = object.__new__(FixGenerator)
            generator.output_dir = root / "out"
            generator.provider = _AdjudicationRetryProvider()
            generator.web_search = False
            generator.architecture_version = "v2"
            generator.logger = logging.getLogger("test")
            generator.evidence_packet_builder = FindingEvidencePacketBuilder(
                repository_context_budget=140_000
            )
            generator.policy_registry = PolicyRegistry(root / "no_policies")
            error = {
                "spec": "SSLContext usage",
                "method_name": "createHttpClient",
                "method_body": "SSLContext.getInstance(\"TLS\")",
                "imports": "",
                "source_file_path": "app/src/main/kotlin/HttpClientFactory.kt",
                "csv_class": "HttpClientFactory",
            }
            legacy, artifacts = generator.adjudicate_finding(
                error, "app.apk", "createHttpClient"
            )

            # The rejected first attempt (cause_status="inferred") must be
            # corrected with feedback rather than immediately discarded.
            self.assertEqual(
                generator.provider.calls,
                ["evidence_extraction", "adjudication",
                 "adjudication.correction", "issue_presentation"],
            )
            self.assertEqual(artifacts["adjudication"]["decision"], "FIX_SUPPORTED")
            self.assertEqual(artifacts["adjudication"]["cause_status"], "confirmed")
            self.assertTrue(artifacts["adjudication"]["confirmed_cause"])
            self.assertEqual(artifacts["adjudication"]["blocking_for_generation"], [])
            self.assertEqual(
                legacy["confirmed_cause"],
                artifacts["adjudication"]["confirmed_cause"],
            )
            # The schemas are named by their content, the correction's as the
            # call it corrects.
            from cognalys.llm.llm_contracts import (
                adjudication_schema, evidence_extraction_schema, schema_name_by_content)
            names = generator.provider.schema_names
            self.assertEqual(names["adjudication"], schema_name_by_content(
                "adjudication", adjudication_schema("tls")))
            self.assertEqual(names["adjudication.correction"], names["adjudication"])
            self.assertEqual(names["evidence_extraction"], schema_name_by_content(
                "evidence_extraction", evidence_extraction_schema("tls")))


class SchemaNameByContentTests(unittest.TestCase):
    """The schema name is part of the cached prefix: in the C arm of
    comparison_20261113, 15 adjudication calls whose earlier match differed
    only in the <family>_adjudication_v2 name got 0 cached tokens, against 27
    of 28 full matches cached."""

    FAMILIES = ("tls", "message_digest", "cipher", "dependency", "key_generation",
                "keystore", "secure_random", "generic")

    def test_identical_schemas_share_a_name_and_different_ones_never_do(self):
        from cognalys.llm.llm_contracts import (
            adjudication_schema, evidence_extraction_schema, schema_name_by_content)

        for stem, build in (("adjudication", adjudication_schema),
                            ("evidence_extraction", evidence_extraction_schema)):
            with self.subTest(stem=stem):
                by_content, by_name = {}, {}
                for family in self.FAMILIES:
                    schema = build(family)
                    name = schema_name_by_content(stem, schema)
                    content = json.dumps(schema, sort_keys=True)
                    self.assertEqual(by_content.setdefault(content, name), name)
                    self.assertEqual(by_name.setdefault(name, content), content)
                    # A valid OpenAI format name.
                    self.assertRegex(name, r"^[A-Za-z0-9_-]{1,64}$")
                    self.assertTrue(name.startswith(stem + "_"))
                # Families without a schema of their own share one name; the
                # ones with their own get their own.
                self.assertLess(len(by_name), len(self.FAMILIES))
                self.assertGreater(len(by_name), 1)

    def test_the_name_follows_the_content_not_the_key_order_or_the_family(self):
        from cognalys.llm.llm_contracts import adjudication_schema, schema_name_by_content

        schema = adjudication_schema("cipher")
        reordered = json.loads(json.dumps(schema, sort_keys=True))
        self.assertEqual(schema_name_by_content("adjudication", schema),
                         schema_name_by_content("adjudication", reordered))
        changed = json.loads(json.dumps(schema))
        changed["properties"]["decision"]["enum"] = changed["properties"]["decision"]["enum"][:-1]
        self.assertNotEqual(schema_name_by_content("adjudication", schema),
                            schema_name_by_content("adjudication", changed))
        self.assertEqual(schema_name_by_content("adjudication", adjudication_schema("cipher")),
                         schema_name_by_content("adjudication",
                                                adjudication_schema("key_generation")))
        with self.assertRaises(ValueError):
            schema_name_by_content("not a stem", schema)



_SCHEDULE_SOURCE = """package net.gaast.giggity;

import java.io.Serializable;

public class Schedule implements Serializable {
    private String url;

    public Schedule() {
        this.url = null;
    }

    public String getUrl() {
        return url;
    }

    @Override
    public int hashCode() {
        Item first = getItem("a");
        line.addItem(first);
        return getUrl().hashCode();
    }

    public Item getItem(String id) {
        return null;
    }

    public class Item implements Comparable<Item>, Serializable {
        Item(String guid, String id) {
        }

        public Schedule getSchedule() {
            return Schedule.this;
        }
    }
}
"""


class DeclaredApiSurfaceTests(unittest.TestCase):
    """The outline is what a created test file has instead of a source.

    In run_20260906_080507 the generated test called the Schedule
    constructor with one argument against a class that declares only a
    no-argument one, and javac rejected it after a 2m30s build. The model
    said so itself: the target source was empty because the file was new,
    and no production source was supplied for it to verify the API against.
    """

    def test_reports_the_declared_constructor(self):
        outline = declared_api_surface(_SCHEDULE_SOURCE)
        self.assertIn("public Schedule()", outline)

    def test_reports_a_package_private_nested_constructor(self):
        outline = declared_api_surface(_SCHEDULE_SOURCE)
        self.assertIn("Item(String guid, String id)", outline)

    def test_reports_type_headers_with_their_supertypes(self):
        outline = declared_api_surface(_SCHEDULE_SOURCE)
        self.assertIn("public class Schedule implements Serializable", outline)
        self.assertIn(
            "public class Item implements Comparable<Item>, Serializable",
            outline,
        )

    def test_never_reports_an_ordinary_call_as_a_declaration(self):
        # The addItem call has a method signature's exact shape; reporting it
        # would invent an API that this file does not declare.
        outline = declared_api_surface(_SCHEDULE_SOURCE)
        self.assertFalse([item for item in outline if item.startswith("line.")])

    def test_never_reports_a_control_statement(self):
        outline = declared_api_surface(
            "public class A {\n"
            "    void run() {\n"
            "        if (ready()) { return; }\n"
            "        while (next()) { }\n"
            "    }\n"
            "}\n"
        )
        self.assertFalse([item for item in outline if item.startswith("if ")])
        self.assertFalse([item for item in outline if item.startswith("while ")])

    def test_truncation_is_marked_rather_than_silent(self):
        source = "public class A {\n" + "".join(
            "    public void method%d() { }\n" % index for index in range(20)
        ) + "}\n"
        outline = declared_api_surface(source, max_lines=5)
        self.assertIn("... (API outline truncated)", outline)
        self.assertLessEqual(len(outline), 6)


class ConstructorResolutionGateTests(unittest.TestCase):
    """Catch the giggity constructor mismatch before Gradle, not after."""

    def _repository(self, directory):
        root = Path(directory)
        package = root / "app/src/main/java/net/gaast/giggity"
        package.mkdir(parents=True)
        (package / "Schedule.java").write_text(
            _SCHEDULE_SOURCE, encoding="utf-8"
        )
        return {
            "repository_path": str(root),
            "source_file_path": (
                "app/src/main/java/net/gaast/giggity/Schedule.java"
            ),
            "method_name": "hashCode",
        }

    def _issues(self, directory, corrected_code):
        error = self._repository(directory)
        return unresolvable_constructor_calls(error, [{
            "source_file_path": (
                "app/src/test/java/net/gaast/giggity/ScheduleTest.java"
            ),
            "edit_kind": "create",
            "corrected_code": corrected_code,
        }])

    def test_flags_a_constructor_call_with_an_undeclared_arity(self):
        with tempfile.TemporaryDirectory() as directory:
            issues = self._issues(
                directory, "Schedule schedule = new Schedule(scheduleUrl);"
            )
            self.assertEqual(len(issues), 1)
            self.assertEqual(
                issues[0]["code"], "CONSTRUCTOR_NOT_DECLARED_IN_REPOSITORY"
            )

    def test_accepts_the_declared_arity(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                self._issues(directory, "Schedule schedule = new Schedule();"),
                [],
            )

    def test_stays_quiet_about_a_type_the_repository_does_not_declare(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                self._issues(directory, 'URL parsed = new URL("http://a.b");'),
                [],
            )

    def test_a_literal_argument_still_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            issues = self._issues(
                directory, 'Schedule schedule = new Schedule("http://a.b");')
        self.assertEqual(len(issues), 1)
        self.assertIn("with 1 argument(s)", issues[0]["details"][0])

    def test_a_commented_out_or_unchanged_call_is_not_judged(self):
        """Talk's SSLSocketFactoryCompat draft kept a commented-out call (2026-10-25)."""
        with tempfile.TemporaryDirectory() as directory:
            error = self._repository(directory)
            path = "app/src/main/java/net/gaast/giggity/Loader.java"
            existing = "        Schedule old = new Schedule(url, cache);\n"
            commented = ("//      httpClient.addInterceptor(new Schedule(userManager, "
                         "context, sslSocketFactoryCompat, trustManager));\n")
            issues = unresolvable_constructor_calls(error, [{
                "source_file_path": path, "edit_kind": "method",
                "original_code": existing,
                "corrected_code": existing + commented + "        run();\n",
            }])
            added = unresolvable_constructor_calls(error, [{
                "source_file_path": path, "edit_kind": "method",
                "original_code": existing,
                "corrected_code": existing + "        Schedule s = new Schedule(url, cache);\n",
            }])
        self.assertEqual(issues, [])
        self.assertEqual(len(added), 1)

    def test_a_java_call_to_a_kotlin_constructor_is_not_judged(self):
        """Talk's RemoteWipeInterceptor is a Kotlin class with a primary constructor."""
        with tempfile.TemporaryDirectory() as directory:
            error = self._repository(directory)
            package = Path(directory) / "app/src/main/java/net/gaast/giggity"
            (package / "RemoteWipeInterceptor.kt").write_text(
                "package net.gaast.giggity\n\n"
                "class RemoteWipeInterceptor(\n"
                "    private val userManager: UserManager,\n"
                "    private val context: Context,\n"
                ") : Interceptor {\n}\n",
                encoding="utf-8",
            )
            issues = unresolvable_constructor_calls(error, [{
                "source_file_path": "app/src/main/java/net/gaast/giggity/RestModule.java",
                "edit_kind": "method", "original_code": "",
                "corrected_code": "builder.addInterceptor(new RemoteWipeInterceptor(userManager, context));",
            }])
        self.assertEqual(issues, [])



class _RecordingDraftProvider:
    """A draft provider that keeps every prompt it was given.

    It answers with an edit that is shape-valid against _SCHEDULE_SOURCE, so
    generation reaches every planned file instead of aborting on the first.
    """

    context_length = 16384

    def __init__(self):
        self.prompts = []

    def generate(self, prompt, *_args, **_kwargs):
        self.prompts.append(prompt)
        marker = '"target_file":'
        relative = json.JSONDecoder().raw_decode(
            prompt.split(marker, 1)[1].lstrip())[0]
        new_file = '"new_file":true' in prompt.split(marker, 1)[1][:400]
        edit = {
            "source_file_path": relative, "symbol": "getUrl",
            "edit_kind": "create" if new_file else "method",
            "original_code": "" if new_file else "        return url;",
            "corrected_code": (
                "class ScheduleTest { }" if new_file
                else "        return this.url;"
            ),
            "reason": "coordinated",
        }
        return json.dumps({
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "source_file_path": relative,
            "explanation": "file edit",
            "edits": [edit],
            "provided_contracts": [relative + ":getUrl"],
            "required_contracts": [], "required_tests": ["round trip"],
            "manual_review_required": True,
            "review_assumptions": ["review lifecycle"],
            "confidence": "medium",
        })


class CoordinatedGenerationContextTests(unittest.TestCase):
    """A created test file must be told the API of the file it exercises.

    The giggity run generated a test against a constructor that does not
    exist, and the model explained why: the target source was empty because
    the file was new, so it had nothing to verify the API against. Every
    file in the batch now receives its siblings' declarations, because
    previous_file_contracts carries their edits, not their declarations.
    """

    def _run(self, provider):
        directory = tempfile.mkdtemp()
        root = Path(directory)
        repo = root / "repo"
        production = repo / "src/Schedule.java"
        production.parent.mkdir(parents=True)
        production.write_text(_SCHEDULE_SOURCE, encoding="utf-8")
        generator = object.__new__(FixGenerator)
        generator.output_dir = root / "out"
        generator.provider = provider
        generator.web_search = False
        error = {
            "repository_path": str(repo), "error_index": 1,
            "case_migration_policy": {},
            "evidence_analysis": {
                "confirmed_cause": "cause",
                "coordinated_fix_plan": {"required_edits": [
                    {"source_file_path": "src/Schedule.java", "symbol": "v"},
                    {"source_file_path": "src/test/ScheduleTest.java",
                     "symbol": "v", "create_new_file": True},
                ], "required_tests": ["round trip"]},
            },
        }
        return generator.generate_coordinated_file_drafts(
            error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "hashCode"
        )

    def _prompt_for(self, provider, needle):
        matches = [item for item in provider.prompts
                   if '"target_file":"%s"' % needle in item]
        self.assertEqual(len(matches), 1, "expected one prompt for " + needle)
        return matches[0]

    def test_a_created_test_file_receives_the_production_api(self):
        provider = _RecordingDraftProvider()
        self._run(provider)
        prompt = self._prompt_for(provider, "src/test/ScheduleTest.java")
        payload = json.loads(prompt.split("\n\n", 1)[1].split(
            "\n\nREQUIRED JSON SCHEMA:", 1)[0])
        # The file itself is new, so its own source is empty on purpose.
        self.assertEqual(payload["source"], "")
        self.assertTrue(payload["new_file"])
        outline = payload["sibling_files_api_surface"]["src/Schedule.java"]
        self.assertIn("public Schedule()", outline)
        self.assertIn("Item(String guid, String id)", outline)

    def test_a_file_is_not_given_its_own_outline(self):
        provider = _RecordingDraftProvider()
        self._run(provider)
        prompt = self._prompt_for(provider, "src/Schedule.java")
        payload = json.loads(prompt.split("\n\n", 1)[1].split(
            "\n\nREQUIRED JSON SCHEMA:", 1)[0])
        self.assertNotIn(
            "src/Schedule.java", payload["sibling_files_api_surface"]
        )



_ITEM_SOURCE = """package net.gaast.giggity;

public class Schedule {
    public class Item implements Comparable<Item> {
        Item(String guid, String id) {
        }

        public int hashCode() {
            return 1;
        }
    }
}
"""

_EQUATABLE_SOURCE = """package net.gaast.giggity;

public class Money {
    public Money(int cents) {
    }

    @Override
    public boolean equals(Object other) {
        return true;
    }
}
"""


class IdentityEqualityAssertionTests(unittest.TestCase):
    """A test asserting equality on a type without equals() can only fail.

    The giggity test built two Schedule.Item values with identical fields
    and asserted assertEquals(first, second). Item declares no
    equals(Object), so Java compared references: the assertion failed after
    a compile that had finally succeeded and a full unit-test run. The
    repair stage had already written exactly this in its
    remaining_uncertainties, so the knowledge existed and nothing used it.
    """

    def _repository(self, directory, sources):
        root = Path(directory)
        package = root / "app/src/main/java/net/gaast/giggity"
        package.mkdir(parents=True)
        for name, content in sources.items():
            (package / name).write_text(content, encoding="utf-8")
        return {"repository_path": str(root)}

    def _issues(self, directory, code, sources=None):
        error = self._repository(
            directory, sources or {"Schedule.java": _ITEM_SOURCE})
        return identity_equality_assertions(error, [{
            "source_file_path": "app/src/test/java/ScheduleTest.java",
            "edit_kind": "create",
            "corrected_code": code,
        }])

    def test_flags_equality_between_two_identity_typed_locals(self):
        with tempfile.TemporaryDirectory() as directory:
            issues = self._issues(directory, (
                "Schedule.Item first = item();\n"
                "Schedule.Item second = item();\n"
                "assertEquals(first, second);\n"
            ))
            self.assertEqual(len(issues), 1)
            self.assertEqual(
                issues[0]["code"], "EQUALITY_ASSERTED_ON_IDENTITY_TYPE")
            self.assertIn("declares no equals(Object)", issues[0]["details"][0])

    def test_resolves_a_nested_type_through_its_outer_file(self):
        # Schedule.Item lives in Schedule.java: a simple-name lookup for
        # Item.java finds nothing and the gate would go silent.
        with tempfile.TemporaryDirectory() as directory:
            issues = self._issues(directory, (
                "Schedule.Item first = item();\n"
                "Schedule.Item second = item();\n"
                "assertEquals(first, second);\n"
            ))
            self.assertTrue(issues)

    def test_stays_silent_when_the_type_overrides_equals(self):
        with tempfile.TemporaryDirectory() as directory:
            issues = self._issues(
                directory,
                "Money first = a();\nMoney second = b();\n"
                "assertEquals(first, second);\n",
                {"Money.java": _EQUATABLE_SOURCE},
            )
            self.assertEqual(issues, [])

    def test_stays_silent_on_hash_code_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            issues = self._issues(directory, (
                "Schedule.Item first = item();\n"
                "Schedule.Item second = item();\n"
                "assertEquals(first.hashCode(), second.hashCode());\n"
            ))
            self.assertEqual(issues, [])

    def test_stays_silent_on_a_type_the_repository_does_not_declare(self):
        with tempfile.TemporaryDirectory() as directory:
            issues = self._issues(directory, (
                "Instant first = a();\nInstant second = b();\n"
                "assertEquals(first, second);\n"
            ))
            self.assertEqual(issues, [])

    def test_reads_past_a_junit_message_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            issues = self._issues(directory, (
                "Schedule.Item first = item();\n"
                "Schedule.Item second = item();\n"
                'assertEquals("same fields", first, second);\n'
            ))
            self.assertEqual(len(issues), 1)

    def test_dropping_added_api_also_regenerates_the_tests_written_against_it(self):
        targets = semantic_validation_retry_targets(
            [{"code": "UNNECESSARY_PUBLIC_API_EXPANSION", "path": "src/Service.kt"}],
            ["src/Service.kt", "src/androidTest/ServiceTest.kt", "src/Other.kt"],
        )
        self.assertEqual(targets, {"src/Service.kt", "src/androidTest/ServiceTest.kt"})

    def test_the_code_is_a_test_retry_target(self):
        # The offending file is the test, so a retry must regenerate it
        # rather than the production edit.
        targets = semantic_validation_retry_targets(
            [{"code": "EQUALITY_ASSERTED_ON_IDENTITY_TYPE"}],
            ["src/Schedule.java", "src/test/ScheduleTest.java"],
        )
        self.assertEqual(targets, {"src/test/ScheduleTest.java"})



class EvidenceRequestClassificationTests(unittest.TestCase):
    """The extractor names what it is missing; most of it is unobtainable.

    Of the 193 requested_evidence items in the recorded runs, 106 ask to
    observe a running program. Classifying them is what keeps the retrieval
    honest: a request is either answered with real file content or declined
    with the reason, never silently treated as satisfied.
    """

    def test_a_runtime_observation_is_not_answerable_from_source(self):
        self.assertEqual(
            classify_evidence_request({
                "kind": "handshake_telemetry",
                "symbol": "SSLSession.getProtocol()"}),
            evidence_requests.RUNTIME_ONLY,
        )

    def test_runtime_wins_over_a_configuration_wording(self):
        # "runtime_configuration_evidence" asks for the value a process used,
        # which reading the configuration file cannot establish.
        self.assertEqual(
            classify_evidence_request({
                "kind": "runtime_configuration_evidence",
                "symbol": "enabled protocols"}),
            evidence_requests.RUNTIME_ONLY,
        )

    def test_a_named_type_is_a_source_request(self):
        self.assertEqual(
            classify_evidence_request({
                "kind": "source",
                "symbol": "at.bitfire.cert4android.CustomCertManager"}),
            evidence_requests.REPOSITORY_SOURCE,
        )

    def test_a_dependency_request_is_build_configuration(self):
        self.assertEqual(
            classify_evidence_request({
                "kind": "resolved_dependency_graph_or_lockfile",
                "symbol": "OkHttp version"}),
            evidence_requests.BUILD_CONFIGURATION,
        )

    def test_type_names_come_from_a_qualified_symbol(self):
        names = requested_type_names({
            "symbol": "at.bitfire.cert4android.CustomCertManager and "
                      "CustomCertManager.hostnameVerifier(...)"})
        self.assertIn("CustomCertManager", names)


class EvidenceRetrievalTests(unittest.TestCase):
    """What the repository can answer is fetched; the rest is declined."""

    def _repository(self, directory):
        root = Path(directory)
        package = root / "app/src/main/java/com/example"
        package.mkdir(parents=True)
        (package / "Schedule.java").write_text(
            "package com.example;\npublic class Schedule {\n"
            "    public class Item { }\n}\n",
            encoding="utf-8",
        )
        (root / "build.gradle").write_text(
            "dependencies { implementation 'com.squareup.okhttp3:okhttp:4.9.0' }\n",
            encoding="utf-8",
        )
        tests = root / "app/src/test/java/com/example"
        tests.mkdir(parents=True)
        (tests / "ScheduleTest.java").write_text(
            "class ScheduleTest { Schedule s; }\n", encoding="utf-8")
        return root

    def test_fetches_the_source_of_a_named_type(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            result = resolve_evidence_requests(
                root, [{"kind": "source", "symbol": "com.example.Schedule"}],
                set())
            paths = [item["data"]["source_file_path"]
                     for item in result["entries"]]
            self.assertIn("app/src/main/java/com/example/Schedule.java", paths)

    def test_resolves_a_nested_type_through_its_outer_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            result = resolve_evidence_requests(
                root, [{"kind": "source", "symbol": "Schedule.Item"}], set())
            self.assertTrue(result["entries"])

    def test_fetches_tests_that_mention_the_symbol(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            result = resolve_evidence_requests(
                root, [{"kind": "targeted_tests", "symbol": "Schedule"}], set())
            paths = [item["data"]["source_file_path"]
                     for item in result["entries"]]
            self.assertIn("app/src/test/java/com/example/ScheduleTest.java",
                          paths)

    def test_declines_a_runtime_request_with_its_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            result = resolve_evidence_requests(
                root,
                [{"kind": "runtime_trace", "symbol": "SSLSession.getProtocol()"}],
                set())
            self.assertEqual(result["entries"], [])
            self.assertEqual(len(result["declined"]), 1)
            self.assertIn("running program", result["declined"][0]["reason"])

    def test_declines_a_type_the_repository_does_not_contain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            result = resolve_evidence_requests(
                root, [{"kind": "source", "symbol": "OkHttpClient"}], set())
            self.assertEqual(result["entries"], [])
            self.assertIn("no matching file", result["declined"][0]["reason"])

    def test_never_refetches_evidence_the_packet_already_carries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            result = resolve_evidence_requests(
                root, [{"kind": "source", "symbol": "com.example.Schedule"}],
                {"app/src/main/java/com/example/Schedule.java"})
            self.assertEqual(result["entries"], [])

    def test_one_request_cannot_consume_the_whole_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            for index in range(6):
                (root / f"module{index}").mkdir()
                (root / f"module{index}/build.gradle").write_text(
                    "// module\n", encoding="utf-8")
            result = resolve_evidence_requests(
                root, [{"kind": "build", "symbol": "gradle"}], set())
            self.assertLessEqual(
                len(result["entries"]),
                evidence_requests.MAX_ENTRIES_PER_REQUEST,
            )

    def test_an_all_runtime_batch_never_walks_the_repository(self):
        # The walk costs seconds on a mounted filesystem; nothing to look up
        # means it must not happen at all.
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            with patch.object(evidence_requests, "RepositoryIndex") as index:
                result = resolve_evidence_requests(
                    root,
                    [{"kind": "runtime_trace", "symbol": "x"},
                     {"kind": "handshake_telemetry", "symbol": "y"}],
                    set())
            index.assert_not_called()
            self.assertEqual(len(result["declined"]), 2)

    def test_fetched_entries_are_citable_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            result = resolve_evidence_requests(
                root, [{"kind": "source", "symbol": "com.example.Schedule"}],
                set())
            supplement = catalog_supplement(result["entries"])
            self.assertEqual(supplement[0]["evidence_id"], "SUP-001")
            self.assertTrue(supplement[0]["sha256"])
            self.assertFalse(supplement[0]["mandatory"])



class RetryTargetingTests(unittest.TestCase):
    """A retry must regenerate the file that actually carries the defect.

    The router read only `path`, while the checks in this module report the
    offending file as `source_file_path` -- the shape an edit uses. So the
    precise per-file targeting silently never fired for them and the retry
    fell back to the error code's half of the plan. For
    CONSTRUCTOR_NOT_DECLARED_IN_REPOSITORY that half is production, and
    giggity's offending constructor call was in the generated test: the
    retry would have regenerated the already-correct production fix and
    left the broken test exactly as it was.

    The errors below come from the real gates rather than hand-written
    dicts, because a dict written by hand carries whichever key the author
    remembers -- which is how the mismatch survived in the first place.
    """

    PRODUCTION = "app/src/main/java/net/gaast/giggity/Schedule.java"
    TEST = "app/src/test/java/net/gaast/giggity/ScheduleHashCodeTest.java"
    SOURCE = (
        "package net.gaast.giggity;\n"
        "public class Schedule {\n"
        "    public Schedule() { }\n"
        "    public class Item {\n"
        "        Item(String guid) { }\n"
        "    }\n"
        "}\n"
    )

    def _error(self, directory):
        root = Path(directory)
        (root / self.PRODUCTION).parent.mkdir(parents=True)
        (root / self.PRODUCTION).write_text(self.SOURCE, encoding="utf-8")
        return {"repository_path": str(root),
                "source_file_path": self.PRODUCTION}

    def _targets(self, errors):
        return semantic_validation_retry_targets(
            errors, [self.PRODUCTION, self.TEST])

    def test_a_constructor_defect_in_a_test_retries_the_test(self):
        with tempfile.TemporaryDirectory() as directory:
            errors = unresolvable_constructor_calls(
                self._error(directory),
                [{"source_file_path": self.TEST, "edit_kind": "create",
                  "corrected_code": "Schedule s = new Schedule(url);"}],
            )
            self.assertTrue(errors)
            self.assertEqual(self._targets(errors), {self.TEST})

    def test_a_constructor_defect_in_production_retries_production(self):
        with tempfile.TemporaryDirectory() as directory:
            errors = unresolvable_constructor_calls(
                self._error(directory),
                [{"source_file_path": self.PRODUCTION, "edit_kind": "method",
                  "corrected_code": "Schedule s = new Schedule(url);"}],
            )
            self.assertTrue(errors)
            self.assertEqual(self._targets(errors), {self.PRODUCTION})

    def test_an_equality_defect_retries_the_test_that_asserts_it(self):
        with tempfile.TemporaryDirectory() as directory:
            errors = identity_equality_assertions(
                self._error(directory),
                [{"source_file_path": self.TEST, "edit_kind": "create",
                  "corrected_code": "Schedule.Item a = x();\n"
                                    "Schedule.Item b = y();\n"
                                    "assertEquals(a, b);\n"}],
            )
            self.assertTrue(errors)
            self.assertEqual(self._targets(errors), {self.TEST})

    def test_the_router_reads_either_file_key(self):
        # `path` is the older spelling and must keep working.
        self.assertEqual(
            self._targets([{"code": "X", "path": self.TEST}]), {self.TEST})
        self.assertEqual(
            self._targets([{"code": "X", "source_file_path": self.TEST}]),
            {self.TEST})

    def test_an_unknown_code_without_a_file_regenerates_everything(self):
        self.assertEqual(
            self._targets([{"code": "SOMETHING_NEW"}]),
            {self.PRODUCTION, self.TEST},
        )



_SYMBOL_REPO_SOURCE = """package com.example;

import java.io.Serializable;

public class Schedule implements Serializable {
    public Schedule() { }

    public Item getItem(String id) {
        return null;
    }

    public void loadSchedule(BufferedReader in,
                             String url) throws IOException, LoadException {
    }

    public class Item implements Comparable<Item>, Serializable {
        public int compareTo(Item other) { return 0; }
    }
}
"""


class SymbolResolutionTests(unittest.TestCase):
    """Reject a call to a method the receiver's type does not declare.

    Every validation failure measured across the recorded runs was in a
    generated test writing against an API the model expected rather than
    the one the repository declares. Catching that here replaces a two- to
    five-minute Gradle round trip with a source check.

    The gate reports only a method name that appears nowhere in the type's
    readable hierarchy. Argument counts are deliberately not judged for
    methods: an overload whose other form the outline could not parse made
    that produce false positives on code that compiles.
    """

    def _error(self, directory, sources=None):
        root = Path(directory)
        package = root / "app/src/main/java/com/example"
        package.mkdir(parents=True)
        for name, content in (sources or
                              {"Schedule.java": _SYMBOL_REPO_SOURCE}).items():
            (package / name).write_text(content, encoding="utf-8")
        return {"repository_path": str(root)}

    def _issues(self, directory, code, sources=None):
        return unresolved_repository_symbols(
            self._error(directory, sources),
            [{"source_file_path": "app/src/test/java/ScheduleTest.java",
              "edit_kind": "create", "corrected_code": code}],
        )

    def test_flags_a_method_the_type_never_declares(self):
        with tempfile.TemporaryDirectory() as directory:
            issues = self._issues(
                directory,
                "Schedule schedule = build();\nschedule.findItemByGuid(id);\n")
            self.assertEqual(len(issues), 1)
            self.assertEqual(
                issues[0]["code"], "SYMBOL_NOT_DECLARED_IN_REPOSITORY")
            self.assertIn("findItemByGuid", issues[0]["details"][0])

    def test_accepts_a_declared_method(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                self._issues(directory,
                             "Schedule schedule = build();\n"
                             "schedule.getItem(id);\n"),
                [],
            )

    def test_accepts_a_signature_wrapped_across_lines(self):
        # loadSchedule's parameter list spans two lines; a per-line scanner
        # drops it and the caller looks like it invented the method.
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                self._issues(directory,
                             "Schedule schedule = build();\n"
                             "schedule.loadSchedule(reader, url);\n"),
                [],
            )

    def test_accepts_a_method_inherited_from_a_repository_supertype(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                self._issues(
                    directory,
                    "Derived value = build();\nvalue.getItem(id);\n",
                    {"Schedule.java": _SYMBOL_REPO_SOURCE,
                     "Derived.java": "package com.example;\n"
                                     "public class Derived extends Schedule { }\n"},
                ),
                [],
            )

    def test_stays_silent_when_a_supertype_lies_outside_the_repository(self):
        # Anything extending Application inherits an API this cannot read.
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                self._issues(
                    directory,
                    "App app = build();\napp.getProcessName();\n",
                    {"App.java": "package com.example;\n"
                                 "public class App extends Application { }\n"},
                ),
                [],
            )

    def test_a_marker_interface_does_not_silence_the_check(self):
        # Implementing Serializable is near-universal; treating it as opaque
        # would switch the gate off for almost every class.
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(self._issues(
                directory,
                "Schedule schedule = build();\nschedule.notAMethod();\n"))

    def test_accepts_object_methods_on_any_receiver(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                self._issues(directory,
                             "Schedule schedule = build();\n"
                             "schedule.hashCode();\n"),
                [],
            )

    def test_accepts_the_synthetic_members_of_an_enum(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                self._issues(
                    directory, "Category.values();\n",
                    {"Category.java": "package com.example;\n"
                                      "public enum Category { A, B }\n"},
                ),
                [],
            )

    def test_accepts_the_accessors_of_a_record(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                self._issues(
                    directory,
                    "Strs strs = build();\nstrs.policyName();\n",
                    {"Strs.java": "package com.example;\n"
                                  "public record Strs(String policyName, "
                                  "String ownSymbols) { }\n"},
                ),
                [],
            )

    def test_ignores_a_commented_out_call(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                self._issues(directory,
                             "Schedule schedule = build();\n"
                             "// schedule.findItemByGuid(id);\n"),
                [],
            )

    def test_stays_silent_on_a_kotlin_declaration(self):
        # Kotlin puts callables in companion objects and generated accessors
        # that this Java-shaped reader does not see.
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                self._issues(
                    directory, "HttpClient.create(context);\n",
                    {"HttpClient.kt": "package com.example\n"
                                      "class HttpClient { }\n"},
                ),
                [],
            )

    def test_stays_silent_when_the_simple_name_is_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for area in ("main", "androidTest"):
                package = root / f"app/src/{area}/java/com/example"
                package.mkdir(parents=True)
                (package / "Utils.java").write_text(
                    "package com.example;\npublic class Utils { }\n",
                    encoding="utf-8")
            issues = unresolved_repository_symbols(
                {"repository_path": str(root)},
                [{"source_file_path": "app/src/test/java/T.java",
                  "corrected_code": "Utils.whatever(a);\n"}],
            )
            self.assertEqual(issues, [])

    def test_stays_silent_on_a_receiver_of_unknown_type(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                self._issues(directory, "something.whatever(1);\n"), [])



class PostValidationIssueCandidateTests(unittest.TestCase):
    """Keep the model's reasoning when generation is blocked after adjudication.

    On com.gelakinetic.mtgfam's decrypt the model declined eligibility -- no
    PR was ready, correctly -- and wrote the reasons anyway, asking which
    component produces the three hard-coded ciphertexts. That is the question
    that settles whether the finding can be fixed at all: the app only ever
    decrypts, so nothing in the repository can re-encrypt them. The whole
    presentation was discarded because eligible was false, and replaced by a
    template asking the maintainer to "clarify the unresolved scope and
    compatibility assumptions" -- while the replacement set eligible to true
    regardless. Eligibility is this layer's call; the explanation is not.
    """

    MODEL_ISSUE = {
        "eligible": False,
        "title": "Confirm ciphertext producer and migration contract",
        "finding_summary": "The evidenced paths configure AES/CBC/PKCS5Padding.",
        "why_no_pr": "The producer and format of the ciphertexts are unknown.",
        "maintainer_question": "Which component produces the ciphertexts?",
        "proposed_next_step": "Identify the producer, then validate a migration.",
    }
    BLOCKERS = ["ciphertext_format_and_producer_compatibility",
                "key_iv_lifecycle"]

    def _candidate(self, issue, style="v1"):
        return post_validation_issue_candidate(
            issue, self.BLOCKERS, "decrypt", "CipherSpec",
            "a confirmed cause", style)

    def test_a_complete_presentation_is_kept(self):
        result = self._candidate(self.MODEL_ISSUE)
        self.assertEqual(result["presentation_source"],
                         "model_presentation_retained")
        self.assertEqual(result["maintainer_question"],
                         "Which component produces the ciphertexts?")

    def test_eligibility_is_decided_here_not_by_the_model(self):
        # The model said false; this layer holds the blockers and publishes.
        result = self._candidate(self.MODEL_ISSUE)
        self.assertTrue(result["eligible"])

    def test_the_blockers_are_recorded_alongside_the_kept_text(self):
        result = self._candidate(self.MODEL_ISSUE)
        self.assertIn("ciphertext_format_and_producer_compatibility",
                      result["post_validation_blockers"])

    def test_an_incomplete_presentation_falls_back_to_the_template(self):
        partial = dict(self.MODEL_ISSUE, maintainer_question="")
        result = self._candidate(partial)
        self.assertEqual(result["presentation_source"],
                         "deterministic_post_validation_fallback")
        self.assertIn("clarify", result["maintainer_question"])

    def test_a_missing_presentation_falls_back_to_the_template(self):
        for empty in ({}, None, "not a dict"):
            result = self._candidate(empty)
            self.assertEqual(result["presentation_source"],
                             "deterministic_post_validation_fallback")

    def test_the_first_person_template_is_used_for_the_v2_style(self):
        result = self._candidate({}, style="v2")
        self.assertIn("I have not opened a pull request", result["why_no_pr"])

    def test_the_template_names_the_actual_blockers(self):
        result = self._candidate({})
        self.assertIn("key_iv_lifecycle", result["why_no_pr"])

    def test_no_blockers_still_produces_a_usable_explanation(self):
        result = post_validation_issue_candidate(
            {}, [], "decrypt", "CipherSpec", "a cause", "v1")
        self.assertIn("does not authorize a safe patch", result["why_no_pr"])

    def test_every_required_field_is_present_on_both_paths(self):
        for issue in (self.MODEL_ISSUE, {}):
            result = self._candidate(issue)
            for field in ISSUE_PRESENTATION_FIELDS:
                self.assertTrue(str(result.get(field, "")).strip(), field)


class PlatformDefaultPrecedencePromptTests(unittest.TestCase):
    """The rule-only change for a platform default must not move the finding.

    The explicit form of a TLS context initialised with nulls passes the
    factories their own null/default argument, which the runtime checker
    reports under their specifications: a pull request built on it trades
    one finding for another. Without a clean producer the code is the
    documented use and ends as a violation without security impact.
    """

    @classmethod
    def setUpClass(cls):
        cls.system = " ".join(_adjudication_system_prompt().split())

    def _precedence(self):
        start = self.system.index("This takes precedence over either list")
        return self.system[start:self.system.index(
            "reported_by_rule.non_security_violation_shapes is different", start)]

    def test_the_precedence_requires_every_added_call_to_satisfy_its_own_spec(self):
        precedence = self._precedence()
        self.assertIn("every call that explicit form adds itself satisfies its own "
                      "specification", precedence)
        self.assertIn("passes no null or omitted platform-default argument to another "
                      "governed API", precedence)
        self.assertIn("trades this finding for another", precedence)
        self.assertNotIn("default factories", self.system)
        self.assertNotIn("TLS context", precedence)

    def test_without_a_clean_producer_the_finding_is_the_documented_use(self):
        precedence = self._precedence()
        tail = precedence[precedence.index("this does not apply"):]
        # documented_use_without_security_impact needs a confirmed cause;
        # without one the finding falls back to a maintainer issue.
        self.assertIn("detector_violation confirmed", tail)
        self.assertIn("cause_status confirmed", tail)
        self.assertIn("confirmed_cause", tail)
        self.assertIn("decision NO_SAFE_FIX", tail)
        self.assertIn("runtime_security_impact non_security", tail)
        self.assertIn("propose no edit", tail)
        self.assertIn("correct-use answer described above", tail)
        # "above" must hold: the correct-use answer is described earlier.
        self.assertLess(self.system.index("current_code_is_correct_use"),
                        self.system.index("This takes precedence over either list"))

    def test_the_correct_use_answer_does_not_count_a_moved_default_as_a_fix(self):
        start = self.system.index("Set current_code_is_correct_use to true")
        correct_use = self.system[start:self.system.index("A FLOW evidence entry", start)]
        self.assertIn("passes a null or omitted platform-default argument to another "
                      "governed API only moves the finding and does not count as "
                      "satisfying the rule", correct_use)


def _adjudication_system_prompt() -> str:
    """The adjudication system prompt, captured from a stubbed provider."""
    systems = {}

    class Provider:
        provider_name, model = "test", "test-model"

        @staticmethod
        def get_token_usage():
            return {"input": 0, "output": 0}

        def generate(self, prompt, system=None, **kwargs):
            stage = kwargs.get("trace_stage", "")
            systems.setdefault(stage, system or "")
            if stage == "evidence_extraction":
                return json.dumps({
                    "claims": [], "observed_events": [], "predicate_assessment": [],
                    "confirmed_dataflows": [], "relations": [], "unresolved_questions": [],
                    "needs_more_evidence": False, "requested_evidence": [],
                    "family_assessment": {}})
            return json.dumps({
                "cause_status": "unknown", "confirmed_cause": "", "detector_violation": "unknown",
                "runtime_security_impact": "unknown", "compatibility_status": "unknown",
                "scope_status": "incomplete", "decision": "NO_SAFE_FIX",
                "decision_claim_ids": [], "blocking_for_generation": [],
                "blocking_for_publication": [], "generation_status": "blocked",
                "publication_status": "blocked", "required_edit_categories": [],
                "required_tests": [], "forward_compatibility_strategy": "",
                "authorized_behavior_change": {"authorized": False, "description": "",
                                               "policy_reference": ""},
                "review_assumptions": []})

    with tempfile.TemporaryDirectory() as directory:
        generator = object.__new__(FixGenerator)
        generator.output_dir = Path(directory) / "out"
        generator.provider = Provider()
        generator.web_search = False
        generator.architecture_version = "v2"
        generator.logger = logging.getLogger("test")
        generator.evidence_packet_builder = FindingEvidencePacketBuilder(
            repository_context_budget=140_000)
        generator.policy_registry = PolicyRegistry(Path(directory) / "no_policies")
        generator.adjudicate_finding({
            "spec": "SSLContextSpec", "method_name": "buildSocket",
            "method_body": "ctx.init(null, null, null)", "imports": "",
            "source_file_path": "app/src/main/java/SSLConnector.java",
            "csv_class": "SSLConnector"}, "app.apk", "buildSocket")
    return systems.get("adjudication", "")


if __name__ == "__main__":
    unittest.main()


class V2ScopeCreditAndReviewLabelTests(unittest.TestCase):
    """The V2 projection must not manufacture a spurious scope abstention.

    Reproduces me.blog.korn123.easydiary_346.apk / ZipHelper.decompress: the
    Zip Slip finding was fully evidenced, the adjudicator confirmed the cause
    with no generation blocker and produced a complete patch plan, and the run
    still abstained with INCOMPLETE_MULTI_FILE_SCOPE. Two independent defects
    stacked. The packet had handed the adjudicator both coverage_requirements
    files as mandatory related_source items, but the projection credited only
    plan edit targets and semantic relations, so validate_multi_file_scope
    graded them unreviewed; and the adjudicator returned MULTI_FILE_FIX_SUPPORTED
    with generation_status supported_for_review, which missed the review-only
    waiver written for precisely that state.
    """

    TARGET = "app/src/main/java/me/blog/korn123/easydiary/helper/ZipHelper.kt"
    VISITOR = (
        "app/src/main/java/me/blog/korn123/easydiary/helper/"
        "ZipHelperWithVisitor.kt"
    )
    WORKER = (
        "app/src/main/java/me/blog/korn123/easydiary/workers/"
        "FullRecoveryWorker.kt"
    )
    TEST_FILE = (
        "app/src/androidTest/java/me/blog/korn123/easydiary/helper/"
        "ZipHelperTest.kt"
    )

    def _packet(self):
        return {
            "finding": {"spec_family": "generic"},
            "evidence_catalog": [
                {"evidence_id": "SRC-001", "kind": "target_source",
                 "mandatory": True, "data": {"source_file_path": self.TARGET}},
                {"evidence_id": "SRC-002", "kind": "related_source",
                 "mandatory": True, "data": {"source_file_path": self.VISITOR}},
                {"evidence_id": "SRC-003", "kind": "related_source",
                 "mandatory": True, "data": {"source_file_path": self.WORKER}},
                {"evidence_id": "CALL-001", "kind": "lexical_caller",
                 "mandatory": False,
                 "data": {"path": self.WORKER, "enclosing_symbol": "decompress"}},
                {"evidence_id": "SRC-004", "kind": "related_source",
                 "mandatory": False,
                 "data": {"source_file_path":
                          "app/src/main/java/p/Unrelated.kt"}},
            ],
        }

    def _projected(self, generation_status="supported_for_review"):
        return _analysis_record(
            {"case_migration_policy": {}},
            self._packet(),
            {"sources": []},
            {"claims": [], "family_assessment": {}},
            {
                "decision": "MULTI_FILE_FIX_SUPPORTED",
                "cause_status": "confirmed",
                "scope_status": "complete",
                "generation_status": generation_status,
                "publication_status": "blocked",
                "blocking_for_generation": [],
                "blocking_for_publication": [
                    {"kind": "regression_validation", "description": "no test"},
                ],
            },
            {"required_edits": [
                {"source_file_path": self.TARGET, "symbol": "decompress"},
                {"source_file_path": self.TEST_FILE, "symbol": "tests"},
            ]},
            {"eligible": False},
        )

    def _error(self):
        return {
            "expanded_repository_context": {"multi_file_impact": {
                "status": "available",
                "multi_file_candidate": True,
                "scope_completeness": {"status": "complete"},
                "coverage_requirements": {
                    "flow_consumer_files": [self.VISITOR, self.WORKER],
                },
            }},
            "case_migration_policy": {},
        }

    def test_mandatory_coverage_evidence_counts_as_reviewed(self):
        reviewed = {
            item["source_file_path"]: item["action"]
            for item in self._projected()["scope_assessment"]["reviewed_files"]
        }
        self.assertEqual(reviewed.get(self.VISITOR), "mandatory_context_reviewed")
        # The worker is both a mandatory source and the lexical caller; the
        # first credit wins and the path is recorded exactly once.
        self.assertIn(self.WORKER, reviewed)
        self.assertEqual(reviewed[self.TARGET], "edit")
        self.assertEqual(reviewed[self.TEST_FILE], "required_test")

    def test_supplementary_sources_are_not_credited(self):
        reviewed = {
            item["source_file_path"]
            for item in self._projected()["scope_assessment"]["reviewed_files"]
        }
        self.assertNotIn("app/src/main/java/p/Unrelated.kt", reviewed)

    def test_reviewable_generation_projects_to_the_review_only_label(self):
        self.assertEqual(
            self._projected()["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"
        )

    def test_automatic_generation_keeps_the_auto_apply_label(self):
        self.assertEqual(
            self._projected("supported")["decision"], "MULTI_FILE_FIX_SUPPORTED"
        )

    def test_the_finding_no_longer_abstains_on_scope(self):
        issues = validate_multi_file_scope(self._error(), self._projected())
        self.assertEqual(issues, [])


class SingleFileReviewOnlyPlanTests(unittest.TestCase):
    """A review-only plan of one file must not fail two contradictory gates.

    minimum_planned_files deliberately allows a REVIEW_ONLY_DECISIONS plan to
    be one correctly-scoped file, because forcing a second one made the model
    pad the diff or abstain. multi_file_change_required, however, is derived
    from that same file count, and the check on it applied to every
    MULTI_FILE_DECISIONS member -- so the single-file review-only plan passed
    one gate and died on the other, inside the same function. Observed on
    com.etesync.syncadapter's HttpClient.kt SSLContext finding.
    """

    def _analysis(self, decision, planned):
        return {
            "decision": decision,
            "architecture_version": "v2",
            "v2": {"adjudication": {
                "generation_status": "supported_for_review",
                "publication_status": "blocked",
                "blocking_for_generation": [],
            }},
            "scope_assessment": {
                "status": "complete",
                "local_code_scope": "complete",
                "multi_file_change_required": len(set(planned)) > 1,
                "unresolved_relations": [],
                "reviewed_files": [
                    {"source_file_path": p, "action": "edit"} for p in planned
                ],
            },
            "coordinated_fix_plan": {"required_edits": [
                {"source_file_path": p} for p in planned
            ]},
        }

    def _error(self):
        return {
            "expanded_repository_context": {"multi_file_impact": {
                "status": "available",
                "multi_file_candidate": True,
                "scope_completeness": {"status": "complete"},
                "coverage_requirements": {},
            }},
            "case_migration_policy": {},
        }

    def test_single_file_review_only_plan_is_accepted(self):
        issues = validate_multi_file_scope(
            self._error(),
            self._analysis("MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                           ["app/src/main/java/p/HttpClient.kt"]),
        )
        self.assertEqual(issues, [])

    def test_auto_apply_still_needs_two_files_and_the_flag(self):
        issues = validate_multi_file_scope(
            self._error(),
            self._analysis("MULTI_FILE_FIX_SUPPORTED",
                           ["app/src/main/java/p/HttpClient.kt"]),
        )
        self.assertTrue(
            any("multi_file_change_required" in issue for issue in issues),
            issues,
        )


class TestFileDoesNotMakeAFixMultiFileTests(unittest.TestCase):
    """A required new test must not turn a one-file fix into a multi-file one.

    multi_file_change_required counted every distinct planned edit path, and a
    required NEW TEST FILE is a distinct path. A plan of one production file
    plus its regression test therefore reported a multi-file change while the
    adjudicator answered FIX_SUPPORTED -- a combination validate_multi_file_
    scope rejects outright. Live on me.blog.korn123.easydiary's ZipHelper Zip
    Slip finding in run_20260908_151705, whose plan was exactly ZipHelper.kt
    plus a new ZipHelperTest.kt and whose adjudication was otherwise clean.
    """

    PROD = "app/src/main/java/me/blog/korn123/easydiary/helper/ZipHelper.kt"
    TEST = ("app/src/androidTest/java/me/blog/korn123/easydiary/helper/"
            "ZipHelperTest.kt")
    OTHER = "app/src/main/java/me/blog/korn123/easydiary/helper/Other.kt"

    def _projected(self, planned):
        return _analysis_record(
            {"case_migration_policy": {}},
            {"finding": {"spec_family": "generic"}, "evidence_catalog": []},
            {"sources": []},
            {"claims": [], "family_assessment": {}},
            {"decision": "FIX_SUPPORTED", "cause_status": "confirmed",
             "scope_status": "complete", "generation_status": "supported",
             "publication_status": "blocked",
             "blocking_for_generation": [], "blocking_for_publication": []},
            {"required_edits": [
                {"source_file_path": p, "symbol": "s"} for p in planned
            ]},
            {"eligible": False},
        )

    def test_production_file_plus_its_test_is_not_a_multi_file_change(self):
        analysis = self._projected([self.PROD, self.TEST])
        self.assertFalse(
            analysis["scope_assessment"]["multi_file_change_required"]
        )
        self.assertEqual(validate_multi_file_scope(self._error(), analysis), [])

    def test_two_production_files_still_are_a_multi_file_change(self):
        analysis = self._projected([self.PROD, self.OTHER, self.TEST])
        self.assertTrue(
            analysis["scope_assessment"]["multi_file_change_required"]
        )

    def test_the_test_file_is_still_labelled_as_a_required_test(self):
        analysis = self._projected([self.PROD, self.TEST])
        actions = {
            item["source_file_path"]: item["action"]
            for item in analysis["scope_assessment"]["reviewed_files"]
        }
        self.assertEqual(actions[self.TEST], "required_test")
        self.assertEqual(actions[self.PROD], "edit")

    def _error(self):
        return {
            "expanded_repository_context": {"multi_file_impact": {
                "status": "available", "multi_file_candidate": True,
                "scope_completeness": {"status": "complete"},
                "coverage_requirements": {},
            }},
            "case_migration_policy": {},
        }
