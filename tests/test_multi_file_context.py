import sys
import tempfile
import unittest
import json
import logging
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.multi_file_context import (  # noqa: E402
    _declaration_like,
    collect_multi_file_context,
)
from cognalys.llm.generate_error_fixes import (  # noqa: E402
    FixGenerator,
    validate_multi_file_scope,
)


class MultiFileContextTests(unittest.TestCase):
    def test_discovers_callers_declarations_tests_and_exact_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Crypto.kt"
            caller = root / "src" / "Consumer.kt"
            implementation = root / "src" / "OtherCrypto.kt"
            test = root / "test" / "CryptoTest.kt"
            contents = {
                target: "class Crypto {\n fun hash(value: String) = value\n}\n",
                caller: "class Consumer {\n fun use(c: Crypto) = c.hash(\"x\")\n}\n",
                implementation: "class OtherCrypto {\n fun hash(value: String) = value\n}\n",
                test: "fun testHash() { Crypto().hash(\"x\") }\n",
            }
            for path, content in contents.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            context = collect_multi_file_context(
                repo_root=root,
                source_file=target,
                method_name="hash",
                class_name="example.Crypto",
                method_body="fun hash(value: String) = value",
                source_cache=contents,
                repository_paths=list(contents),
                repository_index_metadata={"truncated": False},
            )

            self.assertTrue(context["multi_file_candidate"])
            self.assertIn("src/Consumer.kt", context["coverage_requirements"]["caller_files"])
            self.assertIn("src/OtherCrypto.kt", context["coverage_requirements"]["declaration_files"])
            self.assertIn("test/CryptoTest.kt", context["coverage_requirements"]["test_files"])
            exact_paths = {
                item["source_file_path"] for item in context["exact_candidate_sources"]
            }
            self.assertIn("src/Crypto.kt", exact_paths)
            self.assertIn("src/Consumer.kt", exact_paths)

    def _large_caller_context(self, caller_calls_target):
        """A 44,000-char caller file (NotallyX's ExportExtensions.kt was 44,298)."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "IOExtensions.kt"
            caller = root / "src" / "ExportExtensions.kt"
            call = "fun export(f: java.io.File) = f.md5Hash()\n" if caller_calls_target else ""
            contents = {
                target: "fun java.io.File.md5Hash(): ByteArray = readBytes()\n",
                caller: call + "// filler\n" * 4_400,
            }
            for path, content in contents.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            context = collect_multi_file_context(
                repo_root=root, source_file=target, method_name="md5Hash",
                class_name="example.IOExtensionsKt",
                method_body="fun java.io.File.md5Hash(): ByteArray = readBytes()",
                source_cache=contents, repository_paths=list(contents),
                repository_index_metadata={"truncated": False},
            )
        return context

    def test_a_large_caller_file_is_a_mandatory_exact_source(self):
        context = self._large_caller_context(caller_calls_target=True)
        exact = {item["source_file_path"]: item for item in context["exact_candidate_sources"]}
        self.assertGreater(len(exact["src/ExportExtensions.kt"]["content"]), 40_000)
        self.assertIn("src/ExportExtensions.kt", context["required_caller_sources"])
        self.assertIn("src/ExportExtensions.kt", context["coverage_requirements"]["caller_files"])

    def test_required_call_site_files_are_bounded_as_a_group(self):
        # A helper called from forty 90k-char files used to put 3.6M chars of
        # mandatory exact source into every prompt.
        from cognalys.extraction.multi_file_context import (
            MAX_REQUIRED_CALLER_FILES, MAX_REQUIRED_CALLER_TOTAL_CHARS,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app" / "src" / "main" / "IOExtensions.kt"
            contents = {target: "fun java.io.File.md5Hash(): ByteArray = readBytes()\n"}
            for index in range(40):
                caller = root / "app" / "src" / "main" / f"Caller{index:02}.kt"
                contents[caller] = (
                    f"fun use{index}(f: java.io.File) = f.md5Hash()\n" + "// filler\n" * 9_000)
            for path, content in contents.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            context = collect_multi_file_context(
                repo_root=root, source_file=target, method_name="md5Hash",
                class_name="example.IOExtensionsKt",
                method_body="fun java.io.File.md5Hash(): ByteArray = readBytes()",
                source_cache=contents, repository_paths=list(contents),
                repository_index_metadata={"truncated": False},
            )
        required = context["required_caller_sources"]
        exact = {item["source_file_path"]: item for item in context["exact_candidate_sources"]}
        self.assertTrue(required)
        self.assertLessEqual(len(required), MAX_REQUIRED_CALLER_FILES)
        self.assertLessEqual(
            sum(len(exact[path]["content"]) for path in required), MAX_REQUIRED_CALLER_TOTAL_CHARS)
        self.assertLess(sum(len(item["content"]) for item in exact.values()), 400_000)
        self.assertEqual(len(required) + len(context["omitted_required_caller_sources"]), 40)
        self.assertEqual(len(context["call_site_files"]), 40)

    def test_require_caller_sources_counts_the_callers_already_required(self):
        from cognalys.extraction.multi_file_context import (
            MAX_REQUIRED_CALLER_FILES, REQUIRED_CALLER_RELEVANCE, require_caller_sources,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            impact = {"target": {"source_file_path": "Target.kt"}, "exact_candidate_sources": [
                {"source_file_path": f"Old{index}.kt", "content": "x" * 10,
                 "relevance": [REQUIRED_CALLER_RELEVANCE]}
                for index in range(MAX_REQUIRED_CALLER_FILES - 1)]}
            for name in ("A.kt", "B.kt"):
                (root / name).write_text("fun f() = g()\n", encoding="utf-8")
            supplied = require_caller_sources(impact, root, ["A.kt", "B.kt"])
        self.assertEqual(supplied, ["A.kt"])
        self.assertEqual(impact["omitted_required_caller_sources"], ["B.kt"])

    def test_lexical_matches_of_another_api_are_not_required_callers(self):
        # Amethyst's MacInstance.init with the semantic index unresolved:
        # every unrelated `cipher.init(` became a mandatory exact source.
        from unittest import mock

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "MacInstance.kt"
            user = root / "src" / "Tagger.kt"
            contents = {
                target: "class MacInstance {\n fun init(key: ByteArray) {}\n}\n",
                user: "fun tag(m: MacInstance, k: ByteArray) = m.init(k)\n",
            }
            for index in range(15):
                contents[root / "src" / f"Box{index}.kt"] = (
                    "fun seal(c: javax.crypto.Cipher, k: java.security.Key) = "
                    "c.init(1, k)\nfun mac(m: javax.crypto.Mac, k: java.security.Key) = m.init(k)\n")
            for path, content in contents.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            with mock.patch("cognalys.extraction.semantic_index.build_semantic_index",
                            return_value={"status": "unresolved", "backend": "none"}):
                context = collect_multi_file_context(
                    repo_root=root, source_file=target, method_name="init",
                    class_name="example.MacInstance",
                    method_body="fun init(key: ByteArray) {}",
                    source_cache=contents, repository_paths=list(contents),
                    repository_index_metadata={"truncated": False},
                )
        self.assertEqual(context["required_caller_sources"], ["src/Tagger.kt"])
        self.assertEqual(context["call_site_files"], ["src/Tagger.kt"])

    def test_a_large_file_without_a_call_site_is_still_skipped(self):
        context = self._large_caller_context(caller_calls_target=False)
        exact = {item["source_file_path"] for item in context["exact_candidate_sources"]}
        self.assertNotIn("src/ExportExtensions.kt", exact)
        self.assertEqual(context["required_caller_sources"], [])

    def test_constructor_call_sites_are_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "RestService.java"
            caller = root / "src" / "Factory.java"
            contents = {
                target: "class RestService {\n RestService() {}\n}\n",
                caller: (
                    "class Factory {\n"
                    " RestService make() { return new RestService(); }\n"
                    "}\n"
                ),
            }
            for path, content in contents.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            context = collect_multi_file_context(
                repo_root=root,
                source_file=target,
                method_name="<init>",
                class_name="example.RestService",
                method_body="RestService() {}",
                source_cache=contents,
                repository_paths=list(contents),
                repository_index_metadata={"truncated": False},
            )

            self.assertIn(
                "src/Factory.java", context["coverage_requirements"]["caller_files"]
            )

    def test_kotlin_constructor_call_sites_are_discovered(self):
        # Amethyst MacInstance: Kotlin callers write `MacInstance(...)`.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "MacInstance.kt"
            caller = root / "src" / "EngramDTag.kt"
            java_declaration = root / "src" / "Other.java"
            contents = {
                target: "class MacInstance(algorithm: String, key: ByteArray) {\n}\n",
                caller: "fun tag(k: ByteArray) = MacInstance(\"HmacSHA256\", k)\n",
                java_declaration: "class Other {\n void f() {}\n}\n",
            }
            for path, content in contents.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            context = collect_multi_file_context(
                repo_root=root,
                source_file=target,
                method_name="<init>",
                class_name="example.MacInstance",
                method_body="class MacInstance(algorithm: String, key: ByteArray)",
                source_cache=contents,
                repository_paths=list(contents),
                repository_index_metadata={"truncated": False},
            )

            self.assertEqual(
                context["coverage_requirements"]["caller_files"], ["src/EngramDTag.kt"]
            )

    def test_nested_and_generic_constructor_calls_match_the_caller_contract(self):
        # Kotlin `Outer.Inner(` and Java `new a.Outer.Inner<>(` were missed
        # here while evidence_facts found them, so the two disagreed.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "a" / "Outer.kt"
            kotlin_caller = root / "b" / "Use.kt"
            java_caller = root / "c" / "Legacy.java"
            unrelated = root / "c" / "Other.kt"
            contents = {
                target: "package a\nsealed class Outer {\n    class Inner<T>(val k: T) : Outer()\n}\n",
                kotlin_caller: "package b\nimport a.Outer\nfun make(k: ByteArray) = Outer.Inner(k)\n",
                java_caller: "package c;\nclass Legacy {\n  Object f(byte[] k) { return new a.Outer.Inner<>(k); }\n}\n",
                unrelated: "package c\nfun g(x: Any) = x.Inner(1)\n",
            }
            for path, content in contents.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            context = collect_multi_file_context(
                repo_root=root,
                source_file=target,
                method_name="<init>",
                class_name="a.Outer$Inner",
                method_body="class Inner<T>(val k: T) : Outer()",
                source_cache=contents,
                repository_paths=list(contents),
                repository_index_metadata={"truncated": False},
            )

            self.assertEqual(
                sorted(context["coverage_requirements"]["caller_files"]),
                ["b/Use.kt", "c/Legacy.java"],
            )

    def test_exact_sources_anchor_an_untouched_test_source_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app" / "src" / "main" / "java" / "RestService.java"
            unrelated_test = (
                root / "app" / "src" / "androidTest" / "java" / "OtherTest.java"
            )
            contents = {
                target: "class RestService {\n RestService() {}\n}\n",
                unrelated_test: (
                    "class OtherTest {\n void testSomethingElse() {}\n}\n"
                ),
            }
            for path, content in contents.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            context = collect_multi_file_context(
                repo_root=root,
                source_file=target,
                method_name="<init>",
                class_name="example.RestService",
                method_body="RestService() {}",
                source_cache=contents,
                repository_paths=list(contents),
                repository_index_metadata={"truncated": False},
            )

            exact_paths = {
                item["source_file_path"] for item in context["exact_candidate_sources"]
            }
            self.assertIn(
                "app/src/androidTest/java/OtherTest.java", exact_paths
            )

    def test_a_symbol_used_across_the_repository_selects_no_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app" / "src" / "main" / "java" / "Crypto.java"
            target.parent.mkdir(parents=True)
            body = (
                "void deriveKey(char[] pw) { Arrays.fill(pw, (char) 0); "
                "new PBEKeySpec(pw, salt, 10000, 256); }"
            )
            contents = {target: "class Crypto { " + body + " }"}
            for index in range(12):
                path = target.parent / f"Unrelated{index}.java"
                contents[path] = (
                    f"class Unrelated{index} {{ void f() {{ Arrays.asList(1); }} }}"
                )
            for path, content in contents.items():
                path.write_text(content, encoding="utf-8")

            context = collect_multi_file_context(
                repo_root=root,
                source_file=target,
                method_name="deriveKey",
                class_name="example.Crypto",
                method_body=body,
                source_cache=contents,
                repository_paths=list(contents),
                repository_index_metadata={"truncated": False},
            )

            dropped = {
                item["symbol"] for item in
                context["limits"]["symbols_dropped_as_ubiquitous"]
            }
            self.assertIn("Arrays", dropped)
            self.assertNotIn("PBEKeySpec", dropped)
            selected = {
                item["source_file_path"]
                for item in context["exact_candidate_sources"]
            }
            self.assertNotIn(
                "app/src/main/java/Unrelated0.java", selected,
            )

    def test_the_test_root_anchor_does_not_claim_no_related_test_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app" / "src" / "main" / "java" / "Crypto.java"
            unrelated_test = (
                root / "app" / "src" / "test" / "java" / "OtherTest.java"
            )
            contents = {
                target: "class Crypto { void k() {} }",
                unrelated_test: "class OtherTest { void other() {} }",
            }
            for path, content in contents.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            context = collect_multi_file_context(
                repo_root=root,
                source_file=target,
                method_name="k",
                class_name="example.Crypto",
                method_body="void k() {}",
                source_cache=contents,
                repository_paths=list(contents),
                repository_index_metadata={"truncated": False},
            )

            item = next(
                item for item in context["exact_candidate_sources"]
                if item["source_file_path"].endswith("OtherTest.java")
            )
            reason = " ".join(item["relevance"])
            self.assertIn("anchor only", reason)
            self.assertNotIn("no existing test currently references", reason)

    def test_a_called_helper_is_resolved_to_its_definition(self):
        """The packet carried the reviewed method, its callers and its tests,
        but never the body of what it calls. Element Android's handleAppStarted
        reads its nested Intent through getParcelableExtraCompat, and the
        adjudication of CVE-2024-26131 blocked on not knowing whether that
        helper sanitises what it returns -- fifteen lines in the same repo."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app" / "src" / "main" / "java" / "Main.kt"
            helper = root / "library" / "src" / "main" / "java" / "Compat.kt"
            for path in (target, helper):
                path.parent.mkdir(parents=True, exist_ok=True)
            body = (
                "private fun handleAppStarted() { "
                "val next = intent.getParcelableExtraCompat<Intent>(EXTRA) }"
            )
            contents = {
                target: "class Main { " + body + " }",
                helper: (
                    "inline fun <reified T> Intent."
                    "getParcelableExtraCompat(key: String): T? = "
                    "getParcelableExtra(key) as? T?"
                ),
            }
            for path, content in contents.items():
                path.write_text(content, encoding="utf-8")

            context = collect_multi_file_context(
                repo_root=root,
                source_file=target,
                method_name="handleAppStarted",
                class_name="example.Main",
                method_body=body,
                source_cache=contents,
                repository_paths=list(contents),
                repository_index_metadata={"truncated": False},
            )

            resolved = {
                item["callee"]: item
                for item in context["callee_definitions"]
            }
            self.assertIn("getParcelableExtraCompat", resolved)
            self.assertEqual(
                resolved["getParcelableExtraCompat"]["source_file_path"],
                "library/src/main/java/Compat.kt",
            )
            self.assertIn(
                "getParcelableExtra(key)",
                resolved["getParcelableExtraCompat"]["definition"],
            )

    def test_a_kotlin_extension_declaration_is_not_read_as_a_call_site(self):
        line = (
            "inline fun <reified T> Intent."
            "getParcelableExtraCompat(key: String): T? = when {"
        )
        self.assertTrue(_declaration_like(line, "getParcelableExtraCompat"))
        self.assertFalse(_declaration_like(
            "    val next = intent.getParcelableExtraCompat<Intent>(EXTRA)",
            "getParcelableExtraCompat",
        ))

    def test_a_platform_call_resolves_to_no_repository_definition(self):
        """Only what this repository declares. A platform or library API is
        left to external research, which is the path that can answer for code
        this project does not contain."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Main.kt"
            target.parent.mkdir(parents=True)
            body = "fun run() { Thread.sleep(10) }"
            contents = {target: "class Main { " + body + " }"}
            target.write_text(contents[target], encoding="utf-8")

            context = collect_multi_file_context(
                repo_root=root, source_file=target, method_name="run",
                class_name="example.Main", method_body=body,
                source_cache=contents, repository_paths=list(contents),
                repository_index_metadata={"truncated": False},
            )

            self.assertEqual(context["callee_definitions"], [])

    def test_reports_incomplete_repository_index(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "Crypto.java"
            content = "class Crypto { String hash(String v) { return v; } }"
            target.write_text(content, encoding="utf-8")

            context = collect_multi_file_context(
                root, target, "hash", "Crypto", content,
                {target: content}, [target], {"truncated": True},
            )

            self.assertEqual(context["scope_completeness"]["status"], "incomplete")

    def test_scope_validator_requires_caller_review(self):
        error = {
            "expanded_repository_context": {
                "multi_file_impact": {
                    "status": "available",
                    "multi_file_candidate": True,
                    "scope_completeness": {"status": "complete"},
                    "coverage_requirements": {
                        "caller_files": ["Consumer.kt"],
                        "declaration_files": [],
                    },
                }
            }
        }
        analysis = {
            "decision": "FIX_SUPPORTED",
            "scope_assessment": {
                "status": "complete",
                "multi_file_change_required": False,
                "reviewed_files": [],
                "unresolved_relations": [],
            },
        }

        issues = validate_multi_file_scope(error, analysis)

        self.assertTrue(any("Consumer.kt" in issue for issue in issues))

    def test_review_only_decision_accepts_a_complete_multi_file_plan(self):
        error = {
            "expanded_repository_context": {"multi_file_impact": {
                "status": "available", "multi_file_candidate": True,
                "scope_completeness": {"status": "complete"},
                "coverage_requirements": {
                    "caller_files": ["Consumer.java"],
                    "declaration_files": ["Crypto.java"],
                    "ambiguous_call_files": [],
                    "flow_consumer_files": ["Consumer.java"],
                },
            }}
        }
        analysis = {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "scope_assessment": {
                "status": "complete", "multi_file_change_required": True,
                "reviewed_files": [
                    {"source_file_path": "Crypto.java", "action": "edit"},
                    {"source_file_path": "Consumer.java", "action": "edit"},
                ],
                "unresolved_relations": [],
            },
            "coordinated_fix_plan": {"required_edits": [
                {"source_file_path": "Crypto.java"},
                {"source_file_path": "Consumer.java"},
            ]},
        }

        self.assertEqual(
            validate_multi_file_scope(error, analysis), []
        )

    def test_review_only_allows_external_publication_blockers(self):
        error = {"expanded_repository_context": {"multi_file_impact": {
            "status": "available", "multi_file_candidate": True,
            "scope_completeness": {"status": "complete"},
            "coverage_requirements": {
                "caller_files": ["Consumer.java"],
                "declaration_files": ["Crypto.java"],
                "ambiguous_call_files": [], "flow_consumer_files": [],
            },
        }}}
        analysis = {
            "decision": "BACKEND_MIGRATION_REQUIRED_REVIEW_ONLY",
            "scope_assessment": {
                "status": "complete", "local_code_scope": "complete",
                "external_contract_scope": "unresolved",
                "multi_file_change_required": True,
                "reviewed_files": [
                    {"source_file_path": "Crypto.java", "action": "edit"},
                    {"source_file_path": "Consumer.java", "action": "edit"},
                ],
                "unresolved_relations": [{
                    "kind": "external_backend_contract",
                    "blocking_for_generation": False,
                    "blocking_for_publication": True,
                    "description": "backend rollout is not in this repository",
                }],
            },
            "coordinated_fix_plan": {"required_edits": [
                {"source_file_path": "Crypto.java"},
                {"source_file_path": "Consumer.java"},
            ]},
        }
        self.assertEqual(
            validate_multi_file_scope(error, analysis), []
        )

    def test_v2_review_plan_allows_explicit_incomplete_publication_scope(self):
        error = {
            "case_migration_policy": {
                "consumer_scope": "signature_preserving_internal_transport_change"
            },
            "expanded_repository_context": {"multi_file_impact": {
                "status": "available", "multi_file_candidate": True,
                "scope_completeness": {"status": "incomplete"},
                "coverage_requirements": {
                    "caller_files": ["src/Caller.kt"],
                    "declaration_files": ["src/OtherBuilder.kt"],
                    "ambiguous_call_files": ["src/OtherBuilder.kt"],
                    "flow_consumer_files": [], "behavioral_contract_files": [],
                },
            }},
        }
        analysis = {
            "architecture_version": "v2",
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "v2": {"adjudication": {
                "generation_status": "supported_for_review",
                "publication_status": "blocked",
                "blocking_for_generation": [],
            }},
            "scope_assessment": {
                "status": "incomplete", "local_code_scope": "incomplete",
                "multi_file_change_required": True,
                "reviewed_files": [
                    {"source_file_path": "src/Client.kt", "action": "edit"},
                    {"source_file_path": "src/test/ClientTest.kt", "action": "required_test"},
                    {"source_file_path": "src/OtherBuilder.kt", "action": "semantic_ambiguity_accounted"},
                ],
                "unresolved_relations": [{
                    "kind": "runtime_compatibility",
                    "blocking_for_generation": False,
                    "blocking_for_publication": True,
                    "description": "requires validation before publication",
                }],
            },
            "coordinated_fix_plan": {"required_edits": [
                {"source_file_path": "src/Client.kt"},
                {"source_file_path": "src/test/ClientTest.kt"},
            ]},
        }
        self.assertEqual(
            validate_multi_file_scope(error, analysis), []
        )

    def test_v2_post_validation_block_creates_deterministic_issue(self):
        with tempfile.TemporaryDirectory() as directory:
            generator = FixGenerator.__new__(FixGenerator)
            generator.architecture_version = "v2"
            generator.output_dir = Path(directory)
            generator.logger = logging.getLogger("test-v2-issue")
            evidence_file = Path(directory) / "review.json"
            evidence_file.write_text(
                json.dumps({"analysis": {}}), encoding="utf-8"
            )
            error = {
                "error_index": 0,
                "repository_url": "https://github.com/etesync/android",
                "source_file_path": "src/Client.kt",
                "spec": "SSLContextSpec", "tool": "ape",
                "error_message": "literal mismatch",
                "method_body": 'SSLContext.getInstance("TLS")',
            }
            analysis = {
                "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                "confirmed_cause": "The supplied TLS literal violates the detector predicate.",
                "predicate_assessment": [{
                    "status": "violated",
                    "evidence": 'SSLContext.getInstance("TLS")',
                }],
                "issue_candidate": {"eligible": False},
            }
            path = generator.persist_blocked_issue_candidate(
                error, analysis, evidence_file, "app.apk", "build",
                ["multi-file plan requires a concrete test edit"],
            )
            self.assertIsNotNone(path)
            issue = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                issue["issue_content"]["presentation_source"],
                "deterministic_post_validation_fallback",
            )
            review = json.loads(evidence_file.read_text(encoding="utf-8"))
            self.assertTrue(review["analysis"]["issue_candidate"]["eligible"])


class ClaimGroundedIssueCandidateTests(unittest.TestCase):
    """Regression test for two real dropped findings.

    The gate that decides whether a maintainer sees a blocked finding used
    to require a violated predicate whose prose occurred verbatim in the
    finding's own method body, with a fallback that recognised only
    MessageDigest, Cipher and SSLContext factory calls. Two confirmed
    findings had a complete, eligible presentation written and were dropped
    without a trace: zemzeme's ChannelManager.verifyChannelPassword, which
    returns an unconditional true, and opencloud's getKnownServersStore,
    whose KeyStore.load reads a hard-coded "password". Neither is a crypto
    factory call, so neither could ever pass however well evidenced.

    v2 grounds the cause in the claim graph instead, which
    sanitize_evidence_extraction has already checked against the packet.
    """

    def _generator(self, directory: str):
        generator = FixGenerator.__new__(FixGenerator)
        generator.architecture_version = "v2"
        generator.output_dir = Path(directory)
        generator.logger = logging.getLogger("test-claim-grounding")
        return generator

    def _analysis(self, cause_status: str, evidence_ids: list) -> dict:
        return {
            "decision": "NO_SAFE_FIX",
            "cause_status": cause_status,
            "confirmed_cause": (
                "verifyChannelPassword returns true without inspecting "
                "either parameter."
            ),
            "predicate_assessment": [{
                "status": "violated",
                "evidence": (
                    "Evidence IDs: SRC-001. The method body does not "
                    "inspect either parameter."
                ),
            }],
            "issue_candidate": {
                "eligible": True,
                "title": "verifyChannelPassword accepts every password",
                "finding_summary": "The verifier returns an unconditional true.",
                "why_no_pr": "The expected credential contract is not established.",
                "maintainer_question": "Which credential must the verifier compare?",
                "proposed_next_step": "Identify the authoritative contract.",
            },
            "v2": {
                "claims": [{
                    "claim_id": "CLM-001",
                    "epistemic_status": "confirmed",
                    "evidence_ids": evidence_ids,
                }],
                "adjudication": {"decision_claim_ids": ["CLM-001"]},
            },
        }

    def _persist(self, analysis: dict):
        with tempfile.TemporaryDirectory() as directory:
            evidence_file = Path(directory) / "review.json"
            evidence_file.write_text(
                json.dumps({"analysis": {}}), encoding="utf-8"
            )
            return self._generator(directory).persist_blocked_issue_candidate(
                {
                    "error_index": 5,
                    "repository_url": "https://github.com/whisperbit-labs/zemzeme-android",
                    "source_file_path": "app/src/main/java/ChannelManager.kt",
                    "spec": "ChannelPasswordSpec", "tool": "manual_static_review",
                    "error_message": "verifyChannelPassword returns true",
                    "method_body": "return true",
                },
                analysis, evidence_file, "app.apk", "verifyChannelPassword",
                ["the expected credential contract is not established"],
            )

    def test_non_crypto_finding_reaches_the_maintainer(self):
        self.assertIsNotNone(
            self._persist(self._analysis("confirmed", ["SRC-001", "WEB-001"]))
        )

    def test_cause_grounded_only_in_external_pages_is_withheld(self):
        self.assertIsNone(
            self._persist(self._analysis("confirmed", ["WEB-001"]))
        )

    def test_unconfirmed_cause_is_withheld_despite_prose(self):
        # v2 writes a confirmed_cause sentence even when it confirms nothing
        # ("No concrete CipherSpec violation ... is confirmed"), so a
        # non-empty string is not on its own a confirmed cause.
        self.assertIsNone(
            self._persist(self._analysis("unknown", ["SRC-001"]))
        )


class ReportableFindingTests(unittest.TestCase):
    """A confirmed cause is not a confirmed finding.

    Arcanum's verifyPin confirmed its cause -- the PIN lockout combines an
    elapsed-time and a wall-clock deadline with maxOf -- while the same
    adjudication recorded detector_violation "not_confirmed", because the
    monotonic term holds the lockout while it is positive and the reported
    clock-forward bypass therefore does not happen. An issue was prepared
    for the maintainer regardless, headed "I identified a potential issue"
    over a body explaining that the reported issue was not confirmed.

    The gate withholds only an explicit negative. "unknown" means nobody
    could tell, which is the shape of several real findings -- opencloud's
    KeyStore.load reading a hard-coded "password" among them -- and those
    still reach the maintainer.
    """

    def test_a_confirmed_violation_is_reportable(self):
        for value in ("confirmed", "source_established"):
            with self.subTest(detector_violation=value):
                self.assertTrue(FixGenerator.finding_is_reportable({
                    "detector_violation": value,
                    "runtime_security_impact": "not_established",
                }))

    def test_a_confirmed_runtime_impact_is_reportable_on_its_own(self):
        self.assertTrue(FixGenerator.finding_is_reportable({
            "detector_violation": "unknown",
            "runtime_security_impact": "confirmed",
        }))

    def test_a_refuted_finding_is_withheld(self):
        # verifyPin's exact adjudication values.
        self.assertFalse(FixGenerator.finding_is_reportable({
            "detector_violation": "not_confirmed",
            "runtime_security_impact": "not_established",
        }))

    def test_an_undetermined_violation_still_reaches_the_maintainer(self):
        # getKnownServersStore: the hard-coded "password" is confirmed, only
        # the detector's reported category was left unknown.
        self.assertTrue(FixGenerator.finding_is_reportable({
            "detector_violation": "unknown",
            "runtime_security_impact": "not_established",
        }))

    def test_confirmation_outranks_a_non_security_use(self):
        self.assertTrue(FixGenerator.finding_is_reportable({
            "detector_violation": "confirmed",
            "runtime_security_impact": "non_security",
        }))
        self.assertFalse(FixGenerator.finding_is_reportable({
            "detector_violation": "unknown",
            "runtime_security_impact": "non_security",
        }))

    def test_a_v1_analysis_without_the_fields_is_unaffected(self):
        # Only v2 emits them; the v1 baseline must behave as before.
        self.assertTrue(FixGenerator.finding_is_reportable({}))

    def test_the_fields_are_read_from_evidence_status_as_a_fallback(self):
        self.assertFalse(FixGenerator.finding_is_reportable({
            "evidence_status": {"detector_violation": "not_confirmed"},
        }))

    def test_a_refuted_finding_produces_no_issue_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            generator = FixGenerator.__new__(FixGenerator)
            generator.architecture_version = "v2"
            generator.output_dir = Path(directory)
            generator.logger = logging.getLogger("test-reportable")
            evidence_file = Path(directory) / "review.json"
            evidence_file.write_text(
                json.dumps({"analysis": {}}), encoding="utf-8"
            )
            analysis = {
                "decision": "NO_SAFE_FIX",
                "cause_status": "confirmed",
                "confirmed_cause": "the lockout combines two clocks with maxOf",
                "detector_violation": "not_confirmed",
                "runtime_security_impact": "not_established",
                "predicate_assessment": [],
                "issue_candidate": {
                    "eligible": True,
                    "title": "Clarify persisted PIN lockout timing semantics",
                    "finding_summary": "the reported bypass is not confirmed",
                    "why_no_pr": "changing the fallback may weaken the lockout",
                    "maintainer_question": "what behaviour is intended?",
                    "proposed_next_step": "define the reboot contract",
                },
                "v2": {
                    "claims": [{
                        "claim_id": "CLM-001",
                        "epistemic_status": "confirmed",
                        "evidence_ids": ["SRC-001"],
                    }],
                    "adjudication": {"decision_claim_ids": ["CLM-001"]},
                },
            }
            path = generator.persist_blocked_issue_candidate(
                {
                    "error_index": 3,
                    "repository_url": "https://github.com/Esdex/Arcanum",
                    "source_file_path": "PinManager.kt",
                    "spec": "PinLockoutSpec", "tool": "manual_dynamic_review",
                    "error_message": "clock-forward bypass",
                    "method_body": "maxOf(0L, remElapsed, remWall)",
                },
                analysis, evidence_file, "arcanum.apk", "verifyPin", [],
            )

            self.assertIsNone(path)
            # Everything else about it qualified, so the only thing that
            # withheld it is the refuted finding.
            analysis["detector_violation"] = "confirmed"
            self.assertIsNotNone(generator.persist_blocked_issue_candidate(
                {
                    "error_index": 3,
                    "repository_url": "https://github.com/Esdex/Arcanum",
                    "source_file_path": "PinManager.kt",
                    "spec": "PinLockoutSpec", "tool": "manual_dynamic_review",
                    "error_message": "clock-forward bypass",
                    "method_body": "maxOf(0L, remElapsed, remWall)",
                },
                analysis, evidence_file, "arcanum.apk", "verifyPin", [],
            ))


class RepositoryEvidencePrefixTests(unittest.TestCase):
    """Every prefix pipeline_architecture mints for repository evidence must
    be recognised as repository evidence by the issue gate.

    MANIFEST and CTOR were not. A cause resting only on the application's own
    AndroidManifest declaration -- an exported component without a permission,
    which is the entire finding for FtpReceiver -- would have been judged
    ungrounded and its issue withheld for want of evidence it had.
    """

    def test_manifest_and_constructor_evidence_ground_a_cause(self):
        from cognalys.llm.generate_error_fixes import (  # noqa: PLC0415
            REPOSITORY_EVIDENCE_PREFIXES,
            claim_grounded_cause,
        )
        self.assertIn("MANIFEST", REPOSITORY_EVIDENCE_PREFIXES)
        self.assertIn("CTOR", REPOSITORY_EVIDENCE_PREFIXES)
        analysis = {
            "v2": {
                "claims": [{
                    "claim_id": "CLM-005",
                    "epistemic_status": "confirmed",
                    "evidence_ids": ["MANIFEST-001"],
                }],
                "adjudication": {"decision_claim_ids": ["CLM-005"]},
            },
        }
        self.assertTrue(claim_grounded_cause(analysis))

    def test_an_external_source_alone_does_not_ground_a_cause(self):
        from cognalys.llm.generate_error_fixes import claim_grounded_cause  # noqa: PLC0415
        analysis = {
            "v2": {
                "claims": [{
                    "claim_id": "CLM-007",
                    "epistemic_status": "confirmed",
                    "evidence_ids": ["WEB-004"],
                }],
                "adjudication": {"decision_claim_ids": ["CLM-007"]},
            },
        }
        self.assertFalse(claim_grounded_cause(analysis))


if __name__ == "__main__":
    unittest.main()
