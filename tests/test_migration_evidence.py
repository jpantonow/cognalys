import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.migration_context import (  # noqa: E402
    _promote_flow_sources,
    collect_migration_context,
)


class MethodTypeDeclarationTests(unittest.TestCase):
    """The declaration of a receiver's type reaches the exact sources.

    ru.valle.btc's Transaction constructor closes a BitcoinInputStream, which
    extends ByteArrayInputStream without overriding close(). The packet held
    Transaction.java and its test only, and the adjudication abstained for
    want of the receiver's type (run_20260915_175048).
    """

    PACKAGE = "app/src/main/java/ru/valle/btc"
    CONSTRUCTOR = (
        "    public Transaction(byte[] rawBytes, boolean withWitness) {\n"
        "        BitcoinInputStream bais = null;\n"
        "        try {\n"
        "            bais = new BitcoinInputStream(rawBytes);\n"
        "        } finally {\n"
        "            bais.close();\n"
        "        }\n"
        "    }\n"
    )

    def _repository(self, root):
        package = root / self.PACKAGE
        package.mkdir(parents=True)
        target = package / "Transaction.java"
        target.write_text(
            "package ru.valle.btc;\npublic class Transaction {\n"
            + self.CONSTRUCTOR + "}\n",
            encoding="utf-8",
        )
        (package / "BitcoinInputStream.java").write_text(
            "package ru.valle.btc;\n"
            "public class BitcoinInputStream extends java.io.ByteArrayInputStream {\n"
            "    public BitcoinInputStream(byte[] buf) { super(buf); }\n}\n",
            encoding="utf-8",
        )
        return target

    def test_the_declaration_of_a_receiver_type_is_collected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = self._repository(root)
            context = collect_migration_context(
                root, target, "<init>", "ru.valle.btc.Transaction",
                self.CONSTRUCTOR, multi_file_exact_chars=20_000,
            )
            self.assertIn(
                {"path": f"{self.PACKAGE}/BitcoinInputStream.java",
                 "type": "BitcoinInputStream"},
                context["method_type_declarations"],
            )

    def test_the_declaration_is_promoted_into_the_exact_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = self._repository(root)
            declaration = f"{self.PACKAGE}/BitcoinInputStream.java"
            context = {
                "multi_file_impact": {
                    "status": "available", "coverage_requirements": {},
                },
                "method_type_declarations": [
                    {"path": declaration, "type": "BitcoinInputStream"},
                ],
            }
            _promote_flow_sources(root, target, {}, context, 50_000)
            sources = {
                item["source_file_path"]: item
                for item in context["multi_file_impact"]["exact_candidate_sources"]
            }
            self.assertIn("extends java.io.ByteArrayInputStream",
                          sources[declaration]["content"])
            self.assertTrue(any(
                "BitcoinInputStream" in reason
                for reason in sources[declaration]["relevance"]
            ))


class MigrationEvidenceTests(unittest.TestCase):
    def test_returned_digest_wrapper_is_promoted_into_value_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "MiscUtils.java"
            caller = root / "NoteViewModel.kt"
            target.write_text(
                'class MiscUtils { static long sha1(String value) { '
                'return MessageDigest.getInstance("SHA-1").digest('
                'value.getBytes())[0]; } }', encoding="utf-8",
            )
            caller.write_text(
                "class NoteViewModel { private var originalHash: Long = 0L\n"
                "private fun notePayloadHash(value: String): Long {\n"
                " return MiscUtils.sha1(value)\n}\n"
                "fun load(value: String) { originalHash = notePayloadHash(value) }\n"
                "fun changed(value: String) = notePayloadHash(value) != originalHash\n}",
                encoding="utf-8",
            )

            context = collect_migration_context(
                root, target, "sha1", "example.MiscUtils",
                target.read_text(encoding="utf-8"),
                multi_file_exact_chars=20_000,
            )

            self.assertIn("notePayloadHash", context["target_flow_symbols"])
            transitive = context["transitive_consumer_evidence"]
            self.assertTrue(any(
                item["path"] == "NoteViewModel.kt"
                and "notePayloadHash" in item["matched_symbols"]
                for item in transitive
            ))
            assessment = context["ephemeral_runtime_discriminator_assessment"]
            self.assertTrue(assessment["supported"], assessment)
            self.assertEqual(
                context["usage_classification"]["primary"],
                "ephemeral_runtime_discriminator",
            )
            self.assertTrue(context["automatic_migration_candidate"])
    def test_runtime_discriminator_promotes_variants_constants_duplicates_and_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            main = root / "app/src/main/kotlin/example/Selector.kt"
            duplicate = root / "app/src/main/kotlin/example/GraphSelector.kt"
            constants = root / "app/src/main/kotlin/example/Constants.kt"
            test = root / "app/src/test/kotlin/example/SelectorTest.kt"
            gradle = root / "app/build.gradle.kts"
            for path in (main, duplicate, constants, test, gradle):
                path.parent.mkdir(parents=True, exist_ok=True)
            body = (
                'fun calculateType(): Int { val digest = MessageDigest.getInstance("MD5")'
                '.digest(context.packageName.toByteArray()).contentHashCode(); '
                'return when (digest) { TYPE1, TYPE2 -> SIZE_MAX; TYPE3 -> SIZE_MIN; '
                'else -> SIZE_MIN } }'
            )
            main.write_text("class Selector { " + body + " }", encoding="utf-8")
            duplicate.write_text(
                'class GraphSelector { fun graphType(): Int { val digest = '
                'MessageDigest.getInstance("MD5").digest(context.packageName.'
                'toByteArray()).contentHashCode(); return if (digest == TYPE1) '
                'SIZE_MAX else SIZE_MIN } }', encoding="utf-8",
            )
            constants.write_text(
                "const val TYPE1 = 1147798476\nconst val TYPE2 = 535509942\n"
                "const val TYPE3 = 1256180258\nconst val TYPE4 = 1546740952\n"
                "const val SIZE_MAX = 50\nconst val SIZE_MIN = 10\n",
                encoding="utf-8",
            )
            test.write_text(
                "class SelectorTest { fun calculateTypeTest() { "
                "\nassert(select(TYPE1) == SIZE_MAX)\n"
                "assert(select(TYPE2) == SIZE_MAX)\n"
                "assert(select(TYPE4) == SIZE_MIN)\n} }",
                encoding="utf-8",
            )
            gradle.write_text(
                'android { defaultConfig { applicationId = "com.vrem.wifianalyzer" } '
                'buildTypes { debug { applicationIdSuffix = ".BETA" } } }',
                encoding="utf-8",
            )

            context = collect_migration_context(
                root, main, "calculateType", "example.Selector", body,
                multi_file_exact_chars=100_000,
            )

            assessment = context["runtime_discriminator_assessment"]
            self.assertTrue(assessment["supported"])
            self.assertEqual(
                context["usage_classification"]["primary"],
                "runtime_discriminator",
            )
            self.assertEqual(
                context["android_build_variants"]["known_application_ids"],
                ["com.vrem.wifianalyzer", "com.vrem.wifianalyzer.BETA"],
            )
            required = set(
                context["multi_file_impact"]["required_behavioral_sources"]
            )
            self.assertIn("app/src/main/kotlin/example/GraphSelector.kt", required)
            self.assertIn("app/src/main/kotlin/example/Constants.kt", required)
            self.assertIn("app/src/test/kotlin/example/SelectorTest.kt", required)
            self.assertIn("app/build.gradle.kts", required)
            mappings = {
                item["input"]: item["matching_constants"]
                for item in assessment["evaluated_input_mappings"]
            }
            self.assertEqual(mappings["com.vrem.wifianalyzer"], ["TYPE1"])
            self.assertEqual(
                mappings["com.vrem.wifianalyzer.BETA"], ["TYPE3"]
            )
            self.assertEqual(
                assessment["mapping_coverage"]["current_variants"],
                "complete",
            )
            roles = {item["symbol"]: item for item in assessment["constant_roles"]}
            self.assertTrue(roles["TYPE2"]["used_as_accepted_branch"])
            self.assertFalse(roles["TYPE2"]["covered_as_fallback_or_negative"])
            self.assertTrue(roles["TYPE4"]["covered_as_fallback_or_negative"])

    def test_gradle_variant_parser_ignores_dynamic_variables_and_never_crosses_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Selector.kt"
            gradle = root / "app/build.gradle.kts"
            source.write_text(
                'fun select() = MessageDigest.getInstance("MD5").digest('
                'context.packageName.toByteArray()).contentHashCode() + TYPE1',
                encoding="utf-8",
            )
            gradle.parent.mkdir(parents=True)
            gradle.write_text(
                'defaultConfig { applicationId = "org.example" }\n'
                'debug { applicationIdSuffix = ".debug" }\n'
                'var applicationId = android.defaultConfig.applicationId!!\n'
                'println("$applicationId")\n'
                'android.defaultConfig.versionName = "1.0"\n',
                encoding="utf-8",
            )
            context = collect_migration_context(
                root, source, "select", "Selector", source.read_text(),
            )
            self.assertEqual(
                context["android_build_variants"]["known_application_ids"],
                ["org.example", "org.example.debug"],
            )

    def test_member_assignment_does_not_expand_generic_property_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Selector.kt"
            unrelated = root / "Unrelated.kt"
            source.write_text(
                "class Selector { fun calculate(): Int = 1; fun update() { "
                "configuration.size = calculate() } }", encoding="utf-8",
            )
            unrelated.write_text(
                "class Unrelated { val size = 20 }", encoding="utf-8",
            )
            context = collect_migration_context(
                root, source, "calculate", "Selector",
                "fun calculate(): Int = 1",
            )
            self.assertNotIn("size", context["target_flow_symbols"])
            self.assertNotIn(
                "Unrelated.kt",
                context["multi_file_impact"].get("required_flow_sources", []),
            )

    def test_direct_call_symbols_promote_transitive_digest_consumers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "Digest.java"
            caller = root / "Producer.java"
            sink = root / "Sender.java"
            target.write_text(
                "class Digest { static String hash(String value) { return value; } }",
                encoding="utf-8",
            )
            caller.write_text(
                "class Producer { String make(String value) { "
                "String identifier = Digest.hash(value); return identifier; } }",
                encoding="utf-8",
            )
            sink.write_text(
                "class Sender { void send(Producer p) { String identifier = "
                "p.make(\"x\"); upload(identifier); } void upload(String x) {} }",
                encoding="utf-8",
            )
            context = collect_migration_context(
                root, target, "hash", "Digest",
                "static String hash(String value) { return value; }",
                multi_file_exact_chars=20_000,
            )
            self.assertIn("identifier", context["target_flow_symbols"])
            required = context["multi_file_impact"]["required_flow_sources"]
            self.assertIn("Sender.java", required)

    def test_policy_consumers_are_resolved_and_prioritized_in_exact_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package_dir = root / "src" / "org" / "example"
            package_dir.mkdir(parents=True)
            target = package_dir / "Crypto.java"
            wrapper = package_dir / "SecretWrapper.java"
            target.write_text(
                "package org.example; class Crypto { Object getCipher() { "
                "return null; } SecretWrapper value; }", encoding="utf-8",
            )
            wrapper.write_text(
                "package org.example; class SecretWrapper { byte[] sealedValue; }",
                encoding="utf-8",
            )

            context = collect_migration_context(
                root, target, "getCipher", "org.example.Crypto",
                "Object getCipher() { return null; }",
                multi_file_exact_chars=10_000,
                case_migration_policy={"required_consumers": [
                    "org.example.SecretWrapper",
                    "org.example.SecretWrapper.sealedValue",
                ]},
            )

            self.assertEqual(context["unresolved_policy_consumers"], [])
            self.assertEqual(
                context["required_policy_sources"],
                ["src/org/example/SecretWrapper.java"],
            )
            impact = context["multi_file_impact"]
            self.assertIn(
                "src/org/example/SecretWrapper.java",
                impact["required_flow_sources"],
            )
            exact = [item["source_file_path"]
                     for item in impact["exact_candidate_sources"]]
            self.assertLess(
                exact.index("src/org/example/SecretWrapper.java"),
                len(exact),
            )

    def test_missing_policy_member_marks_scope_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "Crypto.java"
            target.write_text(
                "package org.example; class Crypto { Object getCipher() { "
                "return null; } }", encoding="utf-8",
            )
            context = collect_migration_context(
                root, target, "getCipher", "org.example.Crypto",
                "Object getCipher() { return null; }",
                case_migration_policy={"required_consumers": [
                    "org.example.Crypto.missingField",
                ]},
            )
            self.assertEqual(
                context["unresolved_policy_consumers"][0]["reason"],
                "member_not_found",
            )
            self.assertEqual(
                context["multi_file_impact"]["scope_completeness"]["status"],
                "incomplete",
            )

    def test_a_kotlin_extension_declares_its_own_name_not_a_returned_call(self):
        """NotallyX (2026-10-28): `return inputStream(` read as a declaration
        named inputStream, which then matched app/build.gradle.kts."""
        from cognalys.extraction.migration_context import _flow_symbols

        lines = ["fun File.md5Hash(): ByteArray {", " return inputStream().md5Hash() }"]
        symbols = _flow_symbols(lines, 1)
        self.assertIn("md5Hash", symbols)
        self.assertNotIn("inputStream", symbols)
        self.assertNotIn("return", symbols)

    def test_a_typed_val_names_the_variable_not_its_type(self):
        from cognalys.extraction.migration_context import _flow_symbols

        symbols = _flow_symbols(["val digest: ByteArray = target()"], 0)
        self.assertIn("digest", symbols)
        self.assertNotIn("ByteArray", symbols)
        thrown = _flow_symbols(["fun check() {", " throw ZipVerificationException(sourceMd5)"], 1)
        self.assertNotIn("ZipVerificationException", thrown)

    def _flow_context(self, root, consumers):
        target = root / "Target.kt"
        target.write_text("target", encoding="utf-8")
        files = {target: "target"}
        for name, size in [("Caller.kt", 30), *consumers]:
            path = root / name
            path.write_text("c" * size, encoding="utf-8")
            files[path] = "c" * size
        return target, files, {
            "target_flow_symbols": ["inputStream", "digest"],
            "repository_call_sites": [{"path": "Caller.kt"}],
            "transitive_consumer_evidence": [
                {"path": name, "depth": 1, "matched_symbols": ["inputStream"]}
                for name, _ in consumers
            ],
            "tests": [],
            "multi_file_impact": {
                "status": "available",
                "target": {"method": "md5Hash"},
                "exact_candidate_sources": [],
                "scope_completeness": {"status": "complete", "reasons": []},
                "coverage_requirements": {},
            },
        }

    def test_a_direct_caller_survives_a_small_budget_and_generic_importers_are_cut(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, files, context = self._flow_context(
                root, [("EvernoteImporter.kt", 40), ("JsonImporter.kt", 40)])
            _promote_flow_sources(root, target, files, context, max_exact_chars=50)
            impact = context["multi_file_impact"]
            exact = [item["source_file_path"] for item in impact["exact_candidate_sources"]]
            self.assertIn("Caller.kt", exact)
            self.assertIn("Caller.kt", impact["required_caller_sources"])
            self.assertIn("Caller.kt", impact["coverage_requirements"]["caller_files"])
            # Ordered: target, then the caller, then transitive consumers.
            self.assertEqual(impact["required_flow_sources"][:2], ["Target.kt", "Caller.kt"])
            self.assertIn("JsonImporter.kt", impact["omitted_promoted_sources"])

    def test_a_gradle_script_is_never_a_required_flow_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            target, files, context = self._flow_context(
                root, [("app/build.gradle.kts", 10), ("build.gradle", 10), ("Reader.kt", 10)])
            _promote_flow_sources(root, target, files, context, max_exact_chars=10_000)
            required = context["multi_file_impact"]["required_flow_sources"]
            self.assertIn("Reader.kt", required)
            self.assertFalse([path for path in required if "gradle" in path], required)

    def test_supplementary_context_does_not_become_required_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "Target.java"
            consumer = root / "Consumer.java"
            unrelated = root / "Unrelated.java"
            target.write_text("target", encoding="utf-8")
            consumer.write_text("consumer", encoding="utf-8")
            unrelated.write_text("x" * 100, encoding="utf-8")
            context = {
                "target_flow_symbols": ["bridge"],
                "repository_call_sites": [{"path": "Unrelated.java"}],
                "transitive_consumer_evidence": [{
                    "path": "Consumer.java", "depth": 1,
                    "matched_symbols": ["bridge"],
                }],
                "representation_lifetime_assessment": {
                    "reviewed_flow_files": ["Unrelated.java"],
                },
                "tests": [],
                "multi_file_impact": {
                    "status": "available",
                    "exact_candidate_sources": [],
                    "scope_completeness": {"status": "complete", "reasons": []},
                    "coverage_requirements": {},
                },
            }

            _promote_flow_sources(
                root, target,
                {target: "target", consumer: "consumer", unrelated: "x" * 100},
                context, max_exact_chars=20,
            )

            impact = context["multi_file_impact"]
            self.assertEqual(
                impact["coverage_requirements"]["flow_consumer_files"],
                ["Consumer.java"],
            )
            self.assertIn("Unrelated.java", impact["omitted_promoted_sources"])
            self.assertEqual(impact["omitted_required_flow_sources"], [])
            self.assertEqual(impact["scope_completeness"]["status"], "complete")

    def test_test_source_root_anchor_survives_budget_exhausted_by_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app/src/main/java/example/Big.java"
            unrelated_test = (
                root / "app/src/androidTest/java/example/OtherTest.java"
            )
            for path in (target, unrelated_test):
                path.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("x" * 5_000, encoding="utf-8")
            unrelated_test.write_text(
                "class OtherTest { void testSomethingElse() {} }",
                encoding="utf-8",
            )
            context = {
                "target_flow_symbols": [],
                "repository_call_sites": [],
                "transitive_consumer_evidence": [],
                "representation_lifetime_assessment": {},
                "tests": [],
                "multi_file_impact": {
                    "status": "available",
                    "exact_candidate_sources": [],
                    "scope_completeness": {"status": "complete", "reasons": []},
                    "coverage_requirements": {},
                },
            }

            # A budget that fits only the target file leaves no room for the
            # androidTest file under ordinary priority-order competition.
            _promote_flow_sources(
                root, target,
                {
                    target: "x" * 5_000,
                    unrelated_test: unrelated_test.read_text(encoding="utf-8"),
                },
                context, max_exact_chars=5_000,
            )

            impact = context["multi_file_impact"]
            exact_paths = {
                item["source_file_path"]
                for item in impact["exact_candidate_sources"]
            }
            self.assertIn(
                "app/src/androidTest/java/example/OtherTest.java", exact_paths
            )

    def test_generic_method_class_only_test_is_not_promoted_as_edit_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app/src/main/kotlin/example/HttpClient.kt"
            unrelated_test = root / "app/src/androidTest/java/example/DavFinderTest.java"
            target.parent.mkdir(parents=True)
            unrelated_test.parent.mkdir(parents=True)
            target.write_text(
                'class HttpClient { class Builder { fun build() { '
                'SSLContext.getInstance("TLS") } } }',
                encoding="utf-8",
            )
            unrelated_test.write_text(
                "class DavFinderTest { void setup() { "
                "HttpClient.create(null); } }",
                encoding="utf-8",
            )

            context = collect_migration_context(
                root, target, "build", "example.HttpClient$Builder",
                'fun build() { SSLContext.getInstance("TLS") }',
                multi_file_exact_chars=50_000,
            )

            test_record = next(
                item for item in context["tests"]
                if item["path"].endswith("DavFinderTest.java")
            )
            self.assertEqual(test_record["relevance"], "target class only")
            self.assertFalse(test_record["edit_target_recommended"])
            exact = {
                item["source_file_path"]
                for item in context["multi_file_impact"]["exact_candidate_sources"]
            }
            self.assertNotIn(
                "app/src/androidTest/java/example/DavFinderTest.java", exact,
            )

    def test_detects_ephemeral_sensitive_representation_and_min_sdk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app" / "src" / "PwsFile.java"
            consumer = root / "app" / "src" / "PasswordField.java"
            gradle = root / "app" / "build.gradle"
            source.parent.mkdir(parents=True)
            source.write_text(
                "class PwsFile { byte[] memoryIv; Object getCipher(boolean write) "
                "{ return memoryIv; } }",
                encoding="utf-8",
            )
            consumer.write_text(
                "class PasswordField { Object value(PwsFile f) { return "
                "f.getCipher(true); /* SealedObject in-memory password */ } }",
                encoding="utf-8",
            )
            gradle.write_text(
                "android { defaultConfig { minSdkVersion 21 } }",
                encoding="utf-8",
            )

            context = collect_migration_context(
                root, source, "getCipher", "example.PwsFile",
                "Object getCipher(boolean write) { return memoryIv; }",
            )

            lifetime = context["representation_lifetime_assessment"]
            self.assertTrue(lifetime["supported"])
            self.assertEqual(lifetime["classification"], "ephemeral_sensitive")
            self.assertFalse(lifetime["legacy_compatibility_required"])
            self.assertEqual(
                context["usage_classification"]["primary"],
                "ephemeral_sensitive",
            )
            self.assertEqual(context["platform_context"]["android_min_sdk"], 21)
            self.assertTrue(context["automatic_migration_candidate"])
            exact_paths = {
                item["source_file_path"]
                for item in context["multi_file_impact"]["exact_candidate_sources"]
            }
            self.assertIn("app/src/PwsFile.java", exact_paths)
            self.assertIn("app/src/PasswordField.java", exact_paths)

    def test_concrete_file_serialization_sink_blocks_ephemeral_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "PwsFile.java"
            source.write_text(
                "class PwsFile { Object memoryKey; Object getCipher() { "
                "return memoryKey; } void save() { new ObjectOutputStream("
                "new FileOutputStream(\"state\")); } }",
                encoding="utf-8",
            )

            context = collect_migration_context(
                root, source, "getCipher", "PwsFile",
                "Object getCipher() { return memoryKey; }",
            )

            lifetime = context["representation_lifetime_assessment"]
            self.assertFalse(lifetime["supported"])
            self.assertTrue(lifetime["real_persistence_sinks"])

    def test_private_target_promotes_the_class_only_test_as_an_edit_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app/src/main/java/crypt/Crypto.java"
            test = root / "app/src/test/java/crypt/CryptoTest.java"
            source.parent.mkdir(parents=True)
            test.parent.mkdir(parents=True)
            source.write_text(
                "package crypt; class Crypto { private Object deriveKey("
                "char[] pw) { return new PBEKeySpec(pw, salt, 10000, 256); } }",
                encoding="utf-8",
            )
            test.write_text(
                "package crypt; class CryptoTest { void roundtrip() { "
                "new Crypto().encrypt(\"x\"); } }",
                encoding="utf-8",
            )

            context = collect_migration_context(
                root, source, "deriveKey", "crypt.Crypto",
                "    private Object deriveKey(char[] pw) { return new "
                "PBEKeySpec(pw, salt, 10000, 256); }",
            )

            record = next(
                item for item in context["tests"]
                if item["path"].endswith("CryptoTest.java")
            )
            self.assertEqual(record["relevance_score"], 60)
            self.assertTrue(record["edit_target_recommended"])
            self.assertIn("target method is private", record["relevance"])
            exact = {
                item["source_file_path"]
                for item in context["multi_file_impact"]["exact_candidate_sources"]
            }
            self.assertIn("app/src/test/java/crypt/CryptoTest.java", exact)

    def test_a_class_only_signal_shared_by_many_tests_promotes_none(self):
        """Promoting "target class only" was right for markor, which had one
        test of the reported class. Element Android's target is a private
        method of MainActivity, a name seven androidTest files mention merely
        because they launch the app; all seven became edit targets and spent
        49k of the packet's 140k character budget."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app/src/main/java/app/MainActivity.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package app; class MainActivity { private Object start() "
                "{ return 1; } }",
                encoding="utf-8",
            )
            for index in range(3):
                test = root / f"app/src/androidTest/java/app/Ui{index}Test.java"
                test.parent.mkdir(parents=True, exist_ok=True)
                test.write_text(
                    f"class Ui{index}Test {{ void t() {{ launch(MainActivity"
                    ".class); }} }}",
                    encoding="utf-8",
                )

            context = collect_migration_context(
                root, source, "start", "app.MainActivity",
                "    private Object start() { return 1; }",
            )

            promoted = [
                item for item in context["tests"]
                if item["edit_target_recommended"]
            ]
            self.assertEqual(promoted, [])
            self.assertTrue(context["tests"])
            for item in context["tests"]:
                self.assertIn("singles out none", item["relevance"])

    def test_a_sole_class_only_test_of_a_private_target_is_still_promoted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app/src/main/java/crypt/Crypto.java"
            test = root / "app/src/test/java/crypt/CryptoTest.java"
            source.parent.mkdir(parents=True)
            test.parent.mkdir(parents=True)
            source.write_text(
                "package crypt; class Crypto { private Object deriveKey() "
                "{ return 1; } }",
                encoding="utf-8",
            )
            test.write_text(
                "class CryptoTest { void roundtrip() { new Crypto(); } }",
                encoding="utf-8",
            )

            context = collect_migration_context(
                root, source, "deriveKey", "crypt.Crypto",
                "    private Object deriveKey() { return 1; }",
            )

            record = next(
                item for item in context["tests"]
                if item["path"].endswith("CryptoTest.java")
            )
            self.assertTrue(record["edit_target_recommended"])
            self.assertEqual(record["relevance_score"], 60)

    def test_construction_sites_of_the_reported_class_are_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app/src/Crypto.java"
            caller = root / "app/src/Document.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "class Crypto { Crypto(Random r) { this.r = r; } "
                "Object deriveKey() { return r; } }",
                encoding="utf-8",
            )
            caller.write_text(
                "class Document { void save() { new Crypto(new SecureRandom())"
                ".encrypt(text); } }",
                encoding="utf-8",
            )

            context = collect_migration_context(
                root, source, "deriveKey", "Crypto",
                "Object deriveKey() { return r; }",
            )

            sites = context["class_construction_sites"]
            self.assertTrue(any(
                item["path"] == "app/src/Document.java"
                and "new SecureRandom()" in item["snippet"]
                for item in sites
            ))
            reasons = {
                item["source_file_path"]: item["relevance"]
                for item in context["multi_file_impact"]["exact_candidate_sources"]
            }
            self.assertIn(
                "constructs the reported class, deciding the state it reads",
                reasons.get("app/src/Document.java", []),
            )

    def test_promoted_sources_keep_the_reason_they_were_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app/src/Crypto.java"
            source.parent.mkdir(parents=True)
            source.write_text("class Crypto { Object k() { return 1; } }",
                              encoding="utf-8")

            context = collect_migration_context(
                root, source, "k", "Crypto", "Object k() { return 1; }",
            )

            target = next(
                item for item in
                context["multi_file_impact"]["exact_candidate_sources"]
                if item["source_file_path"] == "app/src/Crypto.java"
            )
            self.assertIn("reported finding location", target["relevance"])
            self.assertNotEqual(
                target["relevance"],
                ["target or transitive protected-value flow"],
            )


if __name__ == "__main__":
    unittest.main()
