import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.semantic_index import _parse_batch_isolated, build_semantic_index  # noqa: E402


class SemanticIndexTests(unittest.TestCase):
    def test_failed_batch_recovers_healthy_files_by_bisection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            healthy = root / "Healthy.kt"
            broken = root / "Broken.kt"

            def parse_once(items, _root, _timeout):
                if len(items) > 1 or items[0][0] == broken:
                    return None, "isolated tree-sitter parser failed with signal 11"
                return [{
                    "path": "Healthy.kt", "has_error": False,
                    "classes": [], "declarations": [], "calls": [],
                }], ""

            with patch("cognalys.extraction.semantic_index._parse_batch_once", side_effect=parse_once):
                parsed, warning = _parse_batch_isolated(
                    [(healthy, "fun ok() = 1"), (broken, "broken")], root
                )
            self.assertEqual([item["path"] for item in parsed], ["Healthy.kt"])
            self.assertIn("skipped 1 file", warning)

    def test_native_parser_failure_uses_qualified_lexical_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "Target.java"
            caller = root / "Use.kt"
            unrelated = root / "Other.kt"
            sources = {
                target: "class Target { static String hash(String x) { return x; } }",
                caller: 'fun use() = Target.hash("x")',
                unrelated: 'fun useOther(value: Other) = value.hash("x")',
            }
            with patch(
                "cognalys.extraction.semantic_index._parse_batch_isolated",
                return_value=(None, "isolated tree-sitter parser failed with signal 11"),
            ):
                result = build_semantic_index(root, sources, target, "hash", 1)
            self.assertEqual(result["status"], "available")
            self.assertEqual(
                result["backend"],
                "lexically_qualified_repository_fallback",
            )
            self.assertIn("signal 11", result["parser_fallback_reason"])
            self.assertEqual(
                {item["path"] for item in result["resolved_callers"]},
                {"Use.kt"},
            )
            self.assertEqual(
                {item["path"] for item in result["ambiguous_calls"]},
                {"Other.kt"},
            )

    def test_resolves_unique_java_method_by_ast_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "Crypto.java"
            caller = root / "Use.java"
            sources = {
                target: (
                    "package p; class Crypto { "
                    "String hash(String value) { return value; } }"
                ),
                caller: (
                    "package p; class Use { String run(Crypto c) { "
                    "return c.hash(\"x\"); } }"
                ),
            }
            result = build_semantic_index(
                root, sources, target, "hash"
            )

            self.assertEqual(result["status"], "available")
            self.assertEqual(result["target_symbol"]["arity"], 1)
            self.assertEqual(len(result["resolved_callers"]), 1)
            self.assertEqual(result["resolved_callers"][0]["path"], "Use.java")

    def test_keeps_overloaded_dispatch_ambiguous_without_type_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "A.kt"
            other = root / "B.kt"
            caller = root / "Use.kt"
            sources = {
                target: "class A { fun hash(v: String): String = v }",
                other: "class B { fun hash(v: String): String = v }",
                caller: "fun use(value: Any) = value.hash(\"x\")",
            }
            result = build_semantic_index(root, sources, target, "hash")

            self.assertEqual(result["status"], "available")
            self.assertTrue(result["related_declarations"])
            self.assertTrue(result["ambiguous_calls"])

    def test_generic_build_requires_qualified_target_receiver(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "HttpClient.kt"
            real = root / "Real.kt"
            unrelated = root / "Other.kt"
            sources = {
                target: "class HttpClient { class Builder { fun build() = HttpClient() } }",
                real: "fun real() = HttpClient.Builder().build()",
                unrelated: "fun other(uri: Uri.Builder) = uri.build()",
            }
            result = build_semantic_index(root, sources, target, "build")
            resolved = {item["path"] for item in result["resolved_callers"]}
            ambiguous = {item["path"] for item in result["ambiguous_calls"]}
            self.assertEqual(resolved, {"Real.kt"})
            self.assertIn("Other.kt", ambiguous)


if __name__ == "__main__":
    unittest.main()


class DroppedTargetFileTests(unittest.TestCase):
    """A partial recovery that loses the target must still resolve callers.

    _parse_batch_isolated bisects a batch whose isolated parser crashed and
    returns everything it could still parse, so `files` comes back healthy
    while the one file the finding is about is gone. The lexical fallback was
    reachable only when the WHOLE batch failed, so this case fell through to
    "unresolved" with no callers at all -- and scope_completeness then reported
    resolved_callers "unknown", which is what 20 of 54 stored evidence packets
    recorded. Reproduces me.blog.korn123.easydiary's ZipHelper.kt, which
    segfaults tree-sitter-kotlin 1.1.0 under tree-sitter 0.26.0 while every
    other file in its repository parses.
    """

    def _repository(self):
        return {
            "target": "Target.java",
            "sources": lambda root: {
                root / "Target.java":
                    "class Target { static String hash(String x) { return x; } }",
                root / "Use.kt": 'fun use() = Target.hash("x")',
            },
        }

    def test_a_dropped_target_falls_back_instead_of_reporting_unresolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "Target.java"
            sources = self._repository()["sources"](root)
            # The bisection saved Use.kt and dropped the crashing target.
            recovered = ([{
                "path": "Use.kt", "has_error": False,
                "classes": [], "declarations": [], "calls": [],
            }], "recovered partial semantic corpus; skipped 1 file(s): "
                "isolated tree-sitter parser failed with signal 11")
            with patch("cognalys.extraction.semantic_index._parse_batch_isolated",
                       return_value=recovered):
                result = build_semantic_index(root, sources, target, "hash", 1)
            self.assertEqual(result["status"], "available")
            self.assertEqual(
                result["backend"], "lexically_qualified_repository_fallback"
            )
            self.assertIn("signal 11", result["parser_fallback_reason"])
            self.assertEqual(
                {item["path"] for item in result["resolved_callers"]}, {"Use.kt"}
            )

    def test_a_parsed_target_missing_the_method_still_reports_unresolved(self):
        """A real name/arity mismatch must not be masked by a lexical guess."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "Target.java"
            sources = self._repository()["sources"](root)
            parsed = ([{
                "path": "Target.java", "has_error": False,
                "classes": [], "declarations": [], "calls": [],
            }], "")
            with patch("cognalys.extraction.semantic_index._parse_batch_isolated",
                       return_value=parsed):
                result = build_semantic_index(root, sources, target, "hash", 1)
            self.assertEqual(result["status"], "unresolved")
            self.assertEqual(result["backend"], "tree_sitter")


class KotlinTopLevelFallbackTests(unittest.TestCase):
    """NotallyX (2026-10-28): tree-sitter crashed with signal 11 on
    IOExtensions.kt, and the lexical fallback counted the three
    `fun Context.md5Hash(` extension declarations as callers while both real
    callers, reached through `import com.philkes.notallyx.utils.md5Hash`,
    stayed ambiguous."""

    IO_EXTENSIONS = (
        "package com.example.utils\n\n"
        "fun Context.md5Hash(uri: Uri): ByteArray? {\n"
        "    return contentResolver.openInputStream(uri)?.md5Hash()\n}\n\n"
        "fun File.md5Hash(): ByteArray {\n    return inputStream().md5Hash()\n}\n\n"
        "fun InputStream.md5Hash(): ByteArray {\n"
        "    return MessageDigest.getInstance(\"MD5\").digest(readBytes())\n}\n"
    )

    def _resolve(self, sources: dict[str, str],
                 target: str = "utils/IOExtensions.kt") -> dict:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {root / relative: text for relative, text in sources.items()}
            with patch(
                "cognalys.extraction.semantic_index._parse_batch_isolated",
                return_value=(None, "isolated tree-sitter parser failed with signal 11"),
            ):
                return build_semantic_index(
                    root, files, root / target, "md5Hash", None,
                )

    @staticmethod
    def _lines(items: list) -> set:
        return {(item["path"], item["line"]) for item in items}

    def test_extension_declarations_and_package_imports_resolve(self):
        result = self._resolve({
            "utils/IOExtensions.kt": self.IO_EXTENSIONS,
            "utils/backup/Export.kt": (
                "package com.example.utils.backup\n\n"
                "import com.example.utils.md5Hash\n\n"
                "fun Context.verify(zip: File, uri: Uri): Boolean {\n"
                "    val source = runCatching { zip.md5Hash() }.getOrNull()\n"
                "    return source == md5Hash(uri)\n}\n"
            ),
            "utils/Sizes.kt": (
                "package com.example.utils\n\n"
                "fun Context.same(uri: Uri, other: Uri) = md5Hash(uri) == md5Hash(other)\n"
            ),
            "other/Wild.kt": (
                "package com.example.other\n\nimport com.example.utils.*\n\n"
                "fun Context.check(uri: Uri) = md5Hash(uri)\n"
                "fun check(file: Hasher) = file.md5Hash()\n"
            ),
        })
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["target_symbol"]["line"], 3)
        self.assertEqual(self._lines(result["resolved_callers"]), {
            ("utils/IOExtensions.kt", 4), ("utils/IOExtensions.kt", 8),
            ("utils/backup/Export.kt", 6), ("utils/backup/Export.kt", 7),
            ("utils/Sizes.kt", 3), ("other/Wild.kt", 5),
        })
        # A receiver call reached only through a wildcard import may be a
        # member of the receiver's type.
        self.assertEqual(self._lines(result["ambiguous_calls"]), {("other/Wild.kt", 6)})

    def test_another_declaration_of_the_name_keeps_package_calls_ambiguous(self):
        result = self._resolve({
            "utils/IOExtensions.kt": self.IO_EXTENSIONS,
            "utils/Hasher.kt": (
                "package com.example.utils\n\nclass Hasher {\n"
                "    fun md5Hash(bytes: ByteArray) = bytes\n"
                "    fun run(bytes: ByteArray) {\n        return md5Hash(bytes)\n    }\n}\n"
            ),
            "utils/backup/Export.kt": (
                "package com.example.utils.backup\n\nimport com.example.utils.md5Hash\n\n"
                "fun Context.verify(uri: Uri) = md5Hash(uri)\n"
            ),
        })
        self.assertEqual(
            self._lines(result["related_declarations"]), {("utils/Hasher.kt", 4)},
        )
        # `return md5Hash(bytes)` is a call, not a declaration.
        self.assertEqual(self._lines(result["ambiguous_calls"]), {
            ("utils/Hasher.kt", 6), ("utils/backup/Export.kt", 5),
        })

    def test_the_same_name_imported_from_elsewhere_stays_ambiguous(self):
        result = self._resolve({
            "utils/IOExtensions.kt": self.IO_EXTENSIONS,
            "utils/Legacy.kt": (
                "package com.example.utils\n\nimport org.library.md5Hash\n\n"
                "fun legacy(bytes: ByteArray) = md5Hash(bytes)\n"
            ),
        })
        self.assertEqual(self._lines(result["ambiguous_calls"]), {("utils/Legacy.kt", 5)})

    def test_java_reaches_the_function_only_through_the_kt_facade(self):
        result = self._resolve({
            "utils/IOExtensions.kt": self.IO_EXTENSIONS,
            "utils/Facade.java": (
                "package com.example.utils;\n\nclass Facade {\n"
                "    byte[] hash(Context context, Uri uri) {\n"
                "        return IOExtensionsKt.md5Hash(context, uri);\n    }\n}\n"
            ),
            "other/Static.java": (
                "package com.example.other;\n\n"
                "import static com.example.utils.IOExtensionsKt.md5Hash;\n\n"
                "class Static {\n"
                "    byte[] hash(Context context, Uri uri) { return md5Hash(context, uri); }\n}\n"
            ),
            # Same package, but Java cannot call a top-level Kotlin function
            # unqualified: this is the inherited LibraryBase.md5Hash.
            "utils/Helper.java": (
                "package com.example.utils;\n\nclass Helper extends LibraryBase {\n"
                "    void run(Uri uri) {\n        md5Hash(uri);\n    }\n}\n"
            ),
        })
        resolved = self._lines(result["resolved_callers"])
        self.assertIn(("utils/Facade.java", 5), resolved)
        self.assertIn(("other/Static.java", 6), resolved)
        self.assertEqual(self._lines(result["ambiguous_calls"]), {("utils/Helper.java", 5)})

    def test_a_java_return_of_the_call_is_a_caller_not_a_declaration(self):
        result = self._resolve({
            "utils/Digests.java": (
                "package com.example.utils;\n\nclass Digests {\n"
                "    static byte[] md5Hash(byte[] bytes) {\n"
                "        return MessageDigest.getInstance(\"MD5\").digest(bytes);\n    }\n"
                "    static byte[] twice(byte[] bytes) {\n"
                "        return md5Hash(md5Hash(bytes));\n    }\n}\n"
            ),
        }, target="utils/Digests.java")
        self.assertEqual(result["target_symbol"]["line"], 4)
        self.assertEqual(result["related_declarations"], [])
        self.assertEqual(self._lines(result["resolved_callers"]), {("utils/Digests.java", 8)})


class WalkTraversalTests(unittest.TestCase):
    """_walk must stay a pre-order traversal without recursing per node."""

    def test_order_matches_the_recursive_definition(self):
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_java
        except ImportError:  # pragma: no cover - parsers are optional here
            self.skipTest("tree-sitter parsers are unavailable")
        from cognalys.extraction.semantic_index import _walk
        parser = Parser(Language(tree_sitter_java.language()))
        tree = parser.parse(
            b"class A { void m() { if (x) { y(z(w())); } else { q(); } } }"
        )

        def recursive(node):
            yield node
            for child in node.children:
                yield from recursive(child)

        self.assertEqual(
            [(n.type, n.start_byte) for n in _walk(tree.root_node)],
            [(n.type, n.start_byte) for n in recursive(tree.root_node)],
        )
