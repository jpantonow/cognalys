import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.solutions.scope_utils import (  # noqa: E402
    brace_depth_at,
    enclosing_class_stack,
    find_declaration_scope_mismatches,
    indentation_of,
    new_callable_symbols,
    keep_doc_comment_on_anchor,
    unqualified_call_sites,
)


class BraceDepthTests(unittest.TestCase):
    def test_top_level_offset_is_depth_zero(self):
        content = "class A {\n    val x = 1\n}\n"
        self.assertEqual(brace_depth_at(content, 0), 0)

    def test_offset_inside_class_body_is_depth_one(self):
        content = "class A {\n    val x = 1\n}\n"
        offset = content.index("val")
        self.assertEqual(brace_depth_at(content, offset), 1)

    def test_braces_inside_string_literals_are_ignored(self):
        content = 'val s = "{ not a brace }"\nclass A {\n    val x = 1\n}\n'
        offset = content.index("val x")
        self.assertEqual(brace_depth_at(content, offset), 1)

    def test_braces_inside_comments_are_ignored(self):
        content = "// { fake\nclass A {\n    val x = 1\n}\n"
        offset = content.index("val x")
        self.assertEqual(brace_depth_at(content, offset), 1)


class EnclosingClassStackTests(unittest.TestCase):
    def test_empty_at_top_level(self):
        content = "class Outer {\n    fun f() {}\n}\n"
        self.assertEqual(enclosing_class_stack(content, 0), [])

    def test_nested_class_is_reported(self):
        content = "class Outer {\n    internal class Inner {\n        val x = 1\n    }\n}\n"
        offset = content.index("val x")
        stack = enclosing_class_stack(content, offset)
        self.assertEqual([frame["name"] for frame in stack], ["Outer", "Inner"])
        self.assertFalse(stack[-1]["is_inner"])
        self.assertFalse(stack[-1]["is_companion"])

    def test_inner_class_is_flagged(self):
        content = "class Outer {\n    inner class Inner {\n        val x = 1\n    }\n}\n"
        offset = content.index("val x")
        stack = enclosing_class_stack(content, offset)
        self.assertTrue(stack[-1]["is_inner"])

    def test_companion_object_is_flagged(self):
        content = "class Outer {\n    companion object {\n        val x = 1\n    }\n}\n"
        offset = content.index("val x")
        stack = enclosing_class_stack(content, offset)
        self.assertTrue(stack[-1]["is_companion"])

    def test_function_bodies_do_not_count_as_class_frames(self):
        content = "class Outer {\n    fun f() {\n        val x = 1\n    }\n}\n"
        offset = content.index("val x")
        stack = enclosing_class_stack(content, offset)
        self.assertEqual([frame["name"] for frame in stack], ["Outer"])


class NewCallableSymbolsTests(unittest.TestCase):
    def test_only_symbols_absent_from_original_are_returned(self):
        original = "class A {\n    val kept = 1\n}"
        corrected = "class A {\n    val kept = 1\n    fun helper(): Int = 2\n}"
        names = [name for name, _ in new_callable_symbols(original, corrected)]
        self.assertEqual(names, ["helper"])


class UnqualifiedCallSitesTests(unittest.TestCase):
    def test_finds_unqualified_call_in_other_file(self):
        edits = [
            {"source_file_path": "A.kt", "corrected_code": "fun helper() = 1"},
            {"source_file_path": "Test.kt", "corrected_code": "val r = helper()"},
        ]
        self.assertEqual(
            unqualified_call_sites(edits, "helper", declaring_file="A.kt"),
            ["Test.kt"],
        )

    def test_qualified_call_is_not_flagged(self):
        edits = [
            {"source_file_path": "Test.kt", "corrected_code": "val r = Utils.helper()"},
        ]
        self.assertEqual(
            unqualified_call_sites(edits, "helper", declaring_file="A.kt"), []
        )

    def test_imported_symbol_is_not_flagged(self):
        edits = [
            {
                "source_file_path": "Test.kt",
                "corrected_code": "import com.example.helper\nval r = helper()",
            },
        ]
        self.assertEqual(
            unqualified_call_sites(edits, "helper", declaring_file="A.kt"), []
        )


class DeclarationScopeMismatchTests(unittest.TestCase):
    def test_top_level_anchor_never_flags(self):
        original = "class Marker"
        corrected = "internal fun helper(): Int = 1\nclass Marker"
        findings = find_declaration_scope_mismatches(
            original, corrected, anchor_is_nested=False,
            other_edits=[{"source_file_path": "Test.kt", "corrected_code": "helper()"}],
            declaring_file="A.kt",
        )
        self.assertEqual(findings, [])

    def test_nested_anchor_with_cross_file_unqualified_call_is_flagged(self):
        original = "    private object Marker {\n        val x = 1\n    }"
        corrected = (
            "    internal fun helper(): Int = 1\n\n"
            "    private object Marker {\n        val x = 1\n    }"
        )
        findings = find_declaration_scope_mismatches(
            original, corrected, anchor_is_nested=True,
            other_edits=[{"source_file_path": "Test.kt", "corrected_code": "helper()"}],
            declaring_file="A.kt",
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("helper", findings[0])
        self.assertIn("Test.kt", findings[0])

    def test_nested_anchor_with_non_inner_sibling_caller_is_flagged(self):
        original = "    private object Marker {\n        val x = 1\n    }"
        corrected = (
            "    internal fun helper(): Int = 1\n\n"
            "    internal class Sibling {\n"
            "        fun use(): Int = helper()\n"
            "    }\n\n"
            "    private object Marker {\n        val x = 1\n    }"
        )
        findings = find_declaration_scope_mismatches(
            original, corrected, anchor_is_nested=True,
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("Sibling", findings[0])

    def test_companion_object_wrapped_declaration_is_not_flagged(self):
        original = "    private object Marker {\n        val x = 1\n    }"
        corrected = (
            "    companion object {\n"
            "        internal fun helper(): Int = 1\n"
            "    }\n\n"
            "    internal class Sibling {\n"
            "        fun use(): Int = helper()\n"
            "    }\n\n"
            "    private object Marker {\n        val x = 1\n    }"
        )
        findings = find_declaration_scope_mismatches(
            original, corrected, anchor_is_nested=True,
        )
        self.assertEqual(findings, [])

    def test_inner_class_caller_is_not_flagged(self):
        original = "    private object Marker {\n        val x = 1\n    }"
        corrected = (
            "    internal fun helper(): Int = 1\n\n"
            "    inner class Sibling {\n"
            "        fun use(): Int = helper()\n"
            "    }\n\n"
            "    private object Marker {\n        val x = 1\n    }"
        )
        findings = find_declaration_scope_mismatches(
            original, corrected, anchor_is_nested=True,
        )
        self.assertEqual(findings, [])


class IndentationOfTests(unittest.TestCase):
    def test_top_level_line_has_zero_indentation(self):
        self.assertEqual(indentation_of("class A {\n}\n"), 0)

    def test_nested_line_reports_leading_whitespace(self):
        self.assertEqual(indentation_of("    private object A {\n}\n"), 4)


class DocCommentOnAnchorTests(unittest.TestCase):
    """InterTune (2026-10-27): code prepended to an anchor went between the
    anchor and its KDoc, which then documented the new code."""

    CONTENT = (
        "fun before() = 1\n\n"
        "/**\n * Fetches only once per song.\n */\n"
        "@Suppress(\"x\")\n"
        "internal fun shouldFetch(): Boolean = true\n"
    )
    ANCHOR = "internal fun shouldFetch(): Boolean = true"

    def apply(self, original, corrected):
        original, corrected = keep_doc_comment_on_anchor(self.CONTENT, original, corrected)
        return self.CONTENT.replace(original, corrected, 1)

    def test_prepended_code_goes_above_the_doc_comment(self):
        result = self.apply(self.ANCHOR, "private fun added() = 2\n\n" + self.ANCHOR)
        self.assertIn(
            "private fun added() = 2\n\n/**\n * Fetches only once per song.\n */\n"
            "@Suppress(\"x\")\n" + self.ANCHOR, result)

    def test_an_edit_that_changes_the_anchor_is_left_alone(self):
        original, corrected = keep_doc_comment_on_anchor(
            self.CONTENT, self.ANCHOR, "internal fun shouldFetch(): Boolean = false")
        self.assertEqual((original, corrected),
                         (self.ANCHOR, "internal fun shouldFetch(): Boolean = false"))

    def test_an_anchor_without_a_doc_comment_is_left_alone(self):
        original, corrected = keep_doc_comment_on_anchor(
            self.CONTENT, "fun before() = 1", "fun added() = 0\nfun before() = 1")
        self.assertEqual(original, "fun before() = 1")

    def test_indented_members_keep_their_indentation(self):
        content = "object A {\n    /** Doc. */\n    fun b() = 1\n}\n"
        original, corrected = keep_doc_comment_on_anchor(
            content, "    fun b() = 1", "    fun c() = 2\n\n    fun b() = 1")
        self.assertEqual(content.replace(original, corrected, 1),
                         "object A {\n    fun c() = 2\n\n    /** Doc. */\n    fun b() = 1\n}\n")


if __name__ == "__main__":
    unittest.main()
