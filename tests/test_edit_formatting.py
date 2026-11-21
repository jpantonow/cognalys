import unittest


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils.edit_text import keep_untouched_formatting  # noqa: E402


class KeepUntouchedFormattingTests(unittest.TestCase):
    def test_inserting_after_an_unchanged_partial_line_keeps_the_newline(self):
        original = '    private static final String TAG = "tag";'
        corrected = original + '\n    private static final int COST = 100000;'
        self.assertEqual(keep_untouched_formatting(original, corrected), corrected)

    def test_a_removed_helper_leaves_no_blank_line_and_spaces_stay(self):
        """AmaRadio: md5() removed, and a whitespace-only line rewritten."""
        original = (
            "    }\n"
            "\n"
            "    private fun String.md5(): String {\n"
            "        return digest(this)\n"
            "    }\n"
            "\n"
            "    fun read() {\n"
            "        val name = key.md5()\n"
            "            \n"
            "        use(name)\n"
            "    }\n"
        )
        corrected = (
            "    }\n"
            "\n"
            "\n"
            "\n"
            "    fun read() {\n"
            "        val name = sha(key)\n"
            "\n"
            "        use(name)\n"
            "    }\n"
        )
        self.assertEqual(keep_untouched_formatting(original, corrected), (
            "    }\n"
            "\n"
            "    fun read() {\n"
            "        val name = sha(key)\n"
            "            \n"
            "        use(name)\n"
            "    }\n"
        ))

    def test_a_dropped_import_leaves_no_blank_line(self):
        """WiFiAnalyzer: `import java.security.MessageDigest` became a blank line."""
        original = "import a.B\nimport java.security.MessageDigest\nimport c.D\n"
        corrected = "import a.B\n\nimport c.D\n"
        self.assertEqual(keep_untouched_formatting(original, corrected),
                         "import a.B\nimport c.D\n")

    def test_deleting_a_block_keeps_a_single_separator(self):
        from cognalys.utils.edit_text import remove_block

        content = "    }\n\n    private fun md5() {\n    }\n\n    fun read() {}\n"
        self.assertEqual(remove_block(content, "    private fun md5() {\n    }\n"),
                         "    }\n\n    fun read() {}\n")
        # Without a blank line on both sides nothing extra is removed.
        self.assertEqual(remove_block("a\nb\nc\n", "b\n"), "a\nc\n")

    def test_a_removed_import_line_takes_its_line_break_with_it(self):
        """primftpd SshBuilder (2026-11-03): two removed imports left a blank line."""
        from cognalys.utils.edit_text import remove_block

        content = "import a.A;\nimport b.ARCFOUR128;\nimport b.ARCFOUR256;\nimport c.C;\n"
        self.assertEqual(
            remove_block(content, "import b.ARCFOUR128;\nimport b.ARCFOUR256;"),
            "import a.A;\nimport c.C;\n")
        # Copied without its indentation, the line still goes as a whole.
        self.assertEqual(remove_block("{\n    x();\n}\n", "x();"), "{\n}\n")
        # Text sharing the line with the block stays where it was.
        self.assertEqual(remove_block("a(); b();\n", "b();"), "a(); \n")

    def test_removals_do_not_pile_up_blank_lines(self):
        """BaseRC4Cipher (2026-11-03): three blank lines after the package line."""
        from cognalys.utils.edit_text import remove_block

        content = ("package p;\n\nimport javax.crypto.spec.SecretKeySpec;\n\n"
                   "import q.SecurityUtils;\n\npublic class C {}\n")
        content = remove_block(content, "import javax.crypto.spec.SecretKeySpec;")
        content = remove_block(content, "import q.SecurityUtils;")
        self.assertEqual(content, "package p;\n\npublic class C {}\n")
        # Blank lines the removal did not bring together are left alone.
        self.assertEqual(remove_block("a\n\n\nb\nx\nc\n", "x"), "a\n\n\nb\nc\n")
        # The longer run around the block is what stays.
        self.assertEqual(remove_block("a\n\n\nx\n\nb\n", "x\n"), "a\n\n\nb\n")

    def test_a_deletion_through_the_edit_set_removes_whole_lines(self):
        from cognalys.solutions.coordinated_edits import apply_edits_to_sources

        sources = {"A.java": "import a.A;\nimport b.B;\nimport c.C;\n"}
        edits = [{"source_file_path": "A.java", "edit_kind": "delete",
                  "symbol": "B", "reason": "unused",
                  "original_code": "import b.B;", "corrected_code": ""}]
        updated, issues = apply_edits_to_sources(sources, edits)
        self.assertEqual(issues, [])
        self.assertEqual(updated["A.java"], "import a.A;\nimport c.C;\n")

    def test_new_code_and_its_blank_lines_are_kept(self):
        original = "fun a() {\n    old()\n}\n"
        corrected = "fun a() {\n    first()\n\n    second()\n}\n"
        self.assertEqual(keep_untouched_formatting(original, corrected), corrected)


if __name__ == "__main__":
    unittest.main()
