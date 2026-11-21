"""A type is found in the file that declares it, whatever that file is called (B11).

RepositoryIndex.declaring_path looked only at files named after the type.
Kotlin declares top-level types in files of any name: InterTune's
`object WidgetCodec` is in WidgetSnapshot.kt, and the evidence request
{"kind": "related_source", "symbol": "WidgetCodec"} was declined "no
matching file in the repository" (agent_baseline_20261108 intertune_hash
run_k3v9 and run_k3v10).
"""
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.evidence_requests import RepositoryIndex, resolve_evidence_requests  # noqa: E402

SNAPSHOT = """package app.widget

data class WidgetSnapshot(val title: String)

object WidgetCodec {
    fun encode(snapshot: WidgetSnapshot): String = snapshot.title
}
"""


class DeclaringPathTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        main = self.root / "app" / "src" / "main" / "java" / "app" / "widget"
        main.mkdir(parents=True)
        (main / "WidgetSnapshot.kt").write_text(SNAPSHOT, encoding="utf-8")
        test = self.root / "app" / "src" / "test" / "java" / "app" / "widget"
        test.mkdir(parents=True)
        (test / "Fakes.kt").write_text("object WidgetCodec\n", encoding="utf-8")
        self.index = RepositoryIndex(self.root)

    def test_both_top_level_types_of_one_kotlin_file_are_found(self):
        main = self.root / "app/src/main/java/app/widget/WidgetSnapshot.kt"
        self.assertEqual(self.index.declaring_path("WidgetSnapshot"), main)
        # Found by content, the main source before the test fake.
        self.assertEqual(self.index.declaring_path("WidgetCodec"), main)
        self.assertIsNone(self.index.declaring_path("NoSuchType"))

    def test_a_word_in_a_comment_or_string_is_not_a_declaration(self):
        # The content search reads every source: "an object The ..." in a
        # comment answered the prose symbol "The" before declarations were
        # required to start their line.
        notes = self.root / "app" / "src" / "main" / "java" / "app" / "Notes.java"
        notes.write_text(
            "class Notes {\n"
            "    // Wraps an object The caller owns.\n"
            "    String s = \"a class Secret here\";\n"
            "    public static class Engine {}\n"
            "}\n"
            "@Deprecated final class Holder {}\n", encoding="utf-8")
        index = RepositoryIndex(self.root)
        self.assertIsNone(index.declaring_path("The"))
        self.assertIsNone(index.declaring_path("Secret"))
        # A nested namesake in an unrelated file is another type.
        self.assertIsNone(index.declaring_path("Engine"))
        # A second top-level type of the file, annotated, is found.
        self.assertEqual(index.declaring_path("Holder"), notes)

    def test_the_answer_is_kept_for_the_next_request(self):
        first = self.index.declaring_path("WidgetCodec")
        (first).unlink()
        self.assertEqual(self.index.declaring_path("WidgetCodec"), first)

    def test_the_declined_request_is_answered(self):
        resolution = resolve_evidence_requests(
            self.root, [{"kind": "related_source", "symbol": "WidgetCodec"}], set(),
            index=self.index)
        self.assertFalse([item for item in resolution["declined"]
                          if item.get("reason") == "no matching file in the repository"])
        self.assertTrue(resolution["entries"])


if __name__ == "__main__":
    unittest.main()
