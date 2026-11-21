"""The repository index lists the same checkout the same way on every run.

ripgrep streams files in the order its threads finish. The index kept that
order, so one checkout produced a different file order -- and, through it, a
different evidence packet, prompt and LLM cache key -- run after run: the
same finding replayed twice at the same commit gave two different context
snapshots.
"""
import shutil
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction import repository_index  # noqa: E402


class RepositoryIndexOrderTests(unittest.TestCase):
    def _checkout(self, directory):
        root = Path(directory)
        for index, name in enumerate(("z/Last.kt", "a/First.java", "m/Middle.java",
                                      "a/b/Deep.kt", "README.md")):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"class C{index} {{}}\n", encoding="utf-8")
        return root

    def _assert_sorted(self, index):
        self.assertEqual(index["paths"], sorted(index["paths"]))
        self.assertEqual(list(index["source_cache"]), sorted(index["source_cache"]))

    @unittest.skipUnless(shutil.which("rg") or shutil.which("rg.exe"), "ripgrep not installed")
    def test_the_ripgrep_index_is_in_path_order(self):
        with tempfile.TemporaryDirectory() as directory:
            index = repository_index.build_repository_index(self._checkout(directory))
        self.assertEqual(index["metadata"]["backend"], "ripgrep_stream")
        self._assert_sorted(index)

    def test_a_capped_index_keeps_the_first_files_in_path_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._checkout(directory)
            index = repository_index.build_repository_index(root, max_total_chars=25)
        kept = [path.relative_to(root).as_posix() for path in index["source_cache"]]
        self.assertEqual(kept, ["a/First.java", "a/b/Deep.kt"])

    def test_the_fallback_walk_is_in_path_order(self):
        with tempfile.TemporaryDirectory() as directory:
            index = repository_index._fallback_index(self._checkout(directory), 500_000, 60_000_000)
        self._assert_sorted(index)


if __name__ == "__main__":
    unittest.main()
