import contextlib
import io
import os
import tempfile
import time
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import cache, cli  # noqa: E402
from cognalys.models import FindingResult, RunResult  # noqa: E402


def _finding(outcome):
    return FindingResult(apk="a.apk", csv_class="a.B", method="m", spec="S", outcome=outcome)


class FailOnTests(unittest.TestCase):
    RESULT = RunResult(runs=(), findings=(
        _finding("PR pronto"),
        _finding("issue para o mantenedor do app"),
        _finding("falso positivo reconhecido"),
        _finding("evidência insuficiente"),
        _finding("correção não aplicável: código mudou upstream"),
    ))

    def test_levels(self):
        self.assertEqual(len(self.RESULT.failing("none")), 0)
        self.assertEqual([f.outcome for f in self.RESULT.failing("unfixed")],
                         ["issue para o mantenedor do app"])
        self.assertEqual(len(self.RESULT.failing("confirmed")), 2)
        # A false positive and code already fixed upstream never fail a run.
        self.assertEqual(len(self.RESULT.failing("any")), 3)

    def test_the_cli_keeps_a_failed_runs_own_code(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli._fail_on(self.RESULT, "unfixed", 0), 1)
            self.assertEqual(cli._fail_on(self.RESULT, "unfixed", 3), 3)
            self.assertEqual(cli._fail_on(self.RESULT, "none", 0), 0)

    def test_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as exit_:
            cli.main(["--version"])
        self.assertEqual(exit_.exception.code, 0)
        self.assertTrue(out.getvalue().startswith("cognalys "))


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.outputs = Path(self.directory.name)
        shard = self.outputs / ".llm_cache" / "ab"
        shard.mkdir(parents=True)
        self.old = shard / "old.json"
        self.new = shard / "new.json"
        self.old.write_text("x" * 100, encoding="utf-8")
        self.new.write_text("y" * 50, encoding="utf-8")
        forty_days_ago = time.time() - 40 * 86400
        os.utime(self.old, (forty_days_ago, forty_days_ago))
        self.baseline = self.outputs / "run_x" / "baseline_build_cache" / "abc123_worktree"
        self.baseline.mkdir(parents=True)
        (self.baseline / "build.gradle").write_text("", encoding="utf-8")

    def tearDown(self):
        self.directory.cleanup()

    def test_info_counts_each_cache(self):
        lines = cache.info(self.outputs)
        self.assertIn("2 entries", lines[0])
        self.assertIn("1 entries", lines[1])

    def test_a_dry_run_removes_nothing(self):
        self.assertEqual(cache.clear(self.outputs, ["llm"], dry_run=True), (2, 150))
        self.assertTrue(self.old.exists())

    def test_older_than_keeps_recent_entries(self):
        self.assertEqual(cache.clear(self.outputs, ["llm"], older_than_days=30), (1, 100))
        self.assertFalse(self.old.exists())
        self.assertTrue(self.new.exists())

    def test_only_the_named_kind_is_cleared(self):
        cache.clear(self.outputs, ["baselines"])
        self.assertFalse(self.baseline.exists())
        self.assertTrue(self.new.exists())

    def test_clearing_the_caches_leaves_the_research_corpus(self):
        entry = self.outputs / "research_corpus" / "abc.json"
        entry.parent.mkdir()
        entry.write_text("{}", encoding="utf-8")
        cache.clear(self.outputs, list(cache.CACHE_KINDS))
        self.assertFalse(self.new.exists())
        self.assertTrue(entry.exists())
        self.assertNotIn("research_corpus", cache.CACHE_KINDS)


class ResearchCorpusCommandTests(unittest.TestCase):
    def test_research_corpus_list_and_import(self):
        import json

        from test_research_corpus import BRIEF, SYNTHESIS, _Session, recording_provider, research

        def run(*argv):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = cli.main(list(argv))
            return code, out.getvalue()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / "run" / "application_results" / "openai_prompt_logs"
            research(recording_provider(logs, _Session(BRIEF, SYNTHESIS)))
            corpus = root / "corpus"
            code, printed = run("research-corpus", "import", "--dir", str(corpus),
                                str(root / "run"), "--dry-run")
            self.assertEqual(code, 0)
            self.assertIn("would store 1", printed)
            self.assertFalse(corpus.exists())
            code, printed = run("research-corpus", "import", str(root / "run"),
                                "--dir", str(corpus), "--json")
            self.assertEqual((code, json.loads(printed)["stored"]), (0, 1))
            code, printed = run("research-corpus", "list", "--dir", str(corpus))
            self.assertEqual(code, 0)
            self.assertIn("1 entries, 0 older than 90 days", printed)
            self.assertIn("import", printed)
            code, printed = run("research-corpus", "list", "--dir", str(corpus), "--json")
            self.assertEqual(len(json.loads(printed)["entries"]), 1)
            self.assertEqual(run("research-corpus", "import", "--dir", str(corpus))[0], 2)
            self.assertEqual(run("research-corpus", "import", str(root / "absent"),
                                 "--dir", str(corpus))[0], 2)


if __name__ == "__main__":
    unittest.main()
