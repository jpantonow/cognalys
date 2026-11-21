"""A result is a result of something, and the something has to be recorded.

The runs in `outputs/` record a commit and `uncommitted_changes: true`. That
names the problem without identifying the code, and it says nothing about
the three things that changed underneath the pipeline while it ran: the
specifications it generated mid-run, the web research it fetched live, and
the learning store it wrote for the next run to read.

These tests pin the manifest's two halves -- capture and verification --
and pin the three refusals, including the one that matters most: a frozen
run that is missing a specification fails and names it, instead of writing
the rule it is about to be judged against.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.evaluation.experiment_manifest import (  # noqa: E402
    FROZEN_ENVIRONMENT_VARIABLE, capture, file_digest, frozen, pipeline_state,
    read, refusal, tree_digest, verify, write,
)


class FrozenFlagTests(unittest.TestCase):

    def test_the_flag_is_read_from_the_environment_each_time(self):
        with patch.dict(os.environ, {FROZEN_ENVIRONMENT_VARIABLE: "1"}):
            self.assertTrue(frozen())
        with patch.dict(os.environ, {FROZEN_ENVIRONMENT_VARIABLE: "no"}):
            self.assertFalse(frozen())
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(frozen())

    def test_the_refusal_says_what_was_refused_and_why(self):
        message = refusal("generating a specification", "missing: SpecA")
        self.assertIn("generating a specification", message)
        self.assertIn("SpecA", message)
        self.assertIn("cannot be compared", message)


class CaptureTests(unittest.TestCase):

    def _repository(self, directory: Path) -> Path:
        root = directory / "repo"
        root.mkdir()
        for args in (
            ("init", "-q"), ("config", "user.email", "t@example.com"),
            ("config", "user.name", "Test"),
        ):
            subprocess.run(["git", "-C", str(root), *args],
                           check=True, capture_output=True)
        (root / "code.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "-A"],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "one"],
                       check=True, capture_output=True)
        return root

    def test_an_uncommitted_change_is_identified_not_just_flagged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(Path(directory))
            clean = pipeline_state(root)
            (root / "code.py").write_text("x = 2\n", encoding="utf-8")
            dirty = pipeline_state(root)
        self.assertFalse(clean["uncommitted_changes"])
        self.assertEqual(clean["diff_sha256"], "")
        self.assertTrue(dirty["uncommitted_changes"])
        # The diff itself is hashed: two runs from the same dirty tree are
        # comparable, two from different ones are visibly not.
        self.assertEqual(len(dirty["diff_sha256"]), 64)
        self.assertEqual(dirty["commit"], clean["commit"])

    def test_an_untracked_module_is_part_of_the_code_identity(self):
        # git diff HEAD does not see untracked files, so two versions of an
        # untracked module used to record the same pipeline identity.
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(Path(directory))
            (root / "helper.py").write_text("y = 1\n", encoding="utf-8")
            first = pipeline_state(root)
            (root / "helper.py").write_text("y = 2\n", encoding="utf-8")
            second = pipeline_state(root)
            (root / "notes.txt").write_text("not code", encoding="utf-8")
            third = pipeline_state(root)
        self.assertEqual(first["diff_sha256"], second["diff_sha256"])
        self.assertTrue(first["uncommitted_changes"])
        self.assertEqual(first["untracked_code_files"], ["helper.py"])
        self.assertNotEqual(first["untracked_code_sha256"],
                            second["untracked_code_sha256"])
        self.assertEqual(second["untracked_code_sha256"],
                         third["untracked_code_sha256"])

    def test_the_specification_digest_carries_the_file_names(self):
        with tempfile.TemporaryDirectory() as directory:
            specs = Path(directory) / "specifications"
            specs.mkdir()
            (specs / "A.json").write_text("{}", encoding="utf-8")
            first = tree_digest(specs)
            (specs / "B.json").write_text("{}", encoding="utf-8")
            second = tree_digest(specs)
        self.assertEqual(first["files"], 1)
        self.assertEqual(second["files"], 2)
        self.assertNotEqual(first["sha256"], second["sha256"])
        self.assertIn("B.json", second["names"])

    def test_an_absent_directory_is_absent_rather_than_empty(self):
        self.assertEqual(tree_digest(Path("no/such/dir"))["status"], "absent")

    def test_a_manifest_round_trips(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(Path(directory))
            corpus = Path(directory) / "corpus.csv"
            corpus.write_text("unique_msg\nf-1\n", encoding="utf-8")
            manifest = capture(
                root=root, corpus=corpus,
                specifications=Path(directory) / "specs",
                model={"provider": "openai", "model": "gpt-5.6-terra"},
                budgets={"context_length": 400_000},
                learning_dir=Path(directory) / "learning",
                cohort=["f-1"], condition="B1",
            )
            path = Path(directory) / "manifest.json"
            write(path, manifest)
            self.assertEqual(read(path), manifest)
            self.assertEqual(manifest["corpus"]["sha256"], file_digest(corpus))
        self.assertEqual(manifest["condition"], "B1")
        self.assertIn("python", manifest["toolchain"])

    def test_the_manifest_records_the_history_rules_version(self):
        """Runs whose planners read earlier attempts under different rules differ."""
        from cognalys.learning.knowledge import HISTORY_RULES_VERSION

        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(Path(directory))
            corpus = Path(directory) / "corpus.csv"
            corpus.write_text("unique_msg\nf-1\n", encoding="utf-8")
            manifest = capture(
                root=root, corpus=corpus, specifications=Path(directory) / "specs",
                model={"model": "m"}, budgets={}, learning_dir=Path(directory) / "learning",
            )
        self.assertEqual(manifest["learning_store"]["history_rules_version"],
                         HISTORY_RULES_VERSION)


class VerifyTests(unittest.TestCase):

    BASE = {
        "pipeline": {"commit": "abc", "diff_sha256": ""},
        "corpus": {"sha256": "c1"},
        "specifications": {"sha256": "s1"},
        "model": {"model": "m1", "provider": "openai", "reasoning_effort": "high"},
        "toolchain": {"java": "openjdk 17", "python": "3.12.0"},
        "learning_store": {"ledger_sha256": "l1", "knowledge_sha256": "k1"},
        "budgets": {"max_output_tokens": 32768, "workers": 1, "retries": 2,
                    "step_timeout_minutes": 720.0},
        "cohort": ["f-1", "f-2"],
    }

    def _changed(self, section: str, field: str, value):
        observed = {key: dict(item) if isinstance(item, dict) else item
                    for key, item in self.BASE.items()}
        observed[section][field] = value
        return observed

    def test_an_identical_run_has_no_differences(self):
        self.assertEqual(verify(self.BASE, dict(self.BASE)), [])

    def test_each_compared_field_is_reported_by_name(self):
        for section, field, value in (
            ("pipeline", "commit", "def"),
            ("corpus", "sha256", "c2"),
            ("specifications", "sha256", "s2"),
            ("model", "model", "m2"),
            ("model", "service_tier", "flex"),
            ("toolchain", "java", "openjdk 21"),
            ("learning_store", "ledger_sha256", "l2"),
            ("model", "research_reasoning_effort", "medium"),
            ("budgets", "workers", 4),
            ("budgets", "step_timeout_minutes", 60.0),
        ):
            differences = verify(self.BASE, self._changed(section, field, value))
            self.assertEqual(len(differences), 1, f"{section}.{field}")
            self.assertIn(f"{section}.{field}", differences[0])

    def test_two_runs_that_differ_only_in_the_output_ceiling_do_not_match(self):
        # PLANO_CORRECOES_DEFESA A2: the budgets were recorded and not compared.
        differences = verify(self.BASE, self._changed("budgets", "max_output_tokens", 16384))
        self.assertEqual(differences, [
            "budgets.max_output_tokens: manifest has 32768, this run has 16384"])

    def test_the_run_records_the_tier_its_openai_calls_ask_for(self):
        # What prepare_frozen_experiment puts in the manifest's model block.
        from cognalys.orchestration import run_pipeline

        for argv, tier in ((["--llm-provider", "openai"], "flex"),
                           (["--llm-provider", "openai", "--llm-service-tier", "auto"], "auto"),
                           (["--llm-provider", "anthropic"], "")):
            with self.subTest(argv=argv):
                self.assertEqual(
                    run_pipeline.requested_service_tier(run_pipeline.parse_args(argv)), tier)

    def test_a_dirty_tree_against_a_clean_manifest_is_a_difference(self):
        observed = self._changed("pipeline", "diff_sha256", "abc123")
        self.assertTrue(verify(self.BASE, observed))

    def test_a_manifest_without_a_research_corpus_matches_an_old_one(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "corpus.csv"
            corpus.write_text("unique_msg\nf-1\n", encoding="utf-8")
            manifest = capture(
                root=Path(directory), corpus=corpus, specifications=Path(directory) / "specs",
                model={"model": "m"}, budgets={}, learning_dir=Path(directory) / "learning")
        self.assertNotIn("research_corpus", manifest)
        self.assertNotIn("web_research", manifest)
        # BASE stands for a manifest written before the fields existed.
        self.assertEqual(verify(self.BASE, dict(self.BASE)), [])

    def test_the_maintainer_answers_the_prompts_read_are_part_of_the_experiment(self):
        """B12: data/pr_outcomes reaches adjudication, planning and generation."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "corpus.csv"
            corpus.write_text("unique_msg\nf-1\n", encoding="utf-8")
            outcomes = root / "pr_outcomes"
            outcomes.mkdir()
            (outcomes / "owner__app.json").write_text("[]", encoding="utf-8")

            def manifest():
                return capture(root=root, corpus=corpus, specifications=root / "specs",
                               model={"model": "m"}, budgets={}, learning_dir=root / "learning",
                               pr_outcomes_dir=outcomes)

            before = manifest()
            self.assertEqual(before["pr_outcomes"]["names"], ["owner__app.json"])
            self.assertEqual(verify(before, manifest()), [])
            (outcomes / "owner__app.json").write_text('[{"state": "merged"}]', encoding="utf-8")
            differences = verify(before, manifest())
        self.assertEqual(len(differences), 1)
        self.assertIn("pr_outcomes.sha256", differences[0])
        # A manifest written before the field recorded none: compared without it.
        old = {key: value for key, value in before.items() if key != "pr_outcomes"}
        self.assertNotIn("pr_outcomes.sha256", " ".join(verify(old, before)))

    def test_the_holdout_is_recorded_only_when_on_and_compared(self):
        """B13: a run without --holdout-repository writes the manifest it wrote before."""
        from cognalys.orchestration import run_pipeline

        self.assertFalse(run_pipeline.parse_args(["--llm-provider", "openai"]).holdout_repository)
        self.assertTrue(run_pipeline.parse_args(["--llm-provider", "openai", "--holdout-repository"]).holdout_repository)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "corpus.csv"
            corpus.write_text("unique_msg\nf-1\n", encoding="utf-8")
            common = dict(root=root, corpus=corpus, specifications=root / "specs",
                          model={"model": "m"}, budgets={}, learning_dir=root / "learning",
                          pr_outcomes_dir=root / "outcomes")
            off = capture(**common)
            on = capture(**common, holdout_repository=True)
        self.assertNotIn("evaluation", off)
        self.assertEqual(on["evaluation"], {"holdout_repository": True})
        self.assertEqual(verify(on, off), [
            "evaluation.holdout_repository: manifest has True, this run has None"])

    @staticmethod
    def _corpus(directory: Path, *prompts):
        from cognalys.llm.research_corpus import ResearchCorpus, request_identity

        corpus = ResearchCorpus(directory)
        for prompt in prompts:
            identity = request_identity(
                provider="openai", endpoint="e", model="m", reasoning_effort="high",
                max_output_tokens=1, system_prompt="s", prompt=prompt, json_schema=None,
                schema_name=None, research_instructions="r", synthesis_header="h",
                synthesis_instructions="i", web_search_tool={"type": "t"})
            corpus.put(identity, {}, json.dumps({"sources": [{"url": "https://a"}]}), "b", {})

    def test_two_research_corpora_with_different_entries_are_different_experiments(self):
        from cognalys.llm.research_corpus import corpus_digest

        with tempfile.TemporaryDirectory() as directory:
            self._corpus(Path(directory) / "a", "q1")
            self._corpus(Path(directory) / "b", "q1", "q2")
            first = dict(self.BASE, research_corpus=corpus_digest(Path(directory) / "a"))
            second = dict(self.BASE, research_corpus=corpus_digest(Path(directory) / "b"))
        differences = verify(first, second)
        self.assertEqual(len(differences), 1)
        self.assertIn("research_corpus.sha256", differences[0])
        self.assertEqual(verify(first, dict(first)), [])
        self.assertTrue(verify(self.BASE, first))

    def test_a_live_research_run_may_add_entries_but_not_lose_or_change_one(self):
        from cognalys.llm.research_corpus import corpus_digest, corpus_entry_digests

        def recorded(path, run="/runs/v9/logs"):
            return {**corpus_digest(path), "max_age_days": 90.0, "run_log_dir": run,
                    "entry_sha256": corpus_entry_digests(path)}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._corpus(root / "start", "q1")
            self._corpus(root / "grown", "q1", "q2")
            self._corpus(root / "other", "q2")
            live = {"web_research": {"mode": "live"}}
            start = dict(self.BASE, research_corpus=recorded(root / "start"), **live)
            grown = dict(self.BASE, research_corpus=recorded(root / "grown"), **live)
            other = dict(self.BASE, research_corpus=recorded(root / "other"), **live)
            replica = dict(self.BASE, research_corpus=recorded(root / "grown", "/runs/v10/logs"),
                           **live)
            aged = dict(self.BASE, research_corpus={**recorded(root / "grown"),
                                                    "max_age_days": 30.0}, **live)
        # The run resumed, with what it stored meanwhile: the same experiment.
        self.assertEqual(verify(start, grown), [])
        self.assertEqual(len(verify(start, other)), 1)
        self.assertIn("missing or changed", verify(start, other)[0])
        # Another run against the manifest would be served what this one researched.
        self.assertEqual(len(verify(start, replica)), 1)
        self.assertIn("run_log_dir", verify(start, replica)[0])
        self.assertIn("research_corpus.max_age_days", verify(start, aged)[0])
        # Live research against a frozen-research manifest is another experiment.
        frozen = dict(self.BASE, research_corpus=corpus_digest(Path("absent")))
        self.assertTrue(any("web_research.mode" in item for item in verify(frozen, start)))

    def test_a_changed_cohort_is_reported_in_both_directions(self):
        observed = dict(self.BASE, cohort=["f-1", "f-3"])
        differences = verify(self.BASE, observed)
        self.assertEqual(len(differences), 2)
        self.assertTrue(any("missing" in item for item in differences))
        self.assertTrue(any("added" in item for item in differences))


class FrozenRefusalTests(unittest.TestCase):

    def test_a_frozen_run_refuses_to_generate_a_missing_specification(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "corpus.csv"
            corpus.write_text(
                "apk,spec,class,method,message\n"
                "app.apk,NeverSeenSpec,a.B,m,broken\n",
                encoding="utf-8",
            )
            specs = Path(directory) / "specifications"
            specs.mkdir()
            completed = subprocess.run(
                [sys.executable, "-m", "cognalys.specifications.generate_specifications",
                 "--csv-file", str(corpus), "--specifications-dir", str(specs)],
                capture_output=True, text=True,
                env={**os.environ, FROZEN_ENVIRONMENT_VARIABLE: "1",
                     "PYTHONPATH": str(ROOT / "src")},
            )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("NeverSeenSpec", completed.stderr)
        self.assertIn("frozen experiment", completed.stderr)
        # Nothing was written.
        self.assertEqual(list(specs.glob("*.json")), [])

    def test_a_frozen_run_does_not_fetch_web_research(self):
        sys.path.insert(0, str(ROOT / "src" / "cognalys" / "llm"))
        from cognalys.llm.llm_providers import _frozen_experiment

        with patch.dict(os.environ, {FROZEN_ENVIRONMENT_VARIABLE: "1"}):
            self.assertTrue(_frozen_experiment())
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(_frozen_experiment())

    def test_live_research_lets_a_frozen_run_reach_the_web_and_needs_a_manifest(self):
        from cognalys.evaluation.experiment_manifest import LIVE_RESEARCH_VARIABLE
        from cognalys.llm.llm_providers import _frozen_experiment
        from cognalys.orchestration import run_pipeline

        with patch.dict(os.environ, {FROZEN_ENVIRONMENT_VARIABLE: "1",
                                     LIVE_RESEARCH_VARIABLE: "1"}):
            self.assertFalse(_frozen_experiment())
        self.assertTrue(run_pipeline.parse_args(
            ["--llm-provider", "openai", "--experiment-live-research"]).experiment_live_research)
        self.assertFalse(run_pipeline.parse_args(["--llm-provider", "openai"]).experiment_live_research)


class PrepareFrozenExperimentTests(unittest.TestCase):
    """prepare_frozen_experiment with the options a real command line gives.

    No test went through it, and it read args.llm_context_length, an
    attribute parse_args never sets (the option's dest is
    ollama_context_length): every --experiment-manifest run stopped with an
    AttributeError before its first step.
    """

    TOOLCHAIN = {"java": "openjdk 17", "python": "3.12.0",
                 "python_environment_sha256": "p1"}

    def _prepare(self, root: Path, argv):
        from cognalys.orchestration import run_pipeline

        args = run_pipeline.parse_args(["--llm-provider", "openai", *argv])
        paths = run_pipeline.resolve_paths(args, root)
        with patch("cognalys.evaluation.experiment_manifest.toolchain",
                   return_value=dict(self.TOOLCHAIN)):
            return run_pipeline.prepare_frozen_experiment(args, paths, root)

    def test_it_writes_then_verifies_then_refuses_a_divergent_run(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {}, clear=False):
            root = Path(directory)
            (root / "findings.csv").write_text("unique_msg\nf-1\n", encoding="utf-8")
            manifest = root / "manifest.json"
            argv = ["--csv-file", "findings.csv", "--experiment-manifest", str(manifest),
                    "--llm-context-length", "8192"]
            self.assertEqual(self._prepare(root, argv), 0)
            self.assertEqual(read(manifest)["budgets"]["context_length"], 8192)
            self.assertEqual(self._prepare(root, argv), 0)
            self.assertEqual(self._prepare(root, [*argv, "--llm-reasoning-effort", "low"]), 2)
            self.assertEqual(self._prepare(root, [*argv, "--llm-max-output-tokens", "1000"]), 2)
            self.assertEqual(self._prepare(
                root, [*argv, "--llm-research-reasoning-effort", "medium"]), 2)

    def test_a_dry_run_assembles_the_manifest_without_writing_it(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {}, clear=False):
            root = Path(directory)
            manifest = root / "manifest.json"
            self.assertEqual(self._prepare(
                root, ["--experiment-manifest", str(manifest), "--dry-run"]), 0)
            self.assertFalse(manifest.exists())


class FrozenRetrospectiveTests(unittest.TestCase):

    def test_a_frozen_run_reports_without_writing_the_learning_store(self):
        from cognalys.learning.retrospective import run_retrospective

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run_20260101_000000"
            (run_dir / "error_solutions" / "evidence_reviews").mkdir(parents=True)
            (run_dir / "application_results").mkdir(parents=True)
            (run_dir / "pull_requests").mkdir(parents=True)
            learning = root / "learning"
            learning.mkdir()
            with patch.dict(os.environ, {FROZEN_ENVIRONMENT_VARIABLE: "1"}):
                report = run_retrospective(run_dir, learning)
            self.assertFalse(report["learning_store_written"])
            self.assertEqual(list(learning.glob("*.json")), [])

            with patch.dict(os.environ, {}, clear=True):
                report = run_retrospective(run_dir, learning)
            self.assertTrue(report["learning_store_written"])
            self.assertTrue(list(learning.glob("*.json")))


if __name__ == "__main__":
    unittest.main()
