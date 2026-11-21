import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import api  # noqa: E402
from cognalys.detectors import RepositoryTarget, locate, snapshot  # noqa: E402
from cognalys.models import RunConfig, RunResult  # noqa: E402
from cognalys.validation import semgrep_rules  # noqa: E402

HASHER = """package org.example;

import java.security.MessageDigest;

public class Hasher {
    private final String salt = "x";

    public byte[] digest(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(input);
    }
}
"""
SOURCE = "app/src/main/java/org/example/Hasher.java"


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.run(["git", *arguments], cwd=repo, capture_output=True,
                          text=True, check=True).stdout.strip()


def _repository(directory: str) -> Path:
    repo = Path(directory) / "notes"
    (repo / SOURCE).parent.mkdir(parents=True)
    (repo / SOURCE).write_text(HASHER, encoding="utf-8")
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    return repo


class LocateTests(unittest.TestCase):

    def test_a_line_is_located_by_its_class_and_method(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Hasher.java"
            path.write_text(HASHER, encoding="utf-8")
            self.assertEqual(locate(path, 9), ("org.example.Hasher", "digest"))

    def test_a_kotlin_top_level_function_belongs_to_the_file_class(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Crypto.kt"
            path.write_text("package org.example\n\nfun hash(b: ByteArray): ByteArray {\n"
                            "    return b\n}\n", encoding="utf-8")
            self.assertEqual(locate(path, 4), ("org.example.CryptoKt", "hash"))


class TargetNameTests(unittest.TestCase):

    def test_a_clone_named_after_its_apk_is_not_suffixed_twice(self):
        self.assertEqual(RepositoryTarget(local_path=Path("/x/com.app_3.apk")).name(), "com.app_3")
        self.assertEqual(RepositoryTarget(url="https://github.com/o/notes.git").name(), "notes")


class SnapshotTests(unittest.TestCase):

    def test_a_clean_checkout_and_a_changed_one(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = _repository(directory)
            clean = snapshot(repo)
            self.assertFalse(clean.dirty)
            self.assertEqual(clean.commit, _git(repo, "rev-parse", "HEAD"))
            (repo / SOURCE).write_text(HASHER + "// edited\n", encoding="utf-8")
            changed = snapshot(repo)
            self.assertTrue(changed.dirty)
            self.assertEqual(changed.changed_files, (SOURCE,))

    def test_a_directory_without_git_is_refused(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            snapshot(Path(directory))


@unittest.skipUnless(semgrep_rules.find_semgrep(), "semgrep is not installed")
class SemgrepDiscoveryTests(unittest.TestCase):

    def test_the_rules_find_the_misuse_in_a_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = _repository(directory)
            found = api.scan(RepositoryTarget(local_path=repo),
                             specifications=["MessageDigestSpec"])
        self.assertTrue(found.complete)
        [finding] = found.findings
        self.assertEqual(finding.key,
                         ("notes.apk", "org.example.Hasher", "digest", "MessageDigestSpec"))
        self.assertEqual(finding.detector["source_location"], f"{SOURCE}:9")
        self.assertEqual(finding.repo_url, str(repo.resolve()))
        self.assertEqual(finding.commit, found.commit)


class SemgrepUnavailableTests(unittest.TestCase):

    def test_a_missing_detector_is_a_problem_not_an_empty_result(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = _repository(directory)
            with patch.object(semgrep_rules, "find_semgrep", return_value=""):
                found = api.scan(RepositoryTarget(local_path=repo))
        self.assertFalse(found.complete)
        self.assertEqual(found.findings, ())
        self.assertEqual(found.problems[0]["status"], semgrep_rules.DETECTOR_UNAVAILABLE)


class RepairRepositoryTests(unittest.TestCase):

    def test_a_checkout_with_uncommitted_changes_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = _repository(directory)
            (repo / SOURCE).write_text(HASHER + "// edited\n", encoding="utf-8")
            with self.assertRaises(api.RepositoryChanged) as caught:
                api.repair_repository(RepositoryTarget(local_path=repo),
                                      RunConfig.from_legacy_args(["--llm-provider", "openai"]))
        self.assertIn(SOURCE, str(caught.exception))

    def test_the_scan_findings_are_what_the_run_receives(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = _repository(directory)
            seen = {}

            def fake_run(config, workspace=None, findings=None):
                seen["findings"] = findings
                return RunResult(runs=())

            with patch.object(api, "run", side_effect=fake_run), \
                    patch.object(semgrep_rules, "find_semgrep", return_value=""):
                found, result = api.repair_repository(
                    RepositoryTarget(local_path=repo), RunConfig.from_legacy_args(["--llm-provider", "openai"]))
        # No detector: nothing found, so the pipeline is not started at all.
        self.assertEqual(found.findings, ())
        self.assertEqual(seen, {})
        self.assertEqual(result.findings, ())


if __name__ == "__main__":
    unittest.main()
