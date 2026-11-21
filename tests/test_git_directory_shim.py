import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cognalys.builds import apk_build, git_directory
from cognalys.builds.git_directory import GIT_POINTER_BACKUP, git_directory_for_build
from cognalys.extraction import dependency_context

# NotallyX's app/build.gradle.kts (run_v4, 2026-10-29): a preBuild dependency
# that copies hooks into .git/hooks.
HOOKS_TASK = (
    'tasks.register<Copy>("installLocalGitHooks") {\n'
    '    into(File(rootProject.rootDir, ".git/hooks"))\n'
    "}\n"
)


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *arguments],
                          check=True, capture_output=True, text=True).stdout.strip()


@unittest.skipIf(sys.platform.startswith("win"), "the fake gradlew is a POSIX script")
class EveryBuildGetsTheGitDirectoryTests(unittest.TestCase):
    """The shim used to wrap only the validation's production build: NotallyX's
    unit-test build and its baseline then failed at installLocalGitHooks
    because a worktree's .git is a file."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        main = self.root / "main"
        main.mkdir()
        _git(main, "init", "-q", "-b", "main")
        _git(main, "config", "user.email", "t@t")
        _git(main, "config", "user.name", "t")
        (main / "app").mkdir()
        (main / "app" / "build.gradle.kts").write_text(HOOKS_TASK, encoding="utf-8")
        (main / "settings.gradle.kts").write_text('include(":app")\n', encoding="utf-8")
        _git(main, "add", "-A")
        _git(main, "commit", "-qm", "init")
        self.worktree = self.root / "projects" / "finding"
        self.worktree.parent.mkdir()
        _git(main, "worktree", "add", "-q", str(self.worktree), "-b", "fix/hooks")

    def _build(self, gradlew: str, gradle_root: Path = None):
        gradle_root = gradle_root or self.worktree
        script = gradle_root / "gradlew"
        script.write_text("#!/bin/sh\n" + gradlew, encoding="utf-8")
        script.chmod(0o755)
        args = SimpleNamespace(
            clean_first=False, additional_task=[], gradle_property=[],
            refresh_dependencies=False, android_sdk="", java_home="/usr",
            skip_submodules=True, timeout=60, hung_client_grace=30,
            projects_dir=str(self.worktree.parent),
        )
        with mock.patch.object(apk_build, "ensure_validation_keystore", return_value=None):
            return apk_build.run_build(self.worktree, gradle_root, ":app:testDebugUnitTest",
                                       None, self.root / "out", args)

    def _android_subdirectory(self) -> Path:
        # The Gradle build in android/, its script reading the checkout's
        # .git one level up -- find_gradle_root's subdirectory layout.
        android = self.worktree / "android"
        android.mkdir()
        (android / "settings.gradle").write_text("include ':app'\n", encoding="utf-8")
        (android / "build.gradle").write_text(
            "def head = new File(rootDir, '../.git/HEAD').text\n", encoding="utf-8")
        return android

    def test_a_gradle_root_in_a_subdirectory_gets_the_shim_on_the_checkout(self):
        android = self._android_subdirectory()
        (self.worktree / "settings.gradle.kts").unlink()
        self.assertEqual(apk_build.find_gradle_root(self.worktree), android)
        result = self._build('cat ../.git/HEAD || exit 1\necho "BUILD SUCCESSFUL in 1s"\n',
                             gradle_root=android)
        self.assertEqual(result.return_code, 0, Path(result.log_file).read_text())
        self.assertEqual(result.git_directory_shim, {
            "applied": True, "build_scripts_reading_git": ["android/build.gradle"],
        })
        self.assertIn("ref: refs/heads/fix/hooks", Path(result.log_file).read_text())
        self.assertTrue((self.worktree / ".git").is_file())
        self.assertEqual(_git(self.worktree, "rev-parse", "--abbrev-ref", "HEAD"), "fix/hooks")

    def test_the_dependency_graph_is_resolved_with_the_shim(self):
        android = self._android_subdirectory()
        (android / "app").mkdir()
        (android / "app" / "build.gradle").write_text(
            "plugins { id 'com.android.application' }\n", encoding="utf-8")
        gradlew = android / "gradlew"
        gradlew.write_text("#!/bin/sh\ncat ../.git/HEAD >/dev/null || exit 1\n"
                           "echo '+--- com.example:lib:1.0'\n", encoding="utf-8")
        gradlew.chmod(0o755)
        dependency_context._GRAPH_CACHE.pop(str(self.worktree.resolve()), None)
        self.addCleanup(dependency_context._GRAPH_CACHE.pop, str(self.worktree.resolve()), None)
        graph = dependency_context.resolve_dependency_graph(self.worktree)
        self.assertEqual(graph["status"], "available", graph)
        self.assertEqual([node["artifact"] for node in graph["nodes"]], ["lib"])
        self.assertTrue((self.worktree / ".git").is_file())

    def _assert_worktree_restored(self):
        self.assertTrue((self.worktree / ".git").is_file())
        self.assertFalse((self.worktree / GIT_POINTER_BACKUP).exists())
        self.assertEqual(_git(self.worktree, "rev-parse", "--abbrev-ref", "HEAD"), "fix/hooks")

    def test_a_read_only_directory_the_build_wrote_is_removed(self):
        with git_directory_for_build(self.worktree) as record:
            self.assertTrue(record["applied"])
            hooks = self.worktree / ".git" / "hooks"
            hooks.mkdir()
            (hooks / "pre-commit").write_text("hook\n", encoding="utf-8")
            hooks.chmod(0o555)
        self._assert_worktree_restored()

    def test_a_shim_that_cannot_be_deleted_still_gives_the_pointer_back(self):
        gitdir = Path(_git(self.worktree, "rev-parse", "--absolute-git-dir"))
        # Nothing inside can be removed: the directory is moved aside first.
        with mock.patch.object(git_directory, "_remove_tree"):
            with git_directory_for_build(self.worktree):
                (self.worktree / ".git" / "hooks").mkdir()
        self._assert_worktree_restored()
        self.assertEqual(len(list(gitdir.glob(f"{git_directory.SHIM_LEFTOVER_PREFIX}*"))), 1)

    def test_a_restore_that_cannot_finish_keeps_the_backup_for_the_next_build(self):
        with mock.patch.object(git_directory, "_remove_tree"), \
                mock.patch.object(git_directory.os, "replace", side_effect=OSError("busy")):
            with git_directory_for_build(self.worktree):
                (self.worktree / ".git" / "hooks").mkdir()
        # The pointer used to be copied into the leftover directory and its
        # only copy deleted.
        self.assertTrue((self.worktree / ".git").is_dir())
        self.assertTrue((self.worktree / GIT_POINTER_BACKUP).is_file())
        with git_directory_for_build(self.worktree) as record:
            self.assertTrue(record["applied"])
        self._assert_worktree_restored()

    def test_a_test_build_writing_git_hooks_succeeds_and_the_worktree_is_restored(self):
        result = self._build(
            "mkdir -p .git/hooks && echo hook > .git/hooks/pre-commit || exit 1\n"
            "cat .git/HEAD\n"
            'echo "BUILD SUCCESSFUL in 1s"\n')
        self.assertEqual(result.return_code, 0, Path(result.log_file).read_text())
        self.assertEqual(result.git_directory_shim, {
            "applied": True, "build_scripts_reading_git": ["app/build.gradle.kts"],
        })
        self.assertTrue((self.worktree / ".git").is_file())
        self.assertEqual(_git(self.worktree, "rev-parse", "--abbrev-ref", "HEAD"), "fix/hooks")
        self.assertFalse((self.worktree / ".git.worktree-pointer.bak").exists())
        log = Path(result.log_file).read_text(encoding="utf-8")
        self.assertIn("building with a temporary .git directory", log)
        self.assertIn("ref: refs/heads/fix/hooks", log)

    def test_the_worktree_is_restored_when_the_build_fails(self):
        result = self._build("echo 'BUILD FAILED in 1s'\nexit 1\n")
        self.assertEqual(result.status, "failed")
        self.assertTrue((self.worktree / ".git").is_file())
        # Git recognises the worktree again (it raises otherwise).
        self.assertIn("gradlew", _git(self.worktree, "status", "--porcelain"))

    def test_a_project_whose_scripts_never_name_git_is_left_alone(self):
        (self.worktree / "app" / "build.gradle.kts").write_text("android {}\n", encoding="utf-8")
        result = self._build('test -f .git || exit 1\necho "BUILD SUCCESSFUL in 1s"\n')
        self.assertEqual(result.return_code, 0)
        self.assertIsNone(result.git_directory_shim)
        with git_directory_for_build(self.worktree) as record:
            self.assertIsNone(record)


if __name__ == "__main__":
    unittest.main()
