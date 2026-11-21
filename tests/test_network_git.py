import io
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from cognalys.builds import apk_build
from cognalys.extraction import extract_methods_single_csv as extraction
from cognalys.prs import pr_creator
from cognalys.utils import network_git
from cognalys.utils.network_git import (
    clone_destination,
    network_git_env,
    network_subcommand,
    run_git_command,
    run_network_git,
)

REAL_GIT = shutil.which("git")


def _fake_git(directory: Path, body: str) -> Path:
    """A `git` on PATH that runs `body` for network commands, real git otherwise.

    Each call is appended to $FAKE_GIT_CALLS.
    """
    bin_dir = directory / "bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / "git"
    script.write_text(
        "#!/bin/sh\n"
        'echo "$*" >> "$FAKE_GIT_CALLS"\n'
        'case " $* " in\n'
        f'  *" submodule update "*|*" fetch "*|*" clone "*|*" push "*) {body} ;;\n'
        "esac\n"
        f'exec "{REAL_GIT}" "$@"\n',
        encoding="utf-8",
    )
    script.chmod(0o755)
    return bin_dir


class NetworkSubcommandTests(unittest.TestCase):
    def test_network_commands_are_recognised_past_global_options(self):
        self.assertEqual(network_subcommand(["git", "-C", "/r", "fetch", "origin"]), "fetch")
        self.assertEqual(network_subcommand(
            ["git", "-c", "core.autocrlf=false", "clone", "--depth", "1", "u", "d"]), "clone")
        self.assertEqual(network_subcommand(["git", "ls-remote", "u"]), "ls-remote")
        self.assertEqual(network_subcommand(["git", "push", "origin", "b"]), "push")
        self.assertEqual(network_subcommand(
            ["git", "submodule", "update", "--init", "--recursive"]), "submodule")

    def test_local_commands_are_not(self):
        for command in (["git", "status"], ["git", "-C", "/r", "rev-parse", "HEAD"],
                        ["git", "submodule", "sync", "--recursive"],
                        ["gradlew", "fetch"], []):
            with self.subTest(command=command):
                self.assertIsNone(network_subcommand(command))

    def test_the_environment_carries_the_low_speed_limit(self):
        env = network_git_env({"PATH": "/bin"})
        self.assertEqual(env["GIT_HTTP_LOW_SPEED_LIMIT"], "1000")
        self.assertEqual(env["GIT_HTTP_LOW_SPEED_TIME"], "60")
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(env["PATH"], "/bin")
        # An operator's own setting is kept.
        self.assertEqual(
            network_git_env({"GIT_HTTP_LOW_SPEED_TIME": "300"})["GIT_HTTP_LOW_SPEED_TIME"],
            "300",
        )


@unittest.skipIf(sys.platform.startswith("win") or not REAL_GIT, "needs a POSIX shell and git")
class BoundedNetworkGitTests(unittest.TestCase):
    """AntennaPod (2026-10-29): `git fetch origin <sha>` of a submodule sat on
    a connection the standby had killed for over an hour."""

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)
        self.calls = self.directory / "calls.txt"

    def _environment(self, body: str):
        bin_dir = _fake_git(self.directory, body)
        return mock.patch.dict(os.environ, {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "FAKE_GIT_CALLS": str(self.calls),
        })

    def _calls(self) -> list[str]:
        try:
            return self.calls.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []

    def test_a_hung_fetch_times_out_is_retried_once_and_then_raises(self):
        with self._environment("exec sleep 30"):
            started = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                run_network_git(["git", "fetch", "origin", "abc"], 1,
                                capture_output=True, text=True)
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual(len(self._calls()), 2)

    def test_a_caller_reading_return_codes_gets_124(self):
        log = io.StringIO()
        with self._environment("exec sleep 30"):
            completed = run_git_command(["git", "fetch", "origin"], timeout=1,
                                        capture_output=True, text=True)
            run_network_git(["git", "fetch", "origin"], 1, retries=0, log=log,
                            raise_on_timeout=False, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 124)
        self.assertIn("timed out", completed.stderr)
        self.assertIn("timed out after 1s", log.getvalue())

    def test_a_stalled_transfer_is_retried_and_a_refusal_is_not(self):
        with self._environment(
                "echo 'error: RPC failed; curl 28 Operation too slow.' >&2; exit 128"):
            stalled = run_network_git(["git", "fetch", "origin"], 10,
                                      capture_output=True, text=True)
        self.assertEqual(stalled.returncode, 128)
        self.assertEqual(len(self._calls()), 2)
        self.calls.unlink()
        with self._environment("echo 'fatal: repository not found' >&2; exit 128"):
            refused = run_network_git(["git", "fetch", "origin"], 10,
                                      capture_output=True, text=True)
        self.assertEqual(refused.returncode, 128)
        self.assertEqual(len(self._calls()), 1)

    def test_the_command_sees_the_bounds_in_its_environment(self):
        with self._environment('echo "$GIT_HTTP_LOW_SPEED_LIMIT/$GIT_HTTP_LOW_SPEED_TIME"; exit 0'):
            completed = run_network_git(["git", "fetch", "origin"], 10,
                                        capture_output=True, text=True)
        self.assertEqual(completed.stdout.strip(), "1000/60")

    def test_a_local_command_runs_unchanged(self):
        with self._environment("exec sleep 30"):
            completed = run_git_command(["git", "--version"], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0)
        self.assertIn("git version", completed.stdout)

    def test_the_publishing_push_is_bounded(self):
        creator = pr_creator.AutomatedPRCreator.__new__(pr_creator.AutomatedPRCreator)
        creator.github_token = "token"
        with self._environment("exec sleep 30"), \
                mock.patch.dict(network_git.NETWORK_GIT_TIMEOUTS, {"push": 1}), \
                mock.patch("builtins.print"):
            started = time.monotonic()
            with self.assertRaises(RuntimeError) as raised:
                creator.push_branch(self.directory, "fix/tls")
        self.assertLess(time.monotonic() - started, 15)
        self.assertIn("git push timed out after 1s", str(raised.exception))
        self.assertNotIn("token", str(raised.exception))
        self.assertEqual(sum("push" in line for line in self._calls()), 2)

    def _source_repository(self) -> Path:
        source = self.directory / "source"
        source.mkdir()
        for command in (["init", "-q"], ["config", "user.email", "t@t"],
                        ["config", "user.name", "t"], ["commit", "-q", "--allow-empty", "-m", "i"]):
            subprocess.run([REAL_GIT, "-C", str(source), *command], check=True, capture_output=True)
        return source

    def _hung_clone(self, destination: Path, log) -> subprocess.CompletedProcess:
        # The server never answers: git has created the destination and waits.
        return run_network_git(
            ["git", "clone", "--upload-pack=sleep 30; git-upload-pack",
             f"file://{self._source_repository()}", str(destination)],
            2, raise_on_timeout=False, log=log, capture_output=True, text=True,
        )

    def test_a_clone_that_timed_out_leaves_no_partial_destination(self):
        destination = self.directory / "clone"
        log = io.StringIO()
        completed = self._hung_clone(destination, log)
        self.assertEqual(completed.returncode, 124, completed.stderr)
        self.assertIn("timed out", completed.stderr)
        self.assertIn("(attempt 1/2); retrying.", log.getvalue())
        self.assertIn("(attempt 2/2).", log.getvalue())
        self.assertFalse(destination.exists())

    def test_a_clone_into_a_directory_it_did_not_create_is_not_retried(self):
        destination = self.directory / "clone"
        destination.mkdir()
        log = io.StringIO()
        completed = self._hung_clone(destination, log)
        self.assertEqual(completed.returncode, 124, completed.stderr)
        self.assertNotIn("retrying", log.getvalue())
        self.assertTrue(destination.is_dir())


class CloneDestinationTests(unittest.TestCase):
    def test_the_directory_argument_or_git_default(self):
        self.assertEqual(clone_destination(
            ["git", "clone", "--depth", "1", "-b", "main", "https://h/o/r.git", "/w/dst"]), "/w/dst")
        self.assertEqual(clone_destination(
            ["git", "-c", "x=y", "clone", "https://h/o/repo.git"], cwd="/w"), "/w/repo")
        self.assertEqual(clone_destination(["git", "clone", "git@h:o/repo"], cwd="/w"), "/w/repo")
        self.assertEqual(clone_destination(
            ["git", "clone", "--filter=blob:none", "u/r", "d"], cwd="/w"), "/w/d")
        self.assertIsNone(clone_destination(["git", "fetch", "origin"]))
        self.assertIsNone(clone_destination(["git", "clone", "u", "."]))


@unittest.skipIf(sys.platform.startswith("win") or not REAL_GIT, "needs a POSIX shell and git")
class HungSubmoduleUpdateTests(unittest.TestCase):
    """A submodule update that never ends is stopped, and the step goes on."""

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)
        self.calls = self.directory / "calls.txt"
        self.repo = self.directory / "repo"
        self.repo.mkdir()
        for command in (["init", "-q"], ["config", "user.email", "t@t"],
                        ["config", "user.name", "t"]):
            subprocess.run([REAL_GIT, "-C", str(self.repo), *command],
                           check=True, capture_output=True)
        (self.repo / ".gitmodules").write_text(
            '[submodule "store-metadata"]\n'
            "\tpath = store-metadata\n"
            "\turl = https://example.invalid/StoreMetadata.git\n",
            encoding="utf-8",
        )
        (self.repo / "settings.gradle").write_text("include ':app'\n", encoding="utf-8")
        (self.repo / "app").mkdir()
        (self.repo / "app" / "build.gradle").write_text("android {}\n", encoding="utf-8")
        (self.repo / "store-metadata").mkdir()
        # The gitlink a real superproject records for its submodule.
        subprocess.run(
            [REAL_GIT, "-C", str(self.repo), "update-index", "--add", "--cacheinfo",
             f"160000,{'1' * 40},store-metadata"],
            check=True, capture_output=True,
        )

    def _environment(self):
        bin_dir = _fake_git(self.directory, "exec sleep 30")
        return mock.patch.dict(os.environ, {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "FAKE_GIT_CALLS": str(self.calls),
        })

    def _updates(self) -> int:
        try:
            lines = self.calls.read_text(encoding="utf-8").splitlines()
        except OSError:
            return 0
        return sum("submodule update" in line for line in lines)

    def test_extraction_continues_without_the_submodule(self):
        logger = logging.getLogger("test_network_git.extraction")
        with self._environment(), \
                mock.patch.object(extraction, "SUBMODULE_TIMEOUT_SECONDS", 1), \
                self.assertLogs(logger, level="WARNING") as logged:
            started = time.monotonic()
            populated = extraction.populate_empty_submodules(self.repo, logger)
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual(populated, [])
        self.assertEqual(self._updates(), 2)
        self.assertTrue(any("continuing without submodule(s) store-metadata" in line
                            for line in logged.output))

    def _initialize(self):
        # A real file: the build step hands it to git as stdout.
        with tempfile.TemporaryFile("w+", encoding="utf-8") as log, self._environment():
            failure, _ = apk_build.initialize_submodules(
                self.repo, log, 1, self.directory / "recovery")
            log.seek(0)
            return failure, log.read()

    def test_the_build_goes_on_without_a_submodule_no_build_file_uses(self):
        failure, log = self._initialize()
        self.assertIsNone(failure)
        self.assertIn("no build file uses store-metadata; continuing without it", log)
        self.assertIn("timed out after 1s", log)

    def test_a_submodule_the_build_names_still_fails_the_setup(self):
        (self.repo / "settings.gradle").write_text(
            "include ':app'\nincludeBuild('store-metadata')\n", encoding="utf-8")
        failure, _ = self._initialize()
        self.assertEqual(failure, "submodule_initialization_timeout_after_1s")


class SubmoduleUseTests(unittest.TestCase):
    def _project(self, directory: str) -> Path:
        root = Path(directory)
        (root / "app" / "src" / "main").mkdir(parents=True)
        (root / "settings.gradle").write_text("include ':app'\n", encoding="utf-8")
        (root / "app" / "build.gradle").write_text("android {}\n", encoding="utf-8")
        return root

    def test_a_top_level_submodule_no_build_file_names_is_unused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._project(directory)
            self.assertFalse(apk_build.submodule_used_by_build(root, root / "store-metadata"))

    def test_a_submodule_inside_a_module_or_named_by_a_build_file_is_used(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._project(directory)
            self.assertTrue(apk_build.submodule_used_by_build(
                root, root / "app" / "src" / "main" / "cpp" / "libsodium"))
            (root / "app" / "build.gradle").write_text(
                "android { sourceSets { main { java.srcDirs += '../shared-crypto/src' } } }\n",
                encoding="utf-8")
            self.assertTrue(apk_build.submodule_used_by_build(root, root / "shared-crypto"))
            # A name that only shares a prefix is not a reference.
            self.assertFalse(apk_build.submodule_used_by_build(root, root / "shared"))

    def test_a_submodule_reached_through_a_nested_native_build_file_is_used(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._project(directory)
            (root / "app" / "build.gradle").write_text(
                "android { externalNativeBuild { cmake { path 'src/main/cpp/CMakeLists.txt' } } }\n",
                encoding="utf-8")
            cpp = root / "app" / "src" / "main" / "cpp"
            cpp.mkdir()
            (cpp / "CMakeLists.txt").write_text(
                "add_subdirectory(${CMAKE_SOURCE_DIR}/../../../../third_party/opus opus)\n",
                encoding="utf-8")
            (root / "third_party" / "opus").mkdir(parents=True)
            self.assertTrue(apk_build.submodule_used_by_build(root, root / "third_party" / "opus"))
            # Its own build files, and build outputs, are no reference.
            (cpp / "CMakeLists.txt").write_text("add_library(native SHARED a.c)\n", encoding="utf-8")
            (root / "third_party" / "opus" / "CMakeLists.txt").write_text(
                "project(opus)\n", encoding="utf-8")
            (root / "app" / "build" / "intermediates").mkdir(parents=True)
            (root / "app" / "build" / "intermediates" / "CMakeLists.txt").write_text(
                "add_subdirectory(third_party/opus)\n", encoding="utf-8")
            self.assertFalse(apk_build.submodule_used_by_build(root, root / "third_party" / "opus"))

    def test_a_submodule_outside_the_gradle_root_counts_as_used(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._project(directory)
            self.assertTrue(apk_build.submodule_used_by_build(root / "app", root / "lib"))


class DefaultTimeoutTests(unittest.TestCase):
    def test_each_operation_has_a_limit_proportionate_to_it(self):
        self.assertLess(network_git.network_git_timeout(["git", "ls-remote", "u"]),
                        network_git.network_git_timeout(["git", "fetch", "origin"]))
        self.assertLess(network_git.network_git_timeout(["git", "fetch", "origin"]),
                        network_git.network_git_timeout(["git", "clone", "u", "d"]))


if __name__ == "__main__":
    unittest.main()
