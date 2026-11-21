import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (scripts/ and src/ on sys.path)


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "cognalys" / "builds" / "apk_build.py"
SPEC = importlib.util.spec_from_file_location("builds.apk_build", MODULE_PATH)
build_apks_no_proguard = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = build_apks_no_proguard
SPEC.loader.exec_module(build_apks_no_proguard)


class SubmoduleRecoveryTests(unittest.TestCase):
    def test_quarantines_only_declared_submodule_with_binary_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "checkout"
            root.mkdir()
            (root / ".gitmodules").write_text(
                '[submodule "cert4android"]\n'
                '\tpath = cert4android\n'
                '\turl = https://example.invalid/cert4android.git\n',
                encoding="utf-8",
            )
            checkout = root / "cert4android"
            checkout.mkdir()
            (checkout / "local-marker").write_text("preserve", encoding="utf-8")

            git_dir = Path(directory) / "git" / "worktrees" / "finding"
            config = git_dir / "modules" / "cert4android" / "config"
            config.parent.mkdir(parents=True)
            config.write_bytes(b"\0" * 64)
            recovery_root = Path(directory) / "recovery"

            with patch.object(
                build_apks_no_proguard, "worktree_git_dir", return_value=git_dir
            ):
                recovered = build_apks_no_proguard.recover_corrupt_submodules(
                    root, recovery_root, io.StringIO()
                )

            self.assertEqual(recovered, ["cert4android"])
            self.assertFalse(config.exists())
            self.assertFalse(checkout.exists())
            backups = list(recovery_root.rglob("git_metadata/config"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), b"\0" * 64)
            self.assertEqual(
                (backups[0].parent.parent / "checkout" / "local-marker").read_text(
                    encoding="utf-8"
                ),
                "preserve",
            )

    def test_ignores_non_binary_submodule_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "checkout"
            root.mkdir()
            git_dir = Path(directory) / "git" / "worktrees" / "finding"
            config = git_dir / "modules" / "cert4android" / "config"
            config.parent.mkdir(parents=True)
            config.write_text("[core]\nrepositoryformatversion = 0\n", encoding="utf-8")

            with patch.object(
                build_apks_no_proguard, "worktree_git_dir", return_value=git_dir
            ):
                corrupt = build_apks_no_proguard.corrupt_submodule_configs(root)

            self.assertEqual(corrupt, [])

    def test_skips_submodule_setup_when_project_declares_none(self):
        with tempfile.TemporaryDirectory() as directory:
            result = build_apks_no_proguard.initialize_submodules(
                Path(directory), io.StringIO(), 10, Path(directory) / "recovery"
            )

        self.assertEqual(result, (None, []))

    def test_a_forced_update_overwrites_a_dirty_submodule(self):
        """fdroid-build resets a reused checkout by force; its submodules too."""
        commands = []
        with patch.object(build_apks_no_proguard.subprocess, "run",
                          side_effect=lambda command, **kwargs: commands.append(command)
                          or subprocess.CompletedProcess(command, 0)):
            self.assertIsNone(build_apks_no_proguard.run_submodule_commands(
                Path("."), io.StringIO(), 10, force=True))
            build_apks_no_proguard.run_submodule_commands(Path("."), io.StringIO(), 10)
        self.assertEqual(commands[1][-1], "--force")
        self.assertNotIn("--force", commands[3])


class DeadSubmoduleProtocolTests(unittest.TestCase):
    """git:// submodule urls can no longer connect from anywhere.

    GitHub disabled the unauthenticated protocol in 2022, so an older
    repository declaring one times out rather than failing fast and the
    build is recorded as an infrastructure failure with a bare git exit
    code. Two of the four cloned projects that declare submodules carry one.

    The rewrite has to travel in the environment. `git submodule update`
    clones each submodule with a child `git clone`, and a clone creating a
    new repository reads only system and global config -- never the
    superproject's `--local` -- so an insteadOf set there is silently
    ignored. Verified on git 2.43: the same clone that fails with the local
    config succeeds with GIT_CONFIG_COUNT.
    """

    GITMODULES = (
        '[submodule "a"]\n'
        '\tpath = external-libs/a\n'
        '\turl = https://github.com/ge0rg/MemorizingTrustManager.git\n'
        '[submodule "b"]\n'
        '\tpath = external-libs/b\n'
        '\turl = git://github.com/JakeWharton/ActionBarSherlock.git\n'
    )

    def _root(self, directory, content=None):
        root = Path(directory) / "checkout"
        root.mkdir()
        (root / ".gitmodules").write_text(
            self.GITMODULES if content is None else content, encoding="utf-8"
        )
        return root

    def test_every_declared_url_is_read_in_file_order(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                build_apks_no_proguard.declared_submodule_urls(
                    self._root(directory)
                ),
                [
                    "https://github.com/ge0rg/MemorizingTrustManager.git",
                    "git://github.com/JakeWharton/ActionBarSherlock.git",
                ],
            )

    def test_a_repository_without_submodules_declares_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "checkout"
            root.mkdir()
            self.assertEqual(
                build_apks_no_proguard.declared_submodule_urls(root), []
            )

    def test_the_rewrite_is_passed_to_children_through_the_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory)
            log = io.StringIO()
            dead, env = (
                build_apks_no_proguard.rewrite_dead_submodule_protocols(
                    root, log
                )
            )
            self.assertEqual(
                dead, ["git://github.com/JakeWharton/ActionBarSherlock.git"]
            )
            self.assertEqual(env["GIT_CONFIG_COUNT"], "1")
            self.assertEqual(
                env["GIT_CONFIG_KEY_0"], "url.https://.insteadOf"
            )
            self.assertEqual(env["GIT_CONFIG_VALUE_0"], "git://")
            self.assertIn("git://", log.getvalue())

    def test_an_existing_environment_config_is_extended_not_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory)
            existing = {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.pager",
                "GIT_CONFIG_VALUE_0": "cat",
            }
            with patch.dict(build_apks_no_proguard.os.environ, existing):
                _, env = (
                    build_apks_no_proguard.rewrite_dead_submodule_protocols(
                        root, io.StringIO()
                    )
                )
            self.assertEqual(env["GIT_CONFIG_COUNT"], "2")
            self.assertEqual(env["GIT_CONFIG_KEY_0"], "core.pager")
            self.assertEqual(
                env["GIT_CONFIG_KEY_1"], "url.https://.insteadOf"
            )

    def test_nothing_is_configured_when_no_url_is_dead(self):
        content = (
            '[submodule "a"]\n\tpath = a\n'
            '\turl = https://github.com/ge0rg/MemorizingTrustManager.git\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory, content)
            log = io.StringIO()
            dead, env = (
                build_apks_no_proguard.rewrite_dead_submodule_protocols(
                    root, log
                )
            )
            self.assertEqual(dead, [])
            self.assertIsNone(env)
            self.assertEqual(log.getvalue(), "")


class SshSubmoduleUrlTests(unittest.TestCase):
    """TagMo's amiitool submodule, reproduced (run_20260927_175748).

    Its .gitmodules names 'git@github.com:8bitDream/amiitool.git'. This
    sandbox has no SSH key or known_hosts entry configured for any host, so
    the clone fails immediately with "Host key verification failed" -- not a
    network timeout, and not fixed by retrying. https reaches the same public
    repository.
    """

    GITMODULES = (
        '[submodule "amiitool"]\n'
        '\tpath = app/libs/amiitool\n'
        '\turl = git@github.com:8bitDream/amiitool.git\n'
    )

    def _root(self, directory, content=None):
        root = Path(directory) / "checkout"
        root.mkdir()
        (root / ".gitmodules").write_text(
            self.GITMODULES if content is None else content, encoding="utf-8"
        )
        return root

    def test_the_scp_style_ssh_url_is_routed_over_https(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory)
            log = io.StringIO()
            dead, env = (
                build_apks_no_proguard.rewrite_dead_submodule_protocols(
                    root, log
                )
            )
            self.assertEqual(
                dead, ["git@github.com:8bitDream/amiitool.git"]
            )
            self.assertEqual(env["GIT_CONFIG_COUNT"], "1")
            self.assertEqual(
                env["GIT_CONFIG_KEY_0"], "url.https://github.com/.insteadOf"
            )
            self.assertEqual(env["GIT_CONFIG_VALUE_0"], "git@github.com:")
            self.assertIn("git@github.com:8bitDream/amiitool.git", log.getvalue())

    def test_the_explicit_ssh_scheme_form_is_also_routed(self):
        content = (
            '[submodule "amiitool"]\n\tpath = app/libs/amiitool\n'
            '\turl = ssh://git@github.com/8bitDream/amiitool.git\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory, content)
            dead, env = (
                build_apks_no_proguard.rewrite_dead_submodule_protocols(
                    root, io.StringIO()
                )
            )
            self.assertEqual(
                dead, ["ssh://git@github.com/8bitDream/amiitool.git"]
            )
            self.assertEqual(
                env["GIT_CONFIG_KEY_0"], "url.https://github.com/.insteadOf"
            )
            self.assertEqual(
                env["GIT_CONFIG_VALUE_0"], "ssh://git@github.com/"
            )

    def test_a_git_protocol_url_and_an_ssh_url_together_each_get_one_rule(self):
        content = (
            '[submodule "a"]\n\tpath = a\n'
            '\turl = git://github.com/JakeWharton/ActionBarSherlock.git\n'
            '[submodule "b"]\n\tpath = b\n'
            '\turl = git@github.com:8bitDream/amiitool.git\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory, content)
            dead, env = (
                build_apks_no_proguard.rewrite_dead_submodule_protocols(
                    root, io.StringIO()
                )
            )
            # File order is preserved even though the rules are keyed
            # differently.
            self.assertEqual(dead, [
                "git://github.com/JakeWharton/ActionBarSherlock.git",
                "git@github.com:8bitDream/amiitool.git",
            ])
            self.assertEqual(env["GIT_CONFIG_COUNT"], "2")
            self.assertEqual(env["GIT_CONFIG_KEY_0"], "url.https://.insteadOf")
            self.assertEqual(env["GIT_CONFIG_VALUE_0"], "git://")
            self.assertEqual(
                env["GIT_CONFIG_KEY_1"], "url.https://github.com/.insteadOf"
            )
            self.assertEqual(env["GIT_CONFIG_VALUE_1"], "git@github.com:")

    def test_two_ssh_submodules_share_the_single_rule(self):
        content = (
            '[submodule "a"]\n\tpath = a\n'
            '\turl = git@github.com:owner/one.git\n'
            '[submodule "b"]\n\tpath = b\n'
            '\turl = git@github.com:owner/two.git\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory, content)
            dead, env = (
                build_apks_no_proguard.rewrite_dead_submodule_protocols(
                    root, io.StringIO()
                )
            )
            self.assertEqual(
                dead, ["git@github.com:owner/one.git", "git@github.com:owner/two.git"]
            )
            self.assertEqual(env["GIT_CONFIG_COUNT"], "1")


class UnbuildableRecordTests(unittest.TestCase):
    """A server that answered "not found" will answer it again.

    gtalksms's build spent 276 seconds per run waiting out two connection
    timeouts and then failing, every run, for a submodule url that is not a
    repository. Recording the definitive answer spares every later run the
    attempt. A failure that only says this machine could not reach the
    server is never recorded: blacklisting a project over a network blip is
    the expensive mistake.
    """

    def _repo(self, directory):
        root = Path(directory) / "repo"
        root.mkdir()
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        return root

    def test_a_definitive_server_rejection_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text(
                "Cloning into 'external-libs/ActionBarSherlock'...\n"
                "remote: Not Found\n"
                "fatal: repository 'https://github.com/x/y.git/z/' not "
                "found\n",
                encoding="utf-8",
            )
            self.assertEqual(
                build_apks_no_proguard.nonrecoverable_submodule_reason(log),
                "not_found",
            )

    def test_a_missing_pinned_ref_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text(
                "fatal: remote error: upload-pack: not our ref b834a930\n",
                encoding="utf-8",
            )
            self.assertEqual(
                build_apks_no_proguard.nonrecoverable_submodule_reason(log),
                "not_our_ref",
            )

    def test_a_transient_failure_is_never_recorded(self):
        for text in (
            "fatal: unable to connect to github.com: errno=Connection timed out",
            "fatal: could not resolve host: github.com",
            "fatal: unable to access 'https://github.com/x/y.git/'",
        ):
            with self.subTest(text=text):
                with tempfile.TemporaryDirectory() as directory:
                    log = Path(directory) / "build.log"
                    log.write_text(text, encoding="utf-8")
                    self.assertEqual(
                        build_apks_no_proguard
                        .nonrecoverable_submodule_reason(log),
                        "",
                    )

    def test_a_definitive_answer_beside_a_timeout_is_not_recorded(self):
        # The run cannot tell which of the two decided the outcome.
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.log"
            log.write_text(
                "fatal: repository not found\n"
                "fatal: unable to connect: errno=Connection timed out\n",
                encoding="utf-8",
            )
            self.assertEqual(
                build_apks_no_proguard.nonrecoverable_submodule_reason(log),
                "",
            )

    def test_the_record_survives_into_worktrees_of_the_same_clone(self):
        # Validation builds in a finding worktree, not in the clone, so the
        # record has to live where both see it.
        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory)
            (root / "f.txt").write_text("x", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(root), "-c", "user.email=t@t",
                 "-c", "user.name=t", "commit", "-qm", "c"], check=True,
            )
            build_apks_no_proguard.record_unbuildable(
                root, "not_found", "submodule url is not a repository"
            )
            worktree = Path(directory) / "wt"
            subprocess.run(
                ["git", "-C", str(root), "worktree", "add", "-q", "--detach",
                 str(worktree)], check=True,
            )
            self.assertEqual(
                build_apks_no_proguard.recorded_unbuildable_reason(worktree),
                "submodule url is not a repository",
            )

    def test_a_checkout_with_no_record_reports_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repo(directory)
            self.assertEqual(
                build_apks_no_proguard.recorded_unbuildable_reason(root), ""
            )


if __name__ == "__main__":
    unittest.main()
