import contextlib
import io
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils import repository_lock as lock  # noqa: E402


def _leave_lock(root: Path, pid: int, host: str | None = None) -> Path:
    path = root / "outputs" / ".repository_usage.lock"
    path.mkdir(parents=True)
    (path / "owner.json").write_text(json.dumps({
        "pid": pid, "host": host or socket.gethostname(), "started_at": "2026-10-12T00:00:00"}),
        encoding="utf-8")
    return path


class StaleLockTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_a_dead_owners_lock_is_taken_over_when_nothing_else_runs(self):
        _leave_lock(self.root, pid=999999)
        with patch.object(lock, "_pid_alive", return_value=False), \
                patch.object(lock, "_repository_users", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            with lock.RepositoryUsageLock(self.root) as held:
                owner = json.loads((held.path / "owner.json").read_text(encoding="utf-8"))
                self.assertEqual(owner["pid"], os.getpid())
        self.assertIn("stale repository lock", out.getvalue())

    @unittest.skipUnless(Path("/proc").is_dir(), "reads /proc")
    def test_the_processes_that_started_this_run_are_not_its_users(self):
        """A run started from tmux: the server's command line says "cognalys run"."""
        ancestors = lock._ancestors(os.getpid())
        self.assertIn(os.getpid(), ancestors)
        self.assertIn(os.getppid(), ancestors)
        with patch.object(lock, "_ancestors", return_value={os.getpid(), 4242}), \
                patch.object(lock.Path, "iterdir", return_value=[Path("/proc/4242")]), \
                patch.object(lock.Path, "read_bytes", return_value=b"tmux\0new-session\0cognalys run x"):
            self.assertEqual(lock._repository_users(exclude=os.getpid()), [])

    def test_a_running_step_keeps_the_lock(self):
        _leave_lock(self.root, pid=999999)
        with patch.object(lock, "_pid_alive", return_value=False), \
                patch.object(lock, "_repository_users",
                             return_value=["4242 python -m cognalys.validation.applied_solutions"]):
            with self.assertRaises(lock.RepositoryBusyError) as raised:
                lock.RepositoryUsageLock(self.root).__enter__()
        self.assertIn("applied_solutions", str(raised.exception))

    def test_a_live_owner_keeps_the_lock(self):
        _leave_lock(self.root, pid=os.getpid())
        with patch.object(lock, "_repository_users", return_value=[]):
            with self.assertRaises(lock.RepositoryBusyError):
                lock.RepositoryUsageLock(self.root).__enter__()

    def test_a_lock_from_another_host_is_never_touched(self):
        """Windows and WSL report different hostnames for their processes."""
        path = _leave_lock(self.root, pid=999999, host="some-other-host")
        with patch.object(lock, "_pid_alive", return_value=False), \
                patch.object(lock, "_repository_users", return_value=[]):
            with self.assertRaises(lock.RepositoryBusyError):
                lock.RepositoryUsageLock(self.root).__enter__()
        self.assertTrue((path / "owner.json").exists())

    def test_a_pid_reused_after_a_restart_does_not_keep_the_lock(self):
        """WSL is shut down after every queue and numbers PIDs from 1 again."""
        for label, fields in (
                ("another boot", {"boot_id": "boot-before-restart"}),
                ("another process", {"start_ticks": "1"})):
            with self.subTest(label):
                path = _leave_lock(self.root, pid=os.getpid())
                owner = json.loads((path / "owner.json").read_text(encoding="utf-8"))
                owner.update(fields)
                (path / "owner.json").write_text(json.dumps(owner), encoding="utf-8")
                with patch.object(lock, "_boot_id", return_value="boot-now"), \
                        patch.object(lock, "_start_ticks", return_value="777"), \
                        patch.object(lock, "_repository_users", return_value=[]):
                    self.assertIn("no longer runs", lock.stale_lock_reason(path))
                (path / "owner.json").unlink()
                path.rmdir()

    def test_the_lock_records_its_boot_and_start_time(self):
        with patch.object(lock, "_boot_id", return_value="boot-now"), \
                patch.object(lock, "_start_ticks", return_value="777"):
            with lock.RepositoryUsageLock(self.root) as held:
                owner = json.loads((held.path / "owner.json").read_text(encoding="utf-8"))
                with patch.object(lock, "_repository_users", return_value=[]):
                    # Its own lock, same boot and start time: alive.
                    self.assertEqual(lock.stale_lock_reason(held.path), "")
        self.assertEqual((owner["boot_id"], owner["start_ticks"]), ("boot-now", "777"))

    def test_an_unreadable_owner_is_never_touched(self):
        path = self.root / "outputs" / ".repository_usage.lock"
        path.mkdir(parents=True)
        self.assertEqual(lock.stale_lock_reason(path), "")


if __name__ == "__main__":
    unittest.main()
