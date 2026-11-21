"""A step that stops making progress is ended, children included.

run_pipeline used to wait on each step with a bare subprocess.run, so a step
that hung without any of its own timeouts firing held the whole run open.
These tests run real processes: a mocked Popen would not show that the
grandchild -- the Gradle daemon or JVM a step starts -- is ended too.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils.process_tree import (  # noqa: E402
    STEP_TIMEOUT_EXIT_CODE, run_with_deadline,
)


# Starts a grandchild that writes its pid and then sleeps, and sleeps itself.
PARENT = """
import subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
open(sys.argv[1], "w").write(str(child.pid))
time.sleep(60)
"""


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie still answers kill(0); it is gone for every practical purpose.
    try:
        state = Path(f"/proc/{pid}/stat").read_text().split()[2]
        return state != "Z"
    except OSError:
        return True


class DeadlineTests(unittest.TestCase):

    def test_a_step_that_finishes_keeps_its_exit_code(self):
        result = run_with_deadline(
            [sys.executable, "-c", "raise SystemExit(3)"], timeout_seconds=30,
        )
        self.assertEqual(result, {"returncode": 3, "timed_out": False})

    def test_no_deadline_waits_for_the_step(self):
        result = run_with_deadline(
            [sys.executable, "-c", "import time; time.sleep(0.2)"],
            timeout_seconds=0,
        )
        self.assertFalse(result["timed_out"])

    @unittest.skipIf(os.name == "nt", "process-group checks use POSIX signals")
    def test_a_hung_step_is_ended_with_its_children(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "child.pid"
            started = time.monotonic()
            result = run_with_deadline(
                [sys.executable, "-c", PARENT, str(pid_file)],
                timeout_seconds=1.5, grace=2,
            )
            elapsed = time.monotonic() - started
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["returncode"], STEP_TIMEOUT_EXIT_CODE)
            self.assertLess(elapsed, 15)
            child = int(pid_file.read_text())
            for _ in range(20):
                if not _alive(child):
                    break
                time.sleep(0.1)
            self.assertFalse(_alive(child), "the grandchild survived the step")


class SuspendedMachineTests(unittest.TestCase):
    """Standby is not a stall.

    SMSecure's getKeyFromPassphrase (rvsec_misuse_20261016/run_v2): the
    laptop slept from 08:21 to 09:58 with a model call in flight, and the
    wall clock's 97 minutes ended the llm step the moment it woke.
    """

    def _clock_that_jumps(self, after_calls: int, seconds: float):
        from unittest.mock import patch
        import cognalys.utils.process_tree as process_tree

        real = time.time
        calls = {"count": 0}

        def clock():
            calls["count"] += 1
            return real() + (seconds if calls["count"] > after_calls else 0)

        return patch.object(process_tree.time, "time", side_effect=clock)

    def test_a_suspension_is_not_counted_as_idleness(self):
        with tempfile.TemporaryDirectory() as directory, \
                self._clock_that_jumps(after_calls=2, seconds=5800):
            result = run_with_deadline(
                [sys.executable, "-c", "import time; time.sleep(1.5)"],
                idle_seconds=60, activity_paths=[directory], poll_seconds=0.2,
                grace=1,
            )
        self.assertEqual(result, {"returncode": 0, "timed_out": False})

    def test_idleness_after_the_suspension_still_ends_the_step(self):
        with tempfile.TemporaryDirectory() as directory, \
                self._clock_that_jumps(after_calls=2, seconds=5800):
            started = time.monotonic()
            result = run_with_deadline(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                idle_seconds=1, activity_paths=[directory], poll_seconds=0.2,
                grace=1,
            )
        self.assertTrue(result.get("idle"))
        self.assertLess(time.monotonic() - started, 30)


if __name__ == "__main__":
    unittest.main()
