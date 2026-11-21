import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.orchestration import run_status  # noqa: E402


IDENTITY = {"commit": "abc", "dirty": False, "src_tree_sha256": "tree-1"}
CHANGED = {"commit": "def", "dirty": False, "src_tree_sha256": "tree-2"}
APK = "app.apk"


def _finding(run: Path, index: int, method: str, finding_id: str) -> None:
    path = run / "error_methods" / APK / f"{index}_{method}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "extraction_metadata": {"apk_name": APK, "csv_index": index},
        "error": {"csv_method": method, "unique_error_id": finding_id},
    }))


def _tracking(run: Path, failures) -> None:
    path = run / "error_solutions" / "solutions_tracking.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"failures": [
        {"apk_name": APK, "finding_id": finding_id, "kind": kind}
        for finding_id, kind in failures]}))


def _solution(run: Path, index: int, method: str) -> None:
    path = run / "error_solutions" / APK / f"{index}_{method}_solution.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}")


class RunStatusTests(unittest.TestCase):
    """What is left of a run, from the run's own files.

    Salty run_v4 (2026-10-31) lost both findings to one OpenAI HTTP 500 and
    was marked done because it listed findings; six runs whose
    validation_fix exited 1 had finished normally. Neither the exit code nor
    the finding count says whether a run is done.
    """

    def setUp(self):
        self.run = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.run, True)
        _finding(self.run, 0, "deriveKey", "C:::deriveKey:::PBE")
        _finding(self.run, 1, "encode", "C:::encode:::Cipher")

    def _end(self, outcome=None, failed_steps=(), identity_now=IDENTITY, selected=True):
        return run_status.record_pass_end(
            self.run, analysis_selected=selected, analysis_outcome=outcome,
            failed_steps=failed_steps, identity_now=identity_now)

    def _completed_outcome(self, returncode=0):
        return {"returncode": returncode, "timed_out": False, "idle": False,
                "started_at": time.time() - 60}

    def test_a_crashed_unit_leaves_both_joined_findings_resumable(self):
        # Salty run_v4: encode crashed and deriveKey was joined into it.
        run_status.record_pass_start(self.run, IDENTITY)
        _tracking(self.run, [("C:::encode:::Cipher", "crashed")])
        (self.run / "error_solutions" / "joint_findings.json").write_text(json.dumps([{
            "joined": {"apk_name": APK, "unique_error_id": "C:::deriveKey:::PBE"},
            "into": {"apk_name": APK, "unique_error_id": "C:::encode:::Cipher"}}]))

        status = self._end(self._completed_outcome(returncode=1))

        self.assertEqual(status["status"], run_status.RESUMABLE)
        self.assertEqual(len(status["crashed_findings"]), 2)
        code, line = run_status.resume_check(self.run, IDENTITY)
        self.assertEqual(code, run_status.CHECK_RESUME_IN_PLACE)
        self.assertIn("2 finding(s) crashed", line)

    def test_a_provider_unavailable_finding_is_left_for_a_resume_and_a_refusal_is_not(self):
        # agent_baseline_20261108 run_v4: server_is_overloaded was recorded as
        # provider_refused, a verdict, so the five findings it took counted
        # as concluded. As provider_unavailable they are left for a resume.
        run_status.record_pass_start(self.run, IDENTITY)
        _tracking(self.run, [("C:::encode:::Cipher", "provider_unavailable"),
                             ("C:::deriveKey:::PBE", "provider_refused")])

        status = self._end(self._completed_outcome(returncode=1))

        self.assertEqual(status["status"], run_status.RESUMABLE)
        # Review of 2026-11-09: listed apart from crashes, which may be
        # defects here, and resumed all the same.
        self.assertEqual(status["provider_unavailable_findings"],
                         [f"{APK}:C:::encode:::Cipher"])
        self.assertEqual(status["crashed_findings"], [])
        self.assertEqual(status["unfinished_findings"], [])
        self.assertIn("1 finding(s) left by an unavailable provider", status["reasons"])
        self.assertFalse(any("crashed" in reason for reason in status["reasons"]))
        # After the passes a run may take, nothing in its log to fix.
        for _ in range(run_status.MAX_PASSES - 1):
            run_status.record_pass_start(self.run, IDENTITY)
            self._end(self._completed_outcome(returncode=1))
        code, line = run_status.resume_check(self.run, IDENTITY)
        self.assertEqual(code, run_status.CHECK_GIVE_UP)
        self.assertIn("once the provider answers", line)
        self.assertNotIn("look at its log", line)

    def test_a_failed_validation_fix_after_a_concluded_analysis_is_complete(self):
        # bluegate run_v5: validation_fix "0 repaired, 1 failed", exit 1.
        run_status.record_pass_start(self.run, IDENTITY)
        _solution(self.run, 1, "encode")
        _tracking(self.run, [("C:::deriveKey:::PBE", "not_analyzable")])

        status = self._end(self._completed_outcome(), failed_steps=[("validation_fix", 1)])

        self.assertEqual(status["status"], run_status.COMPLETE)
        self.assertEqual(status["failed_steps"], [{"step": "validation_fix", "exit_code": 1}])
        code, line = run_status.resume_check(self.run, IDENTITY)
        self.assertEqual(code, run_status.CHECK_COMPLETE)
        self.assertIn("validation_fix exit 1", line)

    def test_a_completed_analysis_accounts_for_findings_without_files(self):
        # A false positive leaves only an evidence review; the step's own
        # accounting, written at its end, is what concludes it.
        run_status.record_pass_start(self.run, IDENTITY)
        _tracking(self.run, [])

        self.assertEqual(self._end(self._completed_outcome())["status"], run_status.COMPLETE)

    def test_a_stalled_analysis_leaves_its_unsaved_findings(self):
        # Amethyst run_v2: the step stalled twice and ended with exit 124.
        run_status.record_pass_start(self.run, IDENTITY)
        _solution(self.run, 0, "deriveKey")
        evidence = self.run / "error_solutions" / "evidence_reviews" / APK / "1_encode_evidence.json"
        evidence.parent.mkdir(parents=True)
        evidence.write_text("{}")

        status = self._end({"returncode": 124, "timed_out": True, "idle": True,
                            "started_at": time.time()})

        self.assertEqual(status["status"], run_status.RESUMABLE)
        self.assertEqual(status["unfinished_findings"], [f"{APK}:C:::encode:::Cipher"])

    def test_an_ending_recorded_without_an_issue_concludes_its_finding(self):
        # Review of cc3c117 (2026-11-09): a scope gap recorded as a correction
        # not generated writes no issue, and a stalled pass listed it as
        # unfinished although nothing was left to do for it.
        for folder in run_status.CONCLUDED_RECORD_FOLDERS:
            with self.subTest(folder):
                run_status.record_pass_start(self.run, IDENTITY)
                _solution(self.run, 0, "deriveKey")
                record = self.run / "error_solutions" / folder / APK / "1_encode.json"
                record.parent.mkdir(parents=True, exist_ok=True)
                record.write_text("{}")

                status = self._end({"returncode": 124, "timed_out": True, "idle": True,
                                    "started_at": time.time()})

                self.assertEqual(status["unfinished_findings"], [])
                record.unlink()
        # Without the record, the same finding is still left.
        status = self._end({"returncode": 124, "timed_out": True, "idle": True,
                            "started_at": time.time()})
        self.assertEqual(status["unfinished_findings"], [f"{APK}:C:::encode:::Cipher"])

    def test_an_analysis_that_never_accounted_for_its_findings_is_resumable(self):
        # misuse run_v2: "Cannot connect to OpenAI" after a wake, exit 1, and
        # the tracking file is the previous pass's.
        _tracking(self.run, [])
        os.utime(self.run / "error_solutions" / "solutions_tracking.json", (1, 1))
        run_status.record_pass_start(self.run, IDENTITY)

        status = self._end(self._completed_outcome(returncode=1))

        self.assertEqual(status["status"], run_status.RESUMABLE)
        self.assertEqual(len(status["unfinished_findings"]), 2)

    def test_a_run_stopped_before_its_analysis_is_resumable(self):
        # NotallyX (2026-10-28): the clone hit a TLS outage.
        run_status.record_pass_start(self.run, IDENTITY)

        status = self._end(None, failed_steps=[("cloning", 1)])

        self.assertEqual(status["status"], run_status.RESUMABLE)
        self.assertIn("the analysis step did not run", status["reasons"])

    def test_a_changed_library_sends_the_run_to_a_new_directory(self):
        run_status.record_pass_start(self.run, IDENTITY)
        _tracking(self.run, [("C:::encode:::Cipher", "crashed")])
        self._end(self._completed_outcome())

        code, line = run_status.resume_check(self.run, CHANGED)

        self.assertEqual(code, run_status.CHECK_NEW_RUN)
        self.assertIn("new run_vN", line)

    def test_a_library_edited_during_the_pass_is_a_mixed_run(self):
        run_status.record_pass_start(self.run, IDENTITY)
        _tracking(self.run, [])

        status = self._end(self._completed_outcome(), identity_now=CHANGED)

        self.assertTrue(status["mixed_pipeline"])
        code, line = run_status.resume_check(self.run, CHANGED)
        self.assertEqual(code, run_status.CHECK_COMPLETE)
        self.assertIn("library changed during the run", line)

    def test_a_crash_that_repeats_is_given_up_after_three_passes(self):
        _tracking(self.run, [("C:::encode:::Cipher", "crashed")])
        for _ in range(run_status.MAX_PASSES):
            run_status.record_pass_start(self.run, IDENTITY)
            self._end(self._completed_outcome())

        code, _ = run_status.resume_check(self.run, IDENTITY)

        self.assertEqual(code, run_status.CHECK_GIVE_UP)

    def test_a_pass_killed_outright_reads_as_interrupted(self):
        status = run_status.record_pass_start(self.run, IDENTITY)
        self.assertEqual(status["status"], run_status.RUNNING)

        with patch.object(run_status, "_pid_alive", return_value=True):
            self.assertEqual(run_status.resume_check(self.run, IDENTITY)[0],
                             run_status.CHECK_RUNNING)
        with patch.object(run_status, "_pid_alive", return_value=False):
            code, line = run_status.resume_check(self.run, IDENTITY)
        self.assertEqual(code, run_status.CHECK_RESUME_IN_PLACE)
        self.assertIn("interrupted", line)

    def test_a_run_from_before_the_status_existed_says_so(self):
        self.assertEqual(run_status.resume_check(self.run, IDENTITY)[0],
                         run_status.CHECK_NO_STATUS)

    def test_the_command_gives_the_verdict_as_its_exit_code_only_when_asked(self):
        import contextlib
        import io

        from cognalys import cli

        run_status.record_pass_start(self.run, run_status.library_identity())
        _tracking(self.run, [("C:::encode:::Cipher", "crashed")])
        self._end(self._completed_outcome(), identity_now=run_status.library_identity())
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["status", str(self.run), "--resume-check"]),
                             run_status.CHECK_RESUME_IN_PLACE)
            self.assertEqual(cli.main(["status", str(self.run)]), 0)
        self.assertIn("resume it in place", out.getvalue())


    def test_a_running_status_whose_pid_was_reused_after_a_restart_is_resumable(self):
        # 2026-10-31 review: WSL restarts number PIDs from 1 again, so a run
        # killed by the restart named a pid another process now holds and the
        # queue read it as still running on every pass.
        status = run_status.record_pass_start(self.run, IDENTITY)
        self.assertIn("boot_id", status)
        data = json.loads((self.run / run_status.RUN_STATUS_FILE).read_text())
        data["pid"] = 1
        data["boot_id"] = "an-earlier-boot"
        (self.run / run_status.RUN_STATUS_FILE).write_text(json.dumps(data))
        with patch.object(run_status, "_pid_alive", return_value=True),                 patch.object(run_status.repository_lock, "_pid_alive", return_value=True),                 patch.object(run_status.repository_lock, "_boot_id", return_value="this-boot"):
            code, line = run_status.resume_check(self.run, IDENTITY)
        self.assertEqual(code, run_status.CHECK_RESUME_IN_PLACE)
        self.assertIn("interrupted", line)

    def test_a_running_status_of_this_process_is_still_running(self):
        run_status.record_pass_start(self.run, IDENTITY)
        code, _line = run_status.resume_check(self.run, IDENTITY)
        self.assertEqual(code, run_status.CHECK_RUNNING)


class LibraryIdentityTests(unittest.TestCase):
    def test_the_tree_hash_follows_content_and_ignores_bytecode(self):
        package = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, package, True)
        (package / "a.py").write_text("x = 1\n")
        before = run_status.src_tree_sha256(package)
        (package / "__pycache__").mkdir()
        (package / "__pycache__" / "a.cpython-312.pyc").write_bytes(b"\0")
        self.assertEqual(run_status.src_tree_sha256(package), before)
        (package / "a.py").write_text("x = 2\n")
        self.assertNotEqual(run_status.src_tree_sha256(package), before)

    def test_an_explicit_package_is_hashed_even_with_the_override_set(self):
        package = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, package, True)
        (package / "a.py").write_text("x = 1\n")
        with patch.dict(os.environ, {run_status.IDENTITY_VARIABLE: "fixed"}):
            self.assertEqual(run_status.library_identity()["src_tree_sha256"], "fixed")
            self.assertEqual(run_status.library_identity(package)["src_tree_sha256"],
                             run_status.src_tree_sha256(package))

    def test_a_library_version_names_the_commit_or_else_the_tree(self):
        self.assertEqual(run_status.library_version(
            {"commit": "a" * 40, "dirty": False, "src_tree_sha256": "1" * 64}), "aaaaaaaaaa")
        self.assertEqual(run_status.library_version(
            {"commit": "a" * 40, "dirty": True, "src_tree_sha256": "1" * 64}), "aaaaaaaaaa dirty")
        self.assertEqual(run_status.library_version(
            {"commit": "", "dirty": None, "src_tree_sha256": "2" * 64}), "src 222222222222")
        self.assertEqual(run_status.library_version({}), "unrecorded")

    def test_the_recorded_library_falls_back_to_the_run_status(self):
        run = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, run, True)
        self.assertEqual(run_status.recorded_library(run), {})
        (run / "run_inputs.json").write_text(json.dumps({"config": {}}), encoding="utf-8")
        (run / run_status.RUN_STATUS_FILE).write_text(json.dumps(
            {"library": {"commit": "b" * 40, "dirty": False}}), encoding="utf-8")
        self.assertEqual(run_status.recorded_library(run)["commit"], "b" * 40)
        (run / "run_inputs.json").write_text(json.dumps(
            {"library": {"commit": "c" * 40}}), encoding="utf-8")
        self.assertEqual(run_status.recorded_library(run)["commit"], "c" * 40)

    def test_a_run_resumed_under_another_tree_is_named_mixed(self):
        run = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, run, True)
        clean = {"commit": "a" * 40, "dirty": False, "src_tree_sha256": "1" * 64}
        edited = {"commit": "a" * 40, "dirty": True, "src_tree_sha256": "2" * 64}
        reedited = {"commit": "a" * 40, "dirty": True, "src_tree_sha256": "3" * 64}

        def status(passes, mixed):
            (run / run_status.RUN_STATUS_FILE).write_text(json.dumps(
                {"passes": passes, "library": passes[0], "mixed_pipeline": mixed}),
                encoding="utf-8")

        status([clean, clean], False)
        self.assertEqual(run_status.run_version(run), "aaaaaaaaaa")
        status([clean, edited, edited], True)
        self.assertEqual(run_status.run_version(run),
                         "aaaaaaaaaa -> aaaaaaaaaa dirty (mixed)")
        status([clean, edited, reedited], True)
        self.assertEqual(
            run_status.run_version(run),
            "aaaaaaaaaa -> aaaaaaaaaa dirty -> aaaaaaaaaa dirty src 333333333333 (mixed)")
        # One pass, src/ edited while it ran: only the status says so.
        status([clean], True)
        self.assertEqual(run_status.run_version(run), "aaaaaaaaaa (mixed)")


if __name__ == "__main__":
    unittest.main()
