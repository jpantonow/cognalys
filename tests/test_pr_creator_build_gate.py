import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs.pr_creator import (  # noqa: E402
    AutomatedPRCreator, production_only_build_note,
)
from cognalys.prs.publication_checks import current_review_contract_version  # noqa: E402
from cognalys.reporting import finding_statistics  # noqa: E402
from cognalys.utils.disposition import (  # noqa: E402
    BUILD_VALIDATION_PASSING_STATUSES, PRODUCTION_ONLY_TEST_BUILD_PREEXISTING,
)
from cognalys.validation import applied_solutions  # noqa: E402
from cognalys.validation.applied_solutions import PASSING_STATUSES  # noqa: E402


class ExplicitApprovalBuildGateTests(unittest.TestCase):
    """Regression tests for com.ivanovsky.passnotes_11700.apk's finding.

    Its full multi-module build cannot succeed on this machine (missing
    Rust/cargo/NDK toolchain for an unrelated native submodule), even
    though the module containing the patch compiles cleanly in isolation.
    validate_applied_solutions.py now records that as
    build_validation.status == "success_app_module_only" (see
    rescue_unrelated_module_failure). Explicit review approval must accept
    that status -- it must not require the literal "success" a full,
    unrelated-module-inclusive build would produce.
    """

    def _creator(self):
        return AutomatedPRCreator(
            approved_reviewed_findings=["finding-1"], dry_run=True,
        )

    def _write_metadata(self, directory: Path, build_status: str,
                         commit_hash: str = "") -> Path:
        metadata = {
            "finding_id": "finding-1",
            "publication_allowed": False,
            "manual_review_required": True,
            "auto_apply": False,
            "build_validation": {"status": build_status},
            "commit_hash": commit_hash,
        }
        path = directory / "finding.json"
        path.write_text(json.dumps(metadata), encoding="utf-8")
        return path

    def test_rejects_a_failed_build_for_an_explicitly_approved_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(Path(directory), "failed")
            with self.assertRaisesRegex(RuntimeError, "successful build"):
                self._creator().process_pr_file(path)

    def test_accepts_app_module_only_success_and_proceeds_past_the_build_check(self):
        with tempfile.TemporaryDirectory() as directory:
            # commit_hash left empty: proceeding past the build-status check
            # is what we're testing, and the next check raises about the
            # missing commit hash instead -- proof the build-status gate
            # itself did not reject "success_app_module_only".
            path = self._write_metadata(
                Path(directory), "success_app_module_only"
            )
            with self.assertRaisesRegex(RuntimeError, "commit hash"):
                self._creator().process_pr_file(path)

    def test_accepts_a_production_only_pass_past_the_build_check(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(
                Path(directory), "success_production_only_test_build_preexisting"
            )
            with self.assertRaisesRegex(RuntimeError, "commit hash"):
                self._creator().process_pr_file(path)

    def test_the_production_only_note_names_what_the_pr_text_leaves_out(self):
        note = production_only_build_note({
            "status": "success_production_only_test_build_preexisting",
            "failed_test_tasks": [":common:checkDebugAndroidTestAarMetadata"],
            "removed_generated_tests": ["common/src/androidTest/java/CryptoTest.kt"],
        })
        self.assertIn("only the production build was verified", note)
        self.assertIn(":common:checkDebugAndroidTestAarMetadata", note)
        self.assertIn("common/src/androidTest/java/CryptoTest.kt", note)
        # A patch test in a module whose test task passed may have run.
        self.assertNotIn("no test compiled", note)
        self.assertIn("that test build says nothing about the patch", note)
        bare = production_only_build_note({})
        self.assertNotIn("failed test task", bare)
        self.assertNotIn("removed", bare)

    def test_the_production_only_note_reaches_the_operator(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(
                Path(directory), "success_production_only_test_build_preexisting",
                commit_hash="abc123",
            )
            metadata = json.loads(path.read_text(encoding="utf-8"))
            metadata["build_validation"]["failed_test_tasks"] = [":lib:checkAar"]
            metadata["review_contract_version"] = current_review_contract_version()
            path.write_text(json.dumps(metadata), encoding="utf-8")
            # An earlier dry run: past the gate it stops at "Already processed".
            path.with_name("finding_created.json").write_text(
                json.dumps({"dry_run": True}), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self._creator().process_pr_file(path)
        self.assertIn("only the production build was verified", output.getvalue())
        self.assertIn(":lib:checkAar", output.getvalue())

    def test_still_rejects_an_unrelated_status_string(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(Path(directory), "timeout")
            with self.assertRaisesRegex(RuntimeError, "successful build"):
                self._creator().process_pr_file(path)

    def test_the_validator_and_the_publishers_share_one_passing_set(self):
        """The stage that records the status and the stages that read it agree.

        applied_solutions.py cannot import utils (test_validation_feedback
        loads it by path with no package root on sys.path), so its
        PASSING_STATUSES is written out a second time. This pins the copy to
        the original: a status added to one and not the other is how
        pr_generator came to reject a status pr_creator documents accepting.
        """
        self.assertEqual(
            set(PASSING_STATUSES), set(BUILD_VALIDATION_PASSING_STATUSES),
        )

    def test_the_production_only_status_has_one_name(self):
        """The reports and the PR text compare against disposition's name;
        applied_solutions, which writes the status, keeps its own copy."""
        self.assertEqual(
            PRODUCTION_ONLY_TEST_BUILD_PREEXISTING,
            applied_solutions.PRODUCTION_ONLY_TEST_BUILD_PREEXISTING,
        )
        self.assertEqual(
            finding_statistics.PRODUCTION_ONLY_BUILD,
            PRODUCTION_ONLY_TEST_BUILD_PREEXISTING,
        )
        self.assertIn(PRODUCTION_ONLY_TEST_BUILD_PREEXISTING,
                      BUILD_VALIDATION_PASSING_STATUSES)


class PublishWithoutBuildValidationTests(unittest.TestCase):
    """Publishing a patch nothing ever compiled, and only that.

    com.googlecode.gtalksms declares the submodule
    git://github.com/JakeWharton/ActionBarSherlock.git/actionbarsherlock,
    whose path segment after .git is not a repository on any protocol, so
    its build cannot run on any machine and its findings could never become
    pull requests however sound the patch was. The escape hatch exists for
    that, and the line it must never cross is a build that ran and failed:
    a patch that does not compile must not reach a maintainer, however
    explicitly its publication was approved.
    """

    def _creator(self, without_validation=("finding-1",)):
        return AutomatedPRCreator(
            approved_reviewed_findings=["finding-1"],
            publish_without_build_validation=list(without_validation),
            dry_run=True,
        )

    def _write_metadata(self, directory: Path, build_status: str,
                        commit_hash: str = "") -> Path:
        metadata = {
            "finding_id": "finding-1",
            "publication_allowed": False,
            "manual_review_required": True,
            "auto_apply": False,
            "build_validation": {"status": build_status},
            "commit_hash": commit_hash,
        }
        path = directory / "finding.json"
        path.write_text(json.dumps(metadata), encoding="utf-8")
        return path

    def test_a_build_that_never_ran_may_be_published_when_approved(self):
        for status in ("infrastructure_failure", "not_run"):
            with self.subTest(status=status):
                with tempfile.TemporaryDirectory() as directory:
                    path = self._write_metadata(Path(directory), status)
                    # Reaching the commit-hash check proves the build-status
                    # gate let it through.
                    with self.assertRaisesRegex(RuntimeError, "commit hash"):
                        self._creator().process_pr_file(path)

    def test_a_patch_that_failed_to_compile_is_never_published(self):
        # The whole safety of the flag. "failed" means the patch itself did
        # not compile.
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(Path(directory), "failed")
            with self.assertRaisesRegex(RuntimeError, "successful build"):
                self._creator().process_pr_file(path)

    def test_an_inconclusive_timeout_is_never_published(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(Path(directory), "timeout")
            with self.assertRaisesRegex(RuntimeError, "successful build"):
                self._creator().process_pr_file(path)

    def test_it_covers_only_the_findings_it_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(
                Path(directory), "infrastructure_failure"
            )
            creator = self._creator(without_validation=("another-finding",))
            with self.assertRaisesRegex(RuntimeError, "successful build"):
                creator.process_pr_file(path)

    def test_it_grants_no_approval_of_its_own(self):
        # Without the review approval the finding is blocked before the
        # build status is ever consulted.
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(
                Path(directory), "infrastructure_failure"
            )
            creator = AutomatedPRCreator(
                approved_reviewed_findings=[],
                publish_without_build_validation=["finding-1"],
                dry_run=True,
            )
            self.assertEqual(creator.process_pr_file(path), "blocked")

    def test_a_draft_promoted_after_validation_still_needs_its_approval(self):
        """READY_FOR_PUBLICATION_WITH_NOTES recommends a review-only draft; it never
        publishes one on its own (P7)."""
        for decision, status in (("MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "blocked"),
                                 ("FIX_SUPPORTED", "")):
            with self.subTest(decision=decision), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "finding.json"
                path.write_text(json.dumps({
                    "finding_id": "finding-1", "decision": decision,
                    "publication_status": status, "publishable": True,
                    "preview_status": "READY_FOR_PUBLICATION_WITH_NOTES",
                    "publication_promoted_after_validation": True,
                    "build_validation": {"status": "success"}, "commit_hash": "abc",
                }), encoding="utf-8")
                refused = AutomatedPRCreator(approved_reviewed_findings=[], dry_run=True)
                printed = io.StringIO()
                with contextlib.redirect_stdout(printed):
                    self.assertEqual(refused.process_pr_file(path), "blocked")
                self.assertIn("review-only preview", printed.getvalue())
                # With the approval it goes on to the next gates.
                approved = AutomatedPRCreator(approved_reviewed_findings=["finding-1"],
                                              dry_run=True)
                printed = io.StringIO()
                with contextlib.redirect_stdout(printed):
                    approved.process_pr_file(path)
                self.assertNotIn("review-only preview", printed.getvalue())

    def test_a_repaired_patch_no_review_cleared_is_refused_even_when_approved(self):
        """Review of 2026-10-31: pr_creator never read the review of a patch
        whose build repair edited a file the plan did not include."""
        for blocks, review in (
                (["the behaviour review of the repaired patch found 1 regression(s)"], {}),
                ([], {"status": "not_run", "regressions": [],
                      "files_beyond_plan": ["app/Authenticator.kt"]})):
            with self.subTest(blocks=blocks), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "finding.json"
                path.write_text(json.dumps({
                    "finding_id": "finding-1", "decision": "MULTI_FILE_FIX_SUPPORTED",
                    "publication_status": "", "publishable": True,
                    "preview_status": "READY_FOR_PUBLICATION",
                    "repaired_patch_review_blocks": blocks, "repair_behavior_review": review,
                    "build_validation": {"status": "success"}, "commit_hash": "abc",
                }), encoding="utf-8")
                creator = AutomatedPRCreator(approved_reviewed_findings=["finding-1"],
                                             dry_run=True)
                printed = io.StringIO()
                with contextlib.redirect_stdout(printed):
                    self.assertEqual(creator.process_pr_file(path), "blocked")
                self.assertIn("repaired patch", printed.getvalue())

    def test_a_draft_no_repair_went_beyond_the_plan_for_passes_that_gate(self):
        """BlueGate run_v7 (2026-10-31): no build repair ran, and the PR
        record's empty repair_behavior_review ({}) read as a review that
        never ran, naming no file."""
        from cognalys.utils.disposition import repaired_patch_review_blocks

        for review in ({}, None, {"status": "not_run", "regressions": []},
                       {"status": "not_run", "files_beyond_plan": []}):
            with self.subTest(review=review):
                self.assertEqual(repaired_patch_review_blocks(
                    {"repair_behavior_review": review}), [])
        self.assertEqual(repaired_patch_review_blocks({"repair_behavior_review": {
            "status": "not_run", "files_beyond_plan": ["app/Authenticator.kt"]}}), [
            "no behaviour review judged the repaired patch's edits of app/Authenticator.kt"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "finding.json"
            path.write_text(json.dumps({
                "finding_id": "finding-1", "decision": "MULTI_FILE_FIX_SUPPORTED",
                "publication_status": "", "publishable": True,
                "preview_status": "READY_FOR_PUBLICATION",
                "repaired_patch_review_blocks": [], "repair_behavior_review": {},
                "build_validation": {"status": "success"}, "commit_hash": "abc",
            }), encoding="utf-8")
            creator = AutomatedPRCreator(approved_reviewed_findings=["finding-1"],
                                         dry_run=True)
            printed = io.StringIO()
            with contextlib.redirect_stdout(printed):
                creator.process_pr_file(path)
            self.assertNotIn("repaired patch", printed.getvalue())

    def test_the_never_ran_set_excludes_every_failing_status(self):
        from cognalys.utils.disposition import BUILD_NEVER_RAN_STATUSES
        self.assertNotIn("failed", BUILD_NEVER_RAN_STATUSES)
        self.assertNotIn("timeout", BUILD_NEVER_RAN_STATUSES)
        self.assertFalse(
            BUILD_NEVER_RAN_STATUSES & BUILD_VALIDATION_PASSING_STATUSES
        )


class StaleReviewApprovalTests(unittest.TestCase):
    """Drafts that predate the current behaviour review stayed approvable.

    Syncthing-Lite's (2026-10-25) renamed a constant to one with the same
    value, and Orgzly's added a type annotation: the review that rejects such
    patches came later. Approving one now needs a rerun, or an explicit
    --allow-stale-review that says which review is skipped.
    """

    def _write_metadata(self, directory: str, **extra) -> Path:
        run = Path(directory) / "rvsec_app" / "run"
        pull_requests = run / "pull_requests"
        pull_requests.mkdir(parents=True)
        (run.parent / "run_v2").mkdir()
        (run.parent / "run.toml").write_text("", encoding="utf-8")
        path = pull_requests / "app_m_S_pr.json"
        path.write_text(json.dumps({
            "finding_id": "finding-1",
            "publication_allowed": False,
            "manual_review_required": True,
            "auto_apply": False,
            "build_validation": {"status": "success"},
            "commit_hash": "abc123",
            **extra,
        }), encoding="utf-8")
        # An earlier dry run: a draft that passes the gate stops at "Already
        # processed" instead of going on to GitHub.
        (pull_requests / "app_m_S_pr_created.json").write_text(
            json.dumps({"dry_run": True}), encoding="utf-8")
        return path

    def _process(self, path: Path, **options):
        import contextlib
        import io

        creator = AutomatedPRCreator(
            approved_reviewed_findings=["finding-1"], dry_run=True, **options,
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = creator.process_pr_file(path)
        return result, output.getvalue()

    def test_a_draft_without_the_current_review_is_refused_with_the_rerun_command(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(directory, behavior_review_recorded=False)
            result, output = self._process(path)
            experiment = path.resolve().parents[2]
        self.assertEqual(result, "blocked")
        self.assertIn("no behaviour review ran on this draft", output)
        # Its own clones: --run-dir alone keeps the earlier run's.
        self.assertIn(f"cognalys run {experiment / 'run.toml'} --run-dir "
                      f"{experiment / 'run_v3'} --cloned-projects-dir "
                      f"{experiment / 'clones'}_v3", output)
        self.assertNotIn("approval accepted", output)

    def test_the_rerun_starts_from_the_run_s_own_file_with_new_clones(self):
        with tempfile.TemporaryDirectory() as directory:
            experiment = Path(directory).resolve() / "rvsec_app"
            (experiment / "run").mkdir(parents=True)
            (experiment / "run_v3").mkdir()
            (experiment / "run.toml").write_text(
                'cloned-projects-dir = "/home/u/work/app/clones"\n', encoding="utf-8")
            (experiment / "run_v3.toml").write_text(
                'cloned-projects-dir = "/home/u/work/app/clones_v3"\n', encoding="utf-8")
            command = AutomatedPRCreator.rerun_command(experiment / "run_v3")
        self.assertEqual(
            command,
            f"cognalys run {experiment / 'run_v3.toml'} --run-dir "
            f"{experiment / 'run_v4'} --cloned-projects-dir /home/u/work/app/clones_v4",
        )

    def test_a_single_method_draft_is_noted_not_sent_to_a_rerun(self):
        # That path writes no behaviour review: Grocy's insertConscrypt and
        # KeyPass's getKey came from it, and a rerun takes it again.
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(directory, behavior_review_recorded=False,
                                        fix_scope="single_method")
            result, output = self._process(path)
        self.assertNotEqual(result, "blocked")
        self.assertIn("single_method fix path has no behaviour review", output)
        self.assertNotIn("cognalys run", output)
        self.assertNotIn("--allow-stale-review", output)

    APK = "com.example.keys_1.apk"

    def _write_run_draft(self, directory: str, solution_metadata: dict,
                         review: dict | None = None, **pr_fields) -> Path:
        """A PR file written before it carried the review fields, and its solution file."""
        run = Path(directory) / "rvsec_app" / "run"
        (run.parent / "run.toml").parent.mkdir(parents=True, exist_ok=True)
        (run.parent / "run.toml").write_text("", encoding="utf-8")
        identity = {"csv_class": "app.CryptoManager", "method_name": "getKey",
                    "spec": "KeyStoreSpec"}
        solutions = run / "error_solutions" / self.APK
        solutions.mkdir(parents=True)
        (solutions / "0_getKey_solution.json").write_text(json.dumps({
            "solution_metadata": {**identity, **solution_metadata}}), encoding="utf-8")
        if review is not None:
            folder = run / "error_solutions" / "coordinated_drafts" / self.APK / "0_getKey"
            folder.mkdir(parents=True)
            (folder / "behavior_review.json").write_text(json.dumps(review), encoding="utf-8")
        pull_requests = run / "pull_requests"
        pull_requests.mkdir(parents=True)
        path = pull_requests / f"{self.APK}_getKey_KeyStoreSpec_pr.json"
        path.write_text(json.dumps({
            **identity, "finding_id": "finding-1", "title": "Generated title",
            "body": "Generated body.", "publication_allowed": False,
            "manual_review_required": True, "auto_apply": False,
            "build_validation": {"status": "success"}, "commit_hash": "abc123",
            **pr_fields,
        }), encoding="utf-8")
        path.with_name(f"{path.stem}_created.json").write_text(
            json.dumps({"dry_run": True}), encoding="utf-8")
        return path

    def test_a_pr_file_without_fix_scope_reads_it_from_the_solution_file(self):
        # KeyPass's getKey (rvsec_keypass_20261025) and whoBIRD's
        # downloadModels lambda: the preview said "no behaviour review by
        # design", pr_creator refused the same draft as stale.
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_run_draft(directory, {"fix_scope": "single_method"})
            result, output = self._process(path)
        self.assertNotEqual(result, "blocked")
        self.assertIn("NOTE: the single_method fix path has no behaviour review", output)
        self.assertNotIn("cognalys run", output)
        self.assertIn("approval accepted", output)

    def test_a_hand_written_description_still_wins_over_the_recorded_notes(self):
        import unittest.mock as mock

        with tempfile.TemporaryDirectory() as directory:
            path = self._write_run_draft(directory, {"fix_scope": "single_method"})
            path.with_name(f"{path.stem}_body.md").write_text(
                "# Written title\n\nWritten body.", encoding="utf-8")
            seen = {}

            def capture(metadata, json_file):
                seen.update({key: metadata.get(key) for key in ("title", "body", "fix_scope")})
                return False

            with mock.patch.object(AutomatedPRCreator, "refuses_stale_review",
                                   side_effect=capture):
                self._process(path)
        self.assertEqual(seen, {"title": "Written title", "body": "Written body.",
                                "fix_scope": "single_method"})

    def test_a_draft_completed_through_a_review_outage_says_no_review_ran(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_run_draft(
                directory, {"fix_scope": "coordinated", "review_contract_version": None},
                review={"status": "not_run", "regressions": []})
            result, output = self._process(path)
        self.assertEqual(result, "blocked")
        self.assertIn("no behaviour review ran on this draft", output)
        self.assertNotIn("predates", output)

    def test_an_empty_review_field_in_the_pr_file_gives_way_to_the_recorded_one(self):
        # The statistics kept the solution file's version for a PR file's
        # null; pr_creator took the null and refused the draft as stale.
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_run_draft(
                directory, {"fix_scope": "coordinated",
                            "review_contract_version": current_review_contract_version()},
                review={"status": "reviewed", "regressions": []},
                review_contract_version=None, fix_scope="")
            result, output = self._process(path)
        self.assertNotEqual(result, "blocked")
        self.assertNotIn("cognalys run", output)
        self.assertIn("approval accepted", output)

    def test_a_draft_already_published_is_skipped_not_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(directory, behavior_review_recorded=False)
            path.with_name("app_m_S_pr_created.json").write_text(json.dumps({
                "dry_run": False, "html_url": "https://github.com/o/r/pull/7",
            }), encoding="utf-8")
            result, output = self._process(path)
        self.assertNotEqual(result, "blocked")
        self.assertIn("Already processed", output)
        self.assertNotIn("cognalys run", output)

    def test_an_older_review_contract_is_refused(self):
        current = current_review_contract_version()
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(directory, review_contract_version=current - 1)
            result, output = self._process(path)
        self.assertEqual(result, "blocked")
        self.assertIn(f"the current one is {current}", output)

    def test_the_override_publishes_it_and_names_the_review_it_skips(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(directory)
            result, output = self._process(path, allow_stale_review=True)
        self.assertNotEqual(result, "blocked")
        self.assertIn("WARNING: --allow-stale-review", output)
        self.assertIn("no behaviour review contract is recorded", output)
        self.assertIn("approval accepted", output)

    def test_a_draft_under_the_current_review_is_not_held(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_metadata(
                directory, review_contract_version=current_review_contract_version())
            result, output = self._process(path)
        self.assertNotEqual(result, "blocked")
        self.assertNotIn("--allow-stale-review", output)


if __name__ == "__main__":
    unittest.main()
