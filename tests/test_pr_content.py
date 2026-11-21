import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs.pr_generator import PrGenerator  # noqa: E402


class PullRequestContentTests(unittest.TestCase):
    def make_generator(self, directory: str, style: str = "v1") -> PrGenerator:
        report = Path(directory) / "execution.json"
        report.write_text("{}", encoding="utf-8")
        return PrGenerator(
            str(report), str(Path(directory) / "prs"), style=style
        )

    def test_template_guidance_is_applied_without_being_appended_verbatim(self):
        with tempfile.TemporaryDirectory() as directory:
            body = self.make_generator(directory).build_pr_body({
                "method_name": "select", "csv_class": "Selector",
                "source_file": "src/Selector.kt", "spec": "DigestSpec",
                "explanation": "Replace the local discriminator.",
                "repository_guidance": [{
                    "path": ".github/PULL_REQUEST_TEMPLATE.md",
                    "content": (
                        "Thanks for sending a pull request!\n"
                        "## Summary\n- One-line summary\n## AI Assistance"
                    ),
                }],
                "build_validation": {"status": "success", "task": "test"},
                "coordinated_edits": [{
                    "source_file": "src/Selector.kt", "edit_kind": "test",
                }, {
                    "source_file": "src/SelectorTest.kt", "edit_kind": "test",
                }],
            }, "diff")
            self.assertNotIn("Thanks for sending a pull request!", body)
            self.assertNotIn("One-line summary", body)
            self.assertIn("## Summary", body)
            self.assertIn("## How was this tested?", body)
            self.assertIn("AI assistance was used", body)
            self.assertIn("Automated test coverage added in 2 test file(s)", body)

    def test_cache_note_is_scoped_to_confirmed_cache_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            generator = self.make_generator(directory)
            base = {
                "method_name": "select", "explanation": "change",
                "compatibility_policy": {"allow_cache_invalidation": True},
                "build_validation": {"status": "success"},
            }
            runtime = generator.build_pr_body({
                **base,
                "migration_assessment": {"usage_kind": "runtime_discriminator"},
            }, "")
            cache = generator.build_pr_body({
                **base, "migration_assessment": {"usage_kind": "cache"},
            }, "")
            self.assertNotIn("regenerable cache entries", runtime)
            self.assertIn("regenerable cache entries", cache)

    def test_the_body_is_written_without_encoding_damage(self):
        """This checked the encoding through the "Reviewer notes" section,
        which no longer reaches the maintainer. The subject was always the
        mojibake, so it is asserted on text the body still carries."""
        with tempfile.TemporaryDirectory() as directory:
            body = self.make_generator(directory).build_pr_body({
                "method_name": "select", "explanation": "change",
                "manual_review_required": True,
                "review_assumptions": ["TYPE2 mapping is not established."],
                "review_blockers": [{
                    "code": "LEGACY_MAPPING", "details": ["TYPE2"],
                }],
                "build_validation": {"status": "success"},
            }, "")
            self.assertIn("Brasília", body)
            self.assertNotIn("BrasÃ", body)
            self.assertNotIn("Do not merge", body)
            self.assertNotIn("TYPE2 mapping is not established", body)

    def test_legacy_coordinated_placeholder_becomes_dynamic_error_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            body = self.make_generator(directory).build_pr_body({
                "method_name": "build", "spec": "SSLContextSpec", "tool": "ape",
                "error_message": "expecting TLSv1.2 but found TLS.",
                "explanation": (
                    "Coordinated fix assembled from persisted per-file drafts."
                ),
                "migration_assessment": {
                    "usage_kind": "protocol",
                    "safe_strategy": "Filter only legacy protocols.",
                },
                "coordinated_edits": [{
                    "source_file": "src/Client.kt", "edit_kind": "method",
                    "reason": "Filters every created socket.",
                }, {
                    "source_file": "src/ClientTest.kt", "edit_kind": "test",
                    "reason": "Tests future protocol preservation.",
                }],
                "required_tests": ["Reject TLSv1.1."],
                "build_validation": {"status": "failed"},
            }, "")
            self.assertIn("The dynamic-analysis run by `ape` reported", body)
            self.assertIn("expecting TLSv1.2 but found TLS", body)
            self.assertIn("Filter only legacy protocols", body)
            self.assertNotIn("assembled from persisted", body)

    def test_unknown_dynamic_error_is_not_presented_as_observed_failure(self):
        summary = PrGenerator.elaborate_legacy_coordinated_summary({
            "error_message": "unknown", "coordinated_edits": [],
        })
        self.assertNotIn("dynamic-analysis", summary)

    def test_app_module_only_success_does_not_withhold_the_commit(self):
        """The gate that decides whether a branch and commit are created.

        A blocked validation skips both, and pr_creator's explicit-approval
        path requires the commit hash it would have produced, so rejecting
        "success_app_module_only" here made that path unreachable for every
        finding whose full build failed outside the patched module.
        """
        self.assertFalse(
            PrGenerator.build_validation_blocks_publication("success")
        )
        self.assertFalse(
            PrGenerator.build_validation_blocks_publication(
                "success_app_module_only"
            )
        )
        self.assertTrue(
            PrGenerator.build_validation_blocks_publication("failed")
        )
        self.assertTrue(
            PrGenerator.build_validation_blocks_publication("timeout")
        )
        self.assertTrue(PrGenerator.build_validation_blocks_publication(""))
        self.assertTrue(
            PrGenerator.build_validation_blocks_publication(
                "verified_preexisting_build_failure"
            )
        )

    def test_app_module_only_success_is_stated_without_claiming_a_full_build(self):
        """The narrower pass is reported, and reported as what it was.

        pr_generator used to treat any status other than "success" as an
        incomplete validation, which both hid this result from the PR body and
        -- through the same comparison -- withheld the commit that
        pr_creator's explicit-approval path requires.
        """
        with tempfile.TemporaryDirectory() as directory:
            body = self.make_generator(directory).build_pr_body({
                "method_name": "decompress", "spec": "ZipSlipSpec",
                "explanation": "Contain entries to the destination.",
                "build_validation": {
                    "status": "success_app_module_only",
                    "task": ":app:compileFossDebugKotlin",
                },
            }, "")

            self.assertIn("The patched module compiles successfully", body)
            self.assertIn(":app:compileFossDebugKotlin", body)
            self.assertNotIn("Project compiles successfully", body)
            self.assertNotIn(
                "Build validation has not completed successfully", body,
            )

    def test_a_compile_only_pass_says_it_compiled_not_that_it_built(self):
        """Salty: the only module compiled after the full build timed out; the
        text claims neither another module nor a packaged APK."""
        status = "success_compile_only"
        self.assertFalse(PrGenerator.build_validation_blocks_publication(status))
        result = {
            "method_name": "encode", "spec": "CipherSpec", "tool": "ape",
            "explanation": "Use a random salt.",
            "build_validation": {"status": status, "task": ":app:compileDebugSources"},
        }
        with tempfile.TemporaryDirectory() as directory:
            v1 = self.make_generator(directory).build_pr_body(result, "")
            v3 = self.make_generator(directory, style="v3").build_pr_body(result, "")
        self.assertIn("- [x] The project compiles successfully (`:app:compileDebugSources`)", v1)
        self.assertIn("The project compiles with this change (`:app:compileDebugSources`).", v3)
        for body in (v1, v3):
            self.assertNotIn("module", body)
            self.assertNotIn("builds with this change", body)

    def test_production_only_pass_never_claims_the_tests_compiled(self):
        """The test build fails on the base commit before any test compiles;
        the text says the app builds and that the tests were not run."""
        status = "success_production_only_test_build_preexisting"
        self.assertFalse(PrGenerator.build_validation_blocks_publication(status))
        result = {
            "method_name": "encrypt", "spec": "CipherSpec", "tool": "ape",
            "explanation": "Use an authenticated mode.",
            "build_validation": {
                "status": status, "task": ":app:assembleDebug",
                "failed_test_tasks": [":common:checkDebugAndroidTestAarMetadata"],
                "removed_generated_tests": ["common/src/androidTest/java/CryptoTest.kt"],
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            v1 = self.make_generator(directory).build_pr_body(result, "")
            v3 = self.make_generator(directory, style="v3").build_pr_body(result, "")

        self.assertIn("- [x] The app compiles successfully with this change", v1)
        self.assertIn("so it could not be used to check this change", v1)
        self.assertNotIn("Project compiles successfully", v1)
        self.assertNotIn("Build validation has not completed successfully", v1)
        self.assertIn("The app builds with this change (`:app:assembleDebug`).", v3)
        self.assertIn("so that build couldn't check the change.", v3)
        for body in (v1, v3):
            # Operator-only detail stays out of the maintainer's text.
            self.assertNotIn("checkDebugAndroidTestAarMetadata", body)
            self.assertNotIn("CryptoTest", body)
            self.assertNotIn("tests pass", body.lower())
        self.assertNotIn("##", v3)
        self.assertNotIn("- [", v3)

    def test_production_only_pass_with_a_kept_test_does_not_deny_it(self):
        """settle_test_build_failing_on_base keeps a patch test whose module's
        test task passed; the text must not say no test compiled or ran
        next to the line announcing that test."""
        result = {
            "method_name": "encrypt", "spec": "CipherSpec", "tool": "ape",
            "explanation": "Use an authenticated mode.",
            "coordinated_edits": [{
                "source_file": "app/src/test/java/CryptoTest.kt", "edit_kind": "test",
            }],
            "build_validation": {
                "status": "success_production_only_test_build_preexisting",
                "task": ":app:assembleDebug",
                "failed_test_tasks": [":common:checkDebugAndroidTestAarMetadata"],
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            v1 = self.make_generator(directory).build_pr_body(result, "")
            v3 = self.make_generator(directory, style="v3").build_pr_body(result, "")

        self.assertIn("Automated test coverage added in 1 test file(s)", v1)
        self.assertIn("CryptoTest.kt", v3)
        for body in (v1, v3):
            lowered = body.lower()
            self.assertNotIn("not compiled", lowered)
            self.assertNotIn("no test compiled", lowered)
            self.assertNotIn("couldn't run the tests", lowered)

    def test_review_contract_version_is_read_from_the_execution_row(self):
        """The row carries it (solution_applicator), so a report outside a
        run directory's layout still yields it; a row without one falls back
        to the run's files, which here hold nothing."""
        with tempfile.TemporaryDirectory() as directory:
            generator = self.make_generator(directory)
            row = {"apk_name": "app", "csv_class": "C", "method_name": "m", "spec": "S"}
            self.assertEqual(
                generator.review_notes({**row, "review_contract_version": 4})
                ["review_contract_version"], 4,
            )
            self.assertIsNone(
                generator.review_notes({**row, "review_contract_version": None})
                ["review_contract_version"],
            )
            self.assertIsNone(generator.review_notes(row)["review_contract_version"])

    def test_neither_review_section_reaches_the_pull_request_body(self):
        """Removed at the maintainer's boundary only: the same assumptions and
        blockers stay in the solution and execution JSON for the operator."""
        with tempfile.TemporaryDirectory() as directory:
            body = self.make_generator(directory).build_pr_body({
                "method_name": "encrypt", "spec": "CipherSpec",
                "explanation": "Replace the transformation.",
                "build_validation": {"status": "success"},
                "review_assumptions": ["An unresolved assumption."],
                "review_blockers": ["An unresolved blocker."],
                "publication_considerations": [{
                    "category": "maintainer_decision",
                    "description": "Decide whether the fallback is acceptable.",
                }],
            }, "")

            self.assertNotIn("Reviewer notes", body)
            self.assertNotIn("Residual review requirements", body)
            self.assertNotIn("An unresolved assumption.", body)
            self.assertNotIn("An unresolved blocker.", body)
            self.assertNotIn("Do not merge until", body)
            # The user asked for the section to go entirely.
            self.assertNotIn("Before merging", body)
            self.assertNotIn("Decide whether the fallback is acceptable.", body)

    def test_v1_style_is_unchanged_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            body = self.make_generator(directory).build_pr_body({
                "method_name": "build", "spec": "SSLContextSpec", "tool": "ape",
                "explanation": "change", "build_validation": {"status": "success"},
            }, "")
            self.assertIn("## Additional context", body)
            self.assertNotIn("usage rule that was checked", body)

    def test_v2_style_adds_the_tool_and_spec_glossary_once(self):
        with tempfile.TemporaryDirectory() as directory:
            body = self.make_generator(directory, style="v2").build_pr_body({
                "method_name": "build", "spec": "SSLContextSpec", "tool": "ape",
                "explanation": "change", "build_validation": {"status": "success"},
            }, "")
            self.assertEqual(body.count("running the app under RVSec"), 1)
            self.assertNotIn("SSLContextSpec", body)
            self.assertIn("## How was this tested?", body)

    def test_v3_style_names_rvsec_once_without_the_spec_id(self):
        with tempfile.TemporaryDirectory() as directory:
            body = self.make_generator(directory, style="v3").build_pr_body({
                "method_name": "build", "spec": "SSLContextSpec", "tool": "ape",
                "explanation": "change", "build_validation": {"status": "success"},
            }, "")
            self.assertEqual(body.count("running the app under RVSec"), 1)
            self.assertNotIn("SSLContextSpec", body)

    def test_v3_body_is_prose_and_mentions_only_a_build_that_passed(self):
        """2026-10-22: no headings or checkboxes; a failed build goes unsaid."""
        with tempfile.TemporaryDirectory() as directory:
            generator = self.make_generator(directory, style="v3")
            result = {"method_name": "build", "tool": "ape", "explanation": "change"}
            passed = generator.build_pr_body(
                {**result, "build_validation": {"status": "success", "task": ":app:assembleDebug"}}, "")
            self.assertIn("The project builds with this change (`:app:assembleDebug`).", passed)
            for status in ("failed", "timeout", "not_run"):
                body = generator.build_pr_body({**result, "build_validation": {"status": status}}, "")
                self.assertNotIn("build", body.replace("`build`", "").lower())
            for text in (passed, body):
                self.assertNotIn("##", text)
                self.assertNotIn("- [", text)
                self.assertNotIn("---", text)

    def test_v2_style_moves_the_disclosure_to_a_trailing_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            body = self.make_generator(directory, style="v2").build_pr_body({
                "method_name": "build", "explanation": "change",
                "build_validation": {"status": "success"},
            }, "")
            self.assertNotIn("## Additional context", body)
            self.assertIn("University of Brasília", body)
            # The disclosure must be the last thing in the body (a trailing
            # signature), not the first thing a reader sees.
            self.assertLess(
                body.index("change"), body.index("University of Brasília")
            )

    def test_v2_style_widens_the_strategy_lookup_to_compatibility_policy(self):
        # Reproduces the real passwdsafe gap: a detailed strategy exists only
        # under compatibility_policy.case_migration_policy.strategy.
        with tempfile.TemporaryDirectory() as directory:
            body = self.make_generator(directory, style="v2").build_pr_body({
                "method_name": "getCipher",
                "error_message": "expecting authenticated encryption but found AES/CTR.",
                "explanation": "Coordinated fix assembled from persisted per-file drafts.",
                "compatibility_policy": {
                    "case_migration_policy": {
                        "strategy": "Replace CTR with authenticated AES/GCM.",
                    },
                },
                "build_validation": {"status": "success"},
            }, "")
            self.assertIn("Replace CTR with authenticated AES/GCM.", body)

    def test_a_summary_written_with_a_removed_test_is_not_published_as_it_is(self):
        """The summary still said "I also added a test" once validation had
        removed the generated test it was written with."""
        from cognalys.validation.applied_solutions import record_removed_tests

        test_path = "app/src/test/java/app/CryptoTest.kt"
        solution = {
            "method_name": "encrypt", "error_message": "",
            "coordinated_edits": [
                {"source_file": "app/src/main/java/app/Crypto.kt", "edit_kind": "method"},
                {"source_file": test_path, "edit_kind": "test"},
            ],
        }
        record_removed_tests(solution, [test_path], "The test was removed.")
        with tempfile.TemporaryDirectory() as directory:
            problems = self.make_generator(directory).text_problems_of(
                solution, "Use an authenticated cipher mode", "Body text.", "")
        self.assertTrue(any("summary was written for edits" in item for item in problems))


class PlainPullRequestBodyTests(unittest.TestCase):
    """The maintainer reads what was wrong and what changed, not a checklist."""

    CANDIDATE = {
        "method_name": "BrowserAuthScreen",
        "csv_class": "ui.screens.BrowserAuthScreenKt",
        "source_file": "app/src/main/BrowserAuthScreen.kt",
        "spec": "WebViewSslErrorBypassSpec", "tool": "static:manual",
        "error_message": (
            "Static candidate (not executed): onReceivedSslError calls "
            "handler.proceed() unconditionally."
        ),
        "explanation": (
            "### Observed dynamic-analysis failure\n\n"
            "The dynamic-analysis run by `static:manual` reported "
            "(`WebViewSslErrorBypassSpec`) while exercising "
            "`ui.screens.BrowserAuthScreenKt.BrowserAuthScreen`:\n\n"
            "> Static candidate (not executed): proceed() is unconditional.\n\n"
            "### Root cause\n\n"
            "The callback always calls proceed(). [C1, C2]\n\n"
            "### Correction strategy\n\n"
            "Cancel the request instead.\n\n"
            "### Coordinated changes\n\n"
            "- `Screen.kt`: Cancels the request.\n\n"
            "### Verification included\n\n"
            "- Run the module tests.\n"
            "- Compile the androidTest sources.\n"
        ),
        "required_tests": ["Run the module tests."],
        "build_validation": {"status": "success", "task": ":app:test"},
        "coordinated_edits": [{
            "source_file": "src/test/ScreenTest.kt", "edit_kind": "test",
        }],
    }

    def body(self, style: str = "v1", **overrides) -> str:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "execution.json"
            report.write_text("{}", encoding="utf-8")
            generator = PrGenerator(
                str(report), str(Path(directory) / "prs"), style=style
            )
            return generator.build_pr_body({**self.CANDIDATE, **overrides}, "")

    def test_no_checklist_sections_reach_the_maintainer(self):
        body = self.body()
        for unwanted in (
            "Verification included", "Test scenarios covered",
            "Run the module tests.", "Compile the androidTest sources.",
            "| Property | Value |", "What does this implement/fix?",
            "Confirmed by a project maintainer", "### Root cause",
            "### Correction strategy",
        ):
            self.assertNotIn(unwanted, body)
        self.assertIn("Cancel the request instead.", body)
        self.assertIn("Project compiles successfully", body)

    def test_parenthesised_evidence_ids_are_not_shown_either(self):
        body = self.body(explanation=(
            "The callback calls proceed() (CLM-001, CLM-002, CLM-003). "
            "SHA1 (SHA1) stays."
        ))
        self.assertNotIn("CLM-00", body)
        self.assertIn("calls proceed().", body)
        self.assertIn("(SHA1)", body)

    def test_evidence_ids_are_not_shown(self):
        body = self.body()
        self.assertNotIn("[C1, C2]", body)
        self.assertIn("The callback always calls proceed().", body)

    def test_a_candidate_read_from_the_code_is_not_called_a_dynamic_run(self):
        for style in ("v1", "v2"):
            body = self.body(style)
            self.assertNotIn("dynamic-analysis", body)
            self.assertNotIn("static:manual", body)
            # Its message only restates the cause that follows, so it is not
            # quoted; a maintainer reads the cause once.
            self.assertNotIn("Static candidate (not executed)", body)
            self.assertNotIn("Reported finding", body)
            self.assertNotIn("is the name of the specific usage rule", body)

    def test_a_candidate_with_no_stated_cause_keeps_its_message(self):
        body = self.body(explanation=(
            "Coordinated fix assembled from persisted per-file drafts."
        ), migration_assessment={})
        self.assertIn("Reported finding (`WebViewSslErrorBypassSpec`)", body)
        self.assertIn("in `BrowserAuthScreen`", body)
        self.assertIn("Static candidate (not executed)", body)

    def test_a_dynamic_analyzer_is_still_named(self):
        body = self.body(
            tool="ape", explanation="Coordinated fix assembled from "
            "persisted per-file drafts.",
        )
        self.assertIn("The dynamic-analysis run by `ape` reported", body)

    def test_the_location_is_stated_once_and_only_when_missing(self):
        plain = self.body(explanation="Cancel the request instead.")
        self.assertIn(
            "Affects `BrowserAuthScreen` in "
            "`app/src/main/BrowserAuthScreen.kt`.", plain,
        )
        already_named = self.body(
            explanation="BrowserAuthScreen cancels the request now.",
        )
        self.assertNotIn("Affects", already_named)


class DeveloperCertificateOfOriginTests(unittest.TestCase):
    """Every commit this pipeline pushes carries a Signed-off-by trailer.

    nextcloud/news-android enforces DCO, and PR #1716 was opened and
    immediately blocked: "There is one commit incorrectly signed off."
    Repairing a pushed commit means a rebase and a force push, which is far
    more expensive than signing every commit in the first place, and
    projects that do not check DCO simply ignore the trailer.

    git builds the trailer from user.name/user.email, the same identity that
    authors the commit, so it asserts nothing the author was not already
    asserting by committing.
    """

    def _repo(self, directory: Path) -> Path:
        repo = directory / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        for key, value in (
            ("user.name", "jpantonow"),
            ("user.email", "jpantonow@gmail.com"),
        ):
            subprocess.run(
                ["git", "-C", str(repo), "config", key, value], check=True
            )
        return repo

    def _trailer(self, repo: Path) -> str:
        return subprocess.run(
            ["git", "-C", str(repo), "log", "-1",
             "--format=%(trailers:key=Signed-off-by)"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()

    def test_the_pull_request_commit_is_signed_off(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = self._repo(root)
            (repo / "a.txt").write_text("x", encoding="utf-8")
            report = root / "execution.json"
            report.write_text("{}", encoding="utf-8")
            generator = PrGenerator(str(report), str(root / "prs"))
            commit = generator.commit_changes(repo, "Fix loadAppKeyStore")
            self.assertTrue(commit)
            self.assertEqual(
                self._trailer(repo),
                "Signed-off-by: jpantonow <jpantonow@gmail.com>",
            )

    def test_a_repair_commit_takes_the_pull_request_message(self):
        # DSub2000#178 showed "Repair validation compilation for f167efd80107".
        from cognalys.validation.repair import commit_repair
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = self._repo(root)
            (repo / "a.txt").write_text("x", encoding="utf-8")
            commit_repair(repo, ["a.txt"], "f167efd80107")
            report = root / "execution.json"
            report.write_text("{}", encoding="utf-8")
            generator = PrGenerator(str(report), str(root / "prs"))
            self.assertTrue(generator.commit_changes(repo, "Use platform trust managers"))
            message = subprocess.run(["git", "-C", str(repo), "log", "--format=%s"],
                                     capture_output=True, text=True, check=True).stdout
            self.assertEqual(message.strip(), "Use platform trust managers")
            self.assertTrue(self._trailer(repo))

    def test_the_repair_commit_is_signed_off(self):
        # A repair commit rides into the same pull request, and DCO fails
        # the branch when any single commit on it lacks the trailer.
        from cognalys.validation.repair import commit_repair
        with tempfile.TemporaryDirectory() as directory:
            repo = self._repo(Path(directory))
            (repo / "a.txt").write_text("x", encoding="utf-8")
            commit_repair(repo, ["a.txt"], "finding-1")
            self.assertEqual(
                self._trailer(repo),
                "Signed-off-by: jpantonow <jpantonow@gmail.com>",
            )


if __name__ == "__main__":
    unittest.main()


class PublicationAfterValidationPreviewTests(unittest.TestCase):
    """A review-only draft is judged again once it is built and reviewed (P7).

    Orgzly's sha1 (2026-10-29): MULTI_FILE_FIX_PROPOSED_FOR_REVIEW, a passing
    build, a current review with no regression, only a maintainer-decision
    blocker -- and still REVIEW_ONLY_NOT_PUBLISHABLE. Salty's run_v2 draft
    carried code_evidence_missing and stays review-only.
    """

    def generate(self, *categories, overrides=None, repair_review=None, template=False,
                 text_client=None, summary_current=True):
        import json
        from cognalys.llm.coordinated_generation import REVIEW_CONTRACT_VERSION

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "clones" / "orgzly.apk"
            source = repo / "app/src/main/java/x/MiscUtils.java"
            source.parent.mkdir(parents=True)
            source.write_text('class MiscUtils {\n  byte[] hash(byte[] b) throws Exception {\n'
                              '    return MessageDigest.getInstance("SHA-1").digest(b);\n  }\n}\n',
                              encoding="utf-8")
            if template:
                (repo / ".github").mkdir()
                (repo / ".github/pull_request_template.md").write_text(
                    "## Description\n\n", encoding="utf-8")
            for command in (["init", "-q"], ["config", "user.name", "jpantonow"],
                            ["config", "user.email", "jpantonow@gmail.com"],
                            ["add", "."], ["commit", "-q", "-m", "base"]):
                subprocess.run(["git", "-C", str(repo), *command], check=True)
            base = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, check=True).stdout.strip()
            source.write_text(source.read_text(encoding="utf-8").replace('"SHA-1"', '"SHA-256"'),
                              encoding="utf-8")
            solution = {
                "status": "SUCCESS", "apk_name": "orgzly.apk", "method_name": "hash",
                "csv_class": "x.MiscUtils", "spec": "MessageDigestSpec", "finding_id": "f-1",
                "source_file": "app/src/main/java/x/MiscUtils.java", "worktree_path": str(repo),
                "base_commit": base, "branch": "fix/hash-f-1",
                "error_message": "expecting one of SHA-256,SHA-384,SHA-512 but found SHA-1",
                "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "publication_status": "blocked",
                "manual_review_required": True, "auto_apply": False, "publication_allowed": False,
                "fix_scope": "review_only", "review_contract_version": REVIEW_CONTRACT_VERSION,
                "build_validation": {"status": "success",
                                     "phases": {"production": {"status": "success"}}},
                "semantic_validation": {"status": "valid", "errors": [], "warnings": []},
                "changed_files": ["app/src/main/java/x/MiscUtils.java"],
                "explanation": ("<!-- pr-title: Use SHA-256 for note hashes -->\n"
                                "`hash` used SHA-1. It now uses SHA-256."),
                "coordinated_edits": [{
                    "source_file": "app/src/main/java/x/MiscUtils.java", "edit_kind": "method",
                    "symbol": "hash", "reason": "Uses SHA-256.",
                    "original_code": '    return MessageDigest.getInstance("SHA-1").digest(b);',
                    "corrected_code": '    return MessageDigest.getInstance("SHA-256").digest(b);'}],
                "publication_blocker_record": {
                    "blockers": [{"category": category, "kind": category,
                                  "description": f"{category} question",
                                  "discharged_by_pipeline_validation": False}
                                 for category in categories],
                    "discharged_blockers": [], "plan_publication_blockers": [],
                    "behavior_review": {"status": "reviewed",
                                        "review_contract_version": REVIEW_CONTRACT_VERSION,
                                        "regression_count": 0, "patch_has_no_effect": False}},
                **(overrides or {}),
            }
            if repair_review is not None:
                # What validation.repair records once a repair edited a file
                # the plan did not include; the text rewrite the PR step
                # makes in a real run leaves the summary current.
                from cognalys.validation.repair import record_repair_review

                record_repair_review(solution, repair_review, ["app/src/main/java/x/Other.java"])
                if summary_current:
                    solution["summary_stale"] = False
            report = root / "run" / "application_results" / "execution_report.json"
            report.parent.mkdir(parents=True)
            report.write_text(json.dumps({"config": {"cloned_projects_dir": str(root / "clones")},
                                          "per_solution_details": [solution]}), encoding="utf-8")
            generator = PrGenerator(str(report), str(root / "run" / "pull_requests"))
            if text_client is not None:
                generator.text_model = {"model": "fake"}
                generator._text_client = text_client
            generator.generate_prs()
            written = list((root / "run" / "pull_requests").glob("*_pr.json"))
            self.assertEqual(len(written), 1)
            return json.loads(written[0].read_text(encoding="utf-8"))

    def test_a_rewritten_stale_summary_is_not_held_again_by_the_template_check(self):
        """Review of 2026-10-31: after repair_text rewrote a summary marked
        stale (a repair edited a file outside the plan), only the edits were
        carried back, so the template re-check read summary_stale again and
        held the draft in every repository with a pull-request template."""
        import json
        from cognalys.llm.coordinated_generation import REVIEW_CONTRACT_VERSION

        class Client:
            def generate(self, prompt, system, **kwargs):
                return json.dumps({"title": "Use SHA-256 for note hashes",
                                   "summary": "`hash` used SHA-1. It now uses SHA-256."})

        reviewed = {"status": "reviewed", "review_contract_version": REVIEW_CONTRACT_VERSION,
                    "regressions": []}
        for template in (False, True):
            with self.subTest(template=template):
                pr = self.generate("maintainer_decision", repair_review=reviewed,
                                   template=template, text_client=Client(),
                                   summary_current=False)
                self.assertEqual(pr["text_problems"], [])
                self.assertFalse(pr.get("pr_held"))
                self.assertEqual(pr["repaired_patch_review_blocks"], [])

    def test_the_repaired_patchs_review_holds_a_publishable_draft(self):
        """Review of 2026-10-31: the verdict after validation applied only to
        review-only drafts, so a publishable draft whose repaired patch
        regressed, had no effect or was never reviewed came out
        READY_FOR_PUBLICATION."""
        from cognalys.llm.coordinated_generation import REVIEW_CONTRACT_VERSION

        publishable = {"decision": "MULTI_FILE_FIX_SUPPORTED", "publication_status": "",
                       "manual_review_required": False, "auto_apply": True,
                       "publication_allowed": True, "fix_scope": "coordinated"}
        reviewed = {"status": "reviewed", "review_contract_version": REVIEW_CONTRACT_VERSION}
        for label, review in (
                ("regression", {**reviewed, "regressions": [{"scenario": "the signer reads a null key"}]}),
                ("no_effect", {**reviewed, "regressions": [], "patch_has_no_effect": True,
                               "no_effect_reason": "same calls"}),
                ("not_run", {"status": "not_run", "regressions": []})):
            with self.subTest(review=label):
                pr = self.generate(overrides=publishable, repair_review=review)
                self.assertFalse(pr["publishable"])
                self.assertEqual(pr["preview_status"], "REVIEW_ONLY_NOT_PUBLISHABLE")
                self.assertTrue(pr["repaired_patch_review_blocks"])
        regressed = self.generate(overrides=publishable, repair_review={
            **reviewed, "regressions": [{"scenario": "the signer reads a null key"}]})
        self.assertTrue(any("null key" in line for line in regressed["review_blockers"]),
                        regressed["review_blockers"])
        clean = self.generate(overrides=publishable, repair_review={**reviewed, "regressions": []})
        self.assertEqual(clean["preview_status"], "READY_FOR_PUBLICATION", clean["text_problems"])
        self.assertTrue(clean["publishable"])
        self.assertEqual(clean["repaired_patch_review_blocks"], [])

    def test_an_orgzly_shaped_draft_is_ready_with_notes(self):
        pr = self.generate("maintainer_decision")
        self.assertEqual(pr["preview_status"], "READY_FOR_PUBLICATION_WITH_NOTES", pr["text_problems"])
        self.assertTrue(pr["publishable"])
        self.assertTrue(pr["publication_promoted_after_validation"])
        self.assertTrue(any("maintainer_decision" in note for note in pr["publication_notes"]))
        # The solution record's own flag is never rewritten.
        self.assertFalse(pr["publication_allowed"])
        self.assertEqual(pr["fix_scope"], "review_only")
        self.assertEqual(pr["decision_label"], "SINGLE_FILE_FIX_PROPOSED_FOR_REVIEW")

    def test_the_pr_record_carries_the_adjudications_impact_class(self):
        """M2: the class comes from the adjudication's runtime_security_impact;
        a draft with no adjudication records not_recorded. Nothing else moves."""
        without = self.generate("maintainer_decision")
        self.assertEqual(without["impact_class"], "not_recorded")
        rule_only = self.generate("maintainer_decision", overrides={"evidence_analysis": {
            "v2": {"adjudication": {"runtime_security_impact": "non_security"}}}})
        self.assertEqual(rule_only["impact_class"], "no_security_impact")
        for key in ("preview_status", "publishable", "title", "body", "text_problems"):
            self.assertEqual(rule_only[key], without[key], key)

    def test_a_salty_shaped_draft_with_an_evidence_gap_stays_review_only(self):
        pr = self.generate("maintainer_decision", "code_evidence_missing")
        self.assertEqual(pr["preview_status"], "REVIEW_ONLY_NOT_PUBLISHABLE")
        self.assertFalse(pr["publishable"])
        self.assertFalse(pr["publication_promoted_after_validation"])
        self.assertTrue(any(item.startswith("code_evidence_missing")
                            for item in pr["publication_verdict_blocks"]))
        self.assertFalse(pr["publication_allowed"])


class SpeakToTheMaintainerTests(unittest.TestCase):
    """The strategy is written for the model and the caveats for the operator."""

    def rewrite(self, text: str) -> str:
        from cognalys.utils.pr_text import speak_to_the_maintainer
        return speak_to_the_maintainer(text)

    def test_a_directive_to_generate_a_change_becomes_a_statement_about_it(self):
        text = (
            "Generate a reviewable coordinated source change that removes the "
            "compiled-in credential default from the Retrofit declaration."
        )
        self.assertEqual(
            self.rewrite(text),
            "This change removes the compiled-in credential default from the Retrofit declaration.",
        )
        self.assertEqual(
            self.rewrite("Produce a patch which cancels SSL errors."),
            "This change cancels SSL errors.",
        )

    def test_sentences_for_the_reviewer_or_the_pipeline_are_dropped(self):
        text = (
            "The callback always proceeds. "
            "The reviewer must approve the resulting request contract. "
            "This draft is review-only. "
            "Any credential rotation remains an external operational action."
        )
        self.assertEqual(
            self.rewrite(text),
            "The callback always proceeds. Any credential rotation remains an external operational action.",
        )

    def test_lists_quotes_and_ordinary_prose_are_left_alone(self):
        text = "Changes:\n\n- `A.kt`: The reviewer field is renamed.\n\n> The reviewer said so."
        self.assertEqual(self.rewrite(text), text)
        prose = "Reviews of this code found that proceed() ignores the error."
        self.assertEqual(self.rewrite(prose), prose)

    def test_nothing_is_ever_reduced_to_an_empty_summary(self):
        text = "The reviewer must approve this."
        self.assertEqual(self.rewrite(text), text)

    def test_the_body_uses_it(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "execution.json"
            report.write_text("{}", encoding="utf-8")
            body = PrGenerator(str(report), str(Path(directory) / "prs")).build_pr_body({
                "method_name": "getUpdate", "build_validation": {"status": "success"},
                "explanation": (
                    "The token is a default. Generate a reviewable coordinated source "
                    "change that removes it. The reviewer must approve the contract."
                ),
            }, "")
        self.assertIn("This change removes it.", body)
        self.assertNotIn("reviewer", body.lower())
        self.assertNotIn("Generate", body)


class EvidenceFactsInBodyTests(unittest.TestCase):
    """zSMTH (2026-10-17): the hosts checked and why a root is bundled were in
    the evidence, not in the pull request a maintainer would read."""

    def test_the_policy_facts_follow_the_summary_as_written(self):
        fact = "I checked the certificate chain of `www.example.org`: it leads to Root A."
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "execution.json"
            report.write_text("{}", encoding="utf-8")
            body = PrGenerator(str(report), str(Path(directory) / "prs"), style="v2").build_pr_body({
                "method_name": "build", "spec": "SSLContextSpec", "tool": "rvsec",
                "explanation": "The client trusted every certificate.",
                "build_validation": {"status": "success"},
                "compatibility_policy": {"case_migration_policy": {"maintainer_facts": [fact]}},
            }, "")
        summary = body.split("## How was this tested?")[0]
        self.assertIn("The client trusted every certificate.\n\n" + fact, summary)
        self.assertEqual(body.count(fact), 1)


class ReviewNotesInMetadataTests(unittest.TestCase):
    """Trigger's createKeyPair (2026-10-28): seven plan blockers and a "for the
    maintainer to decide" note on its ED25519 option stayed in the solution
    file, and nothing the operator read before approving showed them."""

    APK = "app.trigger.debug_1.apk"

    def make_run(self, directory: str, version=None) -> Path:
        import json

        run = Path(directory) / "run"
        report = run / "application_results" / "execution_report.json"
        report.parent.mkdir(parents=True)
        report.write_text("{}", encoding="utf-8")
        solutions = run / "error_solutions"
        metadata = {
            "csv_class": "app.trigger.ssh.GenerateIdentityTask", "method_name": "createKeyPair",
            "spec": "KeyPairGeneratorSpec",
            "review_assumptions": ["For the maintainer to decide: ED25519 now yields EC/256."],
        }
        if version is not None:
            metadata["review_contract_version"] = version
        (solutions / self.APK).mkdir(parents=True)
        (solutions / self.APK / "0_createKeyPair_solution.json").write_text(json.dumps({
            "solution_metadata": metadata,
            "evidence_analysis": {"v2": {"patch_plan": {
                "publication_blockers": ["Maintainer authorization for EC/256 is required."]}}},
        }), encoding="utf-8")
        review = solutions / "coordinated_drafts" / self.APK / "0_createKeyPair"
        review.mkdir(parents=True)
        (review / "behavior_review.json").write_text('{"status": "reviewed"}', encoding="utf-8")
        return report

    def solution(self, **extra) -> dict:
        return {"apk_name": self.APK, "csv_class": "app.trigger.ssh.GenerateIdentityTask",
                "method_name": "createKeyPair", "spec": "KeyPairGeneratorSpec", **extra}

    def test_the_solution_files_notes_reach_the_pull_request_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.make_run(directory, version=3)
            notes = PrGenerator(str(report), str(Path(directory) / "prs")).review_notes(
                self.solution(review_blockers=[{"code": "W", "maintainer_decides": True}]))

        self.assertEqual(notes["publication_blockers"],
                         ["Maintainer authorization for EC/256 is required."])
        self.assertEqual(notes["review_assumptions"],
                         ["For the maintainer to decide: ED25519 now yields EC/256."])
        # The execution report's own copy wins over the solution file's.
        self.assertEqual(notes["review_blockers"], [{"code": "W", "maintainer_decides": True}])
        self.assertEqual(notes["review_contract_version"], 3)
        self.assertTrue(notes["behavior_review_recorded"])

    def test_a_draft_from_before_review_contracts_records_none(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.make_run(directory)
            notes = PrGenerator(str(report), str(Path(directory) / "prs")).review_notes(
                self.solution())
        self.assertIsNone(notes["review_contract_version"])
        self.assertTrue(notes["behavior_review_recorded"])

    def test_a_missing_solution_file_leaves_the_review_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "execution.json"
            report.write_text("{}", encoding="utf-8")
            notes = PrGenerator(str(report), str(Path(directory) / "prs")).review_notes(
                self.solution())
        self.assertIsNone(notes["behavior_review_recorded"])
        self.assertEqual(notes["publication_blockers"], [])

    def test_the_fix_scope_is_read_from_the_solution_file_first(self):
        """The execution report defaults a missing scope to single_method,
        which would excuse a coordinated draft from the review."""
        import json

        with tempfile.TemporaryDirectory() as directory:
            report = self.make_run(directory)
            path = (Path(directory) / "run" / "error_solutions" / self.APK
                    / "0_createKeyPair_solution.json")
            data = json.loads(path.read_text(encoding="utf-8"))
            data["solution_metadata"]["fix_scope"] = "coordinated"
            path.write_text(json.dumps(data), encoding="utf-8")
            generator = PrGenerator(str(report), str(Path(directory) / "prs"))
            recorded = generator.review_notes(self.solution(fix_scope="single_method"))
            unknown = PrGenerator(str(Path(directory) / "none.json"),
                                  str(Path(directory) / "prs")).review_notes(
                self.solution(fix_scope="single_method"))
        self.assertEqual(recorded["fix_scope"], "coordinated")
        self.assertEqual(unknown["fix_scope"], "single_method")
