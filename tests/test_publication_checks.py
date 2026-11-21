import base64
import contextlib
import io
import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs import publication_checks  # noqa: E402

# tuisku's README (omaawr/tuisku), which closed tuisku#11.
TUISKU_README = """# Tuisku
Encrypted notes.

### AI disclaimer
AI generated code is not permitted in this repository.

Pull requests that have AI assistance are not really allowed and would be rejected.
"""

ORIGINAL = "class A {\n    int hash() {\n        return md5(name);\n    }\n}\n"
FIXED = "class A {\n    int hash() {\n        return name.hashCode();\n    }\n}\n"
DIFF = """diff --git a/src/A.java b/src/A.java
index 1111111..2222222 100644
--- a/src/A.java
+++ b/src/A.java
@@ -1,5 +1,5 @@
 class A {
     int hash() {
-        return md5(name);
+        return name.hashCode();
     }
 }
"""


def fake_github(files: dict):
    """get(url, params) over a repository whose default branch holds ``files``."""
    def get(url, params=None):
        path = url.split("/contents", 1)[1].lstrip("/")
        if path in files:
            return {"path": path, "content": base64.b64encode(files[path].encode()).decode()}
        prefix = f"{path}/" if path else ""
        listing = [{"path": name, "type": "file"} for name in files
                   if name.startswith(prefix) and "/" not in name[len(prefix):]]
        return listing or None
    return get


def blockers(files, diff=DIFF, **options):
    metadata = {"repo_owner": "o", "repo_name": "r", "base_branch": "main", "diff": diff}
    return publication_checks.publication_blockers(metadata, fake_github(files), **options)


def blockers_and_output(files, **options):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        found = blockers(files, **options)
    return found, output.getvalue()


class AiPolicyTests(unittest.TestCase):
    """A policy is reported, never a blocker: the operator writes that PR or issue."""

    def test_tuiskus_readme_is_a_policy_noted_not_blocked(self):
        found, output = blockers_and_output({"README.md": TUISKU_README, "src/A.java": ORIGINAL})
        self.assertEqual(found, [])
        self.assertIn("restricts AI-assisted contributions", output)
        self.assertIn("AI generated code is not permitted", output)
        self.assertIn("Write this contribution's text yourself", output)

    def test_a_policy_in_contributing_or_the_pr_template_counts(self):
        for path in ("CONTRIBUTING.md", ".github/PULL_REQUEST_TEMPLATE.md"):
            files = {path: "Contributions written with ChatGPT or Copilot must be disclosed."}
            self.assertIsNotNone(publication_checks.ai_policy(files), path)

    def test_an_app_without_ai_is_not_a_policy(self):
        files = {"README.md": "No ads, no AI, no tracking. Contributions welcome!\n"
                              "This app does not use AI features.",
                 "src/A.java": ORIGINAL}
        found, output = blockers_and_output(files)
        self.assertEqual(found, [])
        self.assertNotIn("AI-assisted", output)

    def test_the_waiver_silences_the_note(self):
        files = {"README.md": TUISKU_README, "src/A.java": ORIGINAL}
        found, output = blockers_and_output(files, allow_ai_policy=True)
        self.assertEqual(found, [])
        self.assertNotIn("AI-assisted", output)


APP_MANAGER_CONTRIBUTING = (
    "Pull or merge requests must be authored by the\n"
    "human author(s) submitting the pull or merge request. By submitting a pull or\n"
    "merge request, you affirm that the code was authored by you without the use of\n"
    "generative AI tools that produce functional code blocks.\n\nRules\n-----\n")


class AiAffirmationTests(unittest.TestCase):
    """App Manager (2026-11-01): submitting affirms that no AI was used."""

    def test_an_affirmation_on_submission_is_a_warning_never_a_blocker(self):
        """CLAUDE.md: a "no AI" policy is a note for the user, never a blocker."""
        files = {"CONTRIBUTING.rst": APP_MANAGER_CONTRIBUTING, "src/A.java": ORIGINAL}
        policy = publication_checks.ai_policy(files)
        self.assertEqual(policy["kind"], "affirmation_required")
        self.assertIn("you affirm that the code was authored by you", policy["statement"])
        for options in ({}, {"allow_ai_policy": True}):
            found, output = blockers_and_output(files, **options)
            self.assertEqual(found, [])
            self.assertIn("WARNING", output)
            self.assertIn("without the use of generative AI tools", output)

    def test_the_policy_recorded_with_the_draft_is_warned_when_the_remote_says_nothing(self):
        metadata = {"repo_owner": "o", "repo_name": "r", "base_branch": "main", "diff": DIFF,
                    "ai_policy": {"kind": "affirmation_required", "path": "CONTRIBUTING.rst",
                                  "statement": "you affirm ... without generative AI"}}
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            found = publication_checks.publication_blockers(metadata, fake_github({"src/A.java": ORIGINAL}))
        self.assertEqual(found, [])
        self.assertIn("you affirm ... without generative AI", output.getvalue())

    def test_a_negation_that_does_not_govern_ai_is_no_affirmation(self):
        """2026-11-01 review: a license clause and a review reminder."""
        for text in ("By submitting a pull request, you agree that your contribution, whether "
                     "AI-assisted or not, is licensed under the MIT license.",
                     "By submitting a PR, you confirm that you tested it and that any "
                     "AI-generated code was reviewed, not pasted blindly."):
            policy = publication_checks.ai_policy({"CONTRIBUTING.md": text})
            self.assertTrue(policy is None or policy["kind"] != "affirmation_required", text)
        self.assertEqual(publication_checks.ai_policy({"CONTRIBUTING.md": (
            "By opening a pull request you confirm the code was not generated by AI.")})["kind"],
            "affirmation_required")

    def test_the_preview_shows_the_affirmation_warning_first(self):
        from cognalys.prs.generate_github_previews import operator_notes
        notes = operator_notes({"ai_policy": {"kind": "affirmation_required",
                                                 "path": "CONTRIBUTING.rst", "statement": "S"}})
        self.assertIn("WARNING", notes[0])

    def test_a_template_box_affirming_it_is_an_affirmation(self):
        files = {".github/PULL_REQUEST_TEMPLATE/pull_request.md":
                 "- [ ] I know that generating a PR or its code, in whole or in part, "
                 "using AI/LLM is prohibited.\n"}
        self.assertEqual(publication_checks.ai_policy(files)["kind"], "affirmation_required")

    def test_a_plain_restriction_stays_a_note(self):
        files = {"README.md": TUISKU_README, "src/A.java": ORIGINAL}
        self.assertEqual(publication_checks.ai_policy(files)["kind"], "restriction")
        self.assertEqual(blockers(files), [])

    def test_policy_files_are_read_from_a_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github").mkdir()
            (root / "CONTRIBUTING.rst").write_text(APP_MANAGER_CONTRIBUTING, encoding="utf-8")
            (root / ".github" / "CODEOWNERS").write_text("* @x", encoding="utf-8")
            files = publication_checks.policy_files_in_checkout(root)
            self.assertEqual(sorted(files), ["CONTRIBUTING.rst"])


class ClosedRepositoryTests(unittest.TestCase):
    """idunnololz/summit#54: "Please note that I am currently not accepting PRs."."""

    def test_a_project_not_accepting_prs_is_blocked_unless_waived(self):
        for statement in ("Please note that I am currently not accepting PRs. This repo is "
                          "still mostly meant for me.",
                          "We do not accept pull requests at this time.",
                          "This project is no longer accepting contributions.",
                          "The repository is not open to outside contributions."):
            files = {"README.md": statement, "src/A.java": ORIGINAL}
            [found] = blockers(files)
            self.assertIn("does not accept contributions", found, statement)
            self.assertEqual(blockers(files, allow_closed_repository=True), [], statement)

    def test_an_open_project_or_an_unrelated_sentence_is_not_closed(self):
        for statement in ("Contributions welcome! Pull requests are accepted.",
                          "The app does not accept self-signed certificates.",
                          "PRs that fail CI are not merged."):
            files = {"README.md": statement, "src/A.java": ORIGINAL}
            self.assertEqual(blockers(files), [], statement)


class UpstreamTests(unittest.TestCase):
    def test_a_diff_that_still_applies_passes(self):
        self.assertEqual(blockers({"src/A.java": ORIGINAL}), [])

    def test_a_change_the_maintainer_already_made_is_blocked(self):
        """giggity#543: 'Oh, just made this change myself independently.'"""
        [found] = blockers({"src/A.java": FIXED})
        self.assertIn("already contains this change", found)
        # Not waivable: there is nothing left to propose.
        self.assertEqual(len(blockers({"src/A.java": FIXED}, allow_changed_upstream=True)), 1)

    def test_code_that_moved_on_is_blocked_unless_waived(self):
        moved = ORIGINAL.replace("md5(name)", "sha1(name)")
        [found] = blockers({"src/A.java": moved})
        self.assertIn("analyse the finding again", found)
        self.assertEqual(blockers({"src/A.java": moved}, allow_changed_upstream=True), [])

    def test_an_unreadable_file_does_not_block(self):
        self.assertEqual(blockers({}), [])

    def test_a_new_file_needs_nothing_upstream(self):
        diff = ("diff --git a/src/B.java b/src/B.java\nnew file mode 100644\nindex 0000000..3333333\n"
                "--- /dev/null\n+++ b/src/B.java\n@@ -0,0 +1 @@\n+class B {}\n")
        state = publication_checks.upstream_state(diff, lambda path: None)
        self.assertEqual(state["state"], "applies")

    def test_a_diff_of_only_tests_is_blocked(self):
        """FreeOTP#521: merged, but the finding stayed where it was."""
        path = "mobile/src/androidTest/java/A.java"
        diff = DIFF.replace("src/A.java", path)
        [found] = blockers({path: ORIGINAL}, diff=diff)
        self.assertIn("changes only tests", found)
        # Not waivable either: nothing in it fixes the finding.
        self.assertEqual(len(blockers({path: ORIGINAL}, diff=diff, allow_changed_upstream=True)), 1)

    def test_a_submodule_pointer_does_not_make_the_check_unknown(self):
        """Clash Fest (2026-10-28): the contents API has no file for a
        submodule path, and one "Subproject commit" section made the whole
        check give up."""
        diff = DIFF + ("diff --git a/core/clash b/core/clash\n--- a/core/clash\n+++ b/core/clash\n"
                       "@@ -1 +1 @@\n-Subproject commit 3f27ef39\n+Subproject commit 3f27ef39-dirty\n")
        files = {"src/A.java": ORIGINAL}
        state = publication_checks.upstream_state(
            diff, lambda path: files[path].encode() if path in files else None)
        self.assertEqual(state["state"], "applies")
        self.assertEqual(state["paths"], ["src/A.java"])
        self.assertIn("src/A.java", publication_checks.without_submodule_pointers(diff))


class StaleReviewTests(unittest.TestCase):
    """Syncthing-Lite's draft (2026-10-25) renamed a constant to one with the
    same value, and stayed approvable: it predates the review that rejects it."""

    def test_a_draft_without_a_recorded_contract_is_stale(self):
        self.assertIn("no behaviour review ran", publication_checks.stale_review(None, False, 3))
        self.assertIn("predates", publication_checks.stale_review(None, True, 3))
        self.assertIn("no behaviour review contract", publication_checks.stale_review("", None, 3))

    def test_an_older_contract_is_stale_and_the_current_one_is_not(self):
        self.assertIn("contract 2; the current one is 3",
                      publication_checks.stale_review(2, True, 3))
        self.assertEqual(publication_checks.stale_review(3, True, 3), "")
        current = publication_checks.current_review_contract_version()
        self.assertEqual(publication_checks.stale_review(current), "")

    def test_a_path_without_the_review_is_not_stale_but_says_so(self):
        """Grocy's insertConscrypt came from the single-method path, which
        writes no behaviour review; a rerun takes the same path."""
        self.assertEqual(publication_checks.stale_review(None, False, 3, fix_scope="single_method"), "")
        self.assertIn("a rerun will not add one",
                      publication_checks.review_absent_by_design("single_method"))
        self.assertEqual(publication_checks.review_absent_by_design("coordinated"), "")
        # A recorded review is judged by its contract, whatever the path.
        self.assertEqual(publication_checks.review_absent_by_design("single_method", 3), "")
        self.assertIn("contract 2", publication_checks.stale_review(2, True, 3, fix_scope="single_method"))


class ReviewJudgedDraftTests(unittest.TestCase):
    """A review file is written for an outage too: a draft completed through
    one was reported as a review that "predates the review contract versions"."""

    def judged(self, metadata, review):
        from cognalys.llm.fix_artifacts import review_judged_draft

        return review_judged_draft(metadata, review)

    def test_the_statuses_are_the_ones_the_review_writes(self):
        """coordinated_generation imports fix_artifacts, so the set is a copy."""
        from cognalys.llm import coordinated_generation
        from cognalys.llm.fix_artifacts import REVIEWED_STATUSES

        written = getattr(coordinated_generation, "REVIEWED_STATUSES",
                          getattr(coordinated_generation, "_REVIEWED_STATUSES", None))
        self.assertEqual(REVIEWED_STATUSES, written)

    def test_only_a_review_that_judged_the_draft_counts(self):
        self.assertTrue(self.judged({"review_contract_version": 3}, {"status": "reviewed"}))
        self.assertTrue(self.judged({}, {"status": "all_edits_on_base"}))
        self.assertFalse(self.judged({}, {"status": "not_run"}))
        self.assertFalse(self.judged({}, {}))
        # A version the draft recorded says the review judged it.
        self.assertTrue(self.judged({"review_contract_version": 3}, {"status": "other"}))

    def test_an_explicitly_recorded_none_is_not_a_review(self):
        # finding_processing records None when the review did not judge the draft.
        self.assertFalse(self.judged({"review_contract_version": None}, {"status": "reviewed"}))
        self.assertFalse(self.judged({"review_contract_version": None}, {"status": "not_run"}))

    def test_an_older_draft_without_the_key_is_decided_by_its_review_file(self):
        self.assertTrue(self.judged({}, {"status": "reviewed"}))
        # A review file from before statuses were written.
        self.assertTrue(self.judged({}, {"regressions": []}))

    def test_the_outage_then_reads_as_no_review(self):
        reviewed = self.judged({"review_contract_version": None}, {"status": "not_run"})
        self.assertEqual(publication_checks.stale_review(None, reviewed, 3),
                         "no behaviour review ran on this draft")


class PublishedPullRequestTests(unittest.TestCase):
    """One answer to "was this draft already published?" for pr_creator, the
    preview and the statistics."""

    def published(self, record):
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            draft = Path(directory) / "app.apk_m_S_pr.json"
            draft.write_text("{}", encoding="utf-8")
            if record is not None:
                Path(directory, "app.apk_m_S_pr_created.json").write_text(
                    record if isinstance(record, str) else json.dumps(record),
                    encoding="utf-8")
            return publication_checks.published_pull_request(draft)

    def test_the_creation_record_names_the_pull_request(self):
        self.assertEqual(self.published({"dry_run": False, "html_url": "https://github.com/o/r/pull/7"}),
                         "https://github.com/o/r/pull/7")
        self.assertEqual(self.published({"html_url": "https://github.com/o/r/pull/7"}),
                         "https://github.com/o/r/pull/7")

    def test_a_dry_run_a_missing_or_a_broken_record_is_not_a_publication(self):
        self.assertEqual(self.published({"dry_run": True, "html_url": "https://x/pull/1"}), "")
        self.assertEqual(self.published(None), "")
        self.assertEqual(self.published("{not json"), "")
        self.assertEqual(self.published([1]), "")



class AllowlistStatementTests(unittest.TestCase):
    """zSMTH's summary said the rule allows "only TLSv1.2 or TLSv1.3"."""

    message = "expecting one of TLSV1.2,TLSV1.3,TLS but found SSL"

    def test_the_reported_allowlist_is_read_in_both_shapes(self):
        from cognalys.utils.pr_text import reported_allowlist

        self.assertEqual(reported_allowlist(self.message), ["TLSV1.2", "TLSV1.3", "TLS"])
        self.assertEqual(reported_allowlist("expecting one of {SHA-256, SHA-512} but found MD5"),
                         ["SHA-256", "SHA-512"])
        self.assertEqual(reported_allowlist("expecting one of {AES, ...} but found DES"), [])

    def test_naming_only_part_of_the_allowlist_is_a_problem(self):
        from cognalys.utils.pr_text import text_problems

        wrong = ("## Summary\n\nThe selector violates the requirement that allows only "
                 "`TLSv1.2` or `TLSv1.3`.\n")
        right = ("## Summary\n\nThe rule accepts only `TLSv1.2`, `TLSv1.3` or the "
                 "negotiating `TLS` selector. The client now uses `TLS`.\n")
        self.assertTrue(any("accepts only some" in item
                            for item in text_problems("Restore certificate checks", wrong, self.message)))
        self.assertEqual(text_problems("Restore certificate checks", right, self.message), [])
        # zSMTH run7: a sentence about the client's versions is not about the rule.
        client = ("## Summary\n\nOkHttp 4.12.0 already negotiates only TLS 1.2 and 1.3 by "
                  "default, so no protocol filter was added.\n")
        self.assertEqual(text_problems("Restore certificate checks", client, self.message), [])
        # Without the finding's message nothing is judged.
        self.assertEqual(text_problems("Restore certificate checks", wrong), [])



class IssueLiveCheckTests(unittest.TestCase):
    """An issue gets the live checks that make sense for it (A7).

    The issue path called none of publication_blockers: it would open an
    issue on a repository closed to contributions, or about code the default
    branch no longer has.
    """

    SOURCE = 'class A {\n    byte[] hash(byte[] d) {\n        return MessageDigest.getInstance("MD5").digest(d);\n    }\n}\n'
    STATEMENT = 'return MessageDigest.getInstance("MD5").digest(d);'

    def _blockers(self, files, **options):
        metadata = {"repo_owner": "o", "repo_name": "r", "source_file": "src/A.java",
                    "method_name": "hash", "reported_statement": self.STATEMENT}
        metadata.update(options.pop("metadata", {}))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            found = publication_checks.issue_publication_blockers(
                metadata, fake_github(files), **options)
        return found, output.getvalue()

    def test_a_repository_closed_to_contributions_blocks_unless_waived(self):
        files = {"README.md": "Please note that I am currently not accepting PRs.",
                 "src/A.java": self.SOURCE}
        found, _ = self._blockers(files)
        self.assertEqual(len(found), 1)
        self.assertIn("--allow-closed-repository", found[0])
        self.assertEqual(self._blockers(files, allow_closed_repository=True)[0], [])

    def test_an_ai_policy_is_a_note_never_a_block(self):
        found, printed = self._blockers({"README.md": TUISKU_README, "src/A.java": self.SOURCE})
        self.assertEqual(found, [])
        self.assertIn("restricts AI-assisted contributions", printed)

    def test_the_reported_statement_gone_from_the_default_branch_blocks_unless_waived(self):
        fixed = self.SOURCE.replace('"MD5"', '"SHA-256"')
        found, _ = self._blockers({"src/A.java": fixed})
        self.assertEqual(len(found), 1)
        self.assertIn("--allow-changed-upstream", found[0])
        self.assertEqual(self._blockers({"src/A.java": fixed}, allow_changed_upstream=True)[0], [])
        # Still there, reformatted over two lines: present.
        wrapped = self.SOURCE.replace("getInstance(", "getInstance(\n            ")
        self.assertEqual(self._blockers({"src/A.java": wrapped})[0], [])

    def test_a_deleted_file_blocks_and_an_unreadable_one_does_not(self):
        found, _ = self._blockers({"src/B.java": "class B {}\n"})
        self.assertIn("src/A.java does not exist", found[0])
        # Nothing could be read at all: a note, not a block.
        found, printed = self._blockers({})
        self.assertEqual(found, [])
        self.assertIn("could not check", printed)

    def test_without_a_statement_the_method_is_looked_for(self):
        found, _ = self._blockers({"src/A.java": "class A {\n    void other() {}\n}\n"},
                                  metadata={"reported_statement": ""})
        self.assertIn("no longer has hash", found[0])
        self.assertEqual(self._blockers({"src/A.java": self.SOURCE},
                                        metadata={"reported_statement": ""})[0], [])

    def test_an_issue_to_an_upstream_library_is_not_looked_for_here(self):
        found, _ = self._blockers({"src/B.java": "class B {}\n"},
                                  metadata={"issue_target": "upstream_library"})
        self.assertEqual(found, [])

    def test_the_candidate_records_the_reported_line_of_the_analysed_checkout(self):
        from cognalys.llm.issue_candidates import _reported_statement

        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "src").mkdir()
            (Path(directory) / "src" / "A.java").write_text(self.SOURCE, encoding="utf-8")
            error = {"repository_path": directory, "source_file_path": "src/A.java",
                     "source_line_hint": 3}
            self.assertEqual(_reported_statement(error), self.STATEMENT)
            # A line without a call, or no line at all, records nothing.
            self.assertEqual(_reported_statement({**error, "source_line_hint": 1}), "")
            self.assertEqual(_reported_statement({**error, "source_line_hint": None}), "")


if __name__ == "__main__":
    unittest.main()
