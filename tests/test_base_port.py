import json
import subprocess
import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.config.apply_solutions_config import ApplySolutionsConfig  # noqa: E402
from cognalys.solutions.base_port import (  # noqa: E402
    port_payload,
    port_to_base,
    validate_port,
)
from cognalys.solutions.solution_applicator import SolutionApplicator  # noqa: E402

PATH = "app/src/main/java/org/example/Client.kt"
ANALYSED = (
    "class Client {\n"
    "    fun trustAll() {\n"
    "        val managers = arrayOf<TrustManager>(object : X509TrustManager {})\n"
    "        context.init(null, managers, SecureRandom())\n"
    "    }\n"
    "}\n"
)
BASE = (
    "class Client {\n"
    "    fun trustAll() {\n"
    "        val manager = object : X509TrustManager {}\n"
    "        context.init(null, arrayOf(manager), SecureRandom())\n"
    "    }\n"
    "}\n"
)
REVIEWED_EDIT = {
    "source_file_path": PATH, "symbol": "trustAll", "edit_kind": "method",
    "original_code": "        val managers = arrayOf<TrustManager>(object : X509TrustManager {})\n"
                     "        context.init(null, managers, SecureRandom())\n",
    "corrected_code": "        context.init(null, null, SecureRandom())\n",
    "reason": "use the platform trust managers",
}
PORTED_EDIT = dict(
    REVIEWED_EDIT,
    original_code="        val manager = object : X509TrustManager {}\n"
                  "        context.init(null, arrayOf(manager), SecureRandom())\n",
)


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.run(["git", *arguments], cwd=repo, capture_output=True,
                          text=True, check=True).stdout.strip()


class FakeProvider:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.prompts = []

    def generate(self, prompt, system, **options):
        self.prompts.append(prompt)
        return json.dumps(self.answers.pop(0))


class BasePortTests(unittest.TestCase):
    """nextcloudcookbook's trust-all helper is still on main, refactored from
    an array literal to a single object; the reviewed edit no longer anchors
    and the three-way merge conflicts on the very lines it changes."""

    def _repo(self, directory: str) -> tuple[Path, str]:
        repo = Path(directory) / "repo"
        (repo / PATH).parent.mkdir(parents=True)
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "config", "user.email", "t@example.invalid")
        _git(repo, "config", "user.name", "Test")
        (repo / PATH).write_text(ANALYSED, encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "analysed")
        analysed = _git(repo, "rev-parse", "HEAD")
        (repo / PATH).write_text(BASE, encoding="utf-8")
        _git(repo, "commit", "-qam", "refactor the trust manager")
        base = _git(repo, "rev-parse", "HEAD")
        _git(repo, "checkout", "-q", "--detach", analysed)
        return repo, base

    def _worktree(self, directory: str) -> Path:
        worktree = Path(directory) / "worktree"
        (worktree / PATH).parent.mkdir(parents=True)
        (worktree / PATH).write_text(BASE, encoding="utf-8")
        return worktree

    def _solution(self):
        return {"finding_id": "f1", "spec": "SSLContextSpec",
                "method_name": "trustAll", "source_file_path": PATH,
                "coordinated_edits": [dict(REVIEWED_EDIT)]}

    def test_the_payload_shows_what_upstream_changed_and_the_base_file(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, base = self._repo(directory)
            payload = port_payload(self._solution(), repo,
                                   self._worktree(directory), base)
            [file] = payload["files_on_base"]
            self.assertEqual(file["content_on_base"], BASE)
            self.assertIn("+        val manager = object : X509TrustManager {}",
                          file["upstream_diff_since_analysed_revision"])

    def test_a_port_anchored_on_the_base_is_applied(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, base = self._repo(directory)
            worktree = self._worktree(directory)
            provider = FakeProvider({"decision": "PORT", "explanation": "re-anchored",
                                     "edits": [PORTED_EDIT]})
            applied = []

            def apply(ported):
                edit = ported["coordinated_edits"][0]
                text = (worktree / PATH).read_text(encoding="utf-8")
                if text.count(edit["original_code"]) != 1:
                    return False, [], f"ORIGINAL_CODE_NOT_FOUND:{PATH}"
                applied.append(edit)
                return True, [{"source_file": PATH}], ""

            port = port_to_base(provider, self._solution(), repo, worktree, base,
                                apply)

            self.assertTrue(port["applied"])
            self.assertEqual(applied[0]["corrected_code"],
                             REVIEWED_EDIT["corrected_code"])

    def test_a_rejected_port_goes_back_once_with_the_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, base = self._repo(directory)
            outside = dict(PORTED_EDIT, source_file_path="build.gradle")
            provider = FakeProvider(
                {"decision": "PORT", "explanation": "", "edits": [outside]},
                {"decision": "PORT", "explanation": "", "edits": [PORTED_EDIT]},
            )

            port = port_to_base(provider, self._solution(), repo,
                                self._worktree(directory), base,
                                lambda ported: (True, [], ""))

            self.assertTrue(port["applied"])
            self.assertIn("PORT_EDIT_OUTSIDE_REVIEWED_FILES:build.gradle",
                          provider.prompts[1])
            self.assertEqual(len(port["attempts"]), 1)

    def test_a_port_that_never_applies_is_reported_not_applied(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, base = self._repo(directory)
            provider = FakeProvider(
                {"decision": "PORT", "explanation": "", "edits": [REVIEWED_EDIT]},
                {"decision": "PORT", "explanation": "", "edits": [REVIEWED_EDIT]},
            )

            port = port_to_base(
                provider, self._solution(), repo, self._worktree(directory), base,
                lambda ported: (False, [], f"ORIGINAL_CODE_NOT_FOUND:{PATH}"),
            )

            self.assertFalse(port["applied"])
            self.assertEqual(port["error"], f"ORIGINAL_CODE_NOT_FOUND:{PATH}")

    def test_semantic_objections_reject_a_port(self):
        with tempfile.TemporaryDirectory() as directory:
            repo, base = self._repo(directory)
            provider = FakeProvider(
                {"decision": "PORT", "explanation": "", "edits": [PORTED_EDIT]},
                {"decision": "ABSTAIN", "explanation": "cannot", "edits": []},
            )

            port = port_to_base(
                provider, self._solution(), repo, self._worktree(directory), base,
                lambda ported: (True, [], ""),
                semantic_check=lambda ported: [
                    {"code": "TRUST_ALL", "details": ["still trusts all"]}],
            )

            self.assertEqual(port["decision"], "ABSTAIN")
            self.assertIn("PORT_VIOLATES_SEMANTIC_GATES:TRUST_ALL",
                          provider.prompts[1])

    def test_validate_port_refuses_an_empty_original(self):
        self.assertEqual(
            validate_port({"decision": "PORT", "edits": [
                dict(PORTED_EDIT, original_code="  ")]}, self._solution()),
            f"PORT_EMPTY_ORIGINAL:{PATH}",
        )

    def _gone_repo(self, directory: str) -> tuple[Path, str]:
        """The base dropped the trust-all call: the reported line is nowhere on it."""
        repo, _ = self._repo(directory)
        _git(repo, "checkout", "-q", "-b", "gone", "main")
        (repo / PATH).write_text("class Client {\n    fun trustAll() {\n    }\n}\n",
                                 encoding="utf-8")
        _git(repo, "commit", "-qam", "drop the trust-all helper")
        gone = _git(repo, "rev-parse", "HEAD")
        _git(repo, "checkout", "-q", "--detach", "HEAD~2")
        return repo, gone

    def _reported(self):
        # The detector reported line 4, context.init(null, managers, SecureRandom()).
        return dict(self._solution(), detector_context={"source_location": "Client.kt:4"})

    def test_a_violation_gone_from_the_base_makes_the_finding_not_applicable(self):
        """Giggity's maintainer removed the MD5 hashCode; that is not a
        failed patch and not a false positive. B5: only when a deterministic
        check confirms the port's answer, here the reported statement being on
        no file of the base."""
        with tempfile.TemporaryDirectory() as directory:
            repo, base = self._gone_repo(directory)
            applicator = SolutionApplicator(ApplySolutionsConfig(port_model="m"))
            applicator._port_client = FakeProvider({
                "decision": "ALREADY_FIXED_UPSTREAM",
                "explanation": "the base no longer calls init", "edits": [],
            })
            result = {}

            port = applicator._port_to_base(
                self._reported(), None, self._worktree(directory), repo, base, result)

            self.assertEqual(port["decision"], "ALREADY_FIXED_UPSTREAM")
            self.assertEqual(result["status"], "NOT_APPLICABLE_TO_BASE")
            self.assertEqual(result["error"], "ORIGINAL_CODE_ABSENT_FROM_BASE_BRANCH")
            self.assertTrue(result["contribution_base"]["violation_absent_per_port"])
            self.assertIn("in no file of the base", result["base_port"]["confirmation"])

    def test_an_unconfirmed_already_fixed_answer_is_an_abstention(self):
        """B5: the base still makes the reported call (refactored around it),
        so the model's ALREADY_FIXED_UPSTREAM is not taken: the finding stays a
        generated correction a person reads, not a correction not applicable."""
        with tempfile.TemporaryDirectory() as directory:
            repo, base = self._repo(directory)
            applicator = SolutionApplicator(ApplySolutionsConfig(port_model="m"))
            applicator._port_client = FakeProvider({
                "decision": "ALREADY_FIXED_UPSTREAM",
                "explanation": "the base no longer uses the array", "edits": [],
            })
            result = {}

            port = applicator._port_to_base(
                self._reported(), None, self._worktree(directory), repo, base, result)

            self.assertEqual(port["decision"], "ABSTAIN")
            self.assertEqual(port["error"], "PORT_ALREADY_FIXED_UNCONFIRMED")
            self.assertEqual(result["base_port"]["model_decision"], "ALREADY_FIXED_UPSTREAM")
            self.assertNotIn("status", result)
            self.assertNotIn("contribution_base", result)

    def test_the_corrected_code_already_on_the_base_confirms_it(self):
        from cognalys.solutions.solution_applicator import port_already_fixed_confirmation

        with tempfile.TemporaryDirectory() as directory:
            repo, _ = self._repo(directory)
            _git(repo, "checkout", "-q", "-b", "fixed", "main")
            (repo / PATH).write_text(
                "class Client {\n    fun trustAll() {\n"
                + REVIEWED_EDIT["corrected_code"] + "    }\n}\n", encoding="utf-8")
            _git(repo, "commit", "-qam", "use the platform trust managers")
            fixed = _git(repo, "rev-parse", "HEAD")
            _git(repo, "checkout", "-q", "--detach", "HEAD~2")
            # No reported line known: the edit's corrected code decides.
            self.assertIn("already on the base",
                          port_already_fixed_confirmation(self._solution(), repo, fixed))

    def _port_with(self, directory, *answers):
        """_port_to_base with a client answering ``answers`` in order, the
        applicator writing the ported edit into the worktree."""
        repo, base = self._repo(directory)
        worktree = self._worktree(directory)
        applicator = SolutionApplicator(ApplySolutionsConfig(port_model="m"))
        provider = FakeProvider(*answers)
        applicator._port_client = provider

        def apply_edits(ported, _mapper, root):
            edit = ported["coordinated_edits"][0]
            text = (root / PATH).read_text(encoding="utf-8")
            if text.count(edit["original_code"]) != 1:
                return False, [], f"ORIGINAL_CODE_NOT_FOUND:{PATH}"
            (root / PATH).write_text(text.replace(edit["original_code"], edit["corrected_code"]),
                                     encoding="utf-8")
            return True, [{"source_file": PATH}], ""

        applicator._apply_coordinated_edits = apply_edits
        result = {}
        port = applicator._port_to_base(self._solution(), None, worktree, repo, base, result)
        return port, result, provider

    def test_a_port_that_only_re_anchors_the_correction_is_not_reviewed_again(self):
        """B6: the same corrected code on the base's lines needs no new review."""
        with tempfile.TemporaryDirectory() as directory:
            port, result, provider = self._port_with(
                directory, {"decision": "PORT", "explanation": "re-anchored",
                            "edits": [PORTED_EDIT]})
        self.assertTrue(port["applied"])
        self.assertEqual(len(provider.prompts), 1)
        self.assertNotIn("behavior_reviews", result["base_port"])

    def test_a_port_that_rewrites_the_correction_is_reviewed(self):
        """B6: a regression the review finds rejects the port, which goes back
        once with the scenario; the second port passes a clean review."""
        rewritten = dict(PORTED_EDIT, corrected_code=(
            "        context.init(null, arrayOf(PinnedManager()), SecureRandom())\n"))
        clean = {"regressions": [], "maintainer_decision_required": False,
                 "maintainer_decision": "", "rationale": ""}
        regression = dict(clean, regressions=[{
            "source_file_path": PATH, "scenario": "pinning rejects the user's server",
            "before": "b", "after": "a"}])
        with tempfile.TemporaryDirectory() as directory:
            port, result, provider = self._port_with(
                directory,
                {"decision": "PORT", "explanation": "", "edits": [rewritten]},
                regression,
                {"decision": "PORT", "explanation": "", "edits": [PORTED_EDIT]})
        # The second port only re-anchors: no second review.
        self.assertTrue(port["applied"])
        self.assertEqual(len(provider.prompts), 3)
        self.assertIn("PORT_BEHAVIOR_REGRESSION", provider.prompts[2])
        self.assertIn("pinning rejects the user's server", provider.prompts[2])
        [review] = result["base_port"]["behavior_reviews"]
        self.assertEqual(review["status"], "reviewed")
        self.assertEqual(len(review["regressions"]), 1)

    def test_porting_is_off_without_a_model(self):
        applicator = SolutionApplicator(ApplySolutionsConfig())
        self.assertEqual(
            applicator._port_to_base(self._solution(), None, Path("."), Path("."),
                                     "abc", {}),
            {},
        )


if __name__ == "__main__":
    unittest.main()
