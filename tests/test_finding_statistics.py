import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (scripts/ and src/ on sys.path)


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "finding_statistics", ROOT / "src" / "cognalys" / "reporting" / "finding_statistics.py")
STATS = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = STATS
SPEC.loader.exec_module(STATS)


class WilsonIntervalTests(unittest.TestCase):
    def test_a_known_interval(self):
        # 3 of 109: the PR-ready share of run_20261009_012517.
        low, high = STATS.wilson(3, 109)
        self.assertAlmostEqual(low, 0.0094, places=3)
        self.assertAlmostEqual(high, 0.0778, places=3)

    def test_no_observations_gives_an_empty_interval(self):
        self.assertEqual(STATS.wilson(0, 0), (0.0, 0.0))


class CohenKappaTests(unittest.TestCase):
    def test_perfect_agreement_is_one(self):
        self.assertEqual(STATS.cohen_kappa([("a", "a"), ("b", "b")]), 1.0)

    def test_a_textbook_value(self):
        # 20 yes/yes, 5 yes/no, 10 no/yes, 15 no/no: po=0.7, pe=0.5, k=0.4.
        pairs = ([("y", "y")] * 20 + [("y", "n")] * 5
                 + [("n", "y")] * 10 + [("n", "n")] * 15)
        self.assertAlmostEqual(STATS.cohen_kappa(pairs), 0.4)


class CombineAndOutcomeTests(unittest.TestCase):
    def test_the_latest_run_that_processed_a_finding_wins(self):
        key_a, key_b = ("a.apk", "C", "m", "S"), ("b.apk", "D", "n", "T")
        runs = {
            "run_1": {key_a: {"extraction_status": "success", "analysed": True, "run": "run_1"},
                      key_b: {"extraction_status": "success", "run": "run_1"}},
            "run_2": {key_b: {"extraction_status": "success", "analysed": True, "run": "run_2"}},
        }
        combined = STATS.combine_runs(runs)
        self.assertEqual(combined[key_a]["run"], "run_1")
        self.assertEqual(combined[key_b]["run"], "run_2")

    def test_a_later_extraction_does_not_erase_an_analysis(self):
        """run_20261011_161752 extracted all 109 findings and analysed 14."""
        key = ("a.apk", "C", "m", "S")
        runs = {
            "run_1": {key: {"extraction_status": "success", "analysed": True, "run": "run_1"}},
            "run_2": {key: {"extraction_status": "success", "run": "run_2"}},
        }
        self.assertEqual(STATS.combine_runs(runs)[key]["run"], "run_1")

    def test_a_finding_never_analysed_comes_from_its_latest_extraction(self):
        key = ("a.apk", "C", "m", "S")
        runs = {
            "run_1": {key: {"extraction_status": "success", "run": "run_1"}},
            "run_2": {key: {"extraction_status": "external_dependency_candidate", "run": "run_2"}},
        }
        self.assertEqual(STATS.combine_runs(runs)[key]["run"], "run_2")

    def test_a_reason_for_not_analysing_survives_a_later_bare_extraction(self):
        key = ("a.apk", "C", "m", "S")
        runs = {
            "run_1": {key: {"extraction_status": "external_dependency_candidate",
                            "not_analysed_reason": "biblioteca sem código nem bytecode",
                            "run": "run_1"}},
            "run_2": {key: {"extraction_status": "external_dependency_candidate", "run": "run_2"}},
        }
        self.assertEqual(STATS.combine_runs(runs)[key]["run"], "run_1")

    def test_a_fix_the_base_branch_cannot_take_is_not_a_failed_fix(self):
        """nextcloudcookbook and Giggity had fixed the finding upstream; EteSync's
        code is in a submodule. None of them is a patch that failed."""
        outcome = STATS.final_outcome
        fixed = {"solution": True, "apply_status": "NOT_APPLICABLE_TO_BASE",
                 "apply_error": "ORIGINAL_CODE_ABSENT_FROM_BASE_BRANCH",
                 "base_port": "ALREADY_FIXED_UPSTREAM"}
        self.assertEqual(outcome(fixed), ("correção não aplicável: código mudou upstream",
                                          "o branch de destino já não tem a violação"))
        moved = dict(fixed, base_port="")
        self.assertEqual(outcome(moved)[0], "correção não aplicável: código mudou upstream")
        submodule = {"solution": True, "apply_status": "NOT_APPLICABLE_TO_BASE",
                     "apply_error": "SOURCE_IN_SUBMODULE", "submodule": "https://x/cert4android.git"}
        self.assertEqual(outcome(submodule), (
            "correção não aplicável: arquivo fora do branch de destino",
            "submódulo https://x/cert4android.git"))
        failed = {"solution": True, "apply_status": "SUCCESS", "build_status": "failed"}
        self.assertEqual(outcome(failed), ("correção gerada, sem PR", "build: failed (sem atribuição)"))

    def test_a_finding_without_a_patch_whose_statement_left_the_base_is_no_issue(self):
        """AmaRadio's md5 (misuse3 run7): no patch, the MD5 line gone from master,
        and the outcome was "issue para o mantenedor do app"."""
        import json

        outcome = STATS.final_outcome
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "error_solutions" / "issue_candidates" / "a.apk"
            folder.mkdir(parents=True)
            (folder / "0_md5_not_applicable_to_base.json").write_text(json.dumps({
                "apk_name": "a.apk", "csv_class": "a.Utils", "method_name": "md5",
                "spec": "MessageDigestSpec", "status": "not_applicable_to_base",
                "not_applicable_reason": "the reported statement is no longer in Utils.kt"}),
                encoding="utf-8")
            (folder / "1_hash_issue.json").write_text(json.dumps({
                "apk_name": "a.apk", "csv_class": "a.Hash", "method_name": "hash",
                "spec": "MessageDigestSpec", "repo_owner": "o", "repo_name": "a",
                "method_changed_upstream": True}), encoding="utf-8")
            records = STATS.read_run(Path(directory))
        gone = records["a.apk", "a.Utils", "md5", "MessageDigestSpec"]
        self.assertEqual(outcome(gone), ("correção não aplicável: código mudou upstream",
                                         "the reported statement is no longer in Utils.kt"))
        self.assertEqual(outcome(dict(gone, base_file_absent=True))[0],
                         "correção não aplicável: arquivo fora do branch de destino")
        # A statement still on the base keeps its issue, with a note.
        self.assertEqual(outcome(records["a.apk", "a.Hash", "hash", "MessageDigestSpec"]),
                         ("issue para o mantenedor do app", "o/a; o método mudou upstream"))

    def test_a_generation_that_failed_only_on_its_drafts_is_a_correction_not_generated(self):
        """Audit of 2026-10-31: Ursa's sessionPinnedClient (an API the draft widened)
        ended as "issue para o mantenedor do app"."""
        import json

        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "error_solutions" / "generation_shortfall" / "a.apk"
            folder.mkdir(parents=True)
            (folder / "0_sessionPinnedClient.json").write_text(json.dumps({
                "apk_name": "a.apk", "csv_class": "a.Net", "method_name": "sessionPinnedClient",
                "spec": "SSLContextSpec", "generation_blockers": [
                    "UNNECESSARY_PUBLIC_API_EXPANSION", "STATEMENT_WITHOUT_EFFECT: x"]}),
                encoding="utf-8")
            records = STATS.read_run(Path(directory))
        record = records["a.apk", "a.Net", "sessionPinnedClient", "SSLContextSpec"]
        self.assertEqual(STATS.final_outcome(record), (
            "correção não gerada", "STATEMENT_WITHOUT_EFFECT; UNNECESSARY_PUBLIC_API_EXPANSION"))
        self.assertIn("correção não gerada", STATS.OUTCOME_ORDER)

    def test_a_correction_not_generated_names_a_scope_gap_or_a_draft_shape(self):
        """Winterhold's derive (2026-11-07): no draft was written, and the row
        read like drafts that failed."""
        import json

        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "error_solutions" / "generation_shortfall" / "a.apk"
            folder.mkdir(parents=True)
            for index, (method, kind) in enumerate((
                    ("derive", "scope_gap"), ("verify", "draft_shape"),
                    ("hash", "draft_quality"))):
                (folder / f"{index}_{method}.json").write_text(json.dumps({
                    "apk_name": "a.apk", "csv_class": "a.K", "method_name": method,
                    "spec": "S", "shortfall_kind": kind, "generation_blockers": [
                        "scope assessment did not review required files: src/K.kt"]}),
                    encoding="utf-8")
            records = STATS.read_run(Path(directory))
        detail = {method: STATS.final_outcome(records["a.apk", "a.K", method, "S"])[1]
                  for method in ("derive", "verify", "hash")}
        self.assertEqual(detail["derive"],
                         "scope_gap: scope assessment did not review required files")
        self.assertTrue(detail["verify"].startswith("draft_shape: "))
        self.assertEqual(detail["hash"], "scope assessment did not review required files")

    def test_a_finding_settled_before_analysis_reads_why(self):
        """2026-10-31: reruns beside our open Grocy #1013 and Fread #168."""
        outcome = STATS.final_outcome
        url = "https://github.com/patzly/grocy-android/pull/1013"
        self.assertEqual(outcome({"settled_before_analysis": {
            "kind": "open_pull_request", "pull_request": url}}), ("PR já aberto", url))
        self.assertEqual(outcome({"settled_before_analysis": {
            "kind": "merged_pull_request", "pull_request": url}})[0],
            "correção não aplicável: código mudou upstream")
        self.assertEqual(outcome({"settled_before_analysis": {
            "kind": "file_absent_from_base", "reason": "a.kt is not on main"}}),
            ("correção não aplicável: arquivo fora do branch de destino", "a.kt is not on main"))
        self.assertIn("PR já aberto", STATS.OUTCOME_ORDER)

    def test_a_planner_abstention_after_a_promotion_stays_a_confirmed_violation(self):
        """Audit of 2026-10-31: Trigger's decodePublic, promoted to review and
        then planned with no edit, became a maintainer issue."""
        import json

        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "error_solutions" / "confirmed_without_safe_fix" / "a.apk"
            folder.mkdir(parents=True)
            (folder / "0_decodePublic.json").write_text(json.dumps({
                "apk_name": "a.apk", "csv_class": "a.Keys", "method_name": "decodePublic",
                "spec": "KeyFactorySpec", "reason": "no edit keeps ED25519 working"}),
                encoding="utf-8")
            records = STATS.read_run(Path(directory))
        record = records["a.apk", "a.Keys", "decodePublic", "KeyFactorySpec"]
        # Whatever the recorded detector verdict, never a false positive.
        for violation in ("confirmed", "not_confirmed", "unknown"):
            self.assertEqual(STATS.final_outcome(dict(record, analysed=True,
                                                      detector_violation=violation)),
                             ("violação confirmada sem correção segura",
                              "no edit keeps ED25519 working"))

    def test_an_external_contract_record_is_its_own_outcome(self):
        """finding_processing.blocked_without_confirmed_impact (2026-11-10):
        a counterpart outside the repository fixes the value and the
        adjudication did not confirm an impact."""
        import json

        def outcome(kind, with_issue=False):
            with tempfile.TemporaryDirectory() as directory:
                folder = (Path(directory) / "error_solutions" / "confirmed_without_safe_fix"
                          / "a.apk")
                folder.mkdir(parents=True)
                (folder / "0_md5Hex.json").write_text(json.dumps(dict({
                    "apk_name": "a.apk", "csv_class": "a.Api", "method_name": "md5Hex",
                    "spec": "MessageDigestSpec", "reason": "the API fixes MD5"},
                    **({"kind": kind} if kind else {}))), encoding="utf-8")
                if with_issue:
                    issues = Path(directory) / "error_solutions" / "issue_candidates" / "a.apk"
                    issues.mkdir(parents=True)
                    (issues / "0_x_issue.json").write_text(json.dumps({
                        "apk_name": "a.apk", "csv_class": "a.Api", "method_name": "md5Hex",
                        "spec": "MessageDigestSpec"}), encoding="utf-8")
                records = STATS.read_run(Path(directory))
            record = records["a.apk", "a.Api", "md5Hex", "MessageDigestSpec"]
            return [STATS.final_outcome(dict(record, analysed=True, detector_violation=v))
                    for v in ("confirmed", "not_confirmed", "unknown")]

        external = ("contrato externo impede a correção", "the API fixes MD5")
        self.assertEqual(outcome("external_contract"), [external] * 3)
        self.assertEqual(outcome("external_contract", with_issue=True), [external] * 3)
        for kind in ("", "no_safe_fix"):
            self.assertEqual({item[0] for item in outcome(kind)},
                             {"violação confirmada sem correção segura"})

    def test_the_external_contract_reading_is_the_dispositions(self):
        from cognalys.utils.disposition import external_contract_decision

        self.assertTrue(external_contract_decision("EXTERNAL_DIGEST_CONTRACT_NO_CLIENT_ONLY_FIX"))
        for decision in ("NO_SAFE_FIX", "FIX_SUPPORTED", "MULTI_FILE_FIX_REQUIRES_POLICY", ""):
            self.assertFalse(external_contract_decision(decision), decision)

    def test_an_adjudicated_finding_stopped_by_the_provider_is_not_concluded(self):
        """Review of 2026-11-09: InterTune v4's draft failed after adjudication
        (server_is_overloaded); its evidence review made it "analysed", and
        the FIX decision read "correção proposta, reprovada antes de gerar"
        while run_status left it for a resume."""
        import json

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            failures = []
            for index, (method, kind, cause, analysed) in enumerate((
                    ("hash", "provider_unavailable", "BackgroundResponseFailed: overloaded", True),
                    ("sign", "crashed", "KeyError: 'x'", True),
                    ("seal", "provider_refused", "refused (cyber_policy)", True),
                    ("open", "provider_unavailable", "BackgroundCreateFailed: 503", False),
                    ("wrap", "failed", "ProviderRequestRejected: context_length_exceeded",
                     False))):
                path = run / "error_methods" / "a.apk" / f"{index}_{method}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({
                    "extraction_metadata": {"apk_name": "a.apk", "csv_index": index,
                                            "extraction_status": "success"},
                    "error": {"csv_class": "a.W", "csv_method": method, "spec": "S"}}),
                    encoding="utf-8")
                failures.append({"apk_name": "a.apk", "method_name": method, "kind": kind,
                                 "finding_id": f"a.W:::{method}:::S:::Rule:::m", "cause": cause})
                if analysed:
                    review = (run / "error_solutions" / "evidence_reviews" / "a.apk"
                              / f"{index}_{method}_evidence.json")
                    review.parent.mkdir(parents=True, exist_ok=True)
                    review.write_text(json.dumps({
                        "apk_name": "a.apk", "csv_class": "a.W", "method_name": method,
                        "spec": "S", "analysis": {"decision": "SAFE_FIX",
                                                  "detector_violation": "confirmed"}}),
                        encoding="utf-8")
            (run / "error_solutions" / "solutions_tracking.json").write_text(
                json.dumps({"failures": failures}), encoding="utf-8")
            records = STATS.read_run(run)
        outcome = {method: STATS.final_outcome(records["a.apk", "a.W", method, "S"])
                   for method in ("hash", "sign", "seal", "open", "wrap")}
        self.assertEqual(outcome["hash"], (
            "não analisado", "análise interrompida: falha na chamada ao LLM (provedor indisponível)"))
        # A crash after the verdict (exp_final_20261019's datetime
        # serialization) and a refusal keep the decision's category.
        self.assertEqual(outcome["sign"][0], "correção proposta, reprovada antes de gerar")
        self.assertEqual(outcome["seal"][0], "correção proposta, reprovada antes de gerar")
        self.assertEqual(outcome["open"],
                         ("não analisado", "falha na chamada ao LLM (provedor indisponível)"))
        self.assertEqual(outcome["wrap"], ("não analisado", "pedido recusado pelo provedor"))

    def test_findings_read_from_a_failed_tasks_logcat_are_grouped_apart(self):
        """DNSToggle and Beta (2026-10-29): reports of an errored ape task came
        from its logcat, beside monkey's errors.csv."""
        findings = {("a.apk", "C", "m", "S"): {"report_source": "errors.csv"},
                    ("a.apk", "C", "n", "S"): {"report_source": "logcat"}}
        self.assertIn(("report_source", "fonte dos relatos"), STATS.grouping_columns(findings))
        findings.popitem()
        self.assertEqual(STATS.grouping_columns(findings), [])

    def test_a_paid_analysis_that_concluded_nothing_was_interrupted(self):
        """SMSecure run_v2 (2026-10-29): 6 calls, US$ 0.38 for getKeyFromPassphrase,
        then the llm step died and the finding read "não analisado" with no reason."""
        import json

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            for index, method in enumerate(("getKeyFromPassphrase", "untouched")):
                path = run / "error_methods" / "a.apk" / f"{index}_{method}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({
                    "extraction_metadata": {"apk_name": "a.apk", "csv_index": index,
                                            "extraction_status": "success"},
                    "error": {"csv_class": "a.M", "csv_method": method, "spec": "PBEKeySpecSpec"}}),
                    encoding="utf-8")
            logs = run / "application_results" / "openai_prompt_logs"
            logs.mkdir(parents=True)
            (logs / "0001_evidence_extraction_metadata.json").write_text(json.dumps({
                "finding_id": "a.M:::getKeyFromPassphrase:::PBEKeySpecSpec:::ForbiddenMethod:::x",
                "delivery": "sent_to_openai", "status": "success", "model": "m",
                "input_tokens": 10, "output_tokens": 5}), encoding="utf-8")
            # An Anthropic call: the cost reports count it, this marking (an
            # outcome) reads the OpenAI traces as it did before they did.
            (logs / "0002_evidence_extraction_metadata.json").write_text(json.dumps({
                "finding_id": "a.M:::untouched:::PBEKeySpecSpec:::ForbiddenMethod:::x",
                "delivery": "sent_to_anthropic", "status": "success", "model": "c",
                "input_tokens": 10, "output_tokens": 5}), encoding="utf-8")
            records = STATS.read_run(run)
        self.assertEqual(STATS.final_outcome(records["a.apk", "a.M", "getKeyFromPassphrase",
                                                     "PBEKeySpecSpec"]),
                         ("não analisado", "análise interrompida"))
        # Never started: no model call, no reason invented.
        self.assertEqual(STATS.final_outcome(records["a.apk", "a.M", "untouched", "PBEKeySpecSpec"]),
                         ("não analisado", ""))

    def test_each_finding_has_exactly_one_outcome(self):
        outcome = STATS.final_outcome
        self.assertEqual(outcome({"pr_ready": True, "solution": True})[0], "PR pronto")
        self.assertEqual(outcome({"solution": True, "apply_status": "FAILED",
                                  "apply_error": "X"})[0], "correção gerada, sem PR")
        self.assertEqual(outcome({"issue": True, "issue_target": "upstream_library",
                                  "analysed": True})[0], "issue para a biblioteca")
        self.assertEqual(outcome({"analysed": True, "decision": "NO_SAFE_FIX",
                                  "detector_violation": "not_confirmed"})[0],
                         "falso positivo reconhecido")
        self.assertEqual(outcome({"analysed": True, "decision": "NO_SAFE_FIX",
                                  "detector_violation": "unknown"})[0], "evidência insuficiente")
        self.assertEqual(outcome({"not_analysed_reason": "biblioteca sem código nem bytecode"}),
                         ("não analisado", "biblioteca sem código nem bytecode"))
        for result in (outcome({}), outcome({"analysed": True})):
            self.assertIn(result[0], STATS.OUTCOME_ORDER)


class StaleReviewTests(unittest.TestCase):
    """Orgzly, Syncthing-Lite, Olvid and Tasks.org drafts predate the review
    that rejects no-effect patches and stayed "PR pronto". The category stays,
    so counts remain comparable; the detail says to rerun them."""

    def setUp(self):
        # Recorded outcomes come from a folder of the test's own, never the
        # repository's data/pr_outcomes.
        import unittest.mock as mock

        from cognalys.prs import pr_outcomes

        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.outcomes = Path(folder.name)
        patcher = mock.patch.object(pr_outcomes, "OUTCOMES_DIR", self.outcomes)
        patcher.start()
        self.addCleanup(patcher.stop)
        STATS._RECORDED_OUTCOMES.clear()
        self.addCleanup(STATS._RECORDED_OUTCOMES.clear)

    def current(self):
        from cognalys.prs.publication_checks import current_review_contract_version

        return current_review_contract_version()

    def test_a_draft_without_the_current_review_is_marked_for_a_rerun(self):
        outcome = STATS.final_outcome
        self.assertEqual(outcome({"pr_ready": True}), ("PR pronto", STATS.STALE_REVIEW_DETAIL))
        self.assertEqual(outcome({"pr_ready": True, "review_contract_version": self.current() - 1}),
                         ("PR pronto", STATS.STALE_REVIEW_DETAIL))
        self.assertEqual(outcome({"pr_ready": True, "review_contract_version": self.current()}),
                         ("PR pronto", ""))

    def test_a_finding_already_published_is_not_marked(self):
        """Grocy, KeyPass, Amethyst, ReadYou and InterTune were published from
        older drafts; a rerun marker there is only noise."""
        self.assertEqual(STATS.final_outcome({"pr_ready": True, "pr_published": "https://x/pull/1"}),
                         ("PR pronto", ""))

    def test_a_single_method_draft_is_not_sent_to_a_rerun(self):
        """That fix path writes no behaviour review, and a rerun takes it
        again: Grocy's insertConscrypt and KeyPass's getKey came from it."""
        record = {"pr_ready": True, "fix_scope": "single_method",
                  "behavior_review_recorded": False}
        self.assertEqual(STATS.final_outcome(record), ("PR pronto", STATS.UNREVIEWED_PATH_DETAIL))
        self.assertEqual(STATS.final_outcome({**record, "pr_published": "https://x/pull/1"}),
                         ("PR pronto", ""))

    def write(self, path: Path, value) -> None:
        import json

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def make_run(self, directory: str) -> Path:
        run = Path(directory) / "run"
        apk = "app.debug_1.apk"
        details = []
        for index, (method, version) in enumerate((("old", None), ("new", self.current()),
                                                   ("shipped", None), ("single", None))):
            self.write(run / "error_methods" / apk / f"{index}_{method}.json", {
                "extraction_metadata": {"apk_name": apk, "csv_index": index,
                                        "extraction_status": "success"},
                "error": {"csv_class": "a.C", "csv_method": method, "spec": "S"}})
            metadata = {"csv_class": "a.C", "method_name": method, "spec": "S"}
            if version is not None:
                metadata["review_contract_version"] = version
            if method == "single":
                metadata["fix_scope"] = "single_method"
            self.write(run / "error_solutions" / apk / f"{index}_{method}_solution.json",
                       {"solution_metadata": metadata})
            details.append({"apk_name": apk, "csv_class": "a.C", "method_name": method,
                            "spec": "S", "status": "SUCCESS",
                            "build_validation": {"status": "success"}})
            self.write(run / "pull_requests" / f"{apk}_{method}_S_pr.json", {
                "csv_class": "a.C", "method_name": method, "spec": "S", "commit_hash": "abc"})
        self.write(run / "application_results" / "execution_report.json",
                   {"per_solution_details": details})
        self.write(run / "pull_requests" / f"{apk}_shipped_S_pr_created.json",
                   {"html_url": "https://github.com/o/r/pull/7"})
        return run

    def test_the_contract_is_read_from_the_runs_solution_files(self):
        with tempfile.TemporaryDirectory() as directory:
            records = STATS.read_run(self.make_run(directory))
        outcomes = {key[2]: STATS.final_outcome(record) for key, record in records.items()}
        self.assertEqual(outcomes["old"], ("PR pronto", STATS.STALE_REVIEW_DETAIL))
        self.assertEqual(outcomes["new"], ("PR pronto", ""))
        self.assertEqual(outcomes["shipped"], ("PR pronto", ""))
        self.assertEqual(outcomes["single"], ("PR pronto", STATS.UNREVIEWED_PATH_DETAIL))

    def test_a_draft_its_repaired_patchs_review_holds_is_not_ready(self):
        """Review of 2026-10-31: the statistics counted it as "PR pronto"."""
        apk = "app.debug_1.apk"
        with tempfile.TemporaryDirectory() as directory:
            run = self.make_run(directory)
            self.write(run / "pull_requests" / f"{apk}_new_S_pr.json", {
                "csv_class": "a.C", "method_name": "new", "spec": "S", "commit_hash": "abc",
                "repaired_patch_review_blocks": [
                    "the behaviour review of the repaired patch found 1 regression(s)"]})
            records = {key[2]: record for key, record in STATS.read_run(run).items()}
        self.assertNotIn("pr_ready", records["new"])
        self.assertIn("repaired patch", records["new"]["pr_held"])

    def test_a_draft_no_repair_went_beyond_the_plan_for_is_not_held_by_that_review(self):
        """BlueGate run_v7 (2026-10-31): built on the first try, no repair ran,
        and the empty repair_behavior_review held the draft on "no behaviour
        review judged the repaired patch's edits of " with no file named."""
        apk = "app.debug_1.apk"
        with tempfile.TemporaryDirectory() as directory:
            run = self.make_run(directory)
            for review in ({}, None, {"status": "not_run", "files_beyond_plan": []}):
                self.write(run / "pull_requests" / f"{apk}_new_S_pr.json", {
                    "csv_class": "a.C", "method_name": "new", "spec": "S", "commit_hash": "abc",
                    "repaired_patch_review_blocks": [], "repair_behavior_review": review})
                records = {key[2]: record for key, record in STATS.read_run(run).items()}
                with self.subTest(review=review):
                    self.assertNotIn("pr_held", records["new"])
                    self.assertTrue(records["new"].get("pr_ready"))
            # A repair beyond the plan that no review judged still holds it.
            self.write(run / "pull_requests" / f"{apk}_new_S_pr.json", {
                "csv_class": "a.C", "method_name": "new", "spec": "S", "commit_hash": "abc",
                "repaired_patch_review_blocks": [], "repair_behavior_review": {
                    "status": "not_run", "files_beyond_plan": ["app/Authenticator.kt"]}})
            records = {key[2]: record for key, record in STATS.read_run(run).items()}
        self.assertIn("app/Authenticator.kt", records["new"]["pr_held"])

    def test_an_outage_and_a_dry_run_are_read_as_pr_creator_reads_them(self):
        """A review that did not run is not one that "predates the contract
        versions", and a dry-run record opened no pull request."""
        import json

        apk = "app.debug_1.apk"
        with tempfile.TemporaryDirectory() as directory:
            run = self.make_run(directory)
            solution = run / "error_solutions" / apk / "0_old_solution.json"
            data = json.loads(solution.read_text(encoding="utf-8"))
            data["solution_metadata"]["review_contract_version"] = None
            self.write(solution, data)
            self.write(run / "error_solutions" / "coordinated_drafts" / apk / "0_old"
                       / "behavior_review.json", {"status": "not_run", "regressions": []})
            self.write(run / "pull_requests" / f"{apk}_new_S_pr_created.json",
                       {"dry_run": True, "html_url": "https://github.com/o/r/pull/8"})
            records = {key[2]: record for key, record in STATS.read_run(run).items()}
        self.assertIs(records["old"]["behavior_review_recorded"], False)
        self.assertEqual(STATS.stale_review_reason(records["old"]),
                         "no behaviour review ran on this draft")
        self.assertNotIn("pr_published", records["new"])
        self.assertEqual(records["shipped"]["pr_published"], "https://github.com/o/r/pull/7")

    def test_another_repositorys_pull_request_for_the_same_method_is_not_this_drafts(self):
        """A fork or a vendored class shares the class, method and spec."""
        apk = "app.debug_1.apk"
        with tempfile.TemporaryDirectory() as directory:
            run = self.make_run(directory)
            self.write(run / "pull_requests" / f"{apk}_old_S_pr.json", {
                "csv_class": "a.C", "method_name": "old", "spec": "S", "commit_hash": "abc",
                "repo_owner": "fork", "repo_name": "app"})
            self.write(self.outcomes / "upstream__app.json", [{
                "pull_request": "https://github.com/upstream/app/pull/3", "state": "open",
                "spec": "S", "csv_class": "a.C", "method_name": "old"}])
            elsewhere = STATS.read_run(run)
            STATS._RECORDED_OUTCOMES.clear()
            self.write(self.outcomes / "fork__app.json", [{
                "pull_request": "https://github.com/fork/app/pull/4", "state": "open",
                "spec": "S", "csv_class": "a.C", "method_name": "old"}])
            here = STATS.read_run(run)
        old = next(record for key, record in elsewhere.items() if key[2] == "old")
        self.assertNotIn("pr_published", old)
        self.assertEqual(STATS.final_outcome(old), ("PR pronto", STATS.STALE_REVIEW_DETAIL))
        old = next(record for key, record in here.items() if key[2] == "old")
        self.assertEqual(old["pr_published"], "https://github.com/fork/app/pull/4")

    def test_the_same_draft_published_from_another_run_of_the_experiment_counts(self):
        """ReadYou's repository was transferred after publication, so its
        outcome sits under the new name; the run that published it still
        holds the record."""
        apk = "app.debug_1.apk"
        with tempfile.TemporaryDirectory() as directory:
            run = self.make_run(directory)
            self.write(run.parent / "run3" / "pull_requests" / f"{apk}_old_S_pr_created.json",
                       {"html_url": "https://github.com/new-owner/app/pull/9"})
            self.write(run.parent / "run4" / "pull_requests" / f"{apk}_new_S_pr_created.json",
                       {"dry_run": True, "html_url": "https://github.com/o/r/pull/8"})
            records = {key[2]: record for key, record in STATS.read_run(run).items()}
        self.assertEqual(records["old"]["pr_published"], "https://github.com/new-owner/app/pull/9")
        self.assertNotIn("pr_published", records["new"])

    def test_an_empty_review_field_in_the_pr_file_keeps_the_recorded_one(self):
        """pr_creator and the preview read the same value through
        fix_artifacts.with_recorded_review_notes."""
        apk = "app.debug_1.apk"
        with tempfile.TemporaryDirectory() as directory:
            run = self.make_run(directory)
            self.write(run / "pull_requests" / f"{apk}_new_S_pr.json", {
                "csv_class": "a.C", "method_name": "new", "spec": "S", "commit_hash": "abc",
                "review_contract_version": None, "fix_scope": ""})
            records = {key[2]: record for key, record in STATS.read_run(run).items()}
        self.assertEqual(records["new"]["review_contract_version"], self.current())
        self.assertEqual(STATS.final_outcome(records["new"]), ("PR pronto", ""))


class StageTests(unittest.TestCase):
    def test_pr_ready_splits_into_publishable_and_review_without_changing_the_total(self):
        """P7: "PR pronto" keeps its count; its two parts say which drafts
        pr_generator found publishable and which stay for review."""
        publishable = STATS.stage_flags({"pr_ready": True, "pr_publishable": True})
        review = STATS.stage_flags({"pr_ready": True, "pr_publishable": False})
        neither = STATS.stage_flags({"pr_ready": False, "pr_publishable": True})
        self.assertEqual((publishable["pr_ready"], publishable["pr_ready_publishable"],
                          publishable["pr_ready_review"]), (True, True, False))
        self.assertEqual((review["pr_ready"], review["pr_ready_publishable"],
                          review["pr_ready_review"]), (True, False, True))
        self.assertFalse(neither["pr_ready_publishable"] or neither["pr_ready_review"])
        labels = dict(STATS.STAGES)
        self.assertEqual(labels["pr_ready_publishable"], "PR pronto (publicável)")
        self.assertEqual(labels["pr_ready_review"], "PR pronto (revisão)")
        self.assertEqual(STATS.final_outcome({"pr_ready": True, "pr_publishable": True})[0],
                         "PR pronto")

    def test_the_split_reads_the_pr_files_publishable_flag(self):
        import json

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            key = ("a.apk", "x.A", "m", "S")
            prs = run / "pull_requests"
            prs.mkdir(parents=True)
            report = run / "application_results" / "execution_report.json"
            report.parent.mkdir(parents=True)
            report.write_text(json.dumps({"per_solution_details": [{
                "apk_name": "a.apk", "csv_class": "x.A", "method_name": "m", "spec": "S",
                "status": "SUCCESS", "build_validation": {"status": "success"}}]}),
                encoding="utf-8")
            (prs / "a.apk_m_S_pr.json").write_text(json.dumps({
                "csv_class": "x.A", "method_name": "m", "spec": "S", "commit_hash": "abc",
                "publishable": True, "preview_status": "READY_FOR_PUBLICATION_WITH_NOTES"}),
                encoding="utf-8")
            records = STATS.read_run(run)
        self.assertTrue(records[key]["pr_ready"])
        self.assertTrue(STATS.stage_flags(records[key])["pr_ready_publishable"])

    def test_a_built_patch_without_a_commit_is_not_pr_ready(self):
        flags = STATS.stage_flags({"analysed": True, "build_status": "success"})
        self.assertTrue(flags["built"])
        self.assertFalse(flags["pr_ready"])

    def test_a_production_only_pass_is_built_and_said_apart(self):
        status = "success_production_only_test_build_preexisting"
        flags = STATS.stage_flags({"analysed": True, "build_status": status})
        self.assertTrue(flags["built"])
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            report = run / "application_results" / "build_validation" / "build_report.json"
            report.parent.mkdir(parents=True)
            report.write_text(
                '[{"apk_name": "a", "status": "%s"}, {"apk_name": "b", "status": "success"}]'
                % status, encoding="utf-8")
            text, rows = STATS.build_section(run, {})
        self.assertEqual(rows[0][-1], "sucesso (só produção; testes falham na base)")
        self.assertEqual(rows[1][-1], "sucesso")
        self.assertIn("só produção", text)


class CostSectionTests(unittest.TestCase):
    def test_calls_replayed_within_a_finding_are_shown_apart(self):
        # llm_providers.finding_replay_scope: a replan's identical calls are
        # answered by the finding's first ones and never sent.
        text = STATS.costs_section({
            "runs/run_v2": {"llm": {"findings": 3, "calls": 20, "failed_calls": 1,
                                    "replayed_calls": 6, "model_seconds": 3600},
                            "steps": {"llm": 7200}},
            "runs/run_v1": {"llm": {"findings": 3, "calls": 26, "failed_calls": 0},
                            "steps": {}},
        })
        header, _, newer, older = text.splitlines()
        self.assertIn("| falhas | reaproveitadas |", header)
        self.assertTrue(newer.startswith("| run_v2 | 3 | 20 | 1 | 6 | 1.0 | 2.0 |"))
        # A run from before replays were counted says so, not 0.
        self.assertTrue(older.startswith("| run_v1 | 3 | 26 | 0 | – |"))


if __name__ == "__main__":
    unittest.main()
