import argparse
import csv
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (scripts/ and src/ on sys.path)


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


IMPORT = _load("import_rv_misuses", ROOT / "src" / "cognalys" / "corpus" / "import_rv_misuses.py")
PIPELINE = _load("run_pipeline", ROOT / "src" / "cognalys" / "orchestration" / "run_pipeline.py")

COMMIT = "0a9e080f9cc5e1f62af5545f06abd9f154341f21"
ENVELOPE = (
    "v=1 code=MESSAGEDIGEST-ALG-02 ev=g4 obj=MessageDigest val='SHA-1' "
    "exp='SHA-256,SHA-512' msg='expecting one of SHA-256,SHA-512 but found SHA-1'"
)
TRUST_ENVELOPE = (
    "v=1 code=SSLCONTEXT-NOBS-05 ev=init obj=SSLContext val='TLS' "
    "exp='a TrustManager[]' msg='the TrustManager[] given to SSLContext.init "
    "holds a manager' vcls='com.example.Net$trust$1'"
)

KEY_ENVELOPE = (
    "v=1 code=SECRETKEYSPEC-NOBS-00 ev=c1 obj=SecretKeySpec val='AES' "
    "exp='prepared key material' msg='the keyMaterial was not observed' "
    "vfp='sha256:abc'"
)


def _write(path: Path, header, rows) -> None:
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def _package(directory: Path, *, commit=COMMIT, with_site=True) -> Path:
    _write(
        directory / "20260925_misuses-selected.csv",
        ["id", "apk", "class", "method", "spec", "origin", "runs", "every_run", "outcome"],
        [
            ["1", "app_1.apk", "com.example.Pin", "hash", "MessageDigestSpec", "app", "3", "False", "primary"],
            ["2", "app_1.apk", "com.example.Net", "trustAll", "SSLContextSpec", "app", "99", "True", "severe-trust-all"],
            ["3", "app_1.apk", "com.example.Enc", "encrypt", "IvParameterSpecSpec", "app", "1", "False", "undecided"],
            ["4", "app_1.apk", "com.example.Key", "make", "SecretKeySpecSpec", "app", "2", "False", "severe-constant"],
        ],
    )
    report_header = [
        "apk", "rep", "timeout", "tool", "time", "spec", "class", "method",
        "source", "code", "event", "message", "unique_msg",
    ]
    _write(
        directory / "primary-accusations.csv",
        report_header,
        [
            ["app_1.apk", "1", "300", "ape", "8", "MessageDigestSpec", "com.example.Pin", "hash",
             "Pin.kt:10", "MESSAGEDIGEST-ALG-02", "g4", ENVELOPE,
             "com.example.Pin:::hash:::MessageDigestSpec:::UnsafeAlgorithm:::MESSAGEDIGEST-ALG-02:::g4:::" + ENVELOPE],
            # A later report of the same misuse is not the representative.
            ["app_1.apk", "2", "60", "monkey", "3", "MessageDigestSpec", "com.example.Pin", "hash",
             "Pin.kt:11", "MESSAGEDIGEST-ALG-00", "update", ENVELOPE, "x:::y:::z:::Other:::m:::e:::v"],
        ],
    )
    _write(
        directory / "severe-accusations.csv",
        report_header,
        [["app_1.apk", "1", "60", "ape", "22", "SSLContextSpec", "com.example.Net", "trustAll",
          "Net.kt:32", "SSLCONTEXT-NOBS-05", "init", TRUST_ENVELOPE,
          "com.example.Net:::trustAll:::SSLContextSpec:::UnsatisfiedConstraint:::SSLCONTEXT-NOBS-05:::init:::" + TRUST_ENVELOPE],
         *[["app_1.apk", rep, "60", "ape", "5", "SecretKeySpecSpec", "com.example.Key", "make",
            "Key.kt:7", "SECRETKEYSPEC-NOBS-00", "c1", KEY_ENVELOPE,
            "com.example.Key:::make:::SecretKeySpecSpec:::UnsatisfiedConstraint:::SECRETKEYSPEC-NOBS-00:::c1:::" + KEY_ENVELOPE]
           for rep in ("1", "2")]],
    )
    _write(
        directory / "severe-sites.csv",
        ["apk", "class", "method", "spec", "code", "criterion", "evidence", "verdict", "in_primary"],
        [
            *([["app_1.apk", "com.example.Enc", "encrypt", "IvParameterSpecSpec", "IVPARAMETERSPEC-NOBS-00",
                "constant", "runs=1", "undecided", "false"]] if with_site else []),
            ["app_1.apk", "com.example.Net", "trustAll", "SSLContextSpec", "SSLCONTEXT-NOBS-05",
             "trust-all", "checkServerTrusted: return-void", "trust-all", "false"],
        ],
    )
    _write(
        directory / "codes.csv",
        ["spec", "code", "error_type", "site_kind", "event", "file_line", "label"],
        [
            ["MessageDigestSpec", "MESSAGEDIGEST-ALG-02", "UnsafeAlgorithm", "ALG", "g4", "m:1", "violation"],
            ["SSLContextSpec", "SSLCONTEXT-NOBS-05", "UnsatisfiedConstraint", "NOBS", "init", "m:2", "application-manager"],
            ["IvParameterSpecSpec", "IVPARAMETERSPEC-NOBS-00", "UnsatisfiedConstraint", "NOBS", "c", "m:3", "not-observed"],
            ["SecretKeySpecSpec", "SECRETKEYSPEC-NOBS-00", "UnsatisfiedConstraint", "NOBS", "c1", "m:4", "not-observed"],
        ],
    )
    _write(
        directory / "dataset.csv",
        ["apk", "repo_url", "pinned_commit", "head_pinned_commit"],
        [["app_1.apk", "https://github.com/owner/app", "1111111111111111111111111111111111111111", commit]],
    )
    return directory


class ConvertTests(unittest.TestCase):
    def _rows(self, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            return IMPORT.convert(_package(Path(directory), **kwargs))

    def test_every_misuse_becomes_one_row_whatever_its_outcome(self):
        rows = self._rows()
        self.assertEqual(
            [row["outcome"] for row in rows],
            ["primary", "severe-trust-all", "undecided", "severe-constant"],
        )

    def test_message_is_the_plain_msg_the_predicate_parser_reads(self):
        row = self._rows()[0]
        self.assertEqual(row["message"], "expecting one of SHA-256,SHA-512 but found SHA-1")
        self.assertEqual(
            (row["detector_value"], row["detector_expected"]),
            ("SHA-1", "SHA-256,SHA-512"),
        )

    def test_msg_followed_by_another_field_stops_at_its_own_quote(self):
        row = self._rows()[1]
        self.assertEqual(
            row["message"],
            "the TrustManager[] given to SSLContext.init holds a manager",
        )

    def test_unique_msg_has_the_five_parts_the_pipeline_splits(self):
        row = self._rows()[0]
        self.assertEqual(
            row["unique_msg"].split(":::"),
            ["com.example.Pin", "hash", "MessageDigestSpec", "UnsafeAlgorithm", row["message"]],
        )

    def test_the_first_report_of_a_misuse_is_its_representative(self):
        row = self._rows()[0]
        self.assertEqual(
            (row["rep"], row["timeout"], row["tool"], row["time"],
             row["detector_source_location"], row["detector_code"]),
            ("1", "300", "ape", "8", "Pin.kt:10", "MESSAGEDIGEST-ALG-02"),
        )
        self.assertEqual(row["detector_label"], "violation")

    def test_commit_is_the_head_pinned_commit_not_the_earlier_build(self):
        row = self._rows()[0]
        self.assertEqual(row["commit"], COMMIT)
        self.assertEqual(row["repo"], "owner/app")

    def test_an_undecided_misuse_without_report_takes_its_site_code(self):
        row = self._rows()[2]
        self.assertEqual(row["message"], "unknown")
        self.assertEqual(row["detector_code"], "IVPARAMETERSPEC-NOBS-00")
        self.assertEqual(row["unique_msg"].split(":::")[3], "UnsatisfiedConstraint")
        self.assertEqual((row["rep"], row["tool"]), ("", ""))

    def test_the_label_and_site_kind_carry_their_meaning(self):
        row = self._rows()[1]
        self.assertEqual(row["detector_label"], "application-manager")
        self.assertIn("checkServerTrusted", row["detector_label_meaning"])
        self.assertTrue(row["detector_site_kind"].startswith("NOBS: "))

    def test_a_platform_default_is_neither_called_correct_nor_a_defect(self):
        # quad9's init(null, ...) was dismissed and Clash Fest's identical
        # one confirmed (2026-10-23/28): the label must not settle it.
        meaning = IMPORT.LABEL_MEANINGS["platform-default"]
        self.assertNotIn("correct code", meaning)
        self.assertIn("not a security defect", meaning)
        self.assertIn("producer requirement is unmet", meaning)
        self.assertIn("identical default", meaning)
        # An explicit key store for a trust factory skips the Network
        # Security Config; the label must not offer it as the default.
        self.assertIn("skips platform configuration", meaning)
        self.assertNotIn("TrustManagerFactory.init((KeyStore) null)", meaning)

    def test_a_platform_default_producer_must_not_move_the_report(self):
        # The factories' own init(null) is reported as platform-default under
        # their specifications; offering it trades one finding for another.
        meaning = IMPORT.LABEL_MEANINGS["platform-default"]
        self.assertIn("counts only when it follows the same path and passes no "
                      "other null or default argument to a governed API", meaning)
        self.assertIn("only moves this report to that API", meaning)

    def test_a_trust_manager_site_carries_its_class_and_severe_check(self):
        observation = self._rows()[1]["detector_runtime_observation"]
        self.assertIn("com.example.Net$trust$1", observation)
        self.assertIn("verdict=trust-all", observation)
        self.assertIn("checkServerTrusted: return-void", observation)
        self.assertIn("every run of the campaign", observation)

    def test_one_fingerprint_across_runs_is_reported_as_such(self):
        observation = self._rows()[3]["detector_runtime_observation"]
        self.assertIn("1 distinct value(s) over 2 reporting run(s)", observation)

    def test_a_misuse_with_neither_report_nor_site_stops_the_conversion(self):
        with self.assertRaisesRegex(IMPORT.ConversionError, "com.example.Enc"):
            self._rows(with_site=False)

    def test_a_missing_commit_stops_the_conversion(self):
        with self.assertRaisesRegex(IMPORT.ConversionError, "head_pinned_commit"):
            self._rows(commit="")

    def test_main_writes_the_pipeline_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            package = _package(Path(directory))
            output = Path(directory) / "out" / "findings.csv"
            self.assertEqual(IMPORT.main([str(package), "--output", str(output)]), 0)
            with open(output, encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 4)
        for column in ("apk", "repo_url", "commit", "class", "method", "spec", "message", "unique_msg"):
            self.assertIn(column, rows[0])


def _step_args(**overrides) -> argparse.Namespace:
    base = dict(
        prune_unused_repos="off", cleanup=False, cleanup_issues=False,
        only=None, start_from="spec_generation", skip=[],
        enable_filter_v3=False, enable_rv_import=False,
        csv_file="data/processed/in.csv",
        filter_v3_input="data/raw/errors.csv",
        filter_v3_output="data/processed/sample.csv",
        rv_import_dir="data/raw/exp_novo",
        rv_import_output="data/processed/rv_import_findings.csv",
        cloned_projects_dir="c", extracted_methods_dir="e", build_output_dir="b",
        error_solutions_dir="s", application_results_dir="a", worktrees_dir="w",
        pull_requests_dir="p", issues_dir="i", previews_dir="v",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


class RvImportStepTests(unittest.TestCase):
    def test_disabled_by_default(self):
        steps = PIPELINE.selected_steps(_step_args())
        self.assertNotIn("rv_import", steps)
        self.assertEqual(steps[0], "spec_generation")

    def test_the_flag_runs_it_first(self):
        steps = PIPELINE.selected_steps(_step_args(enable_rv_import=True))
        self.assertEqual(steps[:2], ["rv_import", "spec_generation"])

    def test_the_flag_runs_it_first_even_from_a_later_start(self):
        steps = PIPELINE.selected_steps(
            _step_args(enable_rv_import=True, start_from="extraction")
        )
        self.assertEqual(steps[:2], ["rv_import", "extraction"])

    def test_its_output_replaces_the_csv_for_every_later_step(self):
        root = Path("/repo")
        paths = PIPELINE.resolve_paths(_step_args(enable_rv_import=True), root)
        self.assertEqual(paths.csv_file, (root / "data/processed/rv_import_findings.csv").resolve())
        paths = PIPELINE.resolve_paths(_step_args(), root)
        self.assertEqual(paths.csv_file, (root / "data/processed/in.csv").resolve())

    def test_command_converts_the_package_into_the_effective_csv(self):
        root = Path("/repo")
        args = _step_args(enable_rv_import=True)
        paths = PIPELINE.resolve_paths(args, root)
        command = PIPELINE.STEP_COMMAND_BUILDERS["rv_import"]("rv_import", args, paths, "python")
        self.assertEqual(command[1:3], ["-m", "cognalys.corpus.import_rv_misuses"])
        self.assertEqual(command[3], str((root / "data/raw/exp_novo").resolve()))
        self.assertEqual(command[4:], ["--output", str(paths.csv_file)])


if __name__ == "__main__":
    unittest.main()


class DetectorContextTests(unittest.TestCase):
    def test_only_filled_detector_columns_pass_without_their_prefix(self):
        sys.path.insert(0, str(ROOT / "src"))
        from cognalys.utils.corpus_rows import detector_context

        row = {"apk": "a.apk", "detector_code": "X-1", "detector_value": " ",
               "detector_label": "violation", None: ["extra"]}
        self.assertEqual(detector_context(row), {"code": "X-1", "label": "violation"})

    # The meaning stored with a row in 93 findings of the input files
    # (2026-11-10) ended in a verdict the current text no longer gives.
    STALE_PLATFORM_DEFAULT = (
        "NOT OBSERVED: the runtime monitor tracks the producers a rule requires "
        "by object identity within one process, and saw none for this object. "
        "The argument was null, which the API documents as 'use the platform "
        "default' (e.g. TrustManagerFactory.init((KeyStore) null)); correct "
        "code produces this.")

    def test_a_known_labels_stale_meaning_is_replaced_by_the_current_one(self):
        sys.path.insert(0, str(ROOT / "src"))
        from cognalys.utils.corpus_rows import detector_context

        row = {"detector_code": "SSLCONTEXT-NOBS-01", "detector_label": "platform-default",
               "detector_label_meaning": self.STALE_PLATFORM_DEFAULT,
               "detector_site_kind": "NOBS: an older wording"}
        context = detector_context(row)
        self.assertEqual(context["label_meaning"], IMPORT.LABEL_MEANINGS["platform-default"])
        self.assertNotIn("correct code produces this", context["label_meaning"])
        self.assertEqual(context["site_kind"], "NOBS: " + IMPORT.SITE_KINDS["NOBS"])
        self.assertEqual(context["code"], "SSLCONTEXT-NOBS-01")

    def test_an_unknown_label_passes_unchanged(self):
        sys.path.insert(0, str(ROOT / "src"))
        from cognalys.utils.corpus_rows import detector_context

        row = {"detector_code": "SSLCONTEXT-NOBS-09", "detector_label": "a-new-label",
               "detector_label_meaning": "whatever the detector wrote",
               "detector_site_kind": "NOBS: an older wording"}
        self.assertEqual(detector_context(row), {
            "code": "SSLCONTEXT-NOBS-09", "label": "a-new-label",
            "label_meaning": "whatever the detector wrote",
            "site_kind": "NOBS: an older wording"})
