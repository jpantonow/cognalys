"""A failure must never produce the state that means "all clear".

The most damaging defects found in this pipeline had one shape: a failure
degraded to a neutral value -- [], "", None, False -- that downstream code
read as a legitimate answer. A crashed detector read as "alert absent" and
credited a repair; a rejected API key read as a content refusal and the step
succeeded; a shifted CSV row read as a finding with spec "35". Each test here
injects one failure and checks that the result names it instead of reading
as the absence of a problem.
"""
import importlib.util
import json
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.extract_methods_single_csv import RepositoryIndexer  # noqa: E402
from cognalys.prs import pr_github  # noqa: E402
from cognalys.prs import pr_validation  # noqa: E402

MODULE_PATH = ROOT / "src" / "cognalys" / "llm" / "generate_error_fixes.py"
SPEC = importlib.util.spec_from_file_location("absence_generator", MODULE_PATH)
generator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = generator
SPEC.loader.exec_module(generator)

LOGGER = logging.getLogger("failure-is-not-absence")


@unittest.skipIf(os.name == "nt", "a dangling symlink needs POSIX semantics")
class ClassIndexTests(unittest.TestCase):
    """An unreadable source file is not a file without classes."""

    def test_an_unreadable_file_is_recorded_and_the_index_is_not_cached(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.java").write_text("class A {}", encoding="utf-8")
            # Listed by the walk, unreadable when opened.
            (root / "Gone.java").symlink_to(root / "missing-target.java")
            indexer = RepositoryIndexer(root, LOGGER)
            with patch.object(indexer, "_index_fingerprint", return_value="c0ffee"), \
                 patch.object(indexer, "_store_index_cache") as store:
                indexer.build_index()
        self.assertIn("A", indexer.class_index)
        self.assertEqual(indexer.unreadable_files, ["Gone.java"])
        store.assert_not_called()


class FindingDiscoveryTests(unittest.TestCase):
    """A finding file that cannot be loaded stays in the denominator."""

    def _discover(self, files):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in files.items():
                (root / name).write_text(text, encoding="utf-8")
            fixer = generator.FixGenerator.__new__(generator.FixGenerator)
            fixer.input_dir = root
            fixer.logger = LOGGER
            fixer.migration_policies = {}
            errors = fixer.discover_errors()
            return errors, fixer.input_invalid

    def test_a_corrupt_json_is_recorded_not_dropped(self):
        errors, invalid = self._discover({"broken.json": '{"error": {'})
        self.assertEqual(errors, [])
        self.assertEqual(len(invalid), 1)
        self.assertIn("JSONDecodeError", invalid[0]["cause"])

    def test_an_unrelated_json_is_not_reported_as_a_finding(self):
        _, invalid = self._discover({"index.json": json.dumps({"files": []})})
        self.assertEqual(invalid, [])

    def test_a_stored_label_meaning_is_discovered_in_its_current_words(self):
        # 2026-11-10: 17 adjudications read an older platform-default meaning
        # ending "correct code produces this"; the analysis reads the label
        # catalogue's current text instead of the one stored with the finding.
        from cognalys.utils.detector_labels import detector_tables
        stale = ("NOT OBSERVED: the runtime monitor tracks the producers a rule "
                 "requires by object identity within one process, and saw none "
                 "for this object. The argument was null, which the API documents "
                 "as 'use the platform default' (e.g. TrustManagerFactory.init("
                 "(KeyStore) null)); correct code produces this.")
        record = {"error": {"error_message": "m", "unique_error_id": "id-1",
                            "spec": "SSLContextSpec", "tool": "rvsec",
                            "detector_context": {"code": "SSLCONTEXT-NOBS-01",
                                                 "label": "platform-default",
                                                 "label_meaning": stale,
                                                 "value": "null"}},
                  "method_info": {"name": "build"},
                  "source_code": {"method_body": "void build() {}"}}
        errors, invalid = self._discover({"finding.json": json.dumps(record)})
        self.assertEqual(invalid, [])
        [error] = errors
        context = error["detector_context"]
        self.assertEqual(context["label_meaning"],
                         detector_tables("rvsec")["label_meanings"]["platform-default"])
        self.assertNotIn("correct code produces this", context["label_meaning"])
        self.assertEqual((context["code"], context["value"]), ("SSLCONTEXT-NOBS-01", "null"))

    def test_a_flat_record_is_discovered_in_its_current_words_and_gains_no_key(self):
        # The older flat structure carries its record as stored; it reads the
        # same current texts, and a flat record without one gets none.
        from cognalys.utils.detector_labels import detector_tables
        stale = ("NOT OBSERVED: the runtime monitor tracks the producers a rule "
                 "requires by object identity within one process, and saw none "
                 "for this object. The argument was null, which the API documents "
                 "as 'use the platform default' (e.g. TrustManagerFactory.init("
                 "(KeyStore) null)); correct code produces this.")
        flat = {"error_message": "m", "method_body": "void build() {}",
                "method_name": "build", "spec": "SSLContextSpec"}
        files = {
            "with.json": json.dumps({**flat, "unique_error_id": "with",
                                     "detector_context": {"code": "SSLCONTEXT-NOBS-01",
                                                          "label": "platform-default",
                                                          "label_meaning": stale}}),
            "without.json": json.dumps({**flat, "unique_error_id": "without"}),
        }
        errors, invalid = self._discover(files)
        self.assertEqual(invalid, [])
        found = {error["unique_error_id"]: error for error in errors}
        self.assertEqual(found["with"]["detector_context"]["label_meaning"],
                         detector_tables("rvsec")["label_meanings"]["platform-default"])
        self.assertNotIn("detector_context", found["without"])


class ResumeKeyTests(unittest.TestCase):
    """A saved solution skips its own APK's finding on resume, not another APK's."""

    def test_two_apks_reporting_the_same_finding_id_are_resumed_apart(self):
        # unique_msg does not name the APK (rvsec.py): two APKs embedding one
        # library method report the same id, and the resume looked the id up
        # across every APK's solutions.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            solved = root / "out" / "a.apk"
            solved.mkdir(parents=True)
            (solved / "0_digest_solution.json").write_text(json.dumps(
                {"original_error": {"unique_error_id": "lib.Hash.digest|MD5"}}),
                encoding="utf-8")
            (solved / "1_broken_solution.json").write_text("{", encoding="utf-8")
            fixer = generator.FixGenerator.__new__(generator.FixGenerator)
            fixer.output_dir = root / "out"
            fixer.logger = LOGGER
            with self.assertLogs(LOGGER, level="WARNING"):
                existing = fixer.check_existing_solutions()
        errors = [{"_file_path": root / "in" / apk / "0_digest.json",
                   "unique_error_id": "lib.Hash.digest|MD5"} for apk in ("a.apk", "b.apk")]
        self.assertEqual([fixer.solution_key(error) in existing for error in errors],
                         [True, False])


class ContinuousIntegrationEvidenceTests(unittest.TestCase):
    """Checks that could not be read are not checks that passed."""

    PR = {"base": {"repo": {"full_name": "o/r"}, "ref": "main"},
          "head": {"sha": "abcdef1234567890"}}

    def test_a_failed_fetch_is_reported_through_errors(self):
        errors = []
        with patch.object(pr_github, "fetch_check_runs",
                          side_effect=RuntimeError("HTTP 502")):
            failures = pr_github.ci_failures_from_pr(self.PR, errors)
            signoff = pr_github.signoff_check_failure(self.PR, errors)
        self.assertEqual(failures, [])
        self.assertIsNone(signoff)
        self.assertEqual(len(errors), 2)
        self.assertIn("HTTP 502", errors[0])

    def test_without_an_error_list_the_old_contract_holds(self):
        with patch.object(pr_github, "fetch_check_runs",
                          side_effect=RuntimeError("HTTP 502")):
            self.assertEqual(pr_github.ci_failures_from_pr(self.PR), [])


class StyleRepairTests(unittest.TestCase):
    """A formatter change that could not be reverted fails the repair."""

    def test_an_unreverted_file_outside_the_patch_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrapper = root / ("gradlew.bat" if os.name == "nt" else "gradlew")
            wrapper.write_text("", encoding="utf-8")
            source = root / "app" / "src" / "main" / "A.kt"
            source.parent.mkdir(parents=True)
            source.write_text("", encoding="utf-8")

            def fake_git(_root, *args):
                if args[:2] == ("status", "--porcelain"):
                    return " M app/src/main/A.kt\n M other/B.kt\n"
                raise RuntimeError("index.lock exists")

            completed = type("Completed", (), {"returncode": 0,
                                                "stdout": "", "stderr": ""})()
            with patch.object(pr_validation, "run_git", fake_git), \
                 patch.object(pr_validation.subprocess, "run",
                              return_value=completed):
                result = pr_validation.repair_style_violations(root, [source], 60)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["not_reverted"], ["other/B.kt"])



class GeneratedPackageTests(unittest.TestCase):
    """A source package named "generated" is source; build/generated is not."""

    def test_a_package_named_generated_is_indexed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app" / "src" / "main" / "java" / "org" / "app" / "generated"
            source.mkdir(parents=True)
            (source / "Activity.java").write_text(
                "package org.app.generated;\nclass Activity {}", encoding="utf-8")
            output = root / "app" / "build" / "generated" / "source"
            output.mkdir(parents=True)
            (output / "BuildConfig.java").write_text(
                "package org.app;\nclass BuildConfig {}", encoding="utf-8")
            indexer = RepositoryIndexer(root, LOGGER)
            with patch.object(indexer, "_index_fingerprint", return_value=""):
                indexer.build_index()
        self.assertIn("org.app.generated.Activity", indexer.class_index)
        self.assertNotIn("org.app.BuildConfig", indexer.class_index)


if __name__ == "__main__":
    unittest.main()
