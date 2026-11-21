"""Re-running the detector, and refusing to credit what it did not check.

Compiling shows a patch is well-formed, not that the reported problem is
gone. The detector that reported the finding can be asked directly -- but a
naive replay collapses three different situations into "fixed", and these
tests pin them apart:

  * the alert is absent from the baseline too (`not_reproduced`), so the
    patch cannot be credited with removing it;
  * the file was never analysed (`not_exercised`) -- PMD's Java rulesets do
    not parse Kotlin, which is most of this corpus's Android code;
  * the detector is not on this machine (`detector_unavailable`).

PMD itself is not installed where this suite runs, so the subprocess path is
exercised against a stand-in executable that writes a report in PMD's XML
format. That tests the command line, the report parsing and the matching
together, which a mocked scan would not.
"""
import os
import stat
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.validation.detector_replay import (  # noqa: E402
    ALERT_ABSENT, ALERT_PRESENT, DETECTOR_ERROR, DETECTOR_MISMATCH, DETECTOR_UNAVAILABLE,
    FILE_NOT_PROCESSED, INVALID_REPORT, METHOD_REMOVED, METHOD_RENAMED, NOT_EXERCISED,
    declares_method, file_at_revision, matches, reclassify, replay, reproduce,
    replay_pair, scan_file,
)


# Writes one violation of rule AvoidUnsafeThing in method `encrypt` when the
# scanned file contains the marker UNSAFE, and an empty report otherwise.
FAKE_PMD = """#!/usr/bin/env python3
import sys
args = sys.argv[1:]
target = args[args.index("--dir") + 1]
report = args[args.index("--report-file") + 1]
source = open(target, encoding="utf-8").read()
# Failure modes, keyed on markers in the scanned file.
if "CRASH" in source:
    sys.stderr.write("internal error")
    sys.exit(2)
if "TRUNCATE" in source:
    open(report, "w", encoding="utf-8").write('<?xml version="1.0"?><pmd><file')
    sys.exit(0)
if "SILENT" in source:
    sys.exit(0)
if "UNPARSEABLE" in source:
    open(report, "w", encoding="utf-8").write(
        '<?xml version="1.0"?><pmd><error filename="%s" msg="ParseException"/>'
        '</pmd>' % target
    )
    sys.exit(0)
violations = ""
if "UNSAFE" in source:
    violations = (
        '<file name="%s"><violation beginline="3" rule="AvoidUnsafeThing" '
        'package="app" class="Crypto" method="encrypt" priority="3">'
        'Unsafe thing</violation></file>' % target
    )
open(report, "w", encoding="utf-8").write(
    '<?xml version="1.0"?><pmd xmlns="http://pmd.sourceforge.net/report/2.0.0">'
    + violations + '</pmd>'
)
"""


class _Detector:
    def __enter__(self):
        self.directory = tempfile.TemporaryDirectory()
        path = Path(self.directory.name) / "pmd"
        # The interpreter running this suite, so the stand-in needs nothing
        # installed beyond what the tests already use.
        path.write_text(
            f"#!{sys.executable}\n" + FAKE_PMD.split("\n", 1)[1],
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
        self.path = str(path)
        return self

    def __exit__(self, *exc):
        self.directory.cleanup()


def _java(directory: Path, name: str, unsafe: bool, marker: str = "") -> Path:
    path = directory / name
    path.write_text(
        "package app;\nclass Crypto {\n  void encrypt() { "
        + ("UNSAFE();" if unsafe else "safe();") + marker + " }\n}\n",
        encoding="utf-8",
    )
    return path


@unittest.skipIf(os.name == "nt", "the stand-in detector is a POSIX script")
class ScanTests(unittest.TestCase):

    def test_a_missing_detector_is_reported_as_such(self):
        with tempfile.TemporaryDirectory() as directory:
            target = _java(Path(directory), "Crypto.java", unsafe=True)
            result = scan_file(target, detector="/no/such/pmd")
        self.assertEqual(result["status"], DETECTOR_UNAVAILABLE)

    def test_a_kotlin_file_is_not_exercised_rather_than_clean(self):
        with _Detector() as detector, tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "Crypto.kt"
            target.write_text("class Crypto { fun encrypt() { UNSAFE() } }",
                              encoding="utf-8")
            result = scan_file(target, detector=detector.path)
        self.assertEqual(result["status"], NOT_EXERCISED)
        self.assertIn("not analysed", result["detail"])

    def test_the_reported_rule_is_found_on_the_unsafe_file(self):
        with _Detector() as detector, tempfile.TemporaryDirectory() as directory:
            target = _java(Path(directory), "Crypto.java", unsafe=True)
            result = replay(target, "AvoidUnsafeThing", "encrypt",
                            "app.Crypto", detector=detector.path)
        self.assertEqual(result["status"], ALERT_PRESENT)
        self.assertEqual(len(result["matching_violations"]), 1)

    def test_the_reported_rule_is_absent_from_the_safe_file(self):
        with _Detector() as detector, tempfile.TemporaryDirectory() as directory:
            target = _java(Path(directory), "Crypto.java", unsafe=False)
            result = replay(target, "AvoidUnsafeThing", "encrypt",
                            "app.Crypto", detector=detector.path)
        self.assertEqual(result["status"], ALERT_ABSENT)


@unittest.skipIf(os.name == "nt", "the stand-in detector is a POSIX script")
class PairTests(unittest.TestCase):

    def _pair(self, before_unsafe: bool, after_unsafe: bool) -> dict:
        with _Detector() as detector, tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "before").mkdir()
            (root / "after").mkdir()
            before = _java(root / "before", "Crypto.java", before_unsafe)
            after = _java(root / "after", "Crypto.java", after_unsafe)
            return replay_pair(before, after, "AvoidUnsafeThing", "encrypt",
                               "app.Crypto", detector=detector.path)

    def test_an_alert_that_disappears_is_repaired(self):
        self.assertEqual(self._pair(True, False)["outcome"], "repaired")

    def test_an_alert_that_stays_is_unchanged(self):
        self.assertEqual(self._pair(True, True)["outcome"], "unchanged")

    def test_an_alert_the_patch_creates_is_introduced(self):
        self.assertEqual(self._pair(False, True)["outcome"], "introduced")

    def test_an_alert_absent_from_the_baseline_cannot_be_credited(self):
        pair = self._pair(False, False)
        self.assertEqual(pair["outcome"], "not_reproduced")
        self.assertIn("cannot be credited", pair["detail"])

    def test_an_unavailable_detector_decides_the_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").mkdir()
            (root / "b").mkdir()
            pair = replay_pair(
                _java(root / "a", "Crypto.java", True),
                _java(root / "b", "Crypto.java", False),
                "AvoidUnsafeThing", "encrypt", detector="/no/such/pmd",
            )
        self.assertEqual(pair["outcome"], DETECTOR_UNAVAILABLE)


@unittest.skipIf(os.name == "nt", "the stand-in detector is a POSIX script")
class DetectorFailureTests(unittest.TestCase):
    """A scan that failed after the patch must never credit a repair.

    Each case has the alert in the baseline and a patched file on which the
    detector fails in a different way; a reader that turns "no report" into
    "no violations" would score every one of them as repaired.
    """

    def _pair_with_failed_patch(self, marker: str) -> dict:
        with _Detector() as detector, tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "before").mkdir()
            (root / "after").mkdir()
            before = _java(root / "before", "Crypto.java", True)
            after = _java(root / "after", "Crypto.java", False, marker)
            return replay_pair(before, after, "AvoidUnsafeThing", "encrypt",
                               "app.Crypto", detector=detector.path)

    def test_an_abnormal_exit_is_a_detector_error(self):
        pair = self._pair_with_failed_patch("CRASH")
        self.assertEqual(pair["outcome"], DETECTOR_ERROR)
        self.assertEqual(pair["patched"]["exit_code"], 2)

    def test_a_truncated_report_is_invalid(self):
        self.assertEqual(self._pair_with_failed_patch("TRUNCATE")["outcome"],
                         INVALID_REPORT)

    def test_a_missing_report_is_invalid(self):
        self.assertEqual(self._pair_with_failed_patch("SILENT")["outcome"],
                         INVALID_REPORT)

    def test_a_file_the_detector_could_not_parse_is_not_processed(self):
        self.assertEqual(self._pair_with_failed_patch("UNPARSEABLE")["outcome"],
                         FILE_NOT_PROCESSED)


@unittest.skipIf(os.name == "nt", "the stand-in detector is a POSIX script")
class RemovalTests(unittest.TestCase):
    """Deleting the method silences a method-scoped rule; that is no repair."""

    def test_a_deleted_method_is_not_credited(self):
        with _Detector() as detector, tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "before").mkdir()
            (root / "after").mkdir()
            before = _java(root / "before", "Crypto.java", True)
            after = root / "after" / "Crypto.java"
            after.write_text("package app;\nclass Crypto {\n}\n", encoding="utf-8")
            pair = replay_pair(before, after, "AvoidUnsafeThing", "encrypt",
                               "app.Crypto", detector=detector.path)
        self.assertEqual(pair["outcome"], METHOD_REMOVED)


def _marker_replay(marker):
    """A replay that reports the alert wherever `marker` is in the file."""
    def replay_fn(target, rule, method, class_name="", **_options):
        present = marker in Path(target).read_text(encoding="utf-8")
        return {"status": ALERT_PRESENT if present else ALERT_ABSENT}
    return replay_fn


class ReporterAgreementTests(unittest.TestCase):
    """A replayed rule is not the reporting detector (2026-10-29 review, P3).

    Fread's "SSL" -> "TLS" read as unchanged because SSLContextSpec.yml
    rejects "TLS", which RVSec's own message accepted; Orgzly's sha1 ->
    sha256 rename read as a removed method.
    """

    FREAD_BEFORE = ('object GlobalOkHttpClient {\n    fun buildSSLFactory(): SSLSocketFactory {\n'
                    '        val sslContext = SSLContext.getInstance("SSL")\n'
                    '        sslContext.defaultSSLParameters.protocols = arrayOf("SSLv3")\n'
                    '        return sslContext.socketFactory\n    }\n}\n')
    FREAD_AFTER = ('object GlobalOkHttpClient {\n    fun buildSSLFactory(): SSLSocketFactory {\n'
                   '        val sslContext = SSLContext.getInstance("TLS")\n'
                   '        return sslContext.socketFactory\n    }\n}\n')

    def _pair(self, before, after, method, message="", suffix=".kt", marker="getInstance"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").mkdir()
            (root / "b").mkdir()
            baseline = root / "a" / f"File{suffix}"
            patched = root / "b" / f"File{suffix}"
            baseline.write_text(before, encoding="utf-8")
            patched.write_text(after, encoding="utf-8")
            return replay_pair(baseline, patched, "SSLContextSpec", method,
                               replay_fn=_marker_replay(marker), reporter_message=message)

    def test_a_value_the_reporter_accepts_is_a_detector_mismatch(self):
        pair = self._pair(self.FREAD_BEFORE, self.FREAD_AFTER, "buildSSLFactory",
                          "expecting one of TLSV1.2,TLSV1.3,TLS but found SSL")
        self.assertEqual(pair["outcome"], DETECTOR_MISMATCH)
        self.assertEqual(pair["reporter_accepted_value"], "TLS")

    def test_a_value_the_reporter_rejects_stays_unchanged(self):
        pair = self._pair(self.FREAD_BEFORE, self.FREAD_AFTER,
                          "buildSSLFactory", "expecting one of {TLSv1.2, TLSv1.3} but found SSL")
        self.assertEqual(pair["outcome"], "unchanged")
        self.assertEqual(self._pair(self.FREAD_BEFORE, self.FREAD_AFTER,
                                    "buildSSLFactory")["outcome"], "unchanged")

    ORGZLY_BEFORE = ('object MiscUtils {\n'
                     '    fun sha1(text: String): String {\n'
                     '        val digest = MessageDigest.getInstance("SHA-1")\n'
                     '        return digest.digest(text.toByteArray()).toHex()\n    }\n'
                     '    fun other() = sha1("x")\n}\n')

    def test_a_confirmed_rename_is_not_a_removal(self):
        after = self.ORGZLY_BEFORE.replace("sha1", "sha256").replace('"SHA-1"', '"SHA-256"')
        pair = self._pair(self.ORGZLY_BEFORE, after, "sha1", marker='"SHA-1"')
        self.assertEqual(pair["outcome"], METHOD_RENAMED)
        self.assertEqual(pair["renamed_to"], "sha256")
        self.assertEqual(renamed_declaration_of(self.ORGZLY_BEFORE, after, "sha1",
                                                {"sha1": "sha256"}), "sha256")

    def test_a_deleted_method_is_still_removed(self):
        after = ('object MiscUtils {\n    fun other() = "x"\n'
                 '    fun unrelated(text: String): Int { return text.length }\n}\n')
        pair = self._pair(self.ORGZLY_BEFORE, after, "sha1", marker='"SHA-1"')
        self.assertEqual(pair["outcome"], METHOD_REMOVED)

    def test_a_method_whose_old_name_is_still_called_was_not_renamed(self):
        after = self.ORGZLY_BEFORE.replace("fun sha1(", "fun sha256(").replace(
            '"SHA-1"', '"SHA-256"')
        self.assertEqual(renamed_declaration_of(self.ORGZLY_BEFORE, after, "sha1"), "")


def renamed_declaration_of(before, after, method, confirmed=None):
    from cognalys.validation.detector_replay import renamed_declaration

    with tempfile.TemporaryDirectory() as directory:
        baseline = Path(directory) / "Before.kt"
        patched = Path(directory) / "After.kt"
        baseline.write_text(before, encoding="utf-8")
        patched.write_text(after, encoding="utf-8")
        return renamed_declaration(baseline, patched, method, confirmed)


class PatchCorrectnessTests(unittest.TestCase):
    def test_a_mismatch_or_a_rename_does_not_contradict_the_patch(self):
        from cognalys.evaluation.patch_correctness import assess

        for outcome in (DETECTOR_MISMATCH, METHOD_RENAMED):
            verdict = assess({"status": "success", "detector_replay": {"outcome": outcome}},
                             {"success"})
            self.assertEqual(verdict["verdict"], "unverified", outcome)
            self.assertEqual(verdict["contradicted"], [])
        removed = assess({"status": "success", "detector_replay": {"outcome": METHOD_REMOVED}},
                         {"success"})
        self.assertEqual(removed["verdict"], "incorrect")


class DeclarationTests(unittest.TestCase):

    def _declares(self, source, method="encrypt"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "A.java"
            path.write_text(source, encoding="utf-8")
            return declares_method(path, method)

    def test_a_declaration_with_throws_is_found(self):
        self.assertTrue(self._declares(
            "class A { byte[] encrypt(String s)\n throws Exception { return null; } }"
        ))

    def test_a_call_alone_is_not_a_declaration(self):
        self.assertFalse(self._declares("class A { void run() { encrypt(x); } }"))

    def test_an_unanswerable_question_keeps_the_repair(self):
        self.assertTrue(declares_method(Path("/no/such/file.java"), "encrypt"))
        self.assertTrue(self._declares("class A {}", method="<init>"))


class ReproduceTests(unittest.TestCase):
    """The detector's own verdict on the unpatched file, for adjudication."""

    def test_a_tool_without_an_adapter_is_uncovered(self):
        result = reproduce("semgrep", Path("."), "A.java", "Rule", "m")
        self.assertEqual(result["status"], "no_detector_coverage")

    @unittest.skipIf(os.name == "nt", "the stand-in detector is a POSIX script")
    def test_the_reported_rule_firing_is_reported_present(self):
        from cognalys.validation import detector_replay as module

        with _Detector() as detector, tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _java(root, "Crypto.java", unsafe=True)
            adapter = module.ADAPTERS["pmd"]
            local = module.DetectorAdapter(
                tool="pmd", suffixes=adapter.suffixes,
                replay_pair=adapter.replay_pair,
                describe=lambda: {"tool": "pmd"},
                replay=lambda *a, **k: replay(*a, detector=detector.path, **k),
            )
            with unittest.mock.patch.dict(module.ADAPTERS, {"pmd": local}):
                result = reproduce("PMD", root, "Crypto.java",
                                   "AvoidUnsafeThing", "encrypt", "app.Crypto")
        self.assertEqual(result["status"], ALERT_PRESENT)
        self.assertEqual(result["matching_lines"], ["3"])


class ReclassifyTests(unittest.TestCase):
    """Pairs stored before these states existed are re-read, not trusted."""

    def test_a_recorded_repair_over_a_failed_scan_becomes_an_error(self):
        stored = {"outcome": "repaired",
                  "baseline": {"status": "alert_present", "exit_code": 0},
                  "patched": {"status": "alert_absent", "exit_code": 2}}
        result = reclassify(stored)
        self.assertEqual(result["outcome"], DETECTOR_ERROR)
        self.assertEqual(result["recorded_outcome"], "repaired")

    def test_a_clean_recorded_repair_stands(self):
        stored = {"outcome": "repaired",
                  "baseline": {"exit_code": 0}, "patched": {"exit_code": 0}}
        self.assertIs(reclassify(stored), stored)

    def test_a_record_without_an_outcome_is_untouched(self):
        self.assertEqual(reclassify({}), {})


class MatchingTests(unittest.TestCase):

    VIOLATION = {"rule": "AvoidUnsafeThing", "method": "encrypt",
                 "class": "Crypto", "message": "at line 3"}

    def test_rule_and_method_must_both_match(self):
        self.assertTrue(matches(self.VIOLATION, "AvoidUnsafeThing", "encrypt"))
        self.assertFalse(matches(self.VIOLATION, "OtherRule", "encrypt"))
        self.assertFalse(matches(self.VIOLATION, "AvoidUnsafeThing", "decrypt"))

    def test_a_different_class_does_not_match(self):
        self.assertFalse(matches(
            self.VIOLATION, "AvoidUnsafeThing", "encrypt", "app.Other",
        ))

    def test_a_changed_message_still_matches(self):
        # Messages carry positions that move between versions; requiring an
        # exact match would report every rephrasing as a repair.
        self.assertTrue(matches(
            {**self.VIOLATION, "message": "at line 97"},
            "AvoidUnsafeThing", "encrypt", "app.Crypto",
        ))


class RevisionTests(unittest.TestCase):

    def test_the_baseline_is_read_from_git_without_touching_the_tree(self):
        import subprocess

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            repo.mkdir()
            for args in (("init", "-q"),
                         ("config", "user.email", "t@example.com"),
                         ("config", "user.name", "Test")):
                subprocess.run(["git", "-C", str(repo), *args], check=True,
                               capture_output=True)
            _java(repo, "Crypto.java", unsafe=True)
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True,
                           capture_output=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "a"],
                           check=True, capture_output=True)
            _java(repo, "Crypto.java", unsafe=False)
            baseline = file_at_revision(
                repo, "HEAD", "Crypto.java", Path(directory) / "base" / "Crypto.java",
            )
            self.assertIn("UNSAFE", baseline.read_text(encoding="utf-8"))
            self.assertIn("safe();", (repo / "Crypto.java").read_text(encoding="utf-8"))
            self.assertIsNone(file_at_revision(
                repo, "HEAD", "Missing.java", Path(directory) / "x.java",
            ))


if __name__ == "__main__":
    unittest.main()
