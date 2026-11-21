import contextlib
import csv
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import cli  # noqa: E402
from cognalys.integrations import rvsec  # noqa: E402
from cognalys.sources import read_rows  # noqa: E402
from cognalys.utils.corpus_rows import row_problems  # noqa: E402

COLUMNS = ["apk", "rep", "timeout", "tool", "time", "spec", "class", "method",
           "source", "code", "event", "message", "unique_msg"]
DES = ("cryptoapp.apk", "br.unb.cic.cryptoapp.cipher.CipherUtil", "des")
KEYGEN_MESSAGE = ("v=1 code=KEYGENERATOR-ALG-00 ev=g1 obj=KeyGenerator val='DES' "
                  "exp='one of AES,HmacSHA256' msg='expecting one of AES,HmacSHA256 but found DES'")
ORDER_MESSAGE = ("v=1 code=CIPHER-ORDER-00 ev=i1 obj=Cipher val='' exp='' "
                 "msg='the observed call sequence is not one CipherSpec accepts'")


def _report(rep, tool, spec, code, message, apk="cryptoapp.apk", cls=DES[1], method="des"):
    return {"apk": apk, "rep": rep, "timeout": "300", "tool": tool, "time": "40",
            "spec": spec, "class": cls, "method": method, "source": "CipherUtil.java:21",
            "code": code, "event": "g1", "message": message,
            "unique_msg": f"{cls}:::{method}:::{spec}:::UnsafeAlgorithm:::{code}:::g1:::{message}"}


def _errors_csv(path: Path, rows) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _codes(path: Path) -> Path:
    path.write_text(
        "spec,code,error_type,site_kind,event,file_line,label\n"
        "KeyGeneratorSpec,KEYGENERATOR-ALG-00,UnsafeAlgorithm,ALG,g1,KeyGeneratorSpec.mop:80,violation\n"
        "CipherSpec,CIPHER-ORDER-00,InvalidSequenceOfMethodCalls,ORDER,i1,CipherSpec.mop:300,sequence\n"
        "SecretKeySpecSpec,SECRETKEYSPEC-NOBS-03,RequiredPredicateError,NOBS,c1,"
        "SecretKeySpecSpec.mop:147,random-key-material\n",
        encoding="utf-8")
    return path


def _checkout(directory: Path) -> Path:
    repo = directory / "cryptoapp"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "build.gradle").write_text(
        'android {\n    defaultConfig {\n        applicationId "br.unb.cic.cryptoapp"\n    }\n}\n',
        encoding="utf-8")
    for arguments in (["init", "-q", "-b", "main"], ["config", "user.email", "t@x.invalid"],
                      ["config", "user.name", "T"], ["add", "-A"], ["commit", "-qm", "app"]):
        subprocess.run(["git", *arguments], cwd=repo, check=True, capture_output=True)
    return repo


class ImportTests(unittest.TestCase):
    """RVSec's errors.csv (rv-android `rv-experiment run`): one report per
    monitor firing, many per misuse across repetitions and tools."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.results = self.root / "results" / "exp_1"
        _errors_csv(self.results / "errors.csv", [
            _report("1", "monkey", "KeyGeneratorSpec", "KEYGENERATOR-ALG-00", KEYGEN_MESSAGE),
            _report("2", "monkey", "KeyGeneratorSpec", "KEYGENERATOR-ALG-00", KEYGEN_MESSAGE),
            _report("1", "ape", "KeyGeneratorSpec", "KEYGENERATOR-ALG-00", KEYGEN_MESSAGE),
            _report("1", "monkey", "CipherSpec", "CIPHER-ORDER-00", ORDER_MESSAGE),
        ])
        self.codes = rvsec.codes_table(_codes(self.root / "codes.csv"))
        self.repo = _checkout(self.root)

    def tearDown(self):
        self.directory.cleanup()

    def test_reports_of_one_misuse_become_one_finding(self):
        source = rvsec.checkout_source(self.repo)
        imported = rvsec.import_results([self.results], {"cryptoapp.apk": source}, self.codes)
        self.assertTrue(imported.complete)
        self.assertEqual(imported.reports, 4)
        keygen = next(row for row in imported.findings if row["spec"] == "KeyGeneratorSpec")
        self.assertEqual(keygen["message"], "expecting one of AES,HmacSHA256 but found DES")
        self.assertEqual(keygen["runs"], "3")
        self.assertEqual(keygen["detector_label"], "violation")
        self.assertEqual(keygen["detector_value"], "DES")
        self.assertEqual(keygen["detector_tools"], "ape, monkey")
        # RVSec reported it; the explorers only drove the app (detector_tools).
        self.assertEqual(keygen["tool"], "rvsec")
        self.assertEqual(keygen["commit"], source.commit)
        self.assertEqual(keygen["origin"], "app")
        self.assertEqual(keygen["repo"], "")
        self.assertEqual(row_problems(keygen), [])
        self.assertEqual(len(imported.findings), 2)

    def test_a_random_key_material_report_carries_the_catalogues_meaning(self):
        # CometOTP (2026-11-08): the stored meaning called a SecureRandom key
        # "the normal way to make a key" under a NOT OBSERVED prefix; the
        # meaning written now is data/detector_labels.json's.
        from cognalys.utils.detector_labels import detector_tables
        message = ("v=1 code=SECRETKEYSPEC-NOBS-03 ev=c1 obj=SecretKeySpec val='' "
                   "exp='prepared key material' msg='the key material was not prepared'")
        results = self.root / "results" / "exp_2"
        _errors_csv(results / "errors.csv", [
            _report("1", "monkey", "SecretKeySpecSpec", "SECRETKEYSPEC-NOBS-03", message)])
        source = rvsec.checkout_source(self.repo)
        imported = rvsec.import_results([results], {"cryptoapp.apk": source}, self.codes)
        [row] = imported.findings
        self.assertEqual(row["detector_label"], "random-key-material")
        meaning = detector_tables("rvsec")["label_meanings"]["random-key-material"]
        self.assertEqual(row["detector_label_meaning"], meaning)
        self.assertFalse(meaning.startswith(rvsec.LABEL_MEANINGS["not-observed"][:13]))
        self.assertNotIn("normal way", row["detector_label_meaning"])

    def test_an_apk_without_source_is_a_problem_not_a_guess(self):
        imported = rvsec.import_results([self.results], {}, self.codes)
        self.assertEqual(imported.findings, [])
        self.assertEqual({problem["problem"] for problem in imported.problems},
                         {"no source for this APK"})

    def test_rvsecs_dataset_sheet_is_a_source_map(self):
        sheet = self.root / "dataset.csv"
        sheet.write_text(
            "apk,manifest_package,repo_url,pinned_commit,head_pinned_commit\n"
            "org.app_12.apk,org.app,https://github.com/o/app,1111111,2222222\n",
            encoding="utf-8")
        [source] = rvsec.source_map(sheet).values()
        self.assertEqual(source.commit, "2222222")
        self.assertEqual(source.packages, ("org.app",))

    def test_an_app_with_several_own_packages_lists_them_all(self):
        """Futon's code lives under io.github.landwarderer.futon and eu.kanade.tachiyomi."""
        sheet = self.root / "sources.csv"
        sheet.write_text(
            "apk,repo_url,commit,manifest_package\n"
            "f_1.apk,https://github.com/o/f,5d2206a,io.github.landwarderer.futon; eu.kanade.tachiyomi\n",
            encoding="utf-8")
        [source] = rvsec.source_map(sheet).values()
        self.assertEqual(source.packages, ("io.github.landwarderer.futon", "eu.kanade.tachiyomi"))
        self.assertEqual(rvsec.code_origin("eu.kanade.tachiyomi.source.online.HttpSource",
                                           source.packages), "app")
        self.assertEqual(rvsec.code_origin("okhttp3.OkHttpClient", source.packages), "library")

    def test_the_codes_table_comes_from_an_rvsec_checkout(self):
        home = self.root / "rvsec"
        target = home / rvsec.CODES_IN_CHECKOUT / "jca_android" / "codes.csv"
        target.parent.mkdir(parents=True)
        _codes(target)
        self.assertEqual(set(rvsec.codes_table(rvsec_home=home)),
                         {"KEYGENERATOR-ALG-00", "CIPHER-ORDER-00", "SECRETKEYSPEC-NOBS-03"})

    def test_origin_is_unknown_rather_than_guessed(self):
        self.assertEqual(rvsec.manifest_package("cryptoapp.apk"), "")
        self.assertEqual(rvsec.manifest_package("org.fossify.notes_13.apk"), "org.fossify.notes")
        self.assertEqual(rvsec.code_origin("a.B", []), "")
        self.assertEqual(rvsec.code_origin("okio.ByteString", ["org.app"]), "library")

    def test_a_violation_describes_the_misuse_before_its_more_frequent_echoes(self):
        """okio's digest: ORDER-02 (creation-refused) twice as often as the MD5 violation."""
        codes = rvsec.codes_table(_codes(self.root / "codes.csv"))
        codes["MESSAGEDIGEST-ORDER-02"] = {"code": "MESSAGEDIGEST-ORDER-02", "label": "creation-refused"}
        codes["MESSAGEDIGEST-ALG-02"] = {"code": "MESSAGEDIGEST-ALG-02", "label": "violation"}
        self.assertEqual(rvsec.representative_code(
            {"MESSAGEDIGEST-ORDER-02": 30, "MESSAGEDIGEST-ALG-02": 15}, codes), "MESSAGEDIGEST-ALG-02")
        self.assertEqual(rvsec.representative_code({"X-1": 1, "X-2": 4}, {}), "X-2")

    def test_an_obfuscated_class_is_a_problem_not_a_library(self):
        for name in ("R1.b", "A.c", "a.b.c$d"):
            self.assertTrue(rvsec.is_obfuscated(name), name)
        for name in ("okio.ByteString", "okhttp3.internal.platform.Platform", "A", "io.ab.Crypto"):
            self.assertFalse(rvsec.is_obfuscated(name), name)
        results = self.root / "obfuscated" / "errors.csv"
        _errors_csv(results, [_report("1", "monkey", "KeyGeneratorSpec", "KEYGENERATOR-ALG-00",
                                      KEYGEN_MESSAGE, cls="Y1.d", method="a")])
        imported = rvsec.import_results([results], {"cryptoapp.apk": rvsec.checkout_source(self.repo)},
                                        self.codes)
        self.assertEqual(imported.findings, [])
        self.assertIn("obfuscated", imported.problems[0]["problem"])

    def _task_results(self, states):
        """A results dir: errors.csv with monkey's report, tasks.json, each task's logcat."""
        results = self.root / "failed" / "results" / "rvsec_1"
        _errors_csv(results / "errors.csv", [
            _report("1", "monkey:fast", "KeyGeneratorSpec", "KEYGENERATOR-ALG-00", KEYGEN_MESSAGE)])
        tasks = []
        for tool, state in states.items():
            name, variant = tool.split(":")
            logcat = results / "cryptoapp.apk" / f"cryptoapp.apk__1__300__{tool}.logcat"
            logcat.parent.mkdir(parents=True, exist_ok=True)
            logcat.write_text(
                "10-23 05:20:01.000  3136  3136 V RVSEC   : CipherSpec," + DES[1] + ",CipherUtil,"
                "encrypt,CipherUtil.java:30,InvalidSequenceOfMethodCalls," + ORDER_MESSAGE + "\n",
                encoding="utf-8")
            tasks.append({"config": {"apk_name": "cryptoapp.apk", "repetition": 1, "timeout": 300,
                                     "tool_config": {"name": name, "variant": variant}},
                          "result": {"state": state, "logcat_file": f"/opt/rvsec/{logcat.name}"}})
        (results / "tasks.json").write_text(json.dumps({"tasks": tasks}), encoding="utf-8")
        return results.parent

    def test_a_failed_tasks_reports_are_read_beside_a_completed_tasks_errors_csv(self):
        """2026-10-23 DNSToggle: monkey completed, ape ended in ERROR after 2 reports; 0 findings."""
        results = self._task_results({"monkey:fast": "COMPLETED", "ape:sata": "ERROR"})
        imported = rvsec.import_results([results], {"cryptoapp.apk": rvsec.checkout_source(self.repo)},
                                        self.codes)
        found = {(row["spec"], row["method"]): row for row in imported.findings}
        self.assertEqual(set(found), {("KeyGeneratorSpec", "des"), ("CipherSpec", "encrypt")})
        self.assertEqual(found["CipherSpec", "encrypt"]["detector_tools"], "ape:sata")
        self.assertEqual(found["CipherSpec", "encrypt"]["report_source"], "logcat")
        self.assertEqual(found["KeyGeneratorSpec", "des"]["report_source"], "errors.csv")
        # Monkey's logcat is not read: errors.csv holds that task already.
        self.assertEqual(imported.reports, 2)

    def test_no_logcat_is_read_when_every_task_completed(self):
        results = self._task_results({"monkey:fast": "COMPLETED", "ape:sata": "COMPLETED"})
        # ape completed without a row: its logcat is read, monkey's is not.
        self.assertEqual([path.name for path in rvsec.errors_files([results])],
                         ["errors.csv", "cryptoapp.apk__1__300__ape:sata.logcat"])
        csv_path = next(results.rglob("errors.csv"))
        _errors_csv(csv_path, [
            _report("1", "monkey:fast", "KeyGeneratorSpec", "KEYGENERATOR-ALG-00", KEYGEN_MESSAGE),
            _report("1", "ape:sata", "KeyGeneratorSpec", "KEYGENERATOR-ALG-00", KEYGEN_MESSAGE)])
        self.assertEqual([path.name for path in rvsec.errors_files([results])], ["errors.csv"])

    def test_the_methods_a_run_reached_come_from_its_logcat(self):
        logcat = self.root / "app.apk__1__600__monkey:fast.logcat"
        logcat.write_text(
            "10-14 20:39:01.017  3099  3099 I RVSEC-COV: <org.app.MainActivity: void onCreate(android.os.Bundle)>\n"
            "10-14 20:39:01.018  3099  3099 I RVSEC-COV: <org.app.MainActivity: void onCreate(android.os.Bundle)>\n"
            "10-14 20:39:02.000  3099  3099 I RVSEC-COV: <org.app.Lock: java.lang.Object invoke()>\n"
            "10-14 20:39:03.000  3099  3099 I ActivityManager: unrelated\n", encoding="utf-8")
        self.assertEqual(rvsec.reached_methods(logcat),
                         {("org.app.MainActivity", "onCreate"), ("org.app.Lock", "invoke")})
        self.assertEqual(rvsec.reached_methods(self.root / "missing.logcat"), set())

    def test_the_command_writes_a_findings_file_the_pipeline_reads(self):
        output = self.root / "findings.jsonl"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["rvsec-import", str(self.results), "--repo", str(self.repo),
                             "--codes", str(self.root / "codes.csv"), "-o", str(output)])
        self.assertEqual(code, 0)
        self.assertIn("4 RVSec report(s) -> 2 finding(s)", out.getvalue())
        rows = read_rows(output)
        self.assertEqual({row["spec"] for row in rows}, {"KeyGeneratorSpec", "CipherSpec"})
        self.assertTrue(all(row_problems(row) == [] for row in rows))
        self.assertEqual(json.loads(output.read_text().splitlines()[0])["apk"], "cryptoapp.apk")


if __name__ == "__main__":
    unittest.main()
