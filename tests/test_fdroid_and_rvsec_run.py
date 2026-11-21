import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import cli  # noqa: E402
from cognalys.integrations import fdroid, rvsec  # noqa: E402

# Shaped like fdroiddata's metadata/io.github.landwarderer.futon.yml.
METADATA = """Categories:
  - Reading
License: GPL-3.0-only
Repo: https://github.com/AppFuton/Futon.git

Builds:
  - versionName: 9.8.1
    versionCode: 90801
    commit: 1111111111111111111111111111111111111111
    subdir: app

  - versionName: 9.8.2
    versionCode: 90802
    commit: 5d2206a6926adf53be0867ad784948ed16663f44
    subdir: app

  - versionName: 9.9.0
    versionCode: 90900
    commit: v9.9.0
"""


def fake_fetch(responses):
    def fetch(url, timeout=60):
        for fragment, body in responses.items():
            if fragment in url:
                return body
        raise OSError(f"unexpected {url}")
    return fetch


class FdroidTests(unittest.TestCase):
    def test_the_commit_of_the_suggested_build_is_read(self):
        self.assertEqual(fdroid.parse_metadata(METADATA, 90802),
                         ("https://github.com/AppFuton/Futon",
                          "5d2206a6926adf53be0867ad784948ed16663f44"))

    def test_apks_and_their_source_map_are_written(self):
        fetch = fake_fetch({
            "/api/v1/packages/io.github.landwarderer.futon": json.dumps(
                {"suggestedVersionCode": 90802}).encode(),
            "metadata/io.github.landwarderer.futon.yml": METADATA.encode(),
            "/repo/io.github.landwarderer.futon_90802.apk": b"PK apk",
        })
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            taken, problems = fdroid.prepare(["io.github.landwarderer.futon"], out, fetch)
            self.assertEqual(problems, [])
            self.assertEqual((out / "apks" / "io.github.landwarderer.futon_90802.apk").read_bytes(),
                             b"PK apk")
            [row] = list(csv.DictReader(open(out / "sources.csv", encoding="utf-8")))
        self.assertEqual(row["commit"], "5d2206a6926adf53be0867ad784948ed16663f44")
        self.assertEqual(row["repo_url"], "https://github.com/AppFuton/Futon")

    def test_a_build_recorded_by_tag_is_a_problem_not_a_source(self):
        fetch = fake_fetch({
            "/api/v1/packages/app": json.dumps({"suggestedVersionCode": 90900}).encode(),
            "metadata/app.yml": METADATA.encode(),
        })
        with tempfile.TemporaryDirectory() as directory:
            taken, problems = fdroid.prepare(["app"], Path(directory), fetch)
        self.assertEqual(taken, [])
        self.assertIn("no commit hash (v9.9.0)", problems[0]["problem"])


REPORT_HEADER = "apk,rep,timeout,tool,time,spec,class,method,source,code,event,message,unique_msg\n"
SOURCES = ("apk,repo_url,commit,manifest_package\n"
           "app_1.apk,https://github.com/o/app,5d2206a6926adf53be0867ad784948ed16663f44,org.app\n"
           "other_2.apk,https://github.com/o/other,5d2206a6926adf53be0867ad784948ed16663f44,org.app\n")
FORMAT4RCC = ("instr-cli exited with code 1\nstderr:\n"
              "java.lang.IllegalStateException: Instruction format Format4rcc not supported\n")


class FakeRvsec:
    """rv-experiment as these tests need it: each call follows its own plan.

    A plan names the APKs the instrumenter fails on ("uninstrumented") and,
    per tool, (state, error, methods reached); a completed task that reached
    methods reports one MessageDigest misuse.
    """

    def __init__(self, *plans):
        self.plans, self.calls = list(plans), []

    def __call__(self, apks, folder, name, log, settings):
        plan = self.plans[len(self.calls)]
        names = sorted(path.name for path in Path(apks).glob("*.apk"))
        self.calls.append(SimpleNamespace(apks=Path(apks), names=names, settings=settings,
                                          folder=Path(folder), name=name))
        results = Path(folder) / "results" / name
        instrumented = results / "instrumented_apks"
        instrumented.mkdir(parents=True)
        Path(log).write_text("rv-experiment\n", encoding="utf-8")
        errors, rows, tasks = {}, [], []
        for apk in names:
            if apk in plan.get("uninstrumented", ()):
                errors[f"/opt/rvsec/rv-android/apks/{apk}"] = {"code": 1, "message": FORMAT4RCC}
                continue
            (instrumented / apk).write_bytes(b"PK woven" * 100)
            for tool in settings.tools.split(","):
                state, error, reached = plan.get(tool, ("COMPLETED", "", 3))
                logcat = results / apk / f"{apk}__1__600__{tool}.logcat"
                logcat.parent.mkdir(exist_ok=True)
                logcat.write_text("".join(f"10-31 10:00:00.000 1 1 V RVSEC-COV: <org.app.M{i}: "
                                          f"void run()>\n" for i in range(reached)), encoding="utf-8")
                (results / apk / f"{apk}__1__600__{tool}.trace").write_bytes(b"t" * 50)
                tasks.append({"config": {"apk_name": apk, "repetition": 1, "timeout": 600,
                                         "tool_config": dict(zip(("name", "variant"), tool.split(":")))},
                              "result": {"state": state, "error_message": error,
                                         "execution_time_seconds": 60, "logcat_file": f"/x/{logcat.name}",
                                         "coverage_metrics": {"total_errors": int(bool(reached))}}})
                if state == "COMPLETED" and reached:
                    rows.append(f"{apk},1,600,{tool},9,MessageDigestSpec,org.app.Hasher,digest,"
                                "Hasher.kt:9,MD-ALG,g1,v=1 code=MD-ALG msg='found MD5',"
                                "org.app.Hasher:::digest\n")
        (instrumented / "instrument_errors.json").write_text(json.dumps(errors), encoding="utf-8")
        (results / "woven_classes.dex").write_bytes(b"dex" * 100)
        (results / "lib_tmp").mkdir()
        (results / "lib_tmp" / "aspectjrt.jar").write_bytes(b"jar" * 100)
        if tasks:
            (results / "tasks.json").write_text(json.dumps({"tasks": tasks}), encoding="utf-8")
            (results / "errors.csv").write_text(REPORT_HEADER + "".join(rows), encoding="utf-8")
        return 0, rvsec.errors_files([Path(folder) / "results"])


def rvsec_run(root, fake, *options, min_sdks=None):
    """cli rvsec-run over root/apks (app_1.apk) with ``fake`` as rv-experiment: (code, output).

    ``min_sdks`` maps APK names to the minSdk aapt would read; the image runs API 30.
    """
    (root / "apks").mkdir(exist_ok=True)
    (root / "apks" / "app_1.apk").write_bytes(b"PK app")
    (root / "sources.csv").write_text(SOURCES, encoding="utf-8")
    min_sdks = min_sdks or {}
    with patch.object(rvsec, "run_experiment", fake), \
            patch.object(rvsec, "apk_min_sdk", lambda apk, *args: min_sdks.get(Path(apk).name)), \
            patch.object(rvsec, "image_api_level", return_value=30), \
            contextlib.redirect_stdout(io.StringIO()) as out:
        code = cli.main(["rvsec-run", str(root / "apks"), "--sources", str(root / "sources.csv"),
                         "--tools", "monkey:fast,ape:sata", "--work-dir", str(root / "work"),
                         "-o", str(root / "findings.jsonl"), *options])
    return code, out.getvalue()


class RvsecRunTests(unittest.TestCase):
    def test_the_docker_command_carries_the_settings(self):
        command = rvsec.docker_command(Path("/data/apks"), Path("/work"), "rvsec_x",
                                       rvsec.ExperimentSettings(tools="ape", timeouts="300"))
        self.assertEqual(command[:3], ["docker", "run", "--rm"])
        self.assertIn("/dev/kvm", command)
        self.assertIn("RV_INSTRUMENTATION_VARIANT=dexlib2", command)
        self.assertIn("RV_TOOLS=ape", command)
        self.assertIn("/data/apks:/opt/rvsec/rv-android/apks", command)
        self.assertEqual(command[-1], rvsec.DEFAULT_IMAGE)

    def test_gator_static_analysis_is_skipped_unless_asked_for(self):
        """16.8 h over 158 runs (2026-10-22..31) on a phase nothing reads."""
        skipped = rvsec.docker_command(Path("/a"), Path("/w"), "x")
        # rv-experiment reads the variable as --static-analysis/--skip-static.
        self.assertIn("RV_SKIP_STATIC_ANALYSIS=false", skipped)
        asked = rvsec.docker_command(Path("/a"), Path("/w"), "x",
                                     rvsec.ExperimentSettings(static_analysis=True))
        self.assertIn("RV_SKIP_STATIC_ANALYSIS=true", asked)

    def test_an_apk_the_instrumenter_failed_on_is_found_without_the_static_phase(self):
        """passportreader (2026-10-29): instr-cli exit 1; with GATOR off no "not instrumented" line."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apks = root / "apks"
            apks.mkdir()
            for name in ("a.b.debug_1.apk", "c.d.debug_2.apk", "e.f.debug_3.apk"):
                (apks / name).write_bytes(b"PK")
            instrumented = root / "work" / "results" / "rvsec_x" / "instrumented_apks"
            instrumented.mkdir(parents=True)
            (instrumented / "e.f.debug_3.apk").write_bytes(b"PK woven")
            (instrumented / "e.f.debug_3.apk.json").write_text("{}", encoding="utf-8")
            (instrumented / "instrument_errors.json").write_text(json.dumps({
                "/opt/rvsec/rv-android/apks/a.b.debug_1.apk": {"code": 1, "message": (
                    "instr-cli exited with code 1\nstderr:\n"
                    "com.android.tools.smali.util.ExceptionWithContext: Exception occurred while "
                    "writing code_item for method Lorg/bouncycastle/X;->values()[LX;\n"
                    "\tat com.android.tools.smali.dexlib2.writer.DexWriter.writeTo(DexWriter.java:409)\n"
                    "Caused by: com.android.tools.smali.util.ExceptionWithContext: Error while "
                    "writing instruction at code offset 0x7\n\t... 16 more\n"
                    "Caused by: com.android.tools.smali.util.ExceptionWithContext: Unsigned short "
                    "value out of range: 65536\n")}}), encoding="utf-8")
            log = root / "work" / "rvsec.log"
            log.write_text("x - INFO - Starting APK instrumentation\n", encoding="utf-8")
            problems = rvsec.instrumentation_problems(root / "work", apks, log)
        self.assertEqual(sorted(problems), ["a.b.debug_1.apk", "c.d.debug_2.apk"])
        self.assertEqual(problems["a.b.debug_1.apk"],
                         "Exception occurred while writing code_item for method "
                         "Lorg/bouncycastle/X;->values()[LX; (caused by: Unsigned short value "
                         "out of range: 65536)")
        self.assertIn("no instrumented copy", problems["c.d.debug_2.apk"])

    def test_no_instrumentation_problem_is_claimed_before_instrumentation_ran(self):
        """A run that stopped before instrumenting (no instrumented_apks folder) is not this."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "apks").mkdir()
            (root / "apks" / "a.apk").write_bytes(b"PK")
            (root / "work" / "results" / "rvsec_x").mkdir(parents=True)
            self.assertEqual(rvsec.instrumentation_problems(root / "work", root / "apks"), {})

    def test_the_instrumenters_failure_line_names_the_apk(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "rvsec.log"
            log.write_text("x - ERROR - Failed to instrument /opt/rvsec/rv-android/apks/a.b_1.apk "
                           "after 62.4s: instr-cli exited with code 1\n"
                           "y - Failed to instrument APK: c.d_2.apk\n", encoding="utf-8")
            self.assertEqual(rvsec.instrumentation_failures(log), ["a.b_1.apk", "c.d_2.apk"])

    def test_instrumentation_failures_are_read_from_the_log(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "rvsec.log"
            log.write_text("x - Skipping static analysis for a.b_1.apk: not instrumented\n"
                           "x - Skipping static analysis for c.d_2.apk: not instrumented\n",
                           encoding="utf-8")
            self.assertEqual(rvsec.instrumentation_failures(log), ["a.b_1.apk", "c.d_2.apk"])

    def test_reports_survive_in_the_logcat_when_no_task_completed(self):
        """2026-10-12: Monkey aborted on every app, no errors.csv; 30 reports were logged."""
        line = ("10-12 23:53:09.509  3136  3136 V RVSEC   : SecretKeySpecSpec,org.app.Keys,Keys,"
                "<init>,Keys.kt:25,UnsatisfiedConstraint,v=1 code=SECRETKEYSPEC-NOBS-00 ev=c1 "
                "obj=SecretKeySpec val='' exp='prepared key material' msg='the keyMaterial, given "
                "to SecretKeySpec, was not prepared'")
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory) / "results" / "app_1.apk"
            task.mkdir(parents=True)
            (task / "app_1.apk__1__180__monkey.logcat").write_text(
                "10-12 23:53:09.400  3136  3136 I ActivityManager: Start proc\n" + line + "\n",
                encoding="utf-8")
            [found] = rvsec.errors_files([Path(directory) / "results"])
            [row] = rvsec.logcat_rows(found)
        self.assertEqual((row["apk"], row["rep"], row["timeout"], row["tool"]),
                         ("app_1.apk", "1", "180", "monkey"))
        self.assertEqual((row["spec"], row["class"], row["method"], row["code"]),
                         ("SecretKeySpecSpec", "org.app.Keys", "<init>", "SECRETKEYSPEC-NOBS-00"))
        # The message keeps its own commas.
        self.assertIn("msg='the keyMaterial, given to SecretKeySpec, was not prepared'", row["message"])

    def test_the_command_imports_what_rvsec_wrote(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            errors = root / "results" / "errors.csv"
            errors.parent.mkdir()
            errors.write_text(
                "apk,rep,timeout,tool,time,spec,class,method,source,code,event,message,unique_msg\n"
                "app_1.apk,1,180,monkey,9,MessageDigestSpec,org.app.Hasher,digest,Hasher.kt:9,"
                "MD-ALG,g1,v=1 code=MD-ALG msg='found MD5',org.app.Hasher:::digest\n",
                encoding="utf-8")
            sources = root / "sources.csv"
            sources.write_text("apk,repo_url,commit,manifest_package\n"
                               "app_1.apk,https://github.com/o/app,"
                               "5d2206a6926adf53be0867ad784948ed16663f44,org.app\n", encoding="utf-8")
            output = root / "findings.jsonl"
            with patch.object(rvsec, "run_experiment", return_value=(0, [errors])), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                code = cli.main(["rvsec-run", str(root), "--sources", str(sources),
                                 "--work-dir", str(root / "work"), "-o", str(output)])
            self.assertEqual(code, 0, out.getvalue())
            [line] = output.read_text(encoding="utf-8").splitlines()
        row = json.loads(line)
        self.assertEqual((row["class"], row["method"], row["origin"]), ("org.app.Hasher", "digest", "app"))


class InstrumentationFallbackTests(unittest.TestCase):
    """babymonitor (2026-10-30, twice): dexlib2's Format4rcc failure lost the whole app."""

    def test_an_apk_no_variant_instruments_ends_with_one_problem_line(self):
        fake = FakeRvsec({"uninstrumented": {"app_1.apk"}})
        with tempfile.TemporaryDirectory() as directory:
            code, out = rvsec_run(Path(directory), fake)
        self.assertEqual(code, 2)
        self.assertEqual(len(fake.calls), 1)
        self.assertIn("PROBLEM app_1.apk: RVSec could not instrument it with dexlib2 "
                      "(Instruction format Format4rcc not supported;", out)

    def test_the_opt_in_fallback_instruments_only_the_failed_apks_once_with_ajc(self):
        fake = FakeRvsec({"uninstrumented": {"app_1.apk"}}, {})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "apks").mkdir()
            (root / "apks" / "other_2.apk").write_bytes(b"PK other")
            code, out = rvsec_run(root, fake, "--instrumentation-fallback", "ajc")
            findings = (root / "findings.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(code, 0, out)
        self.assertEqual([call.settings.instrumentation for call in fake.calls], ["dexlib2", "ajc"])
        self.assertEqual(fake.calls[1].names, ["app_1.apk"])
        self.assertNotIn("RVSec could not instrument it", out)
        self.assertIn("note app_1.apk: the dexlib2 instrumentation failed", out)
        self.assertIn("[ajc]", out)
        self.assertEqual(len(findings), 2)

    def test_a_fallback_that_fails_too_names_both_variants(self):
        fake = FakeRvsec({"uninstrumented": {"app_1.apk"}}, {"uninstrumented": {"app_1.apk"}})
        with tempfile.TemporaryDirectory() as directory:
            code, out = rvsec_run(Path(directory), fake, "--instrumentation-fallback", "ajc")
        self.assertEqual(code, 2)
        self.assertIn("PROBLEM app_1.apk: RVSec could not instrument it with dexlib2 or ajc", out)


DEVICE_OFFLINE = ("TaskExecutionError: EmulatorError: Failed to install app app_1.apk caused by "
                  "RuntimeError: APK installation failed for app_1.apk on emulator-5554 (exit code "
                  "1): STDERR: adb: device offline")
OLDER_SDK = ("TaskExecutionError: EmulatorError: Failed to install app app_1.apk ... Failure "
             "[INSTALL_FAILED_OLDER_SDK: ... Requires newer sdk version #31 (current version is #30)]")


class ExplorerRetryTests(unittest.TestCase):
    """capyreader (2026-10-22): monkey lost to "adb: device offline" at install."""

    def test_a_task_that_reached_nothing_runs_again_alone_and_its_reports_count(self):
        fake = FakeRvsec({"ape:sata": ("ERROR", DEVICE_OFFLINE, 0), "monkey:fast": ("COMPLETED", "", 0)},
                         {})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, out = rvsec_run(root, fake)
            coverage = json.loads((root / "findings.coverage.json").read_text(encoding="utf-8"))
        self.assertEqual(code, 0, out)
        self.assertEqual(len(fake.calls), 2)
        self.assertEqual(fake.calls[1].settings.tools, "ape:sata")
        self.assertIn("retry1_ape_sata", str(fake.calls[1].folder))
        self.assertIn("note app_1.apk ape:sata: ERROR with no method reached (transient cause", out)
        self.assertIn("[retry 1]", out)
        self.assertEqual(len(coverage["app_1.apk"]["ape:sata"]), 3)

    def test_a_task_is_run_again_once_whatever_the_second_run_does(self):
        unknown = ("ERROR", "TaskExecutionError: Component ToolExecutionComponent execution failed", 0)
        fake = FakeRvsec({"ape:sata": unknown}, {"ape:sata": unknown})
        with tempfile.TemporaryDirectory() as directory:
            code, out = rvsec_run(Path(directory), fake)
        self.assertEqual(len(fake.calls), 2, out)
        self.assertIn("(unknown cause", out)

    def test_what_a_rerun_cannot_change_is_not_rerun(self):
        cases = {
            "older sdk": {"state": "ERROR", "reached": set(), "error": OLDER_SDK},
            "reached methods": {"state": "ERROR", "reached": {("a.B", "c")}, "error": "x"},
            "completed": {"state": "COMPLETED", "reached": set(), "error": ""},
        }
        for case, task in cases.items():
            with self.subTest(case):
                self.assertEqual(rvsec.task_retry_cause(task), "")
        self.assertEqual(rvsec.task_retry_cause(
            {"state": "ERROR", "reached": set(), "error": "emulator-5554 did not boot within 600s"}),
            "transient")

    def test_no_retry_when_turned_off(self):
        fake = FakeRvsec({"ape:sata": ("ERROR", DEVICE_OFFLINE, 0)})
        with tempfile.TemporaryDirectory() as directory:
            rvsec_run(Path(directory), fake, "--explorer-retries", "0")
        self.assertEqual(len(fake.calls), 1)



class EmulatorApiTests(unittest.TestCase):
    """truvark, shellwave, filepipe (2026-10-25..31): minSdk 31 on the API 30 image."""

    def test_an_apk_the_image_cannot_install_is_not_explored(self):
        fake = FakeRvsec({})
        with tempfile.TemporaryDirectory() as directory:
            code, out = rvsec_run(Path(directory), fake, min_sdks={"app_1.apk": 31})
        self.assertEqual(code, 2)
        self.assertEqual(fake.calls, [])
        self.assertIn("PROBLEM app_1.apk: needs Android API 31 and the emulator image runs API 30;"
                      " RVSec cannot install it, not explored", out)

    def test_the_other_apks_are_explored_without_it(self):
        fake = FakeRvsec({})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "apks").mkdir()
            (root / "apks" / "other_2.apk").write_bytes(b"PK other")
            code, out = rvsec_run(root, fake, min_sdks={"app_1.apk": 31, "other_2.apk": 24})
        self.assertEqual(code, 0, out)
        self.assertEqual(fake.calls[0].names, ["other_2.apk"])

    def test_the_levels_are_read_from_aapt_and_from_the_image(self):
        def run(command):
            if command[0] == "docker":
                return SimpleNamespace(stdout=json.dumps(
                    ["PATH=/opt/android/emulator", "PACKAGE_PATH=system-images;android-30;"
                     "google_apis;x86_64", "API_LEVEL=30"]))
            return SimpleNamespace(stdout="package: name='de.lukaspieper.truvark.dev' "
                                          "versionCode='204'\nminSdkVersion:'31'\n"
                                          "targetSdkVersion:'37'\n")
        self.assertEqual(rvsec.image_api_level("img", run), 30)
        self.assertEqual(rvsec.apk_min_sdk(Path("a.apk"), "aapt2", run), 31)
        self.assertEqual(rvsec.image_api_level("img", lambda command: SimpleNamespace(
            stdout=json.dumps(["PACKAGE_PATH=system-images;android-29;default;x86_64"]))), 29)

    def test_nothing_is_skipped_when_a_level_cannot_be_read(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "a.apk").write_bytes(b"PK")
            self.assertEqual(rvsec.uninstallable_apks(Path(directory), aapt=""), {})
            self.assertEqual(rvsec.uninstallable_apks(
                Path(directory), aapt="aapt2", run=lambda command: SimpleNamespace(
                    stdout="minSdkVersion:'31'\n" if command[0] == "aapt2" else "")), {})


def kept_files(work):
    return sorted(path.relative_to(work).as_posix() for path in work.rglob("*") if path.is_file())


class PruneTests(unittest.TestCase):
    """BookWyrm (2026-10-31): 70 MB a run, 50 MB of it instrumented APK, woven dex and lib_tmp."""

    def test_regenerable_artefacts_go_once_the_reports_are_converted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, out = rvsec_run(root, FakeRvsec({}))
            [work] = (root / "work").iterdir()
            kept = kept_files(work)
        self.assertEqual(code, 0, out)
        self.assertIn("removed (regenerable", out)
        self.assertFalse([name for name in kept if name.endswith((".apk", ".dex", ".jar", ".trace"))],
                         kept)
        self.assertLessEqual({"tasks.json", "errors.csv", "instrument_errors.json",
                              "app_1.apk__1__600__ape:sata.logcat"}, {Path(name).name for name in kept})

    def test_a_run_without_reports_is_pruned_too(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, out = rvsec_run(root, FakeRvsec({"ape:sata": ("COMPLETED", "", 0),
                                                   "monkey:fast": ("COMPLETED", "", 0)}))
            [work] = (root / "work").iterdir()
            kept = kept_files(work)
        self.assertEqual(code, 2)
        self.assertFalse([name for name in kept if name.endswith((".apk", ".dex", ".trace"))], kept)

    def test_everything_stays_when_instrumentation_failed_or_when_asked(self):
        for case, plan, options in (("not instrumented", {"uninstrumented": {"app_1.apk"}}, ()),
                                    ("asked", {}, ("--keep-artifacts",))):
            with self.subTest(case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                rvsec_run(root, FakeRvsec(plan), *options)
                [work] = (root / "work").iterdir()
                self.assertIn("woven_classes.dex", [Path(name).name for name in kept_files(work)])

    def test_a_file_it_may_not_delete_is_skipped_and_counted(self):
        """2026-11-03: a root-owned instrumented_apks/*.idsig aborted disk_cleanup.py."""
        with tempfile.TemporaryDirectory() as directory:
            experiment = Path(directory) / "results" / "exp"
            apks = experiment / rvsec.INSTRUMENTED_APKS_DIR
            apks.mkdir(parents=True)
            (apks / "a.apk").write_bytes(b"x" * 10)
            (apks / "a.apk.idsig").write_bytes(b"y" * 5)
            (experiment / "lib_tmp").mkdir()
            (experiment / "lib_tmp" / "b.jar").write_bytes(b"z" * 7)
            original = Path.unlink

            def unlink(path, *args, **kwargs):
                if path.name.endswith(".idsig"):
                    raise PermissionError(13, "Permission denied", str(path))
                return original(path, *args, **kwargs)

            skipped = []
            with patch.object(Path, "unlink", unlink):
                freed = rvsec.prune_artifacts(Path(directory), skipped)
            self.assertEqual(freed, 17)
            self.assertEqual([path.name for path in skipped], ["a.apk.idsig"])
            self.assertTrue((apks / "a.apk.idsig").exists())
            self.assertFalse((apks / "a.apk").exists())
            self.assertFalse((experiment / "lib_tmp").exists())


if __name__ == "__main__":
    unittest.main()
