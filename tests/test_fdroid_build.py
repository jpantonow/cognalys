import csv
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.integrations import fdroid  # noqa: E402

# Shaped like fdroiddata's metadata/com.emanuelef.remote_capture.yml.
METADATA = """Repo: https://github.com/emanuele-f/PCAPdroid

Builds:
  - versionName: 2.0.1
    versionCode: 94
    commit: 1111111111111111111111111111111111111111
    subdir: app
    gradle:
      - yes

  - versionName: 2.0.2
    versionCode: 95
    commit: 76696f705b3780f9f0951f25bb93b2708f70b98a
    subdir: app
    submodules: true
    gradle:
      - standard
    rm:
      - submodules/PCAPdroid-ushark-bin/release
"""


def fetch(url, timeout=60):
    if "/api/v1/packages/" in url:
        return json.dumps({"suggestedVersionCode": 95}).encode()
    if "metadata/" in url:
        return METADATA.encode()
    raise OSError(url)


class BuildEntryTests(unittest.TestCase):
    def test_the_build_entry_gives_subdir_flavour_and_submodules(self):
        self.assertEqual(fdroid.build_entry(METADATA, 95),
                         {"version_name": "2.0.2", "subdir": "app", "gradle": ("standard",),
                          "submodules": True,
                          "rm": ("submodules/PCAPdroid-ushark-bin/release",),
                          "prebuild": (), "gradleprops": (), "build_commands": (),
                          "srclibs": (), "ndk": ""})
        self.assertEqual(fdroid.build_entry(METADATA, 94),
                         {"version_name": "2.0.1", "subdir": "app", "gradle": (),
                          "submodules": False, "rm": (), "prebuild": (), "gradleprops": (),
                          "build_commands": (), "srclibs": (), "ndk": ""})
        build = fdroid.suggested_build("com.emanuelef.remote_capture", fetch)
        self.assertEqual(fdroid.gradle_task(build), ":app:assembleStandardDebug")

    def test_a_flavour_named_only_by_the_output_path_is_built(self):
        """Clash Fest builds assembleAlphaRelease in its build script, without gradle:."""
        recipe = ("Builds:\n  - versionName: 1.3.0\n    versionCode: 7\n    commit: abc\n"
                  "    subdir: app\n"
                  "    output: build/outputs/apk/alpha/release/clashfest-v*-alpha-release-unsigned.apk\n"
                  "  - versionName: 1.3.1\n    versionCode: 8\n    commit: abd\n"
                  "    gradle:\n      - yes\n    output: build/outputs/apk/release/app-release.apk\n")
        entry = fdroid.build_entry(recipe, 7)
        self.assertEqual(entry["gradle"], ("alpha",))
        build = fdroid.FdroidBuild("p", 7, "https://github.com/o/c", "abc", subdir="app",
                                   gradle=entry["gradle"])
        self.assertEqual(fdroid.gradle_task(build), ":app:assembleAlphaDebug")
        self.assertEqual(fdroid.built_apk([Path("clashfest-v1.3.0-alpha-debug.apk"),
                                           Path("clashfest-v1.3.0-meta-debug.apk")], build),
                         Path("clashfest-v1.3.0-alpha-debug.apk"))
        # An output directory that is the build type names no flavour.
        self.assertEqual(fdroid.build_entry(recipe, 8)["gradle"], ())

    def test_the_flavour_is_read_from_output_paths_of_any_build_type(self):
        """Thunderbird beta's foss/beta, MyExpenses' apk_from_bundle/externRelease."""
        def entry(output):
            return fdroid.build_entry("Builds:\n  - versionName: 1\n    versionCode: 1\n"
                                      f"    commit: abc\n    output: {output}\n", 1)["gradle"]

        self.assertEqual(entry("app-k9mail/build/outputs/apk/foss/beta/app-foss-beta.apk"),
                         ("foss",))
        self.assertEqual(entry("build/outputs/apk_from_bundle/externRelease/*.apk"), ("extern",))
        # One flavour per dimension, as gradle: lists them.
        self.assertEqual(entry("build/outputs/apk/freeActive/release/*.apk"), ("free", "active"))
        self.assertEqual(entry("build/outputs/apk/release/*.apk"), ())
        # moshinda's build type fdroidRelease reads as flavour fdroid; the
        # debug task then does not exist and apk_build's fallbacks
        # (build type, then the ambiguity) reach assembleFdroidRelease.
        build = fdroid.FdroidBuild("p", 1, "https://github.com/o/m", "a" * 40, subdir="mastodon",
                                   gradle=entry("build/outputs/apk/fdroidRelease/*.apk"))
        self.assertEqual(fdroid.gradle_task(build), ":mastodon:assembleFdroidDebug")

    def test_one_flavour_per_dimension_names_one_variant(self):
        """geoshare builds `gradle: [free, active]`: assembleFreeDebug was ambiguous."""
        build = fdroid.FdroidBuild("page.ooooo.geoshare", 1, "https://github.com/o/g",
                                   "a" * 40, subdir="app", gradle=("free", "active"))
        self.assertEqual(fdroid.gradle_task(build), ":app:assembleFreeActiveDebug")
        self.assertEqual(
            fdroid.built_apk([Path("app-free-active-debug.apk"),
                              Path("app-free-legacy-debug.apk")], build),
            Path("app-free-active-debug.apk"))

    def test_a_flavour_separated_by_underscores_is_recognised(self):
        """AmaRadio's foss build is AMARadio_1.37_foss.apk."""
        build = fdroid.FdroidBuild("com.ounben.amaradio", 137, "https://github.com/o/a",
                                   "a" * 40, gradle=("foss",))
        self.assertEqual(fdroid.built_apk([Path("AMARadio_1.37_foss.apk")], build),
                         Path("AMARadio_1.37_foss.apk"))
        # A part that merely contains the flavour does not name it.
        self.assertIsNone(fdroid.built_apk([Path("AMARadio_1.37_fossil.apk"),
                                            Path("AMARadio_1.37_other.apk")], build))

    def test_the_single_apk_of_a_flavour_task_is_taken_whatever_its_name(self):
        """Read You (2026-10-18): assembleFdroidDebug wrote ReadYou-0.16.2-091c9207.apk."""
        build = fdroid.FdroidBuild("me.ash.reader", 1, "https://github.com/o/a",
                                   "a" * 40, gradle=("fdroid",))
        self.assertEqual(fdroid.built_apk([Path("ReadYou-0.16.2-091c9207.apk")], build),
                         Path("ReadYou-0.16.2-091c9207.apk"))

    def test_abi_splits_resolve_to_the_one_the_emulator_runs(self):
        """LavenderPhotos (2026-10-22) builds one APK per ABI."""
        build = fdroid.FdroidBuild("com.kaii.photos", 1, "https://github.com/o/a", "a" * 40)
        splits = [Path("app-armeabi-v7a-debug.apk"), Path("app-arm64-v8a-debug.apk")]
        self.assertEqual(fdroid.built_apk(splits, build), Path("app-arm64-v8a-debug.apk"))
        self.assertEqual(fdroid.built_apk(splits + [Path("app-universal-debug.apk")], build),
                         Path("app-universal-debug.apk"))
        # Different builds that happen to carry ABIs stay ambiguous.
        self.assertIsNone(fdroid.built_apk([Path("app-arm64-v8a-debug.apk"),
                                            Path("other-x86_64-release.apk")], build))

    def test_the_task_module_apk_is_taken_over_an_embedded_module(self):
        """Mixify's :app:assembleDevDebug (2026-11-05) also builds its Wear OS module."""
        build = fdroid.FdroidBuild("com.mixify.app", 1, "https://github.com/o/a", "a" * 40,
                                   gradle=("dev",), subdir="app")
        apks = [Path("MixifyWear-dev-debug.apk"), Path("app-dev-arm64-v8a-debug.apk"),
                Path("app-dev-universal-debug.apk"), Path("app-dev-x86_64-debug.apk")]
        self.assertEqual(fdroid.built_apk(apks, build), Path("app-dev-universal-debug.apk"))
        # Without a module in the task the name cannot decide.
        plain = fdroid.FdroidBuild("com.mixify.app", 1, "https://github.com/o/a", "a" * 40,
                                   gradle=("dev",))
        self.assertIsNone(fdroid.built_apk(apks, plain))

    def test_a_tag_in_the_commit_field_is_resolved_to_its_commit(self):
        """WiFiAnalyzer's F-Droid build names the tag V3.3.1-F-DROID."""
        listing = ("1" * 40 + "\trefs/tags/V3.3.1-F-DROID\n"
                   + "2" * 40 + "\trefs/tags/V3.3.1-F-DROID^{}\n")
        run = lambda command: SimpleNamespace(returncode=0, stdout=listing)
        self.assertEqual(fdroid.resolve_tag("https://github.com/o/a", "V3.3.1-F-DROID", run),
                         "2" * 40)
        self.assertEqual(fdroid.resolve_tag(
            "https://github.com/o/a", "missing", lambda command: SimpleNamespace(
                returncode=0, stdout="")), "")

    def test_the_apk_of_the_declared_flavour_is_taken(self):
        build = fdroid.suggested_build("com.emanuelef.remote_capture", fetch)
        apks = [Path("app-withoutUshark-debug.apk"), Path("app-standard-debug.apk")]
        self.assertEqual(fdroid.built_apk(apks, build), Path("app-standard-debug.apk"))
        plain = fdroid.FdroidBuild("org.app", 1, "https://github.com/o/app", "a" * 40)
        self.assertIsNone(fdroid.built_apk(apks, plain))
        self.assertEqual(fdroid.built_apk([Path("app-debug.apk")], plain), Path("app-debug.apk"))


RECIPE = """Builds:
  - versionName: 1.9.0
    versionCode: 109000
    commit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    subdir: app
    gradle:
      - yes
    rm:
      - iosApp
    prebuild:
      - sed -i -e '/keystoreProperties/d' build.gradle.kts
      - echo $$NDK$$
    gradleprops:
      - disableFirebase=true
"""


class RecipeTests(unittest.TestCase):
    """fread builds only once its recipe drops the keystore lines."""

    def test_the_recipe_is_read_and_turned_into_steps(self):
        entry = fdroid.build_entry(RECIPE, 109000)
        self.assertEqual(entry["rm"], ("iosApp",))
        self.assertEqual(entry["gradleprops"], ("disableFirebase=true",))
        self.assertEqual(len(entry["prebuild"]), 2)
        build = fdroid.FdroidBuild("com.zhangke.fread", 109000, "https://github.com/o/f", "a" * 40,
                                   **entry)
        steps = fdroid.recipe_steps(build, Path("/w/fread"))
        self.assertEqual(steps[0], ["rm", "-rf", "--", "/w/fread/iosApp"])
        self.assertEqual(len(steps), 2, "rm, then the prebuild as one script")
        self.assertIn("cd /w/fread/app || exit 1", steps[1][2])
        self.assertIn("{ sed -i -e '/keystoreProperties/d' build.gradle.kts; } || echo", steps[1][2])
        self.assertNotIn("$$NDK$$", steps[1][2], "F-Droid's own tools are skipped")

    def test_a_cd_in_the_prebuild_carries_into_the_next_step(self):
        """zSMTH: `cd src/main/java/com/zfdang`, then seds the Umeng calls out there."""
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            target = checkout / "app" / "src" / "pkg"
            target.mkdir(parents=True)
            (target / "A.java").write_text("keep\nMobclickAgent.onResume(this);\n")
            build = fdroid.FdroidBuild(
                "p", 7, "https://github.com/o/r", "a" * 40, subdir="app", version_name="1.2",
                prebuild=("false", "cd src/pkg", "sed -i -e '/MobclickAgent/d' A.java",
                          "echo $$VERSION$$-$$VERCODE$$ > v.txt"))
            [script] = fdroid.recipe_steps(build, checkout)
            subprocess.run(script, check=True, capture_output=True)
            self.assertEqual((target / "A.java").read_text(), "keep\n")
            self.assertEqual((target / "v.txt").read_text().strip(), "1.2-7")


BUILD_RECIPE = """Builds:
  - versionName: 0.9
    versionCode: 9
    commit: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    subdir: app
    sudo:
      - apt-get install -y golang
    srclibs:
      - go@go1.24.2
      - yubikit@1.2.3
    build:
      - set -euo pipefail
      - bash -x ../libcore/scripts/build.sh
      - cd $$yubikit$$ && gradle publishToMavenLocal
    ndk: r25c
"""


class RecipeBuildStepTests(unittest.TestCase):
    """DumDum's libcore.aar and Sagernet's gomobile binding are made by the
    recipe's `build:` commands, which fdroid-build never ran (2026-10-28)."""

    def test_build_srclibs_and_ndk_are_read(self):
        entry = fdroid.build_entry(BUILD_RECIPE, 9)
        self.assertEqual(entry["srclibs"], ("go@go1.24.2", "yubikit@1.2.3"))
        self.assertEqual(entry["ndk"], "r25c")
        self.assertEqual(len(entry["build_commands"]), 3)

    def test_an_r_named_ndk_is_its_minor_release(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk = Path(directory)
            for revision in ("25.2.9519653", "27.0.12077973"):
                (sdk / "ndk" / revision).mkdir(parents=True)
                (sdk / "ndk" / revision / "source.properties").write_text(
                    f"Pkg.Desc = Android NDK\nPkg.Revision = {revision}\n")
            self.assertEqual(fdroid.ndk_home(str(sdk), "r25c"), str(sdk / "ndk" / "25.2.9519653"))
            self.assertEqual(fdroid.ndk_home(str(sdk), "27.0.12077973"),
                             str(sdk / "ndk" / "27.0.12077973"))
            self.assertEqual(fdroid.ndk_home(str(sdk), "r21e"), "")

    def test_a_command_is_adapted_to_this_machine(self):
        """restoid's GOROOT_BOOTSTRAP=/usr/lib/go; resticdroid's build starts with set -e."""
        adapt = fdroid._recipe_command
        self.assertEqual(adapt("GOROOT_BOOTSTRAP=/usr/lib/go-1.27 ./make.bash", {}, "/usr/local/go"),
                         "GOROOT_BOOTSTRAP=/usr/local/go ./make.bash")
        self.assertEqual(adapt("set -euo pipefail", {}, ""), "set -o pipefail")
        self.assertEqual(adapt("set -e", {}, ""), "true")
        self.assertNotIn("apt-get", adapt("sudo apt-get install -y swig && make", {}, ""))
        self.assertIn("&& make", adapt("sudo apt-get install -y swig && make", {}, ""))
        self.assertEqual(adapt("echo $$go$$", {}, ""), "", "no source library for it")

    def test_the_build_runs_with_srclibs_and_skips_the_apps_own_gradle(self):
        """passwdsafe publishes its yubikit srclib with gradle; the app's own
        gradle line is F-Droid's release assemble, which the debug task replaces."""
        import os
        import subprocess
        from unittest import mock

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout, library, sdk = root / "checkout", root / "srclibs" / "lib", root / "sdk"
            (checkout / "app").mkdir(parents=True)
            library.mkdir(parents=True)
            (library / "gradlew").write_text('#!/bin/sh\necho "$@" > published.txt\n')
            (sdk / "ndk" / "25.2.9519653").mkdir(parents=True)
            (sdk / "ndk" / "25.2.9519653" / "source.properties").write_text(
                "Pkg.Revision = 25.2.9519653\n")
            build = fdroid.FdroidBuild(
                "p", 9, "https://github.com/o/r", "b" * 40, subdir="app", ndk="r25c",
                build_commands=("set -e", "false", "./gradlew assembleRelease",
                                "echo $$NDK$$ > ../ndk.txt && echo $ANDROID_NDK_HOME >> ../ndk.txt",
                                "cd $$lib$$ && gradle publishToMavenLocal"))
            with mock.patch.dict(os.environ, {"ANDROID_HOME": str(sdk)}):
                [script] = fdroid.recipe_steps(build, checkout, {"lib": library})
            completed = subprocess.run(script, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("F-Droid's own gradle step skipped: gradle assembleRelease",
                          completed.stderr)
            self.assertEqual((library / "published.txt").read_text().strip(), "publishToMavenLocal")
            self.assertEqual((checkout / "ndk.txt").read_text().split(),
                             [str(sdk / "ndk" / "25.2.9519653")] * 2)

    def test_only_tools_the_commands_call_are_missing(self):
        """A package only the recipe's sudo installs is not a missing tool."""
        build = fdroid.FdroidBuild(
            "p", 1, "https://github.com/o/r", "a" * 40,
            prebuild=("sed -i -e 's/go/no/' build.gradle",),
            build_commands=("cd ../core && GOOS=android go build ./...",
                            "flutter build apk", ".flutter/bin/flutter pub get",
                            "echo swig && make", "(cd jni && ninja)", "{ mkdir b; cmake ..; }"))
        installed = {"make", "sed", "cd", "echo", "mkdir"}
        self.assertEqual(fdroid.recipe_missing_tools(build, lambda tool: tool in installed),
                         ("flutter", "ninja", "cmake", "go"))
        self.assertEqual(fdroid.recipe_missing_tools(build, lambda tool: True), ())

    def test_a_srclib_is_cloned_once_at_its_ref_and_reused(self):
        fetched, steps = [], []

        def fetch_srclib(url):
            fetched.append(url)
            if url.endswith("/go.yml"):
                return b"RepoType: git\nRepo: https://go.googlesource.com/go\nSubdir: src\n"
            raise OSError("404")

        def run_step(step):
            steps.append(step)
            if step[:2] == ["git", "clone"]:
                (Path(step[-1]) / ".git").mkdir(parents=True)
            return None

        build = fdroid.FdroidBuild("p", 1, "https://github.com/o/r", "a" * 40,
                                   srclibs=("go@go1.24.2", "missing@" + "c" * 40))
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            folders, problems = fdroid.prepare_srclibs(build, cache, fetch_srclib, run_step)
            self.assertEqual(folders, {"go": cache / "go@go1.24.2" / "src"})
            self.assertEqual(steps[0], ["git", "clone", "-q", "--depth", "1", "--branch", "go1.24.2",
                                        "https://go.googlesource.com/go", str(cache / "go@go1.24.2")])
            self.assertIn(["git", "-C", str(cache / "go@go1.24.2"), "checkout", "-q", "-f",
                           "go1.24.2"], steps)
            self.assertEqual(len(problems), 1)
            self.assertIn("srclib missing", problems[0])
            steps.clear()
            fdroid.prepare_srclibs(build, cache, fetch_srclib, run_step)
            self.assertFalse(any(step[:2] == ["git", "clone"] for step in steps), "reused")


class AppPackagesTests(unittest.TestCase):
    """xivpn ships as io.github.exclude0122.xivpn with its code in cn.gov.xivpn2."""

    def test_the_code_packages_come_from_the_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "app"
            (app / "src" / "main" / "java" / "cn" / "gov" / "xivpn2").mkdir(parents=True)
            (app / "build.gradle").write_text('android { namespace "io.github.exclude0122.xivpn" }')
            for name in ("Utils", "MainActivity", "Service"):
                (app / "src" / "main" / "java" / "cn" / "gov" / "xivpn2" / f"{name}.java").write_text(
                    f"package cn.gov.xivpn2;\nclass {name} {{}}\n")
            (app / "src" / "test").mkdir(parents=True)
            (app / "src" / "test" / "T.java").write_text("package org.junit.extra;\n")
            self.assertEqual(fdroid.app_packages(Path(directory), "app"),
                             ("io.github.exclude0122.xivpn", "cn.gov.xivpn2"))

    def test_every_module_namespace_is_the_apps_code(self):
        """Olvid's engine module is one file in a hundred, but it is the app's crypto."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            (root / "app" / "build.gradle.kts").write_text('android { namespace = "io.olvid.messenger" }')
            (root / "engine").mkdir()
            (root / "engine" / "build.gradle").write_text("android { namespace 'io.olvid.engine' }")
            (root / "engine" / "build").mkdir()
            (root / "engine" / "build" / "build.gradle").write_text("namespace 'generated.leftover'")
            self.assertEqual(fdroid.app_packages(root, "app"), ("io.olvid.messenger", "io.olvid.engine"))


class RefreshAppPackagesTests(unittest.TestCase):
    """Tasks: sources.csv of 2026-10-25 lacked at.bitfire.cert4android, an in-repo module."""

    def tasks_checkout(self, root):
        checkout = root / "checkout"
        (checkout / "app").mkdir(parents=True)
        (checkout / "app" / "build.gradle.kts").write_text('android { namespace = "org.tasks" }')
        module = checkout / "cert4android" / "src" / "main" / "java" / "at" / "bitfire" / "cert4android"
        module.mkdir(parents=True)
        (checkout / "cert4android" / "build.gradle").write_text("android { namespace 'at.bitfire.cert4android' }")
        (module / "CustomCertStore.kt").write_text("package at.bitfire.cert4android\nclass CustomCertStore\n")
        return checkout

    def write_run(self, root, logic=None):
        out = root / "out"
        out.mkdir()
        header = "apk,repo_url,commit,manifest_package" + (",packages_logic" if logic else "")
        (out / "sources.csv").write_text(
            f"{header}\norg.tasks.debug_1.apk,https://github.com/tasks/tasks,{'a' * 40},"
            f"org.tasks;com.todoroo.astrid{',' + logic if logic else ''}\n", encoding="utf-8")
        rows = [("at.bitfire.cert4android.CustomCertStore", "library"),
                # Under the new namespace, but no file of the checkout declares it.
                ("at.bitfire.cert4android.shaded.Pool", "library"),
                ("okhttp3.internal.tls.OkHostnameVerifier", "library"),
                ("org.tasks.Sync", "app")]
        (out / "findings_all.jsonl").write_text("".join(json.dumps(
            {"apk": "org.tasks.debug_1.apk", "class": name, "origin": origin}) + "\n"
            for name, origin in rows), encoding="utf-8")
        return out

    def test_an_older_source_map_is_derived_again_and_the_apps_findings_relabelled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout, out = self.tasks_checkout(root), self.write_run(root)
            [change] = fdroid.refresh_app_packages(out, lambda row: checkout, [out / "findings_all.jsonl"])
            [row] = list(csv.DictReader(open(out / "sources.csv", encoding="utf-8")))
            origins = {record["class"]: record["origin"] for record in map(
                json.loads, (out / "findings_all.jsonl").read_text(encoding="utf-8").splitlines())}
            again = fdroid.refresh_app_packages(out, lambda row: self.fail("fetched again"),
                                                [out / "findings_all.jsonl"])
        self.assertEqual(change["relabelled"], 1)
        self.assertEqual(row["manifest_package"], "org.tasks;at.bitfire.cert4android;com.todoroo.astrid")
        self.assertEqual(row["packages_logic"], fdroid.packages_logic())
        self.assertEqual(origins, {"at.bitfire.cert4android.CustomCertStore": "app",
                                   "at.bitfire.cert4android.shaded.Pool": "library",
                                   "okhttp3.internal.tls.OkHostnameVerifier": "library",
                                   "org.tasks.Sync": "app"})
        self.assertEqual(again, [])

    def test_the_command_fetches_nothing_for_an_apk_without_library_findings(self):
        import contextlib
        import io

        from cognalys import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout, out = self.tasks_checkout(root), self.write_run(root)
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                code = cli.main(["fdroid-packages", str(out), "--checkout", str(checkout)])
            self.assertEqual(code, 0)
            self.assertIn("1 finding(s) now in the app's code", printed.getvalue())
            (out / "findings_all.jsonl").write_text(json.dumps(
                {"apk": "org.tasks.debug_1.apk", "class": "org.tasks.Sync", "origin": "app"}) + "\n",
                encoding="utf-8")
            (out / "sources.csv").write_text("apk,repo_url,commit,manifest_package\n"
                                             f"org.tasks.debug_1.apk,u,{'a' * 40},org.tasks\n")
            self.assertEqual(fdroid.refresh_app_packages(
                out, lambda row: self.fail("fetched"), [out / "findings_all.jsonl"]), [])

    def test_a_source_map_written_by_the_current_logic_is_left_alone(self):
        with tempfile.TemporaryDirectory() as directory:
            out = self.write_run(Path(directory), fdroid.packages_logic())
            self.assertEqual(fdroid.refresh_app_packages(out, lambda row: self.fail("fetched")), [])

    def test_a_build_writes_the_logic_that_derived_its_packages(self):
        self.assertIn("packages_logic", fdroid.SOURCE_COLUMNS)
        self.assertRegex(fdroid.packages_logic(), r"^[0-9a-f]{12}$")


class BuildFromSourceTests(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        from cognalys.builds import apk_build

        # The submodule update runs through apk_build's own commands.
        self.submodules = mock.patch.object(apk_build, "run_submodule_commands", return_value=None)
        self.submodule_commands = self.submodules.start()
        self.addCleanup(self.submodules.stop)

    def test_the_commit_is_built_and_written_with_its_source(self):
        commands = []

        def run(command):
            commands.append(command)
            if "cognalys.builds.apk_build" in command:
                built = Path(command[command.index("--output-dir") + 1]) / "apks" / "pkg"
                built.mkdir(parents=True)
                (built / "app-standard-debug.apk").write_bytes(b"PK standard")
                (built / "app-withoutUshark-debug.apk").write_bytes(b"PK other")
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            out, work = Path(directory) / "out", Path(directory) / "work"
            built, problems = fdroid.build_from_source(
                ["com.emanuelef.remote_capture"], out, work, fetch, run)
            self.assertEqual(problems, [])
            self.assertEqual(len(built), 1)
            apk = out / "apks" / "com.emanuelef.remote_capture.debug_95.apk"
            self.assertEqual(apk.read_bytes(), b"PK standard")
            [row] = list(csv.DictReader(open(out / "sources.csv", encoding="utf-8")))
            self.assertEqual(row["apk"], apk.name)
            self.assertEqual(row["commit"], "76696f705b3780f9f0951f25bb93b2708f70b98a")
        joined = [" ".join(command) for command in commands]
        [call] = self.submodule_commands.call_args_list
        self.assertEqual(call.args[0].name, "com.emanuelef.remote_capture")
        self.assertTrue(call.kwargs["force"])
        self.assertTrue(any("--task :app:assembleStandardDebug" in command
                            and "--disable-minification" in command for command in joined))

    def test_copies_an_earlier_build_left_are_not_candidates(self):
        def run(command):
            if "cognalys.builds.apk_build" in command:
                built = Path(command[command.index("--output-dir") + 1]) / "apks" / "pkg"
                built.mkdir(parents=True, exist_ok=True)
                (built / "app-standard-debug.apk").write_bytes(b"PK new")
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            out, work = Path(directory) / "out", Path(directory) / "work"
            stale = work / "com.emanuelef.remote_capture" / "built" / "apks" / "pkg"
            stale.mkdir(parents=True)
            (stale / "debug-app-standard-debug.apk").write_bytes(b"PK old")
            built, problems = fdroid.build_from_source(
                ["com.emanuelef.remote_capture"], out, work, fetch, run)
            self.assertEqual(problems, [])
            self.assertEqual(
                (out / "apks" / "com.emanuelef.remote_capture.debug_95.apk").read_bytes(),
                b"PK new")

    def test_a_failed_step_is_a_problem(self):
        with tempfile.TemporaryDirectory() as directory:
            built, problems = fdroid.build_from_source(
                ["com.emanuelef.remote_capture"], Path(directory) / "out", Path(directory) / "work",
                fetch, lambda command: SimpleNamespace(returncode=1))
            self.assertEqual(built, [])
            self.assertIn("failed", problems[0]["problem"])

    def test_the_cause_of_a_failed_build_is_kept_beside_the_apks(self):
        """40 of 47 failed builds (2026-10-22..31) kept only a path the cleanups then removed."""
        gradle_log = ("> Task :app:compileDebugKotlin FAILED\n\nFAILURE: Build failed with an exception.\n\n"
                      "* What went wrong:\nExecution failed for task ':app:compileDebugKotlin'.\n"
                      "> Unresolved reference: BuildConfig\n\n* Try:\n> Run with --stacktrace\n\n"
                      "BUILD FAILED in 1m 2s\n")

        def run(command):
            if "cognalys.builds.apk_build" in command:
                built = Path(command[command.index("--output-dir") + 1])
                (built / "logs" / "projects").mkdir(parents=True)
                (built / "logs" / "projects" / "pkg.log").write_text(gradle_log, encoding="utf-8")
                (built / "build_report.json").write_text(json.dumps(
                    [{"status": "failed", "reason": "gradle exited 1"}]), encoding="utf-8")
                return SimpleNamespace(returncode=1)
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            built, problems = fdroid.build_from_source(
                ["com.emanuelef.remote_capture"], out, Path(directory) / "work", fetch, run)
            kept = (out / "build_failure_com.emanuelef.remote_capture.log").read_text(encoding="utf-8")
        self.assertEqual(built, [])
        self.assertIn("(Execution failed for task ':app:compileDebugKotlin'. > Unresolved reference: "
                      "BuildConfig; logs in", problems[0]["problem"])
        self.assertIn("apk_build (failed): gradle exited 1", kept)
        self.assertIn("Gradle, what went wrong:\nExecution failed", kept)
        self.assertIn("BUILD FAILED in 1m 2s", kept)

    def test_a_dropped_clone_is_retried_and_reports_git_s_error(self):
        clones = []

        def run(command):
            if command[:2] == ["git", "clone"]:
                clones.append(command)
                return SimpleNamespace(returncode=128, stderr="fatal: early EOF\n")
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            built, problems = fdroid.build_from_source(
                ["com.emanuelef.remote_capture"], Path(directory) / "out", Path(directory) / "work",
                fetch, run)
        self.assertEqual(len(clones), 3)
        self.assertEqual(built, [])
        self.assertIn("fatal: early EOF", problems[0]["problem"])
        self.assertNotIn("logs in", problems[0]["problem"])

    def test_a_reused_checkout_is_reset_by_force_and_cloned_again_if_that_fails(self):
        """androidipcamera: a checkout left by a crashed run made checkout abort."""
        commands = []

        def run(command, fail_checkout=False):
            commands.append(command)
            if command[:2] == ["git", "clone"]:
                (Path(command[-1]) / ".git").mkdir(parents=True)
            if fail_checkout and "-f" in command:
                return SimpleNamespace(returncode=1, stderr="error: Aborting\n")
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            out, work = Path(directory) / "out", Path(directory) / "work"
            checkout = work / "com.emanuelef.remote_capture" / "projects" / "com.emanuelef.remote_capture"
            (checkout / ".git").mkdir(parents=True)
            fdroid.build_from_source(["com.emanuelef.remote_capture"], out, work, fetch, run)
            git = [command[3:5] if command[1] == "-C" else command[1:2]
                   for command in commands if command[0] == "git"]
            self.assertEqual(git[:2], [["checkout", "-q"], ["clean", "-fdq"]])
            self.assertNotIn(["clone"], git)
            commands.clear()
            fdroid.build_from_source(["com.emanuelef.remote_capture"], out, work, fetch,
                                     lambda command: run(command, fail_checkout=True))
            git = [command[3:5] if command[1] == "-C" else command[1:2]
                   for command in commands if command[0] == "git"]
            self.assertEqual(git[:3], [["checkout", "-q"], ["clone"], ["checkout", "-q"]])

    def test_a_suggested_version_without_a_build_entry_builds_the_newest_recorded_one(self):
        """shoppinglist suggested versionCode 10; fdroiddata listed 4, 8, 9 and 11."""
        def fetch_newer(url, timeout=60):
            if "/api/v1/packages/" in url:
                return json.dumps({"suggestedVersionCode": 96}).encode()
            return fetch(url)

        build = fdroid.suggested_build("com.emanuelef.remote_capture", fetch_newer,
                                       newest_recorded=True)
        self.assertEqual((build.version_code, build.commit),
                         (95, "76696f705b3780f9f0951f25bb93b2708f70b98a"))
        # prepare() downloads F-Droid's APK of the suggested version: no fallback.
        self.assertEqual(fdroid.suggested_build("com.emanuelef.remote_capture", fetch_newer).commit, "")

    def test_an_r8_optimized_apk_is_kept_with_a_problem_line(self):
        """Password Store's fallback built an R8 release APK (2026-10-25)."""
        import zipfile

        def run(command):
            if "cognalys.builds.apk_build" in command:
                built = Path(command[command.index("--output-dir") + 1]) / "apks" / "pkg"
                built.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(built / "app-standard-release.apk", "w") as apk:
                    apk.writestr("classes.dex", b'dex\n~~R8{"backend":"dex","compilation-mode":'
                                                b'"release","r8-mode":"full"}')
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            built, problems = fdroid.build_from_source(
                ["com.emanuelef.remote_capture"], Path(directory) / "out",
                Path(directory) / "work", fetch, run)
            self.assertEqual(len(built), 1)
            self.assertIn("R8", problems[0]["problem"])


if __name__ == "__main__":
    unittest.main()
