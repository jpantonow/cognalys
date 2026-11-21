import csv
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.integrations import fdroid, github_build  # noqa: E402

APP_GRADLE_KTS = """
plugins {
    id("com.android.application")
    // id("com.android.library")
}
android {
    namespace = "org.example.app"
    defaultConfig {
        applicationId = "org.example.vault"
        versionCode = 42
    }
    flavorDimensions += listOf("store", "tier")
    productFlavors {
        create("play") { dimension = "store" }
        create("fdroid") {
            dimension = "store"
            buildConfigField("boolean", "GMS", "false")
        }
        create("pro") { dimension = "tier" }
    }
}
"""

APP_GRADLE = """
apply plugin: 'com.android.application'
android {
    defaultConfig {
        applicationId 'org.example.notes'
        versionCode 7
    }
    productFlavors {
        standard { }
        nightly { applicationIdSuffix '.nightly' }
    }
}
"""


def write(root: Path, files: dict) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


class ReadBuildTests(unittest.TestCase):
    def test_the_free_flavour_of_each_dimension_in_dimension_order(self):
        self.assertEqual(github_build.chosen_flavours(APP_GRADLE_KTS), ("fdroid", "pro"))

    def test_without_a_free_flavour_the_first_one(self):
        self.assertEqual(github_build.chosen_flavours(APP_GRADLE), ("standard",))
        self.assertEqual(github_build.chosen_flavours("android { }"), ())

    def test_the_phone_app_module_with_its_id_and_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write(Path(directory), {
                "app/build.gradle.kts": APP_GRADLE_KTS,
                "wear/build.gradle": APP_GRADLE,
                "core/build.gradle.kts": 'plugins { id("com.android.library") }',
                "settings.gradle.kts": 'include(":app", ":wear", ":core")',
                ".gitmodules": ""})
            build = github_build.build_for_checkout(root, "https://github.com/o/r", "a" * 40)
            self.assertEqual((build.package, build.version_code, build.subdir, build.gradle,
                              build.submodules),
                             ("org.example.vault", 42, "app", ("fdroid", "pro"), True))
            self.assertEqual(fdroid.gradle_task(build), ":app:assembleFdroidProDebug")

    def test_a_root_that_only_declares_the_plugin_is_not_the_app(self):
        """notedelight and hawk (2026-11-03): `apply false` at the root is not the app module."""
        with tempfile.TemporaryDirectory() as directory:
            root = write(Path(directory), {
                "build.gradle.kts": 'plugins {\n    alias(libs.plugins.android.application) apply false\n}\n',
                "androidApp/build.gradle.kts": APP_GRADLE_KTS})
            self.assertEqual(github_build.application_modules(root), [Path("androidApp")])

    def test_a_project_in_a_subfolder_builds_the_module_by_its_gradle_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write(Path(directory), {"Android/settings.gradle": "include ':app'",
                                           "Android/app/build.gradle": APP_GRADLE,
                                           "Android/features/vault/build.gradle": "",
                                           "README.md": ""})
            build = github_build.build_for_checkout(root, "https://github.com/o/r", "e" * 40)
            self.assertEqual((build.subdir, fdroid.gradle_task(build)),
                             ("Android/app", ":app:assembleStandardDebug"))
            self.assertEqual(github_build.gradle_path(root, Path("Android/features/vault")),
                             "features:vault")

    def test_a_single_module_project_at_the_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write(Path(directory), {"build.gradle": APP_GRADLE.replace("applicationId 'org.example.notes'", ""),
                                           "src/main/AndroidManifest.xml":
                                           '<manifest package="org.example.root"><application/></manifest>'})
            build = github_build.build_for_checkout(root, "https://github.com/o/r", "b" * 40)
            self.assertEqual((build.package, build.subdir), ("org.example.root", ""))
            self.assertEqual(fdroid.gradle_task(build), "assembleStandardDebug")

    def test_a_repository_without_an_application_module_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write(Path(directory), {"lib/build.gradle": "apply plugin: 'com.android.library'"})
            with self.assertRaises(ValueError):
                github_build.build_for_checkout(root, "https://github.com/o/r", "c" * 40)


class GithubBuildTests(unittest.TestCase):
    def test_the_head_is_built_like_an_fdroid_build(self):
        """The clone becomes the checkout; apks/ and sources.csv as fdroid-build writes them."""
        from unittest import mock
        from cognalys.builds import apk_build

        commands = []
        commit = "d" * 40

        def run(command):
            commands.append(command)
            if command[:2] == ["git", "clone"]:
                write(Path(command[-1]), {"app/build.gradle": APP_GRADLE,
                                          "app/src/main/java/org/example/notes/A.java":
                                          "package org.example.notes;\nclass A {}\n"})
                subprocess.run(["git", "init", "-q", command[-1]], check=True)
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[-2:] == ["rev-parse", "HEAD"]:
                return SimpleNamespace(returncode=0, stdout=commit + "\n", stderr="")
            if "cognalys.builds.apk_build" in command:
                built = Path(command[command.index("--output-dir") + 1]) / "apks" / "p"
                built.mkdir(parents=True)
                (built / "app-standard-debug.apk").write_bytes(b"PK standard")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(apk_build, "run_submodule_commands", return_value=None):
            out, work = Path(directory) / "out", Path(directory) / "work"
            built, problems = fdroid.build_from_source(
                ["https://github.com/o/notes"], out, work, run=run,
                resolve=lambda url: github_build.probe(url, work, run))
            self.assertEqual(problems, [])
            self.assertTrue((work / "org.example.notes" / "projects" / "org.example.notes" / ".git").is_dir())
            apk = out / "apks" / "org.example.notes.debug_7.apk"
            self.assertEqual(apk.read_bytes(), b"PK standard")
            [row] = list(csv.DictReader(open(out / "sources.csv", encoding="utf-8")))
            self.assertEqual((row["apk"], row["repo_url"], row["commit"]),
                             (apk.name, "https://github.com/o/notes", commit))
            self.assertIn("org.example.notes", row["manifest_package"])
        self.assertTrue(any("--task :app:assembleStandardDebug" in " ".join(command)
                            for command in commands))

    def test_a_failed_clone_is_a_problem_of_that_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / "work"
            run = lambda command: SimpleNamespace(returncode=128, stdout="", stderr="not found")  # noqa: E731
            built, problems = fdroid.build_from_source(
                ["https://github.com/o/gone"], Path(directory) / "out", work, run=run,
                resolve=lambda url: github_build.probe(url, work, run))
            self.assertEqual(built, [])
            self.assertIn("build source unavailable", problems[0]["problem"])


class GoogleServicesPlaceholderTests(unittest.TestCase):
    """The plugin needs a google-services.json the repository never commits (2026-11-03)."""

    GROOVY = """
plugins {
    id 'com.android.application'
    id 'com.google.gms.google-services'
}
android {
    defaultConfig { applicationId "me.example.gateway" }
    buildTypes {
        debug { applicationIdSuffix ".debug" }
        release { minifyEnabled false }
    }
}
"""
    KTS_CATALOG = """
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.google.services)
}
android {
    defaultConfig { applicationId = "org.example.crisis" }
    flavorDimensions += "store"
    productFlavors {
        create("foss") { dimension = "store"; applicationIdSuffix = ".foss" }
        create("play") { dimension = "store" }
    }
    buildTypes {
        getByName("debug") { applicationIdSuffix = ".dev" }
    }
}
"""
    CATALOG = """
[versions]
gms = "4.4.2"
[plugins]
android-application = { id = "com.android.application", version = "8.5.0" }
google-services = { id = "com.google.gms.google-services", version.ref = "gms" }
"""

    def build(self, gradle=(), subdir="app", package="me.example.gateway"):
        return fdroid.FdroidBuild(package=package, version_code=1, repo_url="https://github.com/o/r",
                                  commit="a" * 40, subdir=subdir, gradle=tuple(gradle))

    def test_the_plugin_is_detected_in_groovy_kotlin_and_a_catalog_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write(Path(directory), {
                "groovy/app/build.gradle": self.GROOVY,
                "apply/app/build.gradle": "apply plugin: 'com.android.application'\n"
                                          "apply plugin: 'com.google.gms.google-services'\n",
                "kts/app/build.gradle.kts": 'plugins {\n id("com.android.application")\n'
                                            ' id("com.google.gms.google-services")\n}\n',
                "catalog/app/build.gradle.kts": self.KTS_CATALOG,
                "catalog/gradle/libs.versions.toml": self.CATALOG,
                "none/app/build.gradle": "plugins {\n id 'com.android.application'\n"
                                         " // id 'com.google.gms.google-services'\n}\n",
                "none/build.gradle": "plugins { id 'com.google.gms.google-services' version '4.4' apply false }\n"})
            for name in ("groovy", "apply", "kts", "catalog"):
                self.assertTrue(github_build.applies_google_services(root / name, Path("app")), name)
            self.assertFalse(github_build.applies_google_services(root / "none", Path("app")))
            self.assertFalse(github_build.applies_google_services(root / "none", Path(".")))

    def test_the_client_is_the_variants_application_id_with_its_suffixes(self):
        import json

        with tempfile.TemporaryDirectory() as directory:
            root = write(Path(directory), {"app/build.gradle.kts": self.KTS_CATALOG,
                                           "gradle/libs.versions.toml": self.CATALOG})
            note = github_build.write_google_services_placeholder(
                self.build(gradle=("foss",), package="org.example.crisis"), root)
            data = json.loads((root / "app" / "google-services.json").read_text(encoding="utf-8"))
        self.assertIn("placeholder", note)
        self.assertEqual(data["client"][0]["client_info"]["android_client_info"]["package_name"],
                         "org.example.crisis.foss.dev")
        self.assertEqual(data["project_info"]["project_id"], github_build.PLACEHOLDER_PROJECT)

    def test_a_project_holding_its_own_file_for_the_variant_is_left_alone(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write(Path(directory), {"app/build.gradle": self.GROOVY,
                                           "app/src/debug/google-services.json": '{"own": true}'})
            self.assertEqual(github_build.write_google_services_placeholder(self.build(), root), "")
            self.assertFalse((root / "app" / "google-services.json").exists())
            # An earlier placeholder left in a reused checkout is not the project's file.
            (root / "app" / "src" / "debug" / "google-services.json").unlink()
            github_build.write_google_services_placeholder(self.build(), root)
            self.assertIn("placeholder",
                          github_build.write_google_services_placeholder(self.build(), root))

    def test_without_the_plugin_only_the_builds_own_message_writes_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = write(Path(directory), {"app/build.gradle": "plugins { id 'com.android.application' }\n"
                                           "android { defaultConfig { applicationId 'me.example.gateway' } }\n"})
            build = self.build()
            self.assertEqual(github_build.write_google_services_placeholder(build, root), "")
            self.assertEqual(github_build.write_google_services_placeholder(build, root, "BUILD FAILED"), "")
            self.assertTrue(github_build.write_google_services_placeholder(
                build, root, "Execution failed for task ':app:processDebugGoogleServices'.\n"
                "> File google-services.json is missing."))
            self.assertTrue((root / "app" / "google-services.json").is_file())

    def test_a_build_failing_on_the_missing_file_is_retried_once_and_recorded(self):
        """The detection misses (the plugin comes from a convention plugin); the log settles it."""
        from unittest import mock
        from cognalys.builds import apk_build

        builds = []
        commit = "e" * 40

        def run(command):
            if command[:2] == ["git", "clone"]:
                write(Path(command[-1]), {"app/build.gradle": "plugins { id 'com.android.application'\n"
                                          " id 'my.convention' }\n"
                                          "android { defaultConfig { applicationId 'me.example.gateway'\n"
                                          " versionCode 3 } }\n"})
                subprocess.run(["git", "init", "-q", command[-1]], check=True)
            if command[-2:] == ["rev-parse", "HEAD"]:
                return SimpleNamespace(returncode=0, stdout=commit + "\n", stderr="")
            if "cognalys.builds.apk_build" in command:
                output = Path(command[command.index("--output-dir") + 1])
                checkout = Path(command[command.index("--projects-dir") + 1]) / "me.example.gateway"
                builds.append(command)
                if not (checkout / "app" / "google-services.json").is_file():
                    (output / "logs" / "projects").mkdir(parents=True, exist_ok=True)
                    (output / "logs" / "projects" / "p.log").write_text(
                        "> File google-services.json is missing.\n", encoding="utf-8")
                    return SimpleNamespace(returncode=1, stdout="", stderr="")
                (output / "apks").mkdir(parents=True, exist_ok=True)
                (output / "apks" / "app-debug.apk").write_bytes(b"PK")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(apk_build, "run_submodule_commands", return_value=None):
            out, work = Path(directory) / "out", Path(directory) / "work"
            built, problems = fdroid.build_from_source(
                ["https://github.com/o/gateway"], out, work, run=run,
                resolve=lambda url: github_build.probe(url, work, run),
                prepare=github_build.write_google_services_placeholder)
            self.assertEqual(problems, [])
            self.assertEqual(len(builds), 2)
            [row] = list(csv.DictReader(open(out / "sources.csv", encoding="utf-8")))
        self.assertIn("placeholder google-services.json", row["build_note"])


if __name__ == "__main__":
    unittest.main()
