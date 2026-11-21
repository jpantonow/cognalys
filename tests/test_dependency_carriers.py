import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.dependency_context import (  # noqa: E402
    collect_dependency_context,
    lexical_carriers,
    library_head,
    owning_package_prefix,
)
from cognalys.llm.generate_error_fixes import FixGenerator  # noqa: E402


OKHTTP_CLASS = "okhttp3.internal.platform.Platform"

# jellyfin-android's catalog, reduced to what the matching reads. It never
# declares OkHttp; Coil's own module metadata lists com.squareup.okhttp3:okhttp.
JELLYFIN_CATALOG = (
    "[versions]\n"
    "coroutines = \"1.11.0\"\n"
    "coil = \"3.6.2\"\n"
    "androidx-media3 = \"1.11.0\"\n"
    "\n"
    "[libraries]\n"
    "coroutines-core = { group = \"org.jetbrains.kotlinx\", "
    "name = \"kotlinx-coroutines-core\", version.ref = \"coroutines\" }\n"
    "coil-network = { group = \"io.coil-kt.coil3\", "
    "name = \"coil-network-okhttp\", version.ref = \"coil\" }\n"
    "androidx-media3-datasource-okhttp = { module = "
    "\"androidx.media3:media3-datasource-okhttp\", "
    "version.ref = \"androidx-media3\" }\n"
)


def _declaration(group, artifact, version="1.0"):
    return {"group": group, "artifact": artifact,
            "version_expression": version, "source_file_path": "libs.toml",
            "line": 1}


class LibraryHeadTests(unittest.TestCase):
    """How an integration artifact spells the library it integrates."""

    def test_version_digits_are_dropped_from_the_package_root(self):
        self.assertEqual(library_head(OKHTTP_CLASS), "okhttp")
        self.assertEqual(library_head("retrofit2.Retrofit"), "retrofit")

    def test_an_organisation_root_names_no_library(self):
        """com.google.crypto would match every artifact saying google or
        crypto, so reverse-domain packages are left to the resolved graph."""
        self.assertEqual(
            library_head("com.google.crypto.tink.aead.AesGcmKey"), "",
        )

    def test_the_platform_is_not_a_library(self):
        self.assertEqual(library_head("kotlin.uuid.Uuid"), "")
        self.assertEqual(library_head("javax.net.ssl.SSLContext"), "")

    def test_a_root_too_short_to_be_distinctive_names_nothing(self):
        self.assertEqual(library_head("abc.Thing"), "")


class OwningPackageTests(unittest.TestCase):
    def test_a_layout_segment_is_not_part_of_the_library_name(self):
        self.assertEqual(owning_package_prefix(OKHTTP_CLASS), "okhttp3")
        self.assertEqual(
            owning_package_prefix("okio.internal.Buffer"), "okio",
        )

    def test_a_meaningful_second_segment_is_kept(self):
        self.assertEqual(owning_package_prefix("kotlin.uuid.Uuid"), "kotlin.uuid")


class LexicalCarrierTests(unittest.TestCase):
    """Declared artifacts that probably bring the owning library in."""

    DECLARATIONS = [
        _declaration("org.jetbrains.kotlinx", "kotlinx-coroutines-core"),
        _declaration("io.coil-kt.coil3", "coil-network-okhttp", "3.6.2"),
        _declaration("androidx.media3", "media3-datasource-okhttp", "1.11.0"),
        _declaration("io.coil-kt.coil3", "coil-network-okhttp", "3.6.2"),
    ]

    def test_artifacts_naming_the_library_are_carriers(self):
        carriers = lexical_carriers(OKHTTP_CLASS, self.DECLARATIONS)
        self.assertEqual(
            [(c["group"], c["artifact"]) for c in carriers],
            [("io.coil-kt.coil3", "coil-network-okhttp"),
             ("androidx.media3", "media3-datasource-okhttp")],
        )

    def test_a_carrier_is_never_presented_as_confirmed(self):
        for carrier in lexical_carriers(OKHTTP_CLASS, self.DECLARATIONS):
            self.assertIs(carrier["confirmed"], False)
            self.assertIn("okhttp", carrier["basis"])

    def test_the_owning_library_is_the_owner_not_a_carrier(self):
        carriers = lexical_carriers(OKHTTP_CLASS, [
            _declaration("com.squareup.okhttp3", "okhttp"),
            _declaration("com.squareup.okhttp3", "okhttp-zstd"),
        ])
        self.assertEqual(carriers, [])

    def test_a_token_is_matched_whole(self):
        # "okhttpish" is not okhttp.
        carriers = lexical_carriers(OKHTTP_CLASS, [
            _declaration("com.example", "okhttpish-client"),
        ])
        self.assertEqual(carriers, [])

    def test_a_carrier_is_matched_across_version_digits_on_its_side_too(self):
        carriers = lexical_carriers("retrofit2.Retrofit", [
            _declaration("com.example", "adapter-retrofit2"),
        ])
        self.assertEqual(len(carriers), 1)

    def test_no_carriers_are_guessed_for_an_organisation_package(self):
        carriers = lexical_carriers(
            "com.google.crypto.tink.aead.AesGcmKey",
            [_declaration("androidx.security", "security-crypto")],
        )
        self.assertEqual(carriers, [])


class CollectedContextTests(unittest.TestCase):
    """The whole record for jellyfin's shape of finding."""

    def _context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "gradle").mkdir()
            (root / "gradle" / "libs.versions.toml").write_text(
                JELLYFIN_CATALOG, encoding="utf-8",
            )
            return collect_dependency_context(root, OKHTTP_CLASS)

    def test_the_carriers_are_recorded(self):
        artifacts = {c["artifact"] for c in self._context()["lexical_carriers"]}
        self.assertEqual(
            artifacts, {"coil-network-okhttp", "media3-datasource-okhttp"},
        )

    def test_nothing_is_claimed_as_identified(self):
        """A carrier is a hint, not the artifact that ships the class."""
        context = self._context()
        self.assertEqual(context["status"], "ambiguous")
        self.assertEqual(context["likely_dependency"], {})

    def test_unrelated_declarations_are_not_offered_as_candidates(self):
        self.assertEqual(self._context()["dependency_candidates"], [])

    def test_the_owning_library_is_named(self):
        attribution = self._context()["third_party_attribution"]
        self.assertEqual(attribution["owning_package"], "okhttp3")
        self.assertFalse(attribution["declared_directly"])

    def test_an_unavailable_graph_says_why(self):
        graph = self._context()["dependency_graph"]
        self.assertEqual(graph["status"], "unavailable")
        self.assertTrue(graph["reason"])

    def test_a_failed_offline_build_records_gradles_own_cause(self):
        """End to end, through a wrapper that fails the way jellyfin's did.

        The output is read from a file beside the script so no shell quoting
        stands between the fixture and what the parser sees.
        """
        import os
        import stat

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "gradle").mkdir()
            (root / "gradle" / "libs.versions.toml").write_text(
                JELLYFIN_CATALOG, encoding="utf-8",
            )
            if os.name == "nt":
                self.skipTest("the fake wrapper is a POSIX script")
            wrapper = root / "gradlew"
            wrapper.write_text('#!/bin/sh\ncat "$0.out"\nexit 1\n',
                               encoding="utf-8")
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
            (root / "gradlew.out").write_text(
                GradleFailureCauseTests.OUTPUT, encoding="utf-8",
            )
            graph = collect_dependency_context(
                root, OKHTTP_CLASS,
            )["dependency_graph"]
        self.assertEqual(graph["reason"], "no_dependency_tree_in_output")
        self.assertIn("kotlin-dsl", graph["diagnostic_cause"])
        self.assertNotIn("--stacktrace", graph["diagnostic_cause"])


class GradleFailureCauseTests(unittest.TestCase):
    """An unavailable graph has to say why, and Gradle's footer never does."""

    # jellyfin-android's offline `gradlew dependencies`, verbatim in shape.
    OUTPUT = (
        "\n"
        "FAILURE: Build failed with an exception.\n"
        "\n"
        "* Where:\n"
        "Build file '/repo/buildSrc/build.gradle.kts' line: 1\n"
        "\n"
        "* What went wrong:\n"
        "Plugin [id: 'org.gradle.kotlin.kotlin-dsl', version: '6.7.3'] was "
        "not found in any of the following sources:\n"
        "\n"
        "- Gradle Core Plugins (plugin is not in 'org.gradle' namespace)\n"
        "\n"
        "* Try:\n"
        "> Run with --stacktrace option to get the stack trace.\n"
        "> Run with --scan to get full insights.\n"
        "\n"
        "BUILD FAILED in 2s\n"
    )

    def test_the_cause_is_kept_and_the_footer_is_not(self):
        from cognalys.extraction.dependency_context import gradle_failure_cause

        cause = gradle_failure_cause(self.OUTPUT)
        self.assertIn("kotlin-dsl", cause)
        self.assertIn("was not found", cause)
        self.assertNotIn("--stacktrace", cause)
        self.assertNotIn("BUILD FAILED", cause)

    def test_output_without_a_failure_section_gives_nothing(self):
        from cognalys.extraction.dependency_context import gradle_failure_cause

        self.assertEqual(gradle_failure_cause("BUILD SUCCESSFUL in 3s"), "")
        self.assertEqual(gradle_failure_cause(""), "")

    def test_a_long_cause_is_bounded(self):
        from cognalys.extraction.dependency_context import gradle_failure_cause

        output = "* What went wrong:\n" + ("x " * 2000) + "\n* Try:\n> help\n"
        self.assertLessEqual(len(gradle_failure_cause(output)), 600)


class AnalysableTests(unittest.TestCase):
    """"No dependency" was being recorded as a fact when it was not one."""

    BASE = {"method_body": "", "source_file_path": "",
            "surrounding_context": "",
            "extraction_status": "external_dependency_candidate"}

    def test_a_named_carrier_makes_the_finding_analysable(self):
        error = dict(self.BASE, dependency_context={
            "status": "ambiguous",
            "lexical_carriers": [{"group": "io.coil-kt.coil3",
                                  "artifact": "coil-network-okhttp"}],
        })
        self.assertEqual(FixGenerator.unanalysable_reason(error), "")

    def test_the_refusal_says_what_was_checked_not_that_nothing_exists(self):
        error = dict(self.BASE, dependency_context={
            "status": "ambiguous", "lexical_carriers": [],
            "dependency_graph": {"status": "unavailable",
                                 "reason": "no_dependency_tree_in_output"},
        })
        reason = FixGenerator.unanalysable_reason(error)
        self.assertIn("matched it by name", reason)
        self.assertIn("no_dependency_tree_in_output", reason)
        self.assertNotIn("no dependency artifact was identified", reason)

    def test_an_identified_dependency_is_still_analysable(self):
        error = dict(self.BASE, dependency_context={"status": "identified"})
        self.assertEqual(FixGenerator.unanalysable_reason(error), "")


if __name__ == "__main__":
    unittest.main()
