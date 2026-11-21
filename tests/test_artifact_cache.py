import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.artifact_cache import (  # noqa: E402
    ArtifactCache,
    extract_method_blocks,
    locate_method_bytecode,
    read_module_dependencies,
    read_pom_dependencies,
    select_cached_version,
    trace_owner_through_metadata,
)
from cognalys.extraction.dependency_context import (  # noqa: E402
    collect_dependency_context,
    group_owns_class,
)
from cognalys.llm.generate_error_fixes import FixGenerator  # noqa: E402


TINK_CLASS = "com.google.crypto.tink.integration.android.AndroidKeystoreAesGcm"

# app.maskan.chat's catalog, reduced to what the matching reads.
MASKAN_CATALOG = (
    "[versions]\n"
    "compose-bom = \"2025.04.01\"\n"
    "security-crypto = \"1.1.0-alpha06\"\n"
    "\n"
    "[libraries]\n"
    "compose-bom = { group = \"androidx.compose\", name = \"compose-bom\", "
    "version.ref = \"compose-bom\" }\n"
    "security-crypto = { group = \"androidx.security\", "
    "name = \"security-crypto\", version.ref = \"security-crypto\" }\n"
)

TINK_SOURCE = """
package com.google.crypto.tink.integration.android;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public final class AndroidKeystoreAesGcm {
    private final SecretKey key;

    public AndroidKeystoreAesGcm(SecretKey key) { this.key = key; }

    private byte[] encryptInternal(byte[] plaintext, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    public byte[] decrypt(byte[] ciphertext) { return ciphertext; }
}
"""


def _pom(group, artifact, version, dependencies):
    body = "".join(
        "<dependency>"
        f"<groupId>{g}</groupId><artifactId>{a}</artifactId>"
        f"<version>{v}</version>"
        + (f"<scope>{scope}</scope>" if scope else "")
        + "</dependency>"
        for g, a, v, scope in dependencies
    )
    return (
        '<?xml version="1.0"?>'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        f"<groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
        f"<version>{version}</version><dependencies>{body}</dependencies>"
        "</project>"
    )


def _publish(root, group, artifact, version, name, content):
    directory = root / group / artifact / version / "0123abcd"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def _compiled_jar(workdir: Path, class_name: str, source: str) -> bytes:
    """A jar holding one compiled class, or SkipTest without a JDK."""
    if not shutil.which("javac") or not shutil.which("javap"):
        raise unittest.SkipTest("a JDK (javac and javap) is required")
    package, simple = class_name.rsplit(".", 1)
    source_path = workdir / "src" / Path(*package.split(".")) / f"{simple}.java"
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(source, encoding="utf-8")
    classes = workdir / "classes"
    subprocess.run(
        ["javac", "-d", str(classes), str(source_path)],
        check=True, capture_output=True,
    )
    entry = class_name.replace(".", "/") + ".class"
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.write(classes / entry, entry)
    return buffer.getvalue()


def _owns(class_name):
    return lambda group: group_owns_class(group, class_name)


class VersionSelectionTests(unittest.TestCase):
    def test_the_requested_version_is_used_when_cached(self):
        self.assertEqual(
            select_cached_version("1.8.0", ["1.5.0", "1.8.0"]), ("1.8.0", True),
        )

    def test_a_prerelease_reads_its_own_release_line(self):
        """maskan requests 1.1.0-alpha06; the cache has 1.0.0 and 1.1.0."""
        self.assertEqual(
            select_cached_version("1.1.0-alpha06", ["1.0.0", "1.1.0"]),
            ("1.1.0", False),
        )

    def test_versions_compare_numerically(self):
        self.assertEqual(
            select_cached_version("", ["1.9.0", "1.10.0", "1.2.0"]),
            ("1.10.0", False),
        )

    def test_nothing_cached_selects_nothing(self):
        self.assertEqual(select_cached_version("1.0", []), ("", False))


class MetadataReadingTests(unittest.TestCase):
    def test_module_dependencies_and_redirects_are_read(self):
        module = {
            "variants": [
                {"attributes": {"org.gradle.category": "library"},
                 "available-at": {"group": "com.squareup.okhttp3",
                                  "module": "okhttp-android",
                                  "version": "5.3.2"}},
                {"attributes": {"org.gradle.category": "library"},
                 "dependencies": [{"group": "com.google.crypto.tink",
                                   "module": "tink-android",
                                   "version": {"requires": "1.8.0"}}]},
                {"attributes": {"org.gradle.category": "documentation"},
                 "available-at": {"group": "docs.only", "module": "sources",
                                  "version": "1"}},
            ],
        }
        found = read_module_dependencies(json.dumps(module))
        self.assertEqual(
            [(d["group"], d["artifact"], d["version"], d["relation"]) for d in found],
            [("com.squareup.okhttp3", "okhttp-android", "5.3.2", "available_at"),
             ("com.google.crypto.tink", "tink-android", "1.8.0", "dependency")],
        )

    def test_pom_skips_test_scope_and_resolves_properties(self):
        pom = (
            '<project xmlns="http://maven.apache.org/POM/4.0.0">'
            "<properties><tink.version>1.8.0</tink.version></properties>"
            "<dependencies>"
            "<dependency><groupId>com.google.crypto.tink</groupId>"
            "<artifactId>tink-android</artifactId>"
            "<version>${tink.version}</version></dependency>"
            "<dependency><groupId>junit</groupId><artifactId>junit</artifactId>"
            "<version>4.13</version><scope>test</scope></dependency>"
            "</dependencies></project>"
        )
        found = read_pom_dependencies(pom)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["version"], "1.8.0")


class GroupOwnershipTests(unittest.TestCase):
    def test_a_group_owns_the_packages_inside_it(self):
        self.assertTrue(group_owns_class("com.google.crypto.tink", TINK_CLASS))
        self.assertTrue(group_owns_class(
            "androidx.security", "androidx.security.crypto.MasterKey",
        ))

    def test_a_group_named_after_the_package_root_owns_it(self):
        self.assertTrue(group_owns_class(
            "com.squareup.okhttp3", "okhttp3.internal.platform.Platform",
        ))

    def test_the_platform_root_is_never_owned_by_name(self):
        self.assertFalse(group_owns_class(
            "com.google.android", "android.app.Activity",
        ))

    def test_a_sibling_group_does_not_own_the_class(self):
        self.assertFalse(group_owns_class("androidx.security", TINK_CLASS))
        self.assertFalse(group_owns_class("com.google.crypto.tinkey", TINK_CLASS))


class MetadataTraceTests(unittest.TestCase):
    DECLARATIONS = [
        {"group": "androidx.compose", "artifact": "compose-bom",
         "version_expression": "2025.04.01", "source_file_path": "libs.toml",
         "line": 29},
        {"group": "androidx.security", "artifact": "security-crypto",
         "version_expression": "1.1.0-alpha06",
         "source_file_path": "libs.toml", "line": 68},
    ]

    def test_a_carrier_is_found_through_its_published_pom(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _publish(root, "androidx.security", "security-crypto", "1.1.0",
                     "security-crypto-1.1.0.pom",
                     _pom("androidx.security", "security-crypto", "1.1.0",
                          [("com.google.crypto.tink", "tink-android", "1.8.0", "")]))
            result = trace_owner_through_metadata(
                self.DECLARATIONS, _owns(TINK_CLASS), ArtifactCache([root]),
            )
        self.assertEqual(result["status"], "found")
        [carrier] = result["carriers"]
        self.assertEqual(carrier["artifact"], "security-crypto")
        self.assertEqual(carrier["owner"]["artifact"], "tink-android")
        self.assertEqual(
            carrier["dependency_path"],
            ["androidx.security:security-crypto",
             "com.google.crypto.tink:tink-android"],
        )
        # Read from 1.1.0, not the declared 1.1.0-alpha06.
        self.assertIs(carrier["confirmed"], False)
        self.assertIn("not the declared 1.1.0-alpha06", carrier["basis"])
        self.assertIn(
            "androidx.compose:compose-bom",
            result["declarations_without_cached_metadata"],
        )

    def test_the_exact_version_confirms_the_carrier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _publish(root, "androidx.security", "security-crypto",
                     "1.1.0-alpha06", "security-crypto-1.1.0-alpha06.pom",
                     _pom("androidx.security", "security-crypto",
                          "1.1.0-alpha06",
                          [("com.google.crypto.tink", "tink-android", "1.8.0", "")]))
            result = trace_owner_through_metadata(
                self.DECLARATIONS, _owns(TINK_CLASS), ArtifactCache([root]),
            )
        self.assertIs(result["carriers"][0]["confirmed"], True)

    def test_a_carrier_is_found_across_an_intermediate_module(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _publish(root, "com.example", "sdk", "2.0", "sdk-2.0.pom",
                     _pom("com.example", "sdk", "2.0",
                          [("com.example", "sdk-core", "2.0", "")]))
            _publish(root, "com.example", "sdk-core", "2.0", "sdk-core-2.0.pom",
                     _pom("com.example", "sdk-core", "2.0",
                          [("com.google.crypto.tink", "tink-android", "1.8.0", "")]))
            result = trace_owner_through_metadata(
                [{"group": "com.example", "artifact": "sdk",
                  "version_expression": "2.0"}],
                _owns(TINK_CLASS), ArtifactCache([root]),
            )
        self.assertEqual(
            result["carriers"][0]["dependency_path"],
            ["com.example:sdk", "com.example:sdk-core",
             "com.google.crypto.tink:tink-android"],
        )
        self.assertIs(result["carriers"][0]["confirmed"], True)

    def test_a_test_scoped_dependency_carries_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _publish(root, "com.example", "sdk", "2.0", "sdk-2.0.pom",
                     _pom("com.example", "sdk", "2.0",
                          [("com.google.crypto.tink", "tink-android", "1.8.0", "test")]))
            result = trace_owner_through_metadata(
                [{"group": "com.example", "artifact": "sdk",
                  "version_expression": "2.0"}],
                _owns(TINK_CLASS), ArtifactCache([root]),
            )
        self.assertEqual(result["status"], "not_found")

    def test_no_cache_is_reported_as_such(self):
        result = trace_owner_through_metadata(
            self.DECLARATIONS, _owns(TINK_CLASS), ArtifactCache([]),
        )
        self.assertEqual(result["status"], "cache_unavailable")


class MethodBlockTests(unittest.TestCase):
    OUTPUT = (
        "Compiled from \"Box.java\"\n"
        "public final class p.Box {\n"
        "  private final javax.crypto.SecretKey key;\n"
        "\n"
        "  public p.Box(javax.crypto.SecretKey);\n"
        "    Code:\n"
        "       0: aload_0\n"
        "\n"
        "  private byte[] seal(byte[]) throws java.lang.Exception;\n"
        "    Code:\n"
        "       0: ldc           #7                  // String AES/GCM/NoPadding\n"
        "       2: invokestatic  #9                  // Method javax/crypto/Cipher.getInstance\n"
        "\n"
        "  public byte[] seal-abc12(byte[], int);\n"
        "    Code:\n"
        "       0: aconst_null\n"
        "\n"
        "  public byte[] unseal(byte[]);\n"
        "    Code:\n"
        "       0: aload_1\n"
        "}\n"
    )

    def test_every_overload_and_only_it_is_extracted(self):
        methods = extract_method_blocks(self.OUTPUT, "seal")
        self.assertEqual(
            [method["signature"] for method in methods],
            ["private byte[] seal(byte[]) throws java.lang.Exception;",
             "public byte[] seal-abc12(byte[], int);"],
        )
        self.assertIn("Cipher.getInstance", methods[0]["disassembly"])
        self.assertNotIn("unseal", methods[1]["disassembly"])

    def test_a_constructor_is_found_under_the_class_name(self):
        methods = extract_method_blocks(self.OUTPUT, "<init>", "p.Box")
        self.assertEqual(len(methods), 1)
        self.assertIn("p.Box(", methods[0]["signature"])


class BytecodeLocationTests(unittest.TestCase):
    """Against a real compiled class, so javap's actual output is parsed."""

    def test_the_method_is_disassembled_from_the_cached_jar(self):
        with tempfile.TemporaryDirectory() as directory:
            workdir = Path(directory)
            jar = _compiled_jar(workdir, TINK_CLASS, TINK_SOURCE)
            root = workdir / "cache"
            _publish(root, "com.google.crypto.tink", "tink-android", "1.8.0",
                     "tink-android-1.8.0.jar", jar)
            result = locate_method_bytecode(
                [{"group": "com.google.crypto.tink", "artifact": "tink-android",
                  "version": "1.8.0"}],
                TINK_CLASS, "encryptInternal", ArtifactCache([root]),
            )
        self.assertEqual(result["status"], "available")
        self.assertIs(result["version_exact"], True)
        [method] = result["methods"]
        self.assertIn("encryptInternal(byte[], byte[])", method["signature"])
        self.assertIn("Cipher.updateAAD", method["disassembly"])
        self.assertNotIn("decrypt", method["disassembly"])

    def test_a_redirecting_module_is_followed_into_an_aar(self):
        """okhttp 5 publishes no code itself and redirects to okhttp-android,
        whose binary is cached as okhttp-release.aar."""
        with tempfile.TemporaryDirectory() as directory:
            workdir = Path(directory)
            jar = _compiled_jar(workdir, TINK_CLASS, TINK_SOURCE)
            aar = BytesIO()
            with zipfile.ZipFile(aar, "w") as archive:
                archive.writestr("classes.jar", jar)
            root = workdir / "cache"
            _publish(root, "com.google.crypto.tink", "tink", "2.0", "tink-2.0.module",
                     json.dumps({"variants": [{
                         "attributes": {"org.gradle.category": "library"},
                         "available-at": {"group": "com.google.crypto.tink",
                                          "module": "tink-android",
                                          "version": "2.0"}}]}))
            _publish(root, "com.google.crypto.tink", "tink-android", "2.0",
                     "tink-release.aar", aar.getvalue())
            result = locate_method_bytecode(
                [{"group": "com.google.crypto.tink", "artifact": "tink",
                  "version": "2.0"}],
                TINK_CLASS, "encryptInternal", ArtifactCache([root]),
            )
        self.assertEqual(result["status"], "available")
        self.assertEqual(result["artifact"], "com.google.crypto.tink:tink-android")
        self.assertEqual(result["binary"], "tink-release.aar")

    def test_without_javap_the_record_says_so(self):
        with tempfile.TemporaryDirectory() as directory:
            workdir = Path(directory)
            jar = _compiled_jar(workdir, TINK_CLASS, TINK_SOURCE)
            root = workdir / "cache"
            _publish(root, "com.google.crypto.tink", "tink-android", "1.8.0",
                     "tink-android-1.8.0.jar", jar)
            result = locate_method_bytecode(
                [{"group": "com.google.crypto.tink", "artifact": "tink-android",
                  "version": "1.8.0"}],
                TINK_CLASS, "encryptInternal", ArtifactCache([root]), javap="",
            )
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "javap_not_found")

    def test_a_class_in_no_cached_artifact_is_reported_with_what_was_searched(self):
        with tempfile.TemporaryDirectory() as directory:
            result = locate_method_bytecode(
                [{"group": "com.google.crypto.tink", "artifact": "tink-android",
                  "version": "1.8.0"}],
                TINK_CLASS, "encryptInternal", ArtifactCache([Path(directory)]),
                javap="javap",
            )
        self.assertEqual(result["reason"], "class_not_found_in_cached_artifacts")
        self.assertEqual(
            result["searched"][0]["coordinate"],
            "com.google.crypto.tink:tink-android",
        )


class CollectedContextTests(unittest.TestCase):
    """app.maskan.chat's shape: the owner arrives through a declared
    artifact that shares no name with it, and the graph is unavailable."""

    def _context(self, with_jar=False):
        with tempfile.TemporaryDirectory() as directory:
            workdir = Path(directory)
            repo = workdir / "repo"
            (repo / "gradle").mkdir(parents=True)
            (repo / "gradle" / "libs.versions.toml").write_text(
                MASKAN_CATALOG, encoding="utf-8",
            )
            cache_root = workdir / "cache"
            _publish(cache_root, "androidx.security", "security-crypto", "1.1.0",
                     "security-crypto-1.1.0.pom",
                     _pom("androidx.security", "security-crypto", "1.1.0",
                          [("com.google.crypto.tink", "tink-android", "1.8.0", "")]))
            if with_jar:
                _publish(cache_root, "com.google.crypto.tink", "tink-android",
                         "1.8.0", "tink-android-1.8.0.jar",
                         _compiled_jar(workdir, TINK_CLASS, TINK_SOURCE))
            cache_root.mkdir(exist_ok=True)
            return collect_dependency_context(
                repo, TINK_CLASS, "app.maskan.chat_90.apk",
                method_name="encryptInternal",
                artifact_cache=ArtifactCache([cache_root]),
            )

    def test_the_metadata_carrier_is_recorded(self):
        carriers = self._context()["cached_artifact_metadata"]["carriers"]
        self.assertEqual(
            [(c["artifact"], c["owner"]["artifact"]) for c in carriers],
            [("security-crypto", "tink-android")],
        )

    def test_an_organisation_root_does_not_score_an_artifact_prefix(self):
        """"com" is a prefix of compose-bom; that is not a match."""
        candidates = self._context()["dependency_candidates"]
        self.assertNotIn(
            "compose-bom", {item["artifact"] for item in candidates},
        )

    def test_the_owners_bytecode_is_attached(self):
        bytecode = self._context(with_jar=True)["external_target_bytecode"]
        self.assertEqual(bytecode["status"], "available")
        self.assertEqual(bytecode["artifact"], "com.google.crypto.tink:tink-android")
        self.assertEqual(bytecode["cached_version"], "1.8.0")

    def test_an_approximate_carrier_makes_the_bytecode_version_approximate(self):
        """tink-android 1.8.0 is exact in the cache, but 1.8.0 was read from
        security-crypto 1.1.0 rather than the declared 1.1.0-alpha06."""
        bytecode = self._context(with_jar=True)["external_target_bytecode"]
        self.assertIs(bytecode["requested_version_confirmed"], False)
        self.assertIs(bytecode["version_exact"], False)
        self.assertIn("other than the one the project declares", bytecode["bound"])

    def test_without_a_cached_binary_the_record_says_what_was_searched(self):
        bytecode = self._context()["external_target_bytecode"]
        self.assertEqual(bytecode["status"], "unavailable")


class AnalysableTests(unittest.TestCase):
    BASE = {"method_body": "", "source_file_path": "",
            "surrounding_context": "",
            "extraction_status": "external_dependency_candidate"}

    def test_a_metadata_carrier_makes_the_finding_analysable(self):
        error = dict(self.BASE, dependency_context={
            "status": "ambiguous", "lexical_carriers": [],
            "cached_artifact_metadata": {
                "status": "found",
                "carriers": [{"artifact": "security-crypto"}],
            },
        })
        self.assertEqual(FixGenerator.unanalysable_reason(error), "")

    def test_the_owners_bytecode_makes_the_finding_analysable(self):
        error = dict(self.BASE, dependency_context={
            "status": "ambiguous",
            "external_target_bytecode": {
                "status": "available", "methods": [{"signature": "x()"}],
            },
        })
        self.assertEqual(FixGenerator.unanalysable_reason(error), "")

    def test_a_below_threshold_match_is_not_reported_as_no_match(self):
        error = dict(self.BASE, dependency_context={
            "status": "ambiguous",
            "dependency_candidates": [
                {"group": "androidx.security", "artifact": "security-crypto",
                 "match_score": 2},
            ],
            "cached_artifact_metadata": {"status": "not_found", "carriers": []},
            "dependency_graph": {"status": "unavailable",
                                 "reason": "no_dependency_tree_in_output"},
        })
        reason = FixGenerator.unanalysable_reason(error)
        self.assertIn("below the identification threshold", reason)
        self.assertIn("androidx.security:security-crypto", reason)
        self.assertIn("led to no carrier (not_found)", reason)
        self.assertNotIn("no declared dependency matched", reason)


if __name__ == "__main__":
    unittest.main()
