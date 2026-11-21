import logging
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "src", ROOT / "src" / "cognalys" / "extraction", ROOT / "src" / "cognalys" / "config"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from cognalys.extraction import extract_methods_single_csv as extraction  # noqa: E402
from cognalys.extraction.app_caller_attribution import (  # noqa: E402
    attribute_to_application, declared_name, statement_from,
)

SPEC = {"events": [
    {"condition": "Observation clause: `ep1: setEnabledProtocols(protocols);`"},
    {"condition": "Observation clause: `ec1: setEnabledCipherSuites(suites);`"},
]}
EXTRACTOR = extraction.MethodExtractor(logging.getLogger("test"))
KOTLIN = """package com.example

class Factory {
    private fun withTLS(socket: Socket) = socket.apply {
        (socket as? SSLSocket)?.enabledProtocols = arrayOf("TLSv1", "TLSv1.2")
    }
}
"""


def _row(**overrides):
    row = {"class": "org.conscrypt.ConscryptEngineSocket",
           "method": "setEnabledProtocols", "spec": "SSLEngineSpec",
           "detector_value": "TLSv1", "message": ""}
    row.update(overrides)
    return row


class AttributionTests(unittest.TestCase):
    def _attribute(self, files, row=None, spec=SPEC):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            return attribute_to_application(
                root, row or _row(), spec,
                lambda path, line: extraction._declaration_bounds(EXTRACTOR, path, line),
            )

    def test_a_kotlin_property_setter_passing_the_literal_is_attributed(self):
        result = self._attribute({"app/src/main/kotlin/Factory.kt": KOTLIN})
        self.assertEqual(result["status"], "attributed")
        self.assertEqual(result["call_site"]["line"], 5)
        self.assertEqual(result["reported_frame"]["class"], "org.conscrypt.ConscryptEngineSocket")

    def test_a_java_call_passing_the_literal_is_attributed(self):
        java = (
            "class A {\n"
            "    void configure(SSLSocket s) {\n"
            "        s.setEnabledProtocols(new String[] {\"TLSv1\"});\n"
            "    }\n"
            "}\n"
        )
        result = self._attribute({"src/main/java/A.java": java})
        self.assertEqual(result["status"], "attributed")
        self.assertEqual(result["call_site"]["line"], 3)

    def test_a_library_method_that_only_uses_the_api_is_never_attributed(self):
        # okio's ByteString.digest asks for MD5 itself; an application
        # getInstance("MD5") elsewhere is a different call.
        spec = {"events": [{"condition": "`g1: getInstance(alg);`"}]}
        app = 'class A { void f() { MessageDigest.getInstance("MD5"); } }\n'
        result = self._attribute(
            {"src/main/java/A.java": app},
            row=_row(**{"class": "okio.ByteString", "method": "digest$okio",
                        "spec": "MessageDigestSpec", "detector_value": "MD5"}),
            spec=spec,
        )
        self.assertEqual(result["status"], "not_applicable")

    def test_a_different_protocol_literal_does_not_match(self):
        kotlin = KOTLIN.replace('"TLSv1", ', "")
        result = self._attribute({"app/src/main/kotlin/Factory.kt": kotlin})
        self.assertEqual(result["status"], "no_application_call")

    def test_test_sources_are_not_searched(self):
        result = self._attribute({"app/src/test/kotlin/Factory.kt": KOTLIN})
        self.assertEqual(result["status"], "no_application_call")

    def test_matches_in_two_declarations_leave_the_finding_where_it_was(self):
        result = self._attribute({
            "app/src/main/kotlin/Factory.kt": KOTLIN,
            "app/src/main/kotlin/Other.kt": KOTLIN.replace("Factory", "Other"),
        })
        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(len(result["call_sites"]), 2)

    def test_without_a_reported_value_nothing_is_attributed(self):
        result = self._attribute(
            {"app/src/main/kotlin/Factory.kt": KOTLIN},
            row=_row(detector_value="", message="unknown"),
        )
        self.assertEqual(result["status"], "not_applicable")

    def test_the_value_falls_back_to_the_message(self):
        result = self._attribute(
            {"app/src/main/kotlin/Factory.kt": KOTLIN},
            row=_row(detector_value="",
                     message="expecting one of TLSv1.2,TLSv1.3 but found TLSv1"),
        )
        self.assertEqual(result["status"], "attributed")


class StatementTests(unittest.TestCase):
    def test_a_literal_in_the_next_statement_is_not_an_argument(self):
        lines = [
            "socket.enabledProtocols = protocols",
            'log("TLSv1")',
        ]
        self.assertNotIn("TLSv1", statement_from(lines, 0))

    def test_an_array_spread_over_lines_is_one_statement(self):
        lines = [
            "s.setEnabledProtocols(new String[] {",
            '    "TLSv1",',
            "});",
            'other("x");',
        ]
        statement = statement_from(lines, 0)
        self.assertIn("TLSv1", statement)
        self.assertNotIn("other", statement)


class DeclaredNameTests(unittest.TestCase):
    def test_kotlin_and_java_declarations(self):
        self.assertEqual(declared_name("private fun withTLS(socket: Socket) = x"), "withTLS")
        self.assertEqual(
            declared_name('@SuppressLint("X")\npublic static void configure(A a) {'),
            "configure",
        )


if __name__ == "__main__":
    unittest.main()
