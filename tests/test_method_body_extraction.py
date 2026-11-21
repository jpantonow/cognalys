import logging
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "src", ROOT / "src" / "cognalys" / "extraction", ROOT / "src" / "cognalys" / "config"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from cognalys.extraction import extract_methods_single_csv as extraction  # noqa: E402

EXTRACTOR = extraction.MethodExtractor(logging.getLogger("test"))


def extract(source: str, name: str) -> str:
    found = EXTRACTOR.extract_method_flexible(source, name)
    return found[0] if found else ""


class JavaThrowsClauseTests(unittest.TestCase):
    """A throws clause on the lines after the parameters is part of the signature."""

    def test_a_throws_line_before_the_brace_keeps_the_body(self):
        source = (
            "class U {\n"
            "    private static byte[] encode(char[] password, int n)\n"
            "            throws NoSuchAlgorithmException, InvalidKeySpecException {\n"
            "        PBEKeySpec spec = new PBEKeySpec(password, salt, n, 256);\n"
            "        return spec.getPassword().length;\n"
            "    }\n"
            "}\n"
        )
        body = extract(source, "encode")
        self.assertIn("new PBEKeySpec", body)
        self.assertTrue(body.rstrip().endswith("}"))

    def test_a_throws_list_spread_over_lines_keeps_the_body(self):
        source = (
            "class K {\n"
            "    public SecretKey decrypt(SecretKey key)\n"
            "            throws NoSuchPaddingException, BadPaddingException,\n"
            "            IllegalBlockSizeException,\n"
            "            InvalidKeyException {\n"
            "        Cipher cipher = Cipher.getInstance(mCipher);\n"
            "        return null;\n"
            "    }\n"
            "}\n"
        )
        self.assertIn("Cipher.getInstance", extract(source, "decrypt"))

    def test_an_abstract_method_with_throws_is_still_bodyless(self):
        source = (
            "interface S {\n"
            "    byte[] read(String name)\n"
            "            throws IOException;\n"
            "    void next();\n"
            "}\n"
        )
        body = extract(source, "read")
        self.assertIn("throws IOException;", body)
        self.assertNotIn("next", body)


class KotlinExpressionBodyTests(unittest.TestCase):
    """An expression body that starts on the line after `=` belongs to the function."""

    SOURCE = (
        "class A {\n"
        "    private fun calculateChildType(): Int =\n"
        "        runCatching {\n"
        "            with(MessageDigest.getInstance(\"MD5\")) {\n"
        "                update(packageName.toByteArray())\n"
        "                digest().contentHashCode()\n"
        "            }\n"
        "        }.getOrDefault(TYPE1)\n"
        "\n"
        "    private fun type(value: Int): Int = if (value == TYPE1) 1 else 2\n"
        "}\n"
    )

    def test_the_continued_expression_is_extracted(self):
        body = extract(self.SOURCE, "calculateChildType")
        self.assertIn("MessageDigest.getInstance", body)
        self.assertTrue(body.rstrip().endswith(".getOrDefault(TYPE1)"))
        self.assertNotIn("fun type", body)

    def test_a_one_line_expression_body_stops_at_its_sibling(self):
        source = (
            "class A {\n"
            "    fun a(): Int = 1\n"
            "    fun b(): Int = 2\n"
            "}\n"
        )
        self.assertEqual(extract(source, "a").strip(), "fun a(): Int = 1")

    def test_a_chained_call_on_deeper_lines_is_included(self):
        source = (
            "class A {\n"
            "    fun names(items: List<Item>) = items\n"
            "        .filter { it.enabled }\n"
            "        .map { it.name }\n"
            "    fun other() = 0\n"
            "}\n"
        )
        body = extract(source, "names")
        self.assertIn(".map { it.name }", body)
        self.assertNotIn("other", body)

    def test_a_parenthesis_inside_a_string_does_not_extend_the_body(self):
        source = (
            "class A {\n"
            "    fun label() = \"open (\"\n"
            "    fun other() = 0\n"
            "}\n"
        )
        self.assertNotIn("other", extract(source, "label"))


if __name__ == "__main__":
    unittest.main()


class ReportedOverloadTests(unittest.TestCase):
    """The overload that holds the detector's line is the one analysed."""

    SOURCE = (
        "class Helper {\n"                                          # 1
        "    static String getFingerprint(Context context) {\n"     # 2
        "        return getFingerprint(context, \"SHA1\");\n"       # 3
        "    }\n"                                                   # 4
        "\n"                                                        # 5
        "    static String getFingerprint(Context context, String hash) {\n"  # 6
        "        MessageDigest digest = MessageDigest.getInstance(hash);\n"  # 7
        "        return hex(digest.digest(cert(context)));\n"       # 8
        "    }\n"                                                   # 9
        "}\n"
    )

    def run_case(self, location: str):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Helper.java"
            path.write_text(self.SOURCE, encoding="utf-8")
            return extraction.reported_overload(
                EXTRACTOR, self.SOURCE, path,
                {"detector_source_location": location}, "getFingerprint",
            )

    def test_the_reported_line_selects_the_second_overload(self):
        extracted, line = self.run_case("Helper.java:7")
        self.assertEqual(line, 7)
        self.assertIn("MessageDigest.getInstance(hash)", extracted[0])

    def test_a_line_in_another_file_selects_nothing(self):
        self.assertEqual(self.run_case("Other.java:7"), (None, None))

    def test_without_a_reported_line_the_first_declaration_stays(self):
        self.assertEqual(self.run_case(""), (None, None))
        self.assertIn('"SHA1"', extract(self.SOURCE, "getFingerprint"))


class StaticInitializerTests(unittest.TestCase):
    """<clinit> maps to static blocks, static fields and companion/object initialisers."""

    ALLMAN = (
        "class NetworkClient\n"
        "{\n"
        "\tstatic String UA = \"Mozilla\";\n"
        "\tprivate static TrustManager[] trustAllCerts;\n"
        "\tstatic\n"
        "\t{\n"
        "\t\ttry\n"
        "\t\t{\n"
        "\t\t\tSSLContext sslContext = SSLContext.getInstance(\"TLS\");\n"
        "\t\t} catch(Exception e) {}\n"
        "\t}\n"
        "\n"
        "\tstatic void generate()\n"
        "\t{\n"
        "\t\tint a = 1;\n"
        "\t}\n"
        "}\n"
    )

    def test_an_allman_static_block_is_found(self):
        body, start, end = EXTRACTOR.extract_static_initializer(self.ALLMAN, "SSLContext")
        self.assertIn("SSLContext.getInstance", body)
        self.assertEqual((start, end), (5, 11))
        self.assertNotIn("generate", body)

    def test_the_reported_line_selects_the_field_initialiser(self):
        body, start, end = EXTRACTOR.extract_static_initializer(self.ALLMAN, "SSLContext", 3)
        self.assertEqual((body.strip(), start, end), ('static String UA = "Mozilla";', 3, 3))

    def test_the_initialiser_naming_the_api_is_preferred(self):
        source = (
            "class C {\n"
            "    static {\n"
            "        LOG = 1;\n"
            "    }\n"
            "    private static final MessageDigest MD =\n"
            "            MessageDigest.getInstance(\"MD5\");\n"
            "}\n"
        )
        body, start, end = EXTRACTOR.extract_static_initializer(source, "MessageDigest")
        self.assertEqual((start, end), (5, 6))
        self.assertIn("MD5", body)
        body, start, _ = EXTRACTOR.extract_static_initializer(source, "Cipher")
        self.assertEqual(start, 2)

    def test_kotlin_companion_init_and_property(self):
        source = (
            "class Utils {\n"
            "    init {\n"
            "        println()\n"
            "    }\n"
            "    companion object {\n"
            "        private val ctx: SSLContext = SSLContext.getInstance(\"TLS\")\n"
            "            .also { it.init(null, null, null) }\n"
            "        init {\n"
            "            setup()\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        body, start, end = EXTRACTOR.extract_static_initializer(source, "SSLContext")
        self.assertEqual((start, end), (6, 7))
        body, start, end = EXTRACTOR.extract_static_initializer(source, "Cipher")
        self.assertEqual((start, end), (8, 10))
        self.assertIn("setup()", body)

    def test_kotlin_file_level_property(self):
        source = (
            "package a\n"
            "\n"
            "val client by lazy {\n"
            "    SSLContext.getInstance(\"TLS\")\n"
            "}\n"
            "fun f() {\n"
            "    val x = 1\n"
            "}\n"
        )
        body, start, end = EXTRACTOR.extract_static_initializer(source, "SSLContext")
        self.assertEqual((start, end), (3, 5))

    def test_a_class_without_static_initialisation_gives_none(self):
        source = "class A {\n    void f() {\n        int x = 1;\n    }\n}\n"
        self.assertIsNone(EXTRACTOR.extract_static_initializer(source, "Cipher"))
