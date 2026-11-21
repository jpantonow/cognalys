import unittest


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.evidence_facts import byte_material  # noqa: E402
from cognalys.integrations.rvsec import fold_echoes  # noqa: E402


def _materials(body: str, file_source: str = "") -> list:
    return [(use["api"], use["material"]) for use in byte_material(body, file_source)["uses"]]


class ByteMaterialTests(unittest.TestCase):
    """Where the bytes of a key, IV or salt constructor come from."""

    def test_papercripts_inline_zero_iv_is_fixed_and_its_parameter_key_is_not_settled(self):
        body = ("private fun aesCtr(mode: Int, key: ByteArray, data: ByteArray): ByteArray {\n"
                "    val cipher = Cipher.getInstance(\"AES/CTR/NoPadding\")\n"
                "    cipher.init(mode, SecretKeySpec(key, \"AES\"), IvParameterSpec(ByteArray(16)))\n"
                "    return cipher.doFinal(data)\n}")
        self.assertEqual(_materials(body), [("SecretKeySpec", "not_settled"),
                                            ("IvParameterSpec", "fresh_zero_filled")])

    def test_a_declared_array_is_followed_to_what_fills_it(self):
        self.assertEqual(_materials(
            "val iv = ByteArray(16)\nrandom.nextBytes(iv)\nval spec = IvParameterSpec(iv)"),
            [("IvParameterSpec", "written_after_creation")])
        self.assertEqual(_materials(
            "val iv = ByteArray(12).also(random::nextBytes)\nGCMParameterSpec(128, iv)"),
            [("GCMParameterSpec", "filled_by_nextBytes")])
        self.assertEqual(_materials("byte[] iv = new byte[16];\nnew IvParameterSpec(iv);"),
                         [("IvParameterSpec", "fresh_zero_filled")])

    def test_literal_bytes_are_constant_and_a_file_level_constant_is_found(self):
        self.assertEqual(_materials('SecretKeySpec("0123456789abcdef".toByteArray(), "AES")'),
                         [("SecretKeySpec", "constant_literal")])
        self.assertEqual(_materials("new PBEKeySpec(pw, new byte[]{1, 2, 3}, 1000, 256)"),
                         [("PBEKeySpec", "constant_literal")])
        self.assertEqual(_materials("IvParameterSpec(LEGACY_IV)",
                                    "private val LEGACY_IV = ByteArray(IV_LEN)"),
                         [("IvParameterSpec", "fresh_zero_filled")])

    def test_what_the_method_does_not_show_is_not_guessed(self):
        self.assertEqual(_materials("IvParameterSpec(header.copyOfRange(1, 17))"),
                         [("IvParameterSpec", "not_settled")])
        self.assertEqual(byte_material("")["status"], "no_method_body")
        self.assertEqual(byte_material("val x = 1")["status"], "no_byte_material_constructor")


def _finding(spec, label, method="aesCtr", code="X-00"):
    return {"apk": "a.apk", "class": "org.app.Codec", "method": method, "spec": spec,
            "detector_label": label, "detector_code": code, "runs": "2", "message": spec}


class EchoFoldingTests(unittest.TestCase):
    def test_echoes_travel_with_the_findings_they_echo(self):
        findings = [_finding("SecretKeySpecSpec", "not-observed"),
                    _finding("IvParameterSpecSpec", "not-observed"),
                    _finding("IvChainJunctionSpec", "upstream-refused"),
                    _finding("CipherSpec", "upstream-refused")]
        kept, folded = fold_echoes(findings)
        self.assertEqual(folded, 2)
        self.assertEqual([row["spec"] for row in kept], ["SecretKeySpecSpec", "IvParameterSpecSpec"])
        self.assertIn("IvChainJunctionSpec", kept[1]["detector_echoes"])
        self.assertIn("CipherSpec", kept[1]["detector_echoes"])

    def test_an_echo_whose_origin_is_elsewhere_stays_a_finding(self):
        findings = [_finding("SecretKeySpecSpec", "not-observed", method="tag"),
                    _finding("CipherSpec", "upstream-refused", method="aesCtr")]
        kept, folded = fold_echoes(findings)
        self.assertEqual((len(kept), folded), (2, 0))
        self.assertNotIn("detector_echoes", kept[0])


if __name__ == "__main__":
    unittest.main()
