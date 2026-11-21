import unittest


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.prs.pr_generator import PrGenerator  # noqa: E402
from cognalys.utils import pr_text  # noqa: E402

# The AI Hub draft of 2026-10-12, as the pipeline wrote it before review.
AIHUB_DRAFT = (
    "The primary service-WebView construction path and the onCreateWindow "
    "dummy-WebView path assign the governed WebSettings value "
    "MIXED_CONTENT_ALWAYS_ALLOW (C-001, C-002). Do not rely on the unresolved "
    "request-policy helper."
)
# The text published as SilentCoderHere/aihub#279.
AIHUB_PUBLISHED = (
    "## Summary\n\nBoth WebViews the app creates set `mixedContentMode = "
    "MIXED_CONTENT_ALWAYS_ALLOW`. That lets an HTTPS page load scripts over "
    "plain HTTP, which anyone on the same network can read or replace.\n\n"
    "## How was this tested?\n\nThe project builds (`assembleDebug`)."
)


class TextProblemTests(unittest.TestCase):
    def test_the_draft_that_was_rewritten_by_hand_is_flagged(self):
        problems = pr_text.text_problems("Fix updateWebViewSettings", AIHUB_DRAFT)
        self.assertTrue(any("generic title" in item for item in problems))
        self.assertTrue(any("evidence ids" in item for item in problems))
        self.assertTrue(any("governed" in item for item in problems))

    def test_the_published_text_passes(self):
        self.assertEqual(pr_text.text_problems(
            "Disallow mixed content in the service and popup WebViews", AIHUB_PUBLISHED), [])

    def test_single_letter_evidence_ids_are_stripped(self):
        self.assertEqual(pr_text.strip_evidence_citations("assign it (C-001, C-002)."),
                         "assign it.")
        # Not an id: a short single-letter label, a digest name.
        self.assertEqual(pr_text.strip_evidence_citations("step (X-1) with (SHA1)"),
                         "step (X-1) with (SHA1)")

    def test_a_mixed_id_list_is_stripped(self):
        """Tempus's issue: short and hyphenated ids in one parenthesis."""
        self.assertEqual(pr_text.strip_evidence_citations(
            "the reported mismatch (C1; SRC-001, WEB-005)."), "the reported mismatch.")
        for kept in ("keys (AES-256, SHA1)", "level (API 21)", "a key (AES-256)"):
            self.assertEqual(pr_text.strip_evidence_citations(kept), kept)

    def test_a_kotlin_internal_or_default_suffix_leaves_the_name(self):
        """Input Leaf's draft named discoverySslContext$app."""
        self.assertEqual(pr_text.short_symbol(
            "com.inputleaf.android.network.ServerScanner$Companion", "discoverySslContext$app"),
            "ServerScanner.discoverySslContext")
        self.assertEqual(pr_text.kotlin_member_name("connect$default"), "connect")
        for kept in ("access$000", "lambda$onCreate$1", "plain"):
            self.assertEqual(pr_text.kotlin_member_name(kept), kept)

    def test_the_analyzers_vocabulary_is_flagged(self):
        """Z-Sync's issue named the detector's algorithm list and the runs that observed MD5."""
        body = ("DiskKey passes MD5, outside the detector's accepted SHA-2 algorithm list; "
                "MD5 was also observed in two runs.")
        problems = pr_text.text_problems("Question about the MD5 use in diskKey", body)
        self.assertTrue(any(item.startswith("pipeline vocabulary") and "in two runs" in item
                            for item in problems))

    def test_a_long_summary_is_flagged(self):
        body = "## Summary\n\n" + "word " * 300 + "\n\n## How was this tested?\n\nok"
        self.assertTrue(any("summary of" in item
                            for item in pr_text.text_problems("Restrict X to HTTPS", body)))


# Salty's run_v2 draft (2026-10-29): new messages carry a "v1:" prefix the
# old reader never wrote; the old layout still decodes.
SALTY_EDITS = [{
    "source_file": "app/src/main/java/com/vauth/salty/utils/HashUtils.kt",
    "original_code": (
        "    fun decode(encodedMessage: String, salt: String): String {\n"
        "            val combined = Base64.decode(encodedMessage, Base64.NO_WRAP)\n"
        "            return decrypt(combined, deriveKey(salt))\n"
        "    }"),
    "corrected_code": (
        "    private const val FORMAT_V1 = \"v1:\"\n\n"
        "    fun encodeV1(message: String, salt: String): String =\n"
        "        FORMAT_V1 + Base64.encodeToString(encrypt(message, salt), Base64.NO_WRAP)\n\n"
        "    fun decode(encodedMessage: String, salt: String): String {\n"
        "        val trimmed = encodedMessage.trim()\n"
        "        if (trimmed.startsWith(FORMAT_V1)) return decodeV1(trimmed, salt)\n"
        "            val combined = Base64.decode(encodedMessage, Base64.NO_WRAP)\n"
        "            return decrypt(combined, deriveKey(salt))\n"
        "    }"),
}]

# Salty's run_v3 draft (2026-10-29), trimmed: the marker is joined into a
# listOf(...) and old messages go through a function the patch declares.
SALTY_V3_ORIGINAL = (
    "    fun encode(message: String, salt: String): String {\n"
    "        try {\n"
    "            val key = deriveKey(salt)\n"
    "            val iv = ByteArray(GCM_IV_LENGTH)\n"
    "            val cipher = Cipher.getInstance(ALGORITHM)\n"
    "            val encryptedBytes = cipher.doFinal(message.toByteArray(StandardCharsets.UTF_8))\n"
    "            return Base64.encodeToString(iv + encryptedBytes, Base64.NO_WRAP)\n"
    "        } catch (e: Exception) {\n"
    "            throw EncodingException(\"Failed to encode message: ${e.message}\", e)\n"
    "        }\n"
    "    }\n\n"
    "    fun decode(encodedMessage: String, salt: String): String {\n"
    "        try {\n"
    "            val combined = Base64.decode(encodedMessage, Base64.NO_WRAP)\n"
    "            val iv = combined.copyOfRange(0, GCM_IV_LENGTH)\n"
    "            val encryptedBytes = combined.copyOfRange(GCM_IV_LENGTH, combined.size)\n"
    "            val cipher = Cipher.getInstance(ALGORITHM)\n"
    "            cipher.init(Cipher.DECRYPT_MODE, deriveKey(salt), GCMParameterSpec(128, iv))\n"
    "            return String(cipher.doFinal(encryptedBytes), StandardCharsets.UTF_8)\n"
    "        } catch (e: Exception) {\n"
    "            throw DecodingException(\"Failed to decode message: ${e.message}\", e)\n"
    "        }\n"
    "    }\n")
SALTY_V3_LEGACY_BODY = (
    "        val combined = Base64.decode(encodedMessage, Base64.NO_WRAP)\n"
    "        val iv = combined.copyOfRange(0, GCM_IV_LENGTH)\n"
    "        val encryptedBytes = combined.copyOfRange(GCM_IV_LENGTH, combined.size)\n"
    "        return decrypt(encryptedBytes, deriveLegacyKey(userSalt), iv)\n")
SALTY_V3_CORRECTED = (
    "    private const val CURRENT_ENVELOPE_PREFIX = \"salty:\"\n"
    "    private const val CURRENT_ENVELOPE_VERSION = \"1\"\n\n"
    "    fun encode(message: String, salt: String): String {\n"
    "        try {\n"
    "            val iv = ByteArray(GCM_IV_LENGTH)\n"
    "            val cipher = Cipher.getInstance(ALGORITHM)\n"
    "            val encryptedBytes = cipher.doFinal(message.toByteArray(StandardCharsets.UTF_8))\n"
    "            return listOf(\n"
    "                CURRENT_ENVELOPE_PREFIX.dropLast(1),\n"
    "                CURRENT_ENVELOPE_VERSION,\n"
    "                Base64.encodeToString(iv, Base64.NO_WRAP),\n"
    "                Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)\n"
    "            ).joinToString(\":\")\n"
    "        } catch (e: Exception) {\n"
    "            throw EncodingException(\"Failed to encode message: ${e.message}\", e)\n"
    "        }\n"
    "    }\n\n"
    "    fun decode(encodedMessage: String, salt: String): String {\n"
    "        try {\n"
    "            return if (encodedMessage.startsWith(CURRENT_ENVELOPE_PREFIX)) {\n"
    "                decodeCurrentEnvelope(encodedMessage, salt)\n"
    "            } else {\n"
    "                decodeLegacyEnvelope(encodedMessage, salt)\n"
    "            }\n"
    "        } catch (e: Exception) {\n"
    "            throw DecodingException(\"Failed to decode message: ${e.message}\", e)\n"
    "        }\n"
    "    }\n\n"
    "    private fun decodeCurrentEnvelope(encodedMessage: String, userSalt: String): String {\n"
    "        val parts = encodedMessage.split(':')\n"
    "        if (parts.size != 4 || parts[0] != CURRENT_ENVELOPE_PREFIX.dropLast(1)) {\n"
    "            throw DecodingException(\"Malformed or unsupported current encoded message\")\n"
    "        }\n"
    "        val iv = Base64.decode(parts[2], Base64.NO_WRAP)\n"
    "        return decrypt(Base64.decode(parts[3], Base64.NO_WRAP), deriveCurrentKey(userSalt), iv)\n"
    "    }\n\n"
    "    private fun decodeLegacyEnvelope(encodedMessage: String, userSalt: String): String {\n"
    + SALTY_V3_LEGACY_BODY +
    "    }\n\n"
    "    private fun decrypt(encryptedBytes: ByteArray, key: SecretKeySpec, iv: ByteArray): String {\n"
    "        val cipher = Cipher.getInstance(ALGORITHM)\n"
    "        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))\n"
    "        return String(cipher.doFinal(encryptedBytes), StandardCharsets.UTF_8)\n"
    "    }\n\n"
    "    fun isValidEncodedMessage(encodedMessage: String): Boolean = try {\n"
    "        if (encodedMessage.startsWith(CURRENT_ENVELOPE_PREFIX)) true\n"
    "        else Base64.decode(encodedMessage, Base64.NO_WRAP).size > GCM_IV_LENGTH\n"
    "    } catch (e: Exception) {\n"
    "        false\n"
    "    }\n")
SALTY_V3_EDITS = [{
    "source_file_path": "app/src/main/java/com/vauth/salty/utils/HashUtils.kt",
    "symbol": "HashUtils declaration",
    "original_code": SALTY_V3_ORIGINAL,
    "corrected_code": SALTY_V3_CORRECTED,
}]


class NewWrittenFormatTests(unittest.TestCase):
    """A patch that writes a format earlier versions cannot read must say so."""

    def test_a_prefixed_format_with_the_old_reader_kept_is_a_new_written_format(self):
        self.assertTrue(pr_text.new_written_format(SALTY_EDITS))

    def test_an_algorithm_string_only_diff_writes_no_new_format(self):
        self.assertFalse(pr_text.new_written_format([{
            "source_file_path": "app/src/main/java/x/Hash.kt",
            "original_code": "val digest = MessageDigest.getInstance(\"SHA-1\")",
            "corrected_code": "val digest = MessageDigest.getInstance(\"SHA-256\")"}]))
        self.assertFalse(pr_text.new_written_format([]))

    def test_the_text_must_carry_the_earlier_versions_sentence(self):
        body = ("`encode` now derives each message key from a random salt stored "
                "with the message.\n\nI found this while running the app under RVSec.")
        problems = pr_text.text_problems("Use a random salt for new messages", body,
                                         new_written_format=True)
        self.assertTrue(any("earlier versions" in item for item in problems))
        stated = body.replace(
            "with the message.",
            "with the message. Messages written by this version are not readable by "
            "earlier versions of the app; messages from earlier versions still decode.")
        self.assertEqual(pr_text.text_problems("Use a random salt for new messages", stated,
                                               new_written_format=True), [])
        self.assertEqual(pr_text.text_problems("Use a random salt for new messages", body), [])

    def test_a_kept_shared_line_is_no_reader_of_the_old_layout(self):
        # The corrected decode rejects unmarked data; only the shared
        # `Cipher.getInstance(...)` line is unchanged.
        edits = [{
            "source_file_path": "app/src/main/java/x/Codec.kt",
            "original_code": (
                "    fun decode(text: String): String {\n"
                "        val cipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\")\n"
                "        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(FIXED_IV))\n"
                "        return String(cipher.doFinal(Base64.decode(text, 0)))\n"
                "    }"),
            "corrected_code": (
                "    fun encode(text: String): String = \"v1:\" + seal(text)\n\n"
                "    fun decode(text: String): String {\n"
                "        require(text.startsWith(\"v1:\")) { \"unsupported format\" }\n"
                "        val cipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\")\n"
                "        val raw = Base64.decode(text.removePrefix(\"v1:\"), 0)\n"
                "        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(raw.copyOf(16)))\n"
                "        return String(cipher.doFinal(raw.copyOfRange(16, raw.size)))\n"
                "    }"),
        }]
        self.assertTrue(pr_text.new_written_format(edits))
        self.assertFalse(pr_text.earlier_data_still_reads(edits))
        claim = ("Messages written by this version are not readable by earlier versions "
                 "of the app; messages from earlier versions still decode.")
        problems = pr_text.text_problems("Use a random IV for new messages", claim,
                                         new_written_format=True,
                                         earlier_data_still_reads=False)
        self.assertTrue(any("keeps no reader" in item for item in problems), problems)
        honest = "Messages written by this version are not readable by earlier versions."
        self.assertEqual(pr_text.text_problems("Use a random IV for new messages", honest,
                                               new_written_format=True,
                                               earlier_data_still_reads=False), [])

    def test_the_else_branch_decides_whether_the_old_layout_reads(self):
        def edits(otherwise):
            return [{
                "source_file_path": "app/src/main/java/x/Codec.kt",
                "original_code": "        return decrypt(Base64.decode(text, 0), legacyKey())",
                "corrected_code": (
                    "    fun encode(text: String) = \"v1:\" + seal(text)\n"
                    "    fun decode(text: String): String {\n"
                    "        if (text.startsWith(\"v1:\")) {\n"
                    "            return open(text.removePrefix(\"v1:\"))\n"
                    "        } else {\n" + otherwise + "\n        }\n    }"),
            }]
        kept = edits("        return decrypt(Base64.decode(text, 0), legacyKey())")
        dropped = edits("            throw IllegalArgumentException(\"old format\")")
        self.assertTrue(pr_text.earlier_data_still_reads(kept))
        self.assertTrue(pr_text.new_written_format(dropped))
        self.assertFalse(pr_text.earlier_data_still_reads(dropped))

    def test_salty_keeps_its_reader_for_the_old_layout(self):
        self.assertTrue(pr_text.earlier_data_still_reads(SALTY_EDITS))

    def test_test_edits_never_set_the_fact(self):
        # The merge-time filter: a test that writes and branches on a new
        # prefix is not the app writing a new format.
        unchanged = [dict(SALTY_EDITS[0], corrected_code=SALTY_EDITS[0]["original_code"])]
        in_test_source = dict(SALTY_EDITS[0],
                              source_file="shared/src/commonTest/kotlin/x/HashUtilsTest.kt")
        marked_test = dict(SALTY_EDITS[0], edit_kind="test")
        for name, extra in (("test source set", in_test_source), ("edit_kind test", marked_test)):
            with self.subTest(name):
                self.assertFalse(pr_text.new_written_format([*unchanged, extra]))

    def test_salty_v3_joins_its_marker_and_delegates_the_old_layout(self):
        # run_v3 (2026-10-29): the marker went into listOf(...).joinToString
        # and the unmarked branch called decodeLegacyEnvelope; both facts
        # came out false and the text left the earlier-versions sentence out.
        self.assertTrue(pr_text.new_written_format(SALTY_V3_EDITS))
        self.assertTrue(pr_text.earlier_data_still_reads(SALTY_V3_EDITS))

    def test_a_marker_only_read_is_no_written_format(self):
        # The code accepts a prefixed value and checks its parts, but never
        # produces one: nothing it writes is new.
        corrected = SALTY_V3_CORRECTED.replace(
            "            return listOf(\n"
            "                CURRENT_ENVELOPE_PREFIX.dropLast(1),\n"
            "                CURRENT_ENVELOPE_VERSION,\n"
            "                Base64.encodeToString(iv, Base64.NO_WRAP),\n"
            "                Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)\n"
            "            ).joinToString(\":\")\n",
            "            return Base64.encodeToString(iv + encryptedBytes, Base64.NO_WRAP)\n")
        self.assertNotEqual(corrected, SALTY_V3_CORRECTED)
        edits = [dict(SALTY_V3_EDITS[0], corrected_code=corrected)]
        self.assertFalse(pr_text.new_written_format(edits))
        # Only a test writes it: still not the app writing a new format.
        test_writer = {
            "source_file_path": "app/src/test/java/com/vauth/salty/utils/HashUtilsTest.kt",
            "original_code": "",
            "corrected_code": "        val message = CURRENT_ENVELOPE_PREFIX + \"1:abc\"\n"}
        self.assertFalse(pr_text.new_written_format([*edits, test_writer]))

    def test_a_delegated_reader_that_throws_reads_nothing(self):
        corrected = SALTY_V3_CORRECTED.replace(
            SALTY_V3_LEGACY_BODY,
            "        throw DecodingException(\"Unsupported legacy message\")\n")
        self.assertNotEqual(corrected, SALTY_V3_CORRECTED)
        edits = [dict(SALTY_V3_EDITS[0], corrected_code=corrected)]
        self.assertTrue(pr_text.new_written_format(edits))
        self.assertFalse(pr_text.earlier_data_still_reads(edits))

    def test_a_helper_both_paths_share_is_no_reader(self):
        # The unmarked branch calls only the shared decrypt, whose kept lines
        # the marked path runs too.
        corrected = SALTY_V3_CORRECTED.replace(
            "decodeLegacyEnvelope(encodedMessage, salt)",
            "decrypt(Base64.decode(encodedMessage, Base64.NO_WRAP), deriveKey(salt))")
        edits = [dict(SALTY_V3_EDITS[0], corrected_code=corrected)]
        self.assertTrue(pr_text.new_written_format(edits))
        self.assertFalse(pr_text.earlier_data_still_reads(edits))

    def test_a_require_on_the_marker_leaves_no_reader(self):
        corrected = SALTY_V3_CORRECTED.replace(
            "            return if (encodedMessage.startsWith(CURRENT_ENVELOPE_PREFIX)) {\n"
            "                decodeCurrentEnvelope(encodedMessage, salt)\n"
            "            } else {\n"
            "                decodeLegacyEnvelope(encodedMessage, salt)\n"
            "            }\n",
            "            require(encodedMessage.startsWith(CURRENT_ENVELOPE_PREFIX))\n"
            "            return decodeCurrentEnvelope(encodedMessage, salt)\n")
        self.assertNotEqual(corrected, SALTY_V3_CORRECTED)
        edits = [dict(SALTY_V3_EDITS[0], corrected_code=corrected)]
        self.assertTrue(pr_text.new_written_format(edits))
        self.assertFalse(pr_text.earlier_data_still_reads(edits))

    def _salty_v3(self, *replacements, corrected=SALTY_V3_CORRECTED):
        for old, new in replacements:
            self.assertIn(old, corrected)
            corrected = corrected.replace(old, new, 1)
        return [dict(SALTY_V3_EDITS[0], corrected_code=corrected)]

    def test_a_marker_transformed_inside_the_write_is_still_written(self):
        # The marker as the receiver of a transform derives the value the
        # encoder writes; it tests no input.
        for transform in ('removeSuffix(":")', 'substringBefore(":")', "trimEnd(':')"):
            with self.subTest(transform):
                edits = self._salty_v3(("CURRENT_ENVELOPE_PREFIX.dropLast(1),\n",
                                        f"CURRENT_ENVELOPE_PREFIX.{transform},\n"))
                self.assertTrue(pr_text.new_written_format(edits))
                self.assertTrue(pr_text.earlier_data_still_reads(edits))

    def test_a_validator_declared_before_decode_does_not_hide_the_reader(self):
        # The branch judged is decode's, the function the original declared,
        # not the isValidEncodedMessage the patch added above it.
        validator = SALTY_V3_CORRECTED.index("    fun isValidEncodedMessage")
        decode = SALTY_V3_CORRECTED.index("    fun decode(")
        reordered = (SALTY_V3_CORRECTED[:decode] + SALTY_V3_CORRECTED[validator:] + "\n"
                     + SALTY_V3_CORRECTED[decode:validator])
        edits = [dict(SALTY_V3_EDITS[0], corrected_code=reordered)]
        self.assertTrue(pr_text.new_written_format(edits))
        self.assertTrue(pr_text.earlier_data_still_reads(edits))

    def test_a_one_line_if_else_delegates_to_the_legacy_reader(self):
        edits = self._salty_v3((
            "            return if (encodedMessage.startsWith(CURRENT_ENVELOPE_PREFIX)) {\n"
            "                decodeCurrentEnvelope(encodedMessage, salt)\n"
            "            } else {\n"
            "                decodeLegacyEnvelope(encodedMessage, salt)\n"
            "            }\n",
            "            return if (encodedMessage.startsWith(CURRENT_ENVELOPE_PREFIX)) "
            "decodeCurrentEnvelope(encodedMessage, salt) "
            "else decodeLegacyEnvelope(encodedMessage, salt)\n"))
        self.assertTrue(pr_text.new_written_format(edits))
        self.assertTrue(pr_text.earlier_data_still_reads(edits))

    def test_a_marker_only_named_stripped_or_handed_on_writes_nothing(self):
        # The read-only variant: messages carry the prefix but the encoder
        # never writes it. Naming it in an error or log, stripping it, or
        # passing it to a helper of its own builds no data.
        read_only = self._salty_v3((
            "            return listOf(\n"
            "                CURRENT_ENVELOPE_PREFIX.dropLast(1),\n"
            "                CURRENT_ENVELOPE_VERSION,\n"
            "                Base64.encodeToString(iv, Base64.NO_WRAP),\n"
            "                Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)\n"
            "            ).joinToString(\":\")\n",
            "            return Base64.encodeToString(iv + encryptedBytes, Base64.NO_WRAP)\n"))
        self.assertFalse(pr_text.new_written_format(read_only))
        split = "        val parts = encodedMessage.split(':')\n"
        for name, replacement in (
                ("exception message", "        if (encodedMessage.length < 8) throw DecodingException(\n"
                                      "            \"Malformed message, expected \" + CURRENT_ENVELOPE_PREFIX)\n"
                                      + split),
                ("replace", "        val parts = encodedMessage.replace(CURRENT_ENVELOPE_PREFIX, \"\")"
                            ".split(':')\n"),
                ("log argument", "        Log.d(TAG, CURRENT_ENVELOPE_PREFIX)\n" + split),
                ("log template", "        Log.w(TAG, \"unexpected $CURRENT_ENVELOPE_PREFIX message\")\n"
                                 + split),
                ("lazy require message", "        require(encodedMessage.length > 8) "
                                         "{ \"expected ${CURRENT_ENVELOPE_PREFIX}...\" }\n" + split),
                ("helper argument", "        val parts = strip(encodedMessage, CURRENT_ENVELOPE_PREFIX)"
                                    ".split(':')\n")):
            with self.subTest(name):
                edits = self._salty_v3((split, replacement),
                                       corrected=read_only[0]["corrected_code"])
                self.assertFalse(pr_text.new_written_format(edits))

    def test_a_constant_two_edits_declare_is_one_format(self):
        other = {
            "source_file_path": "app/src/main/java/com/vauth/salty/utils/Envelope.kt",
            "original_code": "",
            "corrected_code": (
                "    private const val CURRENT_ENVELOPE_PREFIX = \"salty:\"\n"
                "    fun isCurrent(text: String) = text.startsWith(CURRENT_ENVELOPE_PREFIX)\n")}
        self.assertEqual(pr_text._written_formats([*SALTY_V3_EDITS, other]), [True])
        # Declared again but written nowhere: still no format.
        unwritten = dict(other, source_file_path="app/src/main/java/x/A.kt",
                         corrected_code=other["corrected_code"]
                         + "    fun first(text: String) = text.startsWith(CURRENT_ENVELOPE_PREFIX)\n")
        self.assertEqual(pr_text._written_formats([unwritten, other]), [])

    def test_a_protocol_requested_and_filtered_writes_no_format(self):
        # A new short literal passed to an API and matched with startsWith is
        # no tagged format: nothing is serialized.
        for name, original, corrected in (
                ("kotlin", "        val context = SSLContext.getInstance(\"SSL\")\n",
                 "        val context = SSLContext.getInstance(\"TLSv1.2\")\n"
                 "        socket.enabledProtocols = socket.supportedProtocols\n"
                 "            .filter { it.startsWith(\"TLSv1.2\") || it.startsWith(\"TLSv1.3\") }\n"
                 "            .toTypedArray()\n"),
                ("java", "        SSLContext context = SSLContext.getInstance(\"SSL\");\n",
                 "        SSLContext context = SSLContext.getInstance(\"TLSv1.3\");\n"
                 "        for (String protocol : socket.getSupportedProtocols()) {\n"
                 "            if (protocol.startsWith(\"TLSv1.3\")) keep.add(protocol);\n"
                 "        }\n")):
            with self.subTest(name):
                self.assertFalse(pr_text.new_written_format([{
                    "source_file_path": "app/src/main/java/x/Tls.kt",
                    "original_code": original, "corrected_code": corrected}]))

    def test_a_delegate_that_copies_only_the_error_handling_reads_nothing(self):
        # The original try/catch kept around a body that rejects old data:
        # `} catch (...)` and the rethrow are no reader.
        edits = self._salty_v3((
            SALTY_V3_LEGACY_BODY,
            "        try {\n"
            "            error(\"legacy messages are no longer supported\")\n"
            "        } catch (e: Exception) {\n"
            "            throw DecodingException(\"Failed to decode message: ${e.message}\", e)\n"
            "        }\n"))
        self.assertTrue(pr_text.new_written_format(edits))
        self.assertFalse(pr_text.earlier_data_still_reads(edits))

    def test_a_kept_value_under_a_renamed_local_is_a_reader(self):
        # BitBanana's legacy verifier (2026-10-19): the old derivation kept
        # under a new local name in a function only the unmarked path calls.
        edits = [{
            "source_file_path": "app/src/main/java/x/AppLockUtil.java",
            "original_code": (
                "    private static byte[] encodePbkdf2(char[] password, byte[] salt) throws Exception {\n"
                "        SecretKeyFactory skf = SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA1\");\n"
                "        return skf.generateSecret(new PBEKeySpec(password, salt, 1000, 256)).getEncoded();\n"
                "    }"),
            "corrected_code": (
                "    private static final String PREFIX = \"lock-v2:\";\n"
                "    public static String hash(String data) {\n"
                "        return PREFIX + currentHash(data);\n"
                "    }\n"
                "    public static boolean verify(String data, String stored) {\n"
                "        if (stored.startsWith(PREFIX)) {\n"
                "            return stored.equals(hash(data));\n"
                "        }\n"
                "        return stored.equals(legacyHash(data));\n"
                "    }\n"
                "    private static String legacyHash(String data) {\n"
                "        try {\n"
                "            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA1\");\n"
                "            return encode(keyFactory.generateSecret(spec(data)).getEncoded());\n"
                "        } catch (Exception e) {\n"
                "            throw new IllegalStateException(e);\n"
                "        }\n"
                "    }"),
        }]
        self.assertTrue(pr_text.new_written_format(edits))
        self.assertTrue(pr_text.earlier_data_still_reads(edits))
        rejecting = [dict(edits[0], corrected_code=edits[0]["corrected_code"].replace(
            "SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA1\");",
            "SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA256\");"))]
        self.assertFalse(pr_text.earlier_data_still_reads(rejecting))

    def test_the_pr_step_reads_the_fact_from_the_final_edits(self):
        generator = object.__new__(PrGenerator)
        body = "`encode` now writes a prefixed message."
        problems = generator.text_problems_of(
            {"coordinated_edits": SALTY_EDITS}, "Use a random salt for new messages", body,
            "\n".join(["diff --git a/x b/x", "+FORMAT_V1"]))
        self.assertTrue(any("earlier versions" in item for item in problems))


class TitleMarkerTests(unittest.TestCase):
    def test_the_summary_carries_its_title_to_the_pr_step(self):
        text = pr_text.with_title_marker("Disallow mixed content in the WebViews", "Both WebViews...")
        self.assertEqual(pr_text.split_title_marker(text),
                         ("Disallow mixed content in the WebViews", "Both WebViews..."))

    def test_the_proposed_title_wins_over_the_method_name(self):
        explanation = pr_text.with_title_marker("Disallow mixed content in the WebViews", "x")
        self.assertEqual(PrGenerator.descriptive_title(
            {"explanation": explanation, "method_name": "onCreateWindow"}, "Fix: onCreateWindow"),
            "Disallow mixed content in the WebViews")

    def test_a_generic_proposed_title_is_not_used(self):
        explanation = pr_text.with_title_marker("Fix onCreateWindow", "x")
        self.assertEqual(PrGenerator.descriptive_title(
            {"explanation": explanation, "method_name": "onCreateWindow"}, "Fix: onCreateWindow"),
            "Fix: onCreateWindow")

    def test_text_without_a_marker_is_unchanged(self):
        self.assertEqual(pr_text.split_title_marker("plain"), ("", "plain"))




# whoBIRD's Downloader (2026-10-18): the digests moved from MD5 to SHA-256
# and the constants kept their MD5 names.
WHOBIRD_MESSAGE = "expecting one of SHA-256,SHA-384,SHA-512,SHA256,SHA384,SHA512 but found MD5"
WHOBIRD_EDITS = [{
    "original_code": 'static final String model16MD5 = "b1c9";\n'
                     'byte[] hash = MessageDigest.getInstance("MD5").digest(data);\n'
                     'calcModelMD5 = new BigInteger(1, hash).toString(16);',
    "corrected_code": 'static final String model16MD5 = "5c64";\n'
                      'byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);\n'
                      'calcModelMD5 = new BigInteger(1, hash).toString(16);',
}]

# Fread's buildSSLFactory draft (tls_20261015): "SSL" became "TLS", a
# socket-factory wrapper was created, and the test spelled every protocol.
FREAD_MESSAGE = "expecting one of TLSV1.2,TLSV1.3,TLS but found SSL"
FREAD_EDITS = [
    {"source_file_path": "framework/src/androidMain/kotlin/c/GlobalOkHttpClient.kt",
     "edit_kind": "method",
     "original_code": ('@SuppressLint("CustomX509TrustManager")\n'
                       "fun buildSSLFactory(): SSLSocketFactory {\n"
                       '    val sslContext = SSLContext.getInstance("SSL")\n'
                       '    sslContext.defaultSSLParameters.protocols = arrayOf("SSLv3")\n'
                       "    return sslContext.socketFactory\n}"),
     "corrected_code": ('@SuppressLint("CustomX509TrustManager")\n'
                        "fun buildSSLFactory(): SSLSocketFactory {\n"
                        '    val sslContext = SSLContext.getInstance("TLS")\n'
                        "    return ProtocolFilteringSSLSocketFactory(sslContext.socketFactory)\n}")},
    {"source_file_path": "framework/src/androidMain/kotlin/c/ProtocolFilteringSSLSocketFactory.kt",
     "edit_kind": "create", "original_code": "",
     "corrected_code": ("class ProtocolFilteringSSLSocketFactory(d: SSLSocketFactory) {\n"
                        "    fun f(s: SSLSocket): SSLSocket { throw SSLException(\"x\") }\n}")},
    {"source_file_path": "framework/src/androidUnitTest/kotlin/c/FilterTest.kt",
     "edit_kind": "test", "original_code": "",
     "corrected_code": 'val p = arrayOf("SSLv3", "TLSv1.2"); val s: SSLSession? = null'},
]


class StaleValueNameTests(unittest.TestCase):
    def test_names_that_still_say_the_replaced_value_are_explained(self):
        note = pr_text.stale_value_names_note(WHOBIRD_MESSAGE, WHOBIRD_EDITS)
        self.assertIn("`model16MD5`, `calcModelMD5` still say MD5", note)
        self.assertIn("now hold SHA-256 values", note)
        self.assertLessEqual(len(note.split()), 25)

    def test_nothing_is_said_when_the_rejected_value_is_still_used(self):
        edits = [{"original_code": WHOBIRD_EDITS[0]["original_code"],
                  "corrected_code": WHOBIRD_EDITS[0]["original_code"]}]
        self.assertEqual(pr_text.stale_value_names_note(WHOBIRD_MESSAGE, edits), "")

    def test_nothing_is_said_when_names_were_renamed(self):
        edits = [{"original_code": WHOBIRD_EDITS[0]["original_code"],
                  "corrected_code": 'String modelSha = MessageDigest.getInstance("SHA-256");'}]
        self.assertEqual(pr_text.stale_value_names_note(WHOBIRD_MESSAGE, edits), "")

    def test_fread_lists_no_name(self):
        """Fread (tls_20261015) listed SuppressLint, SSLSocket and a created class."""
        self.assertEqual(pr_text.stale_value_names_note(FREAD_MESSAGE, FREAD_EDITS), "")
        self.assertEqual(pr_text.stale_value_names(FREAD_MESSAGE, FREAD_EDITS), ([], ""))

    def test_a_token_inside_a_word_is_not_a_name(self):
        edits = [{"source_file_path": "app/src/main/java/A.kt",
                  "original_code": '@SuppressLint("x")\nval suppressLint = 1\n'
                                   'val description = "d"\nval key = Cipher.getInstance("DES")',
                  "corrected_code": '@SuppressLint("x")\nval suppressLint = 1\n'
                                    'val description = "d"\nval key = Cipher.getInstance("AES")'}]
        self.assertEqual(pr_text.stale_value_names(
            "expecting one of AES but found DES", edits)[0], [])
        self.assertEqual(pr_text.stale_value_names(
            "expecting one of TLSv1.2 but found SSL",
            [{"original_code": 'val suppressLint = 1\nval c = getInstance("SSL")',
              "corrected_code": 'val suppressLint = 1\nval c = getInstance("TLS")'}])[0], [])

    def test_the_replacement_is_the_literal_that_replaced_the_value(self):
        edits = [{"source_file_path": "app/src/main/java/c/Client.kt",
                  "original_code": 'val sslHolder = SSLContext.getInstance("SSL")',
                  "corrected_code": 'val sslHolder = SSLContext.getInstance("TLS")'},
                 {"source_file_path": "app/src/test/java/c/ClientTest.kt", "edit_kind": "test",
                  "original_code": "", "corrected_code": 'assertEquals("TLSv1.2", protocol)'}]
        message = "expecting one of TLSV1.2,TLSV1.3,TLS but found SSL"
        self.assertEqual(pr_text.replacement_literal(message, edits), "TLS")
        # SSLContext is a type the code uses: "ssl" still names it.
        self.assertEqual(pr_text.stale_value_names(message, edits)[0], [])
        plain = [{"original_code": 'val sslHolder = Factory.create("SSL")',
                  "corrected_code": 'val sslHolder = Factory.create("TLS")'}]
        self.assertEqual(pr_text.stale_value_names(message, plain), (["sslHolder"], "TLS"))

    def test_an_ambiguous_replacement_says_no_longer(self):
        edits = [{"original_code": 'a = digest("MD5")\nb = digest("MD5")',
                  "corrected_code": 'a = digest("SHA-256")\nb = digest("SHA-512")\nval md5Name = 1'},
                 {"original_code": "val md5Name = 0", "corrected_code": "val md5Name = 1"}]
        note = pr_text.stale_value_names_note(WHOBIRD_MESSAGE, edits)
        self.assertIn("`md5Name` still say MD5 but they no longer hold MD5 values", note)

    def test_the_paragraph_check_flags_created_names_and_platform_types(self):
        body = ("Summary.\n\nThe names `buildSSLFactory`, `SSLSocket`, "
                "`ProtocolFilteringSSLSocketFactory` still say SSL but they now hold "
                "TLSv1.2 values; I kept them to keep the diff small.")
        problems = pr_text.stale_names_paragraph_problems(body, FREAD_EDITS)
        self.assertEqual(len(problems), 2)
        self.assertTrue(any("`SSLSocket`" in item and "platform type" in item for item in problems))
        self.assertTrue(any("`ProtocolFilteringSSLSocketFactory`" in item and "created" in item
                            for item in problems))
        whobird_body = pr_text.stale_value_names_note(WHOBIRD_MESSAGE, WHOBIRD_EDITS)
        self.assertEqual(pr_text.stale_names_paragraph_problems(whobird_body, WHOBIRD_EDITS), [])



class SourceNameTests(unittest.TestCase):
    """2026-10-31 audit: SMSecure #89 "Affects `ConversationListAdapter.<init>`"
    and NotallyX #1167 "`IOExtensionsKt.md5Hash`" reached maintainers."""

    def test_bytecode_names_map_to_source_names(self):
        cases = {
            ("org.smsecure.ConversationListAdapter", "<init>"):
                ("ConversationListAdapter", "", "constructor"),
            ("a.b.Config", "<clinit>"): ("Config", "", "static initializer"),
            ("com.notallyx.utils.IOExtensionsKt", "md5Hash"): ("", "md5Hash", "function"),
            ("a.Outer$Inner", "run"): ("Outer.Inner", "run", "method"),
            ("a.Repo$Companion", "key"): ("Repo", "key", "method"),
            ("a.Screen$1", "invokeSuspend"): ("Screen", "invokeSuspend", "method"),
            ("a.Vault", "getKey-Abc1234"): ("Vault", "getKey", "method"),
            ("a.Main", "lambda$downloadModels$4"): ("Main", "downloadModels", "method"),
        }
        for (owner, member), expected in cases.items():
            with self.subTest(owner=owner, member=member):
                self.assertEqual(pr_text.source_names(owner, member), expected)

    def test_the_location_phrase_reads_as_a_maintainer_writes_it(self):
        self.assertEqual(pr_text.symbol_phrase("x.ConversationListAdapter", "<init>"),
                         "the `ConversationListAdapter` constructor")
        self.assertEqual(pr_text.symbol_phrase("x.IOExtensionsKt", "md5Hash"), "`md5Hash`")
        self.assertEqual(pr_text.symbol_phrase("x.Cipher", "encrypt"), "`Cipher.encrypt`")
        self.assertEqual(pr_text.short_symbol("x.IOExtensionsKt", "md5Hash"), "md5Hash")

    def test_bytecode_names_in_the_text_ask_for_a_rewrite(self):
        for text in ("Affects `ConversationListAdapter.<init>`.", "`IOExtensionsKt.md5Hash` hashed",
                     "In `KeyGenType$1` the key", "`getKey-Abc1234` returns"):
            with self.subTest(text=text):
                self.assertTrue(pr_text.bytecode_name_problems("Use SHA-256", text))
        for text in ("The `ConversationListAdapter` constructor", "`md5Hash` hashed",
                     "> the observed call in <init> is refused", "in `build-logic`",
                     "the `use-sha256` flag"):
            with self.subTest(text=text):
                self.assertEqual(pr_text.bytecode_name_problems("Use SHA-256", text), [])


class RuleVocabularyTests(unittest.TestCase):
    """network-survey #154 was closed with "It only satisfies the CrySL rule";
    48 of 52 drafts of 2026-10-24..31 named the finding's spec id."""

    def test_the_spec_id_and_rule_vocabulary_ask_for_a_rewrite(self):
        problems = pr_text.text_problems(
            "Use compliant PBKDF2 for master-secret derivation",
            "This violates the `PBEKeySpecSpec` usage rule, and the `SecretKeyFactorySpec` "
            "allow-list excludes the algorithm.",
            specs=["PBEKeySpecSpec", "SecretKeyFactorySpec"])
        rule_id = next(item for item in problems if "internal rule id" in item)
        self.assertIn("`PBEKeySpecSpec`", rule_id)
        self.assertIn("`SecretKeyFactorySpec`", rule_id)
        vocabulary = next(item for item in problems if item.startswith("rule vocabulary"))
        for word in ("'usage rule'", "'allow-list'", "'compliant'"):
            self.assertIn(word, vocabulary)

    def test_the_api_name_a_quoted_message_and_a_named_class_pass(self):
        body = ("`MessageDigest.getInstance(\"MD5\")` names the cache files. RVSec reports MD5 "
                "for MessageDigest; this change uses SHA-256.\n\n"
                "> the observed call sequence is not one MessageDigestSpec accepts")
        self.assertEqual(pr_text.rule_vocabulary_problems(
            "Name cache files with SHA-256", body, ["MessageDigestSpec"]), [])
        # A spec named after the class the diff edits is the class's name.
        self.assertEqual(pr_text.rule_vocabulary_problems(
            "t", "The `KeyVault` now loads once.", ["KeyVault"],
            code="+ class KeyVault {"), [])

    def test_the_specs_of_a_finding_include_its_joint_findings(self):
        self.assertEqual(pr_text.finding_specs({
            "spec": "KeyPairSpec",
            "joint_findings": [{"specification": "KeyStoreSpec"}, {"spec": "KeyPairSpec"}]}),
            ["KeyPairSpec", "KeyStoreSpec"])

    def test_the_found_with_sentence_passes(self):
        from cognalys.utils.finding_source import tool_and_spec_context

        sentence = tool_and_spec_context("ape:sata", "MessageDigestSpec")
        self.assertEqual(pr_text.rule_vocabulary_problems(
            "t", sentence, ["MessageDigestSpec"]), [])


class BatchFourteenReviewTests(unittest.TestCase):
    """Review of batch 14 (2026-10-31)."""

    def test_a_spec_id_that_is_the_class_it_governs_is_the_java_api(self):
        self.assertEqual(pr_text.rule_vocabulary_problems(
            "Use a random salt",
            "The `PBEKeySpec` now gets a random 16-byte salt instead of the fixed one.",
            ["PBEKeySpec"], "-    byte[] salt = SALT;\n+    byte[] salt = randomSalt();"), [])
        self.assertTrue(pr_text.rule_vocabulary_problems(
            "t", "This violates the `PBEKeySpecSpec` rule.", ["PBEKeySpecSpec"]))

    def test_ordinary_compliant_and_allowlist_are_not_rule_vocabulary(self):
        self.assertEqual(pr_text.rule_vocabulary_problems(
            "t", "The handshake is now RFC 6455-compliant.", ["MessageDigestSpec"]), [])
        self.assertEqual(pr_text.rule_vocabulary_problems(
            "t", "Hosts outside the app's pinning allowlist now fail the handshake.",
            [], "+ if (!allowList.contains(host))"), [])
        self.assertTrue(pr_text.rule_vocabulary_problems(
            "t", "RVSec flagged the algorithm as outside the rule's allow-list.", []))
        self.assertTrue(pr_text.rule_vocabulary_problems(
            "t", "It satisfies the usage rule.", []))

    def test_a_kotlin_lambda_class_reads_as_its_enclosing_function(self):
        self.assertEqual(pr_text.source_names("a.b.MainActivity$onCreate$1", "invokeSuspend"),
                         ("MainActivity", "onCreate", "method"))
        self.assertEqual(pr_text.source_names("a.b.UtilsKt$hash$1", "invokeSuspend"),
                         ("", "hash", "function"))
        self.assertEqual(pr_text.short_symbol("a.b.Outer$Inner", "run"), "Outer.Inner.run")


class CopiedReviewNoteTests(unittest.TestCase):
    """Your Local Weather (2026-11-02): the review's question to the
    maintainer reached the body word for word."""

    NOTE = ("For the maintainer to decide: Confirm every reader or external contract for "
            "KEY_PREF_WEATHER_INITIAL_TOKEN accepts values newly derived with "
            "PBKDF2WithHmacSHA256 and 100000 iterations, or approve and define a "
            "reader-supported compatibility/migration strategy before publishing this "
            "direct writer replacement.")

    def test_a_sentence_copied_from_a_review_note_is_flagged(self):
        body = ("I changed `encryptKey` to use `PBKDF2WithHmacSHA256`.\n\n"
                "This change makes the choice to confirm every reader or external contract "
                "for `KEY_PREF_WEATHER_INITIAL_TOKEN` accepts values newly derived with "
                "PBKDF2WithHmacSHA256 and 100000 iterations, rather than define a "
                "reader-supported compatibility/migration strategy.\n\n"
                "I found this while running the app under RVSec.")
        problems = pr_text.review_text_problems(body, [self.NOTE])
        self.assertEqual(len(problems), 1)
        self.assertIn("copied from the review", problems[0])
        self.assertIn("This change makes the choice", problems[0])

    def test_a_sentence_in_the_summarys_own_words_is_not(self):
        body = ("`encryptKey` hashes the licence key with PBKDF2WithHmacSHA1; it now uses "
                "PBKDF2WithHmacSHA256. The stored hash is written once and read nowhere "
                "else in the app, so earlier values need no migration.")
        self.assertEqual(pr_text.review_text_problems(body, [self.NOTE]), [])
        self.assertEqual(pr_text.review_text_problems("anything at all here", []), [])

    def test_the_fixed_closing_text_is_not_read(self):
        body = "Short.\n\nI'm a Computer Engineering student " + self.NOTE
        self.assertEqual(pr_text.review_text_problems(body, [self.NOTE]), [])


# Weewx Weather (2026-11-04): the review recorded the effect, the body had to
# state it, and the sentence stating it was held as copied from that note.
WEEWX_EFFECT = ("HTTPS endpoints using self-signed certificates, private roots not trusted by "
                "the platform, or mismatched hostnames will no longer connect.")
WEEWX_NOTES = [
    WEEWX_EFFECT,
    "Verify on representative Android devices and endpoints that factory-provided trust and "
    "hostname verification work for valid connections and reject invalid peers.",
    "Valid and invalid endpoints still need testing on representative Android devices.",
]
WEEWX_BODY = (
    "The `NetworkClient` static initializer gives `SSLContext.init` a manager that accepts "
    "every certificate.\n\n"
    "I use the platform factory's trust manager and restore hostname verification.\n\n"
    "{effect}\n\n"
    "I found this while running the app under RVSec.")


class RecordedEffectWordingTests(unittest.TestCase):
    def setUp(self):
        self.effects = pr_text.user_visible_effects(WEEWX_NOTES[:1])
        self.assertEqual(self.effects, [WEEWX_EFFECT])

    def problems(self, effect_sentence):
        body = WEEWX_BODY.format(effect=effect_sentence)
        return (pr_text.missing_effect_problems(body, self.effects),
                pr_text.review_text_problems(body, WEEWX_NOTES, self.effects))

    def test_the_effect_restated_in_the_summarys_own_structure_passes_both(self):
        # The sentence that held the draft: the fact's nouns, its own order.
        missing, copied = self.problems(
            "Users can no longer connect to HTTPS endpoints with self-signed certificates, "
            "untrusted private roots, or mismatched hostnames.")
        self.assertEqual((missing, copied), ([], []))
        # Without the effects, the term share alone still calls it copied.
        body = WEEWX_BODY.format(
            effect="Users can no longer connect to HTTPS endpoints with self-signed "
                   "certificates, untrusted private roots, or mismatched hostnames.")
        self.assertEqual(len(pr_text.review_text_problems(body, WEEWX_NOTES)), 1)

    def test_the_effect_copied_near_verbatim_is_asked_to_be_restated(self):
        missing, copied = self.problems(
            "HTTPS endpoints that use self-signed certificates, private roots not trusted by "
            "the platform, or mismatched hostnames will no longer connect.")
        self.assertEqual(missing, [])
        self.assertEqual(len(copied), 1)
        self.assertIn("review's own wording", copied[0])
        self.assertIn("keep the effect, but restate it", copied[0])
        self.assertNotIn("say what the change does", copied[0])

    def test_a_note_that_is_no_effect_is_still_flagged_when_copied(self):
        missing, copied = self.problems(
            "Users can no longer connect to HTTPS endpoints with self-signed certificates, "
            "untrusted private roots, or mismatched hostnames. Valid and invalid endpoints "
            "still need testing on representative Android devices.")
        self.assertEqual(missing, [])
        self.assertEqual(len(copied), 1)
        self.assertIn("copied from the review", copied[0])
        self.assertIn("still need testing", copied[0])
        self.assertNotIn("Users can no longer", copied[0])

    def test_the_two_checks_never_ask_for_contradictory_text(self):
        """Leaving the effect out fails one check; any sentence stating it
        that does not reproduce a note's word order passes both, so the
        rewrite always has a text to reach."""
        missing, copied = self.problems("")
        self.assertEqual(len(missing), 1)
        self.assertIn("do not copy the note's wording", missing[0])
        self.assertEqual(copied, [])
        for sentence in (
                "Connections to servers with a self-signed or privately rooted certificate, "
                "or one issued for another host, are now refused.",
                "After this change users cannot connect to servers whose certificates are "
                "self-signed, signed by a private root, or issued for a different hostname."):
            self.assertEqual(self.problems(sentence), ([], []), sentence)


# primftpd's draft (2026-11-03): the reason RC4 is a problem and the effect
# on arcfour-only clients were in the evidence and the review, not the body.
PRIMFTPD_MESSAGE = "expecting one of AES,HMACSHA256 but found ARCFOUR"
PRIMFTPD_EVIDENCE = {
    "confirmed_facts": [
        "ARCFOUR is a standard Java secret-key algorithm name for RC4, although it is "
        "outside the supplied rule's algorithm list.",
        "RFC 8758 prohibits Arcfour and RC4 in SSH, including the RFC 4345 variants.",
    ],
    "external_sources": [{"supported_claim": "Arcfour and RC4 must not be used in SSH."}],
}
PRIMFTPD_BODY = (
    "Today, `BaseRC4Cipher.init` creates an `ARCFOUR` `SecretKeySpec`. RVSec reports "
    "that `ARCFOUR` is not an accepted `SecretKeySpec` algorithm.\n\n"
    "I remove the ARCFOUR factories from the default cipher candidates.\n\n"
    "I found this while running the app under RVSec.")
PRIMFTPD_NOTES = [
    "Direct RC4 callers will now fail, and peers requiring only ARCFOUR will no longer "
    "be able to negotiate a connection.",
    "For the maintainer to decide: the new code no longer uses mode.",
]


class WhyTheChangeMattersTests(unittest.TestCase):
    def test_the_evidence_reason_for_the_reported_value_is_found(self):
        reasons = pr_text.value_problem_reasons(PRIMFTPD_EVIDENCE, PRIMFTPD_MESSAGE)
        self.assertEqual(reasons, [PRIMFTPD_EVIDENCE["confirmed_facts"][1],
                                   "Arcfour and RC4 must not be used in SSH."])
        # Naming the standard that defines a value is no reason either.
        self.assertEqual(pr_text.value_problem_reasons(
            {"confirmed_facts": ["RFC 1321 specifies the MD5 message-digest algorithm."]},
            "expecting one of SHA-256 but found MD5"), [])
        # A statement about the rule's list is no reason, and a message
        # naming no value has none.
        self.assertEqual(pr_text.value_problem_reasons(
            {"confirmed_facts": PRIMFTPD_EVIDENCE["confirmed_facts"][:1]}, PRIMFTPD_MESSAGE), [])
        self.assertEqual(pr_text.value_problem_reasons(PRIMFTPD_EVIDENCE, "Unexpected call"), [])

    def test_a_body_justified_only_by_the_rule_is_flagged(self):
        reasons = pr_text.value_problem_reasons(PRIMFTPD_EVIDENCE, PRIMFTPD_MESSAGE)
        problems = pr_text.rule_only_justification_problems(PRIMFTPD_BODY, reasons)
        self.assertEqual(len(problems), 1)
        self.assertIn("RFC 8758", problems[0])
        fixed = PRIMFTPD_BODY.replace(
            "RVSec reports that `ARCFOUR` is not an accepted `SecretKeySpec` algorithm.",
            "RC4 is broken, and RFC 8758 says it must not be used in SSH.")
        self.assertEqual(pr_text.rule_only_justification_problems(fixed, reasons), [])
        # Without a reason in the evidence the rule is all there is to say.
        self.assertEqual(pr_text.rule_only_justification_problems(PRIMFTPD_BODY, []), [])

    def test_a_recorded_effect_on_peers_must_be_stated(self):
        effects = pr_text.user_visible_effects(PRIMFTPD_NOTES)
        self.assertEqual(effects, [PRIMFTPD_NOTES[0]])
        problems = pr_text.missing_effect_problems(PRIMFTPD_BODY, effects)
        self.assertEqual(len(problems), 1)
        self.assertIn("no longer", problems[0])
        stated = PRIMFTPD_BODY.replace(
            "candidates.", "candidates, so SSH clients that only offer arcfour can no "
            "longer connect.")
        self.assertEqual(pr_text.missing_effect_problems(stated, effects), [])
        # What a check cannot show is no effect a user notices (SMSecure,
        # Fread and Trigger drafts, 2026-11-03).
        self.assertEqual(pr_text.user_visible_effects([
            "The build and source recheck cannot establish actual device socket "
            "behavior for servers."]), [])
        # A note about the code alone records no user-visible effect.
        self.assertEqual(pr_text.user_visible_effects(["Direct RC4 callers will now fail."]), [])

    def test_a_request_to_the_reviewer_records_no_effect(self):
        # Input Leaf run_v5 and RedReader run_v4 (2026-11-09) were held for
        # not stating a request to the reviewer and a maintainer note.
        input_leaf = (
            "Verify on supported Android devices that trusted discovery peers work, untrusted "
            "certificates are rejected, and the existing plaintext fallback does not undermine "
            "the intended trust change. The pipeline does not exercise device handshakes.")
        for text in (
                input_leaf,
                WEEWX_NOTES[1],
                "On supported Android devices, verify trusted-peer discovery, rejection of "
                "untrusted certificates, and discovery failure and plaintext-fallback behavior.",
                "For the maintainer to decide: the new code no longer uses user (the account "
                "name) when connecting."):
            with self.subTest(text[:40]):
                self.assertEqual(pr_text.user_visible_effects([text]), [])
        self.assertEqual(pr_text.user_visible_effects(WEEWX_NOTES), [WEEWX_EFFECT])
        self.assertEqual(pr_text.user_visible_effects([
            "Verify X on devices. Peers with self-signed certificates will no longer connect."]),
            ["Peers with self-signed certificates will no longer connect."])
        # The copied-text check reads the same with or without the request.
        body = WEEWX_BODY.format(effect=WEEWX_EFFECT)
        effects = pr_text.user_visible_effects(WEEWX_NOTES)
        self.assertEqual(
            pr_text.review_text_problems(body, WEEWX_NOTES, effects),
            pr_text.review_text_problems(
                body, [note for note in WEEWX_NOTES if note != WEEWX_NOTES[1]], effects))

    def test_the_maintainer_note_is_the_reviews_prefix(self):
        from cognalys.llm import coordinated_generation

        self.assertIsNotNone(pr_text._MAINTAINER_NOTE.match(
            coordinated_generation.MAINTAINER_DECISION_PREFIX + " x"))

    def test_the_summary_prompt_carries_the_reason_and_the_effects(self):
        from types import SimpleNamespace
        from cognalys.llm.finding_adjudication import FindingAdjudication

        seen = {}

        class Provider:
            def generate(self, prompt, system, **kwargs):
                seen["prompt"] = prompt
                return '{"title": "Remove RC4 from the default ciphers", "summary": "Text."}'

        holder = SimpleNamespace(provider=Provider(), logger=None)
        error = {"error_message": PRIMFTPD_MESSAGE, "tool": "rvsec",
                 "csv_class": "a.BaseRC4Cipher", "method_name": "init",
                 "evidence_analysis": PRIMFTPD_EVIDENCE}
        FindingAdjudication.compose_maintainer_summary(holder, error, [], [], PRIMFTPD_NOTES)
        self.assertIn("RFC 8758 prohibits Arcfour", seen["prompt"])
        self.assertIn("will no longer be able to negotiate", seen["prompt"])
        self.assertIn("why_the_value_is_a_problem", seen["prompt"])
        # The effects are facts to restate, not text to copy (Weewx Weather,
        # 2026-11-04).
        prompt = " ".join(seen["prompt"].split())
        self.assertIn("facts the review recorded, not text to reuse", prompt)
        self.assertIn("a sentence that reproduces a review note is rejected", prompt)


if __name__ == "__main__":
    unittest.main()
