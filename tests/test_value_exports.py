"""Where a reported method's value leaves the app, and what the app is for.

Salty (2026-10-29, run_v2): HashUtils.encode's ciphertext reaches the
clipboard through SaltyViewModel and a Compose state variable, to be shared
with a recipient; no adjudication, plan or review request mentioned it.
"""
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.repository_guidance import (  # noqa: E402
    app_purpose,
    discover_repository_guidance,
)
from cognalys.extraction.value_exports import value_exports  # noqa: E402

HASH_UTILS = """package x.utils

object HashUtils {
    fun encode(message: String, salt: String): String {
        val key = deriveKey(salt)
        cipher.init(Cipher.ENCRYPT_MODE, key, spec)
        return Base64.encodeToString(cipher.doFinal(message.toByteArray()), Base64.NO_WRAP)
    }

    private fun deriveKey(salt: String): SecretKeySpec = SecretKeySpec(bytes(salt), "AES")
}
"""
VIEW_MODEL = """package x

class SaltyViewModel(private val repository: MessageRepository) : ViewModel() {
    fun encodeMessage(message: String, salt: String): OperationResult {
        return try {
            val encoded = HashUtils.encode(message, salt)
            viewModelScope.launch {
                val entry = MessageEntry(
                    originalMessage = message,
                    encodedMessage = encoded,
                )
                repository.insertMessage(entry)
            }
            OperationResult.Success(encoded)
        } catch (e: Exception) {
            OperationResult.Error("failed")
        }
    }
}
"""
MAIN_ACTIVITY = """package x

@Composable
fun EncodeTab(vm: SaltyViewModel) {
    var message by remember { mutableStateOf("") }
    var salt by remember { mutableStateOf("") }
    var encodedResult by remember { mutableStateOf("") }
    val clipboardManager = LocalClipboardManager.current
    OutlinedTextField(
        value = message,
        onValueChange = { message = it },
        label = { Text("Message to Encode *") },
    )
    OutlinedTextField(
        value = salt,
        onValueChange = { salt = it },
        label = { Text("Key *") },
    )
    Button(
        onClick = {
            val result = vm.encodeMessage(
                message = message,
                salt = salt,
            )
            when (result) {
                is OperationResult.Success -> {
                    encodedResult = result.result
                }
                is OperationResult.Error -> {
                    encodedResult = ""
                }
            }
        }
    ) { Text("Encode") }
    Button(onClick = { clipboardManager.setText(AnnotatedString(encodedResult)) }) { Text("Copy") }
}

@Composable
fun DecodeTab(vm: SaltyViewModel) {
    var decodedResult by remember { mutableStateOf("") }
    val clipboardManager = LocalClipboardManager.current
    Button(onClick = {
        val result = vm.decodeMessage("m", "s")
        decodedResult = result.result
        clipboardManager.setText(AnnotatedString(decodedResult))
    }) { Text("Decode") }
}
"""
ROOM_ONLY_VIEW_MODEL = """package x

class NotesViewModel(private val dao: NoteDao) : ViewModel() {
    fun save(text: String) {
        val sealed = HashUtils.encode(text, "k")
        viewModelScope.launch { dao.insertNote(Note(body = sealed)) }
    }
}
"""


def write(root: Path, files: dict) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


class ValueExportTests(unittest.TestCase):
    def test_the_encoded_value_is_followed_to_the_clipboard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, {"app/src/main/java/x/utils/HashUtils.kt": HASH_UTILS,
                         "app/src/main/java/x/SaltyViewModel.kt": VIEW_MODEL,
                         "app/src/main/java/x/MainActivity.kt": MAIN_ACTIVITY})
            exports = value_exports(root, "app/src/main/java/x/utils/HashUtils.kt",
                                    "x.utils.HashUtils", ["encode", "deriveKey"])
        self.assertEqual(exports["status"], "collected")
        self.assertTrue(exports["leaves_the_app"])
        clipboard = [item for item in exports["sinks"] if item["kind"] == "clipboard"]
        self.assertEqual([(item["source_file_path"], item["code"]) for item in clipboard],
                         [("app/src/main/java/x/MainActivity.kt",
                           "Button(onClick = { clipboardManager.setText(AnnotatedString(encodedResult)) }) "
                           "{ Text(\"Copy\") }")])
        self.assertEqual(clipboard[0]["via"], ["app/src/main/java/x/SaltyViewModel.kt:6",
                                               "app/src/main/java/x/MainActivity.kt:21"])
        # The decode tab's clipboard holds another value.
        self.assertFalse(any("decodedResult" in item["code"] for item in exports["sinks"]))
        self.assertIn({"argument": "salt", "label": "Key *",
                       "source_file_path": "app/src/main/java/x/MainActivity.kt", "line": 15},
                      exports["input_labels"])
        self.assertTrue(any(item["kind"] == "database" for item in exports["sinks"]))

    def test_a_room_only_result_has_one_dao_sink_and_none_outside_the_app(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, {"app/src/main/java/x/utils/HashUtils.kt": HASH_UTILS,
                         "app/src/main/java/x/NotesViewModel.kt": ROOM_ONLY_VIEW_MODEL})
            exports = value_exports(root, "app/src/main/java/x/utils/HashUtils.kt",
                                    "x.utils.HashUtils", ["encode"])
        self.assertEqual([item["kind"] for item in exports["sinks"]], ["database"])
        self.assertFalse(exports["leaves_the_app"])

    def test_a_kotlin_top_level_function_is_followed_through_its_import(self):
        """NotallyX's md5Hash: callers import the function, never its FileKt class."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write(root, {
                "app/src/main/java/x/utils/IOExtensions.kt":
                    "package x.utils\n\nfun md5Hash(bytes: ByteArray): String = digest(bytes)\n",
                "app/src/main/java/x/export/Exporter.kt": (
                    "package x.export\n\nimport x.utils.md5Hash\n\n"
                    "class Exporter(private val out: OutputStream) {\n"
                    "    fun export(data: ByteArray) {\n"
                    "        val checksum = md5Hash(data)\n"
                    "        out.write(checksum.toByteArray())\n"
                    "    }\n}\n"),
            })
            exports = value_exports(root, "app/src/main/java/x/utils/IOExtensions.kt",
                                    "x.utils.IOExtensionsKt", ["md5Hash"])
        self.assertEqual([(item["kind"], item["source_file_path"]) for item in exports["sinks"]],
                         [("file_or_stream", "app/src/main/java/x/export/Exporter.kt")])

    def test_no_checkout_says_nothing(self):
        self.assertEqual(value_exports("", "a.kt", "x.A", ["encode"])["status"],
                         "not_applicable")
        self.assertEqual(value_exports(Path("/nonexistent/checkout"), "a.kt", "x.A",
                                       ["encode"])["status"], "not_applicable")


README = """# Salty App

![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Exchange sensitive information securely by encrypting messages with a shared "Salt" (Key).**

<br>

## Key Features
- AES-256

## Contributing
Open a pull request against main.
"""


class AppPurposeTests(unittest.TestCase):
    def test_the_text_under_the_first_heading_without_badges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(README, encoding="utf-8")
            purpose = app_purpose(root)
            guidance = discover_repository_guidance(root)
        self.assertEqual(purpose, "Exchange sensitive information securely by encrypting "
                                  "messages with a shared \"Salt\" (Key).")
        self.assertTrue(any("Open a pull request against main." in item["content"]
                            for item in guidance))

    def test_a_readme_without_a_title_gives_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("Just text.\n", encoding="utf-8")
            self.assertEqual(app_purpose(root), "")
            self.assertEqual(app_purpose(root / "missing"), "")


if __name__ == "__main__":
    unittest.main()
