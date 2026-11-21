import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.persisted_objects import persisted_object_formats  # noqa: E402

MASTER_KEY = ("public final class MasterKey {\n"
              "    private final EncryptedKey mEncryptedKey;\n"
              "    private final String mAlgorithm;\n}\n")
ENCRYPTED_KEY = "public final class EncryptedKey {\n    private final byte[] mCipherText;\n}\n"
PERSISTENCE = ("public class TokenPersistence {\n"
               "    boolean provision(String password) {\n"
               "        MasterKey mk = MasterKey.generate(password);\n"
               "        return mBackups.edit().putString(MASTER, new Gson().toJson(mk)).commit();\n"
               "    }\n"
               "    void restore(String s) {\n"
               "        MasterKey mk = new Gson().fromJson(s, MasterKey.class);\n"
               "    }\n}\n")
SETTINGS = "data class Settings(val theme: String) : Parcelable\n"
PLAIN = "public class Encryptor {\n    private KeyStore mKeyStore;\n}\n"


class PersistedObjectTests(unittest.TestCase):
    """FreeOTP v6: a patch re-encrypted the Gson-serialized MasterKey backup
    under a device-bound key, and nothing told the plan or the review that
    MasterKey is a stored format."""

    def formats(self, *paths):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        files = {"app/src/main/java/a/MasterKey.java": MASTER_KEY,
                 "app/src/main/java/a/EncryptedKey.java": ENCRYPTED_KEY,
                 "app/src/main/java/a/TokenPersistence.java": PERSISTENCE,
                 "app/src/main/java/a/Settings.kt": SETTINGS,
                 "app/src/main/java/a/Encryptor.java": PLAIN}
        for relative, text in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text, encoding="utf-8")
        return {item["class"]: item for item in persisted_object_formats(
            root, [f"app/src/main/java/a/{path}" for path in paths])["classes"]}

    def test_a_gson_serialized_class_names_its_write_and_read_sites(self):
        found = self.formats("MasterKey.java")
        lines = [site["line"] for site in found["MasterKey"]["serialized_at"]]
        self.assertEqual(lines, [4, 7])

    def test_a_field_of_a_serialized_class_is_a_stored_format_too(self):
        found = self.formats("EncryptedKey.java")
        self.assertEqual(found["EncryptedKey"]["serialized_as_field_of"], "MasterKey.mEncryptedKey")

    def test_a_declared_parcelable_counts_and_a_plain_class_does_not(self):
        found = self.formats("Settings.kt", "Encryptor.java")
        self.assertTrue(found["Settings"]["declared_serializable"])
        self.assertNotIn("Encryptor", found)

    def test_each_source_file_is_read_once_whatever_the_number_of_classes(self):
        """Amethyst run_v2 (2026-10-29): a regex per declared class over every
        source file kept the llm step busy past the 30-minute stall watch,
        twice, after adjudication; the finding ended unanalysed."""
        from unittest.mock import patch
        import cognalys.extraction.persisted_objects as persisted_objects

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        files = {"app/src/main/java/a/MasterKey.java": MASTER_KEY,
                 "app/src/main/java/a/EncryptedKey.java": ENCRYPTED_KEY,
                 "app/src/main/java/a/TokenPersistence.java": PERSISTENCE}
        for number in range(60):
            files[f"app/src/main/java/a/Screen{number}.kt"] = "".join(
                f"class Screen{number}Part{part}(val title: String)\n" for part in range(10))
        # A reader call whose class literal is on the next line still counts.
        files["app/src/main/java/a/Restore.kt"] = (
            "fun restore(s: String) = gson.fromJson(s, MasterKey\n    ::class.java)\n")
        for relative, text in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text, encoding="utf-8")
        with patch.object(persisted_objects, "_serialization_sites",
                          wraps=persisted_objects._serialization_sites) as scan:
            found = {item["class"]: item for item in persisted_objects.persisted_object_formats(
                root, ["app/src/main/java/a/MasterKey.java"])["classes"]}
        self.assertEqual(scan.call_count, len(files))
        sites = [(site["source_file_path"].rsplit("/", 1)[-1], site["line"])
                 for site in found["MasterKey"]["serialized_at"]]
        self.assertEqual(sorted(sites), [("Restore.kt", 1), ("TokenPersistence.java", 4),
                                         ("TokenPersistence.java", 7)])

    def test_the_files_asked_about_are_read_past_the_checkout_file_cap(self):
        """Amethyst run_v2 (2026-10-29): 9542 Kotlin/Java files, of which the
        6000 read first leave out 3498 production files; a finding in one of
        those had its classes undeclared and came back none_in_these_files."""
        from unittest.mock import patch
        import cognalys.extraction.persisted_objects as persisted_objects

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        files = {"app/src/main/java/a/TokenPersistence.java": PERSISTENCE,
                 "app/src/main/java/a/Settings.kt": SETTINGS,
                 "zz/src/main/java/a/MasterKey.java": MASTER_KEY}
        for relative, text in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text, encoding="utf-8")
        first_two = lambda repo_root: sorted(Path(repo_root).rglob("*.*"))[:2]
        with patch.object(persisted_objects, "_source_files", first_two):
            result = persisted_objects.persisted_object_formats(
                root, ["zz/src/main/java/a/MasterKey.java"])
        found = {item["class"]: item for item in result["classes"]}
        self.assertEqual([site["line"] for site in found["MasterKey"]["serialized_at"]], [4, 7])

    def test_a_class_declared_in_several_source_sets_is_the_one_in_the_file_asked_about(self):
        """Amethyst run_v2 (2026-10-29): SecretEncryption is declared in
        jvmAndroid, jvmMain and androidMain; whichever the walk met first
        stood for the name, and the androidMain actual asked about was left
        out of the list even when the class is serialized."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        files = {"app/src/commonMain/kotlin/a/MasterKey.kt": "expect class MasterKey\n",
                 "app/src/main/java/a/TokenPersistence.java": PERSISTENCE,
                 "app/src/zandroidMain/kotlin/a/MasterKey.android.kt": (
                     "actual class MasterKey(\n    val encryptedKey: EncryptedKey,\n)\n"),
                 "app/src/main/java/a/EncryptedKey.java": ENCRYPTED_KEY}
        for relative, text in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text, encoding="utf-8")
        from unittest.mock import patch
        import cognalys.extraction.persisted_objects as persisted_objects

        # The common declaration is met first whatever the file system's order.
        in_order = lambda repo_root: sorted(Path(repo_root).rglob("*.*"))
        with patch.object(persisted_objects, "_source_files", in_order):
            found = {item["class"]: item for item in persisted_objects.persisted_object_formats(
                root, ["app/src/zandroidMain/kotlin/a/MasterKey.android.kt",
                       "app/src/main/java/a/EncryptedKey.java"])["classes"]}
        self.assertEqual(found["MasterKey"]["declared_in"],
                         "app/src/zandroidMain/kotlin/a/MasterKey.android.kt")
        self.assertEqual(found["EncryptedKey"]["serialized_as_field_of"], "MasterKey.encryptedKey")


if __name__ == "__main__":
    unittest.main()
