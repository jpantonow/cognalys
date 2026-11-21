import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.evidence_facts import parameter_producers  # noqa: E402

ENCRYPTED_KEY = (
    "public class EncryptedKey {\n"
    "    public static EncryptedKey encrypt(SecretKey key, SecretKey plaintext) throws Exception {\n"
    "        if (key == null) {\n            throw new InvalidKeyException(\"Key is null\");\n        }\n"
    "        Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
    "        cipher.init(Cipher.ENCRYPT_MODE, key);\n"
    "        return new EncryptedKey(cipher, plaintext);\n    }\n}\n")
ENCRYPTOR = (
    "public class Encryptor {\n"
    "    public Encryptor() { mKeyStore = KeyStore.getInstance(\"AndroidKeyStore\"); }\n"
    "    public void encryptToken(SecretKey key) throws Exception {\n"
    "        Key mk = null;\n        mk = mKeyStore.getKey(MASTER, null);\n"
    "        EncryptedKey ekc = EncryptedKey.encrypt((SecretKey) mk, key);\n    }\n}\n")
MASTER_KEY = (
    "public class MasterKey {\n"
    "    private static SecretKeyFactory getSecretKeyFactory() throws Exception {\n"
    "        return SecretKeyFactory.getInstance(\"PBKDF2withHmacSHA512\");\n    }\n"
    "    private MasterKey(PBEKeySpec spec) throws Exception {\n"
    "        SecretKeyFactory skf = getSecretKeyFactory();\n"
    "        SecretKey pwd = skf.generateSecret(spec);\n"
    "        SecretKey key = new SecretKeySpec(raw, \"AES\");\n"
    "        mEncryptedKey = EncryptedKey.encrypt(pwd, key);\n    }\n}\n")


class ParameterProducerTests(unittest.TestCase):
    """FreeOTP#521: EncryptedKey.encrypt only forwards its key to Cipher.init;
    the adjudicator blocked for want of the callers' key origins, and the
    pipeline then shipped a test instead of a fix."""

    def producers(self, **files):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for name, text in files.items():
            (root / f"src/main/java/{name}.java").parent.mkdir(parents=True, exist_ok=True)
            (root / f"src/main/java/{name}.java").write_text(text, encoding="utf-8")
        body = ENCRYPTED_KEY[ENCRYPTED_KEY.index("    public static"):]
        return parameter_producers(root, body, "encrypt")

    def test_each_caller_names_where_its_key_was_made(self):
        found = self.producers(EncryptedKey=ENCRYPTED_KEY, Encryptor=ENCRYPTOR, MasterKey=MASTER_KEY)
        key = next(item for item in found["parameters"] if item["parameter"] == "key")
        self.assertEqual(key["passed_to"], ["cipher.init(Cipher.ENCRYPT_MODE, key);"])
        sites = {site["source_file_path"].rsplit("/", 1)[-1]: site for site in key["call_sites"]}
        self.assertEqual(sites["Encryptor.java"]["argument"], "mk")
        self.assertEqual(sites["Encryptor.java"]["producers"][0]["produced_by"],
                         "mKeyStore.getKey(MASTER, null)")
        master = sites["MasterKey.java"]["producers"]
        self.assertEqual(master[0]["produced_by"], "skf.generateSecret(spec)")
        self.assertEqual(master[1]["which_returns"],
                         ["SecretKeyFactory.getInstance(\"PBKDF2withHmacSHA512\")"])
        # The key was made for PBKDF2 and is used with an AES Cipher.
        self.assertEqual(sites["MasterKey.java"]["key_algorithms"], ["PBKDF2withHmacSHA512"])
        self.assertEqual(found["used_with"], ["AES/GCM/NoPadding"])
        plaintext = next(item for item in found["parameters"] if item["parameter"] == "plaintext")
        spec_site = next(site for site in plaintext["call_sites"]
                         if site["source_file_path"].endswith("MasterKey.java"))
        self.assertEqual(spec_site["key_algorithms"], ["AES"])

    def test_a_value_it_cannot_follow_is_not_settled(self):
        caller = "class C {\n    void f(SecretKey given) {\n        EncryptedKey.encrypt(given, given);\n    }\n}\n"
        found = self.producers(EncryptedKey=ENCRYPTED_KEY, C=caller)
        key = next(item for item in found["parameters"] if item["parameter"] == "key")
        self.assertEqual(key["call_sites"][0]["status"], "not_settled")

    def test_a_kotlin_primary_constructor_lists_what_each_caller_passes(self):
        # Amethyst MacInstance(algorithm, key): the key bytes enter the
        # wrapper through its primary constructor, which was not_applicable.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        files = {
            "quartz/MacInstance.kt": (
                "package q\nclass MacInstance(\n    algorithm: String,\n    private val key: ByteArray,\n) {\n"
                "    private val mac = Mac.getInstance(algorithm).apply { init(SecretKeySpec(key, algorithm)) }\n"
                "}\n"),
            "quartz/EngramDTag.kt": (
                "package q\nfun tag(conversationKey: ByteArray): MacInstance {\n"
                "    val derived = hkdf.extract(conversationKey)\n"
                "    return MacInstance(\"HmacSHA256\", derived)\n}\n"),
            "legacy/Old.java": (
                "class Old {\n  Object f() { byte[] k = random(32); return new MacInstance(\"HmacSHA1\", k); }\n}\n"),
        }
        for relative, text in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text, encoding="utf-8")
        # The reported body is an initializer, not the constructor's header.
        found = parameter_producers(
            root, "private val mac = Mac.getInstance(algorithm).apply { init(SecretKeySpec(key, algorithm)) }",
            "<init>", "q.MacInstance", "quartz/MacInstance.kt")
        self.assertEqual(found["status"], "collected")
        key = next(item for item in found["parameters"] if item["parameter"] == "key")
        self.assertEqual(key["index"], 1)
        sites = {site["source_file_path"]: site for site in key["call_sites"]}
        self.assertEqual(set(sites), {"quartz/EngramDTag.kt", "legacy/Old.java"})
        self.assertEqual(sites["quartz/EngramDTag.kt"]["producers"][0]["produced_by"],
                         "hkdf.extract(conversationKey)")
        self.assertEqual(sites["legacy/Old.java"]["producers"][0]["produced_by"], "random(32)")

    def test_a_constructor_is_read_from_its_own_class(self):
        # The first `constructor(` of the file belonged to another class, and
        # its parameters were reported for this one.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        files = {
            "a/W.kt": (
                "package a\nclass Other constructor(val z: Int)\n"
                "class W {\n    private val mac = Mac.getInstance(\"HmacSHA256\")\n"
                "    constructor(key: ByteArray) {\n        mac.init(SecretKeySpec(key, \"HmacSHA256\"))\n    }\n}\n"),
            "a/Use.kt": "package a\nfun mk(b: ByteArray) = W(b)\nfun other() = Other(3)\n",
            "b/Two.java": (
                "package b;\nclass Two {\n  Two(byte[] k) { init(k); }\n"
                "  Two(byte[] k, int n) { init(k); }\n}\n"),
        }
        for relative, text in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text, encoding="utf-8")
        found = parameter_producers(root, "private val mac = Mac.getInstance(\"HmacSHA256\")",
                                    "<init>", "a.W", "a/W.kt")
        self.assertEqual([item["parameter"] for item in found["parameters"]], ["key"])
        self.assertEqual(found["parameters"][0]["call_sites"][0]["argument"], "b")
        # Two Java constructors and a body that names neither: not guessed.
        ambiguous = parameter_producers(root, "init(k);", "<init>", "b.Two", "b/Two.java")
        self.assertEqual(ambiguous["status"], "not_applicable")

    def test_a_method_that_forwards_nothing_says_so(self):
        found = parameter_producers(Path("."), "void f() {\n    run();\n}\n", "f")
        self.assertEqual(found["status"], "no_forwarded_parameter")


if __name__ == "__main__":
    unittest.main()
