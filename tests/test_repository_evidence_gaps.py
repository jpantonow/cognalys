import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.multi_file_context import (  # noqa: E402
    _is_project_document,
    _type_declaration_like,
    collect_multi_file_context,
)


def _context(root: Path, contents: dict, target: Path, method: str,
             body: str, class_name: str = "example.Handler", **overrides):
    for path, content in contents.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    arguments = dict(
        repo_root=root, source_file=target, method_name=method,
        class_name=class_name, method_body=body, source_cache=contents,
        repository_paths=list(contents),
        repository_index_metadata={"truncated": False},
    )
    arguments.update(overrides)
    return collect_multi_file_context(**arguments)


class ConstantDefinitionEvidenceTests(unittest.TestCase):
    """A constraint finding is decided by a value declared somewhere else.

    photok's CipherSpec finding is entirely about the string behind
    `Algorithm.AesCbcPkcs7Padding`. The packet carried the reviewed method,
    its callers, its tests and the bodies of the functions it calls, and not
    the enum that fixes that string -- so the research pass fetched
    Algorithm.kt from raw.githubusercontent instead, landing the decisive
    fact in the one evidence category the adjudication is told never
    establishes what this repository's code does.
    """

    BODY = (
        "fun create(): Vault {\n"
        "    val params = Params(algorithm = Algorithm.AesCbcPkcs7Padding)\n"
        "    val cipher = Cipher.getInstance(params.algorithm.value)\n"
        "    return Vault(cipher)\n"
        "}\n"
    )

    def _contents(self, root: Path, target: Path) -> dict:
        return {
            target: "class Handler {\n" + self.BODY + "}\n",
            root / "src" / "Algorithm.kt": (
                "enum class Algorithm(val value: String) {\n"
                "    AesCbcPkcs7Padding(value = \"AES/CBC/PKCS7Padding\"),\n"
                "    AesGcmNoPadding(value = \"AES/GCM/NoPadding\")\n"
                "}\n"
            ),
        }

    def test_the_enum_that_fixes_the_reported_value_is_offered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            context = _context(
                root, self._contents(root, target), target, "create", self.BODY
            )
            constants = context["constant_definitions"]
            self.assertEqual(
                [item["constant_owner"] for item in constants], ["Algorithm"]
            )
            declaration = constants[0]["declaration"]
            # Both alternatives, so the adjudication can see that the
            # replacement constant already exists in the project.
            self.assertIn("AES/CBC/PKCS7Padding", declaration)
            self.assertIn("AES/GCM/NoPadding", declaration)

    def test_a_platform_type_resolves_to_nothing(self):
        # Cipher.ENCRYPT_MODE is not this repository's to declare; that is
        # external research's question, not the packet's.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            context = _context(
                root, self._contents(root, target), target, "create", self.BODY
            )
            owners = {
                item["constant_owner"]
                for item in context["constant_definitions"]
            }
            self.assertNotIn("Cipher", owners)

    def test_a_constructed_type_is_not_a_constant_read(self):
        body = "fun create() { val r = SecureRandom(); r.nextBytes(x) }\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            contents = {
                target: "class Handler {\n" + body + "}\n",
                root / "src" / "SecureRandom.kt": "class SecureRandom {\n}\n",
            }
            context = _context(root, contents, target, "create", body)
            self.assertEqual(context["constant_definitions"], [])

    def test_a_type_parameter_bound_is_not_a_declaration(self):
        # `interface H<A : Req, B : CreateRequest>` declares H and nothing
        # else; matching CreateRequest there spends an evidence slot on the
        # wrong file.
        line = "interface H<A : UnlockRequest, B : CreateRequest> {"
        self.assertTrue(_type_declaration_like(line, "H"))
        self.assertFalse(_type_declaration_like(line, "CreateRequest"))

    def test_modifiers_between_the_keyword_and_the_name_are_skipped(self):
        self.assertTrue(
            _type_declaration_like("enum class Algorithm(val v: String) {", "Algorithm")
        )
        self.assertTrue(
            _type_declaration_like("public final class Foo extends Bar {", "Foo")
        )
        self.assertFalse(
            _type_declaration_like("public final class Foo extends Bar {", "Bar")
        )


class ProjectDocumentationEvidenceTests(unittest.TestCase):
    """The project's own account of the format it stores, and why.

    photok's ENCRYPTION.md documents a versioned stored format, a migration
    between versions, and the reason AES/CBC was chosen over AES/GCM. The run
    that reported its CipherSpec finding asked the maintainer for all three.
    """

    BODY = (
        "fun create(): VaultProtection {\n"
        "    val params = VaultProtectionParams(kdf = PBKDF2WithHmacSHA256)\n"
        "    return VaultProtection(params)\n"
        "}\n"
    )

    def _contents(self, root: Path, target: Path, doc: str) -> dict:
        return {
            target: "class Handler {\n" + self.BODY + "}\n",
            root / "ENCRYPTION.md": doc,
        }

    def test_a_document_naming_this_code_is_offered(self):
        doc = (
            "# Encryption Specification\n"
            "Version 3 stores VaultProtectionParams alongside the wrapped "
            "key.\nAES-GCM does not support random access seeking.\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            context = _context(
                root, self._contents(root, target, doc), target, "create",
                self.BODY,
            )
            documents = context["documentation_evidence"]
            self.assertEqual(len(documents), 1)
            self.assertEqual(documents[0]["source_file_path"], "ENCRYPTION.md")
            self.assertIn(
                "VaultProtectionParams", documents[0]["matched_terms"]
            )
            self.assertIn("random access seeking", documents[0]["content"])

    def test_a_document_naming_none_of_this_code_is_not_offered(self):
        # A boilerplate policy file that mentions none of the project's own
        # types buys nothing and costs budget.
        doc = "# Security\nPlease report vulnerabilities to security@example.\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            contents = self._contents(root, target, doc)
            contents[root / "SECURITY.md"] = contents.pop(root / "ENCRYPTION.md")
            context = _context(root, contents, target, "create", self.BODY)
            self.assertEqual(context["documentation_evidence"], [])

    def test_only_design_documents_at_the_root_or_under_docs_qualify(self):
        for relative, expected in (
            ("ENCRYPTION.md", True),
            ("docs/format.md", True),
            ("doc/protocol.adoc", True),
            ("CHANGELOG.md", False),
            ("README.md", False),
            ("app/src/main/design.md", False),
        ):
            with self.subTest(relative=relative):
                suffix = "." + relative.rsplit(".", 1)[-1]
                self.assertEqual(
                    _is_project_document(relative, suffix), expected
                )


class LayerConversionEvidenceTests(unittest.TestCase):
    """Whether a produced value survives a round trip through storage.

    photok's adjudication blocked on "the mapper/schema, all rehydration
    paths, and all import/unlock consumers are not established" with the DAO,
    the repository and the backup flows all in the packet. The mapper is
    twenty-two lines that pass the parameters through untouched in both
    directions, and the Room type converter serialises the whole object to
    JSON; together they establish that each stored record carries the
    algorithm it was written under, which is the entire compatibility
    question.
    """

    BODY = (
        "fun create(): VaultProtection {\n"
        "    val params = VaultProtectionParams(algorithm = Algorithm.Cbc)\n"
        "    return VaultProtection(params = params)\n"
        "}\n"
    )

    MAPPER = (
        "fun VaultProtectionTable.toDomain(): VaultProtection {\n"
        "    return VaultProtection(params = params)\n"
        "}\n"
        "fun VaultProtection.toData(): VaultProtectionTable {\n"
        "    return VaultProtectionTable(params = params)\n"
        "}\n"
    )

    def _contents(self, root: Path, target: Path, **extra) -> dict:
        contents = {
            target: "class Handler {\n" + self.BODY + "}\n",
            root / "src" / "Mapper.kt": self.MAPPER,
        }
        contents.update(extra)
        return contents

    def test_the_mapper_for_the_produced_type_is_offered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            context = _context(
                root, self._contents(root, target), target, "create", self.BODY
            )
            conversions = context["conversion_definitions"]
            self.assertEqual(len(conversions), 1)
            self.assertEqual(conversions[0]["source_file_path"], "src/Mapper.kt")
            self.assertIn("VaultProtection", conversions[0]["converted_types"])
            # Both directions, which is what shows the field survives the
            # round trip rather than only being written.
            self.assertEqual(
                conversions[0]["definition"].count("params = params"), 2
            )

    def test_the_returned_type_is_preferred_over_incidental_construction(self):
        from cognalys.extraction.multi_file_context import _produced_type_names
        produced = _produced_type_names(self.BODY)
        self.assertEqual(produced[0], "VaultProtection")

    def test_a_file_with_no_conversion_function_is_not_offered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            contents = self._contents(root, target)
            contents[root / "src" / "Other.kt"] = (
                "class Other {\n fun use(v: VaultProtection) = v\n}\n"
            )
            context = _context(root, contents, target, "create", self.BODY)
            offered = {
                item["source_file_path"]
                for item in context["conversion_definitions"]
            }
            self.assertNotIn("src/Other.kt", offered)

    def test_a_conversion_naming_no_produced_type_is_not_offered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            contents = {
                target: "class Handler {\n" + self.BODY + "}\n",
                root / "src" / "Unrelated.kt": (
                    "fun PhotoTable.toDomain(): Photo = Photo()\n"
                ),
            }
            context = _context(root, contents, target, "create", self.BODY)
            self.assertEqual(context["conversion_definitions"], [])


class SettingRoundTripTests(unittest.TestCase):
    """Persisting a setting and reading it back is one fact, not two halves.

    photok's packet carried the mapper that persists VaultProtectionParams
    and the file whose unlock() reads params.algorithm back out of it, and
    the adjudication still blocked on "whether all readers select an
    algorithm from the stored parameters". Both halves were present; the
    relation between them was stated nowhere.
    """

    BODY = (
        "fun create(): VaultProtection {\n"
        "    val params = Params(\n"
        "        algorithm = Algorithm.Cbc,\n"
        "        cipher = Cipher.getInstance(\"x\"),\n"
        "    )\n"
        "    return VaultProtection(params)\n"
        "}\n"
    )

    READER = (
        "class Reader {\n"
        "    fun unlock(protection: VaultProtection) {\n"
        "        val c = Cipher.getInstance(protection.params.algorithm.value)\n"
        "        return c\n"
        "    }\n"
        "}\n"
    )

    def _contents(self, root: Path, target: Path, **extra) -> dict:
        contents = {
            target: "class Handler {\n" + self.BODY + "}\n",
            root / "src" / "Algorithm.kt": (
                "enum class Algorithm(val value: String) {\n"
                "    Cbc(value = \"AES/CBC/PKCS7Padding\")\n"
                "}\n"
            ),
            root / "src" / "Reader.kt": self.READER,
        }
        contents.update(extra)
        return contents

    def _round_trip(self, root: Path, target: Path, **extra) -> list:
        context = _context(
            root, self._contents(root, target, **extra), target, "create",
            self.BODY,
        )
        return context["round_trip_evidence"]

    def test_the_setting_and_every_reader_of_it_are_named(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            records = self._round_trip(root, target)
            fields = {item["field"] for item in records}
            self.assertIn("algorithm", fields)
            record = next(i for i in records if i["field"] == "algorithm")
            self.assertEqual(record["chosen_from"], "Algorithm")
            self.assertEqual(record["written_by"], "create")
            readers = record["read_back_by"]
            self.assertTrue(readers)
            self.assertEqual(readers[0]["enclosing_symbol"], "unlock")
            self.assertEqual(readers[0]["source_file_path"], "src/Reader.kt")

    def test_a_platform_type_is_not_a_project_setting(self):
        # `val cipher = Cipher.getInstance(...)` assigns from a platform
        # type, whose round trip means nothing; only constants this
        # repository declares count.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            fields = {
                item["field"] for item in self._round_trip(root, target)
            }
            self.assertNotIn("cipher", fields)

    def test_the_writing_method_is_not_counted_as_a_reader(self):
        # A method reading what it just assigned establishes no round trip.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            body = self.BODY.replace(
                "    return VaultProtection(params)\n",
                "    val again = params.algorithm.value\n"
                "    return VaultProtection(params)\n",
            )
            contents = self._contents(root, target)
            contents[target] = "class Handler {\n" + body + "}\n"
            contents.pop(root / "src" / "Reader.kt")
            context = _context(root, contents, target, "create", body)
            self.assertEqual(context["round_trip_evidence"], [])

    def test_the_enclosing_function_is_the_function_not_a_nearby_call(self):
        # _enclosing_symbol reports whatever is signature-shaped nearby, so
        # a read inside requireNotNull(...) came back as "requireNotNull".
        reader = (
            "class Reader {\n"
            "    fun unlock(protection: VaultProtection) {\n"
            "        requireNotNull(protection.params.algorithm)\n"
            "    }\n"
            "}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            contents = self._contents(root, target)
            contents[root / "src" / "Reader.kt"] = reader
            context = _context(root, contents, target, "create", self.BODY)
            record = next(
                item for item in context["round_trip_evidence"]
                if item["field"] == "algorithm"
            )
            self.assertEqual(
                record["read_back_by"][0]["enclosing_symbol"], "unlock"
            )

    def test_it_states_the_bound_it_cannot_exclude(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            record = self._round_trip(root, target)[0]
            self.assertIn("examined scope", record["bound"])
            self.assertIn("does not prove", record["bound"])


class InjectedReceiverResolutionTests(unittest.TestCase):
    """A Kotlin receiver carries no type, and injection hides the concrete one.

    photok's `create` resolved zero callers out of twenty-one call sites,
    which left resolved_callers "partial" and the scope incomplete -- and an
    incomplete scope is what the adjudication abstains on, so no amount of
    other evidence could move the finding. The caller is
    `passwordProtectionHandler.create(request)`, whose receiver is declared
    as an interface that a Hilt module binds to the concrete class; three
    bindings return the same interface and only the type arguments tell them
    apart.
    """

    MODULE = (
        "@Module\n"
        "abstract class EncryptionModule {\n"
        "    @Binds\n"
        "    fun bindPassword(impl: PasswordHandler): "
        "Handler<Request.Password, Create.Password>\n"
        "    @Binds\n"
        "    fun bindBiometric(impl: BiometricHandler): "
        "Handler<Request.Biometric, Create.Biometric>\n"
        "}\n"
    )
    SERVICE = (
        "class VaultService(\n"
        "    private val passwordHandler: Handler<Request.Password, "
        "Create.Password>,\n"
        "    private val biometricHandler: Handler<Request.Biometric, "
        "Create.Biometric>,\n"
        ") {\n"
        "    fun create() {\n"
        "        passwordHandler.create(request)\n"
        "        biometricHandler.create(request)\n"
        "    }\n"
        "}\n"
    )

    def _bindings(self):
        from cognalys.extraction import multi_file_context as module
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "EncryptionModule.kt"
            path.write_text(self.MODULE, encoding="utf-8")
            return module.collect_injection_bindings(
                [path], root, {path: self.MODULE}
            )

    def test_the_type_arguments_separate_two_bindings_of_one_interface(self):
        bindings = self._bindings()
        self.assertEqual(
            bindings["Handler<Password,Password>"], "PasswordHandler"
        )
        self.assertEqual(
            bindings["Handler<Biometric,Biometric>"], "BiometricHandler"
        )

    def test_a_declared_receiver_keeps_its_type_arguments(self):
        from cognalys.extraction.multi_file_context import declared_receiver_type
        self.assertEqual(
            declared_receiver_type(self.SERVICE, "passwordHandler"),
            "Handler<Password,Password>",
        )

    def test_a_local_gets_its_type_from_the_constructor_it_calls(self):
        from cognalys.extraction.multi_file_context import declared_receiver_type
        source = "fun t() { val handler = PasswordHandler(gen, config) }\n"
        self.assertEqual(
            declared_receiver_type(source, "handler"), "PasswordHandler"
        )

    def test_a_capitalised_receiver_is_a_type_name(self):
        from cognalys.extraction.multi_file_context import declared_receiver_type
        self.assertEqual(
            declared_receiver_type("", "ReviewManagerFactory"),
            "ReviewManagerFactory",
        )

    def test_a_call_bound_to_this_class_becomes_a_resolved_caller(self):
        from cognalys.extraction.multi_file_context import resolve_injected_receivers
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = root / "VaultService.kt"
            service.write_text(self.SERVICE, encoding="utf-8")
            resolution = {
                "status": "available", "resolved_callers": [],
                "ambiguous_calls": [
                    {"name": "create", "receiver": "passwordHandler",
                     "path": "VaultService.kt", "line": 6},
                    {"name": "create", "receiver": "biometricHandler",
                     "path": "VaultService.kt", "line": 7},
                ],
            }
            updated = resolve_injected_receivers(
                resolution, "example.PasswordHandler", root,
                {service: self.SERVICE}, self._bindings(),
            )
            self.assertEqual(len(updated["resolved_callers"]), 1)
            self.assertEqual(
                updated["resolved_callers"][0]["bound_implementation"],
                "PasswordHandler",
            )
            # The biometric call was never about this class, and counting it
            # as unresolved scope is what kept the scope incomplete.
            self.assertEqual(updated["ambiguous_calls"], [])

    def test_a_build_script_is_not_a_caller_of_application_code(self):
        # Gradle's own `create("play")` product-flavor calls were counted as
        # unresolved calls to the reviewed method purely by name.
        from cognalys.extraction.multi_file_context import resolve_injected_receivers
        with tempfile.TemporaryDirectory() as directory:
            resolution = {
                "status": "available", "resolved_callers": [],
                "ambiguous_calls": [
                    {"name": "create", "receiver": "",
                     "path": "app/build.gradle.kts", "line": 47},
                ],
            }
            updated = resolve_injected_receivers(
                resolution, "example.PasswordHandler", Path(directory),
                {}, {"X": "Y"},
            )
            self.assertEqual(updated["ambiguous_calls"], [])

    def test_an_unresolvable_receiver_is_left_exactly_as_it_was(self):
        from cognalys.extraction.multi_file_context import resolve_injected_receivers
        with tempfile.TemporaryDirectory() as directory:
            call = {"name": "create", "receiver": "it",
                    "path": "Fragment.kt", "line": 47}
            updated = resolve_injected_receivers(
                {"status": "available", "resolved_callers": [],
                 "ambiguous_calls": [call]},
                "example.PasswordHandler", Path(directory), {}, {"X": "Y"},
            )
            self.assertEqual(updated["ambiguous_calls"], [call])


class GenericMethodNameScopeTests(unittest.TestCase):
    """A common method name is not an unresolved scope.

    The rule flipped the scope to incomplete whenever the reported method was
    named one of twelve very common words and the repository declared it more
    than once, and the adjudication abstains on an incomplete scope. photok's
    finding is in a method called `create`: its packet recorded target_source,
    resolved_callers, tests and build_config all complete, and still came out
    incomplete with this as the single stated limitation.
    """

    BODY = "fun create(): String = \"x\"\n"

    RESOLVED = {
        "status": "available", "backend": "test", "resolved_callers": [],
        "related_declarations": [], "ambiguous_calls": [],
    }

    def _contents(self, root: Path, target: Path) -> dict:
        return {
            target: "class Handler {\n" + self.BODY + "}\n",
            root / "src" / "Other.kt": "class Other {\n fun create() = 1\n}\n",
        }

    def _with_semantic(self, resolution):
        from cognalys.extraction import semantic_index
        original = semantic_index.build_semantic_index
        semantic_index.build_semantic_index = lambda **kwargs: resolution
        self.addCleanup(
            setattr, semantic_index, "build_semantic_index", original
        )

    def test_a_resolved_target_is_not_made_incomplete_by_its_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            self._with_semantic(self.RESOLVED)
            context = _context(
                root, self._contents(root, target), target, "create",
                self.BODY,
            )
            completeness = context["scope_completeness"]
            self.assertEqual(completeness["status"], "complete")
            self.assertEqual(completeness["reasons"], [])
            # Still said out loud, just not disqualifying.
            self.assertTrue(any(
                "common in this repository" in note
                for note in completeness["resolved_notes"]
            ))

    def test_an_unresolved_scope_still_reports_the_ambiguity(self):
        # Without the semantic index the resolution is lexical, and the name
        # frequency is the only signal there is.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            self._with_semantic({"status": "unavailable", "backend": "none"})
            context = _context(
                root, self._contents(root, target), target, "create",
                self.BODY,
            )
            completeness = context["scope_completeness"]
            self.assertEqual(completeness["status"], "incomplete")
            self.assertIn(
                "generic method name has unresolved declaration ambiguity",
                completeness["reasons"],
            )

    def test_a_truncated_index_still_makes_the_scope_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "Handler.kt"
            self._with_semantic(self.RESOLVED)
            context = _context(
                root, self._contents(root, target), target, "create",
                self.BODY,
                repository_index_metadata={"truncated": True},
            )
            self.assertEqual(
                context["scope_completeness"]["status"], "incomplete"
            )


if __name__ == "__main__":
    unittest.main()
