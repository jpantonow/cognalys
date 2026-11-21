"""hfut-schedule's generated androidTest called a member GiteeService never had.

The gate stayed silent for every Kotlin type, so the missing "test seam" cost a
six-minute build, a repair and a forty-minute revalidation. It now reports a
member that no file of the repository declares, and stays silent whenever a
companion, an extension, a generated accessor or a library supertype could be
the source.
"""
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.semantic_validation import unresolved_repository_symbols  # noqa: E402


SERVICE = "interface GiteeService {\n    fun getUpdate(): Call<ResponseBody>\n}\n"
TEST = (
    "class ContractTest {\n"
    "    @Test fun t() {\n"
    "        assertTrue(GiteeService.getUpdateQueryParameterNamesForTest().isEmpty())\n"
    "    }\n"
    "}\n"
)


def issues_for(files: dict, test: str = TEST):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        edit = {
            "source_file_path": "app/src/androidTest/ContractTest.kt", "symbol": "ContractTest",
            "edit_kind": "create", "original_code": "", "corrected_code": test, "reason": "test",
        }
        return unresolved_repository_symbols({"repository_path": str(root)}, [edit])


class KotlinMemberGateTests(unittest.TestCase):
    def test_a_member_no_file_declares_is_reported(self):
        [issue] = issues_for({"GiteeService.kt": SERVICE})
        self.assertEqual(issue["code"], "SYMBOL_NOT_DECLARED_IN_REPOSITORY")
        self.assertIn("getUpdateQueryParameterNamesForTest", " ".join(issue["details"]))

    def test_a_companion_member_or_top_level_extension_keeps_it_silent(self):
        companion = (
            "interface GiteeService {\n    companion object {\n"
            "        fun getUpdateQueryParameterNamesForTest() = emptyList<String>()\n    }\n}\n"
        )
        self.assertEqual(issues_for({"GiteeService.kt": companion}), [])
        extension = "fun GiteeService.Companion.getUpdateQueryParameterNamesForTest() = 1\n"
        self.assertEqual(issues_for({"GiteeService.kt": SERVICE, "Ext.kt": extension}), [])

    def test_a_property_of_that_name_keeps_it_silent(self):
        service = "object GiteeService {\n    val getUpdateQueryParameterNamesForTest = 1\n}\n"
        self.assertEqual(issues_for({"GiteeService.kt": service}), [])

    def test_a_supertype_outside_the_repository_keeps_it_silent(self):
        service = "class GiteeService : ViewModel() {\n    fun getUpdate() {}\n}\n"
        self.assertEqual(issues_for({"GiteeService.kt": service}), [])

    def test_a_supertype_inside_the_repository_does_not(self):
        service = "class GiteeService : Base() {\n    fun getUpdate() {}\n}\n"
        self.assertEqual(len(issues_for({"GiteeService.kt": service, "Base.kt": "open class Base\n"})), 1)

    def test_generated_members_are_never_reported(self):
        data = "data class Item(val a: Int)\n"
        enum = "enum class Mode { A, B }\n"
        for source, call in ((data, "Item.copy(1)"), (enum, "Mode.values()"), (enum, "Mode.valueOf(\"A\")")):
            with self.subTest(call=call):
                receiver = call.split(".")[0]
                self.assertEqual(
                    issues_for({f"{receiver}.kt": source}, f"class T {{ fun t() {{ {call} }} }}\n"), [])

    def test_a_generating_annotation_keeps_it_silent(self):
        service = "@Serializable\nclass Payload(val a: Int)\n"
        self.assertEqual(
            issues_for({"Payload.kt": service}, "class T { fun t() { Payload.fromJson(\"x\") } }\n"), [])

    def test_a_type_the_repository_does_not_declare_is_not_checked(self):
        self.assertEqual(issues_for({"Other.kt": "class Other\n"}), [])


if __name__ == "__main__":
    unittest.main()
