"""hfut-schedule's getUpdate fix removed a parameter default and broke its caller.

Gradle found that after sixteen minutes; the patch's own text was enough to see
it. These tests pin the cases the check must catch and, as important, the ones
it must stay silent about.
"""
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.semantic_validation import (  # noqa: E402
    signature_change_issues,
    validate_coordinated_semantics,
)
from cognalys.solutions.signature_change import (  # noqa: E402
    changed_symbol_names,
    declarations,
    signature_changes,
)


SERVICE = '''package app.network

interface GiteeService {
    //获取更新内容
    @GET("api/v5/repos/${Constant.OWNER}/releases")
    fun getUpdate(
        @Query("access_token") token : String = Constant.GITEE_TOKEN,
        @Query("page") page : Int = 1,
        @Query("per_page") pageSize : Int = 100
    ) : Call<ResponseBody>
}
'''
ORIGINAL_DECLARATION = '''    @GET("api/v5/repos/${Constant.OWNER}/releases")
    fun getUpdate(
        @Query("access_token") token : String = Constant.GITEE_TOKEN,
        @Query("page") page : Int = 1,
        @Query("per_page") pageSize : Int = 100
    ) : Call<ResponseBody>
'''
WITHOUT_DEFAULT = ORIGINAL_DECLARATION.replace(" = Constant.GITEE_TOKEN", "")
CONSTANTS = '''package app.network

object Constant {
    const val OWNER = "someone"
    const val GITEE_TOKEN = "bf51445a2add374b70205ca460f9a696"
}
'''
CALLER = '''package app.logic

class GithubRepository(private val gitee: GiteeService) {
    fun getUpdate() = launchRequestState(
        request = { gitee.getUpdate() },
    )
}
'''


def write_repository(root: Path, caller: str = CALLER, extra: dict | None = None) -> None:
    files = {
        "network/GiteeService.kt": SERVICE,
        "network/Constant.kt": CONSTANTS,
        "app/GithubRepository.kt": caller,
        **(extra or {}),
    }
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def default_removal_edit() -> dict:
    return {
        "source_file_path": "network/GiteeService.kt", "symbol": "GiteeService.getUpdate",
        "edit_kind": "method", "original_code": ORIGINAL_DECLARATION,
        "corrected_code": WITHOUT_DEFAULT, "reason": "remove the embedded token",
    }


def constant_deletion_edit() -> dict:
    return {
        "source_file_path": "network/Constant.kt", "symbol": "Constant.GITEE_TOKEN",
        "edit_kind": "delete",
        "original_code": '    const val GITEE_TOKEN = "bf51445a2add374b70205ca460f9a696"\n',
        "corrected_code": "", "reason": "remove the literal",
    }


class DeclarationParsingTests(unittest.TestCase):
    def test_a_retrofit_signature_is_read_with_its_defaults(self):
        [declaration] = declarations(ORIGINAL_DECLARATION, "kotlin")
        self.assertEqual(declaration.name, "getUpdate")
        self.assertEqual(
            [(p.name, p.has_default) for p in declaration.parameters],
            [("token", True), ("page", True), ("pageSize", True)],
        )

    def test_generics_and_function_types_do_not_split_a_parameter(self):
        code = "fun run(a: Map<String, Int>, b: (Int, Int) -> Unit = { x, y -> }, c: List<String> = listOf(\"a\", \"b\"))"
        [declaration] = declarations(code, "kotlin")
        self.assertEqual([p.name for p in declaration.parameters], ["a", "b", "c"])
        self.assertEqual([p.has_default for p in declaration.parameters], [False, True, True])

    def test_a_java_method_and_its_arity_are_read(self):
        [declaration] = declarations(
            "public static String join(final Map<String, String> m, String... rest) {\n}", "java")
        self.assertEqual([p.name for p in declaration.parameters], ["m", "rest"])

    def test_a_call_is_not_taken_for_a_declaration(self):
        self.assertEqual(declarations("class A { void f() { return g(1, 2); } }", "java"), [])


class SignatureChangeTests(unittest.TestCase):
    def test_each_kind_of_change_is_named(self):
        self.assertEqual(
            [c.kind for c in signature_changes(ORIGINAL_DECLARATION, WITHOUT_DEFAULT, "kotlin")],
            ["removed_default"],
        )
        removed = signature_changes("fun f(a: Int, b: Int)", "fun f(a: Int)", "kotlin")
        self.assertEqual([(c.kind, c.parameter) for c in removed], [("removed_parameter", "b")])
        added = signature_changes("fun f(a: Int)", "fun f(a: Int, b: Int)", "kotlin")
        self.assertEqual([(c.kind, c.parameter) for c in added], [("added_required_parameter", "b")])
        self.assertEqual(signature_changes("fun f(a: Int)", "fun f(a: Int, b: Int = 1)", "kotlin"), [])
        self.assertEqual(
            [c.kind for c in signature_changes("void f(int a) {}", "void f(int a, int b) {}", "java")],
            ["arity_changed"],
        )

    def test_a_body_only_change_is_not_a_signature_change(self):
        self.assertEqual(signature_changes(
            "fun f(a: Int = 1) { println(a) }", "fun f(a: Int = 2) { println(a + 1) }", "kotlin"), [])


class BreakingCallerTests(unittest.TestCase):
    def issues(self, caller: str = CALLER, edits=None, extra=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_repository(root, caller, extra)
            return signature_change_issues(
                {"repository_path": str(root)}, edits or [default_removal_edit()],
            )

    def test_the_hfut_caller_is_reported_with_where_and_what_to_do(self):
        [issue] = self.issues()
        self.assertEqual(issue["code"], "SIGNATURE_CHANGE_BREAKS_CALLERS")
        self.assertEqual(issue["source_file_path"], "network/GiteeService.kt")
        text = " ".join(issue["details"])
        self.assertIn("`token` lost its default value", text)
        self.assertIn("app/GithubRepository.kt:5", text)
        self.assertIn("gitee.getUpdate()", text)
        self.assertIn("Keep the signature", text)

    def test_a_caller_that_passes_the_argument_is_fine(self):
        self.assertEqual(self.issues(CALLER.replace("gitee.getUpdate()", 'gitee.getUpdate("t")')), [])
        self.assertEqual(self.issues(CALLER.replace("gitee.getUpdate()", 'gitee.getUpdate(token = "t")')), [])

    def test_a_caller_the_same_patch_updates_is_fine(self):
        fix = {
            "source_file_path": "app/GithubRepository.kt", "symbol": "GithubRepository.getUpdate",
            "edit_kind": "method", "original_code": "        request = { gitee.getUpdate() },\n",
            "corrected_code": '        request = { gitee.getUpdate(BuildConfig.TOKEN) },\n',
            "reason": "supply the token",
        }
        self.assertEqual(self.issues(edits=[default_removal_edit(), fix]), [])

    def test_an_unresolved_receiver_is_ours_only_when_the_name_is_unique(self):
        chained = "class R {\n    fun load() = provider().getUpdate()\n}\n"
        other = "class Other : GiteeService {\n    override fun getUpdate(page: Int) = TODO()\n}\n"
        # Nothing else has the name: the call can only be this declaration.
        self.assertEqual(len(self.issues(chained)), 1)
        # Another declaration exists and the receiver's type is unknown: silent.
        self.assertEqual(self.issues(chained, extra={"app/Other.kt": other}), [])

    def test_a_call_that_cannot_be_read_completely_is_not_reported(self):
        for shape in (
            "gitee.getUpdate() { it }", "gitee.getUpdate(*args)", "gitee.getUpdate(listOf<String>())",
        ):
            with self.subTest(shape=shape):
                self.assertEqual(self.issues(CALLER.replace("gitee.getUpdate()", shape)), [])

    def test_comments_and_strings_are_not_calls(self):
        caller = 'class A {\n    // gitee.getUpdate()\n    val s = "gitee.getUpdate()"\n}\n'
        self.assertEqual(self.issues(caller), [])

    def test_a_test_file_caller_counts(self):
        tests = "class T { fun t() { service.getUpdate() } }\n"
        [issue] = self.issues("class Unrelated\n", extra={"test/T.kt": tests})
        self.assertIn("test/T.kt:1", " ".join(issue["details"]))

    def test_the_real_hfut_shape_with_same_named_methods_elsewhere(self):
        """The caller's receiver is typed by `X::class.java`, its own class has a
        `getUpdate` too, and an unrelated ViewModel calls `vm.getUpdate()`."""
        repository = (
            "class GithubRepository {\n"
            "    private val gitee = GiteeServiceCreator.create(GiteeService::class.java)\n"
            "    override suspend fun getUpdate(holder : UiStateHolder<R>) = launchRequestState(\n"
            "        request = { gitee.getUpdate() },\n"
            "    )\n"
            "}\n"
        )
        view = (
            "class Screen(private val vm: NetWorkViewModel) {\n"
            "    fun load() { vm.getUpdate() }\n"
            "}\n"
        )
        [issue] = self.issues(repository, extra={"ui/Screen.kt": view})
        details = " ".join(issue["details"])
        self.assertIn("app/GithubRepository.kt:4", details)
        self.assertNotIn("ui/Screen.kt", details)

    def test_a_receiver_of_another_declared_type_is_not_ours(self):
        other = (
            "class Other(private val service: SomethingElse) {\n"
            "    fun f() { service.getUpdate() }\n"
            "}\n"
        )
        self.assertEqual(self.issues("class Unrelated\n", extra={"x/Other.kt": other}), [])

    def test_a_java_arity_change_reports_the_old_call(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "A.java").write_text("class A {\n    void send(int a) {}\n}\n", encoding="utf-8")
            (root / "B.java").write_text("class B {\n    void f(A a) { a.send(1); }\n}\n", encoding="utf-8")
            edit = {
                "source_file_path": "A.java", "symbol": "A.send", "edit_kind": "method",
                "original_code": "    void send(int a) {}\n",
                "corrected_code": "    void send(int a, int b) {}\n", "reason": "x",
            }
            [issue] = signature_change_issues({"repository_path": str(root)}, [edit])
        self.assertIn("B.java:2", " ".join(issue["details"]))


class DeletedConstantTests(unittest.TestCase):
    def test_a_reference_left_to_a_deleted_constant_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_repository(root, "class A { val t = Constant.GITEE_TOKEN }\n")
            [issue] = signature_change_issues(
                {"repository_path": str(root)}, [constant_deletion_edit()],
            )
        self.assertEqual(issue["code"], "REMOVED_CONSTANT_STILL_REFERENCED")
        self.assertIn("GITEE_TOKEN", " ".join(issue["details"]))

    def test_the_getupdate_patch_as_generated_only_breaks_the_caller(self):
        """Both of its edits together: the constant has no other reader."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_repository(root)
            issues = signature_change_issues(
                {"repository_path": str(root)},
                [default_removal_edit(), constant_deletion_edit()],
            )
        self.assertEqual([issue["code"] for issue in issues], ["SIGNATURE_CHANGE_BREAKS_CALLERS"])

    def test_a_constant_declared_elsewhere_too_is_ambiguous_and_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_repository(
                root, "class A { val t = Other.GITEE_TOKEN }\n",
                {"other/Other.kt": 'object Other { const val GITEE_TOKEN = "x" }\n'},
            )
            self.assertEqual(signature_change_issues(
                {"repository_path": str(root)}, [constant_deletion_edit()]), [])


class GateIntegrationTests(unittest.TestCase):
    def test_the_semantic_validation_reports_it_as_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_repository(root)
            result = validate_coordinated_semantics(
                {"repository_path": str(root)}, [default_removal_edit()],
            )
        self.assertEqual(result["status"], "invalid")
        self.assertIn("SIGNATURE_CHANGE_BREAKS_CALLERS", [e["code"] for e in result["errors"]])

    def test_an_unreadable_repository_never_blocks(self):
        self.assertEqual(signature_change_issues({"repository_path": "/nonexistent/x"}, [default_removal_edit()]), [])
        self.assertEqual(signature_change_issues({}, [default_removal_edit()]), [])


class ChangedSymbolNamesTests(unittest.TestCase):
    def test_names_come_from_signature_changes_and_deleted_constants(self):
        self.assertEqual(
            changed_symbol_names([default_removal_edit(), constant_deletion_edit()]),
            {"getUpdate", "GITEE_TOKEN"},
        )
        self.assertEqual(changed_symbol_names([{
            "source_file_path": "A.kt", "edit_kind": "method",
            "original_code": "fun f() { a() }", "corrected_code": "fun f() { b() }",
        }]), set())


if __name__ == "__main__":
    unittest.main()


class UnrelatedParameterTests(unittest.TestCase):
    """The finding concerned one parameter; the patch also removed two others."""

    FINDING = {
        "error_message": (
            "Static candidate: getUpdate sends Constant.GITEE_TOKEN, a hard-coded "
            "access token, as the access_token query parameter of every update check"
        ),
        "evidence_analysis": {"confirmed_cause": "The token is the default of the token parameter."},
    }

    def edit(self, corrected: str) -> dict:
        return {**default_removal_edit(), "corrected_code": corrected}

    def issues(self, corrected: str, error=None):
        return signature_change_issues(
            {**(error or self.FINDING), "repository_path": "/nonexistent"},
            [self.edit(corrected)],
        )

    def test_removing_parameters_the_finding_never_names_is_reported(self):
        [issue] = self.issues("    fun getUpdate() : Call<ResponseBody>\n")
        self.assertEqual(issue["code"], "UNRELATED_PARAMETER_CHANGED")
        details = " ".join(issue["details"])
        self.assertIn("`page`", details)
        self.assertIn("`pageSize`", details)
        self.assertNotIn("`token`", details)
        self.assertIn("Keep every parameter", details)

    def test_removing_only_the_named_parameter_is_fine(self):
        corrected = (
            "    fun getUpdate(\n"
            "        @Query(\"page\") page : Int = 1,\n"
            "        @Query(\"per_page\") pageSize : Int = 100\n"
            "    ) : Call<ResponseBody>\n"
        )
        self.assertEqual(self.issues(corrected), [])

    def test_a_default_stripped_from_an_unrelated_parameter_counts(self):
        corrected = ORIGINAL_DECLARATION.replace(" = Constant.GITEE_TOKEN", "").replace("page : Int = 1", "page : Int")
        [issue] = self.issues(corrected)
        self.assertIn("`page`", " ".join(issue["details"]))

    def test_name_words_are_matched_across_case_styles_and_prefixes(self):
        error = {"error_message": "the accessToken and page size are read from user input"}
        self.assertEqual(self.issues("    fun getUpdate() : Call<ResponseBody>\n", error), [])
        error = {"error_message": "the algorithm is weak", "evidence_analysis": {}}
        edit = {**default_removal_edit(),
                "original_code": "fun hash(input: String, algo: String = \"MD5\") = 1\n",
                "corrected_code": "fun hash(input: String) = 1\n"}
        self.assertEqual(signature_change_issues({**error, "repository_path": "/x"}, [edit]), [])

    def test_no_finding_text_means_no_judgement(self):
        self.assertEqual(self.issues("    fun getUpdate() : Call<ResponseBody>\n", {"error_message": ""}), [])
