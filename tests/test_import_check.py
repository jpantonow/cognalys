"""hfut-schedule's generated test imported Retrofit's Gradle group as a package."""
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.semantic_validation import validate_coordinated_semantics  # noqa: E402
from cognalys.solutions.import_check import imports_in, mismatched_imports  # noqa: E402


SERVICE = "package app.api\n\nimport retrofit2.http.GET\nimport retrofit2.http.Query\n\ninterface S\n"


def check(files: dict, generated: str, original: str = "", kind: str = "create"):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        edit = {
            "source_file_path": "app/src/test/T.kt", "symbol": "T", "edit_kind": kind,
            "original_code": original, "corrected_code": generated, "reason": "test",
        }
        return mismatched_imports(root, [edit])


class ImportCheckTests(unittest.TestCase):
    def test_a_gradle_group_used_as_a_package_is_reported_with_the_right_import(self):
        [issue] = check({"S.kt": SERVICE}, "import com.squareup.retrofit2.http.Query\nclass T\n")
        self.assertEqual(issue["code"], "IMPORT_PACKAGE_NOT_IN_REPOSITORY")
        text = " ".join(issue["details"])
        self.assertIn("com.squareup.retrofit2.http.Query", text)
        self.assertIn("`retrofit2.http.Query`", text)
        self.assertIn("Gradle group id", text)

    def test_the_import_the_repository_uses_is_fine(self):
        self.assertEqual(check({"S.kt": SERVICE}, "import retrofit2.http.Query\nclass T\n"), [])

    def test_only_added_imports_are_judged(self):
        original = "import com.squareup.retrofit2.http.Query\nclass T\n"
        self.assertEqual(check({"S.kt": SERVICE}, original + "// edited\n", original, "method"), [])

    def test_a_simple_name_the_repository_never_imports_is_not_judged(self):
        self.assertEqual(check({"S.kt": SERVICE}, "import com.example.unknown.Thing\nclass T\n"), [])

    def test_platform_packages_are_never_judged(self):
        files = {"S.kt": SERVICE + "import android.text.Editable\n"}
        self.assertEqual(check(files, "import android.text.Editable\nimport org.junit.Test\nclass T\n"), [])

    def test_a_package_declared_or_imported_from_in_the_repository_is_fine(self):
        files = {
            "S.kt": SERVICE,
            "Other.kt": "package other.http\n\nclass Query\n",
        }
        self.assertEqual(check(files, "import other.http.Query\nclass T\n"), [])
        files = {"S.kt": SERVICE, "U.kt": "import other.http.Header\nclass U\n"}
        self.assertEqual(check(files, "import other.http.Query\nclass T\n"), [])

    def test_a_library_family_the_repository_uses_is_not_second_guessed(self):
        files = {"S.kt": "import com.acme.ui.Text\nclass S\n"}
        # Same first two segments: a sibling package of a family in use (a
        # material3 next to a material import in an API migration).
        self.assertEqual(check(files, "import com.acme.uikit.Text\nclass T\n"), [])
        [issue] = check(files, "import other.lib.Text\nclass T\n")
        self.assertIn("com.acme.ui.Text", " ".join(issue["details"]))

    def test_aliases_wildcards_and_statics_are_read_correctly(self):
        code = "import a.b.C as D\nimport a.b.*\nimport static a.b.E.f\nimport g.h.I;\n"
        self.assertEqual(imports_in(code), {"a.b.C", "g.h.I"})

    def test_the_semantic_validation_reports_it_as_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "S.kt").write_text(SERVICE, encoding="utf-8")
            result = validate_coordinated_semantics(
                {"repository_path": str(root)},
                [{"source_file_path": "app/src/test/T.kt", "symbol": "T", "edit_kind": "create",
                  "original_code": "", "corrected_code": "import com.squareup.retrofit2.http.Query\nclass T\n",
                  "reason": "test"}],
            )
        self.assertIn("IMPORT_PACKAGE_NOT_IN_REPOSITORY", [e["code"] for e in result["errors"]])

    def test_an_unreadable_repository_never_blocks(self):
        from cognalys.llm.semantic_validation import import_issues
        self.assertEqual(import_issues({"repository_path": "/nonexistent"}, []), [])
        self.assertEqual(import_issues({}, []), [])


if __name__ == "__main__":
    unittest.main()
