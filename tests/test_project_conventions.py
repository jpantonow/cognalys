import tempfile
import unittest
from pathlib import Path


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.solutions.project_conventions import (  # noqa: E402
    describe_text_convention, user_visible_text_convention,
)


def _project(root: Path, activity: str, strings: bool = True) -> Path:
    source = root / "app" / "src" / "main" / "java" / "org" / "app" / "MainActivity.java"
    source.parent.mkdir(parents=True)
    source.write_text(activity, encoding="utf-8")
    if strings:
        values = root / "app" / "src" / "main" / "res" / "values"
        values.mkdir(parents=True)
        (values / "strings.xml").write_text("<resources></resources>", encoding="utf-8")
    return source


class UserVisibleTextTests(unittest.TestCase):
    """Auto-Shine reads every Toast text from strings.xml; a revision did not."""

    def test_a_module_that_reads_its_text_from_resources_says_so(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = _project(root, (
                "btn.setText(R.string.show_config);\n"
                "Toast.makeText(this, getResources().getString(R.string.starting), 0).show();\n"
                "builder.setMessage(R.string.permission_request);\n"))
            convention = user_visible_text_convention(root, source)
            self.assertEqual(convention["convention"], "string_resources")
            self.assertEqual(convention["strings_file"], "app/src/main/res/values/strings.xml")
            text = describe_text_convention(convention)
            self.assertIn("strings.xml", text)
            self.assertIn("R.string.starting", text)

    def test_literals_or_no_strings_file_ask_for_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = _project(root, (
                'Toast.makeText(this, "Saved", 0).show();\n'
                'title.setText("Settings");\nbtn.setText(R.string.ok);\n'))
            convention = user_visible_text_convention(root, source)
            self.assertEqual(convention["convention"], "literals")
            self.assertEqual(describe_text_convention(convention), "")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = _project(root, "a(R.string.x); b(R.string.y); c(R.string.z);\n", strings=False)
            self.assertEqual(user_visible_text_convention(root, source)["convention"], "undetermined")


if __name__ == "__main__":
    unittest.main()
