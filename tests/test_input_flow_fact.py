"""Editable text reaching a parser: what a checkout settles about invalid input.

`onCreate` of Auto-Shine abstained in three runs in a row because the adjudicator
found "a feasible non-parsable argument" and "no effective handler" unestablished,
though both are readable from the method. The fact is not tied to that finding: it
is any parse call fed straight from a widget whose type ends in EditText.
"""
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.evidence_facts import user_input_parse_flow  # noqa: E402


JAVA_FIELDS = "class A {\n    EditText etOne, etTwo;\n    TextView label;\n}\n"
JAVA_LISTENER = """
protected void onCreate(Bundle b) {
    btnSave.setOnClickListener(arg0 -> {
        sett.one = Integer.parseInt(etOne.getText().toString());
        sett.two = Integer.parseInt(etTwo.getText().toString());
        sett.save();
    });
}
"""


class InputFlowTests(unittest.TestCase):
    def test_unguarded_widget_text_in_a_listener_is_established(self):
        result = user_input_parse_flow(JAVA_LISTENER, JAVA_FIELDS)
        self.assertEqual(result["status"], "editable_text_reaches_parser_unguarded")
        self.assertEqual([c["widget"] for c in result["parse_calls"]], ["etOne", "etTwo"])
        self.assertEqual(result["unguarded_in_framework_callback"], 2)
        self.assertTrue(all(not c["enclosed_by_try_that_catches"] for c in result["parse_calls"]))
        self.assertIn("validation_search", result["bound"])

    def test_a_catching_try_guards_only_the_calls_it_encloses(self):
        body = """
void save() {
    try {
        a = Integer.parseInt(etOne.getText().toString());
    } catch (NumberFormatException e) {
        a = 0;
    }
    b = Integer.parseInt(etTwo.getText().toString());
}
"""
        result = user_input_parse_flow(body, JAVA_FIELDS)
        guarded = {c["widget"]: c["enclosed_by_try_that_catches"] for c in result["parse_calls"]}
        self.assertEqual(guarded, {"etOne": True, "etTwo": False})
        self.assertEqual(result["status"], "editable_text_reaches_parser_unguarded")
        self.assertEqual(result["unguarded_in_framework_callback"], 0)

    def test_a_catch_of_an_unrelated_exception_does_not_guard(self):
        body = """
void save() {
    try {
        a = Integer.parseInt(etOne.getText().toString());
    } catch (IOException e) {
    }
}
"""
        self.assertEqual(
            user_input_parse_flow(body, JAVA_FIELDS)["status"],
            "editable_text_reaches_parser_unguarded")

    def test_everything_guarded_is_reported_as_guarded(self):
        body = """
void save() {
    try { a = Integer.parseInt(etOne.getText().toString()); } catch (Exception e) { }
}
"""
        self.assertEqual(
            user_input_parse_flow(body, JAVA_FIELDS)["status"],
            "editable_text_reaches_parser_guarded")

    def test_a_widget_that_is_not_editable_or_not_a_widget_is_not_a_source(self):
        body = """
void f() {
    a = Integer.parseInt(label.getText().toString());
    b = Integer.parseInt(config.get("x"));
}
"""
        self.assertEqual(
            user_input_parse_flow(body, JAVA_FIELDS)["status"], "no_editable_text_parse")

    def test_a_call_outside_any_callback_is_not_marked_as_one(self):
        body = "void f() {\n    a = Long.parseLong(etOne.getText().toString());\n}\n"
        result = user_input_parse_flow(body, JAVA_FIELDS)
        self.assertEqual(result["parse_calls"][0]["api"], "Long.parseLong")
        self.assertEqual(result["unguarded_in_framework_callback"], 0)

    def test_an_on_method_body_is_a_framework_callback(self):
        body = "public void onClick(View v) {\n    a = Integer.parseInt(etOne.getText().toString());\n}\n"
        self.assertEqual(
            user_input_parse_flow(body, JAVA_FIELDS)["unguarded_in_framework_callback"], 1)

    def test_kotlin_conversions_and_typed_properties(self):
        fields = "class A {\n    private lateinit var amount: EditText\n}\n"
        body = "fun setup() {\n    save.setOnClickListener {\n        val n = amount.text.toString().toInt()\n    }\n}\n"
        result = user_input_parse_flow(body, fields)
        self.assertEqual(result["status"], "editable_text_reaches_parser_unguarded")
        self.assertEqual(result["parse_calls"][0]["api"], "toInt")
        self.assertEqual(result["unguarded_in_framework_callback"], 1)

    def test_comments_and_strings_are_not_code(self):
        body = 'void f() {\n    // Integer.parseInt(etOne.getText().toString())\n    log("Integer.parseInt(etOne.getText())");\n}\n'
        self.assertEqual(user_input_parse_flow(body, JAVA_FIELDS)["status"], "no_editable_text_parse")

    def test_an_empty_body_says_so(self):
        self.assertEqual(user_input_parse_flow("", JAVA_FIELDS)["status"], "no_method_body")


ACTIVITY = """package app;

class Main extends Activity {
    private EditText etOne, etTwo;

    protected void onCreate(Bundle b) {
        etOne = findViewById(R.id.et_one);
        etTwo = (EditText) findViewById(R.id.et_two);
%(extra)s
        btnSave.setOnClickListener(v -> {
            sett.one = Integer.parseInt(etOne.getText().toString());
            sett.two = Integer.parseInt(etTwo.getText().toString());
        });
    }
}
"""
LAYOUT = """<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android">
    <EditText
        android:id="@+id/et_one"
        android:inputType="number"
        android:maxLength="4" />
    <EditText android:id="@+id/et_two" android:inputType="number" />
</LinearLayout>
"""


class ValidationSearchTests(unittest.TestCase):
    """What the repository does about the widgets, as a fact rather than a silence."""

    def search(self, extra: str = "", files: dict | None = None, body: str | None = None):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            activity = ACTIVITY % {"extra": extra}
            (root / "app/src/main/java/app").mkdir(parents=True)
            (root / "app/src/main/java/app/Main.java").write_text(activity, encoding="utf-8")
            (root / "app/src/main/res/layout").mkdir(parents=True)
            (root / "app/src/main/res/layout/activity_main.xml").write_text(LAYOUT, encoding="utf-8")
            for relative, text in (files or {}).items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            method = body or activity[activity.index("protected void onCreate"):]
            return user_input_parse_flow(method, activity, root)["validation_search"]

    def test_nothing_validating_the_widgets_is_stated_as_a_fact(self):
        result = self.search()
        self.assertTrue(result["searched"])
        self.assertEqual(result["conclusion"], "no_validation_found_for_any_widget")
        self.assertEqual(result["application_level_exception_handlers"], [])
        one = result["widgets"]["etOne"]
        self.assertEqual(one["view_id"], "et_one")
        self.assertEqual(one["layout"]["attributes"], {"inputType": "number", "maxLength": "4"})
        self.assertEqual(result["widgets"]["etTwo"]["layout"]["attributes"], {"inputType": "number"})

    def test_a_watcher_or_filter_on_a_widget_is_reported_for_that_widget_only(self):
        result = self.search("        etOne.addTextChangedListener(watcher);\n")
        self.assertEqual(result["conclusion"], "validation_found_for: etOne")
        self.assertTrue(result["widgets"]["etOne"]["validation_calls"])
        self.assertEqual(result["widgets"]["etTwo"]["validation_calls"], [])

    def test_an_emptiness_check_in_the_method_counts(self):
        body = (
            "void save() {\n"
            "    if (etOne.getText().toString().isEmpty()) return;\n"
            "    a = Integer.parseInt(etOne.getText().toString());\n"
            "}\n"
        )
        result = self.search(body=body)
        self.assertTrue(result["widgets"]["etOne"]["emptiness_check_in_method"])
        self.assertEqual(result["conclusion"], "validation_found_for: etOne")

    def test_a_widget_handed_to_a_helper_leaves_the_question_open(self):
        result = self.search("        validate(etOne, etTwo);\n")
        self.assertTrue(result["conclusion"].startswith("widget_passed_to_helpers_that_may_validate"))

    def test_a_global_exception_handler_is_listed(self):
        files = {"app/src/main/java/app/App.java": (
            "class App {\n  void f() { Thread.setDefaultUncaughtExceptionHandler(h); }\n}\n"
        )}
        result = self.search(files=files)
        self.assertEqual(len(result["application_level_exception_handlers"]), 1)
        self.assertIn("App.java", result["application_level_exception_handlers"][0])

    def test_without_a_repository_there_is_no_search(self):
        flow = user_input_parse_flow(JAVA_LISTENER, JAVA_FIELDS)
        self.assertNotIn("validation_search", flow)


if __name__ == "__main__":
    unittest.main()
