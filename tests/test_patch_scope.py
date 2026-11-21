import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils.patch_scope import PatchScope, is_test_path  # noqa: E402


PROD = "app/src/main/java/me/blog/korn123/easydiary/helper/ZipHelper.kt"
TEST = ("app/src/androidTest/java/me/blog/korn123/easydiary/helper/"
        "ZipHelperTest.kt")
OTHER = "app/src/main/java/me/blog/korn123/easydiary/helper/Other.kt"


def _edits(*paths):
    return [{"source_file_path": path} for path in paths]


class TestPathClassificationTests(unittest.TestCase):
    """One definition, where there used to be four.

    migration_policy held two (different from each other),
    pipeline_architecture a third and adjudication a fourth.
    """

    def test_a_source_set_makes_a_path_a_test(self):
        for path in (TEST, "lib/src/test/java/p/Thing.java",
                     "m/src/androidTest/kotlin/p/Thing.kt"):
            with self.subTest(path=path):
                self.assertTrue(is_test_path(path))

    def test_production_paths_are_not_tests(self):
        for path in (PROD, OTHER, "app/src/main/java/p/TestUtils.java"):
            with self.subTest(path=path):
                self.assertFalse(is_test_path(path))


class MultiFileMeansProductionFilesTests(unittest.TestCase):
    """A required regression test does not make a fix multi-file.

    Counting it did, so a one-production-file plan reported a coordinated
    multi-file change while the adjudicator answered FIX_SUPPORTED -- a
    contradiction validate_multi_file_scope rejects outright. That is why
    me.blog.korn123.easydiary's Zip Slip finding abstained with
    INCOMPLETE_MULTI_FILE_SCOPE in run_20260908_151705, on a plan of exactly
    ZipHelper.kt plus a new ZipHelperTest.kt.
    """

    def test_one_production_file_plus_its_test_is_not_multi_file(self):
        scope = PatchScope.from_required_edits(_edits(PROD, TEST))
        self.assertFalse(scope.is_multi_file)
        self.assertEqual(scope.production_files, frozenset({PROD}))
        self.assertEqual(scope.test_files, frozenset({TEST}))
        self.assertEqual(scope.all_files, frozenset({PROD, TEST}))

    def test_two_production_files_are_multi_file(self):
        scope = PatchScope.from_required_edits(_edits(PROD, OTHER, TEST))
        self.assertTrue(scope.is_multi_file)

    def test_tests_alone_are_never_multi_file(self):
        self.assertFalse(PatchScope.from_required_edits(_edits(TEST)).is_multi_file)

    def test_an_empty_plan_is_empty(self):
        for plan in ([], None, [{"source_file_path": "  "}], ["not a dict"]):
            with self.subTest(plan=plan):
                scope = PatchScope.from_required_edits(plan)
                self.assertEqual(scope.all_files, frozenset())
                self.assertFalse(scope.is_multi_file)

    def test_the_action_label_matches_the_classification(self):
        scope = PatchScope.from_required_edits(_edits(PROD, TEST))
        self.assertEqual(scope.action_for(PROD), "edit")
        self.assertEqual(scope.action_for(TEST), "required_test")

    def test_a_repeated_path_is_counted_once(self):
        scope = PatchScope.from_required_edits(_edits(PROD, PROD))
        self.assertFalse(scope.is_multi_file)


if __name__ == "__main__":
    unittest.main()
