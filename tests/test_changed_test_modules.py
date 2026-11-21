"""Changed test sources select their module's test task, including a root-level project."""
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.validation.applied_solutions import (  # noqa: E402
    changed_test_modules,
    invoked_gradle_root,
    module_test_task,
)


class ChangedTestModulesTests(unittest.TestCase):
    def test_a_root_level_unit_test_selects_the_root_module(self):
        android, unit = changed_test_modules([
            "src/main/java/org/example/Manager.java",
            "src/test/java/org/example/ManagerTest.java",
        ])
        self.assertEqual((android, unit), (set(), {""}))

    def test_module_tests_keep_their_module(self):
        android, unit = changed_test_modules([
            "app/src/test/java/A.java", "core/security/src/androidTest/java/B.kt",
        ])
        self.assertEqual(android, {"core/security"})
        self.assertEqual(unit, {"app"})

    def test_production_sources_select_nothing(self):
        self.assertEqual(changed_test_modules(["app/src/main/java/A.java"]), (set(), set()))

    def test_a_module_keeps_its_case(self):
        # The module names a directory on a case-sensitive worktree and a
        # Gradle project; only the source-set match ignores case.
        android, unit = changed_test_modules([
            "myExpenses/src/androidTest/java/A.kt", "myExpenses/src/Test/java/B.kt",
        ])
        self.assertEqual((android, unit), ({"myExpenses"}, {"myExpenses"}))


class ModuleTestTaskTests(unittest.TestCase):
    """Test tasks are named from the root Gradle runs from, not the repository.

    BWT's settings file sits in comencryptbwt/, and the repository-relative
    ':comencryptbwt:app:assembleDebugAndroidTest' was refused before the
    patch's test compiled (rvsec_bwt_20261024).
    """

    def _repository(self, directory: str) -> Path:
        worktree = Path(directory)
        root = worktree / "comencryptbwt"
        (root / "app").mkdir(parents=True)
        (root / "settings.gradle.kts").write_text('include(":app")\n', encoding="utf-8")
        (root / "app" / "build.gradle.kts").write_text("android {}\n", encoding="utf-8")
        return worktree

    def test_a_settings_file_one_level_down_is_the_root(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = self._repository(directory)
            root = invoked_gradle_root(worktree)
            self.assertEqual(root, worktree / "comencryptbwt")
            android, unit = changed_test_modules([
                "comencryptbwt/app/src/androidTest/java/A.kt",
                "comencryptbwt/app/src/test/java/B.kt",
            ])
            self.assertEqual(
                module_test_task(worktree, root, next(iter(android)),
                                 "assembleDebugAndroidTest"),
                ":app:assembleDebugAndroidTest",
            )
            self.assertEqual(
                module_test_task(worktree, root, next(iter(unit)), "testDebugUnitTest"),
                ":app:testDebugUnitTest",
            )

    def test_a_module_outside_the_root_gets_no_task(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = self._repository(directory)
            (worktree / "tools").mkdir()
            root = invoked_gradle_root(worktree)
            self.assertIsNone(
                module_test_task(worktree, root, "tools", "testDebugUnitTest")
            )

    def test_a_root_level_project_keeps_the_plain_task(self):
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory)
            (worktree / "settings.gradle").write_text("", encoding="utf-8")
            root = invoked_gradle_root(worktree)
            self.assertEqual(
                module_test_task(worktree, root, "", "testDebugUnitTest"),
                "testDebugUnitTest",
            )
            self.assertEqual(
                module_test_task(worktree, root, "core/security",
                                 "assembleDebugAndroidTest"),
                ":core:security:assembleDebugAndroidTest",
            )

    def test_a_worktree_that_does_not_exist_is_its_own_root(self):
        missing = Path(tempfile.gettempdir()) / "no-such-worktree-g5"
        self.assertEqual(invoked_gradle_root(missing), missing)


if __name__ == "__main__":
    unittest.main()
