import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils.preflight import (  # noqa: E402
    BLOCKING_PYFLAKES_MESSAGES,
    _blocking_message_types,
    check_declared_dependencies,
    check_static_analysis,
    run_preflight,
)


class StaticAnalysisTests(unittest.TestCase):
    """The two defects that ended a run each cost four minutes of model time.

    run_20260907_180505 raised NameError for 'reported_violation' and
    run_20260907_185056 raised UnboundLocalError for 'violation', both after
    the finding's evidence had already been paid for.
    """

    def _root_with(self, source: str) -> tempfile.TemporaryDirectory:
        directory = tempfile.TemporaryDirectory()
        src = Path(directory.name) / "src"
        src.mkdir()
        (src / "module.py").write_text(source, encoding="utf-8")
        return directory

    def test_an_undefined_name_blocks_the_run(self):
        with self._root_with(
            "def analyse():\n    return reported_violation\n"
        ) as name:
            problems = check_static_analysis(Path(name))
        self.assertTrue(problems)
        self.assertIn("reported_violation", " ".join(problems))

    def test_a_possibly_unbound_local_blocks_the_run(self):
        source = (
            "def analyse(error):\n"
            "    if error:\n"
            "        violation = error\n"
            "    del violation\n"
            "    return violation\n"
        )
        with self._root_with(source) as name:
            problems = check_static_analysis(Path(name))
        self.assertTrue(problems)
        self.assertIn("violation", " ".join(problems))

    def test_an_unused_import_does_not_block_the_run(self):
        """This project re-exports on purpose; blocking on style would make
        the gate something operators skip rather than something they trust."""
        with self._root_with("import json\n\n\ndef analyse():\n    return 1\n") as name:
            self.assertEqual(check_static_analysis(Path(name)), [])

    def test_a_file_that_cannot_be_parsed_is_reported(self):
        with self._root_with("def analyse(:\n") as name:
            problems = check_static_analysis(Path(name))
        self.assertTrue(any("syntax error" in problem for problem in problems))

    def test_every_blocking_message_name_exists_in_the_installed_pyflakes(self):
        """A name pyflakes dropped would silently stop being checked."""
        resolved, unknown = _blocking_message_types()
        self.assertEqual(unknown, [])
        self.assertEqual(len(resolved), len(BLOCKING_PYFLAKES_MESSAGES))


class DeclaredDependencyTests(unittest.TestCase):
    """tree-sitter was declared and absent, so semantic_index fell back to its
    lexical path on every finding without anything reporting it."""

    def _root_with_requirements(self, text: str):
        directory = tempfile.TemporaryDirectory()
        (Path(directory.name) / "requirements.txt").write_text(
            text, encoding="utf-8",
        )
        return directory

    def test_a_missing_requirement_is_reported_with_the_interpreter(self):
        with self._root_with_requirements(
            "json\nthis-package-does-not-exist==1.0\n"
        ) as name:
            problems = check_declared_dependencies(Path(name))
        self.assertEqual(len(problems), 1)
        self.assertIn("this_package_does_not_exist", problems[0])
        self.assertIn(sys.executable, problems[0])

    def test_importable_requirements_pass(self):
        with self._root_with_requirements(
            "# a comment\njson\nunittest>=1.0\n\n"
        ) as name:
            self.assertEqual(check_declared_dependencies(Path(name)), [])

    def test_a_missing_requirements_file_is_itself_a_problem(self):
        with tempfile.TemporaryDirectory() as name:
            self.assertTrue(check_declared_dependencies(Path(name)))

    def test_a_missing_dependency_stops_the_later_checks(self):
        """One root cause, one message: static analysis would fail for the
        missing dependency and say nothing useful about the code."""
        with self._root_with_requirements(
            "this-package-does-not-exist\n"
        ) as name:
            report = run_preflight(Path(name))
        self.assertFalse(report.ok)
        self.assertEqual(report.checks_run, ["declared dependencies"])


class PreflightScopeTests(unittest.TestCase):
    """The preflight checks the code, and stops there.

    It ran the unit suite once, and the failure mode showed up the same day:
    a run started at 12:58:11 while the tree was mid-edit, and was refused
    because two tests lagged two minutes behind the source they covered.
    Nothing about that predicted anything about the run. Green tests are the
    suite's business at the moment the code changes, not a toll booth in
    front of a pipeline run, so the check is gone and stays gone.
    """

    def test_it_does_not_run_the_unit_suite(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "requirements.txt").write_text("", encoding="utf-8")
            # A tests/ directory that would fail loudly if it were collected.
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_explode.py").write_text(
                "import unittest\n\n\n"
                "class T(unittest.TestCase):\n"
                "    def test_fails(self):\n"
                "        self.fail('the preflight must never run me')\n",
                encoding="utf-8",
            )
            report = run_preflight(root)
        self.assertNotIn("test suite", report.checks_run)
        self.assertEqual(
            report.checks_run, ["declared dependencies", "static analysis"]
        )
        self.assertTrue(report.ok, report.problems)


class InstalledPackageRequirementsTests(unittest.TestCase):
    """A package installed into site-packages answers for its own declared
    dependencies, not for the experiment's requirements.txt."""

    def test_an_installed_package_is_checked_against_what_it_declares(self):
        import cognalys

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("surely_not_installed_xyz\n",
                                                   encoding="utf-8")
            site = Path(directory) / "site-packages" / "cognalys" / "__init__.py"
            with patch.object(cognalys, "__file__", str(site)), \
                    patch("importlib.metadata.requires",
                          return_value=["requests", 'pandas; extra == "research"']):
                self.assertEqual(check_declared_dependencies(root), [])
            # From a checkout, requirements.txt still applies.
            self.assertTrue(check_declared_dependencies(root))


if __name__ == "__main__":
    unittest.main()
