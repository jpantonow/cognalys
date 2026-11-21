import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)


def _load(name: str, relative_path: str):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# The same deterministic shape guard is intentionally duplicated across the
# three modules that read-modify-write execution_report.json, so each copy
# is exercised here rather than assuming they stay in sync.
MODULES = [
    _load("solution_applicator_guard_test", "src/cognalys/solutions/solution_applicator.py"),
    _load("validate_applied_solutions_guard_test", "src/cognalys/validation/applied_solutions.py"),
    _load("repair_validation_failures_guard_test", "src/cognalys/validation/repair.py"),
]


class ExecutionReportGuardTests(unittest.TestCase):
    def test_accepts_a_well_formed_report(self):
        for module in MODULES:
            with self.subTest(module=module.__name__):
                issues = module.validate_execution_report({
                    "per_solution_details": [
                        {"status": "SUCCESS", "finding_id": "abc123"},
                        {"status": "FAILED"},
                    ],
                })
                self.assertEqual(issues, [])

    def test_flags_a_success_entry_missing_finding_id(self):
        for module in MODULES:
            with self.subTest(module=module.__name__):
                issues = module.validate_execution_report({
                    "per_solution_details": [{"status": "SUCCESS"}],
                })
                self.assertTrue(issues)

    def test_flags_a_non_list_per_solution_details(self):
        for module in MODULES:
            with self.subTest(module=module.__name__):
                issues = module.validate_execution_report({
                    "per_solution_details": "not-a-list",
                })
                self.assertTrue(issues)


class AtomicWriteTests(unittest.TestCase):
    def test_solution_applicator_write_is_atomic_and_readable(self):
        import tempfile
        import json

        module = MODULES[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "execution_report.json"
            module.write_execution_report_atomic(path, {"a": 1})
            self.assertEqual(json.loads(path.read_text()), {"a": 1})
            self.assertFalse(path.with_suffix(".json.tmp").exists())

    def test_validate_applied_solutions_write_is_atomic_and_readable(self):
        import tempfile
        import json

        module = MODULES[1]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "execution_report.json"
            module.write_json_atomic(path, {"a": 1})
            self.assertEqual(json.loads(path.read_text()), {"a": 1})
            self.assertFalse(path.with_suffix(".json.tmp").exists())


if __name__ == "__main__":
    unittest.main()
