import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (scripts/ and src/ on sys.path)


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "cognalys" / "specifications" / "enrich_spec_context.py"
SPEC = importlib.util.spec_from_file_location("enrich_spec_context", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class RequiredSpecificationsTests(unittest.TestCase):
    def test_filters_coverage_to_the_selected_project(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_file = Path(directory) / "findings.csv"
            csv_file.write_text(
                "apk,spec\n"
                "target.apk,SSLContextSpec\n"
                "other.apk,CipherSpec\n",
                encoding="utf-8",
            )
            self.assertEqual(
                MODULE.required_specifications(csv_file, "target.apk"),
                {"SSLContextSpec"},
            )


if __name__ == "__main__":
    unittest.main()
