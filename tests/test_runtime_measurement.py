"""A runtime detector's measurement becomes citable evidence; a static report does not."""
import unittest

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.evidence_packet import runtime_measurement  # noqa: E402
from cognalys.llm.fix_generation_common import REPOSITORY_EVIDENCE_PREFIXES  # noqa: E402


class RuntimeMeasurementTests(unittest.TestCase):
    def test_a_runtime_report_keeps_the_measured_value(self):
        measured = runtime_measurement({"tool": "ape", "detector_context": {
            "value": "8192", "source_location": "ScepClient.java:125",
            "runtime_observation": "Reported in 1 run(s) of the app.",
        }})
        self.assertEqual(measured["value"], "8192")
        self.assertEqual(measured["source_location"], "ScepClient.java:125")
        self.assertIn("Measured while the application ran", measured["meaning"])

    def test_a_static_report_has_no_measurement(self):
        self.assertEqual(runtime_measurement({"detector_context": {
            "value": "SHA1", "source_location": "Helper.java:3307"}}), {})
        self.assertEqual(runtime_measurement({}), {})

    def test_it_grounds_a_claim_in_the_application(self):
        self.assertIn("RUN", REPOSITORY_EVIDENCE_PREFIXES)


if __name__ == "__main__":
    unittest.main()
