import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.extraction.detector_emitter import detector_emitter  # noqa: E402

CODES = ("spec,code,error_type,site_kind,event,file_line,label\n"
         "CipherSpec,CIPHER-CONSTR-00,UnsatisfiedConstraint,CONSTR,i2,CipherSpec.mop:9,violation\n")
MOP = "\n".join([
    "spec CipherSpec {",
    "   event i2 before(int mode, Key key, Cipher c):",
    "     call(void Cipher.init(int, Key, ..)) {",
    "        // The direct PBKDF2WithHmacSHA* -> Cipher(\"AES/...\") route matches under",
    "        // neither spelling: the conforming path is the re-wrap, getEncoded() ->",
    "        // new SecretKeySpec(bytes, \"AES\").",
    "        PredicateVerdict origin = validate(GENERATED_KEY, key, alg(c.getAlgorithm()));",
    "        if (origin == PredicateVerdict.VIOLATED) {",
    "            addError(\"code=CIPHER-CONSTR-00\");",
    "        }",
    "   }",
    "}",
])


class DetectorEmitterTests(unittest.TestCase):
    """FreeOTP (2026-10-27): RVSec's own comment at the reporting line named
    the re-wrap as the conforming route; the planner, without it, replaced
    the password-derived key and forbade the wrapper."""

    def catalog(self, directory, **entry):
        path = Path(directory) / "detector_emitters.json"
        path.write_text(json.dumps({"detectors": [{
            "name": "rvsec", "code_pattern": "^[A-Z0-9]+-[A-Z]+-\\d+$",
            "codes_file": "codes.csv", **entry}]}), encoding="utf-8")
        return path

    def test_the_published_source_gives_the_reporting_site(self):
        files = {"https://x/codes.csv": CODES, "https://x/CipherSpec.mop": MOP}
        with tempfile.TemporaryDirectory() as directory:
            found = detector_emitter({"detector_code": "CIPHER-CONSTR-00"}, fetch=files.get,
                                     emitters_path=self.catalog(directory, url_template="https://x/{file}"))
        self.assertEqual((found["status"], found["file"], found["line"]), ("found", "CipherSpec.mop", 9))
        self.assertTrue(found["excerpt"].lstrip().startswith("event i2"))
        self.assertIn("new SecretKeySpec(bytes, \"AES\")", found["excerpt"])
        self.assertIn("code=CIPHER-CONSTR-00", found["excerpt"])

    def test_a_local_checkout_is_read_first(self):
        with tempfile.TemporaryDirectory() as directory:
            specs = Path(directory) / "checkout/specs"
            specs.mkdir(parents=True)
            (specs / "codes.csv").write_text(CODES, encoding="utf-8")
            (specs / "CipherSpec.mop").write_text(MOP, encoding="utf-8")
            catalog = self.catalog(directory, home_env="RVSEC_HOME_TEST", checkout_path="specs",
                                   url_template="https://unused/{file}")
            with mock.patch.dict(os.environ, {"RVSEC_HOME_TEST": str(Path(directory) / "checkout")}):
                found = detector_emitter({"detector_code": "CIPHER-CONSTR-00"},
                                         fetch=lambda url: self.fail(url), emitters_path=catalog)
        self.assertEqual(found["status"], "found")

    def test_what_cannot_be_read_is_a_status(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog = self.catalog(directory, url_template="https://x/{file}")
            self.assertEqual(detector_emitter({}, fetch=lambda url: None,
                                              emitters_path=catalog)["status"], "no_detector_code")
            self.assertEqual(detector_emitter({"detector_code": "CIPHER-CONSTR-00"},
                                              fetch=lambda url: None,
                                              emitters_path=catalog)["status"], "unavailable")
            self.assertEqual(detector_emitter({"detector_code": "semgrep.rule"},
                                              fetch=lambda url: None,
                                              emitters_path=catalog)["status"], "no_detector_for_code")


class ReportingDetectorSiteTests(unittest.TestCase):
    """Adjudication, planning and generation read the same excerpt, fetched once."""

    def test_found_once_and_absent_when_not_found(self):
        from cognalys.llm import fix_generation_common

        calls = []
        site = {"status": "found", "file": "CipherSpec.mop", "line": 9, "excerpt": "x"}
        with mock.patch("cognalys.extraction.detector_emitter.detector_emitter",
                        side_effect=lambda error: calls.append(1) or site):
            error = {"detector_code": "CIPHER-CONSTR-00"}
            self.assertEqual(fix_generation_common.reporting_detector_site(error),
                             {"reporting_detector_site": site})
            fix_generation_common.reporting_detector_site(error)
        self.assertEqual(len(calls), 1)
        with mock.patch("cognalys.extraction.detector_emitter.detector_emitter",
                        return_value={"status": "unavailable"}):
            self.assertEqual(fix_generation_common.reporting_detector_site({"detector_code": "X-Y-0"}), {})


if __name__ == "__main__":
    unittest.main()
