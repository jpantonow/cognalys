import unittest


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils.artifact_names import (  # noqa: E402
    filename_component,
    finding_artifact_stem,
    legacy_finding_artifact_stem,
)


class ArtifactNameTests(unittest.TestCase):
    """org.cry.otp's hmac_sha is reported under two specs; in
    run_20261009_012517 one finding's *_pr.json and previews overwrote the
    other's, because the name stopped at the method."""

    def test_two_specs_of_one_method_get_two_names(self):
        mac = finding_artifact_stem("org.cry.otp_31.apk", "hmac_sha", "MacSpec")
        key = finding_artifact_stem("org.cry.otp_31.apk", "hmac_sha", "SecretKeySpecSpec")
        self.assertNotEqual(mac, key)
        self.assertEqual(mac, "org.cry.otp_31.apk_hmac_sha_MacSpec")

    def test_names_stay_file_safe(self):
        self.assertEqual(filename_component("<init>"), "init")
        self.assertEqual(filename_component("appModule$lambda$0$3"), "appModule_lambda_0_3")
        self.assertEqual(finding_artifact_stem("a.apk", "<clinit>", ""), "a.apk_clinit_spec")

    def test_the_legacy_name_is_what_older_runs_wrote(self):
        self.assertEqual(legacy_finding_artifact_stem("org.cry.otp_31.apk", "<init>"),
                         "org.cry.otp_31.apk_init")


if __name__ == "__main__":
    unittest.main()
