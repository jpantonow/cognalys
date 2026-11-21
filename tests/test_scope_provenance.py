"""A specification's scope written for one app is marked when reused.

Generated specifications describe their scope from the representative
finding they were generated for, often by naming its class. That text then
reached every later finding of the rule as if it described their code: the
com.hmdm.launcher XapkUtils.extract finding was adjudicated against a scope
about me.blog.korn123.easydiary's ZipHelper and ended as
incomplete_multi_file_scope. These tests use that ZipSlipSpec scope as it was
before run_20260929_231422 regenerated the file with a rule-level scope; the
real file is no longer an example of the problem.
"""
import json
import unittest

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.pipeline_architecture import with_scope_provenance  # noqa: E402

ZIP_SLIP = {
    "spec_id": "ZipSlipSpec",
    "applies_to_types": ["java.util.zip.ZipInputStream", "java.io.File"],
    "events": [{"name": "read_entry", "api_patterns": ["getNextEntry()"]}],
    "semantic_scope": (
        "The reported class is me.blog.korn123.easydiary.helper.ZipHelper and "
        "the reported method is decompress. The reported detector behavior "
        "concerns ZIP-entry-name-to-write-sink dataflow."
    ),
}


class ScopeProvenanceTests(unittest.TestCase):

    def test_a_scope_about_another_app_is_marked(self):
        marked = with_scope_provenance(ZIP_SLIP, "com.hmdm.launcher.util.XapkUtils")
        provenance = marked["semantic_scope_provenance"]
        self.assertEqual(provenance["status"], "written_for_another_finding")
        self.assertIn("me.blog.korn123.easydiary.helper.ZipHelper",
                      provenance["named_application_classes"])
        # The rule description is kept; only its provenance is added.
        self.assertEqual(marked["semantic_scope"], ZIP_SLIP["semantic_scope"])

    def test_the_representative_finding_itself_is_not_marked(self):
        marked = with_scope_provenance(
            ZIP_SLIP, "me.blog.korn123.easydiary.helper.ZipHelper",
        )
        self.assertNotIn("semantic_scope_provenance", marked)

    def test_platform_and_governed_types_are_not_application_classes(self):
        specification = {
            "semantic_scope": "Observes java.util.zip.ZipInputStream and "
                              "okhttp3.OkHttpClient.Builder calls.",
            "applies_to_types": ["okhttp3.OkHttpClient"],
            "events": [{"api_patterns": ["okhttp3.OkHttpClient.Builder"]}],
        }
        self.assertNotIn("semantic_scope_provenance",
                         with_scope_provenance(specification, "a.b.C"))

    def test_the_file_contents_are_not_modified(self):
        before = json.dumps(ZIP_SLIP, sort_keys=True)
        with_scope_provenance(ZIP_SLIP, "com.hmdm.launcher.util.XapkUtils")
        self.assertEqual(json.dumps(ZIP_SLIP, sort_keys=True), before)


if __name__ == "__main__":
    unittest.main()
