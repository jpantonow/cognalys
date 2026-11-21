import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.semantic_validation import (  # noqa: E402
    _validate_patch_plan,
    planned_symbol_mismatches,
)


OCR_FORM_ENTITY = """package org.nick.wwwjdic.ocr;

public class OcrFormEntity extends AbstractHttpEntity {

    public OcrFormEntity(Bitmap bitmap, int quality, String eclass,
            Integer numberOfTopCandidates) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(BUFF_SIZE);
        bitmap.compress(CompressFormat.JPEG, quality, baos);
        baos.close();
    }

    public OcrFormEntity(Bitmap img, String eclass,
            Integer numberOfTopCandidates) throws IOException {
        this(img, IMG_QUALITY, eclass, numberOfTopCandidates);
    }

    public OcrFormEntity(Bitmap img) throws IOException {
        this(img, IMG_QUALITY, ECLASS_AUTO, null);
    }

    public void writeTo(OutputStream os) throws IOException {
        buff.writeTo(os);
    }
}
"""


class PlannedSymbolTests(unittest.TestCase):
    """A planned symbol must name a signature its file declares.

    nelenkov/wwwjdic's plan targeted OcrFormEntity(Bitmap bitmap, String lang,
    String profile, boolean text), which OcrFormEntity.java never declared,
    and the generated regression test searched the source for exactly that
    parameter list (run_20260915_175048).
    """

    PATH = "wwwjdic/src/org/nick/wwwjdic/ocr/OcrFormEntity.java"
    INVENTED = "OcrFormEntity(Bitmap bitmap, String lang, String profile, boolean text)"

    def _packet(self):
        return {"evidence_catalog": [{
            "evidence_id": "SRC-001", "kind": "target_source",
            "trust_level": "repository_exact_source",
            "data": {"source_file_path": self.PATH, "content": OCR_FORM_ENTITY},
        }]}

    def _plan(self, symbol, **extra):
        edit = {"source_file_path": self.PATH, "symbol": symbol,
                "supporting_claim_ids": ["C1"]}
        edit.update(extra)
        return {"decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                "required_edits": [edit], "required_tests": [],
                "generation_blockers": []}

    def test_an_invented_parameter_list_is_rejected(self):
        issues = planned_symbol_mismatches(self._plan(self.INVENTED), self._packet())
        self.assertEqual(len(issues), 1)
        self.assertIn("OcrFormEntity(Bitmap, int, String, Integer)", issues[0])

    def test_a_declared_signature_passes_in_any_spelling(self):
        for symbol in (
            "OcrFormEntity(Bitmap bitmap, int quality, String eclass, "
            "Integer numberOfTopCandidates)",
            "OcrFormEntity(Bitmap, int, String, Integer)",
            "org.nick.wwwjdic.ocr.OcrFormEntity(Bitmap img)",
            "OcrFormEntity#writeTo(OutputStream os)",
        ):
            self.assertEqual(
                planned_symbol_mismatches(self._plan(symbol), self._packet()), [],
                symbol,
            )

    def test_symbols_this_check_cannot_read_are_not_judged(self):
        for symbol in (
            "OcrFormEntity", "OcrFormEntity(...)",
            "OcrFormEntity(bitmap, quality)", "newHelper(String value)",
        ):
            self.assertEqual(
                planned_symbol_mismatches(self._plan(symbol), self._packet()), [],
                symbol,
            )

    def test_a_new_file_is_not_checked(self):
        self.assertEqual(planned_symbol_mismatches(
            self._plan(self.INVENTED, create_new_file=True), self._packet(),
        ), [])

    def test_the_patch_plan_validation_reports_it(self):
        adjudication = {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "generation_status": "supported_for_review",
            "_validated_claims": [{"claim_id": "C1"}],
        }
        issues = _validate_patch_plan(
            self._plan(self.INVENTED), self._packet(), adjudication)
        self.assertTrue(any("matches no declaration" in issue for issue in issues))


if __name__ == "__main__":
    unittest.main()
