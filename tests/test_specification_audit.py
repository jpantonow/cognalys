import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)
from _reviewed_shapes import reviewed_false_positive_shapes  # noqa: E402

from cognalys.llm.pipeline_architecture import (  # noqa: E402
    specification_shapes_are_grounded,
    unmodelled_call_false_positive_reason,
)
from cognalys.specifications.audit_specifications import rule_is_present  # noqa: E402


class ShapeGroundingTests(unittest.TestCase):
    """A documented false positive is only as good as the source behind it.

    Ten of this project's specifications cite a URL that answers 404 -- the
    concerns CrySL does not model, each pointed at a plausible-looking path
    in the CrySL rule repository -- and between them they hold 66
    `known_false_positive_shapes`. Those are statements about when a finding
    may be dismissed, and the expensive mistake for this pipeline is
    dismissing a real finding, so none of them may be quoted.
    """

    SPEC = {
        "spec_id": "KeyStoreSpec",
        "source_verified": True,
        "shapes_grounded": True,
        "known_false_positive_shapes": [
            "Valid code using documented setCertificateEntry(...) instead of "
            "the rule's modeled setEntry(...).",
        ],
    }

    def test_a_verified_specification_may_be_quoted(self):
        self.assertTrue(specification_shapes_are_grounded(self.SPEC))

    def test_an_unverified_specification_may_not(self):
        self.assertFalse(
            specification_shapes_are_grounded(
                dict(self.SPEC, source_verified=False)
            )
        )

    def test_an_explicit_quarantine_wins_over_a_verified_flag(self):
        # The audit records shapes_grounded next to the shapes themselves so
        # the guard does not depend on source_verified happening to gate the
        # callers, which is what it depended on before.
        self.assertFalse(
            specification_shapes_are_grounded(
                dict(self.SPEC, shapes_grounded=False)
            )
        )

    def test_the_unmodelled_call_route_refuses_an_ungrounded_shape(self):
        # This route read the documented shapes with no verification gate at
        # all: it was the hole the explicit marker exists to close.
        quarantined = dict(self.SPEC, source_verified=False,
                           shapes_grounded=False)
        self.assertEqual(
            unmodelled_call_false_positive_reason(
                "KeyStoreSpec", "InvalidSequenceOfMethodCalls",
                ["setCertificateEntry"], quarantined,
            ),
            "",
        )

    def test_the_unmodelled_call_route_still_quotes_a_grounded_shape(self):
        with reviewed_false_positive_shapes():
            reason = unmodelled_call_false_positive_reason(
                "KeyStoreSpec", "InvalidSequenceOfMethodCalls",
                ["setCertificateEntry"], self.SPEC,
            )
        self.assertIn("setCertificateEntry", reason)


class SourceCheckTests(unittest.TestCase):
    """The audit must say which check it applied, and refuse a weak match.

    Collections_SynchronizedMap claims to govern
    `java.util.Collections_SynchronizedMap`, a class that does not exist, and
    an audit that accepted any mention would have verified it against an
    Oracle page about something else.
    """

    def test_a_crysl_source_must_declare_the_governed_type(self):
        content = "SPEC java.security.KeyPair\n\nOBJECTS\n"
        ok, detail = rule_is_present(
            "https://example.invalid/KeyPair.crysl", content,
            {"applies_to_types": ["java.security.KeyPair"]},
        )
        self.assertTrue(ok)
        self.assertIn("crysl_spec_line", detail)

    def test_a_crysl_source_for_another_type_is_refused(self):
        content = "SPEC javax.crypto.Cipher\n"
        ok, detail = rule_is_present(
            "https://example.invalid/KeyPair.crysl", content,
            {"applies_to_types": ["java.security.KeyPair"]},
        )
        self.assertFalse(ok)
        self.assertIn("different SPEC type", detail)

    def test_a_mop_source_must_declare_the_named_property(self):
        content = "Object_MonitorOwner() {\n  event bad_notify before(Object o)\n}"
        ok, detail = rule_is_present(
            "https://example.invalid/Object_MonitorOwner.mop", content,
            {"spec_id": "Object_MonitorOwner", "applies_to_types": []},
        )
        self.assertTrue(ok)
        self.assertIn("mop_property_declaration", detail)

    def test_a_document_check_is_reported_as_the_weaker_check_it_is(self):
        ok, detail = rule_is_present(
            "https://docs.example.invalid/SecureRandom.html",
            "java.security.SecureRandom generates random numbers",
            {"applies_to_types": ["java.security.SecureRandom"]},
        )
        self.assertTrue(ok)
        self.assertTrue(detail.startswith("document_mentions_type"))

    def test_an_invented_governed_type_is_not_verified(self):
        ok, detail = rule_is_present(
            "https://docs.example.invalid/Collections.html",
            "Collections.synchronizedMap returns a synchronized map",
            {"applies_to_types": ["java.util.Collections_SynchronizedMap"]},
        )
        self.assertFalse(ok)
        self.assertIn("does not mention", detail)

    def test_a_specification_naming_no_type_cannot_be_verified(self):
        ok, detail = rule_is_present(
            "https://example.invalid/x.crysl", "SPEC a.b.C", {},
        )
        self.assertFalse(ok)
        self.assertIn("no governed type", detail)


class ShippedSpecificationsTests(unittest.TestCase):
    """Every shipped specification carries the audit's verdict."""

    def _specifications(self):
        for path in sorted((ROOT / "data" / "specifications").glob("*.json")):
            yield path.stem, json.loads(path.read_text(encoding="utf-8"))

    def test_no_specification_offers_shapes_it_cannot_ground(self):
        for name, specification in self._specifications():
            with self.subTest(specification=name):
                if specification.get("known_false_positive_shapes"):
                    self.assertEqual(
                        specification.get("shapes_grounded"),
                        specification.get("source_verified"),
                        "shapes_grounded must track the audited verification",
                    )

    def test_every_specification_records_how_it_was_checked(self):
        for name, specification in self._specifications():
            with self.subTest(specification=name):
                audit = specification.get("source_audit") or {}
                self.assertIn("state", audit)
                self.assertIn("detail", audit)


class SourceAuditTests(unittest.TestCase):
    """An audit that verifies the finding's API, from any source it cites."""

    BLOCKADS = [{
        "class": "app.pwhs.blockads.ui.browser.picker.ElementPickerBridge",
        "method": "onPickerCompleted",
        "message": "Static candidate (not executed): the in-app browser "
                   "registers ElementPickerBridge on every page it loads.",
    }]

    def _spec(self, types, examples=None, **fields) -> dict:
        return {
            "spec_id": "WebViewJavascriptBridgeSpec",
            "applies_to_types": types,
            "generation_evidence": {"detector_examples": examples or self.BLOCKADS},
            **fields,
        }

    def test_a_namesake_library_type_the_findings_never_use_is_flagged(self):
        from cognalys.specifications.audit_specifications import unevidenced_library_types

        self.assertEqual(
            unevidenced_library_types(self._spec(
                ["com.github.lzyzsd.jsbridge.WebViewJavascriptBridge"]
            )),
            ["com.github.lzyzsd.jsbridge.WebViewJavascriptBridge"],
        )

    def test_platform_types_need_no_mention(self):
        from cognalys.specifications.audit_specifications import unevidenced_library_types

        self.assertEqual(unevidenced_library_types(self._spec([
            "android.webkit.WebView", "android.webkit.JavascriptInterface",
        ])), [])

    def test_a_library_the_findings_do_use_is_accepted(self):
        from cognalys.specifications.audit_specifications import unevidenced_library_types

        examples = [{"class": "a.B", "method": "c",
                     "message": "okhttp3.OkHttpClient built without a timeout"}]
        self.assertEqual(unevidenced_library_types(self._spec(
            ["okhttp3.OkHttpClient"], examples,
        )), [])

    def test_the_specification_id_alone_does_not_verify_a_document(self):
        spec = self._spec(["android.webkit.WebView"])
        present, _detail = rule_is_present(
            "https://example.com/page", "About WebViewJavascriptBridgeSpec.", spec,
        )
        self.assertFalse(present)

    def test_a_later_cited_source_verifies_after_the_first_404s(self):
        from cognalys.specifications import audit_specifications
        spec = self._spec(
            ["android.database.Cursor"],
            [{"class": "a.B", "method": "c", "message": "Cursor never closed"}],
            source_url="https://raw.githubusercontent.com/x/CursorLeak.crysl",
            authoritative_sources=[
                "https://developer.android.com/reference/android/database/Cursor",
            ],
        )
        pages = {
            "https://developer.android.com/reference/android/database/Cursor":
                "public interface android.database.Cursor ...",
        }

        def fetch(url):
            return (pages[url], "") if url in pages else ("", "http_404")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "CursorLeakSpec.json"
            path.write_text(json.dumps(spec), encoding="utf-8")
            original = audit_specifications.fetch
            audit_specifications.fetch = fetch
            try:
                record = audit_specifications.audit(path)
            finally:
                audit_specifications.fetch = original
        self.assertEqual(record["state"], "verified")
        self.assertEqual(
            record["url"],
            "https://developer.android.com/reference/android/database/Cursor",
        )

    def test_the_namesake_is_rejected_before_anything_is_fetched(self):
        from cognalys.specifications import audit_specifications
        spec = self._spec(
            ["com.github.lzyzsd.jsbridge.WebViewJavascriptBridge"],
            source_url="https://raw.githubusercontent.com/lzyzsd/JsBridge/x.java",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "WebViewJavascriptBridgeSpec.json"
            path.write_text(json.dumps(spec), encoding="utf-8")
            record = audit_specifications.audit(path)
        self.assertEqual(record["state"], "governs_unevidenced_library_type")


if __name__ == "__main__":
    unittest.main()
