import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.issues.issue_creator import IssueCreator  # noqa: E402


class IssueContentTests(unittest.TestCase):
    def test_external_digest_issue_omits_unrelated_cache_permission(self):
        body = IssueCreator.build_no_safe_fix_body("Hello", {
            "method_name": "SHA1", "source_file": "Digest.java",
            "compatibility_policy": {"allow_cache_invalidation": True},
            "migration_assessment": {"usage_kind": "protocol"},
            "digest_contract_assessment": {
                "contract_kind": "external_backend",
                "security_relevance": "not_established",
            },
            "issue_content": {
                "finding_summary": "SHA-1 output crosses an API boundary.",
                "why_no_pr": "The backend contract is unavailable.",
                "maintainer_question": "Are these fields opaque?",
                "proposed_next_step": "Provide the backend compatibility policy.",
            },
        })
        self.assertNotIn("regenerable cache", body)
        self.assertIn("If a migration is desirable, provide", body)
        self.assertNotIn("reviewed against the available repository source", body)
        self.assertNotIn("Additional project context", body)
        self.assertNotIn("automated dynamic analysis", body)

    V2_METADATA = {
        "method_name": "parseConfig", "source_file": "General.kt",
        "csv_class": "org.example.common.General",
        "spec": "IvParameterSpecSpec", "tool": "ape",
        "compatibility_policy": {"allow_cache_invalidation": True},
        "migration_assessment": {"usage_kind": "cache"},
        "issue_content": {
            "finding_summary": "The IV is always 16 zero bytes",
            "why_no_pr": "I didn't open a pull request because the record format is unknown.",
            "maintainer_question": "Is the zero IV intentional?",
            "proposed_next_step": "Otherwise I'm happy to send a PR.",
        },
    }

    def test_v2_style_adds_tool_and_spec_glossary(self):
        body = IssueCreator.build_no_safe_fix_body("Hi! I'm a student.", {
            "method_name": "build", "source_file": "HttpClient.kt",
            "spec": "SSLContextSpec", "tool": "ape",
            "issue_content": {
                "finding_summary": "Uses the generic TLS literal.",
                "why_no_pr": "Runtime evidence is missing.",
                "maintainer_question": "Which protocols are enabled?",
                "proposed_next_step": "Provide runtime evidence.",
            },
        }, style="v2")
        self.assertIn("running the app under RVSec", body)
        self.assertNotIn("is the rule", body)

    def test_v2_style_moves_disclosure_to_a_trailing_signature(self):
        body = IssueCreator.build_no_safe_fix_body("Hi! I'm a student.", {
            "method_name": "build", "source_file": "HttpClient.kt",
            "issue_content": {
                "finding_summary": "Uses the generic TLS literal.",
                "why_no_pr": "Runtime evidence is missing.",
                "maintainer_question": "Which protocols are enabled?",
                "proposed_next_step": "Provide runtime evidence.",
            },
        }, style="v2")
        self.assertIn("Hi! I'm a student.", body)
        self.assertLess(
            body.index("Uses the generic TLS literal."),
            body.index("Hi! I'm a student."),
        )

    def test_v3_no_safe_fix_is_plain_paragraphs(self):
        body = IssueCreator.build_no_safe_fix_body(
            "Hi! I'm a student.", self.V2_METADATA, style="v3")
        self.assertTrue(body.startswith("Hi! I'm a student."))
        self.assertIn(
            "under RVSec, a runtime checker for how apps use the Java crypto "
            "and TLS APIs, it flagged `General.parseConfig` in `General.kt`.", body)
        self.assertIn("The IV is always 16 zero bytes.", body)
        self.assertIn("format is unknown. Is the zero IV intentional?", body)
        self.assertTrue(body.endswith("Otherwise I'm happy to send a PR.\n\nThanks!"))
        for internal in ("##", "Analysis context", "IvParameterSpecSpec",
                         "If a migration is desirable", "regenerable cache"):
            self.assertNotIn(internal, body)

    def test_v3_names_a_constructor_by_its_class(self):
        self.assertIn(
            "flagged the `MD5` constructor",
            IssueCreator.flagged_sentence("rvsec", "org.cry.otp.MD5", "<init>", ""),
        )

    def test_the_wording_checks_a_pull_request_is_rewritten_for_never_hold_an_issue(self):
        """2026-10-31: no step rewrites an issue's text, so the rule-id and
        bytecode checks would only hold it."""
        from cognalys.utils.pr_text import text_problems

        body = "The `KeyStoreSpec` usage rule flags `Vault.<init>`."
        self.assertTrue(text_problems("Load the keystore once", body, specs=["KeyStoreSpec"]))
        self.assertEqual(text_problems("Load the keystore once", body, specs=["KeyStoreSpec"],
                                       wording_checks=False), [])

    def test_v3_issue_with_pull_request_has_no_table(self):
        body = IssueCreator.build_issue_body(
            "Hi! I'm a student.", "Util.java", "MessageDigestSpec", "md5Hex",
            "github.paroj.Util", "expecting SHA-256 but found MD5", "monkey",
            style="v3")
        self.assertIn("> expecting SHA-256 but found MD5", body)
        self.assertIn("Would you be open to reviewing it?", body)
        self.assertNotIn("Analysis context", body)

    def test_v3_publication_blocks_pipeline_wording(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp) / "x_issue.json"
            candidate.write_text(json.dumps({
                **self.V2_METADATA, "issue_kind": "no_safe_fix",
                "repo_host": "github.com", "repo_owner": "o", "repo_name": "r",
                "issue_content": {
                    **self.V2_METADATA["issue_content"],
                    "title": "Review requested for IvParameterSpecSpec finding in parseConfig",
                    "finding_summary": "The governed call fails the predicate.",
                },
            }), encoding="utf-8")
            creator = IssueCreator(tmp, tmp, tmp, "t", "Hi!", dry_run=True, style="v3")
            self.assertEqual(creator.process(candidate), "blocked")
            creator.allow_text_problems = True
            self.assertEqual(creator.process(candidate), "success")

    def test_v1_no_safe_fix_body_is_unchanged_by_default(self):
        body = IssueCreator.build_no_safe_fix_body("Hi! I'm a student.", {
            "method_name": "build", "source_file": "HttpClient.kt",
            "issue_content": {
                "finding_summary": "Uses the generic TLS literal.",
                "why_no_pr": "Runtime evidence is missing.",
                "maintainer_question": "Which protocols are enabled?",
                "proposed_next_step": "Provide runtime evidence.",
            },
        })
        self.assertLess(
            body.index("Hi! I'm a student."),
            body.index("Uses the generic TLS literal."),
        )
        self.assertNotIn("usage rule that was checked", body)

    def test_cache_issue_keeps_scoped_cache_note(self):
        body = IssueCreator.build_no_safe_fix_body("Hello", {
            "source_file": "Cache.java",
            "compatibility_policy": {"allow_cache_invalidation": True},
            "migration_assessment": {"usage_kind": "cache"},
            "digest_contract_assessment": {"contract_kind": "internal"},
            "issue_content": {
                "finding_summary": "Cache key uses a legacy digest.",
                "why_no_pr": "Review requested.",
                "maintainer_question": "May old entries become misses?",
                "proposed_next_step": "Confirm cache regeneration.",
            },
        })
        self.assertIn("regenerable cache", body)


if __name__ == "__main__":
    unittest.main()
