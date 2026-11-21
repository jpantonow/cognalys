import json
import logging
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.pipeline_architecture import (  # noqa: E402
    collateral_constraint_violations,
    evidence_correlates_with_source,
    evidence_extraction_schema,
    governed_call_names,
    predicate_deferred_to_detector,
    sanitize_evidence_extraction,
)
from cognalys.llm.generate_error_fixes import (  # noqa: E402
    FixGenerator,
    collateral_issue_candidate,
)


# The specification that exposed all three defects, reduced to the parts the
# code reads: the events name what it governs, and the claim states the
# requirement that was gathered and dropped.
KEYSTORE = {
    "spec_id": "KeyStoreSpec",
    "source_verified": True,
    "shapes_grounded": True,
    "events": [
        {"name": "Get", "api_patterns": ["KeyStore.getInstance(",
                                         "java.security.KeyStore.getInstance("]},
        {"name": "Load", "api_patterns": [".load("]},
        {"name": "Store", "api_patterns": [".store("]},
    ],
    "detector_semantics": {
        "claim": "passwordIn must not be hard-coded.",
    },
    "known_false_positive_shapes": [
        "Valid code using documented setKeyEntry(...) or "
        "setCertificateEntry(...) instead of the rule's modeled setEntry(...).",
    ],
}

SOURCE = '''
    private static String LOCAL_TRUSTSTORE_PASSWORD = "password";

    public static KeyStore getKnownServersStore(Context context) {
        mKnownServersStore = KeyStore.getInstance(KeyStore.getDefaultType());
        mKnownServersStore.load(in, LOCAL_TRUSTSTORE_PASSWORD.toCharArray());
        return mKnownServersStore;
    }
'''


class GovernedCallNameTests(unittest.TestCase):
    """The matcher comes from the specification, not from a list in code."""

    def test_it_reads_the_names_the_specification_governs(self):
        self.assertEqual(
            governed_call_names(KEYSTORE), ["getInstance", "load", "store"],
        )

    def test_a_specification_documenting_nothing_supplies_nothing(self):
        self.assertEqual(governed_call_names({"events": []}), [])
        self.assertEqual(governed_call_names(None), [])

    def test_a_pattern_that_is_not_a_call_is_ignored(self):
        self.assertEqual(
            governed_call_names({"events": [
                {"api_patterns": ["some prose about keystores", ".load("]},
            ]}),
            ["load"],
        )


class EvidenceCorrelationTests(unittest.TestCase):
    """Correlation used to be three crypto factory names in a regex.

    `MessageDigest.getInstance`, `Cipher.getInstance`, `SSLContext.getInstance`
    and nothing else, so a KeyStore password, a monitor property, an advisory
    or a dependency coordinate could never correlate, and the issue was
    dropped with no reason recorded.
    """

    def test_evidence_quoted_verbatim_from_the_source_correlates(self):
        self.assertTrue(evidence_correlates_with_source(
            "mKnownServersStore.load(in, LOCAL_TRUSTSTORE_PASSWORD.toCharArray())",
            SOURCE, KEYSTORE,
        ))

    def test_a_governed_call_correlates_through_an_explanation(self):
        self.assertTrue(evidence_correlates_with_source(
            "The call KeyStore.getInstance(KeyStore.getDefaultType()) resolves "
            "the platform default, which Oracle documents as configurable.",
            SOURCE, KEYSTORE,
        ))

    def test_a_hard_coded_literal_correlates(self):
        self.assertTrue(evidence_correlates_with_source(
            'The password constant is initialized from the literal "password", '
            'which KeyStoreSpec forbids for passwordIn.',
            SOURCE, KEYSTORE,
        ))

    def test_evidence_about_code_that_is_not_there_does_not_correlate(self):
        self.assertFalse(evidence_correlates_with_source(
            'Cipher.getInstance("AES/ECB/PKCS5Padding") is used to wrap the key.',
            SOURCE, KEYSTORE,
        ))

    def test_a_short_literal_cannot_carry_a_correlation(self):
        self.assertFalse(evidence_correlates_with_source(
            'The value "a" appears.', SOURCE, KEYSTORE,
        ))

    def test_it_works_for_a_specification_with_no_crypto_api_at_all(self):
        """The point of the change: a non-crypto family correlates too."""
        monitor = {"events": [{"api_patterns": [".notify(", ".wait("]}]}
        source = "void ping() { manager.notify(id, notification); }"
        self.assertTrue(evidence_correlates_with_source(
            "manager.notify(id, notification) is invoked without holding the "
            "monitor of manager.", source, monitor,
        ))

    def test_empty_input_never_correlates(self):
        self.assertFalse(evidence_correlates_with_source("", SOURCE, KEYSTORE))
        self.assertFalse(evidence_correlates_with_source("x.load()", "", KEYSTORE))


class DetectorDeferralTests(unittest.TestCase):
    """An `unknown` that rests on what the detector would do.

    opencloud's getKnownServersStore confirmed that the char[] handed to
    KeyStore.load comes from the literal "password" and then marked the
    specification's own notHardCoded requirement unknown, because "the
    supplied specification does not define the detector's treatment of this
    derived char[] flow". The requirement is about the code.
    """

    def test_the_recorded_reason_is_recognised(self):
        self.assertTrue(predicate_deferred_to_detector({
            "status": "unknown", "unknown_reason": "detector_modelling",
        }))

    def test_the_excuse_is_recognised_in_prose(self):
        self.assertTrue(predicate_deferred_to_detector({
            "status": "unknown",
            "explanation": "The source flow begins with a literal String and "
                           "applies toCharArray() before load, but the "
                           "supplied specification does not define the "
                           "detector's treatment of this derived char[] flow.",
        }))

    def test_a_genuine_evidence_gap_is_not_flagged(self):
        self.assertFalse(predicate_deferred_to_detector({
            "status": "unknown",
            "unknown_reason": "runtime_dependent",
            "explanation": "The factory argument is KeyStore.getDefaultType(), "
                           "whose value is determined by a security property "
                           "at run time.",
        }))

    def test_a_decided_predicate_is_never_flagged(self):
        for status in ("confirmed", "violated"):
            with self.subTest(status=status):
                self.assertFalse(predicate_deferred_to_detector({
                    "status": status,
                    "explanation": "the detector's treatment is unclear",
                }))

    def test_the_schema_offers_no_detector_shaped_reason(self):
        """Removing the move matters more than detecting it afterwards."""
        schema = evidence_extraction_schema("generic")
        predicate = (schema["properties"]["predicate_assessment"]["items"]
                     ["properties"])
        self.assertIn("unknown_reason", predicate)
        values = predicate["unknown_reason"]["enum"]
        self.assertEqual(
            sorted(values),
            ["not_applicable", "runtime_dependent", "scope_incomplete",
             "source_incomplete"],
        )

    def test_sanitization_names_the_deferral_without_deciding_it(self):
        packet = {"evidence_catalog": [{"evidence_id": "SRC-001"}]}
        extraction = {
            "claims": [],
            "predicate_assessment": [{
                "predicate": "The password input is not hard-coded.",
                "status": "unknown",
                "evidence_ids": ["SRC-001"],
                "explanation": "The supplied specification does not define "
                               "the detector's treatment of this flow.",
            }],
        }
        sanitized, notes = sanitize_evidence_extraction(extraction, packet)
        predicate = sanitized["predicate_assessment"][0]
        # Named, not repaired: nothing here can decide what the evidence pass
        # declined to decide, and guessing would be worse than the silence.
        self.assertEqual(predicate["status"], "unknown")
        self.assertEqual(predicate["unknown_reason"], "detector_modelling")
        self.assertTrue(any("does not decide" in note for note in notes))


class CollateralViolationTests(unittest.TestCase):
    """A requirement the source breaks that the detector did not report."""

    ERROR = {
        "unique_error_id": "a.NetworkUtils:::getKnownServersStore:::"
                           "KeyStoreSpec:::InvalidSequenceOfMethodCalls:::unknown",
        "spec": "KeyStoreSpec",
    }

    def _extraction(self, *predicates):
        return {"predicate_assessment": list(predicates)}

    def test_a_violated_unreported_requirement_is_surfaced(self):
        collateral = collateral_constraint_violations(self._extraction({
            "predicate": "The password input modeled by the target load call "
                         "is not hard-coded, as required by KeyStoreSpec.",
            "status": "violated",
            "evidence_ids": ["SRC-001"],
            "explanation": 'It is initialized from the literal "password".',
        }), self.ERROR)
        self.assertEqual(len(collateral), 1)
        self.assertIn("hard-coded", collateral[0]["predicate"])

    def test_the_reported_requirement_is_not_collateral(self):
        collateral = collateral_constraint_violations(self._extraction({
            "predicate": "Every InvalidSequenceOfMethodCalls ordering required "
                         "by the rule holds.",
            "status": "violated", "evidence_ids": ["SRC-001"],
        }), self.ERROR)
        self.assertEqual(collateral, [])

    def test_an_unknown_requirement_is_not_collateral(self):
        collateral = collateral_constraint_violations(self._extraction({
            "predicate": "The password input is not hard-coded.",
            "status": "unknown", "evidence_ids": ["SRC-001"],
        }), self.ERROR)
        self.assertEqual(collateral, [])

    def test_a_violation_with_no_evidence_is_not_collateral(self):
        collateral = collateral_constraint_violations(self._extraction({
            "predicate": "The password input is not hard-coded.",
            "status": "violated", "evidence_ids": [],
        }), self.ERROR)
        self.assertEqual(collateral, [])

    def test_a_documented_false_positive_shape_does_not_suppress_it(self):
        """A shape says the detector may report *this* wrongly.

        It answers for the reported condition and says nothing about a
        requirement the source itself settles. Suppressing a source-settled
        violation because the rule is known to misreport something else
        would be the same mistake in a new place.
        """
        error = dict(self.ERROR, specification_context=KEYSTORE)
        collateral = collateral_constraint_violations(self._extraction({
            "predicate": "The password input is not hard-coded.",
            "status": "violated", "evidence_ids": ["SRC-001"],
            "explanation": 'Initialized from the literal "password".',
        }), error)
        self.assertEqual(len(collateral), 1)

    def test_nothing_is_surfaced_for_an_ordinary_finding(self):
        self.assertEqual(collateral_constraint_violations({}, self.ERROR), [])
        self.assertEqual(collateral_constraint_violations(None, None), [])


class CollateralIssueTextTests(unittest.TestCase):
    """The issue must be about the collateral violation, not the dismissal.

    In exactly the case this exists for, `confirmed_cause` explains why the
    *reported* finding is not real. An issue carrying that as its summary
    would cost a maintainer their time to discover nothing was reported.
    """

    COLLATERAL = [{
        "predicate": "The password input modeled by the target load call is "
                     "not hard-coded, as required by KeyStoreSpec.",
        "evidence_ids": ["SRC-001"],
        "explanation": 'LOCAL_TRUSTSTORE_PASSWORD is the literal "password".',
    }]

    def test_the_summary_states_the_collateral_requirement(self):
        issue = collateral_issue_candidate(
            self.COLLATERAL, "getKnownServersStore", "KeyStoreSpec", "v1",
        )
        self.assertTrue(issue["eligible"])
        self.assertIn("hard-coded", issue["finding_summary"])
        self.assertIn("password", issue["finding_summary"])

    def test_it_says_the_reported_condition_was_not_confirmed(self):
        issue = collateral_issue_candidate(
            self.COLLATERAL, "getKnownServersStore", "KeyStoreSpec", "v1",
        )
        text = " ".join(str(value) for value in issue.values()).lower()
        self.assertIn("not confirm", text)

    def test_it_never_carries_the_false_positive_explanation(self):
        issue = collateral_issue_candidate(
            self.COLLATERAL, "getKnownServersStore", "KeyStoreSpec", "v2",
        )
        text = " ".join(str(value) for value in issue.values()).lower()
        self.assertNotIn("false positive", text)
        self.assertNotIn("setcertificateentry", text)

    def test_both_styles_produce_a_complete_presentation(self):
        for style in ("v1", "v2"):
            with self.subTest(style=style):
                issue = collateral_issue_candidate(
                    self.COLLATERAL, "m", "KeyStoreSpec", style,
                )
                for field in ("title", "finding_summary", "why_no_pr",
                              "maintainer_question", "proposed_next_step"):
                    self.assertTrue(str(issue.get(field, "")).strip(), field)

    def test_no_collateral_means_no_issue(self):
        self.assertFalse(
            collateral_issue_candidate([], "m", "KeyStoreSpec", "v1")["eligible"]
        )


if __name__ == "__main__":
    unittest.main()


class SelfDismissedCollateralTests(unittest.TestCase):
    """An entry whose own explanation calls it the documented shape is not raised."""

    SPECIFICATION = {
        **KEYSTORE,
        "known_false_positive_shapes": [
            'Android application code using java.security.KeyStore.getInstance('
            '"AndroidKeyStore") where the static rule\'s type whitelist is '
            'applied literally.',
        ],
    }

    def extraction(self, explanation: str) -> dict:
        return {"predicate_assessment": [{
            "predicate": "The KeyStore type argument passed to getInstance is "
                         "one of JCEKS, JKS, DKS, PKCS11 or PKCS12.",
            "status": "violated",
            "evidence_ids": ["SRC-001"],
            "explanation": explanation,
        }]}

    def test_the_networksurvey_record_is_not_raised(self):
        excluded = []
        found = collateral_constraint_violations(
            self.extraction(
                'The type argument is "AndroidKeyStore", which is outside the '
                "rule's five-value whitelist. The specification lists this as "
                "a known false-positive shape."),
            {"error_message": "", "specification_context": self.SPECIFICATION},
            excluded=excluded,
        )
        self.assertEqual(found, [])
        self.assertEqual(len(excluded), 1)

    def test_an_undocumented_value_is_still_raised(self):
        found = collateral_constraint_violations(
            self.extraction(
                'The type argument is "FOOKS". This is not a false positive.'),
            {"error_message": "", "specification_context": self.SPECIFICATION},
        )
        self.assertEqual(len(found), 1)


class CollateralOnlyIssueTests(unittest.TestCase):
    """A finding settled as documented use keeps only its collateral issue.

    Grocy's MemorizingTrustManager.getTrustManager: the reported init(null)
    is the documented platform default and is recorded as a violation
    without security impact, while its getInstance("X509") is a separate
    requirement the source breaks and still reaches the maintainer.
    """

    COLLATERAL = {
        "predicate": "The password input is not hard-coded.",
        "status": "violated",
        "evidence_ids": ["SRC-001"],
        "explanation": 'The password constant is initialized from the literal '
                       '"password", which KeyStoreSpec forbids for passwordIn.',
    }

    def _persist(self, directory, predicates, collateral_only, contribution_base=None):
        generator = FixGenerator.__new__(FixGenerator)
        generator.architecture_version = "v2"
        generator.output_dir = Path(directory)
        generator.logger = logging.getLogger("test-collateral-only")
        evidence_file = Path(directory) / "review.json"
        evidence_file.write_text(json.dumps({"analysis": {}}), encoding="utf-8")
        analysis = {
            "decision": "NO_SAFE_FIX",
            "cause_status": "confirmed",
            "confirmed_cause": "load reads its password from a constant",
            "detector_violation": "confirmed",
            "runtime_security_impact": "not_established",
            "predicate_assessment": predicates,
            "issue_candidate": {
                "eligible": True, "title": "Keystore password",
                "finding_summary": "the reported sequence is followed",
                "why_no_pr": "the password is shared with stored data",
                "maintainer_question": "may the keystore be migrated?",
                "proposed_next_step": "decide the migration",
            },
            "v2": {
                "claims": [{"claim_id": "CLM-001", "epistemic_status": "confirmed",
                            "evidence_ids": ["SRC-001"]}],
                "adjudication": {"decision_claim_ids": ["CLM-001"]},
            },
        }
        error = {
            "error_index": 1,
            "repository_url": "https://github.com/example/app",
            "source_file_path": "NetworkUtils.java",
            "unique_error_id": CollateralViolationTests.ERROR["unique_error_id"],
            "spec": "KeyStoreSpec", "tool": "rvsec",
            "error_message": "unknown",
            "method_body": SOURCE,
            "specification_context": KEYSTORE,
            "contribution_base": contribution_base or {},
        }
        path = generator.persist_blocked_issue_candidate(
            error, analysis, evidence_file, "app.apk", "getKnownServersStore",
            [], collateral_only=collateral_only,
        )
        return path and json.loads(Path(path).read_text(encoding="utf-8"))

    def test_only_the_collateral_violation_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            issue = self._persist(directory, [self.COLLATERAL], True)

        self.assertEqual(issue["issue_kind"], "collateral_constraint_violation")
        self.assertIn("hard-coded", issue["issue_content"]["finding_summary"])

    def test_without_collateral_nothing_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            # The same finding would otherwise be an issue of its own.
            self.assertEqual(
                self._persist(directory, [], False)["issue_kind"], "no_safe_fix")
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(self._persist(directory, [], True))

    def test_no_issue_is_raised_about_a_statement_gone_from_the_base(self):
        """AmaRadio's md5 (misuse3 run7): the reported statement was no
        longer on the base branch and still ended as a maintainer issue."""
        gone = {"base_branch": "master", "source_file_path": "Utils.kt",
                "target_present": True, "analyzed_code_present": False,
                "reported_statement_present": False}
        with tempfile.TemporaryDirectory() as directory:
            self.assertIsNone(self._persist(directory, [], False, gone))
            folder = Path(directory) / "issue_candidates" / "app.apk"
            self.assertEqual(list(folder.glob("*_issue.json")), [])
            [kept] = folder.glob("*_not_applicable_to_base.json")
            record = json.loads(kept.read_text(encoding="utf-8"))
        self.assertEqual(record["status"], "not_applicable_to_base")
        self.assertIn("no longer in Utils.kt", record["not_applicable_reason"])

    def test_a_method_changed_around_a_still_present_statement_keeps_its_issue(self):
        changed = {"base_branch": "master", "source_file_path": "Utils.kt",
                   "target_present": True, "analyzed_code_present": False,
                   "reported_statement_present": True}
        with tempfile.TemporaryDirectory() as directory:
            issue = self._persist(directory, [], False, changed)
        self.assertEqual(issue["issue_kind"], "no_safe_fix")
        self.assertTrue(issue["method_changed_upstream"])
        self.assertNotIn("status", issue)


class SettledValueCollateralTests(unittest.TestCase):
    """A collateral entry about the value the adjudication judged correct use.

    AntennaPod's BackportTrustManager.getSystemTrustManager (misuse5 run_v2)
    passes a null KeyStore to TrustManagerFactory.init. The adjudication
    called that the documented platform default and the finding ended as a
    violation without security impact, yet an issue was prepared that asked
    about the generatedKeyStore predicate on that same null and said the
    reported condition was "not confirmed".
    """

    ERROR = {
        "unique_error_id": "de.danoeh.antennapod.net.ssl.BackportTrustManager:::"
                           "getSystemTrustManager:::TrustManagerFactorySpec:::"
                           "UnsatisfiedConstraint:::a null KeyStore",
        "spec": "TrustManagerFactorySpec",
        "error_message": "a null KeyStore given to TrustManagerFactory.init "
                         "requests the platform default trust store",
    }
    CORRECT_USE = (
        "`TrustManagerFactory.init(KeyStore)` is documented to accept a key "
        "store or null; here null intentionally selects the system trust "
        "manager route [WEB-001]."
    )
    NULL_KEYSTORE = {
        "event": "Every KeyStore argument passed to the governed "
                 "TrustManagerFactory.init(KeyStore) calls has the "
                 "generatedKeyStore evidence required by the specification.",
        "status": "violated",
        "rule_section": "required_predicate",
        "evidence": "Evidence IDs: SRC-001, CALL-001. create() directly calls "
                    "getSystemTrustManager(null), which forwards null to "
                    "factory.init(keystore). Null cannot possess the "
                    "generatedKeyStore predicate.",
    }
    ALGORITHM = {
        "event": "The TrustManagerFactory algorithm at getInstance is PKIX.",
        "status": "violated",
        "rule_section": "constraint",
        "evidence": 'Evidence IDs: SRC-001. TrustManagerFactory.getInstance('
                    '"X509") names an algorithm the specification does not '
                    'permit.',
    }

    def _analysis(self, *predicates):
        return {
            "detector_violation": "confirmed",
            "confirmed_cause": "create() passes a null KeyStore to "
                               "TrustManagerFactory.init(KeyStore).",
            "predicate_assessment": list(predicates),
            "v2": {"adjudication": {
                "current_code_is_correct_use": True,
                "correct_use_reason": self.CORRECT_USE,
            }},
        }

    def test_the_same_null_at_the_same_call_is_dismissed(self):
        excluded = []
        found = collateral_constraint_violations(
            self._analysis(self.NULL_KEYSTORE), self.ERROR, excluded=excluded,
        )
        self.assertEqual(found, [])
        [item] = excluded
        self.assertIn("generatedKeyStore", item["predicate"])
        self.assertIn("init(...)", item["reason"])
        self.assertIn("null", item["reason"])

    def test_an_explicit_settling_sentence_dismisses_it_too(self):
        found = collateral_constraint_violations(
            {"predicate_assessment": [self.NULL_KEYSTORE]}, self.ERROR,
            settled_texts=[self.CORRECT_USE],
        )
        self.assertEqual(found, [])

    def test_another_call_or_value_still_stands(self):
        found = collateral_constraint_violations(
            self._analysis(self.NULL_KEYSTORE, self.ALGORITHM), self.ERROR,
        )
        self.assertEqual([item["predicate"] for item in found],
                         [self.ALGORITHM["event"]])

    def test_another_argument_of_the_same_call_still_stands(self):
        # SSLContext.init(null, tms, null): the documented null KeyManager[]
        # settles neither the TrustManager nor the SecureRandom argument.
        settled = ("SSLContext.init(null, trustManagers, null) is documented: a null "
                   "KeyManager[] selects the default key managers.")
        trust = {
            "event": "Every TrustManager passed to SSLContext.init validates the "
                     "server certificate chain.",
            "status": "violated", "rule_section": "constraint",
            "evidence": "sslContext.init(null, arrayOf(TrustAllManager()), null) installs "
                        "a trust manager whose checkServerTrusted is empty.",
        }
        random = {
            "event": "The SecureRandom passed to init(...) must come from a generated "
                     "SecureRandom; here it is null.",
            "status": "violated", "rule_section": "required_predicate",
            "evidence": "sslContext.init(null, trustManagers, null).",
        }
        key_managers = {
            "event": "The KeyManager[] passed to SSLContext.init has the generated "
                     "evidence; here it is null.",
            "status": "violated", "rule_section": "required_predicate",
            "evidence": "sslContext.init(null, trustManagers, null).",
        }
        excluded = []
        found = collateral_constraint_violations(
            {"predicate_assessment": [trust, random, key_managers]}, self.ERROR,
            settled_texts=[settled], excluded=excluded,
        )
        self.assertEqual([item["predicate"] for item in found],
                         [trust["event"], random["event"]])
        self.assertEqual([item["predicate"] for item in excluded], [key_managers["event"]])

    def test_without_a_correct_use_judgement_nothing_is_dismissed(self):
        analysis = self._analysis(self.NULL_KEYSTORE)
        analysis["v2"]["adjudication"]["current_code_is_correct_use"] = False
        found = collateral_constraint_violations(analysis, self.ERROR)
        self.assertEqual(len(found), 1)

    def test_the_issue_text_keeps_a_confirmed_verdict(self):
        collateral = [{"predicate": self.ALGORITHM["event"],
                       "explanation": "It names X509."}]
        for style in ("v1", "v2", "v3"):
            with self.subTest(style=style):
                issue = collateral_issue_candidate(
                    collateral, "getSystemTrustManager", "TrustManagerFactorySpec",
                    style, reported_confirmed=True,
                )
                text = " ".join(str(value) for value in issue.values()).lower()
                self.assertNotIn("did not confirm", text)
                self.assertNotIn("not confirmed", text)
                self.assertIn("confirmed the reported condition", text)

    def test_the_documented_use_finding_writes_no_issue(self):
        generator = FixGenerator.__new__(FixGenerator)
        generator.architecture_version = "v2"
        generator.logger = logging.getLogger("test-settled-collateral")
        with tempfile.TemporaryDirectory() as directory:
            generator.output_dir = Path(directory)
            evidence_file = Path(directory) / "review.json"
            evidence_file.write_text(json.dumps({"analysis": {}}), encoding="utf-8")
            analysis = dict(self._analysis(self.NULL_KEYSTORE),
                            decision="NO_SAFE_FIX", cause_status="confirmed",
                            runtime_security_impact="non_security")
            path = generator.persist_blocked_issue_candidate(
                dict(self.ERROR, error_index=0,
                     repository_url="https://github.com/AntennaPod/AntennaPod",
                     method_body="factory.init(keystore);"),
                analysis, evidence_file, "app.apk", "getSystemTrustManager",
                [], collateral_only=True, settled_texts=[self.CORRECT_USE],
            )
        self.assertIsNone(path)

    def test_the_written_collateral_issue_keeps_the_confirmed_verdict(self):
        # The path that writes an issue: the verdict comes from the
        # analysis's detector_violation, not from a default.
        generator = FixGenerator.__new__(FixGenerator)
        generator.architecture_version = "v2"
        generator.pr_issue_style = "v3"
        generator.logger = logging.getLogger("test-settled-collateral")
        with tempfile.TemporaryDirectory() as directory:
            generator.output_dir = Path(directory)
            evidence_file = Path(directory) / "review.json"
            evidence_file.write_text(json.dumps({"analysis": {}}), encoding="utf-8")
            analysis = dict(self._analysis(self.NULL_KEYSTORE, self.ALGORITHM),
                            decision="NO_SAFE_FIX", cause_status="confirmed",
                            runtime_security_impact="non_security")
            path = generator.persist_blocked_issue_candidate(
                dict(self.ERROR, error_index=0,
                     repository_url="https://github.com/AntennaPod/AntennaPod",
                     method_body='TrustManagerFactory factory = TrustManagerFactory'
                                 '.getInstance("X509");\nfactory.init(keystore);'),
                analysis, evidence_file, "app.apk", "getSystemTrustManager",
                [], collateral_only=True, settled_texts=[self.CORRECT_USE],
            )
            self.assertIsNotNone(path)
            record = json.loads(Path(path).read_text(encoding="utf-8"))
        self.assertEqual([item["predicate"] for item in record["collateral_violations"]],
                         [self.ALGORITHM["event"]])
        text = " ".join(str(value) for value in record["issue_content"].values()).lower()
        self.assertIn("confirmed the reported condition", text)
        self.assertNotIn("not confirmed", text)
        self.assertNotIn("did not confirm", text)
