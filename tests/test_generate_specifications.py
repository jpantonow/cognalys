import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)
MODULE_PATH = ROOT / "src" / "cognalys" / "specifications" / "generate_specifications.py"
SPEC = importlib.util.spec_from_file_location("generate_specifications", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _valid_v2_payload(name: str = "ExampleSpec") -> dict:
    return {
        "schema_version": 2,
        "spec_id": name,
        "name": name,
        "applies_to_types": ["com.example.Example"],
        "source_title": "Example docs",
        "source_url": "https://example.com/docs",
        "source_verified": False,
        "protocol": "construct -> use",
        "important_note": "limits apply",
        "events": [{
            "name": "construct", "api_patterns": ["new Example("],
            "condition": "constructed",
        }],
        "forbidden_inferences_without_evidence": ["do not assume X"],
        "semantic_scope": "source-level only",
        "detector_semantics": {
            "claim": "c", "predicates": ["p"], "limitations": ["l"],
        },
        "api_semantics": {
            "documented_behavior": ["b"], "preconditions": ["p"], "unknowns": ["u"],
        },
        "security_semantics": {
            "detector_claim": "d", "runtime_claim": "r", "equivalent": False,
        },
        "evidence_requirements": {
            "source_level": ["s"], "runtime": ["r"], "compatibility": ["c"],
        },
        "known_false_positive_shapes": ["shape"],
        "false_positive_shape_review": [{
            "shape": "shape", "breaks_rule_as_written": False,
            "constraint_outgrown": False, "compliant_equivalent": "",
        }],
        "authoritative_sources": ["https://example.com/docs"],
        "unknowns": ["question"],
    }


class ScopedToOneFindingTests(unittest.TestCase):
    """CursorLeakSpec governed only the DownloadManager.query of its example."""

    EXAMPLE = {
        "class": "com.pennywiseai.tracker.ui.screens.settings.SettingsViewModel",
        "method": "checkDownloadStatus",
    }

    def _spec(self, scope):
        return {
            "semantic_scope": scope,
            "generation_evidence": {"detector_examples": [self.EXAMPLE]},
        }

    def test_a_scope_naming_its_example_class_is_detected(self):
        spec = self._spec(
            "Observes a Cursor in com.pennywiseai.tracker.ui.screens.settings."
            "SettingsViewModel.checkDownloadStatus from DownloadManager.query."
        )
        self.assertEqual(
            MODULE.scoped_to_one_finding(spec), [self.EXAMPLE["class"]]
        )
        spec["source_verified"] = True
        self.assertFalse(MODULE.is_source_grounded(json.dumps(spec)))

    def test_simple_class_and_method_are_detected_too(self):
        spec = self._spec("In SettingsViewModel.checkDownloadStatus a Cursor leaks.")
        self.assertEqual(
            MODULE.scoped_to_one_finding(spec), ["SettingsViewModel.checkDownloadStatus"]
        )

    def test_a_rule_level_scope_is_kept(self):
        spec = self._spec(
            "For every finding of this rule, a Cursor returned by a query is "
            "not closed on every path."
        )
        self.assertEqual(MODULE.scoped_to_one_finding(spec), [])

    def test_fresh_examples_can_be_checked_without_a_record(self):
        self.assertEqual(
            MODULE.scoped_to_one_finding(
                {"semantic_scope": "Only SettingsViewModel.checkDownloadStatus."},
                [self.EXAMPLE],
            ),
            ["SettingsViewModel.checkDownloadStatus"],
        )


class ValidateSpecificationTests(unittest.TestCase):
    def test_accepts_a_complete_v2_payload(self):
        data = MODULE.validate_specification(_valid_v2_payload(), "ExampleSpec")
        self.assertEqual(data["spec_id"], "ExampleSpec")

    def test_rejects_payload_with_no_schema_version(self):
        payload = _valid_v2_payload()
        del payload["schema_version"]
        with self.assertRaisesRegex(ValueError, "schema_version must be 2"):
            MODULE.validate_specification(payload, "ExampleSpec")

    def test_rejects_legacy_schema_version_one(self):
        payload = _valid_v2_payload()
        payload["schema_version"] = 1
        with self.assertRaisesRegex(ValueError, "schema_version must be 2"):
            MODULE.validate_specification(payload, "ExampleSpec")

    def test_rejects_spec_id_mismatch(self):
        payload = _valid_v2_payload()
        payload["spec_id"] = "OtherSpec"
        with self.assertRaisesRegex(ValueError, "spec_id"):
            MODULE.validate_specification(payload, "ExampleSpec")

    def test_rejects_missing_v2_object_field(self):
        payload = _valid_v2_payload()
        del payload["api_semantics"]
        with self.assertRaisesRegex(ValueError, "api_semantics"):
            MODULE.validate_specification(payload, "ExampleSpec")

    def test_rejects_missing_v2_array_field(self):
        payload = _valid_v2_payload()
        del payload["unknowns"]
        with self.assertRaisesRegex(ValueError, "unknowns"):
            MODULE.validate_specification(payload, "ExampleSpec")


class CryslSourceHintTests(unittest.TestCase):
    def test_builds_the_canonical_raw_path_for_the_governed_api(self):
        hint = MODULE.crysl_source_hint("TrustManagerFactorySpec")
        self.assertEqual(
            hint,
            "https://raw.githubusercontent.com/CROSSINGTUD/Crypto-API-Rules/"
            "refs/heads/master/JavaCryptographicArchitecture/src/"
            "TrustManagerFactory.crysl",
        )

    def test_prompt_includes_the_hint_url(self):
        _, user = MODULE.prompt_for("TrustManagerFactorySpec", [])
        self.assertIn(MODULE.crysl_source_hint("TrustManagerFactorySpec"), user)


class _FakeProvider:
    """Returns queued (research, synthesis) pairs, one pair per attempt.

    Each call to generate() is either the research pass (web_search=True) or
    the synthesis pass (web_search=False); both counters advance in lockstep
    since generate_one_specification always calls research then synthesis
    before starting the next attempt.
    """

    def __init__(self, responses):
        self.responses = list(responses)
        self.research_calls = 0
        self.synthesis_calls = 0

    def generate(self, *args, **kwargs):
        if kwargs.get("web_search"):
            research, _ = self.responses[self.research_calls]
            self.research_calls += 1
            return research
        _, synthesis = self.responses[self.synthesis_calls]
        self.synthesis_calls += 1
        return synthesis


class GenerateOneSpecificationTests(unittest.TestCase):
    def _payload(self, source_verified, source_url="https://example.com/docs"):
        payload = _valid_v2_payload("ExampleSpec")
        payload["source_verified"] = source_verified
        payload["source_url"] = source_url
        return json.dumps(payload)

    def test_accepts_source_verified_true_on_the_first_attempt(self):
        provider = _FakeProvider([
            ("research brief", self._payload(True)),
        ])
        with patch.object(MODULE, "verify_source_url", return_value=(True, "HTTP 200")):
            data = MODULE.generate_one_specification("ExampleSpec", [], provider)
        self.assertTrue(data["source_verified"])
        self.assertEqual(provider.synthesis_calls, 1)

    def test_retries_when_source_verified_is_false_and_then_succeeds(self):
        provider = _FakeProvider([
            ("miss", self._payload(False)),
            ("hit", self._payload(True)),
        ])
        with patch.object(MODULE, "verify_source_url", return_value=(True, "HTTP 200")):
            data = MODULE.generate_one_specification("ExampleSpec", [], provider)
        self.assertTrue(data["source_verified"])
        self.assertEqual(provider.synthesis_calls, 2)

    def test_an_unreachable_source_is_accepted_without_further_attempts(self):
        """Re-asking cannot make a 404 into a source.

        SQLInjectionSpec, PinLockoutSpec and IntentReflectionSpec each spent
        three full research and synthesis rounds -- roughly five minutes and
        190k input tokens apiece -- being told to go fetch a CrySL path that
        had already answered 404, because the URL was only ever checked when
        the model claimed success.
        """
        provider = _FakeProvider([
            ("miss1", self._payload(False, source_url="https://absent.example/x")),
            ("miss2", self._payload(False)),
            ("miss3", self._payload(False)),
        ])
        with patch.object(
            MODULE, "verify_source_url", return_value=(False, "HTTP 404")
        ):
            data = MODULE.generate_one_specification("ExampleSpec", [], provider)

        self.assertFalse(data["source_verified"])
        self.assertEqual(provider.synthesis_calls, 1)
        verification = data["source_verification"]
        self.assertTrue(verification["checked"])
        self.assertFalse(verification["reachable"])
        self.assertEqual(verification["source_url"], "https://absent.example/x")
        self.assertIn("404", verification["detail"])

    def test_a_reachable_source_the_model_gave_up_on_is_still_retried(self):
        # The retry that has value: the page is there, the model just did not
        # read it.
        provider = _FakeProvider([
            ("miss", self._payload(False)),
            ("hit", self._payload(True)),
        ])
        with patch.object(
            MODULE, "verify_source_url", return_value=(True, "HTTP 200")
        ):
            data = MODULE.generate_one_specification("ExampleSpec", [], provider)

        self.assertTrue(data["source_verified"])
        self.assertEqual(provider.synthesis_calls, 2)

    def test_the_final_attempt_is_still_accepted_unverified(self):
        # Reachable every time, and the model never confirms: the loop must
        # still end by recording the honest result rather than failing.
        provider = _FakeProvider([
            ("miss1", self._payload(False)),
            ("miss2", self._payload(False)),
            ("miss3", self._payload(False, source_url="https://still.example/x")),
        ])
        with patch.object(
            MODULE, "verify_source_url", return_value=(True, "HTTP 200")
        ):
            data = MODULE.generate_one_specification("ExampleSpec", [], provider)

        self.assertFalse(data["source_verified"])
        self.assertEqual(data["source_url"], "https://still.example/x")
        self.assertEqual(provider.synthesis_calls, MODULE.MAX_GENERATION_ATTEMPTS)


class FalsePositiveShapePlacementTests(unittest.TestCase):
    """SSLContextSpec listed init(null, null, null) as a false positive.

    The shape admitted the call "cannot directly satisfy the rule's three
    non-null provenance predicates", so it breaks the rule in a harmless
    context; quad9's buildSocket was dismissed on it while Clash Fest's
    identical call was confirmed.
    """

    NULL_INIT = "ctx.init(null, null, null) relies on provider defaults."
    CACHE_KEY = "MD5 used only to name a cache file."
    OUTGROWN = "A key size the current documentation no longer requires."
    MISREAD = "A literal the detector could not resolve."

    def _payload(self, reviews):
        payload = _valid_v2_payload("ExampleSpec")
        payload["known_false_positive_shapes"] = [shape for shape, *_ in reviews]
        payload["non_security_violation_shapes"] = ["Weak digest as a cache key."]
        payload["false_positive_shape_review"] = [
            {"shape": shape, "breaks_rule_as_written": breaks,
             "constraint_outgrown": outgrown, "compliant_equivalent": equivalent}
            for shape, breaks, outgrown, equivalent in reviews
        ]
        return payload

    def test_a_harmless_violation_with_an_equivalent_moves_with_it_named(self):
        payload = self._payload([
            (self.NULL_INIT, True, False,
             "the same call with an explicit producer of the identical "
             "default"),
            (self.OUTGROWN, True, True, ""),
            (self.MISREAD, False, False, ""),
        ])
        moved = MODULE.place_false_positive_shapes(payload)

        self.assertEqual(payload["known_false_positive_shapes"],
                         [self.OUTGROWN, self.MISREAD])
        self.assertEqual(payload["non_security_violation_shapes"][0],
                         "Weak digest as a cache key.")
        placed = payload["non_security_violation_shapes"][1]
        self.assertTrue(placed.startswith(self.NULL_INIT))
        self.assertIn("explicit producer of the identical default", placed)
        self.assertEqual([item["shape"] for item in moved], [self.NULL_INIT])
        self.assertNotIn("false_positive_shape_review", payload)

    def test_a_harmless_violation_without_an_equivalent_still_moves(self):
        # A cache-key digest has no same-value change that satisfies the
        # rule; the harmless context alone never makes it a false positive.
        payload = self._payload([(self.CACHE_KEY, True, False, "")])
        moved = MODULE.place_false_positive_shapes(payload)

        self.assertEqual(payload["known_false_positive_shapes"], [])
        self.assertEqual(payload["non_security_violation_shapes"][1], self.CACHE_KEY)
        self.assertEqual(moved, [{"shape": self.CACHE_KEY, "compliant_equivalent": ""}])

    def test_an_outgrown_constraint_with_an_equivalent_moves(self):
        # The rule can still be met with the same behaviour, so the finding
        # is a rule-only change rather than a dismissal.
        payload = self._payload([(self.OUTGROWN, True, True, "the larger size")])
        MODULE.place_false_positive_shapes(payload)
        self.assertEqual(payload["known_false_positive_shapes"], [])

    def test_an_equivalent_inside_the_shape_is_still_named(self):
        payload = self._payload([(self.NULL_INIT, True, False, "init(")])
        MODULE.place_false_positive_shapes(payload)
        self.assertIn(
            "Rule-satisfying equivalent that keeps the behaviour: init(",
            payload["non_security_violation_shapes"][1],
        )

    def test_an_equivalent_without_a_broken_rule_keeps_the_shape(self):
        payload = self._payload([(self.MISREAD, False, False, "the same literal")])
        self.assertEqual(MODULE.place_false_positive_shapes(payload), [])
        self.assertEqual(payload["known_false_positive_shapes"], [self.MISREAD])

    def test_a_cosmetically_different_echo_still_matches_its_shape(self):
        payload = self._payload([(self.MISREAD, False, False, "")])
        payload["known_false_positive_shapes"] = [
            self.NULL_INIT, 'getInstance("TLS")  then restrict.',
        ]
        payload["false_positive_shape_review"] = [
            {"shape": "getinstance(“TLS”) then restrict",
             "breaks_rule_as_written": False, "constraint_outgrown": False,
             "compliant_equivalent": ""},
            {"shape": "a paraphrase of the null init",
             "breaks_rule_as_written": True, "constraint_outgrown": False,
             "compliant_equivalent": ""},
        ]
        MODULE.place_false_positive_shapes(payload)
        self.assertEqual(payload["known_false_positive_shapes"],
                         ['getInstance("TLS")  then restrict.'])
        self.assertEqual(payload["non_security_violation_shapes"][1], self.NULL_INIT)

    def test_an_unreviewed_shape_is_refused(self):
        payload = self._payload([(self.MISREAD, False, False, "")])
        payload["known_false_positive_shapes"].append(self.NULL_INIT)
        with self.assertRaisesRegex(ValueError, "false_positive_shape_review"):
            MODULE.place_false_positive_shapes(payload)

    def test_generation_records_the_move_and_drops_the_review(self):
        payload = self._payload([(self.NULL_INIT, True, False, "explicit defaults")])
        payload["source_verified"] = True
        provider = _FakeProvider([("research", json.dumps(payload))])
        with patch.object(MODULE, "verify_source_url", return_value=(True, "HTTP 200")):
            data = MODULE.generate_one_specification("ExampleSpec", [], provider)

        self.assertEqual(data["known_false_positive_shapes"], [])
        self.assertEqual(
            data["generation_evidence"]["false_positive_shape_review"],
            {"version": MODULE.FALSE_POSITIVE_SHAPE_REVIEW_VERSION,
             "moved": [{"shape": self.NULL_INIT,
                        "compliant_equivalent": "explicit defaults"}]},
        )
        self.assertNotIn("false_positive_shape_review", data)

    def test_generation_stamps_the_review_when_nothing_moved(self):
        # An absent stamp means the shapes were never reviewed, so an
        # unchanged review must still leave one.
        payload = self._payload([(self.MISREAD, False, False, "")])
        payload["source_verified"] = True
        provider = _FakeProvider([("research", json.dumps(payload))])
        with patch.object(MODULE, "verify_source_url", return_value=(True, "HTTP 200")):
            data = MODULE.generate_one_specification("ExampleSpec", [], provider)

        self.assertEqual(data["known_false_positive_shapes"], [self.MISREAD])
        self.assertEqual(data["generation_evidence"]["false_positive_shape_review"],
                         {"version": 1, "moved": []})

    def test_the_schema_and_prompt_ask_for_the_review(self):
        schema = MODULE.specification_schema("ExampleSpec")
        self.assertIn("false_positive_shape_review", schema["required"])
        review = schema["properties"]["false_positive_shape_review"]["items"]
        self.assertIn("constraint_outgrown", review["required"])
        _, user = MODULE.prompt_for("ExampleSpec", [])
        self.assertIn("false_positive_shape_review", user)
        self.assertIn("constraint_outgrown", user)

    def test_an_equivalent_must_not_move_the_default_elsewhere(self):
        # A TLS context initialised with nulls has no clean explicit form:
        # the factories' own null/default init is reported under their
        # specifications, and a loaded key store skips the platform's
        # trust configuration. Neither may be offered as the equivalent.
        _, user = MODULE.prompt_for("ExampleSpec", [])
        text = " ".join(user.split())
        review = text[text.index("- false_positive_shape_review"):
                      text.index("- authoritative_sources")]
        self.assertIn("by the same path it selects it", review)
        self.assertIn("passes a null or default argument to another governed API: "
                      'answer "" then', review)
        self.assertIn("skips configuration the null or default applies", review)
        self.assertIn("Network Security Config, a hardware-backed store", review)
        shapes = text[text.index("- non_security_violation_shapes"):
                      text.index("- false_positive_shape_review")]
        self.assertIn("identical object by the same path the current code selects",
                      shapes)
        self.assertIn("passes a null or default argument to another governed API, "
                      "is no such change", shapes)
        self.assertIn("Network Security Config, a hardware-backed store", shapes)
        self.assertNotIn("TrustManagerFactory", text)


class _ReviewProvider:
    """Answers the review-only request with queued responses, recording them."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def generate(self, prompt, system=None, **kwargs):
        self.calls.append({"prompt": prompt, **kwargs})
        return self.responses.pop(0)


class ReviewStoredShapesTests(unittest.TestCase):
    """The maintenance route for specifications generated before the review.

    None of the 74 stored specifications carried the stamp on 2026-10-29,
    and SSLContextSpec's init(null, ...) shape dismissed Aegis's buildSocket.
    """

    NULL_INIT = "ctx.init(null, null, null) relies on provider defaults."
    MISREAD = "A literal the detector could not resolve."

    def _stored(self, shapes):
        data = _valid_v2_payload("ExampleSpec")
        data.pop("false_positive_shape_review")
        data["known_false_positive_shapes"] = list(shapes)
        data["non_security_violation_shapes"] = ["Weak digest as a cache key."]
        data["false_positive_triggers"] = [{"shape_contains": "literal"}]
        data["generation_evidence"] = {"schema_version": 2, "detector_rule": "crysl"}
        return data

    @staticmethod
    def _review(*items):
        return json.dumps({"false_positive_shape_review": [
            {"shape": shape, "breaks_rule_as_written": breaks,
             "constraint_outgrown": False, "compliant_equivalent": ""}
            for shape, breaks in items
        ]})

    def test_only_the_shape_fields_and_the_stamp_change(self):
        stored = self._stored([self.NULL_INIT, self.MISREAD])
        provider = _ReviewProvider(self._review((self.NULL_INIT, True),
                                                (self.MISREAD, False)))
        result = MODULE.review_stored_shapes("ExampleSpec", stored, provider)

        self.assertEqual(result["known_false_positive_shapes"], [self.MISREAD])
        self.assertEqual(result["non_security_violation_shapes"],
                         ["Weak digest as a cache key.", self.NULL_INIT])
        self.assertEqual(result["generation_evidence"], {
            "schema_version": 2, "detector_rule": "crysl",
            "false_positive_shape_review": {
                "version": 1,
                "moved": [{"shape": self.NULL_INIT, "compliant_equivalent": ""}]},
        })
        changed = {key for key in {*stored, *result}
                   if stored.get(key) != result.get(key)}
        self.assertEqual(changed, {"known_false_positive_shapes",
                                   "non_security_violation_shapes",
                                   "generation_evidence"})
        self.assertNotIn("false_positive_shape_review", result)
        # The stored specification itself is not mutated.
        self.assertEqual(stored["known_false_positive_shapes"],
                         [self.NULL_INIT, self.MISREAD])
        [call] = provider.calls
        self.assertFalse(call["web_search"])
        self.assertIn(self.NULL_INIT, call["prompt"])
        self.assertIn("breaks_rule_as_written", call["prompt"])

    def test_a_review_missing_a_shape_is_asked_again(self):
        stored = self._stored([self.NULL_INIT, self.MISREAD])
        provider = _ReviewProvider(self._review((self.MISREAD, False)),
                                   self._review((self.NULL_INIT, False),
                                                (self.MISREAD, False)))
        result = MODULE.review_stored_shapes("ExampleSpec", stored, provider)
        self.assertEqual(len(provider.calls), 2)
        self.assertIn("previous review was rejected", provider.calls[1]["prompt"])
        self.assertEqual(result["generation_evidence"]["false_positive_shape_review"]
                         ["moved"], [])

    def test_a_specification_without_shapes_is_stamped_without_a_call(self):
        provider = _ReviewProvider()
        result = MODULE.review_stored_shapes("ExampleSpec", self._stored([]), provider)
        self.assertEqual(provider.calls, [])
        self.assertEqual(result["generation_evidence"]["false_positive_shape_review"],
                         {"version": 1, "moved": []})

    def test_the_maintenance_mode_skips_reviewed_specifications(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pending = self._stored([self.MISREAD])
            done = dict(self._stored([self.NULL_INIT]), spec_id="DoneSpec", name="DoneSpec")
            done["generation_evidence"] = {
                "false_positive_shape_review": {"version": 1, "moved": []}}
            (root / "ExampleSpec.json").write_text(json.dumps(pending), encoding="utf-8")
            (root / "DoneSpec.json").write_text(json.dumps(done), encoding="utf-8")
            provider = _ReviewProvider(self._review((self.MISREAD, False)))
            with patch.object(MODULE, "remote_provider", return_value=provider):
                status = MODULE.main(["--review-shapes-only",
                                      "--specifications-dir", str(root)])
            written = json.loads((root / "ExampleSpec.json").read_text(encoding="utf-8"))
            untouched = json.loads((root / "DoneSpec.json").read_text(encoding="utf-8"))

        self.assertEqual(status, 0)
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(written["generation_evidence"]["false_positive_shape_review"],
                         {"version": 1, "moved": []})
        self.assertEqual(untouched, done)

    def test_specifications_the_findings_use_are_reviewed_first(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_file = Path(directory) / "findings.csv"
            csv_file.write_text(
                "apk,spec,class,method,message\n"
                "a.apk,SSLContextSpec,A,m,x\n"
                "a.apk,SSLContextSpec,A,n,x\n"
                "b.apk,CipherSpec,B,m,x\n", encoding="utf-8")
            order = MODULE.review_shapes_order(
                ["AlphaSpec", "CipherSpec", "SSLContextSpec"], csv_file)
        self.assertEqual(order, ["SSLContextSpec", "CipherSpec", "AlphaSpec"])

    def test_generation_still_requires_the_findings_file(self):
        with self.assertRaises(SystemExit):
            MODULE.parse_args(["--specifications-dir", "x"])
        arguments = MODULE.parse_args(["--review-shapes-only",
                                       "--specifications-dir", "x"])
        self.assertIsNone(arguments.csv_file)


class ProjectFilteringTests(unittest.TestCase):
    def test_uses_only_the_selected_projects_specs_and_examples(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_file = Path(directory) / "findings.csv"
            csv_file.write_text(
                "apk,spec,class,method,message\n"
                "target.apk,SSLContextSpec,Target,create,TLS finding\n"
                "other.apk,CipherSpec,Other,encrypt,Cipher finding\n",
                encoding="utf-8",
            )
            self.assertEqual(
                MODULE.required_specifications(csv_file, "target.apk"),
                ["SSLContextSpec"],
            )
            self.assertEqual(
                MODULE.specification_examples(csv_file, "target.apk"),
                {"SSLContextSpec": [{
                    "class": "Target", "method": "create",
                    "message": "TLS finding",
                }]},
            )


class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class _FakeRequests:
    def __init__(self, head_status=200, get_status=None, raise_on_head=False):
        self.head_status = head_status
        self.get_status = get_status
        self.raise_on_head = raise_on_head
        self.head_calls = []
        self.get_calls = []

    def head(self, url, **kwargs):
        self.head_calls.append(url)
        if self.raise_on_head:
            raise RuntimeError("connection refused")
        return _FakeResponse(self.head_status)

    def get(self, url, **kwargs):
        self.get_calls.append(url)
        return _FakeResponse(
            self.get_status if self.get_status is not None else 200
        )


class VerifySourceUrlTests(unittest.TestCase):
    def test_accepts_reachable_https_url(self):
        fake = _FakeRequests(head_status=200)
        with patch.object(MODULE, "requests", fake):
            verified, detail = MODULE.verify_source_url("https://example.com/docs")
        self.assertTrue(verified)
        self.assertEqual(detail, "HTTP 200")
        self.assertEqual(fake.head_calls, ["https://example.com/docs"])
        self.assertEqual(fake.get_calls, [])

    def test_falls_back_to_get_when_head_is_rejected(self):
        fake = _FakeRequests(head_status=405, get_status=200)
        with patch.object(MODULE, "requests", fake):
            verified, detail = MODULE.verify_source_url("https://example.com/docs")
        self.assertTrue(verified)
        self.assertEqual(fake.get_calls, ["https://example.com/docs"])

    def test_rejects_a_404(self):
        fake = _FakeRequests(head_status=404, get_status=404)
        with patch.object(MODULE, "requests", fake):
            verified, detail = MODULE.verify_source_url("https://example.com/missing")
        self.assertFalse(verified)
        self.assertEqual(detail, "HTTP 404")

    def test_rejects_when_the_request_raises(self):
        fake = _FakeRequests(raise_on_head=True)
        with patch.object(MODULE, "requests", fake):
            verified, detail = MODULE.verify_source_url("https://example.com/down")
        self.assertFalse(verified)
        self.assertIn("request failed", detail)

    def test_rejects_a_non_http_url(self):
        fake = _FakeRequests()
        with patch.object(MODULE, "requests", fake):
            verified, detail = MODULE.verify_source_url("ftp://example.com/file")
        self.assertFalse(verified)
        self.assertEqual(fake.head_calls, [])

    def test_skips_verification_when_requests_is_unavailable(self):
        with patch.object(MODULE, "requests", None):
            verified, detail = MODULE.verify_source_url("https://example.com/docs")
        self.assertTrue(verified)
        self.assertIn("unavailable", detail)


class RejectedSpecificationRecordTests(unittest.TestCase):
    """A specification that fails every attempt must leave a diagnosis.

    Generating SQLInjectionSpec on 2026-09-07 ran three full research and
    synthesis rounds, roughly 190k input tokens, reported HTTP success on
    every call, wrote no specification, and left nothing anywhere to say
    what deterministic validation had objected to.
    """

    def test_exhausted_attempts_raise_with_every_rejected_candidate(self):
        provider = _FakeProvider([
            ("r1", json.dumps({"spec_id": "WrongName"})),
            ("r2", json.dumps({"spec_id": "WrongName"})),
            ("r3", json.dumps({"spec_id": "WrongName"})),
        ])
        with self.assertRaises(MODULE.SpecificationRejected) as caught:
            MODULE.generate_one_specification("ExampleSpec", [], provider)

        attempts = caught.exception.attempts
        self.assertEqual(len(attempts), MODULE.MAX_GENERATION_ATTEMPTS)
        self.assertEqual([item["attempt"] for item in attempts], [1, 2, 3])
        for item in attempts:
            self.assertTrue(item["validation_error"])
            self.assertIn("WrongName", item["rejected_response"])

    def test_record_is_written_outside_the_loaded_specification_set(self):
        with tempfile.TemporaryDirectory() as directory:
            specifications_dir = Path(directory)
            path = MODULE.write_rejection_record(
                specifications_dir, "ExampleSpec",
                [{"attempt": 1, "validation_error": "boom", "rejected_response": "{}"}],
            )

            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(record["specification"], "ExampleSpec")
            self.assertEqual(record["attempts"][0]["validation_error"], "boom")
            # The registry is loaded with a non-recursive glob, so a rejected
            # candidate parked in a subdirectory can never be mistaken for a
            # usable specification.
            self.assertEqual(list(specifications_dir.glob("*.json")), [])


class GeneratedSpecificationAuditTests(unittest.TestCase):
    """A generated specification is audited as it is written.

    Without it every run that generated a specification left one with no
    source_audit and no shapes_grounded, and the shipped-specifications tests
    failed for each of OutdatedDependencySpec, DeprecatedApiSpec and
    DeprecatedLibrarySpec.
    """

    def _run(self, audit_side_effect=None):
        import argparse as _argparse
        import tempfile as _tempfile
        calls = {"audited": [], "applied": []}

        def fake_audit(path):
            calls["audited"].append(path)
            if audit_side_effect:
                raise audit_side_effect
            return {"path": path, "state": "unreachable_source", "detail": "http_404", "url": ""}

        with _tempfile.TemporaryDirectory() as directory:
            args = _argparse.Namespace(
                csv_file=Path(directory) / "in.csv", project="",
                specifications_dir=Path(directory) / "specs", overwrite=False,
                endpoint="https://example.com/v1", model="m", timeout=10,
                max_output_tokens=100, reasoning_effort="low", prompt_log_dir="",
            )
            with patch.object(MODULE, "parse_args", return_value=args), \
                    patch.object(MODULE, "required_specifications", return_value=["ExampleSpec"]), \
                    patch.object(MODULE, "specification_examples", return_value={}), \
                    patch.object(MODULE, "OpenAIProvider", return_value=object()), \
                    patch.object(MODULE, "resolve_detector_rule_source", return_value={}), \
                    patch.object(MODULE, "generate_one_specification",
                                 return_value=_valid_v2_payload()), \
                    patch.object(MODULE, "audit_specification", side_effect=fake_audit), \
                    patch.object(MODULE, "apply_specification_audit",
                                 side_effect=lambda record: calls["applied"].append(record)):
                status = MODULE.main()
            written = (args.specifications_dir / "ExampleSpec.json").exists()
        return status, written, calls

    def test_the_written_specification_is_audited_and_the_result_applied(self):
        status, written, calls = self._run()
        self.assertEqual(status, 0)
        self.assertTrue(written)
        self.assertEqual([path.name for path in calls["audited"]], ["ExampleSpec.json"])
        self.assertEqual(calls["applied"][0]["state"], "unreachable_source")

    def test_a_failed_audit_does_not_undo_the_generation(self):
        status, written, calls = self._run(audit_side_effect=OSError("network down"))
        self.assertEqual(status, 0)
        self.assertTrue(written)
        self.assertEqual(calls["applied"], [])


if __name__ == "__main__":
    unittest.main()


MOP_URL = "https://rules.example/props/Comparable_CompareToNull.mop"
MOP_RULE = (
    "package mop;\n"
    "Comparable_CompareToNull() {\n"
    "\tevent nullcompare before(Object o) : call(* Comparable+.compareTo(..)) "
    "&& args(o) && if(o == null) {}\n"
    "}\n"
)
RULE_CATALOG = [
    {"name": "javamop_property", "format": "mop", "governs": "spec",
     "url_template": "https://rules.example/props/{spec}.mop"},
    {"name": "crysl_rule", "format": "crysl", "governs": "api_type",
     "url_template": "https://rules.example/crysl/{api_type}.crysl"},
]


def _pages(pages):
    return lambda url: (pages[url], "") if url in pages else ("", "http_404")


class DetectorRuleSourceTests(unittest.TestCase):
    """The detector's own rule anchors the specification generated for it.

    Comparable_CompareToNull was regenerated in run_20260915_175048 citing a
    CrySL file that answers 404 and describing its event as "the literal
    null", while the JavaMOP property it comes from matches an argument that
    is null when compareTo runs. The adjudication dismissed a finding on
    `Intent.ACTION_PICK.compareTo(action)` for want of a literal.
    """

    def test_the_page_declaring_the_property_is_resolved(self):
        with patch.object(MODULE, "fetch_rule_text",
                          side_effect=_pages({MOP_URL: MOP_RULE})):
            source = MODULE.resolve_detector_rule_source(
                "Comparable_CompareToNull", [], RULE_CATALOG)
        self.assertEqual(source["url"], MOP_URL)
        self.assertEqual(source["format"], "mop")
        self.assertIn("if(o == null)", source["content"])

    def test_a_page_declaring_another_rule_is_not_the_source(self):
        with patch.object(MODULE, "fetch_rule_text",
                          side_effect=_pages({MOP_URL: "Other_Property() {}"})):
            self.assertEqual(MODULE.resolve_detector_rule_source(
                "Comparable_CompareToNull", [], RULE_CATALOG), {})

    def test_a_crysl_rule_is_found_through_its_governed_type(self):
        url = "https://rules.example/crysl/Cipher.crysl"
        with patch.object(MODULE, "fetch_rule_text", side_effect=_pages({
                url: "SPEC javax.crypto.Cipher\nOBJECTS\n"})):
            source = MODULE.resolve_detector_rule_source(
                "CipherSpec", [], RULE_CATALOG)
        self.assertEqual((source["url"], source["format"]), (url, "crysl"))

    def test_the_shipped_catalog_names_both_rule_corpora(self):
        formats = {item["format"] for item in MODULE.load_detector_rule_sources()}
        self.assertEqual(formats, {"mop", "crysl"})

    def test_the_prompt_carries_the_rule_instead_of_the_crysl_convention(self):
        source = {"url": MOP_URL, "format": "mop", "content": MOP_RULE}
        _, user = MODULE.prompt_for("Comparable_CompareToNull", [], source)
        self.assertIn(MOP_RULE.strip(), user)
        self.assertIn(MOP_URL, user)
        self.assertNotIn("CROSSINGTUD", user)

    def test_a_property_requires_no_type_named_after_it(self):
        payload = _valid_v2_payload("Comparable_CompareToNull")
        payload["applies_to_types"] = ["java.lang.Comparable"]
        with self.assertRaisesRegex(ValueError, "governed type mismatch"):
            MODULE.validate_specification(payload, "Comparable_CompareToNull", [])
        MODULE.validate_specification(
            payload, "Comparable_CompareToNull", [],
            {"url": MOP_URL, "format": "mop", "content": MOP_RULE})
        # A stored specification citing the property is validated offline.
        payload["source_url"] = MOP_URL
        MODULE.validate_specification(payload, "Comparable_CompareToNull", [])

    def test_a_candidate_must_cite_the_fetched_rule(self):
        source = {"url": MOP_URL, "format": "mop", "content": MOP_RULE}
        wrong = _valid_v2_payload("Comparable_CompareToNull")
        wrong["applies_to_types"] = ["java.lang.Comparable"]
        wrong["source_verified"] = True
        right = dict(wrong, source_url=MOP_URL)
        provider = _FakeProvider([
            ("research", json.dumps(wrong)), ("research", json.dumps(right)),
        ])
        with patch.object(MODULE, "verify_source_url", return_value=(True, "HTTP 200")):
            data = MODULE.generate_one_specification(
                "Comparable_CompareToNull", [], provider, rule_source=source)
        self.assertEqual(data["source_url"], MOP_URL)
        self.assertEqual(provider.synthesis_calls, 2)


class SpecificationReplacementTests(unittest.TestCase):
    """What regeneration may replace, and what it must leave in place."""

    RULE = {"url": "https://rules.example/props/ExampleSpec.mop",
            "format": "mop", "content": "ExampleSpec() {}"}

    def _run(self, existing, generated, audit_state, rule_source=None):
        import argparse as _argparse
        calls = []

        def fake_generate(name, examples, provider, rule_source=None):
            calls.append(rule_source)
            return dict(generated)

        with tempfile.TemporaryDirectory() as directory:
            specs = Path(directory) / "specs"
            specs.mkdir()
            path = specs / "ExampleSpec.json"
            if existing is not None:
                path.write_text(json.dumps(existing), encoding="utf-8")
            args = _argparse.Namespace(
                csv_file=Path(directory) / "in.csv", project="",
                specifications_dir=specs, overwrite=False,
                endpoint="https://example.com/v1", model="m", timeout=10,
                max_output_tokens=100, reasoning_effort="low", prompt_log_dir="",
            )
            audit = {"path": path, "state": audit_state, "detail": "d", "url": ""}
            with patch.object(MODULE, "parse_args", return_value=args), \
                    patch.object(MODULE, "required_specifications", return_value=["ExampleSpec"]), \
                    patch.object(MODULE, "specification_examples", return_value={}), \
                    patch.object(MODULE, "OpenAIProvider", return_value=object()), \
                    patch.object(MODULE, "resolve_detector_rule_source",
                                 return_value=rule_source or {}), \
                    patch.object(MODULE, "generate_one_specification",
                                 side_effect=fake_generate), \
                    patch.object(MODULE, "audit_specification", return_value=audit), \
                    patch.object(MODULE, "apply_specification_audit"):
                status = MODULE.main()
            written = json.loads(path.read_text(encoding="utf-8"))
            rejected = (specs / ".rejected" / "ExampleSpec.json").exists()
        return status, written, rejected, calls

    def test_a_less_grounded_replacement_leaves_the_verified_specification(self):
        # Legacy (no schema_version), so it is regenerated, but verified.
        legacy = {"name": "ExampleSpec", "source_verified": True,
                  "source_audit": {"state": "verified"}, "marker": "old"}
        status, written, rejected, _ = self._run(
            legacy, _valid_v2_payload(), "unreachable_source")
        self.assertEqual(status, 0)
        self.assertEqual(written.get("marker"), "old")
        self.assertTrue(rejected)

    def test_an_equally_grounded_replacement_is_kept(self):
        legacy = {"name": "ExampleSpec", "source_verified": True,
                  "source_audit": {"state": "verified"}, "marker": "old"}
        _, written, rejected, _ = self._run(
            legacy, _valid_v2_payload(), "verified")
        self.assertEqual(written.get("schema_version"), 2)
        self.assertFalse(rejected)

    def test_an_unverified_specification_is_regenerated_from_the_detector_rule(self):
        generated = dict(_valid_v2_payload(), marker="new")
        _, written, _, calls = self._run(
            _valid_v2_payload(), generated, "verified", rule_source=self.RULE)
        self.assertEqual(written.get("marker"), "new")
        self.assertEqual(calls, [self.RULE])
        self.assertEqual(written["detector_rule_source"]["url"], self.RULE["url"])

    def test_an_unverified_specification_without_a_rule_is_left_alone(self):
        existing = _valid_v2_payload()
        _, written, _, calls = self._run(existing, {}, "verified")
        self.assertEqual(calls, [])
        self.assertEqual(written, existing)


class VulnerabilityClassSpecTests(unittest.TestCase):
    """A vulnerability class must not be forced into the CrySL convention.

    expected_api_type_name assumes an XSpec rule governs a type whose simple
    name is X, and validate_specification enforced it for every rule. No API
    type is named ZipSlip or SQLInjection and the CROSSINGTUD corpus has no
    rule for either, so the only answer that passed validation was a fabricated
    governed type -- data/specifications/ZipSlipSpec.json shipped
    "unresolved.ZipSlip" with source_verified false, and the pipeline then
    skipped specification research for the easydiary Zip Slip finding because
    it was not externally anchored.
    """

    def test_a_crysl_rule_keeps_its_governed_type_requirement(self):
        self.assertEqual(MODULE.expected_api_type_name("CipherSpec"), "Cipher")
        self.assertFalse(MODULE.is_vulnerability_class_spec("CipherSpec"))

    def test_a_vulnerability_class_has_no_namesake_governed_type(self):
        self.assertTrue(MODULE.is_vulnerability_class_spec("ZipSlipSpec"))
        self.assertEqual(MODULE.expected_api_type_name("ZipSlipSpec"), "")

    def test_real_platform_types_are_accepted_for_a_vulnerability_class(self):
        data = _valid_v2_payload("ZipSlipSpec")
        data["applies_to_types"] = [
            "java.util.zip.ZipEntry", "java.util.zip.ZipInputStream",
        ]
        self.assertEqual(
            MODULE.validate_specification(data, "ZipSlipSpec")["applies_to_types"],
            ["java.util.zip.ZipEntry", "java.util.zip.ZipInputStream"],
        )

    def test_a_crysl_rule_still_rejects_an_unrelated_governed_type(self):
        data = _valid_v2_payload("CipherSpec")
        data["applies_to_types"] = ["java.util.zip.ZipEntry"]
        with self.assertRaises(ValueError):
            MODULE.validate_specification(data, "CipherSpec")

    def test_the_prompt_sends_each_kind_at_a_different_authority(self):
        _, crysl = MODULE.prompt_for("CipherSpec")
        self.assertIn(MODULE.crysl_source_hint("CipherSpec"), crysl)
        _, weakness = MODULE.prompt_for("ZipSlipSpec")
        # No CrySL URL to chase: that fetch is the one that 404s and leaves
        # the specification unanchored.
        self.assertNotIn(".crysl", weakness)
        self.assertIn("CWE", weakness)


class RuntimeFailureSpecificationTests(unittest.TestCase):
    """Findings that report thrown exceptions are not routed through CrySL."""

    CRASHES = [
        {"class": "org.schabi.newpipe.player.VideoPlayer", "method": "initPlayer",
         "message": "NullPointerException: 'currentMediaSource' is null."},
        {"class": "com.anysoftkeyboard.theme.KeyboardThemeFactory",
         "method": "loadTheme",
         "message": "java.lang.NullPointerException: 'themeContext' is null"},
    ]
    CRYSL = [{"class": "a.B", "method": "c",
              "message": "expecting one of {SHA-256} but found MD5."}]

    def test_throwable_reports_are_recognised(self):
        self.assertEqual(
            MODULE.reported_throwables(self.CRASHES), ["NullPointerException"])
        self.assertTrue(MODULE.is_runtime_failure_spec(self.CRASHES))

    def test_a_mixture_is_described_by_its_protocol(self):
        self.assertFalse(MODULE.is_runtime_failure_spec(self.CRASHES + self.CRYSL))
        self.assertFalse(MODULE.is_runtime_failure_spec([]))

    def test_no_namesake_governed_type_is_required(self):
        self.assertEqual(
            MODULE.expected_api_type_name("NullPointerSpec", self.CRASHES), "")
        data = _valid_v2_payload("NullPointerSpec")
        data["applies_to_types"] = ["java.lang.NullPointerException"]
        MODULE.validate_specification(data, "NullPointerSpec", self.CRASHES)

    def test_without_findings_the_naming_convention_still_applies(self):
        data = _valid_v2_payload("NullPointerSpec")
        data["applies_to_types"] = ["java.lang.NullPointerException"]
        with self.assertRaises(ValueError):
            MODULE.validate_specification(data, "NullPointerSpec")

    def test_the_prompt_anchors_on_the_throwables_documentation(self):
        _, user = MODULE.prompt_for("NullPointerSpec", self.CRASHES)
        self.assertNotIn(".crysl", user)
        self.assertIn("runtime failures", user)

    def test_protocol_findings_keep_the_crysl_route(self):
        _, user = MODULE.prompt_for("CipherSpec", self.CRYSL)
        self.assertIn(MODULE.crysl_source_hint("CipherSpec"), user)


class NoPublishedRuleTests(unittest.TestCase):
    """A rule no detector publishes is not forced into the CrySL convention.

    run_20260921_124815 generated nine specifications for concerns CrySL does
    not model. The validator required each to govern a type named after the
    rule, so six invented one (`unresolved.CursorLeak`,
    `android.webkit.WebViewFileAccess`) and cited a CrySL file that answers
    404, and WebViewJavascriptBridgeSpec found the only way through: a
    third-party class that happens to carry the name. The decision now rests
    on a fact the pipeline establishes -- every detector rule catalog was
    consulted and none publishes the rule -- not on a hand-kept list of names.
    """

    CURSOR_FINDING = [{
        "class": "com.pennywiseai.tracker.ui.screens.settings.SettingsViewModel",
        "method": "checkDownloadStatus",
        "message": "Static candidate (not executed): a Cursor from "
                   "DownloadManager.query is closed on one branch only.",
    }]

    def test_the_prompt_leaves_the_crysl_route_when_no_rule_is_published(self):
        _, user = MODULE.prompt_for("CursorLeakSpec", self.CURSOR_FINDING, {})
        self.assertNotIn(".crysl", user)
        self.assertIn("names a concern", user)
        self.assertIn("another library", user)

    def test_an_unconsulted_catalog_keeps_the_old_default(self):
        # Callers that never resolved the catalog get the behaviour they had.
        _, user = MODULE.prompt_for("CipherSpec")
        self.assertIn(MODULE.crysl_source_hint("CipherSpec"), user)

    def test_real_platform_types_validate_when_no_rule_is_published(self):
        data = _valid_v2_payload("CursorLeakSpec")
        data["applies_to_types"] = ["android.database.Cursor"]
        validated = MODULE.validate_specification(
            data, "CursorLeakSpec", self.CURSOR_FINDING, {},
        )
        self.assertEqual(validated["applies_to_types"], ["android.database.Cursor"])

    def test_the_same_payload_still_fails_when_the_catalog_was_not_consulted(self):
        data = _valid_v2_payload("CursorLeakSpec")
        data["applies_to_types"] = ["android.database.Cursor"]
        with self.assertRaisesRegex(ValueError, "governed type mismatch"):
            MODULE.validate_specification(data, "CursorLeakSpec", self.CURSOR_FINDING)

    def test_a_stored_specification_is_validated_with_what_it_recorded(self):
        # On a later run the stored file is validated without a rule source;
        # its own record says no rule was published, so it stays valid and
        # is not regenerated every run.
        data = _valid_v2_payload("CursorLeakSpec")
        data["applies_to_types"] = ["android.database.Cursor"]
        data["generation_evidence"] = {"detector_rule": MODULE.NO_PUBLISHED_RULE}
        MODULE.validate_specification(data, "CursorLeakSpec", self.CURSOR_FINDING)

    def test_a_published_crysl_rule_keeps_the_naming_requirement(self):
        rule = {"format": "crysl", "url": "https://x/Cipher.crysl"}
        data = _valid_v2_payload("CipherSpec")
        data["applies_to_types"] = ["java.util.zip.ZipEntry"]
        with self.assertRaisesRegex(ValueError, "governed type mismatch"):
            MODULE.validate_specification(data, "CipherSpec", None, rule)


class LegacyCryslDefaultTests(unittest.TestCase):
    """Specifications produced by the old default are regenerated once."""

    def _legacy(self, **overrides) -> dict:
        data = {
            "source_url": "https://raw.githubusercontent.com/CROSSINGTUD/"
                          "Crypto-API-Rules/refs/heads/master/"
                          "JavaCryptographicArchitecture/src/CursorLeak.crysl",
            "source_audit": {"state": "unreachable_source", "detail": "http_404"},
            "generation_evidence": {"detector_examples": []},
        }
        data.update(overrides)
        return data

    def test_a_404_crysl_anchor_from_the_old_default_is_recognised(self):
        self.assertTrue(MODULE.generated_under_the_crysl_default(self._legacy()))

    def test_a_regenerated_specification_does_not_match_again(self):
        regenerated = self._legacy(generation_evidence={
            "detector_rule": MODULE.NO_PUBLISHED_RULE,
        })
        self.assertFalse(MODULE.generated_under_the_crysl_default(regenerated))

    def test_a_reachable_crysl_rule_is_not_legacy(self):
        self.assertFalse(MODULE.generated_under_the_crysl_default(
            self._legacy(source_audit={"state": "verified"})
        ))

    def test_a_namesake_library_is_not_kept_as_better_grounded(self):
        stored = json.dumps({
            "source_verified": True,
            "source_audit": {"state": "verified"},
            "applies_to_types": [
                "com.github.lzyzsd.jsbridge.WebViewJavascriptBridge",
            ],
            "generation_evidence": {"detector_examples": [{
                "class": "app.pwhs.blockads.ui.browser.picker.ElementPickerBridge",
                "method": "onPickerCompleted",
                "message": "the in-app browser registers ElementPickerBridge "
                           "on every page",
            }]},
        })
        self.assertFalse(MODULE.is_source_grounded(stored))
