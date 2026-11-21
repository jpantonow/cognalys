"""Specification fidelity: a specification compared with the CrySL rule it cites."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (project import paths)

from cognalys import cli  # noqa: E402
from cognalys.evaluation import spec_fidelity  # noqa: E402
from cognalys.reporting import finding_statistics  # noqa: E402

KEYSTORE = """SPEC java.security.KeyStore
OBJECTS
	java.lang.String type;
	char[] passwordIn;
EVENTS
	g1: getInstance(type);
	g2: getInstance(type, _);
	Get := g1 | g2;
	l1: load(fileInput, passwordIn);
	Load := l1;
	gk1: key = getKey(alias, passwordKey);
	GetKey := gk1;
ORDER
	Get, Load, GetKey*
CONSTRAINTS
	type in {"JKS", "PKCS12"};
	neverTypeOf[passwordIn, java.lang.String];
ENSURES
	generatedKeyStore[this] after Load;
"""

FAITHFUL = {
    "name": "KeyStoreSpec", "source_url": "https://example/KeyStore.crysl",
    "protocol": "Get, Load, GetKey*",
    "events": [
        {"name": "Get", "api_patterns": ["KeyStore.getInstance("]},
        {"name": "Load", "api_patterns": [".load("]},
        {"name": "GetKey", "api_patterns": [".getKey("]},
    ],
    "detector_semantics": "type must be JKS or PKCS12; neverTypeOf a String; ensures generatedKeyStore",
}


class SpecFidelityTests(unittest.TestCase):
    def test_parse_crysl_reads_events_order_and_constraints(self):
        rule = spec_fidelity.parse_crysl(KEYSTORE)
        self.assertEqual(rule["type"], "java.security.KeyStore")
        self.assertEqual(rule["methods"], ["getInstance", "getKey", "load"])
        self.assertEqual(rule["events"], ["Get", "GetKey", "Load"])
        self.assertEqual(rule["order"], "Get, Load, GetKey*")
        self.assertEqual(rule["constraint_values"], ["JKS", "PKCS12"])
        self.assertEqual(rule["constraint_predicates"], ["neverTypeOf"])
        self.assertEqual(rule["ensures"], ["generatedKeyStore"])

    def test_a_faithful_specification_scores_one(self):
        result = spec_fidelity.compare(FAITHFUL, spec_fidelity.parse_crysl(KEYSTORE))
        self.assertEqual(result["score"], 1.0)
        self.assertTrue(result["dimensions"]["order"]["exact"])

    def test_events_compare_by_the_methods_they_group_not_their_names(self):
        renamed = {**FAITHFUL, "protocol": "Obtain, Open, Read*", "events": [
            {"name": "Obtain", "api_patterns": ["KeyStore.getInstance("]},
            {"name": "Open", "api_patterns": [".load("]},
            {"name": "Read", "api_patterns": [".getKey("]},
        ]}
        result = spec_fidelity.compare(renamed, spec_fidelity.parse_crysl(KEYSTORE))
        self.assertEqual(result["dimensions"]["events"]["recall"], 1.0)
        self.assertTrue(result["dimensions"]["order"]["exact"])

    def test_dropped_values_and_events_are_named(self):
        lossy = {**FAITHFUL, "events": FAITHFUL["events"][:2],
                 "detector_semantics": "type must be JKS"}
        result = spec_fidelity.compare(lossy, spec_fidelity.parse_crysl(KEYSTORE))
        dimensions = result["dimensions"]
        self.assertEqual(dimensions["constraint_values"]["missing"], ["PKCS12"])
        self.assertEqual(dimensions["methods"]["missing"], ["getKey"])
        self.assertLess(result["score"], 1.0)

    def test_specifications_without_a_crysl_rule_are_not_scored(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "A.json").write_text(json.dumps(FAITHFUL))
            Path(directory, "B.json").write_text(json.dumps(
                {"name": "ZipSlipSpec", "source_url": "https://owasp.org/x"}))
            records = spec_fidelity.evaluate(Path(directory), fetch=lambda url: (KEYSTORE, ""))
        statuses = {record["specification"]: record["status"] for record in records}
        self.assertEqual(statuses, {"KeyStoreSpec": "compared", "ZipSlipSpec": "no_reference"})
        self.assertEqual(spec_fidelity.summary(records)["compared"], 1)


KEY_MATERIAL = {
    "name": "KeySpecSpec",
    "detector_semantics": {
        "predicates": ["keyAlgorithm in {\"AES\", \"HmacSHA256\"}",
                       "preparedKeyMaterial[keyMaterial] || randomized[keyMaterial]"],
        "limitations": []},
    # The analyzer's own words quoted back: never read as the specification's.
    "generation_evidence": ["expecting one of {AES, ARC4}"],
}
PROTOCOL = {
    "name": "ContextSpec",
    "protocol": "Get(getInstance with protocol in {TLSv1.2, TLSv1.3}) -> Init",
    "forbidden": "getDefault() is forbidden; call ContextSpec.getInstance(String) instead",
}
SPECIFICATIONS = {spec["name"]: spec for spec in (KEY_MATERIAL, PROTOCOL)}


def _imported(spec, code, expected, apk="a.apk", method="m", origin="app"):
    return {"source": "imported", "file": "f.jsonl", "apk": apk, "class": "C",
            "method": method, "spec": spec, "code": code, "expected": expected,
            "origin": origin}


def _only(block):
    """The single comparison of a block holding one (spec, code, expected)."""
    (code,) = block["codes"]
    (item,) = code["expected"]
    return code, item


class DetectorComparisonTests(unittest.TestCase):
    def test_a_spec_alternative_the_detector_rejects_is_spec_only(self):
        result = spec_fidelity.compare_expected(KEY_MATERIAL, "AES")
        self.assertEqual((result["kind"], result["status"]), ("values", "compared"))
        self.assertEqual(result["spec_only"], ["HmacSHA256"])
        self.assertEqual(result["detector_only"], [])

    def test_a_value_the_spec_does_not_list_is_detector_only(self):
        result = spec_fidelity.compare_expected(PROTOCOL, "TLSV1.2,TLSV1.3,TLS")
        self.assertEqual(result["status"], "compared")
        self.assertEqual(result["spec_only"], [])
        self.assertEqual(result["detector_only"], ["TLS"])
        # The generation examples are not the specification's text.
        self.assertEqual(spec_fidelity.compare_expected(KEY_MATERIAL, "AES,HmacSHA256")
                         ["spec_only"], [])
        self.assertNotIn(("AES", "ARC4"), spec_fidelity.specification_groups(KEY_MATERIAL))

    def test_a_caveat_naming_values_the_rule_does_not_list_is_no_admitted_set(self):
        # KeyStoreSpec's shape: the rule's whitelist stated in prose, and a
        # caveat quoting values that are absent from it.
        caveat = ('Do not infer that getInstance("AndroidKeyStore"), "AndroidCAStore", '
                  'or "BKS" is insecure merely because they are absent from this whitelist.')
        stated = {"name": "StoreSpec", "protocol": "Get, Load",
                  "detector_semantics": {"claim": "The type must be one of JCEKS, JKS, DKS, "
                                                  "PKCS11 or PKCS12.",
                                         "limitations": [caveat]}}
        for field in ("forbidden_inferences_without_evidence", "known_false_positive_shapes",
                      "non_security_violation_shapes", "unknowns"):
            self.assertEqual(spec_fidelity.specification_groups({**stated, field: [caveat]}), [])
        self.assertEqual(spec_fidelity.specification_groups(
            {**stated, "important_note": caveat}), [])
        specification = {**stated, "forbidden_inferences_without_evidence": [caveat],
                         "important_note": caveat}
        result = spec_fidelity.compare_expected(
            specification, "JCEKS,JKS,DKS,PKCS11,PKCS12,AndroidKeyStore,AndroidCAStore,BKS,"
                           "BouncyCastle")
        # The five values the rule admits are not reported as omitted; the
        # four the analyzer adds are, though the caveat names three of them.
        self.assertEqual(result["status"], "values_absent_from_specification")
        self.assertEqual(result["spec_only"], [])
        self.assertEqual(result["detector_only"],
                         ["AndroidCAStore", "AndroidKeyStore", "BKS", "BouncyCastle"])

    def test_a_quoted_detector_message_is_not_the_specification(self):
        specification = {
            "name": "ContextSpec", "protocol": "Get -> Init",
            "semantic_scope": "It constrains the protocol argument to TLSv1.2 or TLSv1.3.",
            "false_positive_triggers": [
                {"detector_message": "expecting one of {TLSv1.2, TLSv1.3} but found TLS."}]}
        self.assertEqual(spec_fidelity.specification_groups(specification), [])
        block = spec_fidelity.compare_detector(
            [_imported("ContextSpec", "CTX-PROTO-00", "TLSv1.2")], {"ContextSpec": specification})
        code, item = _only(block)
        self.assertEqual(item["status"], "values_without_set")
        self.assertFalse(item["compared"])
        self.assertEqual(code["status"], "not_compared")
        self.assertIn("Nothing was compared", spec_fidelity.detector_markdown(block))
        self.assertNotIn("No mismatch", spec_fidelity.detector_markdown(block))

    def test_a_description_naming_an_alternative_is_compared(self):
        result = spec_fidelity.compare_expected(KEY_MATERIAL, "prepared key material")
        self.assertEqual((result["kind"], result["status"]), ("description", "compared"))
        self.assertEqual(result["spec_only"], ["randomized"])
        # A description enumerates nothing, so nothing is detector-only.
        self.assertEqual(result["detector_only"], [])

    def test_a_description_the_spec_does_not_name_is_not_compared(self):
        block = spec_fidelity.compare_detector(
            [_imported("ContextSpec", "CTX-NOBS-00", "a KeyManager[] an observed factory returned")],
            SPECIFICATIONS)
        code, item = _only(block)
        self.assertEqual(item["status"], "description_not_named")
        self.assertFalse(item["compared"])
        self.assertFalse(item["mismatch"])
        self.assertEqual(code["status"], "not_compared")
        self.assertEqual(block["totals"]["not_compared_combinations"], 1)
        self.assertIn("Not compared: ContextSpec CTX-NOBS-00 (description_not_named)",
                      spec_fidelity.detector_markdown(block))

    def test_an_expected_call_is_compared_by_method_name(self):
        named = spec_fidelity.compare_expected(PROTOCOL, "ContextSpec.getInstance(String)")
        self.assertEqual((named["kind"], named["status"], named["detector_only"]),
                         ("call", "call_compared", []))
        unknown = spec_fidelity.compare_expected(PROTOCOL, "Factory.build(String)")
        self.assertEqual(unknown["detector_only"], ["Factory.build(String)"])

    def test_commas_inside_parentheses_do_not_split_the_value(self):
        self.assertEqual(spec_fidelity.expected_items("PBEKeySpec(char[], byte[], int, int)"),
                         ["PBEKeySpec(char[], byte[], int, int)"])
        self.assertEqual(spec_fidelity.expected_items("a, f(b, c) ,d"), ["a", "f(b, c)", "d"])
        self.assertEqual(spec_fidelity.expected_kind(
            spec_fidelity.expected_items("PBEKeySpec(char[], byte[], int, int)")), "call")

    def test_a_code_with_two_expected_strings_is_flagged(self):
        block = spec_fidelity.compare_detector([
            _imported("KeySpecSpec", "KS-ALG-00", "AES,HmacSHA256"),
            _imported("KeySpecSpec", "KS-ALG-00", "AES,HmacSHA256,ARC4", apk="b.apk"),
        ], SPECIFICATIONS)
        (code,) = block["codes"]
        self.assertTrue(code["multiple_expected"])
        self.assertEqual(len(code["expected"]), 2)
        self.assertEqual(code["detector_only"], ["ARC4"])
        self.assertEqual(code["status"], "mismatch")
        self.assertEqual(block["totals"]["multiple_expected_codes"], 1)
        self.assertIn("KS-ALG-00 (several expected values)", spec_fidelity.detector_markdown(block))

    def test_rows_without_an_expected_value_are_counted_not_compared(self):
        block = spec_fidelity.compare_detector([
            _imported("KeySpecSpec", "KS-ALG-00", ""),
            _imported("KeySpecSpec", "KS-ALG-01", "AES,HmacSHA256"),
        ], SPECIFICATIONS)
        self.assertEqual(block["rows"]["imported"], 2)
        self.assertEqual(block["rows"]["imported_with_expected"], 1)
        self.assertEqual([code["code"] for code in block["codes"]], ["KS-ALG-01"])
        self.assertEqual(block["codes"][0]["status"], "no_mismatch")

    def test_findings_files_and_runs_aggregate_final_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            specs = root / "specs"
            specs.mkdir()
            (specs / "KeySpecSpec.json").write_text(json.dumps(KEY_MATERIAL))
            findings = root / "queue" / "findings.jsonl"
            findings.parent.mkdir()
            findings.write_text("\n".join(json.dumps(row) for row in (
                {"apk": "a.apk", "class": "C", "method": "m", "spec": "KeySpecSpec",
                 "origin": "app", "detector_code": "KS-NOBS-00",
                 "detector_expected": "prepared key material"},
                {"apk": "a.apk", "class": "C", "method": "n", "spec": "KeySpecSpec",
                 "origin": "library", "detector_code": "KS-NOBS-00",
                 "detector_expected": "prepared key material"},
                {"apk": "a.apk", "class": "C", "method": "o", "spec": "KeySpecSpec"},
            )) + "\n")
            for run, status in (("run", "first"), ("run_v2", "second")):
                folder = root / "queue" / run / "error_methods" / "a.apk"
                folder.mkdir(parents=True)
                (folder / "0_m.json").write_text(json.dumps({
                    "extraction_metadata": {"apk_name": "a.apk", "csv_index": 0,
                                            "extraction_status": status},
                    "error": {"csv_class": "C", "csv_method": "m", "spec": "KeySpecSpec",
                              "detector_context": {"code": "KS-NOBS-00",
                                                   "expected": "prepared key material"}}}))
            with patch.object(finding_statistics, "final_outcome",
                              side_effect=lambda record: (record["extraction_status"], "")):
                block = spec_fidelity.evaluate_detector(specs, [root / "queue"], [root / "queue"])
        self.assertEqual(block["sources"],
                         {"findings_files": 1, "unreadable_findings_files": 0, "runs": 2})
        self.assertEqual(block["rows"], {"imported": 3, "imported_with_expected": 2,
                                         "analysed": 2, "analysed_with_expected": 2})
        code, item = _only(block)
        self.assertEqual(item["spec_only"], ["randomized"])
        self.assertEqual((item["findings"], item["app_findings"], item["analysed_findings"],
                          item["analysed_records"]), (2, 1, 1, 2))
        self.assertEqual(item["outcomes"], {"first": 1, "second": 1})
        self.assertIn("first: 1, second: 1", spec_fidelity.detector_markdown(block))

    def test_a_csv_with_an_oversized_field_is_skipped_and_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "findings.csv").write_text(
                "apk,class,method,spec,origin,detector_code,detector_expected\n"
                "a.apk,C,m,KeySpecSpec,app,KS-ALG-00,\"AES,HmacSHA256\"\n")
            # One field past the csv module's default limit (131072).
            (root / "dump.csv").write_text('a,b\n"' + "x" * 200_000 + '",1\n')
            rows, files, unreadable = spec_fidelity.detector_rows_from_findings([root])
            block = spec_fidelity.compare_detector(
                rows, SPECIFICATIONS,
                {"findings_files": files, "unreadable_findings_files": unreadable, "runs": 0})
        self.assertEqual((len(rows), files, unreadable), (1, 1, 1))
        self.assertIn("1 findings files could not be read and were skipped.",
                      spec_fidelity.detector_markdown(block))


def _cli(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(argv)
    return code, out.getvalue()


class SpecFidelityCommandTests(unittest.TestCase):
    def test_without_the_new_options_the_output_is_the_rule_report_only(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "A.json").write_text(json.dumps(FAITHFUL))
            output = Path(directory, "out", "fidelity.json")
            records = spec_fidelity.evaluate(Path(directory), fetch=lambda url: (KEYSTORE, ""))
            with patch("cognalys.specifications.audit_specifications.fetch",
                       return_value=(KEYSTORE, "")):
                code, printed = _cli(["spec-fidelity", "--specifications-dir", directory,
                                      "-o", str(output)])
            written = json.loads(output.read_text(encoding="utf-8"))
            markdown_file = output.with_suffix(".md").read_text(encoding="utf-8")
        report = spec_fidelity.markdown(records, spec_fidelity.summary(records))
        self.assertEqual(code, 0)
        self.assertEqual(printed, report + "\n")
        self.assertEqual(markdown_file, report)
        self.assertEqual(written, {"summary": spec_fidelity.summary(records), "records": records})

    def test_no_rule_reports_the_detector_without_the_network(self):
        with tempfile.TemporaryDirectory() as directory:
            specs = Path(directory, "specs")
            specs.mkdir()
            (specs / "ContextSpec.json").write_text(json.dumps(PROTOCOL))
            findings = Path(directory, "findings.csv")
            findings.write_text("apk,class,method,spec,origin,detector_code,detector_expected\n"
                                "a.apk,C,m,ContextSpec,app,CTX-PROTO-00,\"TLSV1.2,TLSV1.3,TLS\"\n")
            output = Path(directory, "fidelity.json")
            with patch("cognalys.specifications.audit_specifications.fetch",
                       side_effect=AssertionError("no network")):
                code, printed = _cli(["spec-fidelity", "--specifications-dir", str(specs),
                                      "--findings", str(findings), "--no-rule", "-o", str(output)])
            written = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        self.assertEqual(set(written), {"detector"})
        self.assertEqual(written["detector"]["codes"][0]["detector_only"], ["TLS"])
        self.assertNotIn("CrySL rule", printed)
        self.assertIn("| ContextSpec | CTX-PROTO-00 | TLSV1.2,TLSV1.3,TLS | - | TLS |", printed)
        self.assertIn("Report only", printed)

    def test_a_missing_findings_or_runs_path_is_an_argument_error(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory, "nope"))
            for option in ("--findings", "--runs"):
                with self.subTest(option=option), \
                        contextlib.redirect_stderr(io.StringIO()) as errors, \
                        self.assertRaises(SystemExit) as raised:
                    _cli(["spec-fidelity", "--specifications-dir", directory, "--no-rule",
                          option, missing])
                self.assertEqual(raised.exception.code, 2)
                self.assertIn(f"{option}: no such file or directory: {missing}",
                              errors.getvalue())

    def test_an_empty_comparison_says_nothing_was_compared(self):
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory, "empty")
            empty.mkdir()
            code, printed = _cli(["spec-fidelity", "--specifications-dir", directory,
                                  "--no-rule", "--findings", str(empty)])
        self.assertEqual(code, 0)
        self.assertIn("0 (specification, code, expected value) combinations", printed)
        self.assertIn("Nothing was compared", printed)
        self.assertNotIn("No mismatch among the compared values.", printed)


if __name__ == "__main__":
    unittest.main()
