import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils import detector_labels  # noqa: E402
from cognalys.utils.detector_labels import (  # noqa: E402
    DetectorCatalogError, current_detector_context, detector_tables, load_catalog,
    outranking_record, report_kind, reported_by_detector,
)

ROOT = Path(__file__).resolve().parents[1]
CODES_CSV = ROOT / "data" / "raw" / "exp_novo" / "codes.csv"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# The texts moved from corpus.import_rv_misuses to data/detector_labels.json,
# hashed at d34553c before the move: the move changes no byte of them.
UNCHANGED = {
    "site_kinds": {
        "ALG": "c6961f4f0075bccc", "KEYSIZE": "b827361644d75caf",
        "PROTO": "f5539631b9ed55e6", "KSTYPE": "9a405024f11dd08e",
        "CONSTR": "bedad79d6269fe24", "FORB": "5833ebd6af7e5469",
        "ORDER": "e3ddebb4cb716c0e", "NOBS": "1ac83704be43bc1e",
    },
    "label_meanings": {
        "violation": "e95d4d8c82870a87", "sequence": "0e0d79af55c4bd8b",
        "creation-unobserved": "7e1325704c21874b",
        "creation-refused": "b7ba58f3f1625bbc",
        "reuse-after-final": "d483cdda7c420d28",
        "platform-default": "413807b5a027dda4",
        "upstream-refused": "8af8fa1c9457f759",
        "application-manager": "0ff00c8341942478",
        "not-observed": "3f9af22cb4e27c98",
    },
}
NOT_OBSERVED_SHA = "49ad60d9e976af0e"

# The platform-default meaning stored with 112 input rows and 17 adjudicated
# records (2026-11-10), a verdict the current text no longer gives.
STALE_PLATFORM_DEFAULT = (
    "NOT OBSERVED: the runtime monitor tracks the producers a rule requires by "
    "object identity within one process, and saw none for this object. The "
    "argument was null, which the API documents as 'use the platform default' "
    "(e.g. TrustManagerFactory.init((KeyStore) null)); correct code produces this.")

# CometOTP EncryptionHelper.loadOrGenerateWrappedKey's record (agent_baseline_20261108).
RANDOM_KEY = {"code": "SECRETKEYSPEC-NOBS-03", "site_kind": "NOBS: x",
              "label": "random-key-material", "label_meaning": "stored text",
              "expected": "prepared key material", "value": ""}


class CatalogueTests(unittest.TestCase):
    """data/detector_labels.json: what each label means and what kind of statement it is."""

    def test_every_label_has_a_report_kind_and_a_meaning(self):
        from cognalys.integrations.rvsec import LABEL_PRIORITY
        catalog = load_catalog()
        kinds = catalog["report_kinds"]
        [rvsec] = [entry for entry in catalog["detectors"] if entry["name"] == "rvsec"]
        self.assertEqual(set(rvsec["labels"]), set(LABEL_PRIORITY))
        for label, entry in rvsec["labels"].items():
            self.assertIn(entry["report"], kinds, label)
            self.assertTrue(entry["meaning"].strip(), label)
        for name, kind in kinds.items():
            self.assertTrue(kind["statement"].strip(), name)
            # A flag that changes what the analysis is told says why.
            if kind.get("outranks_rule_text_alternative"):
                self.assertTrue(kind.get("rationale", "").strip(), name)

    @unittest.skipUnless(CODES_CSV.is_file(), "the campaign package (data/raw) is not checked in")
    def test_every_label_and_site_kind_of_the_campaign_codes_is_covered(self):
        tables = detector_tables("rvsec")
        with open(CODES_CSV, encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(rows)
        for row in rows:
            if row.get("label"):
                self.assertIn(row["label"], tables["label_meanings"], row.get("code"))
            if row.get("site_kind"):
                self.assertIn(row["site_kind"], tables["site_kinds"], row.get("code"))

    def test_the_move_to_data_changed_no_byte_of_the_unchanged_texts(self):
        tables = detector_tables("rvsec")
        self.assertEqual(_sha(tables["not_observed"]), NOT_OBSERVED_SHA)
        for table, hashes in UNCHANGED.items():
            self.assertEqual(set(tables[table]) - {"random-key-material"}, set(hashes), table)
            for name, digest in hashes.items():
                self.assertEqual(_sha(tables[table][name]), digest, name)

    def test_the_importer_reads_its_tables_from_the_catalogue(self):
        from cognalys.corpus import import_rv_misuses
        tables = detector_tables("rvsec")
        self.assertEqual(import_rv_misuses.SITE_KINDS, tables["site_kinds"])
        self.assertEqual(import_rv_misuses.LABEL_MEANINGS, tables["label_meanings"])
        self.assertEqual(import_rv_misuses.NOT_OBSERVED, tables["not_observed"])

    def test_random_key_material_states_an_origin_the_check_does_not_admit(self):
        # CometOTP: "NOT OBSERVED ... saw none" and "the normal way to make a
        # key" read as a gap and a verdict; the checker recorded the origin.
        tables = detector_tables("rvsec")
        meaning = tables["label_meanings"]["random-key-material"]
        self.assertFalse(meaning.startswith(tables["not_observed"]))
        self.assertNotIn("normal way", meaning)
        self.assertIn("SecureRandom", meaning)
        self.assertIn("does not admit", meaning)
        self.assertEqual(report_kind({"label": "random-key-material"}), "unadmitted_origin")
        self.assertEqual(report_kind(RANDOM_KEY), "unadmitted_origin")

    def test_the_label_sets_code_reads_come_from_the_report_kinds(self):
        from cognalys.integrations.rvsec import ECHO_LABELS, UNOBSERVED_ORIGIN_LABELS
        self.assertEqual(UNOBSERVED_ORIGIN_LABELS,
                         {"not-observed", "platform-default", "application-manager"})
        self.assertEqual(ECHO_LABELS, {"upstream-refused", "creation-refused"})

    def test_both_data_files_name_the_same_detectors_with_the_same_code_pattern(self):
        emitters = json.loads((ROOT / "data" / "detector_emitters.json").read_text(encoding="utf-8"))
        labels = load_catalog()
        self.assertEqual(
            {entry["name"]: entry["code_pattern"] for entry in emitters["detectors"]},
            {entry["name"]: entry["code_pattern"] for entry in labels["detectors"]})

    def test_a_missing_or_unreadable_catalogue_raises_with_its_path(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "none.json"
            with self.assertRaises(DetectorCatalogError) as raised:
                load_catalog(missing)
            self.assertIn("none.json", str(raised.exception))
            broken = Path(directory) / "broken.json"
            broken.write_text("{", encoding="utf-8")
            with self.assertRaises(DetectorCatalogError):
                load_catalog(broken)


class CurrentMeaningTests(unittest.TestCase):
    """The analysis reads a known label's current meaning, not the stored one."""

    def test_the_old_platform_default_text_is_replaced(self):
        stored = {"code": "SSLCONTEXT-NOBS-01", "label": "platform-default",
                  "label_meaning": STALE_PLATFORM_DEFAULT, "value": "null",
                  "site_kind": "NOBS: an older wording"}
        current = current_detector_context(stored)
        tables = detector_tables("rvsec")
        self.assertEqual(current["label_meaning"], tables["label_meanings"]["platform-default"])
        self.assertEqual(current["site_kind"], "NOBS: " + tables["site_kinds"]["NOBS"])
        self.assertEqual(current["value"], "null")
        # The stored record is not changed in place.
        self.assertEqual(stored["label_meaning"], STALE_PLATFORM_DEFAULT)

    def test_a_record_without_a_stored_meaning_gets_none(self):
        stored = {"code": "SSLCONTEXT-NOBS-01", "label": "platform-default"}
        self.assertEqual(current_detector_context(stored), stored)

    def test_an_unknown_label_another_detectors_code_and_a_code_without_label_pass(self):
        for stored in (
                {"code": "SSLCONTEXT-NOBS-09", "label": "a-new-label", "label_meaning": "x"},
                {"code": "other:rule/7", "label": "platform-default", "label_meaning": "x",
                 "site_kind": "NOBS: y"},
                {"code": "SSLCONTEXT-NOBS-01", "label_meaning": "x", "site_kind": "NOBS: y"}):
            self.assertEqual(current_detector_context(stored), stored)

    def test_another_analyzers_record_keeps_its_texts(self):
        # A record with no code, or a code of another shape, may be another
        # tool's using the same label word; only report_kind reads it by label.
        for stored in (
                {"tool": "static:other", "label": "violation",
                 "label_meaning": "OtherTool: taint reached a sink",
                 "site_kind": "ORDER: OtherTool's own text"},
                {"tool": "static:other", "code": "other.java.crypto.weak-hash",
                 "label": "violation", "label_meaning": "OtherTool: weak hash",
                 "site_kind": "ALG: OtherTool's own text"}):
            self.assertEqual(current_detector_context(stored), stored)
        self.assertEqual(report_kind({"label": "violation"}), "value_check")

    def test_a_site_kind_without_a_known_kind_is_kept(self):
        stored = {"code": "SSLCONTEXT-NOBS-01", "label": "platform-default",
                  "site_kind": "NEWKIND: text"}
        self.assertEqual(current_detector_context(stored), stored)


class ReportedByDetectorTests(unittest.TestCase):
    """Only a report kind flagged outranks_rule_text_alternative reaches the prompts."""

    def test_a_random_key_material_finding_lists_its_record(self):
        error = {"spec": "SecretKeySpecSpec", "method_name": "loadOrGenerateWrappedKey",
                 "detector_context": RANDOM_KEY}
        [record] = reported_by_detector(error)["reported_by_detector"]
        self.assertEqual(record["specification"], "SecretKeySpecSpec")
        self.assertEqual(record["method"], "loadOrGenerateWrappedKey")
        self.assertEqual(record["report"], "unadmitted_origin")
        self.assertEqual(record["code"], "SECRETKEYSPEC-NOBS-03")
        self.assertEqual(record["expected"], "prepared key material")
        self.assertEqual(record["meaning"],
                         detector_tables("rvsec")["label_meanings"]["random-key-material"])
        self.assertEqual(record["report_meaning"],
                         load_catalog()["report_kinds"]["unadmitted_origin"]["statement"])
        # Empty values are left out, and the site kind is not repeated.
        self.assertNotIn("value", record)
        self.assertNotIn("site_kind", record)

    def test_no_other_report_gives_a_record(self):
        for context in ({"code": "SECRETKEYSPEC-NOBS-00", "label": "not-observed"},
                        {"code": "CIPHER-ALG-00", "label": "violation"},
                        {"code": "CIPHER-ALG-00", "label": "a-new-label"},
                        {}):
            error = {"spec": "S", "method_name": "m", "detector_context": context}
            self.assertEqual(reported_by_detector(error), {}, context)
            self.assertEqual(outranking_record(context), {}, context)
        self.assertEqual(reported_by_detector({"spec": "S"}), {})

    def test_a_joint_findings_flagged_record_is_listed_with_its_rule_and_method(self):
        # Session's LogFile$Writer.writeEntry: SecretKeySpecSpec
        # random-key-material and CipherSpec reuse-after-final in one method.
        from cognalys.llm.generate_error_fixes import join_findings_of_one_sequence
        common = {"_file_path": Path("/runs/session.apk/errors.json"),
                  "csv_class": "x.LogFile$Writer", "source_file_path": "LogFile.java",
                  "method_name": "writeEntry", "method_body": "void writeEntry() {}"}
        cipher = {**common, "unique_error_id": "cipher", "spec": "CipherSpec",
                  "detector_context": {"code": "CIPHER-ORDER-03", "label": "reuse-after-final"}}
        key = {**common, "unique_error_id": "key", "spec": "SecretKeySpecSpec",
               "detector_context": RANDOM_KEY}
        self.assertEqual(join_findings_of_one_sequence([cipher, key]), {"key": "cipher"})
        self.assertEqual(cipher["joint_detector_contexts"], {"key": RANDOM_KEY})
        # joint_findings, which every prompt reads, carries no record.
        self.assertNotIn("detector_context", cipher["joint_findings"][0])
        [record] = reported_by_detector(cipher)["reported_by_detector"]
        self.assertEqual((record["specification"], record["method"], record["label"]),
                         ("SecretKeySpecSpec", "writeEntry", "random-key-material"))
        from cognalys.llm.fix_generation_common import reported_by_detector as wrapper
        self.assertEqual(wrapper(cipher), reported_by_detector(cipher))

    def test_a_flag_is_read_from_data_not_from_code(self):
        # On value_check the sentences stay true: the check read a value it
        # observed and does not admit.
        catalog = json.loads(json.dumps(load_catalog()))
        catalog["report_kinds"]["unadmitted_origin"]["outranks_rule_text_alternative"] = False
        catalog["report_kinds"]["value_check"]["outranks_rule_text_alternative"] = True
        self.assertEqual(outranking_record(RANDOM_KEY, catalog=catalog), {})
        record = outranking_record({"code": "CIPHER-ALG-00", "label": "violation",
                                    "value": "DES", "expected": "AES"}, catalog=catalog)
        self.assertEqual(record["report"], "value_check")
        self.assertEqual((record["value"], record["expected"]), ("DES", "AES"))
        self.assertEqual(detector_labels.CATALOG.name, "detector_labels.json")

    def test_a_flag_on_a_kind_without_an_observed_fact_is_refused(self):
        # The sentences say a listed record recorded a fact and that a report
        # of no producer is never listed; on these kinds both would be false.
        for kind in ("unobserved_origin", "echo"):
            catalog = json.loads(json.dumps(load_catalog()))
            catalog["report_kinds"][kind]["outranks_rule_text_alternative"] = True
            catalog["report_kinds"][kind]["rationale"] = "r"
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / f"flagged_{kind}.json"
                path.write_text(json.dumps(catalog), encoding="utf-8")
                with self.assertRaises(DetectorCatalogError) as raised:
                    load_catalog(path)
            self.assertIn(path.name, str(raised.exception))
            self.assertIn(kind, str(raised.exception))

    def test_the_shipped_catalogue_flags_only_kinds_that_record_an_observed_fact(self):
        catalog = load_catalog()
        flagged = {name for name, kind in catalog["report_kinds"].items()
                   if kind.get("outranks_rule_text_alternative")}
        self.assertTrue(flagged)
        self.assertFalse(flagged & {"unobserved_origin", "echo"}, flagged)
        for detector in catalog["detectors"]:
            not_observed = detector.get("not_observed_statement", "")
            for label, entry in (detector.get("labels") or {}).items():
                if entry["report"] in flagged and not_observed:
                    self.assertFalse(entry["meaning"].startswith(not_observed), label)

    def test_the_listed_record_carries_the_flagged_code_not_the_codes_summary(self):
        # Session LogFile$Writer.writeEntry (rvsec_tls_20261015): the label is
        # the highest-priority one among the codes, and the summary also
        # counts four not-observed reports.
        session = {"code": "SECRETKEYSPEC-NOBS-03", "label": "random-key-material",
                   "label_meaning": "stored", "expected": "prepared key material",
                   "value": "",
                   "codes": "SECRETKEYSPEC-NOBS-00 [not-observed] (4), "
                            "SECRETKEYSPEC-NOBS-03 [random-key-material] (3)"}
        record = outranking_record(session, "SecretKeySpecSpec", "writeEntry")
        self.assertNotIn("codes", record)
        self.assertEqual(record["code"], "SECRETKEYSPEC-NOBS-03")
        self.assertNotIn("not-observed", json.dumps(record))

    def test_the_adjudication_rule_says_the_record_is_never_cited_and_value_may_be_absent(self):
        """CometOTP run_v6 (2026-11-10): confirmed_cause cited SECRETKEYSPEC-NOBS-03
        beside SRC-001, and the record carried no value (val='')."""
        from cognalys.llm.finding_adjudication import (
            ADJUDICATION_PROMPT_VERSION, _REPORTED_BY_DETECTOR_ADJUDICATION_RULE as rule)

        self.assertIn("value, when the record has one, what it saw", rule)
        self.assertIn("never cite its code or label as an evidence id", rule)
        self.assertIn("say that the analyzer recorded it", rule)
        self.assertNotIn("value what it saw", rule)
        self.assertGreaterEqual(ADJUDICATION_PROMPT_VERSION, 7)
        # The flagged record has no value, as the sentence now allows.
        self.assertNotIn("value", outranking_record(RANDOM_KEY))

    def test_the_adjudication_prompt_without_a_flagged_record_is_unchanged(self):
        # The sentence is said only with a listed record (the system prompt
        # appends it times bool(reported)); a finding without one gets no
        # reported_by_detector, so its prompt is byte-identical (the full
        # prompt check is test_structured_outputs' byte-identity test).
        import inspect

        from cognalys.llm import finding_adjudication

        source = inspect.getsource(finding_adjudication)
        self.assertEqual(source.count("_REPORTED_BY_DETECTOR_ADJUDICATION_RULE * bool(reported)"), 1)
        self.assertEqual(reported_by_detector({"spec": "S", "method_name": "m",
                                               "detector_context": {"code": "X-00",
                                                                    "label": "not-observed"}}), {})


if __name__ == "__main__":
    unittest.main()
