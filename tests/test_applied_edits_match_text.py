"""Grocy, 2026-10-23: what a pull request says must match what it changes.

Master had already dropped TLSv1.1, so one of two planned edits added
nothing, and the text still said it did; two KeyStoreSpec findings in one
class got two incompatible patches; and all three were reported as ready.
"""
import unittest
from pathlib import Path

from cognalys.llm.generate_error_fixes import annotate_co_reported_findings
from cognalys.prs.pr_grouping import edits_missing_from_diff
from cognalys.reporting.finding_statistics import final_outcome
from cognalys.solutions.solution_applicator import already_on_base

PROTOCOLS = """    private Socket enableTLSOnSocket(Socket socket) {
      ((SSLSocket)socket).setEnabledProtocols(new String[] {%s});
      return socket;
    }"""
TLS_EDIT = {
    "source_file": "RequestQueueSingleton.java",
    "original_code": PROTOCOLS % '"TLSv1.1", "TLSv1.2", "TLSv1.3"',
    "corrected_code": PROTOCOLS % '"TLSv1.2", "TLSv1.3"',
    "reason": "Removes obsolete TLSv1.1.",
}
INIT_EDIT = {
    "source_file": "RequestQueueSingleton.java",
    "original_code": "SSLContext c = SSLContext.getInstance(\"TLS\");\nc.init(null, null, null);\nc.init(k, t, r);",
    "corrected_code": "SSLContext c = SSLContext.getInstance(\"TLS\");\nc.init(k, t, r);",
    "reason": "Initialise the context once.",
}
DIFF = """diff --git a/RequestQueueSingleton.java b/RequestQueueSingleton.java
--- a/RequestQueueSingleton.java
+++ b/RequestQueueSingleton.java
@@ -100,3 +100,2 @@
 SSLContext c = SSLContext.getInstance("TLS");
-c.init(null, null, null);
 c.init(k, t, r);
"""


class AlreadyOnBaseTests(unittest.TestCase):
    def test_an_edit_the_base_already_made_is_recognised(self):
        base = "class A {\n" + PROTOCOLS % '"TLSv1.2",   "TLSv1.3"' + "\n}"
        self.assertTrue(already_on_base(TLS_EDIT, base))

    def test_an_edit_still_needed_on_the_base_is_not(self):
        base = "class A {\n" + TLS_EDIT["original_code"] + "\n}"
        self.assertFalse(already_on_base(TLS_EDIT, base))

    def test_a_created_file_is_never_already_on_base(self):
        self.assertFalse(already_on_base({**TLS_EDIT, "edit_kind": "create"}, TLS_EDIT["corrected_code"]))


class EditsMissingFromDiffTests(unittest.TestCase):
    def test_an_edit_whose_lines_are_not_in_the_diff_is_named(self):
        self.assertEqual(edits_missing_from_diff([INIT_EDIT, TLS_EDIT], DIFF),
                         ["Removes obsolete TLSv1.1."])

    def test_every_edit_in_the_diff_gives_nothing(self):
        self.assertEqual(edits_missing_from_diff([INIT_EDIT], DIFF), [])


class CoReportedFindingsTests(unittest.TestCase):
    def test_findings_of_one_class_see_each_other_and_no_other(self):
        apk = Path("/runs/grocy.apk/errors.json")
        load = {"_file_path": apk, "unique_error_id": "a", "spec": "KeyStoreSpec",
                "csv_class": "x.X509KeyStoreFile", "method_name": "load"}
        save = {"_file_path": apk, "unique_error_id": "b", "spec": "KeyStoreSpec",
                "csv_class": "x.X509KeyStoreFile$Inner", "method_name": "save"}
        other = {"_file_path": apk, "unique_error_id": "c", "spec": "SSLContextSpec",
                 "csv_class": "x.NetUtil", "method_name": "insertConscrypt"}
        annotate_co_reported_findings([load, save, other])
        self.assertEqual([item["method"] for item in load["co_reported_findings"]], ["save"])
        self.assertEqual([item["method"] for item in save["co_reported_findings"]], ["load"])
        self.assertNotIn("co_reported_findings", other)


class HeldPullRequestTests(unittest.TestCase):
    def test_a_pull_request_with_text_problems_is_not_ready(self):
        record = {"solution": True, "apply_status": "SUCCESS", "build_status": "success",
                  "pr_held": "describes a change that is not in the diff: Removes obsolete TLSv1.1."}
        outcome, detail = final_outcome(record)
        self.assertEqual(outcome, "correção gerada, sem PR")
        self.assertIn("TLSv1.1", detail)


class RepairTextTests(unittest.TestCase):
    """A text with problems is rewritten from the edits in the diff."""

    def test_a_text_promising_a_missing_edit_is_rewritten(self):
        import json
        import tempfile
        from cognalys.prs.pr_generator import PrGenerator

        class Client:
            def __init__(self):
                self.prompts = []

            def generate(self, prompt, system, **kwargs):
                self.prompts.append(prompt)
                return json.dumps({
                    "title": "Initialize the TLS context once",
                    "summary": "TLSSocketFactory initialized its SSLContext twice; "
                               "I removed the empty first call.",
                })

        with tempfile.TemporaryDirectory() as directory:
            generator = PrGenerator(str(Path(directory) / "report.json"), output_dir=directory,
                                    style="v3", text_model={"model": "fake"})
            client = Client()
            generator._text_client = client
            solution = {"method_name": "<init>", "spec": "SSLContextSpec", "tool": "rvsec",
                        "csv_class": "x.RequestQueueSingleton$TLSSocketFactory",
                        "coordinated_edits": [INIT_EDIT, TLS_EDIT],
                        "explanation": "<!-- pr-title: Initialize the TLS context once and drop TLSv1.1 -->\n"
                                       "I also removed TLSv1.1."}
            title = generator.descriptive_title(solution, "Fix <init>")
            body = generator.build_pr_body(solution, DIFF)
            problems = generator.text_problems_of(solution, title, body, DIFF)
            self.assertTrue(problems)
            repaired, title, body, problems = generator.repair_text(
                solution, "Fix <init>", DIFF, title, body, problems)

        self.assertEqual(problems, [])
        self.assertEqual(title, "Initialize the TLS context once")
        self.assertNotIn("TLSv1.1", body)
        self.assertEqual(repaired["coordinated_edits"], [INIT_EDIT])
        # The model was told what was wrong, and given only the edit in the diff.
        self.assertIn("not in the diff", client.prompts[0])
        self.assertNotIn("Removes obsolete TLSv1.1.\"", client.prompts[0].split('"coordinated_edits":', 1)[1])

    def test_without_a_model_the_text_is_kept_and_held(self):
        import tempfile
        from cognalys.prs.pr_generator import PrGenerator

        with tempfile.TemporaryDirectory() as directory:
            generator = PrGenerator(str(Path(directory) / "report.json"), output_dir=directory)
            result = generator.repair_text({}, "Fix", DIFF, "t", "b", ["x"])
        self.assertEqual(result[1:], ("t", "b", ["x"]))


class BehaviorReviewTests(unittest.TestCase):
    """A patch that compiles but breaks a path, or needs the maintainer, is not complete."""

    def _generate(self, review, path="src/Main.java"):
        import json
        import tempfile
        from cognalys.llm.generate_error_fixes import FixGenerator

        class Provider:
            def __init__(self):
                self.calls = []

            def generate(self, prompt, *args, **kwargs):
                self.calls.append(kwargs.get("schema_name"))
                if kwargs.get("schema_name") == "behavior_review":
                    self.review_system = args[0] if args else kwargs.get("system", "")
                    return json.dumps(review(len(self.calls)))
                return json.dumps({
                    "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                    "source_file_path": path, "explanation": "e",
                    "edits": [{"source_file_path": path, "symbol": "value",
                               "edit_kind": "declaration", "original_code": "int value = 1;",
                               "corrected_code": "int value = 2;", "reason": "r"}],
                    "no_change_required": False, "provided_contracts": [],
                    "required_contracts": [], "required_tests": [],
                    "manual_review_required": True, "review_assumptions": [],
                    "confidence": "high",
                })

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "repo" / path).parent.mkdir(parents=True)
            (root / "repo" / path).write_text("class X { int value = 1; }", encoding="utf-8")
            generator = object.__new__(FixGenerator)
            generator.output_dir = root / "out"
            generator.provider = Provider()
            generator.web_search = False
            generator.logger = __import__("logging").getLogger("test")
            error = {"repository_path": str(root / "repo"), "error_index": 2,
                     "evidence_analysis": {"confirmed_cause": "cause", "coordinated_fix_plan": {
                         "required_edits": [{"source_file_path": path, "symbol": "value"}]}}}
            result = generator.generate_coordinated_file_drafts(
                error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "method")
        self.review_system = getattr(generator.provider, "review_system", "")
        return result, generator.provider.calls

    def test_a_regression_sends_the_patch_back_for_another_draft(self):
        def review(call):
            if call == 2:
                return {"regressions": [{"source_file_path": "src/Main.java",
                                         "scenario": "first run, file absent",
                                         "before": "creates the keystore", "after": "throws"}],
                        "maintainer_decision_required": False, "maintainer_decision": "",
                        "rationale": ""}
            return {"regressions": [], "maintainer_decision_required": False,
                    "maintainer_decision": "", "rationale": ""}

        result, calls = self._generate(review)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(calls.count("behavior_review"), 2)

    def test_a_decision_without_any_regression_is_a_note_not_a_block(self):
        # Grocy's save (v4): no concrete regression, only "the empty file is
        # now written on the first storeKey" -- proposed, with the note.
        result, _ = self._generate(lambda call: {
            "regressions": [], "maintainer_decision_required": True,
            "maintainer_decision": "the empty keystore file is created on the first entry",
            "rationale": ""})
        self.assertEqual(result["status"], "complete")
        self.assertIn("For the maintainer to decide: the empty keystore file is created "
                      "on the first entry", result["review_assumptions"])

    def test_the_review_shares_its_names_with_finding_processing(self):
        # The note's prefix is what generate_github_previews recognises, and
        # finding_processing drops review-removed tests by the same test-path
        # predicate the review removes them under.
        from cognalys.llm import coordinated_generation, finding_processing
        self.assertEqual(coordinated_generation.MAINTAINER_DECISION_PREFIX,
                         "For the maintainer to decide:")
        self.assertIs(finding_processing.is_test_path, coordinated_generation.is_test_path)
        self.assertTrue(coordinated_generation.is_test_path("app/src/test/java/ATest.java"))
        self.assertTrue(coordinated_generation.is_test_path("app/src/androidTest/kotlin/A.kt"))
        self.assertFalse(coordinated_generation.is_test_path("app/src/main/java/Test.java"))

    def test_one_definition_of_a_test_file(self):
        """B8: the three rules (a substring, the file name, a regex) are one."""
        from cognalys.llm import patch_effect_checks, semantic_validation
        from cognalys.llm.coordinated_generation import is_test_path
        from cognalys.utils.test_source_sets import is_test_source

        for path, expected in (
                ("app/src/test/java/a/CipherTest.java", True),
                ("app/src/androidTest/kotlin/a/Flow.kt", True),
                ("shared/src/commonTest/kotlin/a/Codec.kt", True),
                ("app/src/androidUnitTest/kotlin/a/Key.kt", True),
                ("app/src/sharedTest/java/a/Fixture.java", True),
                ("test/a/Helper.java", True),
                ("lib/tests/Vectors.kt", True),
                ("legacy/CryptoTest.java", True),
                ("legacy/CryptoTests.kt", True),
                ("legacy/CryptoIT.java", True),
                # A production source set is production whatever it is called.
                ("app/src/main/java/a/Attestation.kt", False),
                ("app/src/main/java/a/latest/Store.kt", False),
                ("app/src/main/java/a/test/Probe.java", False),
                ("app/src/main/java/a/LatestTest.java", False),
                ("legacy/Attestation.java", False),
                ("build.gradle", False)):
            with self.subTest(path=path):
                self.assertIs(is_test_source(path), expected)
                self.assertIs(is_test_path(path), expected)
                self.assertIs(patch_effect_checks._is_test_edit({"source_file_path": path}),
                              expected)
                self.assertIs(semantic_validation._is_test_edit({"source_file_path": path}),
                              expected)

    def test_an_edit_the_base_branch_already_holds_is_not_reviewed(self):
        import subprocess
        import tempfile
        from cognalys.llm.coordinated_generation import edits_already_on_base

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q", "-b", "master", str(repo)], check=True)
            (repo / "RequestQueueSingleton.java").write_text(
                "class A {\n" + TLS_EDIT["corrected_code"] + "\n}\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
                            "commit", "-qm", "base"], check=True)
            tls = {**TLS_EDIT, "source_file_path": "RequestQueueSingleton.java"}
            init = {**INIT_EDIT, "source_file_path": "RequestQueueSingleton.java"}
            found = edits_already_on_base(
                {"repository_path": str(repo),
                 "contribution_base": {"base_ref": "refs/heads/master"}}, [tls, init])
        self.assertEqual(found, {id(tls)})

    def test_the_review_reads_the_edits_the_base_already_holds_as_present(self):
        # NotallyX md5Hash (comparison arm C, 2026-11-13): main already had the
        # renamed sha256Hash overloads, the review saw only the callers' edits
        # and refused all six drafts as calling functions that do not exist.
        import json
        import subprocess
        import tempfile
        from cognalys.llm.generate_error_fixes import FixGenerator

        declaration = {"source_file_path": "IOExtensions.kt", "symbol": "md5Hash",
                       "original_code": 'fun File.md5Hash(): ByteArray = digest("MD5")',
                       "corrected_code": 'fun File.sha256Hash(): ByteArray = digest("SHA-256")',
                       "reason": "r"}
        caller = {"source_file_path": "ExportExtensions.kt", "symbol": "export",
                  "original_code": "val source = zip.md5Hash()",
                  "corrected_code": "val source = zip.sha256Hash()", "reason": "r"}

        class Provider:
            def __init__(self):
                self.requests = []

            def generate(self, prompt, system, **kwargs):
                self.requests.append((prompt, system))
                return json.dumps({"regressions": [], "maintainer_decision_required": False,
                                   "maintainer_decision": "", "rationale": ""})

        def review(edits):
            with tempfile.TemporaryDirectory() as directory:
                repo = Path(directory)
                subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
                (repo / "IOExtensions.kt").write_text(declaration["corrected_code"] + "\n",
                                                      encoding="utf-8")
                (repo / "ExportExtensions.kt").write_text(caller["original_code"] + "\n",
                                                          encoding="utf-8")
                subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
                subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c",
                                "user.email=t@t", "commit", "-qm", "base"], check=True)
                generator = object.__new__(FixGenerator)
                generator.provider = Provider()
                generator.logger = __import__("logging").getLogger("test")
                generator.review_patch_behavior(
                    {"repository_path": str(repo), "method_name": "md5Hash",
                     "contribution_base": {"base_ref": "refs/heads/main"}},
                    [dict(edit) for edit in edits],
                    {"ExportExtensions.kt": caller["original_code"],
                     "IOExtensions.kt": declaration["original_code"]})
            prompt, system = generator.provider.requests[0]
            body = prompt.split("<patch_and_source untrusted_data=\"true\">\n", 1)[1]
            return json.loads(body.rsplit("\n</patch_and_source>", 1)[0]), system

        payload, system = review([declaration, caller])
        self.assertEqual([edit["source_file_path"] for edit in payload["edits"]],
                         ["ExportExtensions.kt"])
        self.assertEqual(payload["edits_already_on_base"],
                         [{"source_file_path": "IOExtensions.kt", "symbol": "md5Hash",
                           "corrected_code": declaration["corrected_code"]}])
        self.assertIn("edits_already_on_base", system)
        # A patch the base holds none of is reviewed as before.
        payload, _ = review([caller])
        self.assertNotIn("edits_already_on_base", payload)


class JointFindingsTests(unittest.TestCase):
    """Grocy: load calls save, both KeyStoreSpec: one analysis, one change."""

    def _errors(self):
        apk = Path("/runs/grocy.apk/errors.json")
        common = {"_file_path": apk, "spec": "KeyStoreSpec",
                  "csv_class": "x.X509KeyStoreFile", "source_file_path": "X509KeyStoreFile.java"}
        load = {**common, "unique_error_id": "load", "method_name": "load",
                "method_body": "public void load(boolean c) { ks.load(null, null); if (c) { save(); } }"}
        save = {**common, "unique_error_id": "save", "method_name": "save",
                "method_body": "private void save() { ks.store(out, p); }"}
        other = {**common, "unique_error_id": "get", "method_name": "getAliases",
                 "method_body": "public Collection<String> getAliases() { return list(); }"}
        return load, save, other

    def test_a_callee_with_the_same_rule_is_joined_into_its_caller(self):
        from cognalys.llm.generate_error_fixes import join_findings_of_one_sequence
        load, save, other = self._errors()
        self.assertEqual(join_findings_of_one_sequence([load, save, other]), {"save": "load"})
        self.assertEqual([item["method"] for item in load["joint_findings"]], ["save"])
        self.assertEqual(save["joined_into"], "load")
        self.assertNotIn("joint_findings", other)

    def test_another_class_is_not_joined_but_another_rule_in_the_sequence_is(self):
        from cognalys.llm.generate_error_fixes import join_findings_of_one_sequence
        load, save, _ = self._errors()
        self.assertEqual(join_findings_of_one_sequence([load, {**save, "csv_class": "x.Other"}]), {})
        load, save, _ = self._errors()
        self.assertEqual(join_findings_of_one_sequence([load, {**save, "spec": "CipherSpec"}]),
                         {"save": "load"})

    def test_two_rules_reported_in_one_method_are_one_finding(self):
        """KeyPass's decrypt: IvParameterSpecSpec and CipherSpec, two incompatible drafts."""
        from cognalys.llm.generate_error_fixes import join_findings_of_one_sequence
        _, _, other = self._errors()
        body = "String decrypt(byte[] d) { c.init(2, k, new IvParameterSpec(iv)); return c.doFinal(d); }"
        iv = {**other, "unique_error_id": "iv", "method_name": "decrypt", "spec": "IvParameterSpecSpec",
              "method_body": body, "error_message": "no randomized source of the iv was observed"}
        cipher = {**other, "unique_error_id": "cipher", "method_name": "decrypt", "spec": "CipherSpec",
                  "method_body": body,
                  "error_message": "no generator of the key given to Cipher.init was observed"}
        self.assertEqual(join_findings_of_one_sequence([iv, cipher, other]), {"cipher": "iv"})
        self.assertEqual(iv["joint_findings"][0]["specification"], "CipherSpec")
        self.assertNotIn("joint_findings", other)

    def test_one_report_at_several_steps_of_a_lifecycle_is_one_finding(self):
        """Amethyst's MacInstance: 'initialised again' at update, doFinal and init."""
        from cognalys.llm.generate_error_fixes import join_findings_of_one_sequence
        _, _, other = self._errors()
        message = "the Mac was initialised again after it completed an operation"
        steps = [{**other, "unique_error_id": name, "method_name": name, "spec": "MacSpec",
                  "error_message": message, "method_body": f"void {name}() {{}}"}
                 for name in ("update", "doFinal", "init")]
        construct = {**other, "unique_error_id": "ctor", "method_name": "<init>", "spec": "MacSpec",
                     "error_message": "the key given to Mac.init was not observed coming from a generator"}
        self.assertEqual(join_findings_of_one_sequence([*steps, construct]),
                         {"doFinal": "update", "init": "update"})
        self.assertNotIn("joined_into", construct)

    def bookwyrm_findings(self):
        apk = Path("/runs/bookwyrm.apk/errors.json")
        context = {"applies_to_types": ["javax.crypto.spec.GCMParameterSpec"],
                   "events": [{"api_patterns": ["GCMParameterSpec.<init>("]}]}
        common = {"_file_path": apk, "spec": "GCMParameterSpecSpec", "specification_context": context,
                  "error_message": "the IV material was not observed to come from a randomized source"}
        login = {**common, "unique_error_id": "login", "method_name": "LogIn",
                 "csv_class": "b.MainActivity", "source_file_path": "MainActivity.java",
                 "method_body": (
                     "c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, magicCode.getBytes()));\n"
                     "editorMagic.putString(getString(R.string.q), magicCode);\n"
                     "editor.putString(getString(R.string.server), server);")}
        start = {**common, "unique_error_id": "start", "method_name": "onCreate",
                 "csv_class": "b.StartActivity", "source_file_path": "StartActivity.java",
                 "method_body": (
                     "String codeMagic = sharedPrefMagic.getString(getString(R.string.q), defaultValue);\n"
                     "c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, codeMagic.getBytes()));")}
        return login, start

    def test_the_writer_and_reader_of_one_stored_value_are_one_finding(self):
        """BookWyrm (2026-10-31): LogIn stores the GCM IV that StartActivity.onCreate
        reads back; two units wrote two incompatible formats."""
        from cognalys.llm.generate_error_fixes import join_findings_of_one_sequence
        login, start = self.bookwyrm_findings()
        self.assertEqual(join_findings_of_one_sequence([start, login]), {"start": "login"})
        self.assertEqual(login["joint_findings"][0]["stored_value_key"], "R.string.q")

    def test_a_shared_key_name_in_unrelated_code_modules_or_chains_stays_apart(self):
        """2026-11-01 review: "password" stored by one class and read by another
        for something else, another module, one writer for two readers."""
        from cognalys.llm.generate_error_fixes import join_findings_of_one_sequence
        login, start = self.bookwyrm_findings()
        start["method_body"] = ("String codeMagic = prefs.getString(getString(R.string.q), d);\n"
                                "c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, other));\n"
                                "show(codeMagic);")
        self.assertEqual(join_findings_of_one_sequence([login, start]), {})
        login, start = self.bookwyrm_findings()
        login["source_file_path"] = "app/src/main/java/b/MainActivity.java"
        start["source_file_path"] = "wear/src/main/java/b/StartActivity.java"
        self.assertEqual(join_findings_of_one_sequence([login, start]), {})
        login, start = self.bookwyrm_findings()
        second = {**start, "unique_error_id": "second", "csv_class": "b.ThirdActivity",
                  "source_file_path": "ThirdActivity.java"}
        self.assertEqual(join_findings_of_one_sequence([login, start, second]), {})

    def test_another_key_or_a_value_the_governed_call_does_not_use_stays_apart(self):
        from cognalys.llm.generate_error_fixes import join_findings_of_one_sequence
        login, start = self.bookwyrm_findings()
        start["method_body"] = start["method_body"].replace("R.string.q", "R.string.other")
        self.assertEqual(join_findings_of_one_sequence([login, start]), {})
        login, start = self.bookwyrm_findings()
        start["method_body"] = start["method_body"].replace("R.string.q", "R.string.server")
        self.assertEqual(join_findings_of_one_sequence([login, start]), {})
        login, start = self.bookwyrm_findings()
        self.assertEqual(join_findings_of_one_sequence([login, {**start, "spec": "CipherSpec"}]), {})

    def tokn_findings(self):
        _, _, other = self._errors()
        message = "the key given to Cipher.init was not observed coming from a generator"
        encrypt = {**other, "unique_error_id": "encrypt", "method_name": "encrypt",
                   "spec": "CipherSpec", "error_message": message,
                   "method_body": "fun encrypt(d: ByteArray) { c.init(1, key()) }"}
        decrypt = {**other, "unique_error_id": "decrypt", "method_name": "decrypt",
                   "spec": "CipherSpec", "error_message": message,
                   "method_body": "fun decrypt(d: ByteArray) { c.init(2, key(), GCMParameterSpec(128, iv)) }"}
        gcm = {**decrypt, "unique_error_id": "gcm", "spec": "GCMParameterSpecSpec",
               "error_message": "the IV was not observed coming from a randomized source"}
        return encrypt, decrypt, gcm

    def test_a_finding_in_the_method_of_a_joined_one_joins_its_primary(self):
        """Tokn (2026-10-28): decrypt [CipherSpec] joined encrypt, and decrypt
        [GCMParameterSpecSpec], in the same method, was analysed alone."""
        from cognalys.llm.generate_error_fixes import join_findings_of_one_sequence
        encrypt, decrypt, gcm = self.tokn_findings()
        self.assertEqual(join_findings_of_one_sequence([encrypt, decrypt, gcm]),
                         {"decrypt": "encrypt", "gcm": "encrypt"})
        self.assertEqual([item["unique_error_id"] for item in encrypt["joint_findings"]],
                         ["decrypt", "gcm"])
        self.assertEqual(gcm["joined_into"], "encrypt")
        # In any order the three are one group, under the first discovered.
        encrypt, decrypt, gcm = self.tokn_findings()
        self.assertEqual(join_findings_of_one_sequence([gcm, encrypt, decrypt]),
                         {"decrypt": "gcm", "encrypt": "gcm"})
        self.assertNotIn("joint_findings", encrypt)
        # Another file is never joined.
        encrypt, decrypt, gcm = self.tokn_findings()
        gcm["source_file_path"] = "Other.kt"
        self.assertEqual(join_findings_of_one_sequence([encrypt, decrypt, gcm]),
                         {"decrypt": "encrypt"})

    def test_a_caller_joined_into_its_own_caller_brings_its_callee(self):
        from cognalys.llm.generate_error_fixes import join_findings_of_one_sequence
        _, _, other = self._errors()
        inner = {**other, "unique_error_id": "inner", "method_name": "inner",
                 "method_body": "void inner() { ks.store(out, p); }"}
        middle = {**other, "unique_error_id": "middle", "method_name": "middle", "spec": "CipherSpec",
                  "method_body": "void middle() { inner(); }"}
        outer = {**other, "unique_error_id": "outer", "method_name": "outer", "spec": "MacSpec",
                 "method_body": "void outer() { middle(); }"}
        self.assertEqual(join_findings_of_one_sequence([middle, outer, inner]),
                         {"inner": "outer", "middle": "outer"})
        self.assertEqual(sorted(item["unique_error_id"] for item in outer["joint_findings"]),
                         ["inner", "middle"])
        self.assertNotIn("joint_findings", middle)
        self.assertEqual(inner["joined_into"], "outer")

    def test_a_joined_finding_ends_where_its_caller_ends(self):
        import json
        import tempfile
        from cognalys.reporting.finding_statistics import final_outcome, read_run

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            solutions = run / "error_solutions"
            (solutions / "issue_candidates/grocy.apk").mkdir(parents=True)
            (solutions / "issue_candidates/grocy.apk/3_load_issue.json").write_text(json.dumps({
                "apk_name": "grocy.apk", "csv_class": "x.K", "method_name": "load",
                "spec": "KeyStoreSpec", "issue_target": "application_repository"}))
            identity = {"apk_name": "grocy.apk", "csv_class": "x.K", "spec": "KeyStoreSpec"}
            (solutions / "joint_findings.json").write_text(json.dumps([{
                "joined": {**identity, "method_name": "save"},
                "into": {**identity, "method_name": "load"}}]))
            records = read_run(run)
        outcome, detail = final_outcome(records[("grocy.apk", "x.K", "save", "KeyStoreSpec")])
        self.assertEqual(outcome, "issue para o mantenedor do app")
        # An issue resolves nothing: analysed with load, not resolved with it
        # (2026-10-31, JoinedFindingLabelTests).
        self.assertIn("analisado junto com load", detail)


class NoSecurityImpactTests(unittest.TestCase):
    def test_the_marker_gives_the_no_impact_outcome(self):
        import json
        import tempfile
        from cognalys.reporting.finding_statistics import final_outcome, read_run

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            marker = run / "error_solutions/no_security_impact/grocy.apk/4_getTrustManager.json"
            marker.parent.mkdir(parents=True)
            marker.write_text(json.dumps({
                "apk_name": "grocy.apk", "csv_class": "x.M", "method_name": "getTrustManager",
                "spec": "TrustManagerFactorySpec",
                "reason": "init(null) selects the platform trust policy"}))
            records = read_run(run)
        outcome, detail = final_outcome(records[("grocy.apk", "x.M", "getTrustManager",
                                                 "TrustManagerFactorySpec")])
        self.assertEqual(outcome, "violação sem impacto de segurança")
        self.assertIn("platform trust policy", detail)

    def test_correct_use_needs_regressions_and_a_reason(self):
        from cognalys.llm.generate_error_fixes import FixGenerator
        import json

        class Provider:
            def __init__(self, answer):
                self.answer = answer

            def generate(self, *args, **kwargs):
                return json.dumps(self.answer)

        generator = object.__new__(FixGenerator)
        base = {"maintainer_decision_required": False, "maintainer_decision": "",
                "current_code_is_correct_use": True, "rationale": ""}
        generator.provider = Provider({**base, "regressions": [], "correct_use_reason": "documented"})
        self.assertFalse(generator.review_patch_behavior({}, [], {})["current_code_is_correct_use"])
        generator.provider = Provider({**base, "correct_use_reason": "documented", "regressions": [
            {"source_file_path": "a", "scenario": "s", "before": "b", "after": "a"}]})
        self.assertTrue(generator.review_patch_behavior({}, [], {})["current_code_is_correct_use"])


class FdroidBuildRecoveryTests(unittest.TestCase):
    """Olvid, Encrypt-Decrypt, ThreadScoop (2026-10-24): builds that never started."""

    def test_a_subdir_task_is_named_from_the_gradle_root(self):
        from cognalys.builds.apk_build import task_relative_to_root

        project = Path("/w/projects/olvid")
        self.assertEqual(task_relative_to_root(":obv_messenger/app:assembleProdZfdroidDebug",
                                               project, project / "obv_messenger"),
                         ":app:assembleProdZfdroidDebug")
        self.assertEqual(task_relative_to_root(":app:assembleDebug", project, project),
                         ":app:assembleDebug")
        self.assertEqual(task_relative_to_root(":android/app:assembleDebug", project, project),
                         ":android:app:assembleDebug")

    def test_the_published_checksum_replaces_one_of_another_distribution(self):
        import tempfile
        from cognalys.builds.apk_build import official_wrapper_checksum

        published = "d725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "gradle/wrapper").mkdir(parents=True)
            properties = root / "gradle/wrapper/gradle-wrapper.properties"
            properties.write_text(
                "distributionSha256Sum=258e722ec21e955201e31447b0aed14201765a3bfbae296a46cf60b70e66db70\n"
                "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.9-bin.zip\n")
            urls = []
            fetch = lambda url: urls.append(url) or f"{published}\n"
            self.assertEqual(official_wrapper_checksum(root, fetch), published)
            self.assertEqual(urls, ["https://services.gradle.org/distributions/gradle-8.9-bin.zip.sha256"])
            # Same checksum, or a distribution served elsewhere: nothing to do.
            properties.write_text(f"distributionSha256Sum={published}\n"
                                  "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.9-bin.zip\n")
            self.assertEqual(official_wrapper_checksum(root, fetch), "")
            properties.write_text("distributionSha256Sum=00\n"
                                  "distributionUrl=https\\://example.com/gradle-8.9-bin.zip\n")
            self.assertEqual(official_wrapper_checksum(root, fetch), "")


class MoreBuildRecoveryTests(unittest.TestCase):
    """vayunmathur, Unstoppable Wallet (2026-10-24)."""

    def _result(self, directory, log):
        from types import SimpleNamespace
        path = Path(directory) / "build.log"
        path.write_text(log, encoding="utf-8")
        return SimpleNamespace(status="failed", log_file=str(path))

    def test_the_single_task_gradle_suggests_is_tried(self):
        import tempfile
        from cognalys.builds.apk_build import suggested_task

        with tempfile.TemporaryDirectory() as directory:
            result = self._result(directory, (
                "* What went wrong:\nNo matches\n  Cannot locate tasks that match ':office:assembleDebug' "
                "as task 'assembleDebug' not found in project ':office'. Some candidates are: 'assembleDev'.\n"))
            self.assertEqual(suggested_task(":office:assembleDebug", result), ":office:assembleDev")
            several = self._result(directory, "Cannot locate tasks that match ':a:x' as task 'x' not found "
                                              "in project ':a'. Some candidates are: 'assembleA', 'assembleB'.\n")
            self.assertEqual(suggested_task(":a:x", several), "")

    def test_empty_cache_locks_are_removed_after_a_crash(self):
        import tempfile
        from cognalys.builds.apk_build import remove_corrupt_gradle_locks

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "gradle"
            (home / "caches/transforms-4").mkdir(parents=True)
            empty = home / "caches/transforms-4/a.lock"
            empty.write_bytes(b"")
            healthy = home / "caches/transforms-4/b.lock"
            healthy.write_bytes(b"\x03lock")
            zeroed = home / "caches/transforms-4/c.lock"
            zeroed.write_bytes(b"\x00\x00\x00")
            project = Path(directory) / "project"
            (project / ".gradle/8.9").mkdir(parents=True)
            own = project / ".gradle/8.9/fileHashes.lock"
            own.write_bytes(b"\x00")
            result = self._result(directory, "Unexpected lock protocol found in lock file. Expected 3, found 0.")
            self.assertEqual(remove_corrupt_gradle_locks(result, home, project), 3)
            self.assertFalse(empty.exists() or zeroed.exists() or own.exists())
            self.assertTrue(healthy.exists())

    def test_rustup_bin_goes_on_path_when_rust_is_installed(self):
        import os
        import tempfile
        from cognalys.builds.apk_build import with_cargo_on_path

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / ".cargo"
            self.assertEqual(with_cargo_on_path("/usr/bin", home), "/usr/bin")
            (home / "bin").mkdir(parents=True)
            (home / "bin/cargo").write_text("")
            self.assertEqual(with_cargo_on_path("/usr/bin", home),
                             str(home / "bin") + os.pathsep + "/usr/bin")
            already = str(home / "bin") + os.pathsep + "/usr/bin"
            self.assertEqual(with_cargo_on_path(already, home), already)

    def test_convention_plugins_get_minification_turned_off_too(self):
        import io
        import tempfile
        from cognalys.builds.apk_build import disabled_minification_in_build_files

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugin = root / "build-logic/src/main/kotlin/common-conventions-app.gradle.kts"
            plugin.parent.mkdir(parents=True)
            plugin.write_text("isMinifyEnabled = true\nisShrinkResources = true\n")
            with disabled_minification_in_build_files(root, True, io.StringIO()):
                self.assertNotIn("true", plugin.read_text())
            self.assertEqual(plugin.read_text().count("true"), 2)


class SourceSetTests(unittest.TestCase):
    """Amethyst#4642 (2026-10-25): the patch changed the desktop actual."""

    def test_source_sets_are_ranked_by_whether_an_apk_runs_them(self):
        from cognalys.extraction.extract_methods_single_csv import android_source_rank
        rank = lambda path: android_source_rank(Path(path))
        self.assertEqual(rank("commons/src/androidMain/kotlin/A.kt"), 0)
        self.assertEqual(rank("app/src/main/java/A.java"), 0)
        self.assertEqual(rank("app/src/fdroid/java/A.java"), 0)
        self.assertEqual(rank("commons/src/commonMain/kotlin/A.kt"), 1)
        self.assertEqual(rank("cert4android/src/jvmCommonMain/kotlin/A.kt"), 1)
        self.assertEqual(rank("commons/src/jvmMain/kotlin/A.kt"), 2)
        self.assertEqual(rank("commons/src/iosArm64Main/kotlin/A.kt"), 2)
        self.assertEqual(rank("app/src/androidTest/java/A.java"), 2)

    def test_the_index_resolves_a_multiplatform_class_to_its_android_actual(self):
        import logging
        import tempfile
        from cognalys.extraction.extract_methods_single_csv import RepositoryIndexer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for source_set in ("jvmMain", "androidMain", "iosMain"):
                path = root / f"commons/src/{source_set}/kotlin/a/SecretEncryption.kt"
                path.parent.mkdir(parents=True)
                path.write_text("package a\nactual class SecretEncryption {}\n")
            indexer = object.__new__(RepositoryIndexer)
            indexer.repo_root, indexer.class_index, indexer.file_contents = root, {}, {}
            indexer.unreadable_files, indexer.logger = [], logging.getLogger("test")
            indexer._index_fingerprint = lambda: ""
            indexer.build_index()
        self.assertIn("androidMain", str(indexer.class_index["a.SecretEncryption"]))

    def test_a_patch_outside_the_compiled_source_sets_is_reported(self):
        from cognalys.prs.pr_generator import files_the_build_does_not_compile
        self.assertEqual(files_the_build_does_not_compile([
            "commons/src/jvmMain/kotlin/SecretEncryption.jvm.kt",
            "commons/src/androidMain/kotlin/SecretEncryption.android.kt",
            "commons/src/jvmTest/kotlin/SecretEncryptionTest.kt",
        ]), ["commons/src/jvmMain/kotlin/SecretEncryption.jvm.kt"])


class KotlinBytecodeNameTests(unittest.TestCase):
    """Password Store (2026-10-25): seven findings lost to compiled names."""

    def _extractor(self):
        from cognalys.extraction.extract_methods_single_csv import MethodExtractor
        extractor = object.__new__(MethodExtractor)
        extractor.logger = __import__("logging").getLogger("test")
        return extractor

    def test_value_class_mangling_and_d8_lambdas_are_undone(self):
        from cognalys.extraction.extract_methods_single_csv import SingleCsvMethodExtractor
        normalize = SingleCsvMethodExtractor._normalize_bytecode_target
        self.assertEqual(normalize("a.PasswordEntry", "calculateTotp-Zyo9ksc")[1], "calculateTotp")
        self.assertEqual(normalize("a.SettingsActivity$$ExternalSyntheticLambda1", "apply")[0],
                         "a.SettingsActivity")

    def test_a_lambda_is_found_through_the_api_it_uses(self):
        from cognalys.extraction.extract_methods_single_csv import locate_unnamed_method
        content = ("class SettingsActivity {\n"
                   "    fun onCreate() {\n        setup()\n    }\n\n"
                   "    private fun fingerprint(bytes: ByteArray): String {\n"
                   "        val md = MessageDigest.getInstance(\"SHA-1\")\n"
                   "        return md.digest(bytes).toString()\n    }\n}\n")
        found = locate_unnamed_method(self._extractor(), Path("SettingsActivity.kt"), content,
                                      "apply", "apply", "MessageDigestSpec")
        self.assertIsNotNone(found)
        self.assertEqual(found[1], "fingerprint")

    def test_a_method_in_another_file_of_the_package_is_found(self):
        import tempfile
        from cognalys.extraction.extract_methods_single_csv import locate_unnamed_method

        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "SshjSessionFactory.kt").write_text("class SshjSessionFactory {}\n")
            (folder / "SshKey.kt").write_text(
                "object SshKey {\n    fun generateKeystoreNativeKey(alias: String) {\n"
                "        println(alias)\n    }\n}\n")
            found = locate_unnamed_method(
                self._extractor(), folder / "SshjSessionFactory.kt",
                (folder / "SshjSessionFactory.kt").read_text(), "generateKeystoreNativeKey",
                "generateKeystoreNativeKey", "KeyPairGeneratorSpec")
        self.assertIsNotNone(found)
        self.assertEqual(found[2].name, "SshKey.kt")
        self.assertEqual(found[4], "same_package_file")

    def test_a_lambda_whose_class_calls_the_api_elsewhere_is_found_in_the_callee(self):
        """KeyGenType$1.invokeSuspend calls SshKey.generateKeystoreNativeKey, in another package."""
        import tempfile
        from cognalys.extraction.extract_methods_single_csv import locate_unnamed_method

        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / "app"
            (module / "src/main/java/ui").mkdir(parents=True)
            (module / "src/main/java/util").mkdir(parents=True)
            (module / "src/test/java").mkdir(parents=True)
            (module / "build.gradle.kts").write_text("plugins { id(\"com.android.application\") }\n")
            activity = module / "src/main/java/ui/SshKeyGenActivity.kt"
            activity.write_text(
                "sealed class KeyGenType {\n    suspend fun generateKey(alias: String) {\n"
                "        withContext(Dispatchers.IO) { SshKey.generateKeystoreNativeKey(alias) }\n"
                "    }\n    fun remove(alias: String) = SshKey.delete(alias)\n}\n")
            (module / "src/main/java/util/SshKey.kt").write_text(
                "object SshKey {\n    fun generateKeystoreNativeKey(alias: String) {\n"
                "        KeyPairGenerator.getInstance(\"EdDSA\").generateKeyPair()\n    }\n"
                "    fun delete(alias: String) {\n        println(alias)\n    }\n}\n")
            (module / "src/test/java/SshKeyTest.kt").write_text(
                "class SshKeyTest {\n    fun generateKeystoreNativeKey() {\n"
                "        KeyPairGenerator.getInstance(\"RSA\")\n    }\n}\n")
            found = locate_unnamed_method(self._extractor(), activity, activity.read_text(),
                                          "invokeSuspend", "invokeSuspend", "KeyPairGeneratorSpec")
            self.assertIsNotNone(found)
            self.assertEqual((found[1], found[2].name, found[4]),
                             ("generateKeystoreNativeKey", "SshKey.kt", "governed_api_in_callee"))
            # Two callees using the API: ambiguous, so nothing is taken.
            (module / "src/main/java/util/WebKey.kt").write_text(
                "object WebKey {\n    fun delete(alias: String) {\n"
                "        KeyPairGenerator.getInstance(\"EC\")\n    }\n}\n")
            self.assertIsNone(locate_unnamed_method(
                self._extractor(), activity, activity.read_text(),
                "invokeSuspend", "invokeSuspend", "KeyPairGeneratorSpec"))

    def _password_store_module(self, directory: str) -> Path:
        """The real KeyGenType shape: enum-constructor lambdas whose calls sit
        alone on their lines, next to an activity in the same file."""
        module = Path(directory) / "app"
        (module / "src/main/java/ui").mkdir(parents=True)
        (module / "src/main/java/util").mkdir(parents=True)
        (module / "build.gradle.kts").write_text("plugins { id(\"com.android.application\") }\n")
        activity = module / "src/main/java/ui/SshKeyGenActivity.kt"
        activity.write_text(
            "private enum class KeyGenType(val generateKey: suspend (auth: Boolean) -> Unit) {\n"
            "  Rsa({ auth ->\n"
            "    SshKey.generateKeystoreNativeKey(SshKey.Algorithm.Rsa, auth)\n  }),\n"
            "  Ed25519({ auth ->\n"
            "    SshKey.generateKeystoreWrappedEd25519Key(auth)\n  }),\n}\n\n"
            "class SshKeyGenActivity : AppCompatActivity() {\n"
            "  override fun onCreate(state: Bundle?) {\n"
            "    super.onCreate(state)\n"
            "    Backup.exportKeys(this)\n  }\n}\n")
        (module / "src/main/java/util/SshKey.kt").write_text(
            "object SshKey {\n"
            "  fun generateKeystoreNativeKey(algorithm: Algorithm, auth: Boolean) {\n"
            "    KeyPairGenerator.getInstance(algorithm.algorithm, PROVIDER).generateKeyPair()\n"
            "  }\n"
            "  fun generateKeystoreWrappedEd25519Key(auth: Boolean) {\n"
            "    val generator = KeyPairGenerator.getInstance(\"EdDSA\", BouncyCastleProvider())\n"
            "    generator.initialize(ECGenParameterSpec(\"ed25519\"), SecureRandom())\n"
            "  }\n}\n")
        # Another class of the same file calls a function using the API too.
        (module / "src/main/java/util/Backup.kt").write_text(
            "object Backup {\n  fun exportKeys(context: Context) {\n"
            "    ECGenParameterSpec(\"secp256r1\")\n  }\n}\n")
        return activity

    def test_a_callee_call_alone_on_its_line_is_found_in_the_outer_class(self):
        """Every call alone on its line used to read as a declaration and was
        dropped, so KeyGenType$1.invokeSuspend (Password Store) stayed not found."""
        import tempfile
        from cognalys.extraction.extract_methods_single_csv import locate_unnamed_method

        with tempfile.TemporaryDirectory() as directory:
            activity = self._password_store_module(directory)
            found = locate_unnamed_method(
                self._extractor(), activity, activity.read_text(),
                "invokeSuspend", "invokeSuspend", "ECGenParameterSpecSpec",
                outer_class="KeyGenType")
            self.assertIsNotNone(found)
            self.assertEqual((found[1], found[2].name, found[4]),
                             ("generateKeystoreWrappedEd25519Key", "SshKey.kt",
                              "governed_api_in_callee"))
            # The whole file also reaches Backup.exportKeys: ambiguous.
            self.assertIsNone(locate_unnamed_method(
                self._extractor(), activity, activity.read_text(),
                "invokeSuspend", "invokeSuspend", "ECGenParameterSpecSpec"))

    def test_two_callees_using_the_api_stay_ambiguous_unless_the_value_picks_one(self):
        import tempfile
        from cognalys.extraction.extract_methods_single_csv import locate_unnamed_method

        with tempfile.TemporaryDirectory() as directory:
            activity = self._password_store_module(directory)
            arguments = (self._extractor(), activity, activity.read_text(),
                         "invokeSuspend", "invokeSuspend", "KeyPairGeneratorSpec")
            self.assertIsNone(locate_unnamed_method(*arguments, outer_class="KeyGenType"))
            self.assertIsNone(locate_unnamed_method(
                *arguments, outer_class="KeyGenType", value="RSA"))
            # generateKeystoreNativeKey passes algorithm.algorithm, which may
            # be "EdDSA" at run time: the literal does not settle it.
            self.assertIsNone(locate_unnamed_method(
                *arguments, outer_class="KeyGenType", value="EdDSA"))
            ssh_key = activity.parents[1] / "util/SshKey.kt"
            ssh_key.write_text(ssh_key.read_text().replace(
                "algorithm.algorithm", "\"RSA\""))
            found = locate_unnamed_method(*arguments, outer_class="KeyGenType", value="EdDSA")
            self.assertIsNotNone(found)
            self.assertEqual((found[1], found[4]),
                             ("generateKeystoreWrappedEd25519Key", "governed_api_value_literal"))

    def test_a_candidate_calling_the_api_through_a_constant_keeps_it_ambiguous(self):
        import tempfile
        from cognalys.extraction.extract_methods_single_csv import locate_unnamed_method

        with tempfile.TemporaryDirectory() as directory:
            crypto = Path(directory) / "Crypto.kt"
            crypto.write_text(
                "class Crypto {\n"
                "    fun a() {\n"
                "        launch { Cipher.getInstance(TRANSFORMATION) }\n    }\n"
                "    fun b() {\n"
                "        Cipher.getInstance(\"AES/CBC/PKCS5Padding\")\n    }\n}\n")
            arguments = (self._extractor(), crypto, crypto.read_text(),
                         "invokeSuspend", "invokeSuspend", "CipherSpec")
            self.assertIsNone(locate_unnamed_method(
                *arguments, outer_class="Crypto", value="AES/CBC/PKCS5Padding"))
            crypto.write_text(crypto.read_text().replace(
                "TRANSFORMATION", "\"AES/GCM/NoPadding\""))
            found = locate_unnamed_method(
                self._extractor(), crypto, crypto.read_text(), "invokeSuspend",
                "invokeSuspend", "CipherSpec", outer_class="Crypto",
                value="AES/CBC/PKCS5Padding")
            self.assertIsNotNone(found)
            self.assertEqual((found[1], found[4]), ("b", "governed_api_value_literal"))


class NoEffectPatchTests(BehaviorReviewTests):
    def test_a_patch_the_checker_would_not_notice_becomes_no_impact(self):
        result, _ = self._generate(lambda call: {
            "regressions": [], "patch_has_no_effect": True,
            "no_effect_reason": "SSLSocketFactory.getDefault() calls SSLContext.getDefault()",
            "maintainer_decision_required": False, "maintainer_decision": "", "rationale": ""})
        self.assertEqual(result["stage"], "behavior_review")
        self.assertIn("PATCH_HAS_NO_EFFECT", result["issues"][0])
        self.assertIn("SSLContext.getDefault", result["correct_use"])

    def test_no_effect_is_judged_on_the_reported_rule(self):
        """Tokn (2026-10-28): a GCMParameterSpec finding in decrypt got a patch
        that only reordered key creation; the review counted the dropped
        KeyStore call as an effect."""
        self._generate(lambda call: {"regressions": [], "maintainer_decision_required": False,
                                     "maintainer_decision": "", "rationale": ""})
        self.assertIn("what finding.specification governs at the reported call",
                      self.review_system)
        self.assertIn("co_reported_findings, do not count", self.review_system)
        # Tokn's encrypt: "decrypt is still reported" was refused as a regression.
        self.assertIn("leaves doing what it did is never a regression", self.review_system)

    def test_a_patch_of_only_tests_is_not_a_fix(self):
        """FreeOTP#521: every production file came back unchanged; only a test was left."""
        result, calls = self._generate(lambda call: {}, path="src/test/java/MainTest.java")
        self.assertEqual(result["stage"], "no_production_change")
        self.assertIn("NO_PRODUCTION_CHANGE", result["issues"][0])
        self.assertNotIn("correct_use", result)
        self.assertNotIn("behavior_review", calls)



class StalledStepTests(unittest.TestCase):
    """Amethyst (2026-10-25): an analysis stuck in disk I/O for 47 minutes."""

    def test_a_step_that_writes_nothing_is_ended(self):
        import sys
        import tempfile
        import time
        from cognalys.utils.process_tree import run_with_deadline

        with tempfile.TemporaryDirectory() as directory:
            started = time.monotonic()
            outcome = run_with_deadline(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                idle_seconds=1, activity_paths=[directory], poll_seconds=0.2, grace=1)
            self.assertTrue(outcome.get("idle"))
            self.assertLess(time.monotonic() - started, 30)

    def test_a_step_that_keeps_writing_is_left_alone(self):
        import sys
        import tempfile
        from cognalys.utils.process_tree import run_with_deadline

        with tempfile.TemporaryDirectory() as directory:
            script = ("import time, pathlib\n"
                      f"for i in range(8):\n    pathlib.Path(r'{directory}', str(i)).write_text('x')\n"
                      "    time.sleep(0.3)\n")
            outcome = run_with_deadline([sys.executable, "-c", script],
                                        idle_seconds=1.5, activity_paths=[directory],
                                        poll_seconds=0.2, grace=1)
            self.assertEqual(outcome, {"returncode": 0, "timed_out": False})

    def test_only_the_llm_step_is_watched(self):
        import argparse
        import tempfile
        from cognalys.orchestration.run_pipeline import llm_step_watch

        with tempfile.TemporaryDirectory() as directory:
            from types import SimpleNamespace
            paths = SimpleNamespace(root=Path(directory), application_results_dir=Path(directory) / "r",
                                    error_solutions_dir=Path(directory) / "s")
            args = argparse.Namespace(llm_timeout=600, openai_prompt_log_dir="")
            self.assertEqual(llm_step_watch("validation", args, paths), {})
            watch = llm_step_watch("llm", args, paths)
            self.assertEqual(watch["idle_seconds"], 1800)
            self.assertIn(Path(directory) / "s", watch["activity_paths"])

    def test_a_stalled_step_is_reported_as_stalled_not_as_past_its_deadline(self):
        """Amethyst run_v2 (2026-10-29): the stall watch ended the llm step 80
        minutes in and the run said "ended after 720 minutes"."""
        import sys
        import tempfile
        from cognalys.orchestration.run_pipeline import step_ending_message
        from cognalys.utils.process_tree import run_with_deadline

        with tempfile.TemporaryDirectory() as directory:
            outcome = run_with_deadline(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                idle_seconds=1, activity_paths=[directory], poll_seconds=0.2, grace=1)
        message = step_ending_message("llm", outcome, 720, 81 * 60)
        self.assertIn("no progress for 1s", message)
        self.assertIn("81 minutes after it started", message)
        self.assertNotIn("720", message)
        self.assertIn("after 720 minutes", step_ending_message(
            "llm", {"returncode": 124, "timed_out": True}, 720, 720 * 60))


class UnrelatedTestEditsTests(BehaviorReviewTests):
    def test_a_test_edit_the_change_does_not_need_is_dropped(self):
        import json
        import tempfile
        from cognalys.llm.generate_error_fixes import FixGenerator

        class Provider:
            def generate(self, prompt, *args, **kwargs):
                if kwargs.get("schema_name") == "behavior_review":
                    return json.dumps({"regressions": [], "unrelated_test_edits": ["src/test/MainTest.java"],
                                       "maintainer_decision_required": False, "maintainer_decision": "",
                                       "current_code_is_correct_use": False, "correct_use_reason": "",
                                       "rationale": ""})
                import re
                path = re.search(r'"target_file":\s*"([^"]+)"', prompt).group(1)
                original = "int t = 1;" if "MainTest" in path else "int value = 1;"
                return json.dumps({
                    "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "source_file_path": path,
                    "explanation": "e", "edits": [{"source_file_path": path, "symbol": "v",
                                                   "edit_kind": "declaration", "original_code": original,
                                                   "corrected_code": original.replace("1", "2"),
                                                   "reason": "r"}],
                    "no_change_required": False, "provided_contracts": [], "required_contracts": [],
                    "required_tests": [], "manual_review_required": True, "review_assumptions": [],
                    "confidence": "high"})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "repo/src/test").mkdir(parents=True)
            (root / "repo/src/Main.java").write_text("class X { int value = 1; }", encoding="utf-8")
            (root / "repo/src/test/MainTest.java").write_text("class T { int t = 1; }", encoding="utf-8")
            generator = object.__new__(FixGenerator)
            generator.output_dir = root / "out"
            generator.provider = Provider()
            generator.web_search = False
            generator.logger = __import__("logging").getLogger("test")
            error = {"repository_path": str(root / "repo"), "error_index": 2,
                     "evidence_analysis": {"confirmed_cause": "cause", "coordinated_fix_plan": {
                         "required_edits": [{"source_file_path": "src/Main.java", "symbol": "value"},
                                            {"source_file_path": "src/test/MainTest.java", "symbol": "t"}]}}}
            result = generator.generate_coordinated_file_drafts(
                error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "method")
        self.assertEqual(result["status"], "complete")
        self.assertEqual([edit["source_file_path"] for edit in result["edits"]], ["src/Main.java"])


class RepairCommitTests(unittest.TestCase):
    def test_a_created_file_the_repair_deleted_does_not_stop_the_commit(self):
        import subprocess
        import tempfile
        from cognalys.validation.repair import commit_repair

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "Main.java").write_text("class A {}\n")
            subprocess.run([*git, "add", "."], check=True)
            subprocess.run([*git, "commit", "-qm", "base"], check=True)
            (repo / "Main.java").write_text("class A { int x; }\n")
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
            head = commit_repair(repo, ["Main.java", "src/test/GoneTest.kt"], "abc")
            log = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%s"],
                                 capture_output=True, text=True).stdout
        self.assertTrue(head)
        self.assertIn("Repair validation compilation for abc", log)


class PreviousRegressionsTests(unittest.TestCase):
    def test_the_review_sees_what_earlier_drafts_were_refused_for(self):
        import json
        from cognalys.llm.generate_error_fixes import FixGenerator

        prompts = []

        class Provider:
            def generate(self, prompt, *args, **kwargs):
                prompts.append(prompt)
                return json.dumps({"regressions": [], "maintainer_decision_required": False,
                                   "maintainer_decision": "", "rationale": ""})

        generator = object.__new__(FixGenerator)
        generator.provider = Provider()
        generator.review_patch_behavior({}, [], {}, previous_regressions=[
            "default trust: before, platform policy; after, user CAs trusted"])
        self.assertIn("user CAs trusted", prompts[0])


TWO_METHODS = ("class X {\n    void method() { int value = 1; }\n"
               "    void other() { int other = 1; }\n}\n")


def _coordinated_run(review, edits, decision="MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                     source=TWO_METHODS, error_extra=None, provider_attributes=None):
    """One coordinated generation of src/Main.java whose draft carries ``edits``.

    ``review(call)`` answers the behaviour review. Returns the result, the
    provider, the error and behavior_review.json as written.
    """
    import json
    import tempfile
    from cognalys.llm.generate_error_fixes import FixGenerator

    class Provider:
        def __init__(self):
            self.calls = []
            self.draft_prompts = []
            self.draft_schemas = []

        def generate(self, prompt, *args, **kwargs):
            self.calls.append(kwargs.get("schema_name"))
            if kwargs.get("schema_name") == "behavior_review":
                self.review_system = args[0] if args else kwargs.get("system", "")
                self.review_prompt = prompt
                return json.dumps(review(len(self.calls)))
            self.draft_system = args[0] if args else kwargs.get("system", "")
            self.draft_prompts.append(prompt)
            self.draft_schemas.append(kwargs.get("json_schema"))
            return json.dumps({
                "decision": decision, "source_file_path": "src/Main.java", "explanation": "e",
                "edits": [{"source_file_path": "src/Main.java", "edit_kind": "declaration",
                           "reason": "r", **edit} for edit in edits],
                "no_change_required": False, "provided_contracts": [],
                "required_contracts": [], "required_tests": [],
                "manual_review_required": True, "review_assumptions": [],
                "confidence": "high"})

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "repo/src").mkdir(parents=True)
        (root / "repo/src/Main.java").write_text(source, encoding="utf-8")
        generator = object.__new__(FixGenerator)
        generator.output_dir = root / "out"
        generator.provider = Provider()
        for name, value in (provider_attributes or {}).items():
            setattr(generator.provider, name, value)
        generator.web_search = False
        generator.logger = __import__("logging").getLogger("test")
        error = {"repository_path": str(root / "repo"), "error_index": 2,
                 "source_file_path": "src/Main.java", "method_name": "method",
                 "evidence_analysis": {"confirmed_cause": "cause", "coordinated_fix_plan": {
                     "required_edits": [{"source_file_path": "src/Main.java",
                                         "symbol": edit["symbol"]} for edit in edits]}},
                 **(error_extra or {})}
        result = generator.generate_coordinated_file_drafts(error, decision, "app.apk", "method")
        written = root / "out/coordinated_drafts/app.apk/2_method/behavior_review.json"
        review_file = json.loads(written.read_text(encoding="utf-8")) if written.is_file() else {}
    return result, generator.provider, error, review_file


METHOD_EDIT = {"symbol": "method", "original_code": "int value = 1;",
               "corrected_code": "int value = 2;"}
OTHER_EDIT = {"symbol": "other", "original_code": "int other = 1;",
              "corrected_code": "int other = 2;"}
CLEAN_REVIEW = {"regressions": [], "maintainer_decision_required": False,
                "maintainer_decision": "", "rationale": ""}


class OneGenerationPathTests(unittest.TestCase):
    """B3: a FIX_SUPPORTED change inside one method goes through the per-file path."""

    def test_its_draft_meets_the_semantic_gates_and_the_behaviour_review(self):
        from unittest.mock import patch
        from cognalys.llm import coordinated_generation

        with patch.object(coordinated_generation, "validate_coordinated_semantics",
                          wraps=coordinated_generation.validate_coordinated_semantics) as gates:
            result, provider, _error, review = _coordinated_run(
                lambda _call: CLEAN_REVIEW, [METHOD_EDIT], decision="FIX_SUPPORTED")
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["decision"], "FIX_SUPPORTED")
        self.assertFalse(result["manual_review_required"])
        self.assertTrue(gates.called)
        self.assertIn("behavior_review", provider.calls)
        self.assertEqual(review.get("status"), "reviewed")


class ReviewThatDoesNotRunTests(unittest.TestCase):
    """B4: a review that did not run is asked once more, and a draft still
    unreviewed is held from publication until the finding runs again."""

    def _review(self, answers):
        import json
        from cognalys.llm.generate_error_fixes import FixGenerator

        class Provider:
            def __init__(self):
                self.prompts = []

            def generate(self, prompt, *args, **kwargs):
                self.prompts.append(prompt)
                answer = answers.pop(0)
                if isinstance(answer, Exception):
                    raise answer
                return answer if isinstance(answer, str) else json.dumps(answer)

        generator = object.__new__(FixGenerator)
        generator.logger = __import__("logging").getLogger("b4-review")
        generator.provider = Provider()
        with self.assertLogs("b4-review", level="WARNING"):
            review = generator.review_patch_behavior({}, [], {})
        return review, generator.provider.prompts

    def test_an_empty_answer_twice_leaves_the_draft_unreviewed_and_held(self):
        from cognalys.llm.coordinated_generation import BEHAVIOR_REVIEW_RETRY_NOTE
        from cognalys.prs.publication_checks import REVIEW_NOT_RUN, stale_review
        from cognalys.reporting.finding_statistics import (
            NOT_RUN_REVIEW_DETAIL, ready_draft_detail)

        review, prompts = self._review(["", "{}"])
        self.assertEqual(review["status"], "not_run")
        self.assertEqual(review["attempts"], 2)
        self.assertEqual(len(prompts), 2)
        # The second request is a request of its own, so no cache answers it.
        self.assertFalse(prompts[0].endswith(BEHAVIOR_REVIEW_RETRY_NOTE))
        self.assertTrue(prompts[1].endswith(BEHAVIOR_REVIEW_RETRY_NOTE))
        # Such a draft records no contract: the publication gate holds it.
        self.assertEqual(stale_review(None, reviewed=False), REVIEW_NOT_RUN)
        self.assertEqual(ready_draft_detail(
            {"review_contract_version": None, "behavior_review_recorded": False,
             "behavior_review_not_run": True}), NOT_RUN_REVIEW_DETAIL)
        # A draft from before the review existed keeps its own detail.
        self.assertNotEqual(ready_draft_detail(
            {"review_contract_version": None, "behavior_review_recorded": False}),
            NOT_RUN_REVIEW_DETAIL)

    def test_a_failure_then_an_answer_is_a_review(self):
        review, prompts = self._review([RuntimeError("no answer"), CLEAN_REVIEW])
        self.assertEqual(review["status"], "reviewed")
        self.assertEqual(review["regressions"], [])
        self.assertEqual(len(prompts), 2)


class ReviewContractVersionTests(unittest.TestCase):
    """Drafts reviewed before patch_has_no_effect stayed "PR pronto" (2026-10-28)."""

    def test_a_reviewed_draft_records_the_current_contract(self):
        from cognalys.llm.coordinated_generation import REVIEW_CONTRACT_VERSION

        result, _, error, review_file = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(review_file["review_contract_version"], REVIEW_CONTRACT_VERSION)
        self.assertEqual(result["review_contract_version"], REVIEW_CONTRACT_VERSION)
        # Persisted with the solution's evidence_analysis.
        self.assertEqual(error["evidence_analysis"]["behavior_review"]["review_contract_version"],
                         REVIEW_CONTRACT_VERSION)

    def test_a_draft_the_review_never_judged_records_no_contract(self):
        from cognalys.llm.coordinated_generation import review_facts_for_text

        self.assertEqual(review_facts_for_text({"status": "not_run"}), {})
        self.assertIn("review_contract_version",
                      review_facts_for_text({"status": "all_edits_on_base"}))


class CorrectlyNamedDeclarationPromptTests(unittest.TestCase):
    """NotallyX's md5Hash had no correctly named sibling: a draft may add one."""

    def test_a_caller_draft_may_call_a_declaration_another_file_adds(self):
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        system = provider.draft_system
        # The order: an existing sibling, a rename with every reference when
        # rename_safety has no hard blocker, a new correctly named function.
        self.assertIn("(1) switch every caller of the reported method to an "
                      "existing correctly named declaration", system)
        self.assertIn("(2) otherwise rename the declaration, or its whole overload "
                      "family, when rename_safety.hard_blockers is empty", system)
        self.assertIn("(3) otherwise switch every caller of the reported method to a "
                      "correctly named declaration this batch adds beside it", system)
        self.assertIn("Never add a helper no production caller uses", system)
        self.assertIn("not a maintainer approval", system)
        # A sibling of an internal route stays internal (NotallyX draft 1).
        self.assertIn("keeps that function's visibility (internal, private)", system)
        self.assertIn("unless the name states the behaviour the patch removes", system)
        self.assertIn("one recomputed in-process on both sides may change", system)
        # The sibling outline is built from the original sources, so it cannot
        # show that declaration; the plan and earlier drafts can.
        self.assertIn("Call only what it shows, or what shared_plan or "
                      "previous_file_contracts declare as added by another file in "
                      "this batch", system)


class RenameReviewTests(unittest.TestCase):
    """Orgzly's review (2026-10-25) echoed a rename "authorization" as a
    maintainer choice over a rename the repository check allowed."""

    def test_the_review_reads_rename_safety_and_the_rule(self):
        safety = {"symbol": "method", "allowed": True, "hard_blockers": [], "resolvable": [],
                  "references": [{"path": "src/Main.java", "line": 2, "kind": "call"}],
                  "declaration": {"path": "src/Main.java", "line": 2}}
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT],
                                             error_extra={"rename_safety": safety})
        self.assertIn("A rename that rename_safety allows (no hard_blockers) is never a "
                      "regression and never a maintainer decision", provider.review_system)
        self.assertIn('"rename_safety":{"symbol":"method","allowed":true',
                      provider.review_prompt.replace(" ", ""))
        self.assertIn("not a maintainer approval", provider.review_prompt)


class CallSiteSourceGapTests(unittest.TestCase):
    """NotallyX (2026-10-28): the plan never saw the call-site file, the draft
    only added an unused helper, and the no-effect verdict was recorded as a
    violation without security impact."""

    NO_EFFECT = {**CLEAN_REVIEW, "patch_has_no_effect": True,
                 "no_effect_reason": "the helper is never called"}

    def test_a_no_effect_verdict_after_an_unresolved_missing_caller_is_a_pipeline_failure(self):
        gap = {"paths": ["app/src/ExportExtensions.kt"], "rebuilt": True, "supplied": [],
               "unsupplied": ["app/src/ExportExtensions.kt"], "resolved": False}
        result, _, _, _ = _coordinated_run(lambda call: self.NO_EFFECT, [METHOD_EDIT],
                                           error_extra={"caller_source_gap": gap})
        self.assertTrue(result["pipeline_failure"])
        self.assertEqual(result["correct_use"], "")
        self.assertEqual(result["missing_scope_paths"], ["app/src/ExportExtensions.kt"])

    def test_a_plain_no_effect_verdict_is_still_no_security_impact(self):
        # Orgzly's generateKeystoreNativeKey shape: nothing was missing.
        for extra in ({}, {"caller_source_gap": {"paths": ["x/Caller.kt"], "rebuilt": True,
                                                 "supplied": ["x/Caller.kt"],
                                                 "unsupplied": [], "resolved": True}}):
            with self.subTest(extra=bool(extra)):
                result, _, _, _ = _coordinated_run(lambda call: self.NO_EFFECT, [METHOD_EDIT],
                                                   error_extra=extra)
                self.assertFalse(result.get("pipeline_failure"))
                self.assertIn("leaves the calls the checker observes", result["correct_use"])


class DiscardedConstructionRetryTests(unittest.TestCase):
    """BlueGate (2026-10-29): `KeyPair(pair.public, pair.private)` built and
    discarded, `keyPair.getPublic()` for `keyPair.public`; the review saw both
    and still counted the added constructor as an effect."""

    DISCARDED = {"symbol": "method", "original_code": "int value = 1;",
                 "corrected_code": "int value = 1;\n        new KeyPair(pub, priv);"}
    KEY_PAIR = {"specification_context": {"applies_to_types": ["java.security.KeyPair"]}}

    def test_a_discarded_construction_is_regenerated_with_the_reason_and_never_ships(self):
        result, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [self.DISCARDED],
                                                  error_extra=self.KEY_PAIR)
        self.assertNotEqual(result["status"], "complete")
        self.assertEqual(result["stage"], "semantic_validation")
        self.assertIn("DISCARDED_CONSTRUCTION", result["issues"])
        # Every attempt is judged before the behaviour review is asked.
        self.assertNotIn("behavior_review", provider.calls)
        self.assertGreater(len(provider.draft_prompts), 1)
        self.assertNotIn("semantic_validation_retry", provider.draft_prompts[0])
        retry = provider.draft_prompts[1]
        self.assertIn("semantic_validation_retry", retry)
        self.assertIn("DISCARDED_CONSTRUCTION", retry)
        self.assertIn("concerns the object that reaches the reported call", retry)

    def test_retries_that_only_discard_a_construction_end_without_security_impact(self):
        """Review (2026-10-29): like the review's patch_has_no_effect, the
        finding ends as a violation without security impact, not an issue."""
        result, _, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [self.DISCARDED],
                                           error_extra=self.KEY_PAIR)
        self.assertFalse(result.get("pipeline_failure"))
        self.assertTrue(result["correct_use"].startswith(
            "Every proposed change leaves the calls the checker observes as they were: "
            "added statement(s) construct an object and discard it: new KeyPair(pub, priv)"))

    def test_a_missing_call_site_file_or_another_failure_keeps_its_own_ending(self):
        from cognalys.llm.coordinated_generation import CoordinatedGeneration

        failure = {"code": "DISCARDED_CONSTRUCTION", "details": ["added ...: new KeyPair(a, b)"]}
        gap = {"paths": ["app/src/Caller.kt"], "unsupplied": ["app/src/Caller.kt"],
               "resolved": False}
        failed = {}
        CoordinatedGeneration._close_discarded_construction(
            {"caller_source_gap": gap}, failed, [failure])
        self.assertEqual(failed, {"pipeline_failure": True,
                                  "missing_scope_paths": ["app/src/Caller.kt"]})
        for others in ([failure, {"code": "STATEMENT_WITHOUT_EFFECT", "details": ["x"]}],
                       [{"code": "GOVERNED_CALL_RESULT_DISCARDED", "details": ["x"]}], []):
            with self.subTest(codes=[item["code"] for item in others]):
                failed = {}
                CoordinatedGeneration._close_discarded_construction({}, failed, others)
                self.assertEqual(failed, {})

    def test_the_review_counts_a_discarded_object_and_a_getter_spelling_as_no_effect(self):
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        system = provider.review_system
        self.assertIn("an object the patch constructs or obtains and then discards (no "
                      "receiver, argument or return value carries it on", system)
        self.assertIn("the reported call still receives the same object in the same state",
                      system)
        self.assertIn("a Kotlin property read and its getter are one call", system)
        # The value-change and explicit-default carve-outs stay as they were.
        self.assertIn("A change of the value passed (\"SSL\" to \"TLS\") is not this, and "
                      "neither is a change for which explicit_default_only holds", system)
        self.assertIn("so set explicit_default_only, not patch_has_no_effect", system)
        from cognalys.llm.llm_schemas import behavior_review_schema
        description = behavior_review_schema()["properties"]["patch_has_no_effect"]["description"]
        self.assertIn("an object the patch constructs and discards, never a receiver, "
                      "argument or return value, does not count", description)

    def test_an_added_call_on_the_object_the_reported_call_uses_is_a_change(self):
        """Review (2026-10-29): `keyStore.load(null)` before `getEntry`,
        `kpg.initialize(spec)` before `generateKeyPair()` return nothing but
        are the fix; they never read as no effect."""
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        self.assertIn("A call the patch adds on the object or value the reported call then "
                      "uses (init, load, initialize, a setter, nextBytes on the array that is "
                      "passed) changes that object's state and is a change, even when it "
                      "returns nothing", provider.review_system)
        self.assertNotIn("whose result never reaches the reported call", provider.review_system)
        from cognalys.llm.llm_schemas import behavior_review_schema
        description = behavior_review_schema()["properties"]["patch_has_no_effect"]["description"]
        self.assertIn("a call added on the object or value the reported call uses, such as "
                      "init, load or a setter, does", description)
        self.assertNotIn("whose result never reaches the reported call", description)


class WrappedSameObjectReviewTests(unittest.TestCase):
    def test_the_review_counts_an_app_written_factory_around_the_same_object_as_no_effect(self):
        """ICSdroid (run_v2, 2026-10-29): the contract-4 review approved a
        TrustManagerFactorySpi/Provider/TrustManagerFactory around the same
        CustomCertManager as "a substantive provenance repair"."""
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        self.assertIn("the same object wrapped in a factory or provider only so the rule "
                      "stops matching (an app-written *Spi, Provider or factory subclass whose "
                      "product is the object the code already passed: what reaches the call, "
                      "and what it trusts or does, is unchanged)", provider.review_system)


class ReplacementValuePropertyTests(unittest.TestCase):
    """NotallyX's md5Hash (run_v6, 2026-10-29): six reviews called the SHA-256
    patch correct and each reported "16-byte MD5 -> 32-byte SHA-256 digests",
    the last three because previous_regressions said to report it again."""

    CONSUMERS = {"status": "classified", "method": "md5Hash", "persisted": False,
                 "transmitted": False, "fixed": False, "bound": "Lexical",
                 "consumers": [{"path": "app/Cache.kt", "line": 9, "kind": "cache",
                                "statement": "File(context.cacheDir, key.md5Hash())",
                                "basis": "b", "reached_through": "r"}]}

    def test_a_property_of_the_replacement_value_is_no_regression_in_process_only(self):
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        system = provider.review_system
        self.assertIn("other than a property that follows necessarily from the replacement "
                      "value the fix requires: the new algorithm's output length or encoding "
                      "width when that value is recomputed and compared within the process, "
                      "or a file in the app's cache directory, which the platform may delete "
                      "at any time, named by the old value and no longer found.", system)
        # Review (2026-10-29): a cache file lives on disk, so the cache entry
        # does not sit under the "within the process" condition, which no
        # cache file meets (AmaRadio's md5-named feed cache, 2026-10-16).
        self.assertNotIn("no longer found) when that value is recomputed", system)
        # Stored, sent and constant-compared values stay protected.
        self.assertIn("a value it marks persisted, transmitted or fixed (compared with a "
                      "constant), or one that names or keys stored data other than a consumer "
                      "of kind cache, stays protected, and a changed length, width or key "
                      "there is a regression", system)
        self.assertIn("unless what it forbids is only such a necessary property of the "
                      "replacement value, which you name in rationale", system)

    def test_a_previous_regression_is_reported_again_only_while_it_is_one(self):
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        system = provider.review_system
        self.assertIn("report it again only when this draft still causes it and it is a "
                      "regression under the rules above", system)
        self.assertNotIn("report it again whenever this draft still changes behaviour", system)

    def test_the_review_reads_where_the_value_goes(self):
        import json

        _, provider, _, _ = _coordinated_run(
            lambda call: CLEAN_REVIEW, [METHOD_EDIT],
            error_extra={"derived_value_consumers": self.CONSUMERS})
        payload = json.loads(provider.review_prompt.split(
            '<patch_and_source untrusted_data="true">\n', 1)[1].rsplit(
                "\n</patch_and_source>", 1)[0])
        self.assertEqual(payload["derived_value_consumers"]["consumers"], [
            {"path": "app/Cache.kt", "line": 9, "kind": "cache",
             "statement": "File(context.cacheDir, key.md5Hash())"}])
        self.assertFalse(payload["derived_value_consumers"]["persisted"])
        # Nothing recorded, nothing passed.
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        self.assertNotIn('"derived_value_consumers"', provider.review_prompt)

    def test_the_digest_policy_keeps_the_width_only_of_a_fixed_width_fold(self):
        from cognalys.utils.specification_data import specification

        forbidden = specification("MessageDigestSpec")["remediation_policies"][0][
            "policy"]["forbidden_changes"]
        self.assertNotIn("the number of digest bytes folded into the returned value",
                         forbidden[0])
        self.assertIn("when the method folds digest bytes into a fixed-width value (an int, "
                      "a long, a hashCode), keep the number of bytes folded, while a helper "
                      "that returns the whole digest returns the new algorithm's full output",
                      forbidden[0])
        # Stored data stays protected; a cache-directory file is not stored data.
        self.assertTrue(forbidden[2].startswith(
            "Do not change a digest whose value names or keys stored data"))
        self.assertIn("A file in the app's cache directory (a consumer of kind cache), which "
                      "the platform may delete at any time, is not stored data.", forbidden[2])


class UserChoiceRegressionTests(unittest.TestCase):
    def test_a_users_choice_that_now_yields_something_else_is_a_regression(self):
        """Trigger (2026-10-28): the ED25519 option silently generated an EC key,
        and the review filed it as a maintainer decision."""
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        system = provider.review_system
        self.assertIn("A choice the user makes (a selected option, a setting, an entered "
                      "value) that now produces something other than what it names", system)
        self.assertIn("an option the user could choose that the patch removes", system)
        self.assertIn("A value missing from the rule's accepted list is not, by that alone, "
                      "deprecated or insecure", system)
        self.assertNotIn("a user-visible behaviour", system)

    def test_the_insecure_value_carve_out_never_covers_an_option_the_user_turns_on(self):
        """Feeder's trustAllCerts: dropping old protocols there is a regression,
        even though the protocols themselves are deprecated."""
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        system = provider.review_system
        self.assertIn("what that choice gave; after: what it gives now), unless the replaced "
                      "value is itself deprecated or insecure -- never in a compatibility "
                      "path the user turns on deliberately, where 'What the fix removes', "
                      "above, decides.", system)
        self.assertNotIn("beyond the reported violation itself", system)
        self.assertEqual(system.count("unless the replaced value is itself deprecated"), 1)
        # The prompt opens by excluding the reported violation itself from
        # regressions; the carve-out must not contradict it.
        self.assertIn("other than no longer committing the reported violation itself", system)
        self.assertNotIn("is always a regression", system)


def _concluded(method, outcome="no security impact"):
    """A co_reported_findings entry for ``method``, already concluded."""
    from cognalys.llm.coordinated_generation import CONCLUDED_CO_REPORTED_STATUS

    return {"specification": "KeyPairGeneratorSpec", "class": "X", "method": method,
            "error_message": "m", "status": CONCLUDED_CO_REPORTED_STATUS,
            "concluded_outcome": outcome, "concluded_reason": "same object"}


class EditsForOtherFindingsTests(unittest.TestCase):
    """Clash Fest (2026-10-28): the serverSocketFactory draft also rewrote the
    method of a co-reported finding that had already ended with no effect."""

    @staticmethod
    def _review(*named):
        return lambda call: {**CLEAN_REVIEW, "edits_for_other_findings": [
            {"source_file_path": "src/Main.java", "symbol": symbol} for symbol in named]}

    def test_an_edit_for_a_concluded_finding_is_dropped(self):
        result, _, _, _ = _coordinated_run(
            self._review("other"), [METHOD_EDIT, OTHER_EDIT],
            error_extra={"co_reported_findings": [_concluded("other")]})
        self.assertEqual(result["status"], "complete")
        self.assertEqual([edit["symbol"] for edit in result["edits"]], ["method"])
        self.assertEqual(result["dropped_edits_for_other_findings"],
                         [{"source_file_path": "src/Main.java", "symbol": "other"}])

    def test_an_edit_for_a_finding_that_did_not_conclude_stays(self):
        """Amethyst's encrypt ended without a safe fix, and its edit is the other
        half of the format decrypt reads; Tokn's and KeyPass's co-reported
        methods had not concluded at all."""
        for extra in ({}, {"co_reported_findings": [{**_concluded("other"), "status": ""}]},
                      {"co_reported_findings": [_concluded("other", "no safe fix")]}):
            result, _, _, _ = _coordinated_run(self._review("other"), [METHOD_EDIT, OTHER_EDIT],
                                               error_extra=extra)
            self.assertEqual([edit["symbol"] for edit in result["edits"]], ["method", "other"])
            self.assertEqual(result["dropped_edits_for_other_findings"], [])

    def test_the_reported_method_and_joint_findings_are_never_dropped(self):
        result, _, _, _ = _coordinated_run(
            self._review("method", "other"), [METHOD_EDIT, OTHER_EDIT],
            error_extra={"joint_findings": [{"method": "other"}],
                         "co_reported_findings": [_concluded("other"), _concluded("method")]})
        self.assertEqual([edit["symbol"] for edit in result["edits"]], ["method", "other"])

    def test_nothing_is_dropped_unless_an_edit_of_the_reported_method_remains(self):
        from cognalys.llm.coordinated_generation import edits_for_other_findings

        error = {"source_file_path": "src/Main.java", "method_name": "method",
                 "co_reported_findings": [_concluded("other")]}
        other = {"source_file_path": "src/Main.java", "symbol": "other"}
        named = [{"source_file_path": "src/Main.java", "symbol": "other"}]
        self.assertEqual(edits_for_other_findings(
            error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", [other], named, 1), [])
        # A signature-style symbol still names the reported method.
        method = {"source_file_path": "src/Main.java", "symbol": "private fun method"}
        self.assertEqual(edits_for_other_findings(
            error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", [method, other], named, 2), [other])
        named_method = [{"source_file_path": "src/Main.java", "symbol": "void method()"}]
        self.assertEqual(edits_for_other_findings(
            {**error, "co_reported_findings": [_concluded("other"), _concluded("method")]},
            "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            [{"source_file_path": "src/Main.java", "symbol": "void method()"}, other],
            named_method, 2), [])
        # An unattended multi-file decision keeps its edit floor.
        self.assertEqual(edits_for_other_findings(
            error, "MULTI_FILE_FIX_SUPPORTED", [method, other], named, 2), [])
        # Only the reported file: a co-reported finding is in the same class.
        elsewhere = {"source_file_path": "src/Other.java", "symbol": "other"}
        self.assertEqual(edits_for_other_findings(
            error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", [method, elsewhere],
            [{"source_file_path": "src/Other.java", "symbol": "other"}], 2), [])

    def test_a_drop_that_breaks_the_cross_file_contract_is_not_complete(self):
        from unittest import mock
        from cognalys.llm import coordinated_generation

        real = coordinated_generation.validate_coordinated_semantics

        def validate(error, edits):
            # The edit to "other" turns out to be one the rest depends on.
            if any(edit.get("symbol") == "other" for edit in edits):
                return real(error, edits)
            return {"status": "invalid", "errors": [
                {"code": "MISSING_REQUIRED_EDIT", "message": "m", "affected_paths": []}]}

        with mock.patch.object(coordinated_generation, "validate_coordinated_semantics",
                               side_effect=validate):
            result, _, _, _ = _coordinated_run(
                self._review("other"), [METHOD_EDIT, OTHER_EDIT],
                error_extra={"co_reported_findings": [_concluded("other")]})
        self.assertNotEqual(result["status"], "complete")
        self.assertIn("MISSING_REQUIRED_EDIT", result["issues"])

    def _rename_failure_run(self, failure):
        from unittest import mock
        from cognalys.llm import coordinated_generation

        real = coordinated_generation.validate_coordinated_semantics

        def validate(error, edits):
            # Every draft keeps a name the check refuses.
            result = real(error, edits)
            return {**result, "status": "invalid", "errors": [*result["errors"], failure]}

        with mock.patch.object(coordinated_generation, "validate_coordinated_semantics",
                               side_effect=validate):
            return _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT],
                                    decision="MULTI_FILE_FIX_SUPPORTED",
                                    error_extra={"rename_safety": {"symbol": "method"}})

    def test_a_name_still_stating_the_removed_behaviour_goes_on_to_review(self):
        """BWT's decryptDES (2026-10-24): NAME_CONTRADICTS_BEHAVIOR on every
        attempt, the last included, dropped a draft no review had judged."""
        named = {"code": "NAME_CONTRADICTS_BEHAVIOR", "path": "src/Main.java",
                 "name": "decryptDES", "removed_behavior": "des",
                 "details": ["decryptDES still states 'des' but the patch removes it"]}
        result, provider, error, review = self._rename_failure_run(named)
        self.assertEqual(result["status"], "complete")
        self.assertIn("behavior_review", provider.calls)
        self.assertEqual(provider.calls.count("behavior_review"), 1)
        left = [item for item in result["semantic_validation"]["warnings"]
                if item.get("rename_check_left_to_review")]
        self.assertEqual([item["details"] for item in left], [named["details"]])
        # Review only: applied and built, published only once a person reads it.
        self.assertEqual(error["evidence_analysis"]["publication_status"], "blocked")
        self.assertTrue(result["manual_review_required"])
        self.assertNotIn("_rename_checks_left_to_review", error)

    def test_an_unauthorized_rename_is_never_left_to_review(self):
        unauthorized = {"code": "UNAUTHORIZED_RENAME", "path": "src/Main.java",
                        "details": ["method -> other"], "blocked_by": ["platform_or_convention_name"]}
        result, provider, error, _ = self._rename_failure_run(unauthorized)
        self.assertNotEqual(result["status"], "complete")
        self.assertNotIn("behavior_review", provider.calls)
        self.assertNotIn("publication_status", error["evidence_analysis"])

    def test_the_review_keeps_the_other_half_of_a_shared_format(self):
        """Tokn, Amethyst: encrypt and decrypt share one ciphertext format."""
        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        self.assertIn("the other half of a format, record or object the reported code "
                      "shares", provider.review_system)

    def test_the_planner_leaves_a_concluded_finding_as_it_is(self):
        import ast
        import inspect
        from cognalys.llm import finding_adjudication

        texts = [node.value for node in ast.walk(ast.parse(inspect.getsource(finding_adjudication)))
                 if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        planner = next(text for text in texts if "co_reported_findings, when" in text)
        self.assertIn("An entry whose status says it is concluded was already analysed in "
                      "this run and ended without a change (concluded_outcome says why): "
                      "leave its code as it is", planner)
        self.assertIn("the other half of a format both methods read", planner)

    def test_a_concluded_co_reported_finding_is_passed_on_to_the_others(self):
        import json
        import tempfile
        from cognalys.llm.fix_generation_common import FindingOutcome
        from cognalys.llm.generate_error_fixes import (
            CONCLUDED_CO_REPORTED_STATUS, concluded_outcome, pass_on_concluded_outcome)

        apk = Path("/runs/alpha.apk/errors.json")
        key = {"_file_path": apk, "unique_error_id": "a", "spec": "KeyPairGeneratorSpec",
               "csv_class": "x.CompanionTlsIdentity", "method_name": "generateAndroidKeyStoreKey",
               "error_index": 0, "error_message": "m"}
        server = {"_file_path": apk, "unique_error_id": "b", "spec": "SSLContextSpec",
                  "csv_class": "x.CompanionTlsIdentity", "method_name": "serverSocketFactory",
                  "error_index": 1, "error_message": "n"}
        annotate_co_reported_findings([key, server])
        before = server["co_reported_findings"]
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "no_security_impact/alpha.apk/0_generateAndroidKeyStoreKey.json"
            marker.parent.mkdir(parents=True)
            marker.write_text(json.dumps({"reason": "the inlined spec is the same object"}))
            concluded = concluded_outcome(directory, key, FindingOutcome(None, False, "abstained"))
            # A supported fix stopped by the gates concluded nothing.
            self.assertEqual(concluded_outcome(directory, server, FindingOutcome(
                None, False, "abstained", "MULTI_FILE_FIX_SUPPORTED")), {})
        pass_on_concluded_outcome([key, server], key, concluded)
        entry = server["co_reported_findings"][0]
        self.assertEqual(entry["status"], CONCLUDED_CO_REPORTED_STATUS)
        self.assertEqual(entry["concluded_outcome"], "no security impact")
        self.assertIn("same object", entry["concluded_reason"])
        # Replaced, not changed in place: a worker may be reading the old list.
        self.assertNotIn("status", before[0])
        self.assertNotIn("status", key["co_reported_findings"][0])

    def test_a_false_positive_and_a_finding_without_a_safe_fix_are_told_apart(self):
        import json
        import tempfile
        from cognalys.llm.fix_generation_common import FindingOutcome
        from cognalys.llm.generate_error_fixes import concluded_outcome

        error = {"_file_path": Path("/runs/q.apk/errors.json"), "error_index": 3,
                 "method_name": "buildSocket"}
        with tempfile.TemporaryDirectory() as directory:
            review = Path(directory) / "evidence_reviews/q.apk/3_buildSocket_evidence.json"
            review.parent.mkdir(parents=True)

            def ended(analysis):
                review.write_text(json.dumps({"analysis": analysis}))
                return concluded_outcome(directory, error, FindingOutcome(
                    None, False, "abstained", "NO_SAFE_FIX")).get("outcome")

            self.assertEqual(ended({"detector_violation": "not_confirmed",
                                    "confirmed_cause": "shape"}), "false positive")
            self.assertEqual(ended({"detector_violation": "confirmed"}), "no safe fix")
            # Insufficient evidence, or a false positive with no stated cause,
            # decided nothing.
            self.assertIsNone(ended({"detector_violation": "unknown"}))
            self.assertIsNone(ended({"detector_violation": "not_confirmed"}))
            # A generating decision the digest gate turned into NO_SAFE_FIX.
            self.assertIsNone(ended({"detector_violation": "confirmed", "v2": {
                "adjudication": {"decision": "SAFE_INTERNAL_DIGEST_MIGRATION"}}}))


class ExplicitDefaultTests(unittest.TestCase):
    """quad9 and Clash Fest: init(null, ...) made explicit is a rule-only change."""

    @staticmethod
    def _beyond(path="src/Main.java", symbol="method", change="reflows the GatewayServer calls"):
        return [{"source_file_path": path, "symbol": symbol, "change": change}]

    def test_a_rule_only_change_that_touches_more_is_drafted_again(self):
        def review(call):
            return {**CLEAN_REVIEW, "explicit_default_only": True,
                    "beyond_reported_argument": self._beyond() if call == 2 else []}

        result, provider, error, _ = _coordinated_run(review, [METHOD_EDIT])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(provider.calls.count("behavior_review"), 2)
        self.assertTrue(error["evidence_analysis"]["behavior_review"]["makes_default_explicit"])
        self.assertIn("identical default object", provider.review_system)

    def test_building_the_explicit_producer_is_part_of_the_argument(self):
        """SSLContext.init(null, null, null) made explicit needs a factory for
        the default object, its initialisation and their imports."""
        def review(call):
            # A test the plan requires is named, and is not "more".
            return {**CLEAN_REVIEW, "explicit_default_only": True,
                    "beyond_reported_argument": self._beyond(
                        "app/src/test/java/MainTest.java", "MainTest", "adds a test")}

        result, provider, _, _ = _coordinated_run(review, [METHOD_EDIT])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(provider.calls.count("behavior_review"), 1)
        self.assertIn("The statements, locals and imports that only build that explicit "
                      "producer", provider.review_system)
        self.assertIn("test files the plan requires", provider.review_system)

    def test_a_change_that_still_touches_more_after_every_draft_is_kept_with_a_note(self):
        from cognalys.llm.coordinated_generation import MAX_SEMANTIC_VALIDATION_RETRIES

        def review(call):
            return {**CLEAN_REVIEW, "explicit_default_only": True,
                    "beyond_reported_argument": self._beyond()}

        result, provider, error, _ = _coordinated_run(review, [METHOD_EDIT])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(provider.calls.count("behavior_review"),
                         MAX_SEMANTIC_VALIDATION_RETRIES + 1)
        self.assertIn("For the maintainer to decide: besides making the default explicit, "
                      "this change also: method: reflows the GatewayServer calls",
                      result["review_assumptions"])
        # The kept draft does more than make the default explicit, so the
        # text must not say it only does that.
        self.assertNotIn("makes_default_explicit", result["behavior_review"])
        self.assertNotIn("makes_default_explicit", error["evidence_analysis"]["behavior_review"])

    def test_the_extra_changes_reach_the_operator_notes(self):
        from cognalys.prs.generate_github_previews import operator_notes

        result, _, _, _ = _coordinated_run(
            lambda call: {**CLEAN_REVIEW, "explicit_default_only": True,
                          "beyond_reported_argument": self._beyond()}, [METHOD_EDIT])
        notes = operator_notes({"review_assumptions": result["review_assumptions"],
                                "review_contract_version": result["review_contract_version"]})
        self.assertIn("Maintainer decision: besides making the default explicit, this change "
                      "also: method: reflows the GatewayServer calls", notes)

    def test_a_made_explicit_default_is_not_a_patch_without_effect(self):
        """The two answers overlap: an explicit producer of the identical
        default changes the value the reported call receives."""
        result, provider, error, _ = _coordinated_run(
            lambda call: {**CLEAN_REVIEW, "explicit_default_only": True,
                          "patch_has_no_effect": True,
                          "no_effect_reason": "the explicit factory yields the same default",
                          "beyond_reported_argument": []}, [METHOD_EDIT])
        self.assertEqual(result["status"], "complete")
        self.assertFalse(any("PATCH_HAS_NO_EFFECT" in str(item)
                             for item in result.get("issues") or []))
        self.assertTrue(result["behavior_review"]["makes_default_explicit"])
        self.assertTrue(error["evidence_analysis"]["behavior_review"]["makes_default_explicit"])
        system = provider.review_system
        self.assertIn("is a change for which explicit_default_only holds (below)", system)
        self.assertIn("A change for which explicit_default_only holds gives the reported "
                      "call a value the code did not pass before, so set "
                      "explicit_default_only, not patch_has_no_effect; a factory or wrapper "
                      "around an object the code already had still has no effect. A change "
                      "for which explicit_default_only holds must touch only the reported "
                      "argument.", system)
        # Each sentence names its referent: the scope rule must not read as
        # applying to the no-effect wrapper.
        self.assertNotIn("rule-only change like that", system)
        self.assertNotIn("Such a change gives", system)
        self.assertNotIn("nothing the code does changes", system)
        # The other-path exclusion is part of the definition, before the
        # "Otherwise" that closes it.
        self.assertLess(system.index("another path, skipping configuration the null "
                                     "argument applies, does not qualify either"),
                        system.index("Otherwise explicit_default_only is false."))
        self.assertTrue(system.rstrip().endswith("what a joint finding needs -- or leave "
                                                 "it empty."))

    def test_an_explicit_form_that_passes_a_null_default_on_does_not_qualify(self):
        from cognalys.llm.llm_schemas import behavior_review_schema

        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        self.assertIn("every call the explicit form adds itself satisfies its own "
                      "specification: it must not pass a null or omitted platform-default "
                      "argument to another governed API", provider.review_system)
        self.assertIn("Otherwise explicit_default_only is false.", provider.review_system)
        properties = behavior_review_schema()["properties"]
        self.assertIn("none passes a null or omitted platform-default argument to another "
                      "governed API", properties["explicit_default_only"]["description"])
        # The precedence over patch_has_no_effect is in the schema too, for a
        # model that reads field descriptions in structured-output mode.
        self.assertIn("When true, patch_has_no_effect is false: the reported call now "
                      "receives a value the code did not pass.",
                      properties["explicit_default_only"]["description"])
        self.assertIn("false for a change for which explicit_default_only holds",
                      properties["patch_has_no_effect"]["description"])
        self.assertIn("satisfy their own specification",
                      properties["beyond_reported_argument"]["description"])

    def test_an_edit_named_for_other_findings_but_kept_still_counts_as_more(self):
        """Only an edit the code actually dropped leaves beyond_reported_argument;
        one the review also named for another finding but that stayed (no
        co-reported finding concluded) is still a change beyond the argument."""
        def review(call):
            named = [{"source_file_path": "src/Main.java", "symbol": "other"}]
            return {**CLEAN_REVIEW, "explicit_default_only": True,
                    "edits_for_other_findings": named if call == 2 else [],
                    "beyond_reported_argument": self._beyond(
                        symbol="other", change="rewrites other") if call == 2 else []}

        result, provider, _, _ = _coordinated_run(review, [METHOD_EDIT, OTHER_EDIT])
        self.assertEqual(result["status"], "complete")
        # The first review sent the draft back with EXPLICIT_DEFAULT_CHANGE_TOUCHES_MORE.
        self.assertEqual(provider.calls.count("behavior_review"), 2)
        self.assertEqual(result["dropped_edits_for_other_findings"], [])
        self.assertIn("what a joint finding needs -- or leave it empty", provider.review_system)
        self.assertNotIn("the edits listed in edits_for_other_findings", provider.review_system)

    def test_the_reviewed_statuses_are_public(self):
        from cognalys.llm import coordinated_generation

        self.assertEqual(coordinated_generation.REVIEWED_STATUSES,
                         frozenset({"reviewed", "all_edits_on_base"}))
        self.assertIs(coordinated_generation._REVIEWED_STATUSES,
                      coordinated_generation.REVIEWED_STATUSES)

    def test_the_adjudication_states_the_precedence_once(self):
        system = _adjudication_system()
        self.assertEqual(system.count("identical default object"), 1)
        self.assertIn("runtime_security_impact non_security, and propose the rule-only change",
                      system)
        self.assertIn("this does not apply", system)

    def test_the_adjudication_describes_the_correct_use_answer_once(self):
        # finding_processing reads it to choose "violação sem impacto de
        # segurança" over an issue; the prompt must say when it is true.
        system = _adjudication_system()
        self.assertEqual(system.count("current_code_is_correct_use"), 1)
        self.assertIn("NO_SAFE_FIX on a confirmed violation", system)
        self.assertIn("answer false in every other case", system)


class UnparsedReviewTests(unittest.TestCase):
    def test_a_review_that_answered_nothing_records_no_contract(self):
        """A truncated answer judged nothing; it must not read as current."""
        result, _, _, review_file = _coordinated_run(lambda call: {}, [METHOD_EDIT])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(review_file["status"], "not_run")
        self.assertNotIn("review_contract_version", review_file)
        self.assertIsNone(result["review_contract_version"])


def _adjudication_system() -> str:
    import json
    import logging
    import tempfile
    from cognalys.llm.generate_error_fixes import FixGenerator
    from cognalys.llm.pipeline_architecture import FindingEvidencePacketBuilder, PolicyRegistry

    systems = {}

    class Provider:
        provider_name, model = "test", "test-model"

        @staticmethod
        def get_token_usage():
            return {"input": 0, "output": 0}

        def generate(self, prompt, system=None, **kwargs):
            stage = kwargs.get("trace_stage", "")
            systems.setdefault(stage, system or "")
            if stage == "evidence_extraction":
                return json.dumps({
                    "claims": [], "observed_events": [], "predicate_assessment": [],
                    "confirmed_dataflows": [], "relations": [], "unresolved_questions": [],
                    "needs_more_evidence": False, "requested_evidence": [],
                    "family_assessment": {}})
            return json.dumps({
                "cause_status": "unknown", "confirmed_cause": "", "detector_violation": "unknown",
                "runtime_security_impact": "unknown", "compatibility_status": "unknown",
                "scope_status": "incomplete", "decision": "NO_SAFE_FIX",
                "decision_claim_ids": [], "blocking_for_generation": [],
                "blocking_for_publication": [], "generation_status": "blocked",
                "publication_status": "blocked", "required_edit_categories": [],
                "required_tests": [], "forward_compatibility_strategy": "",
                "authorized_behavior_change": {"authorized": False, "description": "",
                                               "policy_reference": ""},
                "review_assumptions": []})

    with tempfile.TemporaryDirectory() as directory:
        generator = object.__new__(FixGenerator)
        generator.output_dir = Path(directory) / "out"
        generator.provider = Provider()
        generator.web_search = False
        generator.architecture_version = "v2"
        generator.logger = logging.getLogger("test")
        generator.evidence_packet_builder = FindingEvidencePacketBuilder(
            repository_context_budget=140_000)
        generator.policy_registry = PolicyRegistry(Path(directory) / "no_policies")
        generator.adjudicate_finding({
            "spec": "SSLContextSpec", "method_name": "buildSocket",
            "method_body": "ctx.init(null, null, null)", "imports": "",
            "source_file_path": "app/src/main/java/SSLConnector.java",
            "csv_class": "SSLConnector"}, "app.apk", "buildSocket")
    return systems.get("adjudication", "")


class MaintainerChoiceInTextTests(unittest.TestCase):
    """Trigger (2026-10-28): the choice the patch made reached neither the
    preview nor the pull request."""

    def test_only_a_product_or_compatibility_choice_reaches_the_text(self):
        from cognalys.llm.coordinated_generation import review_facts_for_text

        choice = {"status": "reviewed", "maintainer_decision_required": True,
                  "maintainer_decision": "the ED25519 option now generates an EC key",
                  "maintainer_decision_kind": "product_or_compatibility_choice"}
        self.assertEqual(review_facts_for_text(choice)["maintainer_choice"],
                         "the ED25519 option now generates an EC key")
        concern = {**choice, "maintainer_decision_kind": "verification_or_analyzer_concern"}
        self.assertNotIn("maintainer_choice", review_facts_for_text(concern))

    def test_the_summary_ends_with_the_choice(self):
        import json
        from cognalys.llm.finding_adjudication import (
            compose_summary_for_applied_edits, summary_error_from_solution)

        prompts = []

        class Provider:
            def generate(self, prompt, *args, **kwargs):
                prompts.append(prompt)
                return json.dumps({"title": "Use EC keys", "summary": "I changed it."})

        error = summary_error_from_solution({"evidence_analysis": {"behavior_review": {
            "maintainer_choice": "the ED25519 option now generates an EC key"}}})
        compose_summary_for_applied_edits(Provider(), __import__("logging").getLogger("t"),
                                          error, [])
        self.assertIn('"maintainer_choice":"the ED25519 option now generates an EC key"',
                      prompts[0])
        self.assertIn("end with one plain sentence that names the choice", prompts[0])


class ReplanAfterRegressionsTests(unittest.TestCase):
    def test_the_new_plan_keeps_the_decision_the_finding_was_normalised_to(self):
        """A supported plan demoted to review must not come back unattended."""
        from cognalys.llm.generate_error_fixes import FixGenerator

        generator = object.__new__(FixGenerator)
        generator.adjudicate_finding = lambda error, apk, method: ({
            "generation_status": "supported", "decision": "MULTI_FILE_FIX_SUPPORTED",
            "publication_status": "eligible_after_validation",
            "v2": {"adjudication": {"decision": "MULTI_FILE_FIX_SUPPORTED"}},
            "coordinated_fix_plan": {"required_edits": [{"symbol": "load"}]}}, {})
        failures = [{"code": "UNINTENDED_BEHAVIOR_CHANGE", "message": "first run: throws"}]
        error = {"evidence_analysis": {"decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                                       "review_assumptions": ["scope incomplete"]}}
        self.assertTrue(generator.replan_after_regressions(
            error, failures, "a.apk", "save", "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"))
        analysis = error["evidence_analysis"]
        self.assertEqual(analysis["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(analysis["v2"]["adjudication"]["decision"],
                         "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(analysis["publication_status"], "blocked")
        self.assertIn("scope incomplete", analysis["review_assumptions"])

    def test_a_new_plan_that_needs_other_handling_is_not_taken(self):
        from cognalys.llm.generate_error_fixes import FixGenerator

        generator = object.__new__(FixGenerator)
        generator.logger = __import__("logging").getLogger("test")
        generator.adjudicate_finding = lambda error, apk, method: ({
            "generation_status": "supported_for_review",
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "coordinated_fix_plan": {"required_edits": [{"symbol": "load"}]}}, {})
        failures = [{"code": "UNINTENDED_BEHAVIOR_CHANGE", "message": "first run: throws"}]
        error = {"evidence_analysis": {"decision": "FIX_SUPPORTED"}}
        self.assertFalse(generator.replan_after_regressions(
            error, failures, "a.apk", "save", "FIX_SUPPORTED"))
        self.assertEqual(error["evidence_analysis"], {"decision": "FIX_SUPPORTED"})

    def _routed_digest_replan(self, new_decision, assessment):
        from cognalys.llm.generate_error_fixes import FixGenerator

        generator = object.__new__(FixGenerator)
        generator.logger = __import__("logging").getLogger("test")
        generator.adjudicate_finding = lambda error, apk, method: ({
            "generation_status": "supported", "decision": new_decision,
            "publication_status": "eligible_after_validation",
            "digest_contract_assessment": assessment,
            "coordinated_fix_plan": {"required_edits": [{"symbol": "sha1"}]}}, {})
        error = {"evidence_analysis": {
            "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
            "decision_before_review_routing": "SAFE_INTERNAL_DIGEST_MIGRATION",
            "publication_status": "eligible_after_validation",
            "digest_contract_assessment": {"contract_kind": "internal_file_name"}}}
        taken = generator.replan_after_regressions(
            error, [{"code": "UNINTENDED_BEHAVIOR_CHANGE", "message": "storage full: throws"}],
            "a.apk", "sha1", "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        return taken, error["evidence_analysis"]

    def test_a_new_plan_with_the_first_plans_own_decision_is_routed_the_same_way(self):
        """RedReader run and run_v3 (2026-11-08/09): a digest migration routed
        to review for editing beyond the reported method had its replan
        refused for coming back with that same digest decision."""
        taken, analysis = self._routed_digest_replan(
            "SAFE_INTERNAL_DIGEST_MIGRATION", {"contract_kind": "internal_file_name"})
        self.assertTrue(taken)
        self.assertEqual(analysis["decision"], "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW")
        self.assertEqual(analysis["decision_before_review_routing"],
                         "SAFE_INTERNAL_DIGEST_MIGRATION")
        # Not the incomplete-scope demotion: publication as the first plan had it.
        self.assertEqual(analysis["publication_status"], "eligible_after_validation")

    def test_a_routed_digest_replan_with_another_contract_or_decision_is_refused(self):
        for decision, assessment in (
                ("SAFE_INTERNAL_DIGEST_MIGRATION", {"contract_kind": "server_value"}),
                ("BACKEND_MIGRATION_REQUIRED_REVIEW_ONLY", {"contract_kind": "internal_file_name"})):
            with self.subTest(decision=decision):
                taken, analysis = self._routed_digest_replan(decision, assessment)
                self.assertFalse(taken)
                self.assertEqual(analysis["digest_contract_assessment"],
                                 {"contract_kind": "internal_file_name"})

    def test_a_plan_whose_drafts_all_broke_behaviour_is_made_again_once(self):
        from cognalys.llm.generate_error_fixes import FixGenerator

        generator = object.__new__(FixGenerator)
        calls = []

        def adjudicate(error, apk, method):
            calls.append(list(error.get("previous_patch_regressions", [])))
            return {"generation_status": "supported", "decision": "FIX_SUPPORTED",
                    "coordinated_fix_plan": {"required_edits": [{"symbol": "load"}]}}, {}

        generator.adjudicate_finding = adjudicate
        error = {"evidence_analysis": {"decision": "FIX_SUPPORTED"}}
        failures = [{"code": "UNINTENDED_BEHAVIOR_CHANGE", "message": "first run: throws"}]
        self.assertTrue(generator.replan_after_regressions(error, failures, "a.apk", "save"))
        self.assertEqual(calls, [["first run: throws"]])
        # Once per finding.
        self.assertFalse(generator.replan_after_regressions(error, failures, "a.apk", "save"))
        self.assertEqual(len(calls), 1)


class ReplanAfterDraftFailuresTests(unittest.TestCase):
    """Audit of 2026-10-31: about 19 failed generations ended on checks of the
    drafts themselves (Ursa's widened API, Trigger's untouched value) and none
    was planned again."""

    @staticmethod
    def _generator(calls):
        from cognalys.llm.generate_error_fixes import FixGenerator

        generator = object.__new__(FixGenerator)
        generator.logger = __import__("logging").getLogger("test")

        def adjudicate(error, apk, method):
            calls.append(list(error.get("previous_draft_failures") or []))
            return {"generation_status": "supported_for_review",
                    "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                    "coordinated_fix_plan": {"required_edits": [{"symbol": "load"}]}}, {}

        generator.adjudicate_finding = adjudicate
        return generator

    def test_drafts_that_failed_only_on_themselves_are_planned_again_once(self):
        calls = []
        generator = self._generator(calls)
        error = {"evidence_analysis": {"decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"}}
        failures = [{"code": "UNNECESSARY_PUBLIC_API_EXPANSION", "message": "made public",
                     "affected_paths": ["src/Net.kt"]},
                    {"code": "UNNECESSARY_PUBLIC_API_EXPANSION", "message": "made public",
                     "affected_paths": ["src/Net.kt"]}]
        self.assertTrue(generator.replan_after_draft_failures(error, failures, "a.apk", "m"))
        self.assertEqual(calls, [[{"code": "UNNECESSARY_PUBLIC_API_EXPANSION",
                                   "message": "made public", "affected_paths": ["src/Net.kt"]}]])
        self.assertFalse(generator.replan_after_draft_failures(error, failures, "a.apk", "m"))
        self.assertEqual(len(calls), 1)

    def test_the_new_plan_reads_what_a_check_found_and_in_which_file(self):
        """RedReader run_v3 (2026-11-09): the replan read SYMBOL_NOT_DECLARED_IN_
        REPOSITORY with an empty message and no file; the check reports both
        as details and source_file_path."""
        calls = []
        generator = self._generator(calls)
        error = {"evidence_analysis": {"decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"}}
        failures = [{"code": "SYMBOL_NOT_DECLARED_IN_REPOSITORY",
                     "source_file_path": "src/test/ManagerTest.java",
                     "details": ["Manager declares no static getDbFilename(...)"]},
                    {"code": "UNNECESSARY_PUBLIC_API_EXPANSION", "path": "src/General.kt",
                     "details": ["legacyDigest"], "message": "made public"}]
        self.assertTrue(generator.replan_after_draft_failures(error, failures, "a.apk", "m"))
        self.assertEqual(calls, [[
            {"code": "SYMBOL_NOT_DECLARED_IN_REPOSITORY",
             "message": "Manager declares no static getDbFilename(...)",
             "affected_paths": ["src/test/ManagerTest.java"]},
            {"code": "UNNECESSARY_PUBLIC_API_EXPANSION", "message": "made public; legacyDigest",
             "affected_paths": ["src/General.kt"]}]])

    def test_a_maintainer_facing_failure_is_not_planned_again_here(self):
        calls = []
        generator = self._generator(calls)
        for failures in ([{"code": "UNNECESSARY_PUBLIC_API_EXPANSION"},
                          {"code": "STORED_DERIVED_VALUE_CHANGED"}],
                         [{"code": "UNINTENDED_BEHAVIOR_CHANGE", "message": "throws"}], []):
            error = {"evidence_analysis": {"decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"}}
            self.assertFalse(generator.replan_after_draft_failures(error, failures, "a.apk", "m"))
        self.assertEqual(calls, [])

    def test_a_unit_gets_one_new_plan_in_all(self):
        calls = []
        generator = self._generator(calls)
        draft = [{"code": "REPORTED_VALUE_UNTOUCHED", "message": "still SHA-1"}]
        regression = [{"code": "UNINTENDED_BEHAVIOR_CHANGE", "message": "first run: throws"}]
        error = {"evidence_analysis": {"decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"}}
        self.assertTrue(generator.replan_after_regressions(error, regression, "a.apk", "m"))
        self.assertFalse(generator.replan_after_draft_failures(error, draft, "a.apk", "m"))
        error = {"evidence_analysis": {"decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW"}}
        self.assertTrue(generator.replan_after_draft_failures(error, draft, "a.apk", "m"))
        self.assertFalse(generator.replan_after_regressions(error, regression, "a.apk", "m"))
        self.assertFalse(generator.replan_after_no_effect(
            error, {"no_effect_reason": "same calls"}, ["src/Main.java"], "a.apk", "m"))
        self.assertEqual(len(calls), 2)

    def test_the_generation_loop_replans_after_the_last_failed_attempt(self):
        from unittest.mock import patch

        from cognalys.llm.generate_error_fixes import FixGenerator

        calls = []

        def adjudicate(error, apk, method):
            calls.append(list(error.get("previous_draft_failures") or []))
            return {"generation_status": "blocked", "decision": "NO_SAFE_FIX",
                    "coordinated_fix_plan": {"required_edits": []}}, {}

        invalid = {"status": "invalid", "errors": [
            {"code": "UNNECESSARY_PUBLIC_API_EXPANSION", "message": "made public",
             "affected_paths": ["src/Main.java"]}]}
        with patch.object(FixGenerator, "adjudicate_finding", create=True,
                          side_effect=lambda *args: adjudicate(*args[-3:])), \
                patch.object(FixGenerator, "_validated", return_value=invalid):
            result, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["issues"], ["UNNECESSARY_PUBLIC_API_EXPANSION"])
        # Three drafts, then one new plan (refused here as it plans no edit).
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0]["code"], "UNNECESSARY_PUBLIC_API_EXPANSION")


class KeptFilesRelianceTests(unittest.TestCase):
    """RedReader run_v3 (2026-11-09): a retry regenerated RedditSubredditManager
    with new method names while the kept test still called the old ones, and
    the last attempt failed on SYMBOL_NOT_DECLARED_IN_REPOSITORY."""

    MANAGER = {"source_file_path": "src/Manager.java", "provided_contracts": [
        "package-private static getDbFilename(String) returns the current name"],
        "edits": [{"corrected_code": (
            "    static String getDbFilename(final String user) {\n"
            "        return General.currentDigest(user) + \".db\";\n    }\n"
            "    static synchronized String migrate(Context context, String user) {\n"
            "        return getDbFilename(user);\n    }")}]}
    TEST = {"source_file_path": "src/test/ManagerTest.java",
            "required_contracts": ["Manager provides getDbFilename and migrate"],
            "edits": [{"corrected_code": (
                "class ManagerTest {\n    @Test public void name() {\n"
                "        assertEquals(\"x.db\", Manager.getDbFilename(\"a\"));\n"
                "        Manager.migrate(context, \"a\");\n    }\n}")}]}
    PATHS = ["src/General.kt", "src/Manager.java", "src/test/ManagerTest.java"]

    def test_a_kept_file_after_the_target_lists_what_it_calls_and_its_contracts(self):
        from cognalys.llm.coordinated_generation import (
            KEPT_FILES_RELIANCE_GUIDANCE, kept_files_reliance)

        reliance = kept_files_reliance("src/Manager.java", self.MANAGER,
                                       {"src/test/ManagerTest.java": self.TEST}, self.PATHS)
        self.assertEqual(reliance["guidance"], KEPT_FILES_RELIANCE_GUIDANCE)
        self.assertEqual(reliance["previous_draft_provided_contracts"],
                         self.MANAGER["provided_contracts"])
        self.assertEqual(reliance["files"], [{
            "source_file_path": "src/test/ManagerTest.java",
            "calls": ["getDbFilename", "migrate"],
            "required_contracts": ["Manager provides getDbFilename and migrate"]}])

    def test_a_kept_file_before_the_target_lists_only_its_calls(self):
        from cognalys.llm.coordinated_generation import kept_files_reliance

        general = {"edits": [{"corrected_code": (
            "    @JvmStatic\n    fun currentDigest(plaintext: ByteArray): String = hex(plaintext)\n"
            "    @JvmStatic\n    fun legacyDigest(plaintext: ByteArray): String = hex(plaintext)")}],
            "provided_contracts": ["General.currentDigest(byte[])"]}
        manager = {"required_contracts": ["General.currentDigest(byte[])"],
                   "edits": self.MANAGER["edits"]}
        reliance = kept_files_reliance("src/General.kt", general,
                                       {"src/Manager.java": manager},
                                       ["src/Manager.java", "src/General.kt"])
        # In previous_file_contracts already: no second copy of its contracts.
        self.assertEqual(reliance["files"], [{"source_file_path": "src/Manager.java",
                                              "calls": ["currentDigest"]}])

    def test_a_regenerated_test_and_a_constructor_call_name_no_reliance(self):
        from cognalys.llm.coordinated_generation import kept_files_reliance

        # A helper the replaced test declared is the production file's own.
        test = {"edits": [{"corrected_code": "    private static String toHex(byte[] b) {\n"
                                             "        return \"\";\n    }"}]}
        general = {"edits": [{"corrected_code": "return toHex(digest.digest(plaintext))"}]}
        self.assertEqual(kept_files_reliance("src/test/ManagerTest.java", test,
                                             {"src/General.kt": general}, self.PATHS), {})
        # `return ByteArray(n) { 0 }` calls a constructor; it declares nothing.
        salt = {"edits": [{"corrected_code": (
            "fun derive(password: CharArray, salt: ByteArray): ByteArray {\n"
            "    return ByteArray(32) { 0 }\n}")}]}
        user = {"edits": [{"corrected_code": "val key = derive(pw, ByteArray(16) { 1 })"}]}
        self.assertEqual(kept_files_reliance("src/Users.kt", salt, {"src/test/UsersTest.kt": user},
                                             ["src/Users.kt", "src/test/UsersTest.kt"])["files"],
                         [{"source_file_path": "src/test/UsersTest.kt", "calls": ["derive"],
                           "required_contracts": []}])

    def test_nothing_when_no_kept_file_calls_the_replaced_declarations(self):
        from cognalys.llm.coordinated_generation import kept_files_reliance

        unrelated = {"edits": [{"corrected_code": "int value = 2;"}]}
        self.assertEqual(kept_files_reliance("src/Manager.java", self.MANAGER,
                                             {"src/test/ManagerTest.java": unrelated},
                                             self.PATHS), {})
        self.assertEqual(kept_files_reliance("src/Manager.java", {},
                                             {"src/test/ManagerTest.java": self.TEST},
                                             self.PATHS), {})

    def test_the_regenerated_file_reads_what_the_kept_test_calls(self):
        import json
        import re
        import tempfile
        from unittest.mock import patch

        from cognalys.llm.generate_error_fixes import FixGenerator

        class Provider:
            def __init__(self):
                self.prompts = []

            def generate(self, prompt, *args, **kwargs):
                if kwargs.get("schema_name") == "behavior_review":
                    return json.dumps(CLEAN_REVIEW)
                path = re.search(r'"target_file":\s*"([^"]+)"', prompt).group(1)
                self.prompts.append((path, prompt))
                if "Test" in path:
                    original = "int t = 1;"
                    corrected = "int t = Manager.getDbFilename(\"a\").length();"
                    contracts = {"required_contracts": ["Manager.getDbFilename(String)"]}
                else:
                    original = "int value = 1;"
                    corrected = ("int value = 2;\n    static String getDbFilename(String user) "
                                 "{ return user; }")
                    contracts = {"provided_contracts": ["static getDbFilename(String)"]}
                return json.dumps({
                    "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "source_file_path": path,
                    "explanation": "e", "edits": [{"source_file_path": path, "symbol": "v",
                                                   "edit_kind": "declaration",
                                                   "original_code": original,
                                                   "corrected_code": corrected, "reason": "r"}],
                    "no_change_required": False, "provided_contracts": [],
                    "required_contracts": [], "required_tests": [],
                    "manual_review_required": True, "review_assumptions": [],
                    "confidence": "high", **contracts})

        outcomes = iter([
            {"status": "invalid", "warnings": [], "errors": [
                {"code": "PUBLIC_API_CONTRACT_CHANGED", "path": "src/Main.java",
                 "details": ["value"]}]}])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "repo/src/test").mkdir(parents=True)
            (root / "repo/src/Main.java").write_text("class X { int value = 1; }",
                                                    encoding="utf-8")
            (root / "repo/src/test/MainTest.java").write_text("class T { int t = 1; }",
                                                             encoding="utf-8")
            generator = object.__new__(FixGenerator)
            generator.output_dir = root / "out"
            generator.provider = Provider()
            generator.web_search = False
            generator.logger = __import__("logging").getLogger("test")
            error = {"repository_path": str(root / "repo"), "error_index": 2,
                     "evidence_analysis": {"confirmed_cause": "cause", "coordinated_fix_plan": {
                         "required_edits": [
                             {"source_file_path": "src/Main.java", "symbol": "value"},
                             {"source_file_path": "src/test/MainTest.java", "symbol": "t"}]}}}
            with patch.object(FixGenerator, "_validated", side_effect=lambda *args: next(
                    outcomes, {"status": "valid", "errors": [], "warnings": []})):
                result = generator.generate_coordinated_file_drafts(
                    error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "method")
        self.assertEqual(result["status"], "complete")
        prompts = generator.provider.prompts
        self.assertEqual([path for path, _ in prompts],
                         ["src/Main.java", "src/test/MainTest.java", "src/Main.java"])
        self.assertNotIn("kept_files_rely_on", prompts[0][1] + prompts[1][1])
        retry = json.loads(prompts[2][1].split("\n\n", 1)[1].split("\n\nREQUIRED JSON SCHEMA:")[0])
        self.assertEqual(retry["kept_files_rely_on"]["files"], [{
            "source_file_path": "src/test/MainTest.java", "calls": ["getDbFilename"],
            "required_contracts": ["Manager.getDbFilename(String)"]}])
        self.assertEqual(retry["kept_files_rely_on"]["previous_draft_provided_contracts"],
                         ["static getDbFilename(String)"])
        self.assertNotIn("_replaced_drafts", error)

    def test_a_regression_redraft_regenerates_the_kept_test(self):
        """Session writeEntry (2026-11-10): the production file was redrafted
        to behave otherwise and the kept test still exercised, and assumed,
        the refused draft."""
        import json
        import re
        import tempfile
        from unittest.mock import patch

        from cognalys.llm.generate_error_fixes import FixGenerator

        regression = {**CLEAN_REVIEW, "regressions": [{
            "scenario": "first run, file absent", "before": "creates the file",
            "after": "throws", "source_file_path": "src/Main.java"}]}
        reviews = iter([regression])

        class Provider:
            def __init__(self):
                self.prompts = []

            def generate(self, prompt, *args, **kwargs):
                if kwargs.get("schema_name") == "behavior_review":
                    return json.dumps(next(reviews, CLEAN_REVIEW))
                path = re.search(r'"target_file":\s*"([^"]+)"', prompt).group(1)
                self.prompts.append((path, prompt))
                attempt = sum(1 for item, _ in self.prompts if item == path)
                if "Test" in path:
                    original = "int t = 1;"
                    corrected = "int t = Manager.getDbFilename(\"a\").length();"
                    contracts = {"required_contracts": ["Manager.getDbFilename(String)"]}
                else:
                    original = "int value = 1;"
                    corrected = ("int value = 2;\n    static String getDbFilename(String user) "
                                 "{ return user; }")
                    contracts = {"provided_contracts": ["static getDbFilename(String)"]}
                return json.dumps({
                    "decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "source_file_path": path,
                    "explanation": "e", "edits": [{"source_file_path": path, "symbol": "v",
                                                   "edit_kind": "declaration",
                                                   "original_code": original,
                                                   "corrected_code": corrected, "reason": "r"}],
                    "no_change_required": False, "provided_contracts": [],
                    "required_contracts": [], "required_tests": [],
                    "manual_review_required": True,
                    "review_assumptions": [f"{path} draft {attempt}"],
                    "confidence": "high", **contracts})

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "repo/src/test").mkdir(parents=True)
            (root / "repo/src/Main.java").write_text("class X { int value = 1; }",
                                                    encoding="utf-8")
            (root / "repo/src/test/MainTest.java").write_text("class T { int t = 1; }",
                                                             encoding="utf-8")
            generator = object.__new__(FixGenerator)
            generator.output_dir = root / "out"
            generator.provider = Provider()
            generator.web_search = False
            generator.logger = __import__("logging").getLogger("test")
            error = {"repository_path": str(root / "repo"), "error_index": 2,
                     "evidence_analysis": {"confirmed_cause": "cause", "coordinated_fix_plan": {
                         "required_edits": [
                             {"source_file_path": "src/Main.java", "symbol": "value"},
                             {"source_file_path": "src/test/MainTest.java", "symbol": "t"}]}}}
            with patch.object(FixGenerator, "_validated", side_effect=lambda *args: {
                    "status": "valid", "errors": [], "warnings": []}):
                result = generator.generate_coordinated_file_drafts(
                    error, "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW", "app.apk", "method")
        self.assertEqual(result["status"], "complete")
        prompts = generator.provider.prompts
        self.assertEqual([path for path, _ in prompts],
                         ["src/Main.java", "src/test/MainTest.java",
                          "src/Main.java", "src/test/MainTest.java"])

        def context(prompt):
            return json.loads(prompt.split("\n\n", 1)[1].split("\n\nREQUIRED JSON SCHEMA:")[0])

        self.assertNotIn("kept_files_rely_on", context(prompts[2][1]))
        retry = context(prompts[3][1])["previous_validation_feedback"]["semantic_validation_retry"]
        self.assertEqual([item["code"] for item in retry["errors"]],
                         ["UNINTENDED_BEHAVIOR_CHANGE"])
        self.assertEqual(context(prompts[3][1])["previous_file_contracts"][0]["source_file_path"],
                         "src/Main.java")
        self.assertEqual(set(result["review_assumptions"]),
                         {"src/Main.java draft 2", "src/test/MainTest.java draft 2"})


# BlueGate run_v8 (2026-10-31): generateNewKeyPair [KeyPairGeneratorSpec]
# joined into getOrCreateKeyPair [KeyPairSpec]; the joint finding's only
# change moved ECGenParameterSpec("secp256r1") into a local.
_JOINT = {"method": "other", "specification": "KeyPairGeneratorSpec",
          "class": "X", "error_message": "no preparation was observed",
          "unique_error_id": "X:::other:::KeyPairGeneratorSpec"}
_LOCAL_ONLY = {"method": "other", "specification": "KeyPairGeneratorSpec",
               "changed_for_it": "val spec = ECGenParameterSpec(\"secp256r1\")",
               "reason": "the same ECGenParameterSpec reaches initialize."}


class JointFindingEffectTests(unittest.TestCase):
    """Effect judged per finding of a joined unit (REVIEW_CONTRACT_VERSION 13)."""

    def test_a_joint_share_restructured_without_effect_regenerates_once(self):
        answers = []

        def review(call):
            answers.append(call)
            return {**CLEAN_REVIEW, "joint_findings_without_effect":
                    [_LOCAL_ONLY] if len(answers) == 1 else []}

        result, provider, error, _ = _coordinated_run(
            review, [METHOD_EDIT, OTHER_EDIT], error_extra={"joint_findings": [_JOINT]})
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(answers), 2)
        self.assertIn("JOINT_FINDING_EDIT_WITHOUT_EFFECT", provider.draft_prompts[-1])
        self.assertIn("Drop it and leave that code exactly as it was", provider.draft_prompts[-1])
        # The second draft left its code as it was, as it was told, and its
        # review listed nothing: the finding is still unresolved, and the
        # earlier verdict is carried (review of 2026-10-31: it was lost, and
        # the text and the statistics counted the finding as resolved).
        facts = error["evidence_analysis"]["behavior_review"]
        self.assertEqual([item["method"] for item in facts["joint_findings_without_effect"]],
                         ["other"])
        from cognalys.utils.pr_text import joint_finding_claims

        self.assertTrue(joint_finding_claims(
            "I now return entries directly. This also resolves the related issue in `other` "
            "by preparing the EC parameter specification.\n\nI found this while running the "
            "app under RVSec.", facts["joint_findings_without_effect"],
            facts["joint_finding_count"], "method"))

    def test_on_the_last_attempt_the_draft_stays_and_the_finding_is_not_claimed(self):
        result, _, error, review_file = _coordinated_run(
            lambda call: {**CLEAN_REVIEW, "joint_findings_without_effect": [_LOCAL_ONLY]},
            [METHOD_EDIT, OTHER_EDIT], error_extra={"joint_findings": [_JOINT]})
        self.assertEqual(result["status"], "complete")
        self.assertEqual(review_file["joint_findings_without_effect"][0]["method"], "other")
        facts = error["evidence_analysis"]["behavior_review"]
        self.assertEqual(facts["joint_findings_without_effect"],
                         [{"method": "other", "specification": "KeyPairGeneratorSpec",
                           "reason": "the same ECGenParameterSpec reaches initialize."}])
        self.assertEqual(facts["joint_finding_count"], 1)
        self.assertFalse(result["behavior_review_summary"]["patch_has_no_effect"])

    def test_a_share_that_changes_nothing_records_without_regenerating(self):
        answers = []

        def review(call):
            answers.append(call)
            return {**CLEAN_REVIEW, "joint_findings_without_effect": [
                {**_LOCAL_ONLY, "changed_for_it": ""}]}

        result, _, error, _ = _coordinated_run(
            review, [METHOD_EDIT], error_extra={"joint_findings": [_JOINT]})
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(answers), 1)
        self.assertEqual(error["evidence_analysis"]["behavior_review"][
            "joint_findings_without_effect"][0]["method"], "other")

    def test_only_the_units_own_joint_findings_with_a_reason_count(self):
        from cognalys.llm.coordinated_generation import joint_findings_without_effect

        error = {"joint_findings": [_JOINT]}
        self.assertEqual(joint_findings_without_effect(error, [
            {**_LOCAL_ONLY, "method": "elsewhere"},
            {**_LOCAL_ONLY, "specification": "CipherSpec"},
            {**_LOCAL_ONLY, "reason": " "}]), [])
        self.assertEqual(len(joint_findings_without_effect(
            error, [_LOCAL_ONLY, {**_LOCAL_ONLY, "method": "X.other(String)"}])), 1)

    def test_the_review_judges_each_joint_finding_and_the_drafts_see_them(self):
        from cognalys.llm.llm_schemas import behavior_review_schema

        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT],
                                             error_extra={"joint_findings": [_JOINT]})
        system = " ".join(provider.review_system.split())
        self.assertIn("Judge effect for each finding of the unit on its own -- the reported "
                      "one (finding.method_name, finding.specification) and each joint "
                      "finding -- at its own reported call and under its own rule", system)
        self.assertIn("it is true only when no finding of the unit has an effect, and false "
                      "when any one has, even if others are listed", system)
        self.assertIn("findings_without_effect", behavior_review_schema()["properties"])
        self.assertIn('"joint_findings"', provider.draft_prompts[0])
        self.assertIn("A joint finding no such change resolves is left exactly as its code "
                      "was", " ".join(provider.draft_system.split()))

    def test_the_summary_does_not_list_a_joint_finding_without_effect(self):
        from cognalys.llm.generate_error_fixes import FixGenerator
        import json
        import logging

        prompts = []

        class Provider:
            def generate(self, prompt, *args, **kwargs):
                prompts.append(prompt)
                return json.dumps({"title": "Return key store entries", "summary": "s"})

        generator = object.__new__(FixGenerator)
        generator.logger = logging.getLogger("joint-summary")
        generator.provider = Provider()
        error = {"spec": "KeyPairSpec", "joint_findings": [_JOINT, {**_JOINT, "method": "third"}],
                 "evidence_analysis": {"behavior_review": {
                     "joint_findings_without_effect": [_LOCAL_ONLY]}}}
        generator.compose_maintainer_summary(error, [], [], [])
        self.assertIn('"also_resolves":[{"method":"third"', prompts[0])
        self.assertNotIn('"method":"other"', prompts[0])
        self.assertIn("Never say the change resolves, fixes or addresses any other finding",
                      prompts[0])

    def test_the_statistics_close_a_joint_finding_without_effect_on_its_own(self):
        import json
        import tempfile
        from cognalys.reporting.finding_statistics import final_outcome, read_run

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            methods = run / "error_methods/bluegate.apk"
            methods.mkdir(parents=True)
            (methods / "1_getOrCreateKeyPair.json").write_text(json.dumps({
                "extraction_metadata": {"apk_name": "bluegate.apk", "csv_index": 1},
                "error": {"csv_class": "x.KeyManager", "csv_method": "getOrCreateKeyPair",
                          "spec": "KeyPairSpec"}}))
            solutions = run / "error_solutions"
            (solutions / "bluegate.apk").mkdir(parents=True)
            (solutions / "bluegate.apk/1_getOrCreateKeyPair_solution.json").write_text(json.dumps({
                "solution_metadata": {"csv_class": "x.KeyManager",
                                      "method_name": "getOrCreateKeyPair", "spec": "KeyPairSpec"},
                "evidence_analysis": {"behavior_review": {
                    "review_contract_version": 13, "joint_finding_count": 1,
                    "joint_findings_without_effect": [
                        {"method": "generateNewKeyPair", "specification": "KeyPairGeneratorSpec",
                         "reason": "the same ECGenParameterSpec reaches initialize."}]}}}))
            identity = {"apk_name": "bluegate.apk", "csv_class": "x.KeyManager"}
            (solutions / "joint_findings.json").write_text(json.dumps([{
                "joined": {**identity, "method_name": "generateNewKeyPair",
                           "spec": "KeyPairGeneratorSpec"},
                "into": {**identity, "method_name": "getOrCreateKeyPair",
                         "spec": "KeyPairSpec"}}]))
            records = read_run(run)
        primary = records[("bluegate.apk", "x.KeyManager", "getOrCreateKeyPair", "KeyPairSpec")]
        joined = records[("bluegate.apk", "x.KeyManager", "generateNewKeyPair",
                          "KeyPairGeneratorSpec")]
        self.assertTrue(primary.get("solution"))
        self.assertNotIn("solution", joined)
        outcome, detail = final_outcome(joined)
        self.assertEqual(outcome, "violação sem impacto de segurança")
        self.assertIn("analisado junto com getOrCreateKeyPair, sem efeito no patch", detail)
        self.assertIn("same ECGenParameterSpec", detail)
        self.assertNotIn("resolvido junto", detail)

    def test_the_statistics_read_the_repaired_patch_review_too(self):
        # Review of 2026-10-31: record_repair_review kept the verdict of the
        # repaired patch's review where the statistics never looked.
        import json
        import tempfile
        from cognalys.reporting.finding_statistics import final_outcome, read_run

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            methods = run / "error_methods/bluegate.apk"
            methods.mkdir(parents=True)
            (methods / "1_getOrCreateKeyPair.json").write_text(json.dumps({
                "extraction_metadata": {"apk_name": "bluegate.apk", "csv_index": 1},
                "error": {"csv_class": "x.KeyManager", "csv_method": "getOrCreateKeyPair",
                          "spec": "KeyPairSpec"}}))
            solutions = run / "error_solutions"
            (solutions / "bluegate.apk").mkdir(parents=True)
            (solutions / "bluegate.apk/1_getOrCreateKeyPair_solution.json").write_text(json.dumps({
                "solution_metadata": {"csv_class": "x.KeyManager",
                                      "method_name": "getOrCreateKeyPair", "spec": "KeyPairSpec"},
                "evidence_analysis": {"behavior_review": {"review_contract_version": 13}}}))
            identity = {"apk_name": "bluegate.apk", "csv_class": "x.KeyManager"}
            (solutions / "joint_findings.json").write_text(json.dumps([{
                "joined": {**identity, "method_name": "generateNewKeyPair",
                           "spec": "KeyPairGeneratorSpec"},
                "into": {**identity, "method_name": "getOrCreateKeyPair",
                         "spec": "KeyPairSpec"}}]))
            (run / "application_results").mkdir()
            (run / "application_results/execution_report.json").write_text(json.dumps({
                "per_solution_details": [{
                    **identity, "method_name": "getOrCreateKeyPair", "spec": "KeyPairSpec",
                    "status": "SUCCESS", "joint_finding_count": 1,
                    "joint_findings_without_effect": [
                        {"method": "generateNewKeyPair", "specification": "KeyPairGeneratorSpec",
                         "reason": "the repair kept the same spec."}]}]}))
            records = read_run(run)
        outcome, detail = final_outcome(records[("bluegate.apk", "x.KeyManager",
                                                 "generateNewKeyPair", "KeyPairGeneratorSpec")])
        self.assertEqual(outcome, "violação sem impacto de segurança")
        self.assertIn("sem efeito no patch", detail)


class ProductionEditsOnBaseTests(unittest.TestCase):
    """tokn run_v6 (2026-10-31): the getEntry -> getKey edit was on main through
    our merged tokn#138, the review saw only KeystoreManagerTest.kt and all
    four findings ended as violations without security impact."""

    TEST_PATH = "app/src/test/java/x/KeystoreManagerTest.kt"

    def test_a_review_left_with_tests_only_ends_the_unit_on_the_base(self):
        from unittest.mock import patch

        from cognalys.llm import coordinated_generation
        from cognalys.llm.generate_error_fixes import FixGenerator

        production = {"source_file_path": "app/src/main/java/x/KeystoreManager.kt",
                      "original_code": "getEntry(alias)", "corrected_code": "getKey(alias)"}
        test = {"source_file_path": self.TEST_PATH, "original_code": "",
                "corrected_code": "class KeystoreManagerTest"}
        error = {"joint_findings": [
            {"unique_error_id": "decrypt-cipher", "class": "x.KeystoreManager",
             "method": "decrypt", "specification": "CipherSpec"},
            {"unique_error_id": "getOrCreateKey", "class": "x.KeystoreManager",
             "method": "getOrCreateKey", "specification": "KeyStoreSpec"}],
            "joint_contribution_bases": {
                "decrypt-cipher": {"analyzed_code_present": True},
                "getOrCreateKey": {"analyzed_code_present": False,
                                   "reported_statement_present": False}}}
        generator = object.__new__(FixGenerator)

        class Provider:
            def generate(self, *args, **kwargs):
                raise AssertionError("a test alone is not reviewed")

        generator.provider = Provider()
        with patch.object(coordinated_generation, "edits_already_on_base",
                          return_value={id(production)}):
            review = generator.review_patch_behavior(error, [production, test], {})
        self.assertEqual(review["status"], "all_edits_on_base")
        self.assertEqual(review["unrelated_test_edits"], [self.TEST_PATH])
        self.assertEqual(review["joint_findings_still_on_base"], [
            {"class": "x.KeystoreManager", "method": "decrypt", "specification": "CipherSpec"}])

    def test_a_joint_finding_still_on_the_base_does_not_end_as_changed_upstream(self):
        import json
        import tempfile
        from cognalys.reporting.finding_statistics import final_outcome, read_run

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            methods = run / "error_methods/tokn.apk"
            methods.mkdir(parents=True)
            (methods / "1_encrypt.json").write_text(json.dumps({
                "extraction_metadata": {"apk_name": "tokn.apk", "csv_index": 1},
                "error": {"csv_class": "x.KeystoreManager", "csv_method": "encrypt",
                          "spec": "CipherSpec"}}))
            solutions = run / "error_solutions"
            (solutions / "tokn.apk").mkdir(parents=True)
            (solutions / "tokn.apk/1_encrypt_solution.json").write_text(json.dumps({
                "solution_metadata": {"csv_class": "x.KeystoreManager",
                                      "method_name": "encrypt", "spec": "CipherSpec"}}))
            drafts = solutions / "coordinated_drafts/tokn.apk/1_encrypt"
            drafts.mkdir(parents=True)
            (drafts / "behavior_review.json").write_text(json.dumps({
                "status": "all_edits_on_base", "production_edits_on_base": True,
                "review_contract_version": 14, "joint_findings_still_on_base": [
                    {"class": "x.KeystoreManager", "method": "decrypt",
                     "specification": "CipherSpec"}]}))
            identity = {"apk_name": "tokn.apk", "csv_class": "x.KeystoreManager"}
            into = {**identity, "method_name": "encrypt", "spec": "CipherSpec"}
            (solutions / "joint_findings.json").write_text(json.dumps([
                {"joined": {**identity, "method_name": "decrypt", "spec": "CipherSpec"},
                 "into": into},
                {"joined": {**identity, "method_name": "getOrCreateKey", "spec": "KeyStoreSpec"},
                 "into": into}]))
            (run / "application_results").mkdir()
            (run / "application_results/execution_report.json").write_text(json.dumps({
                "per_solution_details": [{
                    **into, "status": "NOT_APPLICABLE_TO_BASE",
                    "error": "ORIGINAL_CODE_ABSENT_FROM_BASE_BRANCH"}]}))
            records = read_run(run)
        key = ("tokn.apk", "x.KeystoreManager")
        self.assertEqual(final_outcome(records[(*key, "encrypt", "CipherSpec")])[0],
                         "correção não aplicável: código mudou upstream")
        outcome, detail = final_outcome(records[(*key, "decrypt", "CipherSpec")])
        self.assertEqual(outcome, "correção não gerada")
        self.assertIn("analisado junto com encrypt", detail)
        self.assertIn("continua lá", detail)
        # Its statement gone too: it ends with the unit.
        self.assertEqual(final_outcome(records[(*key, "getOrCreateKey", "KeyStoreSpec")])[0],
                         "correção não aplicável: código mudou upstream")


class JointFindingClaimTests(unittest.TestCase):
    """The PR text of BlueGate run_v8 and run_v7 (2026-10-31)."""

    ENTRY = {"method": "generateNewKeyPair", "specification": "KeyPairGeneratorSpec",
             "reason": "the same ECGenParameterSpec reaches initialize"}

    def test_a_named_claim_is_a_problem(self):
        from cognalys.utils.pr_text import joint_finding_claims

        body = ("I now return `KeyStore.PrivateKeyEntry` values directly. This also resolves "
                "the related issue in `generateNewKeyPair` by preparing the EC parameter "
                "specification before generator initialization.\n\nI found this while "
                "running the app under RVSec, a runtime checker.")
        problems = joint_finding_claims(body, [self.ENTRY], 1)
        self.assertEqual(len(problems), 1)
        self.assertIn("`generateNewKeyPair` (KeyPairGeneratorSpec)", problems[0])

    def test_an_unnamed_claim_is_a_problem_only_when_every_joint_finding_is_without_effect(self):
        from cognalys.utils.pr_text import joint_finding_claims

        body = ("I replaced the wrapper with `KeyMaterial`. The same change also resolves the "
                "related rule issue in the key-generation helper.")
        self.assertEqual(len(joint_finding_claims(body, [self.ENTRY], 1)), 1)
        self.assertEqual(joint_finding_claims(body, [self.ENTRY], 2), [])

    def test_naming_the_method_for_the_reported_change_is_not_a_claim(self):
        from cognalys.utils.pr_text import joint_finding_claims

        body = ("`generateNewKeyPair` now returns the stored entry, which resolves the "
                "reported constructor call.")
        self.assertEqual(joint_finding_claims(body, [self.ENTRY], 1), [])
        self.assertEqual(joint_finding_claims(
            "This also resolves the same KeyStoreSpec order issue in `save`.", [], 1), [])

    def test_the_pr_step_rewrites_such_a_text(self):
        from cognalys.prs.pr_generator import PrGenerator

        generator = object.__new__(PrGenerator)
        solution = {"joint_findings_without_effect": [self.ENTRY], "joint_finding_count": 1,
                    "coordinated_edits": [], "error_message": "m"}
        problems = generator.text_problems_of(
            solution, "Return key store entries",
            "This also resolves the related issue in `generateNewKeyPair`.", "")
        self.assertTrue(any("generateNewKeyPair" in item for item in problems))

    def test_in_a_same_method_join_naming_the_method_is_the_reported_change(self):
        # Review of 2026-10-31: KeyPass's decrypt under IvParameterSpec and Cipher.
        from cognalys.utils.pr_text import joint_finding_claims

        entry = [{"method": "decrypt", "specification": "CipherSpec", "reason": "same calls"}]
        body = ("This change fixes `decrypt` so it reads the IV stored with each record instead "
                "of reusing the same IV for every value.")
        self.assertEqual(joint_finding_claims(body, entry, 1, "decrypt"), [])
        self.assertEqual(len(joint_finding_claims(
            body + " It also resolves the related Cipher rule issue.", entry, 1, "decrypt")), 1)

    def test_claims_without_an_also_are_problems(self):
        from cognalys.utils.pr_text import joint_finding_claims

        for body in ("In `generateNewKeyPair`, preparing the EC parameter specification first "
                     "resolves the KeyPairGenerator rule violation reported there.",
                     "I now return entries. This change resolves both violations reported in "
                     "`KeyManager`."):
            with self.subTest(body=body):
                self.assertEqual(len(joint_finding_claims(body, [self.ENTRY], 1,
                                                          "getOrCreateKeyPair")), 1)

    def test_the_repaired_patch_review_reaches_the_text_check(self):
        # Review of 2026-10-31: the verdict was kept only under
        # repair_behavior_review, and the text check read the draft's review.
        from cognalys.prs.pr_generator import PrGenerator
        from cognalys.validation.repair import record_repair_review

        solution = {"apk_name": "a.apk", "csv_class": "X", "method_name": "getOrCreateKeyPair",
                    "spec": "KeyPairSpec", "coordinated_edits": [], "error_message": "m"}
        record_repair_review(solution, {
            "status": "reviewed", "review_contract_version": 13, "regressions": [],
            "joint_findings_without_effect": [{**self.ENTRY, "changed_for_it": "val s = x"}],
            "joint_finding_count": 1}, ["src/Other.kt"])
        generator = object.__new__(PrGenerator)
        without_effect, count = generator.joint_findings_without_effect(solution)
        self.assertEqual([item["method"] for item in without_effect], ["generateNewKeyPair"])
        self.assertEqual(count, 1)

    def test_reviews_of_one_patch_merge_their_verdicts(self):
        from cognalys.utils.pr_text import merged_joint_without_effect

        other = {"method": "save", "specification": "KeyStoreSpec", "reason": "r"}
        self.assertEqual(merged_joint_without_effect([self.ENTRY], [self.ENTRY, other], None),
                         [self.ENTRY, other])


class JointVerdictAcrossAttemptsTests(unittest.TestCase):
    """Review of 2026-10-31 of the per-finding effect verdict (BlueGate run_v8)."""

    def test_a_valid_draft_with_joint_churn_is_kept_when_the_regeneration_regresses(self):
        regression = {**CLEAN_REVIEW, "regressions": [{
            "scenario": "first run", "before": "a", "after": "b",
            "source_file_path": "src/Main.java"}]}
        answers = []

        def review(call):
            answers.append(call)
            return ({**CLEAN_REVIEW, "joint_findings_without_effect": [_LOCAL_ONLY]}
                    if len(answers) == 1 else regression)

        result, _, error, _ = _coordinated_run(
            review, [METHOD_EDIT, OTHER_EDIT], error_extra={"joint_findings": [_JOINT]})
        self.assertEqual(result["status"], "complete")
        self.assertGreater(len(answers), 1)
        facts = error["evidence_analysis"]["behavior_review"]
        self.assertEqual([item["method"] for item in facts["joint_findings_without_effect"]],
                         ["other"])

    def test_a_carried_verdict_never_asks_for_another_regeneration(self):
        from cognalys.llm.coordinated_generation import (
            joint_no_effect_feedback, with_earlier_joint_verdicts)

        carried = with_earlier_joint_verdicts({"status": "reviewed"}, [_LOCAL_ONLY])
        self.assertTrue(carried["joint_findings_without_effect"][0]["carried_from_earlier_review"])
        self.assertEqual(joint_no_effect_feedback(carried, [], {}), [])
        # Not judged: nothing is carried into a review that did not run.
        self.assertEqual(with_earlier_joint_verdicts({"status": "not_run"}, [_LOCAL_ONLY]),
                         {"status": "not_run"})


_SAME_METHOD_JOINT = {"method": "method", "specification": "KeyStoreSpec", "class": "X",
                      "error_message": "the observed call sequence is not one KeyStoreSpec accepts",
                      "unique_error_id": "X:::method:::KeyStoreSpec"}
_REPORTED_UNTOUCHED = {"method": "method", "specification": "KeyPairSpec", "changed_for_it": "",
                       "reason": "the same generator output reaches the KeyPair."}
_ATTRIBUTION = {
    "reported_finding": {"csv_class": "X", "method_name": "method", "spec": "KeyPairSpec",
                         "error_message": "no construction of the key pair was observed",
                         "unique_error_id": "X:::method:::KeyPairSpec",
                         "reason": "the same generator output reaches the KeyPair."},
    "attributed_to": [{"csv_class": "X", "method_name": "method", "spec": "KeyStoreSpec",
                       "error_message": "the observed call sequence is not one KeyStoreSpec accepts",
                       "unique_error_id": "X:::method:::KeyStoreSpec"}]}


class ReportedFindingEffectTests(unittest.TestCase):
    """The reported finding of a joined unit judged like its joint findings
    (REVIEW_CONTRACT_VERSION 14, LocalSend run_v4)."""

    ERROR = {"method_name": "method", "spec": "KeyPairSpec", "csv_class": "X",
             "error_message": "no construction of the key pair was observed",
             "unique_error_id": "X:::method:::KeyPairSpec",
             "joint_findings": [_SAME_METHOD_JOINT]}

    def test_the_review_attributes_the_patch_to_the_finding_it_affects(self):
        result, _, error, review_file = _coordinated_run(
            lambda call: {**CLEAN_REVIEW, "findings_without_effect": [_REPORTED_UNTOUCHED]},
            [METHOD_EDIT], error_extra={key: value for key, value in self.ERROR.items()
                                        if key != "method_name"})
        self.assertEqual(result["status"], "complete")
        self.assertEqual(review_file["reported_finding_without_effect"]["specification"],
                         "KeyPairSpec")
        self.assertEqual(review_file["joint_findings_without_effect"], [])
        facts = error["evidence_analysis"]["behavior_review"]
        self.assertEqual(facts["pr_attribution"]["attributed_to"][0]["spec"], "KeyStoreSpec")
        self.assertEqual(facts["pr_attribution"]["reported_finding"]["spec"], "KeyPairSpec")
        self.assertFalse(result["behavior_review_summary"]["patch_has_no_effect"])

    def test_the_reported_entry_is_matched_only_without_ambiguity(self):
        from cognalys.llm.coordinated_generation import reported_finding_without_effect

        self.assertEqual(reported_finding_without_effect(self.ERROR, [_REPORTED_UNTOUCHED])[
            "specification"], "KeyPairSpec")
        # Alone, patch_has_no_effect is the verdict; a joint entry, no reason,
        # or no specification in a same-method join is no answer.
        for error, named in (
                ({**self.ERROR, "joint_findings": []}, [_REPORTED_UNTOUCHED]),
                (self.ERROR, [{**_REPORTED_UNTOUCHED, "specification": "KeyStoreSpec"}]),
                (self.ERROR, [{**_REPORTED_UNTOUCHED, "reason": " "}]),
                (self.ERROR, [{**_REPORTED_UNTOUCHED, "specification": ""}])):
            with self.subTest(named=named):
                self.assertEqual(reported_finding_without_effect(error, named), {})

    def test_no_attribution_without_a_joint_finding_the_patch_affects(self):
        from cognalys.llm.coordinated_generation import pr_attribution

        review = {"status": "reviewed", "reported_finding_without_effect": _REPORTED_UNTOUCHED,
                  "joint_findings_without_effect": []}
        self.assertTrue(pr_attribution(self.ERROR, review))
        self.assertEqual(pr_attribution(self.ERROR, {**review, "joint_findings_without_effect": [
            {"method": "method", "specification": "KeyStoreSpec", "reason": "r"}]}), {})
        self.assertEqual(pr_attribution(self.ERROR, {**review, "patch_has_no_effect": True}), {})
        self.assertEqual(pr_attribution(self.ERROR, {**review, "status": "not_run"}), {})

    def test_the_reported_verdict_is_carried_across_regenerations(self):
        from cognalys.llm.coordinated_generation import (
            joint_no_effect_feedback, unit_verdicts_without_effect, with_earlier_joint_verdicts)

        churn = {**_REPORTED_UNTOUCHED, "changed_for_it": "val pair = generator.generateKeyPair()"}
        feedback = joint_no_effect_feedback(
            {"reported_finding_without_effect": churn}, [], {})
        self.assertIn("The change made for the reported finding in method [KeyPairSpec]",
                      feedback[0]["message"])
        self.assertIn("keep every change the joint findings need", feedback[0]["message"])
        carried = with_earlier_joint_verdicts(
            {"status": "reviewed"}, unit_verdicts_without_effect(
                {"reported_finding_without_effect": churn}))
        self.assertTrue(carried["reported_finding_without_effect"]["carried_from_earlier_review"])
        self.assertEqual(carried["reported_finding_without_effect"]["changed_for_it"], "")
        self.assertEqual(joint_no_effect_feedback(carried, [], {}), [])

    def test_the_pull_request_names_the_attributed_finding(self):
        from cognalys.utils.pr_text import analysed_identity, attributed_view

        row = {"apk_name": "a.apk", "csv_class": "X", "method_name": "method",
               "spec": "KeyPairSpec", "error_message": "no construction of the key pair was observed",
               "unique_error_id": "X:::method:::KeyPairSpec", "finding_id": "97b5f3b80d25"}
        view = attributed_view(row, _ATTRIBUTION)
        self.assertEqual((view["spec"], view["error_message"]),
                         ("KeyStoreSpec", "the observed call sequence is not one KeyStoreSpec accepts"))
        self.assertEqual(view["finding_id"], "97b5f3b80d25")
        self.assertEqual(analysed_identity(view)["spec"], "KeyPairSpec")
        self.assertEqual(view["joint_findings_without_effect"][0]["specification"], "KeyPairSpec")
        self.assertEqual(view["joint_findings"][0]["specification"], "KeyPairSpec")
        # Already a view, another finding, or no attribution: unchanged.
        self.assertIs(attributed_view(view, _ATTRIBUTION), view)
        self.assertIs(attributed_view({**row, "spec": "CipherSpec"}, _ATTRIBUTION).get("spec"),
                      "CipherSpec")
        self.assertIs(attributed_view(row, {}), row)

    def test_the_branch_is_named_after_the_attributed_finding(self):
        from cognalys.solutions.worktree_manager import WorktreeManager

        solution = {"apk_name": "a.apk", "csv_class": "X", "method_name": "method",
                    "spec": "KeyPairSpec", "unique_error_id": "X:::method:::KeyPairSpec"}
        self.assertEqual(WorktreeManager.branch_method_and_spec(
            {**solution, "pr_attribution": _ATTRIBUTION}), ("method", "keystorespec"))
        self.assertEqual(WorktreeManager.branch_method_and_spec(solution),
                         ("method", "keypairspec"))
        # The finding id stays the analysed finding's.
        self.assertEqual(WorktreeManager.finding_id({**solution, "pr_attribution": _ATTRIBUTION}),
                         WorktreeManager.finding_id(solution))

    def test_the_summary_is_about_the_attributed_finding(self):
        from cognalys.llm.generate_error_fixes import FixGenerator
        import json
        import logging

        prompts = []

        class Provider:
            def generate(self, prompt, *args, **kwargs):
                prompts.append(prompt)
                return json.dumps({"title": "Store the key entry with setEntry", "summary": "s"})

        generator = object.__new__(FixGenerator)
        generator.logger = logging.getLogger("reported-summary")
        generator.provider = Provider()
        error = {**self.ERROR, "evidence_analysis": {
            "confirmed_cause": "no KeyPairGenerator call was observed",
            "behavior_review": {"pr_attribution": _ATTRIBUTION}}}
        generator.compose_maintainer_summary(error, [], [], [])
        self.assertIn('"analyzer_rule_id_never_written":"KeyStoreSpec"', prompts[0])
        self.assertIn('"also_resolves":[]', prompts[0])
        self.assertNotIn("no KeyPairGenerator call was observed", prompts[0])

    def test_the_title_names_what_the_code_does_not_identifier_words(self):
        """Your Local Weather (2026-11-02): "Use PBKDF2WithHmacSHA256 for
        weather token keys", from a preference key's name, for code that
        hashes the licence key."""
        from cognalys.llm.generate_error_fixes import FixGenerator
        import json
        import logging

        systems, contexts = [], []

        class Provider:
            def generate(self, prompt, system, *args, **kwargs):
                systems.append(system)
                contexts.append(kwargs.get("trace_context") or {})
                return json.dumps({"title": "Hash the licence key with PBKDF2WithHmacSHA256",
                                   "summary": "s"})

        generator = object.__new__(FixGenerator)
        generator.logger = logging.getLogger("title-summary")
        generator.provider = Provider()
        generator.compose_maintainer_summary({**self.ERROR, "evidence_analysis": {}}, [], [], [])
        system = " ".join(systems[0].split())
        self.assertIn("Name what the code does with the value", system)
        self.assertIn("not the words of a method, field or preference-key name", system)
        self.assertEqual(contexts[0]["prompt_version"], "pr-maintainer-summary-v9")

    def test_the_text_check_flags_a_claim_on_the_analysed_finding(self):
        from cognalys.prs.pr_generator import PrGenerator
        from cognalys.utils.pr_text import attributed_view

        generator = object.__new__(PrGenerator)
        row = {"apk_name": "a.apk", "csv_class": "X", "method_name": "method",
               "spec": "KeyPairSpec", "error_message": "m", "coordinated_edits": []}
        view = attributed_view(row, _ATTRIBUTION)
        for body in ("I now store the entry with setEntry. This same change also resolves the "
                     "reported KeyPairSpec violation.",
                     "I now store the entry with setEntry. It also fixes the related key pair "
                     "issue."):
            with self.subTest(body=body):
                self.assertTrue(generator.text_problems_of(view, "Store the key entry", body, ""))
        self.assertFalse([problem for problem in generator.text_problems_of(
            view, "Store the key entry", "I now store the entry with setEntry, which resolves "
            "the reported KeyStoreSpec violation. The KeyPairSpec report is not resolved by it.",
            "") if ("KeyPairSpec" in problem or "another issue" in problem)
            and "internal rule id" not in problem])

    def test_the_statistics_close_the_analysed_finding_and_keep_the_draft(self):
        import json
        import tempfile
        from cognalys.reporting.finding_statistics import final_outcome, read_run

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            methods = run / "error_methods/l.apk"
            methods.mkdir(parents=True)
            (methods / "0_method.json").write_text(json.dumps({
                "extraction_metadata": {"apk_name": "l.apk", "csv_index": 0},
                "error": {"csv_class": "X", "csv_method": "method", "spec": "KeyPairSpec"}}))
            solutions = run / "error_solutions"
            (solutions / "l.apk").mkdir(parents=True)
            (solutions / "l.apk/0_method_solution.json").write_text(json.dumps({
                "solution_metadata": {"csv_class": "X", "method_name": "method",
                                      "spec": "KeyPairSpec"},
                "evidence_analysis": {"behavior_review": {
                    "review_contract_version": 14, "joint_finding_count": 1,
                    "reported_finding_without_effect": {
                        "method": "method", "specification": "KeyPairSpec", "reason": "r"},
                    "pr_attribution": _ATTRIBUTION}}}))
            identity = {"apk_name": "l.apk", "csv_class": "X", "method_name": "method"}
            (solutions / "joint_findings.json").write_text(json.dumps([{
                "joined": {**identity, "spec": "KeyStoreSpec"},
                "into": {**identity, "spec": "KeyPairSpec"}}]))
            (run / "pull_requests").mkdir()
            (run / "pull_requests/l.apk_method_KeyPairSpec_pr.json").write_text(json.dumps({
                "csv_class": "X", "method_name": "method", "spec": "KeyStoreSpec",
                "analysed_finding": {"csv_class": "X", "method_name": "method",
                                     "spec": "KeyPairSpec"},
                "title": "Store the key entry with setEntry", "commit_hash": "abc"}))
            records = read_run(run)
        reported = records[("l.apk", "X", "method", "KeyPairSpec")]
        attributed = records[("l.apk", "X", "method", "KeyStoreSpec")]
        self.assertEqual(final_outcome(reported),
                         ("violação sem impacto de segurança",
                          "analisado junto com method, sem efeito no patch; the same generator "
                          "output reaches the KeyPair."))
        self.assertTrue(attributed.get("pr"))
        self.assertNotIn("reported_without_effect", attributed)
        self.assertIn("PR atribuído a este achado; method [KeyPairSpec] ficou sem efeito",
                      final_outcome(attributed)[1])

    def test_every_finding_without_effect_is_a_patch_without_effect(self):
        # Review of batch 13 (2026-10-31): with the reported and every joint
        # finding listed without effect but patch_has_no_effect false, the
        # patch was "PR pronto" for the reported finding.
        both = [_REPORTED_UNTOUCHED, {"method": "method", "specification": "KeyStoreSpec",
                                      "changed_for_it": "", "reason": "the same setKeyEntry"}]
        result, _, _, review_file = _coordinated_run(
            lambda call: {**CLEAN_REVIEW, "findings_without_effect": both},
            [METHOD_EDIT], error_extra={key: value for key, value in self.ERROR.items()
                                        if key != "method_name"})
        self.assertEqual(result["stage"], "behavior_review")
        self.assertIn("PATCH_HAS_NO_EFFECT", result["issues"][0])
        self.assertTrue(result["correct_use"])
        self.assertTrue(review_file["patch_has_no_effect"])
        self.assertNotIn("pr_attribution", review_file)

    def test_a_carried_verdict_completes_the_unit_without_effect(self):
        from cognalys.llm.coordinated_generation import (
            unit_verdicts_without_effect, with_unit_without_effect)

        earlier = unit_verdicts_without_effect({"reported_finding_without_effect": {
            **_REPORTED_UNTOUCHED, "changed_for_it": "val pair = generator.generateKeyPair()"}})
        joint_only = {"status": "reviewed", "joint_finding_count": 1,
                      "joint_findings_without_effect": [
                          {"method": "method", "specification": "KeyStoreSpec", "reason": "r"}]}
        judged = with_unit_without_effect(joint_only, earlier)
        self.assertTrue(judged["patch_has_no_effect"])
        self.assertIn("method [KeyPairSpec]", judged["no_effect_reason"])
        # A finding with effect, an explicit default, or nothing carried: as before.
        self.assertIs(with_unit_without_effect(joint_only, []), joint_only)
        explicit = {**joint_only, "explicit_default_only": True}
        self.assertIs(with_unit_without_effect(explicit, earlier), explicit)
        two_joint = {**joint_only, "joint_finding_count": 2}
        self.assertIs(with_unit_without_effect(two_joint, earlier), two_joint)

    def test_a_spec_claim_is_negated_only_in_its_own_clause(self):
        from cognalys.utils.pr_text import joint_finding_claims

        # Review of batch 13 (2026-10-31): a "still", "without" or "remains"
        # anywhere in the sentence hid the claim.
        without = [{"method": "m", "specification": "KeyPairSpec", "reason": "r"}]
        for sentence in (
                "This change also fixes the KeyPairSpec violation without changing how keys "
                "are stored.",
                "It resolves the KeyPairSpec report, and keys written by earlier versions still "
                "load.",
                "The KeyPairSpec rule is now satisfied because the entry no longer uses "
                "setKeyEntry.",
                "This addresses KeyPairSpec, which remains compatible with existing keystores.",
                "This change fixes the KeyPairSpec report, so existing keys still load."):
            with self.subTest(sentence=sentence):
                self.assertTrue(joint_finding_claims(sentence, without, 2, "m", "KeyStoreSpec"))
        for sentence in (
                "The reported KeyPairSpec observation remains unresolved.",
                "It fixes the KeyStoreSpec call, but the KeyPairSpec report is not resolved.",
                "This does not resolve the KeyPairSpec report.",
                "KeyPairSpec still reports the generator, which this change fixes elsewhere.",
                "It leaves KeyPairSpec without a fix."):
            with self.subTest(sentence=sentence):
                self.assertFalse(joint_finding_claims(sentence, without, 2, "m", "KeyStoreSpec"))

    def test_a_repaired_patch_without_effect_for_every_finding_is_not_published(self):
        from cognalys.validation.repair import record_repair_review

        solution = {"pr_attribution": _ATTRIBUTION, "joint_finding_count": 1}
        record_repair_review(solution, {
            "status": "reviewed", "review_contract_version": 14, "joint_finding_count": 1,
            "joint_findings_without_effect": [
                {"method": "method", "specification": "KeyStoreSpec", "reason": "r"}]},
            ["src/Other.kt"])
        self.assertTrue(solution["publication_blocker_record"]["behavior_review"][
            "patch_has_no_effect"])
        self.assertTrue(any("no effect" in item
                            for item in solution["repair_review_notes"]["review_blockers"]))
        # A joint finding the repaired patch still affects: the PR stands.
        solution = {"pr_attribution": _ATTRIBUTION, "joint_finding_count": 1}
        record_repair_review(solution, {"status": "reviewed", "review_contract_version": 14,
                                        "joint_finding_count": 1}, ["src/Other.kt"])
        self.assertFalse(solution["publication_blocker_record"]["behavior_review"][
            "patch_has_no_effect"])

    def test_an_attribution_found_at_repair_renames_the_branch(self):
        import subprocess
        import tempfile
        from cognalys.validation.repair import rename_branch_for_attribution

        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.run(["git", "-C", directory, *args], capture_output=True,
                                      text=True, check=True).stdout.strip()

            git("init", "-q")
            git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                "--allow-empty", "-m", "base")
            git("checkout", "-q", "-b", "fix/method-keypairspec-97b5f3b80d25-ab12")
            solution = {"method_name": "method", "spec": "KeyPairSpec", "csv_class": "X",
                        "branch": "fix/method-keypairspec-97b5f3b80d25-ab12",
                        "pr_attribution": _ATTRIBUTION}
            renamed = rename_branch_for_attribution(solution, Path(directory))
            current = git("branch", "--show-current")
        self.assertEqual(renamed, "fix/method-keystorespec-97b5f3b80d25-ab12")
        self.assertEqual(current, renamed)
        self.assertEqual(solution["branch"], renamed)
        # No attribution, or a branch it cannot rename: kept.
        self.assertEqual(rename_branch_for_attribution(
            {**solution, "pr_attribution": {}, "branch": "fix/x"}, Path(".")), "fix/x")


class JoinedFindingLabelTests(unittest.TestCase):
    """2026-10-31: 48 rows under outputs/ said "resolvido junto com" beside an
    ending without a patch (sem impacto, issue, evidência insuficiente, não
    analisado, falso positivo)."""

    def test_resolved_with_only_when_the_unit_ended_with_its_patch(self):
        from cognalys.reporting.finding_statistics import final_outcome

        ready = {"pr_ready": True, "joined_into": "load"}
        self.assertTrue(final_outcome(ready)[1].startswith("resolvido junto com load"))
        for record in ({"issue": True}, {"no_security_impact": "documented use"},
                       {"analysed": True, "detector_violation": "not_confirmed"}, {}):
            with self.subTest(record=record):
                detail = final_outcome({**record, "joined_into": "load"})[1]
                self.assertTrue(detail.startswith("analisado junto com load"), detail)
                self.assertNotIn("resolvido", detail)

    def test_resolved_only_when_the_patch_applied_and_built(self):
        # Review of batch 13 (2026-10-31): six rows read "correção gerada, sem
        # PR, resolvido junto com X" beside "build: failed (generated_patch)".
        from cognalys.reporting.finding_statistics import final_outcome

        failed = {"solution": True, "apply_status": "SUCCESS", "build_status": "failed",
                  "build_attribution": "generated_patch", "joined_into": "load"}
        outcome, detail = final_outcome(failed)
        self.assertEqual(outcome, "correção gerada, sem PR")
        self.assertTrue(detail.startswith("analisado junto com load"), detail)
        held = {"solution": True, "apply_status": "SUCCESS", "build_status": "success",
                "pr_held": "text", "joined_into": "load"}
        self.assertTrue(final_outcome(held)[1].startswith("resolvido junto com load"))

    def test_the_finding_a_pull_request_is_attributed_to_says_so(self):
        from cognalys.reporting.finding_statistics import final_outcome

        detail = final_outcome({"pr_ready": True, "joined_into": "load",
                                "attributed_here": True})[1]
        self.assertTrue(detail.startswith("PR atribuído a este achado; load ficou sem efeito"))
        self.assertNotIn("resolvido", detail)
        # A same-method join names the method twice: the specification tells them apart.
        detail = final_outcome({"pr_ready": True, "joined_into": "load",
                                "attributed_here": "KeyPairSpec"})[1]
        self.assertTrue(detail.startswith(
            "PR atribuído a este achado; load [KeyPairSpec] ficou sem efeito no patch"))

    def test_a_unit_without_effect_closes_its_joint_findings_without_effect(self):
        import json
        import logging
        import tempfile
        from cognalys.llm.generate_error_fixes import FixGenerator
        from cognalys.reporting.finding_statistics import final_outcome, read_run

        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            methods = run / "error_methods/t.apk"
            methods.mkdir(parents=True)
            (methods / "0_encrypt.json").write_text(json.dumps({
                "extraction_metadata": {"apk_name": "t.apk", "csv_index": 0},
                "error": {"csv_class": "K", "csv_method": "encrypt", "spec": "CipherSpec"}}))
            generator = object.__new__(FixGenerator)
            generator.output_dir = run / "error_solutions"
            generator.logger = logging.getLogger("joint-label")
            error = {"csv_class": "K", "spec": "CipherSpec", "error_index": 0,
                     "joint_findings": [{"method": "decrypt", "specification": "CipherSpec"}]}
            generator.record_no_security_impact(error, "t.apk", "encrypt", "same calls", [
                {"method": "decrypt", "specification": "CipherSpec", "reason": "same calls"}])
            identity = {"apk_name": "t.apk", "csv_class": "K", "spec": "CipherSpec"}
            (run / "error_solutions/joint_findings.json").write_text(json.dumps([{
                "joined": {**identity, "method_name": "decrypt"},
                "into": {**identity, "method_name": "encrypt"}}]))
            records = read_run(run)
        outcome, detail = final_outcome(records[("t.apk", "K", "decrypt", "CipherSpec")])
        self.assertEqual(outcome, "violação sem impacto de segurança")
        self.assertTrue(detail.startswith("analisado junto com encrypt, sem efeito no patch"))

    def test_the_no_effect_result_lists_every_joint_finding(self):
        no_effect = {**CLEAN_REVIEW, "patch_has_no_effect": True,
                     "no_effect_reason": "the same Cipher calls"}
        result, _, _, _ = _coordinated_run(
            lambda call: no_effect, [METHOD_EDIT],
            error_extra={"joint_findings": [_JOINT],
                         "evidence_analysis": {
                             "confirmed_cause": "cause",
                             "v2": {"adjudication": {"single_round": True}},
                             "coordinated_fix_plan": {"required_edits": [
                                 {"source_file_path": "src/Main.java", "symbol": "method"}]}}})
        self.assertEqual(result["joint_findings_without_effect"],
                         [{"method": "other", "specification": "KeyPairGeneratorSpec",
                           "reason": "the same Cipher calls"}])

class StrictSchemaNotPastedTests(unittest.TestCase):
    """The draft schema goes as text only to a provider without strict mode.

    OpenAI enforces the json_schema sent as a strict text.format, and every
    recorded draft prompt carried the same schema again as text (2,170 of
    2,170, 7% of their characters).
    """

    def test_a_strict_provider_gets_the_schema_only_as_the_format(self):
        _, provider, _, _ = _coordinated_run(
            lambda call: CLEAN_REVIEW, [METHOD_EDIT],
            provider_attributes={"enforces_json_schema": True})
        self.assertNotIn("REQUIRED JSON SCHEMA", provider.draft_prompts[0])
        self.assertEqual(provider.draft_schemas[0]["type"], "object")

    def test_a_provider_without_strict_mode_still_reads_it(self):
        import json

        _, provider, _, _ = _coordinated_run(lambda call: CLEAN_REVIEW, [METHOD_EDIT])
        text = provider.draft_prompts[0].split("\n\nREQUIRED JSON SCHEMA:\n", 1)[1]
        self.assertEqual(json.loads(text), provider.draft_schemas[0])

    def test_only_the_openai_provider_claims_strict_mode(self):
        from cognalys.llm import llm_providers

        self.assertIs(llm_providers.OpenAIProvider.enforces_json_schema, True)
        self.assertIs(llm_providers.AnthropicProvider.enforces_json_schema, False)
        self.assertFalse(hasattr(llm_providers.OllamaProvider, "enforces_json_schema"))



if __name__ == "__main__":
    unittest.main()
