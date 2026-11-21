"""The questions the adjudicator kept asking, answered from the checkout.

Adjudication is the largest stage in the failure ledger -- 29 occurrences
over 23 signatures -- and nearly all of them are one shape: the model asked
for a fact, the evidence responder could only answer with a repository file,
and the request was declined. The cause was then recorded as unconfirmed.

Each test here covers one of those questions, and for each one there is a
matching test that it refuses rather than guesses when the checkout does not
settle it. That pair is the point: an answer that cannot be wrong because it
is never withheld would be worth nothing to an adjudicator.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm import evidence_requests  # noqa: E402
from cognalys.llm.evidence_requests import (  # noqa: E402
    classify_evidence_request, resolve_evidence_requests,
)
from cognalys.extraction.evidence_facts import (  # noqa: E402
    artifact_ownership, caller_contract, specification_applicability,
)


class RequestRoutingTests(unittest.TestCase):

    def test_each_question_reaches_its_own_family(self):
        cases = {
            "ownership_and_version": evidence_requests.ARTIFACT_OWNERSHIP,
            "reported_rule_applicability": evidence_requests.RULE_APPLICABILITY,
            "reachable_caller_contract": evidence_requests.CALLER_CONTRACT,
            "symbol_resolution": evidence_requests.SYMBOL_BINDING,
        }
        for kind, family in cases.items():
            self.assertEqual(
                classify_evidence_request({"kind": kind, "symbol": "X"}),
                family, f"{kind} was routed to the wrong family",
            )

    def test_the_wordings_seen_in_real_runs_reach_their_family(self):
        # run_20260920_175850 asked `semantic_callee_resolution` and
        # `whole_application_call_inventory`; both were declined as "no
        # matching file in the repository".
        self.assertEqual(
            classify_evidence_request({"kind": "semantic_callee_resolution"}),
            evidence_requests.SYMBOL_BINDING,
        )
        self.assertEqual(
            classify_evidence_request(
                {"kind": "whole_application_call_inventory"}
            ),
            evidence_requests.CALLER_CONTRACT,
        )

    def test_a_runtime_question_is_still_runtime(self):
        self.assertEqual(
            classify_evidence_request({
                "kind": "runtime_caller_trace", "symbol": "x"}),
            evidence_requests.RUNTIME_ONLY,
        )

    def test_provenance_and_trace_no_longer_hide_a_caller_question(self):
        # rvsec_misuse2 2__init__ and rvsec_misuse5 8_newSslSocketFactory were
        # declined as "requires observing a running program".
        for kind, symbol in (
            ("callers_or_byte_provenance",
             "PrfAesCmac.<init>(byte[]) callers and byte[] producers"),
            ("call_site_or_provenance_trace", "callers of Platform.newSslSocketFactory"),
        ):
            self.assertEqual(
                classify_evidence_request({"kind": kind, "symbol": symbol}),
                evidence_requests.CALLER_CONTRACT, kind,
            )
        self.assertEqual(
            classify_evidence_request({"kind": "dependency_provenance",
                                       "symbol": "owning artifact"}),
            evidence_requests.ARTIFACT_OWNERSHIP,
        )

    def test_a_producer_question_is_a_caller_question_only_for_code_the_checkout_has(self):
        # "installed_crysl_rules_and_predicate_producers" asks what the
        # specification defines; a caller list labelled as satisfying it
        # read as the answer.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            (root / "app/SecretService.kt").write_text(
                "package app\nclass SecretService {\n"
                "    fun encrypt(key: Key, data: ByteArray): ByteArray = data\n}\n",
                encoding="utf-8")
            index = evidence_requests.RepositoryIndex(root)
            named = {"kind": "CrySL_predicate_producer_artifact",
                     "symbol": "key producer of SecretService.encrypt"}
            self.assertEqual(classify_evidence_request(named, index),
                             evidence_requests.CALLER_CONTRACT)
            # Without the checkout nothing says the name is code.
            self.assertNotEqual(classify_evidence_request(named),
                                evidence_requests.CALLER_CONTRACT)
            for request in (
                {"kind": "installed_crysl_rules_and_predicate_producers",
                 "symbol": "generatedKey[key, algorithm] producers"},
                {"kind": "crysl_predicate_producer_contract", "symbol": "randomized"},
            ):
                self.assertNotEqual(classify_evidence_request(request, index),
                                    evidence_requests.CALLER_CONTRACT, request["kind"])

    def test_the_word_resource_does_not_hide_a_caller_question(self):
        for request in (
            {"kind": "caller_contract", "symbol": "callers of Enc.close releasing resources"},
            {"kind": "resource_cleanup_callers", "symbol": "CipherOutputStream"},
        ):
            self.assertEqual(classify_evidence_request(request),
                             evidence_requests.CALLER_CONTRACT, request["kind"])
        # A resource reference is still a resource, and so is the bare word
        # when nothing else matches.
        self.assertEqual(
            classify_evidence_request({"kind": "caller_contract",
                                       "symbol": "R.string.default_rsa_len"}),
            evidence_requests.ANDROID_RESOURCE)
        self.assertEqual(classify_evidence_request({"kind": "resource", "symbol": "key size"}),
                         evidence_requests.ANDROID_RESOURCE)

    def test_a_question_only_a_running_program_answers_stays_runtime(self):
        for request in (
            {"kind": "negotiated_protocol", "symbol": "protocol on the running session"},
            {"kind": "iv_provenance", "symbol": "IV bytes"},
            {"kind": "observed_value", "symbol": "key size"},
            {"kind": "callers_seen_by_the_detector", "symbol": "x"},
        ):
            self.assertEqual(classify_evidence_request(request),
                             evidence_requests.RUNTIME_ONLY, request["kind"])

    def test_a_request_naming_a_file_is_answered_with_that_file(self):
        # `callsite_lifecycle_context` reads as a caller-contract question
        # and is not one: it names extensions/Context.kt and wants its body.
        self.assertEqual(
            classify_evidence_request({
                "kind": "callsite_lifecycle_context",
                "symbol": "app/src/main/kotlin/org/example/extensions/"
                          "Context.kt GetMediaAsynctask call site",
                "reason": "Its exact source body is not included.",
            }),
            evidence_requests.REPOSITORY_SOURCE,
        )

    def test_a_dependency_graph_request_is_still_build_configuration(self):
        self.assertEqual(
            classify_evidence_request({
                "kind": "resolved_dependency_graph_or_lockfile",
                "symbol": "OkHttp version"}),
            evidence_requests.BUILD_CONFIGURATION,
        )


class GovernedCallBindingTests(unittest.TestCase):
    """The specification's own governed calls, bound from the file."""

    SPEC = {
        "events": [{
            "name": "enable_web_contents_debugging",
            "api_patterns": ["WebView.setWebContentsDebuggingEnabled(true)"],
            "condition": "Observed when local analysis resolves a static call "
                         "to android.webkit.WebView.setWebContentsDebugging"
                         "Enabled(boolean).",
        }],
    }

    def _file(self, directory: str, body: str) -> tuple:
        root = Path(directory)
        relative = "app/src/main/java/app/MainActivity.kt"
        path = root / relative
        path.parent.mkdir(parents=True)
        path.write_text(body, encoding="utf-8")
        return root, relative

    def test_a_governed_call_binding_to_the_named_type_is_settled(self):
        from cognalys.extraction.evidence_facts import governed_call_bindings

        with tempfile.TemporaryDirectory() as directory:
            root, relative = self._file(directory, (
                "package app\nimport android.webkit.*\nimport androidx.work.*\n"
                "class MainActivity { fun setupWebView() { "
                "WebView.setWebContentsDebuggingEnabled(true) } }\n"
            ))
            record = governed_call_bindings(root, relative, self.SPEC)
        self.assertEqual(record["status"], "resolved_to_governed_type")
        self.assertEqual(record["bindings"][0]["qualified_type"],
                         "android.webkit.WebView")

    def test_a_project_type_of_the_same_name_is_resolved_elsewhere(self):
        from cognalys.extraction.evidence_facts import governed_call_bindings

        with tempfile.TemporaryDirectory() as directory:
            root, relative = self._file(directory, (
                "package app\nclass MainActivity { fun setupWebView() { "
                "WebView.setWebContentsDebuggingEnabled(true) } }\n"
            ))
            own = root / "app/src/main/java/app/WebView.kt"
            own.write_text("package app\nobject WebView { "
                           "fun setWebContentsDebuggingEnabled(b: Boolean) {} }",
                           encoding="utf-8")
            record = governed_call_bindings(root, relative, self.SPEC)
        self.assertEqual(record["status"], "resolved_elsewhere")

    def test_a_governed_constructor_binds_to_the_type_the_specification_governs(self):
        # Review of 2026-10-31: once a receiverless constructor bound from its
        # import, SecretKeySpec(key, "AES") was compared only with the types
        # the condition text spells (java.lang.String) and read as "binds to a
        # type the specification does not name; the rule may not apply to it".
        # 81 stored packets would have moved from unresolved to that.
        from cognalys.extraction.evidence_facts import governed_call_bindings

        spec = {"applies_to_types": ["javax.crypto.spec.SecretKeySpec"],
                "events": [{"name": "c", "api_patterns": ["SecretKeySpec("],
                            "condition": "the key is not a java.lang.String"}]}
        with tempfile.TemporaryDirectory() as directory:
            root, relative = self._file(directory, (
                "package app\nimport javax.crypto.spec.SecretKeySpec\n"
                "class MainActivity { fun key(k: ByteArray) = SecretKeySpec(k, \"AES\") }\n"))
            record = governed_call_bindings(root, relative, spec)
        self.assertEqual(record["status"], "resolved_to_governed_type")
        self.assertEqual(record["expected_types"],
                         ["java.lang.String", "javax.crypto.spec.SecretKeySpec"])
        self.assertEqual(record["bindings"][0]["receiver_kind"], "constructor")

    def test_a_file_without_the_governed_call_says_so(self):
        from cognalys.extraction.evidence_facts import governed_call_bindings

        with tempfile.TemporaryDirectory() as directory:
            root, relative = self._file(directory, "class MainActivity {}")
            record = governed_call_bindings(root, relative, self.SPEC)
        self.assertEqual(record["status"], "no_governed_call")


class OwnershipTests(unittest.TestCase):

    def _module(self, directory: str, *, declare: str = "") -> Path:
        root = Path(directory)
        (root / "app").mkdir(parents=True)
        (root / "app" / "build.gradle").write_text(
            "dependencies {\n" + (f'    implementation "{declare}:1.2.3"\n'
                                  if declare else "") + "}\n",
            encoding="utf-8",
        )
        return root

    def test_a_class_the_checkout_declares_has_no_owning_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._module(directory)
            source = root / "app/src/main/java/app/Helper.java"
            source.parent.mkdir(parents=True)
            source.write_text("class Helper {}", encoding="utf-8")
            record = artifact_ownership(root, "app.Helper", "app/src/main/java/app/Helper.java")
        self.assertEqual(record["status"], "repository_class")
        self.assertEqual(record["artifact"], "")

    def test_a_declared_dependency_that_ships_the_class_is_named_with_its_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._module(directory, declare="com.squareup.okhttp3:okhttp")
            record = artifact_ownership(
                root, "okhttp3.OkHttpClient", "app/src/main/java/app/A.java"
            )
        self.assertEqual(record["status"], "declared_dependency")
        self.assertEqual(record["artifact"], "com.squareup.okhttp3:okhttp")
        self.assertEqual(record["declared_version"], "1.2.3")

    def test_a_class_nothing_declares_is_reported_as_undeclared(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._module(directory, declare="androidx.core:core-ktx")
            record = artifact_ownership(
                root, "com.unknown.vendor.Thing", "app/src/main/java/app/A.java"
            )
        self.assertEqual(record["status"], "undeclared_external")

    def test_without_build_files_ownership_is_unresolved_not_guessed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = artifact_ownership(root, "com.x.Y", "src/A.java")
        self.assertEqual(record["status"], "unresolved")


class ApplicabilityTests(unittest.TestCase):

    SPEC = {
        "spec_id": "WebViewDebuggingSpec",
        "source_verified": False,
        "source_title": "Attempted canonical source (404)",
        "applies_to_types": ["android.webkit.WebViewDebugging"],
        "events": [{
            "name": "enable_web_contents_debugging",
            "api_patterns": ["WebView.setWebContentsDebuggingEnabled(true)"],
            "condition": "Observed when local analysis resolves a static "
                         "call ... Observing this call does not establish "
                         "reachability.",
        }],
    }

    def test_a_governed_api_in_the_source_is_matched_and_quoted(self):
        record = specification_applicability(
            self.SPEC, "WebView.setWebContentsDebuggingEnabled(true)"
        )
        self.assertEqual(record["status"], "governed_api_matched")
        matched = record["matched"][0]
        self.assertEqual(matched["matched_call"], "setWebContentsDebuggingEnabled")
        # The specification's own limitation travels with the match.
        self.assertIn("does not establish", matched["condition"])
        self.assertFalse(record["authority"]["source_verified"])

    def test_source_without_the_governed_api_does_not_match(self):
        record = specification_applicability(self.SPEC, "int value = 1;")
        self.assertEqual(record["status"], "no_governed_api_matched")

    def test_without_a_specification_nothing_is_concluded(self):
        self.assertEqual(
            specification_applicability({}, "anything")["status"],
            "specification_unavailable",
        )


class CallerContractTests(unittest.TestCase):

    def _repository(self, directory: str) -> Path:
        root = Path(directory)
        package = root / "app/src/main/java/app"
        package.mkdir(parents=True)
        (package / "Target.kt").write_text(
            "package app\nclass Target { fun risky() {} }\n", encoding="utf-8"
        )
        (package / "Caller.kt").write_text(
            "package app\nclass Caller { fun go(t: Target) { t.risky() } }\n",
            encoding="utf-8",
        )
        return root

    def test_callers_are_enumerated_with_their_receiver_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            record = caller_contract(
                root, "risky", "app/src/main/java/app/Target.kt", "app.Target"
            )
        self.assertEqual(record["status"], "callers_enumerated")
        self.assertEqual(record["files_with_calls"], 1)
        self.assertEqual(record["receiver_resolved_call_sites"], 1)
        self.assertEqual(
            record["callers"][0]["call_sites"][0]["resolution"], "repository_type"
        )

    def test_no_caller_is_stated_as_such(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            record = caller_contract(
                root, "neverCalled", "app/src/main/java/app/Target.kt"
            )
        self.assertEqual(record["status"], "no_callers_found")
        self.assertIs(record["searched_declaring_file"], True)
        self.assertEqual(record["name_resolution"], "direct")

    def _files(self, directory: str, files: dict) -> Path:
        root = Path(directory)
        for relative, text in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text, encoding="utf-8")
        return root

    def test_a_private_helper_is_called_from_its_own_file(self):
        # YAPM SecretService, papercript SecretCodec: the callers were all in
        # the declaring file, which the record skipped.
        with tempfile.TemporaryDirectory() as directory:
            root = self._files(directory, {"app/Secrets.kt": (
                "package app\nclass Secrets {\n"
                "    private fun removeKey(alias: String) {\n"
                "        if (alias.isEmpty()) removeKey(\"default\")\n"
                "    }\n"
                "    fun reset() {\n        removeKey(\"main\")\n    }\n}\n"
            )})
            record = caller_contract(root, "removeKey", "app/Secrets.kt", "app.Secrets")
        self.assertEqual(record["status"], "callers_enumerated")
        [caller] = record["callers"]
        self.assertIs(caller["declaring_file"], True)
        # The recursive call in its own body and the declaration are not callers.
        self.assertEqual([site["line"] for site in caller["call_sites"]], [7])
        self.assertEqual(caller["call_sites"][0]["resolution"], "declaring_file")
        self.assertEqual(record["same_file_call_sites"], 1)

    def test_a_capitalised_method_keeps_its_same_file_callers(self):
        # Review of 2026-10-31: read as a constructor, a reported Java static
        # SHA1 lost its same-file caller's declaring_file binding.
        with tempfile.TemporaryDirectory() as directory:
            root = self._files(directory, {"a/Utils.java": (
                "package a;\nclass Utils {\n"
                "    static String SHA1(String text) throws Exception {\n"
                "        return text;\n    }\n"
                "    static String deviceId(String id) throws Exception {\n"
                "        return SHA1(id);\n    }\n}\n")})
            record = caller_contract(root, "SHA1", "a/Utils.java", "a.Utils")
        [caller] = record["callers"]
        self.assertEqual([(site["line"], site["resolution"]) for site in caller["call_sites"]],
                         [(7, "declaring_file")])

    def test_constructor_callers_are_found_in_kotlin_and_java(self):
        # Amethyst MacInstance.<init>: no_callers_found next to 23 callers.
        with tempfile.TemporaryDirectory() as directory:
            root = self._files(directory, {
                "a/MacInstance.kt": (
                    "package a\nclass MacInstance(algorithm: String, key: ByteArray) {\n"
                    "    private val mac = Mac.getInstance(algorithm)\n}\n"),
                "b/EngramDTag.kt": (
                    "package b\nimport a.MacInstance\n"
                    "fun tag(k: ByteArray) = MacInstance(\"HmacSHA256\", k)\n"),
                "c/Legacy.java": (
                    "package c;\nimport a.MacInstance;\nclass Legacy {\n"
                    "  Object make(byte[] k) { return new MacInstance(\"HmacSHA1\", k); }\n}\n"),
                "c/Unrelated.java": (
                    "package c;\nclass Unrelated {\n  // new MacInstance(\"x\", k)\n}\n"),
            })
            record = caller_contract(root, "<init>", "a/MacInstance.kt", "a.MacInstance")
        self.assertEqual(record["status"], "callers_enumerated")
        self.assertEqual(record["name_resolution"], "constructor")
        self.assertEqual(record["searched_name"], "MacInstance")
        sites = {caller["source_file_path"]: caller["call_sites"] for caller in record["callers"]}
        self.assertEqual(set(sites), {"b/EngramDTag.kt", "c/Legacy.java"})
        self.assertEqual(sites["b/EngramDTag.kt"][0]["arity"], 2)
        self.assertEqual(sites["c/Legacy.java"][0]["resolution"], "repository_type")
        self.assertEqual(record["receiver_resolved_call_sites"], 2)

    def test_a_kotlin_compiled_name_is_searched_by_its_source_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._files(directory, {
                "app/Client.kt": "package app\nopen class Client {\n"
                                 "    open suspend fun newClient(): Http = build()\n}\n",
                "app/Sync.kt": "package app\nsuspend fun sync(c: Client) { c.newClient() }\n",
            })
            for compiled, rule in (("newClient$suspendImpl", "kotlin_suspend_impl"),
                                   ("newClient-Zyo9ksc", "kotlin_value_class_mangling")):
                record = caller_contract(root, compiled, "app/Client.kt", "app.Client")
                self.assertEqual(record["status"], "callers_enumerated", compiled)
                self.assertEqual(record["name_resolution"], rule)
                self.assertEqual(record["callers"][0]["source_file_path"], "app/Sync.kt")

    def test_a_name_with_no_call_site_in_source_is_not_searchable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._repository(directory)
            for name, owner in (("<clinit>", "app.Target"),
                                ("invoke", "app.Target$setup$1"),
                                ("apply", "app.Target$$ExternalSyntheticLambda0"),
                                ("access$000", "app.Target")):
                record = caller_contract(root, name, "app/src/main/java/app/Target.kt", owner)
                self.assertEqual(record["status"], "not_searchable", name)
                self.assertNotIn("no file", record["detail"])

    def test_the_call_sites_of_one_file_are_capped(self):
        calls = "".join(f"        t.risky()\n" for _ in range(30))
        with tempfile.TemporaryDirectory() as directory:
            root = self._files(directory, {
                "app/Target.kt": "package app\nclass Target { fun risky() {} }\n",
                "app/Many.kt": f"package app\nclass Many {{\n    fun go(t: Target) {{\n{calls}    }}\n}}\n",
            })
            record = caller_contract(root, "risky", "app/Target.kt", "app.Target")
        [caller] = record["callers"]
        self.assertEqual(len(caller["call_sites"]), 12)
        self.assertIs(caller["call_sites_truncated"], True)
        self.assertIn("at most 12 call sites per file", record["detail"])

    def test_a_comment_marker_inside_a_string_does_not_hide_a_caller(self):
        # "image/*" opened a block comment that ran to the next Javadoc, and a
        # URL's "//" blanked the rest of its line.
        with tempfile.TemporaryDirectory() as directory:
            root = self._files(directory, {
                "app/Crypto.kt": "package app\nclass Crypto { fun encrypt(b: ByteArray) = b }\n",
                "app/Share.kt": (
                    "package app\nclass Share {\n"
                    "    fun go(i: Intent, c: Crypto, b: ByteArray) {\n"
                    "        i.type = \"image/*\"\n"
                    "        c.encrypt(b)\n"
                    "    }\n"
                    "    /** Shares it. */\n"
                    "    fun url(c: Crypto) = post(\"https://x.org\", c.encrypt(k))\n"
                    "}\n"),
            })
            record = caller_contract(root, "encrypt", "app/Crypto.kt", "app.Crypto")
        self.assertEqual(record["status"], "callers_enumerated")
        [caller] = record["callers"]
        self.assertEqual([site["line"] for site in caller["call_sites"]], [5, 8])

    def test_an_overload_delegating_to_the_reported_one_is_a_caller(self):
        # `encrypt(String)` calling a private `encrypt(byte[])`: excluding
        # every same-named body dropped the only caller.
        reported = "private byte[] encrypt(byte[] data) {\n    return cipher.doFinal(data);\n  }"
        source = (
            "package app;\nclass Enc {\n"
            "  String encrypt(String s) {\n"
            "    return new String(encrypt(s.getBytes()));\n"
            "  }\n"
            "  " + reported + "\n}\n")
        with tempfile.TemporaryDirectory() as directory:
            root = self._files(directory, {"app/Enc.java": source})
            told_apart = caller_contract(root, "encrypt", "app/Enc.java", "app.Enc", reported)
            by_name_only = caller_contract(root, "encrypt", "app/Enc.java", "app.Enc")
        # The reported body names its declaration: the call in the other
        # overload is listed. Both take one argument, so it stays unresolved.
        self.assertEqual(told_apart["status"], "callers_enumerated")
        [site] = told_apart["callers"][0]["call_sites"]
        self.assertEqual((site["line"], site["resolution"]), (4, "same_name_overload"))
        self.assertEqual(told_apart["receiver_resolved_call_sites"], 0)
        # Without the body nothing is excluded, and the call is still listed.
        self.assertEqual(by_name_only["status"], "callers_enumerated")
        self.assertEqual(by_name_only["callers"][0]["call_sites"][0]["resolution"],
                         "same_name_overload")

    def test_a_member_without_a_body_does_not_take_the_next_ones(self):
        # An abstract or interface member has no `{`, `=` or `;`; the next
        # function's body was excluded as its own.
        with tempfile.TemporaryDirectory() as directory:
            root = self._files(directory, {
                "app/Base.kt": (
                    "package app\nabstract class Base {\n"
                    "    abstract fun encrypt(x: ByteArray): ByteArray\n"
                    "    fun helper(x: ByteArray): ByteArray {\n"
                    "        return encrypt(x)\n"
                    "    }\n}\n"),
                "app/Hasher.kt": (
                    "package app\ninterface Hasher {\n"
                    "    fun hash(x: ByteArray): ByteArray\n\n"
                    "    fun hashTwice(x: ByteArray): ByteArray {\n"
                    "        return hash(hash(x))\n"
                    "    }\n}\n"),
            })
            for name, path, lines in (("encrypt", "app/Base.kt", [5]),
                                      ("hash", "app/Hasher.kt", [6, 6])):
                record = caller_contract(root, name, path, "app." + Path(path).stem)
                self.assertEqual(record["status"], "callers_enumerated", name)
                self.assertEqual([site["line"] for site in record["callers"][0]["call_sites"]],
                                 lines, name)

    def test_a_nested_class_built_through_its_outer_name_is_a_caller(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._files(directory, {
                "a/Outer.kt": "package a\nsealed class Outer {\n"
                              "    class Inner(val k: ByteArray) : Outer()\n}\n",
                "b/Use.kt": "package b\nimport a.Outer\n"
                            "fun make(k: ByteArray) = Outer.Inner(k)\n"
                            "fun other(x: Any) = x.Inner(1)\n",
            })
            record = caller_contract(root, "<init>", "a/Outer.kt", "a.Outer$Inner")
        self.assertEqual(record["status"], "callers_enumerated")
        [caller] = record["callers"]
        # `x.Inner(` is not qualified by an outer name and is not taken.
        self.assertEqual([site["line"] for site in caller["call_sites"]], [3])
        self.assertEqual(caller["call_sites"][0]["resolution"], "repository_type")


class ResponderIntegrationTests(unittest.TestCase):

    def test_the_three_questions_are_answered_not_declined(self):
        spec = json.loads(
            (ROOT / "data" / "specifications" / "WebViewDebuggingSpec.json")
            .read_text(encoding="utf-8")
        )
        requests = [
            {"kind": "ownership_and_version",
             "reason": "Which artifact ships the reported class?",
             "symbol": "app.MainActivity"},
            {"kind": "reported_rule_applicability",
             "reason": "Does the reported rule govern this code?",
             "symbol": "WebViewDebuggingSpec"},
            {"kind": "reachable_caller_contract",
             "reason": "What do the callers require?",
             "symbol": "MainActivity#setupWebView"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "app/src/main/java/app"
            package.mkdir(parents=True)
            (package / "MainActivity.kt").write_text(
                "package app\nimport android.webkit.*\n"
                "class MainActivity { fun setupWebView() { "
                "WebView.setWebContentsDebuggingEnabled(true) } }\n",
                encoding="utf-8",
            )
            (root / "app" / "build.gradle").write_text(
                'dependencies { implementation "androidx.core:core-ktx:1.0" }',
                encoding="utf-8",
            )
            resolution = resolve_evidence_requests(
                root, requests, set(),
                target={
                    "source_file_path": "app/src/main/java/app/MainActivity.kt",
                    "method_name": "setupWebView",
                    "csv_class": "app.MainActivity",
                    "method_body": "WebView.setWebContentsDebuggingEnabled(true)",
                    "error_message": "debugging enabled in release",
                    "specification_context": spec,
                },
            )
        self.assertEqual(resolution["declined"], [])
        kinds = {entry["kind"] for entry in resolution["entries"]}
        self.assertEqual(kinds, {
            "resolved_artifact_ownership", "specification_applicability",
            "resolved_caller_contract",
        })

    def test_a_question_the_finding_cannot_support_is_declined_with_its_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            resolution = resolve_evidence_requests(
                Path(directory),
                [{"kind": "reported_rule_applicability", "reason": "x",
                  "symbol": "y"}],
                set(), target={"source_file_path": "a.kt"},
            )
        self.assertEqual(resolution["entries"], [])
        self.assertIn(
            "specification context",
            resolution["declined"][0]["reason"],
        )


if __name__ == "__main__":
    unittest.main()
