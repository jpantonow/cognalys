"""Regression: omitted PIN readers in exp_final_20261019 lock users out."""
import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import _paths  # noqa: F401
from cognalys.extraction.stored_value_contract import collect_stored_value_contract, promote_stored_value_sources
from cognalys.llm.evidence_packet import FindingEvidencePacketBuilder as EvidencePacketBuilder
from cognalys.llm.semantic_validation import _validate_patch_plan, semantic_validation_retry_targets, stale_stored_value_readers
from cognalys.llm.finding_context import FindingContextCollection
from cognalys.llm.coordinated_generation import CoordinatedGeneration


PREFS = '''class Prefs {
    public static final String HASH = "hash";
    public static final String EMERGENCY = "emergency";
    private static SharedPreferences saved;
    public static SharedPreferences get() { return saved; }
    public static SharedPreferences.Editor edit() { return get().edit(); }
}
'''
CRYPTO = '''class Crypto {
    public static String hash(String input) { return legacy(input); }
}
'''
SETUP = '''class Setup {
    void save(String input) {
        String hashed = Crypto.hash(input);
        Prefs.edit().putString(Prefs.HASH, hashed).commit();
    }
    void saveEmergency(String input) {
        Prefs.edit().putString(Prefs.EMERGENCY, Crypto.hash(input)).commit();
    }
}
'''
ENTRY = '''class Entry {
    boolean unlock(String input) {
        String hash = Crypto.hash(input);
        return Prefs.get().getString(Prefs.HASH, "").equals(hash);
    }
}
'''


class StoredValueMigrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.texts = {'Prefs.java': PREFS, 'Crypto.java': CRYPTO, 'Setup.java': SETUP, 'Entry.java': ENTRY}
        self.write()

    def write(self):
        for name, text in self.texts.items():
            (self.root / name).write_text(text)

    def collect(self, truncated=False):
        return collect_stored_value_contract(self.root, self.consumers(), index={
            'source_cache': {self.root / p: text for p, text in self.texts.items()},
            'metadata': {'truncated': truncated}})

    def consumers(self):
        return {'persisted': True, 'consumers': [{'kind': 'persistence', 'path': 'Setup.java', 'line': 4}]}

    def test_all_readers_and_emergency_writer_with_same_producer_are_found(self):
        contract = self.collect()
        self.assertEqual(contract['status'], 'complete')
        self.assertEqual({e['key'] for e in contract['entries']}, {'literal:"hash"', 'literal:"emergency"'})
        self.assertEqual(contract['required_paths'], ['Entry.java', 'Setup.java'])
        self.assertTrue(all(p in contract['source_hashes'] for p in contract['required_paths']))

    def test_same_key_in_another_storage_is_not_joined(self):
        self.texts['Other.java'] = PREFS.replace('class Prefs', 'class Other')
        self.texts['OtherEntry.java'] = ENTRY.replace('class Entry', 'class OtherEntry').replace('Prefs.get()', 'Other.get()')
        self.write()
        self.assertNotIn('OtherEntry.java', self.collect()['required_paths'])

    def test_commented_access_does_not_create_a_reader(self):
        self.texts['Comment.java'] = '// Prefs.get().getString(Prefs.HASH, "");\n'
        self.write()
        self.assertNotIn('Comment.java', self.collect()['required_paths'])

    def test_ambiguous_accessor_owner_is_not_invented(self):
        self.texts['Alias.java'] = PREFS
        self.write()
        self.assertEqual(self.collect()['status'], 'partial')

    def test_index_limit_is_explicit(self):
        self.assertIn('repository source index truncated', self.collect(True)['limitations'])

    def test_unresolved_seed_cannot_claim_complete(self):
        self.texts['Setup.java'] = SETUP.replace('Prefs.edit()', 'unknownPrefs')
        self.write()
        self.assertEqual(self.collect()['status'], 'partial')

    def test_reader_with_unknown_storage_is_explicitly_unresolved(self):
        self.texts['Entry.java'] = ENTRY.replace('Prefs.get()', 'unknownStorage')
        self.write()
        contract = self.collect()
        self.assertEqual(contract['status'], 'partial')
        self.assertEqual(contract['unresolved_readers'][0]['path'], 'Entry.java')

    def test_reassigned_storage_field_does_not_unify_different_stores(self):
        self.texts['Prefs.java'] = PREFS.replace('return saved;', 'saved = Factory.first(); saved = Factory.second(); return saved;')
        self.write()
        self.assertEqual(self.collect()['status'], 'partial')

    def file_sink_contract(self, write='        File(dir, FILENAME_KEY_PEM).writeText(pem)\n'):
        # Syncthing-lite (2026-10-29): the generated key goes to key.pem.
        self.texts['Keys.kt'] = ('class Keys {\n'
                                 '    fun save(dir: File, pem: String) {\n'
                                 + write +
                                 '    }\n'
                                 '    fun load(dir: File) = File(dir, FILENAME_KEY_PEM).readText()\n'
                                 '    companion object { const val FILENAME_KEY_PEM = "key.pem" }\n'
                                 '}\n')
        self.write()
        return collect_stored_value_contract(self.root, {'persisted': True, 'consumers': [
            {'kind': 'persistence', 'path': 'Keys.kt', 'line': 3,
             'statement': 'File(dir, FILENAME_KEY_PEM).writeText(pem)'}]}, index={
            'source_cache': {self.root / p: text for p, text in self.texts.items()},
            'metadata': {'truncated': False}})

    def test_a_file_sink_is_not_modelled_rather_than_an_unknown_scope(self):
        contract = self.file_sink_contract()
        self.assertEqual(contract['status'], 'not_modelled')
        self.assertEqual(contract['limitations'], [])
        sink = contract['unmodelled_sinks'][0]
        self.assertEqual((sink['path'], sink['line']), ('Keys.kt', 3))
        # The loader names the same constant; its declaration is not a reader.
        self.assertEqual([(r['path'], r['line']) for r in sink['readers']], [('Keys.kt', 5)])

    def test_the_lines_of_the_write_itself_are_not_readers(self):
        # value_consumers joins a write broken over two lines into one
        # statement; its second line names the constant too.
        contract = self.file_sink_contract('        File(dir,\n'
                                           '            FILENAME_KEY_PEM).writeText(pem)\n')
        sink = contract['unmodelled_sinks'][0]
        self.assertEqual([(r['path'], r['line']) for r in sink['readers']], [('Keys.kt', 6)])

    def test_a_preference_sink_without_a_resolved_key_is_still_partial(self):
        self.texts['Setup.java'] = SETUP.replace('Prefs.HASH', 'unknownKey()')
        self.write()
        contract = collect_stored_value_contract(self.root, {'persisted': True, 'consumers': [
            {'kind': 'persistence', 'path': 'Setup.java', 'line': 4,
             'statement': 'Prefs.edit().putString(unknownKey(), hashed).commit();'}]}, index={
            'source_cache': {self.root / p: text for p, text in self.texts.items()},
            'metadata': {'truncated': False}})
        self.assertEqual(contract['status'], 'partial')
        self.assertIn('no preference entry resolved from the observed persistence sinks',
                      contract['limitations'])

    def test_a_not_modelled_contract_leaves_the_scope_complete_and_reaches_the_review(self):
        error = self.error()
        error['stored_value_contract'] = self.file_sink_contract()
        packet = EvidencePacketBuilder().build(error, {})
        scope = packet['scope_completeness']
        self.assertEqual(scope['overall'], 'complete')
        self.assertEqual(scope['stored_value_consumers'], 'not_modelled')
        self.assertEqual(scope['persisted_outside_preferences'],
                         ['Keys.kt:3 File(dir, FILENAME_KEY_PEM).writeText(pem)'])
        self.assertIn('stored_value_contract', {i['kind'] for i in packet['evidence_catalog']})
        # A stored verifier still cannot be planned against it.
        packet = {'case_policy': {'consumer_scope': 'stored_secret_verifier'},
                  'evidence_catalog': [{'kind': 'stored_value_contract', 'data': error['stored_value_contract']}]}
        self.assertTrue(any('persisted outside preferences at Keys.kt:3' in issue
                            for issue in self.validate(['Crypto.java'], packet)))

    def test_nonpersisted_values_do_not_acquire_a_contract(self):
        self.assertEqual(collect_stored_value_contract(self.root, {})['status'], 'not_applicable')

    def test_curated_parameter_target_rejects_detector_minimum(self):
        from cognalys.llm.contract_gates import required_numeric_constants
        error = {'case_migration_policy': {'required_numeric_constants': [
            {'symbol_pattern': '(?i)^(?!.*legacy).*iterations.*$', 'minimum': 100000}]}}
        def check(value):
            return required_numeric_constants(error, [{'source_file_path': 'Crypto.java',
                'corrected_code': f'private static final int CURRENT_ITERATIONS = {value};\n'
                                  'private static final int LEGACY_ITERATIONS = 5000;'}])
        self.assertEqual(check('10_000')[0]['code'], 'CURRENT_PARAMETER_BELOW_POLICY')
        self.assertEqual(check('100_000'), [])
        self.assertEqual(required_numeric_constants({}, []), [])

    def test_parameter_policies_state_what_the_gate_requires(self):
        """Your Local Weather run_v2 (2026-11-02): the prompts kept 65536
        iterations while the gate asked for 100000; the plan and generator
        inputs now carry the gate's own minimum and pattern."""
        from cognalys.llm.contract_gates import parameter_policies
        error = {'case_migration_policy': {'required_numeric_constants': [
            {'symbol_pattern': 'CURRENT_ITERATIONS', 'minimum': 100000, 'purpose': 'New verifiers.'},
            {'symbol_pattern': 'BROKEN'}]}}
        sentences = parameter_policies(error)
        self.assertEqual(len(sentences), 1)
        self.assertIn('at least 100000', sentences[0])
        self.assertIn('CURRENT_ITERATIONS', sentences[0])
        self.assertTrue(sentences[0].endswith('New verifiers.'))
        self.assertEqual(parameter_policies({}), [])
        self.assertEqual(parameter_policies({'case_migration_policy': None}), [])

    def test_a_value_below_the_parameter_policy_is_the_drafts_failure(self):
        """A refused value is answered by another plan, not by a maintainer issue."""
        from cognalys.llm.contract_gates import required_numeric_constants
        from cognalys.llm.fix_generation_common import draft_quality_failure
        error = {'case_migration_policy': {'required_numeric_constants': [
            {'symbol_pattern': 'CURRENT_ITERATIONS', 'minimum': 100000}]}}
        issues = required_numeric_constants(error, [{'source_file_path': 'Crypto.java',
            'corrected_code': 'private static final int CURRENT_ITERATIONS = 65536;'}])
        self.assertTrue(draft_quality_failure(issues))

    def test_copied_preference_does_not_turn_its_accessor_into_a_derivation(self):
        from cognalys.llm.semantic_validation import _store_writes
        self.assertEqual(_store_writes('prefs.putString(PIN, Prefs.getEncryptedPrefs().getString(EMERGENCY, x));'), {})

    def test_numeric_policy_cannot_be_satisfied_by_a_comment(self):
        from cognalys.llm.contract_gates import required_numeric_constants
        error = {'case_migration_policy': {'required_numeric_constants': [
            {'symbol_pattern': 'CURRENT_ITERATIONS', 'minimum': 100000}]}}
        self.assertTrue(required_numeric_constants(error, [{'source_file_path': 'Crypto.java',
            'corrected_code': '// int CURRENT_ITERATIONS = 100000;'}]))

    def test_new_verifier_writer_is_not_a_redundant_rename_of_legacy_helper(self):
        from cognalys.llm.semantic_validation import redundant_caller_renames
        implementation = {'source_file_path': 'Crypto.java', 'corrected_code':
            'class Crypto {\n public static String oldHash(String data) { return legacy(data); }\n'
            ' public static String newHash(String data) { return current(data); }\n}'}
        caller = {'source_file_path': 'Setup.java', 'original_code': 'prefs.putString(KEY, Crypto.oldHash(value));',
                  'corrected_code': 'prefs.putString(KEY, Crypto.newHash(value));'}
        self.assertEqual(redundant_caller_renames([implementation, caller]), [])

    def test_shared_derivation_cohort_keeps_variable_written_keys_in_scope(self):
        edits = [{'source_file_path': 'Setup.java', 'original_code': SETUP,
                  'corrected_code': SETUP.replace('Crypto.hash(', 'Crypto.newHash(')}]
        errors = stale_stored_value_readers({'repository_path': str(self.root),
                                            'stored_value_contract': self.collect()}, edits)
        self.assertIn('Entry.java', errors[0]['affected_paths'])
        self.assertIn('HASH', {v['key'] for v in errors[0]['stored_values']})

    def test_port_gate_rechecks_reader_even_if_port_omitted_its_edit(self):
        from cognalys.validation.repair import semantic_regressions
        edits = [{'source_file': 'Setup.java', 'original_code': SETUP,
                  'corrected_code': SETUP.replace('Crypto.hash(', 'Crypto.newHash(')},
                 {'source_file': 'Crypto.java', 'original_code': CRYPTO,
                  'corrected_code': CRYPTO.rsplit('}', 1)[0] + '    public static String newHash(String input) { return current(input); }\n}\n'}]
        errors = semantic_regressions(self.root, {'stored_value_contract': self.collect()}, edits)
        self.assertIn('STORED_VALUE_READERS_NOT_UPDATED', {e['code'] for e in errors})

    def test_port_recollects_consumers_with_shifted_source_lines(self):
        before = self.collect()
        self.texts['Setup.java'] = '\n' * 30 + SETUP
        self.texts['NewReader.java'] = ENTRY.replace('class Entry', 'class NewReader')
        self.write()
        after = collect_stored_value_contract(self.root, {'persisted': True}, seed_entries=before['entries'])
        self.assertEqual(after['status'], 'complete')
        self.assertIn('NewReader.java', after['required_paths'])

    def test_old_solution_loads_contract_only_from_its_matching_packet(self):
        from cognalys.solutions.solution_mapper import stored_contract_from_artifacts
        source = self.root / 'error_solutions/app/0_hash_solution.json'
        packet = self.root / 'error_solutions/v2_artifacts/app/0_hash_evidence_packet.json'
        packet.parent.mkdir(parents=True)
        packet.write_text(json.dumps({'finding': {'finding_id': 'same'}, 'evidence_catalog': [
            {'kind': 'stored_value_contract', 'data': self.collect()}]}))
        metadata = {'apk_name': 'app', 'method_name': 'hash', 'error_index': 0}
        self.assertTrue(stored_contract_from_artifacts(source, metadata, {'unique_error_id': 'same'})['entries'])
        self.assertEqual(stored_contract_from_artifacts(source, metadata, {'unique_error_id': 'different'}), {})

    def error(self):
        return {'repository_path': str(self.root), 'source_file_path': 'Crypto.java',
                'method_name': 'hash', 'method_body': CRYPTO,
                'stored_value_contract': self.collect(),
                'expanded_repository_context': {'multi_file_impact': {
                    'status': 'available', 'scope_completeness': {'status': 'complete'},
                    'exact_candidate_sources': [{'source_file_path': 'Crypto.java', 'content': CRYPTO}],
                    'coverage_requirements': {}}}}

    def test_consumer_sources_are_full_and_mandatory_even_with_small_budget(self):
        error = self.error()
        promote_stored_value_sources(error)
        packet = EvidencePacketBuilder(repository_context_budget=1).build(error, {})
        exact = {i['data'].get('source_file_path'): i['data'].get('content') for i in packet['evidence_catalog']
                 if i['trust_level'] == 'repository_exact_source'}
        self.assertEqual(exact['Entry.java'], ENTRY)
        self.assertEqual(packet['scope_completeness']['stored_value_consumers'], 'complete')

    def test_missing_consumer_source_marks_scope_incomplete(self):
        error = self.error()
        (self.root / 'Entry.java').unlink()
        promote_stored_value_sources(error)
        packet = EvidencePacketBuilder().build(error, {})
        self.assertEqual(packet['scope_completeness']['overall'], 'incomplete')
        self.assertEqual(packet['scope_completeness']['stored_value_consumers'], 'partial')

    def packet(self):
        return {'case_policy': {'consumer_scope': 'stored_secret_verifier'},
                'evidence_catalog': [{'kind': 'stored_value_contract', 'data': self.collect()},
                    *({'trust_level': 'repository_exact_source', 'data': {'source_file_path': p, 'content': self.texts[p]}}
                      for p in self.texts)]}

    def plan(self, paths):
        return {'decision': 'MULTI_FILE_FIX_PROPOSED_FOR_REVIEW',
                'required_edits': [{'source_file_path': p, 'supporting_claim_ids': ['claim']} for p in paths]}

    def validate(self, paths, packet=None):
        return _validate_patch_plan(self.plan(paths), packet or self.packet(), {
            'decision': 'MULTI_FILE_FIX_PROPOSED_FOR_REVIEW', 'generation_status': 'supported_for_review',
            '_validated_claims': [{'claim_id': 'claim'}]})

    def test_plan_omitting_unlock_reader_is_refused(self):
        self.assertTrue(any('omits affected consumer: Entry.java' in issue
                            for issue in self.validate(['Crypto.java', 'Setup.java'])))

    def test_complete_plan_passes(self):
        self.assertEqual(self.validate(['Crypto.java', 'Setup.java', 'Entry.java']), [])

    def test_caller_repair_keeps_existing_cost_but_cannot_lower_or_delete_it(self):
        from cognalys.llm.contract_gates import required_numeric_constants
        source = 'class Crypto { static final int CURRENT_ITERATIONS = 100000; }'
        (self.root / 'Crypto.java').write_text(source)
        error = {'repository_path': str(self.root), 'source_file_path': 'Crypto.java',
                 'repository_includes_patch': True, 'case_migration_policy': {
                     'required_numeric_constants': [{'symbol_pattern': 'CURRENT_ITERATIONS', 'minimum': 100000}]}}
        caller = {'source_file_path': 'Entry.java', 'original_code': ENTRY, 'corrected_code': ENTRY + '\n// exception handler'}
        self.assertEqual(required_numeric_constants(error, [caller]), [])
        for corrected in [source.replace('100000', '10000'), 'class Crypto {}']:
            edit = {'source_file_path': 'Crypto.java', 'original_code': source, 'corrected_code': corrected}
            self.assertTrue(required_numeric_constants(error, [edit]))

    def test_port_reassesses_private_rename_on_current_checkout(self):
        from cognalys.validation.repair import semantic_regressions
        (self.root / 'build.gradle').write_text("plugins { id 'com.android.application' }")
        before = ('class PrivateHelper {\n private static String encode(String input) {\n'
                  ' return input;\n }\n String hash(String input) {\n'
                  ' return encode(input);\n }\n}\n')
        (self.root / 'PrivateHelper.java').write_text(before)
        edit = {'source_file': 'PrivateHelper.java', 'original_code': before,
                'corrected_code': before.replace('encode(', 'encodeLegacy(')}
        errors = semantic_regressions(self.root, {}, [edit])
        self.assertNotIn('UNAUTHORIZED_RENAME', {e['code'] for e in errors}, errors)
        (self.root / 'Unexpected.java').write_text('class Unexpected { String name = "encode"; }')
        errors = semantic_regressions(self.root, {}, [edit])
        self.assertIn('UNAUTHORIZED_RENAME', {e['code'] for e in errors})

    def test_port_can_migrate_a_verified_reader_without_an_original_edit(self):
        from cognalys.solutions.base_port import port_payload, validate_port
        solution = {'coordinated_edits': [{'source_file_path': 'Crypto.java',
                    'original_code': CRYPTO, 'corrected_code': 'new crypto'}],
                    'stored_value_contract': self.collect()}
        payload = port_payload(solution, self.root, self.root, 'HEAD')
        self.assertIn('Entry.java', {f['source_file_path'] for f in payload['files_on_base']})
        port = {'decision': 'PORT', 'edits': [{'source_file_path': 'Entry.java',
                'original_code': ENTRY, 'corrected_code': 'migrated reader'}]}
        self.assertEqual(validate_port(port, solution), '')
        port['edits'][0]['source_file_path'] = 'Unrelated.java'
        self.assertIn('OUTSIDE_REVIEWED_FILES', validate_port(port, solution))

    def test_port_recollects_readers_added_on_the_new_base(self):
        from cognalys.solutions.base_port import port_to_base
        stored = self.collect()
        (self.root / 'NewReader.java').write_text(ENTRY.replace('class Entry', 'class NewReader'))
        provider = Mock()
        provider.generate.return_value = json.dumps({'decision': 'ABSTAIN', 'explanation': 'test', 'edits': []})
        port_to_base(provider, {'stored_value_contract': stored}, self.root, self.root, 'HEAD', Mock())
        prompt = provider.generate.call_args.args[0]
        self.assertIn('NewReader.java', prompt)

    def test_plan_cannot_authorize_missing_source(self):
        packet = self.packet()
        packet['evidence_catalog'] = [i for i in packet['evidence_catalog'] if i.get('data', {}).get('source_file_path') != 'Entry.java']
        self.assertTrue(any('lacks full source' in issue for issue in self.validate(['Setup.java', 'Entry.java'], packet)))

    def test_gate_reports_every_affected_path_structurally(self):
        (self.root / 'Another.java').write_text(ENTRY.replace('class Entry', 'class Another'))
        edits = [{'source_file_path': 'Crypto.java', 'original_code': CRYPTO,
                  'corrected_code': CRYPTO.replace('return legacy(input)', 'return current(input)')}]
        self.texts['Another.java'] = ENTRY.replace('class Entry', 'class Another')
        result = stale_stored_value_readers({'repository_path': str(self.root), 'stored_value_contract': self.collect()}, edits)
        self.assertEqual(result[0]['affected_paths'], ['Another.java', 'Entry.java'])

    def test_retry_targets_all_affected_readers(self):
        paths = ['Setup.java', 'Entry.java', 'Another.java']
        self.assertEqual(semantic_validation_retry_targets([{
            'code': 'STORED_VALUE_READERS_NOT_UPDATED', 'path': 'Entry.java',
            'affected_paths': ['Entry.java', 'Another.java']}], paths), {'Entry.java', 'Another.java'})

    def test_migrated_reader_can_assign_hash_for_new_writes_without_a_stale_check(self):
        from cognalys.llm.semantic_validation import _stored_derivation_is_checked, _without_store_values
        code = ('String hashed = Crypto.hash(input);\n'
                'boolean correct = verify(input, prefs.getString(KEY, ""));\n'
                'prefs.putString(KEY, hashed).commit();')
        self.assertFalse(_stored_derivation_is_checked(_without_store_values(code), 'hash'))

    def test_hash_given_only_to_the_patch_own_verifier_is_not_a_stale_check(self):
        from cognalys.llm.semantic_validation import _stored_derivation_is_checked, _without_store_values
        # BitBanana PasswordEntryActivity (frozen run v3, 2026-11-13): migration after a match.
        code = ('String current = Crypto.hash(input);\n'
                'if (Crypto.isLegacy(current) || !Crypto.verify(input, current)) { return; }\n'
                'prefs.edit().putString(KEY, current).commit();')
        checks = _without_store_values(code)
        self.assertFalse(_stored_derivation_is_checked(checks, 'hash', frozenset({'verify', 'isLegacy'})))
        # A function the patch did not add may compare it the old way.
        self.assertTrue(_stored_derivation_is_checked(checks, 'hash', frozenset({'isLegacy'})))
        self.assertTrue(_stored_derivation_is_checked(checks, 'hash'))

    def test_reader_moved_to_patch_verifier_with_migration_passes(self):
        verifier = ('    public static boolean verify(String input, String stored) { return stored.equals(legacy(input)) || stored.equals(current(input)); }\n'
                    '    public static boolean isLegacy(String stored) { return !stored.startsWith("v2$"); }\n')
        entry_new = ENTRY.replace(
            '        String hash = Crypto.hash(input);\n'
            '        return Prefs.get().getString(Prefs.HASH, "").equals(hash);\n',
            '        String stored = Prefs.get().getString(Prefs.HASH, "");\n'
            '        if (!Crypto.verify(input, stored)) { return false; }\n'
            '        String upgraded = Crypto.hash(input);\n'
            '        if (Crypto.isLegacy(stored) && Crypto.verify(input, upgraded)) { Prefs.edit().putString(Prefs.HASH, upgraded).commit(); }\n'
            '        return true;\n')
        self.assertNotEqual(entry_new, ENTRY)
        crypto_new = CRYPTO.replace('return legacy(input)', 'return "v2$" + current(input)')
        crypto_new = crypto_new.rsplit('}', 1)[0] + verifier + '}\n'
        contract = self.collect()
        stale_edits = [{'source_file_path': 'Crypto.java', 'original_code': CRYPTO, 'corrected_code': crypto_new}]
        error = {'repository_path': str(self.root), 'stored_value_contract': contract}
        self.assertIn('Entry.java', stale_stored_value_readers(error, stale_edits)[0]['affected_paths'])
        edits = stale_edits + [{'source_file_path': 'Entry.java', 'original_code': ENTRY, 'corrected_code': entry_new}]
        errors = stale_stored_value_readers(error, edits)
        self.assertNotIn('Entry.java', {p for e in errors for p in e['affected_paths']})

    def test_reads_handed_to_patch_verifier_are_migrated_unless_compared(self):
        from cognalys.llm.semantic_validation import _reads_go_through_patch_functions
        # BitBanana PinEntryActivity (frozen run v3, 2026-11-13).
        migrated = ('String normal = prefs.getString(Prefs.HASH, "");\n'
                    'boolean ok = Crypto.verify(pin, normal);\n'
                    'if (ok) { migrate(prefs, Prefs.HASH, normal, pin); }\n'
                    'void migrate(P prefs, String key, String stored, String pin) {\n'
                    '  String current = Crypto.hash(pin);\n'
                    '  if (current.equals(prefs.getString(key, ""))) { return; }\n}\n')
        patch = frozenset({'verify', 'migrate'})
        self.assertTrue(_reads_go_through_patch_functions(migrated, 'HASH', patch))
        self.assertFalse(_reads_go_through_patch_functions(migrated, 'HASH', frozenset()))
        self.assertFalse(_reads_go_through_patch_functions(migrated, 'HASH', frozenset({'migrate'})))
        compared = migrated.replace('boolean ok = Crypto.verify(pin, normal);',
                                    'boolean ok = Crypto.verify(pin, normal) || normal.equals(Crypto.hash(pin));')
        self.assertFalse(_reads_go_through_patch_functions(compared, 'HASH', patch))
        direct = 'boolean ok = Crypto.verify(pin, prefs.getString(Prefs.HASH, ""));'
        self.assertTrue(_reads_go_through_patch_functions(direct, 'HASH', patch))
        second_read = direct + '\nboolean old = prefs.getString(Prefs.HASH, "").equals(Crypto.hash(pin));'
        self.assertFalse(_reads_go_through_patch_functions(second_read, 'HASH', patch))

    def test_old_comparison_of_assigned_hash_is_still_rejected(self):
        from cognalys.llm.semantic_validation import _stored_derivation_is_checked
        self.assertTrue(_stored_derivation_is_checked('String hashed = Crypto.hash(input); return stored.equals(hashed);', 'hash'))

    def test_replanning_only_accepts_paths_verified_by_the_collector(self):
        collector = FindingContextCollection()
        collector.collect_stored_value_context = Mock(side_effect=lambda e: e.update(stored_value_contract=self.collect()))
        collector.adjudicate_finding = Mock()
        self.assertFalse(collector.replan_stored_value_migration({}, {'Unrelated.java'}, 'a', 'm'))
        collector.adjudicate_finding.assert_not_called()

    def test_replan_keeps_decision_and_updates_plan_in_place(self):
        collector = FindingContextCollection()
        collector.collect_stored_value_context = Mock(side_effect=lambda e: e.update(stored_value_contract=self.collect()))
        analysis = {'decision': 'MULTI_FILE_FIX_PROPOSED_FOR_REVIEW', 'coordinated_fix_plan': self.plan(['Entry.java', 'Setup.java'])}
        collector.adjudicate_finding = Mock(return_value=(analysis, {'patch_plan': analysis['coordinated_fix_plan']}))
        previous = {'decision': analysis['decision']}
        error = {'evidence_analysis': previous}
        self.assertTrue(collector.replan_stored_value_migration(error, {'Entry.java'}, 'a', 'm'))
        self.assertIs(error['evidence_analysis'], previous)
        self.assertEqual(previous['coordinated_fix_plan'], analysis['coordinated_fix_plan'])

    def test_outside_reader_rebuilds_contract_once_instead_of_retrying_one_file(self):
        class Generator(CoordinatedGeneration):
            def _generate_one_coordinated_attempt(inner, *args):
                inner.hashes.append(args[10])
                if 'Entry.java' in args[8]:
                    return {'status': 'complete'}
                return {'status': 'invalid', 'stage': 'semantic_validation',
                        'semantic_validation': {'errors': [{'code': 'STORED_VALUE_READERS_NOT_UPDATED',
                            'affected_paths': ['Entry.java']}]}}
            def replan_stored_value_migration(inner, error, paths, apk, method):
                error['evidence_analysis']['coordinated_fix_plan']['required_edits'].append({'source_file_path': 'Entry.java'})
                return True
        generator = Generator()
        generator.output_dir = self.root / 'out'
        generator.logger = logging.getLogger(__name__)
        generator.hashes = []
        error = {'repository_path': str(self.root), 'evidence_analysis': {'coordinated_fix_plan': self.plan(['Setup.java'])}}
        self.assertEqual(generator.generate_coordinated_file_drafts(error, 'FIX_SUPPORTED', 'a', 'm')['status'], 'complete')
        self.assertEqual(len(generator.hashes), 2)
        self.assertNotEqual(generator.hashes[0], generator.hashes[1])


    def _outside_reader_generator(self, replans):
        class Generator(CoordinatedGeneration):
            def _generate_one_coordinated_attempt(inner, *args):
                return {'status': 'invalid', 'stage': 'semantic_validation',
                        'semantic_validation': {'errors': [{'code': 'STORED_VALUE_READERS_NOT_UPDATED',
                            'affected_paths': ['Entry.java']}]}}
            def replan_stored_value_migration(inner, error, paths, apk, method):
                replans.append(paths)
                return False
        generator = Generator()
        generator.output_dir = self.root / 'out'
        generator.logger = logging.getLogger(__name__)
        return generator

    def test_a_unit_already_replanned_does_not_replan_for_a_stored_value(self):
        """B7: a unit gets one new plan in all; the stored-value replan is one of them."""
        from cognalys.llm.coordinated_generation import replanned_once
        replans = []
        error = {'repository_path': str(self.root), '_behavior_replanned': True,
                 'evidence_analysis': {'coordinated_fix_plan': self.plan(['Setup.java'])}}
        self._outside_reader_generator(replans).generate_coordinated_file_drafts(error, 'FIX_SUPPORTED', 'a', 'm')
        self.assertEqual(replans, [])
        # And the other way: a stored-value replan counts as the unit's one.
        self.assertTrue(replanned_once({'_stored_value_replanned': True}))

    def test_a_unit_not_replanned_still_gets_the_stored_value_replan(self):
        replans = []
        error = {'repository_path': str(self.root),
                 'evidence_analysis': {'coordinated_fix_plan': self.plan(['Setup.java'])}}
        self._outside_reader_generator(replans).generate_coordinated_file_drafts(error, 'FIX_SUPPORTED', 'a', 'm')
        self.assertEqual(replans, [{'Entry.java'}])
        self.assertTrue(error['_stored_value_replanned'])

if __name__ == '__main__':
    unittest.main()
