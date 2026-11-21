# Pipeline LLM architecture

> Historical architecture and migration record. For the implementation currently present, see the [detailed Portuguese documentation](docs/README.md). The executable v1 path and `--llm-architecture-version` option have since been removed; persisted historical artifacts remain readable.

This document is the versioned contract and migration map for the LLM pipeline.
It preserves the conservative v1 behavior as a baseline while introducing a
smaller, auditable v2 data flow.

## Baseline v1 call map

| Stage | Caller | Prompt builders | Schema/tooling | Upstream model output | Deterministic checks |
|---|---|---|---|---|---|
| Specification research/synthesis | `cognalys.specifications.generate_specifications:main` | `prompt_for` plus `OpenAIProvider.generate` web/JSON bridge | `specification_schema`; web search then JSON | Research text is appended to synthesis | `validate_specification` |
| Finding evidence + decision + plan + issue | `FixGenerator.process_error` | `build_evidence_prompt` | `evidence_analysis_schema`; optional web search | Research text and corrective `preliminary_evidence_analysis` | multi-file scope, digest/dependency policy checks |
| Single-method generation | `process_error` | `build_prompt` | `single_fix_schema` | complete evidence analysis | code shape/quality validator |
| Coordinated generation | `generate_coordinated_file_drafts` | per-file draft prompt | `coordinated_file_draft_schema` | evidence analysis and its embedded plan | path, coverage, semantic and edit-shape checks |
| Validation repair | `cognalys.validation.repair:main` | inline compiler-repair prompt | `repair_schema` | build diagnostics only | diagnosed-file allowlist and exact replacement checks |
| Published PR revision | `cognalys.prs.pr_feedback:main` | `prompts` | `pr_revision_schema` | maintainer feedback and prior PR prose | source replacement/import/build checks |

The v1 evidence request has too many responsibilities: external research,
repository evidence interpretation, detector/runtime adjudication, migration
assessment, patch planning and issue prose. It also includes family-specific
rules for unrelated specifications and can re-submit prior model analysis.

In the measured EteSync trace, `expanded_repository_context` was about 720k JSON
characters. Dominant sections were `multi_file_impact` (~333k),
`value_usage_graph` (~87k), transitive/consumer evidence (~153k), usage
classification (~56k) and raw repository call sites (~40k). Inside
`multi_file_impact`, exact sources were ~103k but raw/shared/lexical relations
were ~169k. The v2 builder therefore keeps exact source and semantic relations,
excludes relations already classified as unrelated or superseded, and records
every budget exclusion.

## V2 contracts

### External research

- Input: specific unresolved external questions and spec identity.
- May: search official/primary sources.
- Output: source-to-claim mapping, authority, limitations and unresolved facts.
- Must not: inspect repository scope, decide a finding, plan a patch or write
  issue/PR prose.
- Web and repository content are untrusted data, never instructions.

### FindingEvidencePacket (deterministic Python)

- Input: normalized finding, applicable spec policy, case policy and repository
  analysis.
- Output: evidence catalog with stable IDs, trust levels, resolved relations,
  ambiguous relations, completeness, exclusions and canonical hashes.
- Exact target source and required declarations are never silently truncated.
- Lexical/unrelated relations are excluded before the LLM and remain visible in
  the selection report.

### Evidence extraction

- Input: evidence packet, applicable spec-family policy and external research.
- Output: claims (`confirmed|inferred|hypothesis|unknown`), predicate states,
  data flows and unresolved questions, all referencing evidence IDs.
- Must not: decide publication, plan edits, write code or issue prose.
- A confirmed claim without valid evidence IDs is rejected by Python.

### Adjudication

- Input: validated evidence extraction, completeness and case policy.
- Output: cause/scope/compatibility status, decision, blockers and supporting
  claim IDs.
- Previous model output is an untrusted structured interpretation; every
  retained conclusion must resolve to packet evidence.
- Python derives or rejects decisions covered by deterministic invariants.

### Patch planning

- Input: supported/review-only adjudication and exact allowed files.
- Output: required edits, target symbols, tests, behavior invariants and explicit
  generation/publication blockers.
- Must not write final code.

### Code generation

- Input: approved plan, exact sources and build constraints.
- Output: edits only.
- The applier rejects files outside the plan and unauthorized edit classes.

### Validation fix

- Input: compiler diagnostics, exact changed sources and exact related
  declarations.
- May repair compilation only; it cannot reopen the security decision.

### Issue and PR presentation

- Runs only after adjudication/generation status exists.
- Does not participate in evidence reasoning or consume its context budget.

## Evidence trust order

1. `runtime_observation`
2. `repository_exact_source`
3. `repository_semantic_relation`
4. `official_platform_doc` / `official_library_doc`
5. `primary_research`
6. `maintainer_statement`
7. `secondary_source`
8. `search_snippet`
9. `model_inference`

Absence is represented as `not_found_in_examined_scope`, `confirmed_absent` or
`unknown_due_to_incomplete_scope`; these states are not interchangeable.

## Versioned artifacts

Every v2 result records `prompt_version`, `schema_version`, `policy_version`,
`spec_version`, `context_builder_version`, `semantic_resolver_version` and
canonical input hashes. OpenAI traces contain request, response and metadata
files with stage, finding ID, parent call, usage, cache, latency and versions.

## Compatibility and baseline

- `--llm-architecture-version v1` preserves the legacy pipeline for evaluation.
- `v2` is the default after migration.
- Existing input JSONs remain accepted.
- Existing solution/evidence fields remain populated through a compatibility
  adapter; v2-native artifacts are added rather than silently replacing them.
- Human publication approval, conservative abstention, build validation and
  repository-scope checks remain mandatory.

## Evaluation

`evals/manifest.json` defines manually reviewed cases. The evaluator compares
v1/v2 on detector predicate accuracy, runtime-claim support, abstention,
unsafe-fix rate, scope, hallucinated APIs, build/tests, input/output/cache tokens,
latency and decision stability. Prompt/model tuning follows these evals rather
than preceding them.

## Migration notes

- Prompt trace v1 stored request-only JSONs. Trace v2 adds paired response and
  metadata artifacts; no credential fields are serialized.
- Evidence review v2 adds `architecture`, `evidence_packet`,
  `evidence_extraction`, `adjudication` and `patch_plan` while retaining the
  legacy `analysis` view consumed by downstream code.
- Specification v2 adds detector/API/security semantics and evidence
  requirements. The reader accepts v1 specifications and derives conservative
  unknown defaults; overwrite is required to regenerate an existing spec.
