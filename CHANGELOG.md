# Changelog

The public API is what `cognalys.api` and `cognalys.models` export and the
`cognalys` command. Versions follow semantic versioning from 1.0; before it,
a minor version may change that API, and this file says how.

## Unreleased

### Added
- `cognalys --version`; the package ships `py.typed`.
- `--fail-on` for `run` and `results`: exit 1 when a finding reaches the
  given outcome, for CI.
- `cognalys cache info|clear`: the LLM, web-research and baseline-build caches.
- `cognalys diff RUN` and `cognalys apply RUN --finding ID`: a run's patches as
  files, or applied to your own checkout; `--include-unsafe` for corrections
  marked for review.
- `cognalys review RUN`: go through a run's corrections one by one and approve
  (publish or apply), reject or skip.
- Pull request text a maintainer can read: the summary (now `--pr-issue-style
  v2` by default) also writes the title; the commit message is that title;
  publication is refused while the title or body still carries evidence ids,
  the pipeline's vocabulary or a "Fix <method>" title (`--allow-text-problems`).
- One pull request per change: a pull request whose every change another one
  makes is superseded and not published; of two that rewrite the same method
  or lines, only the first is.

## 0.1.0 — 2026-10-12

First version as a package.

### Added
- The `cognalys` package (src layout) and the `cognalys` command: `plan`, `run`,
  `scan`, `propose-prs`, `results`, `doctor`, `check`, `template`, `init`,
  `publish`, `rvsec-import`.
- `cognalys.api`: `plan`, `run`, `run_directory`, `load_results`, `scan`,
  `repair_repository`; `cognalys.models`: `Finding`, `RunConfig`, `Step`,
  `FindingResult`, `RunResult`.
- Findings from CSV, JSON Lines, JSON, SARIF, Semgrep `--json` and RVSec's
  `errors.csv`; common column names; findings by file and line; several files
  per run.
- Run files (`cognalys run minha_run.toml`), `--run-dir`, `cognalys.toml`.
- Deterministic gates against patches that rewrite existing test
  expectations, change a stored or transmitted derived value, or undo a
  security warning the maintainer suppressed.
