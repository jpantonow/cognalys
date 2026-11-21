# Cognalys

Cognalys is a Python library and command-line tool that complements
[RVSec](https://github.com/PAMunb/rvsec) (RV4Android). RVSec runs Android apps
and reports cryptographic API misuses at runtime; Cognalys takes each finding
from the runtime report to a reviewable contribution:

1. maps the reported (bytecode) method back to the source revision of the APK;
2. decides, with repository evidence, whether the violation is real and whether
   a fix keeps the application's behavior (abstaining is a valid outcome);
3. plans, drafts, and reviews a patch under deterministic checks;
4. carries it to the tip of the target branch and builds it;
5. writes the pull-request or issue text, and publishes only after a person
   approves that specific finding.

Model stages run under versioned schemas; deterministic validators reject
unsupported claims, incomplete plans, known unsafe change shapes, and text that
describes edits absent from the diff.

The study that evaluates Cognalys (data, pre-registrations, results) is in
[cognalys-artefacts](https://github.com/jpantonow/cognalys-artefacts).

## Install

Python 3.10 or later. Linux or WSL is recommended (builds use Gradle and the
Android SDK; RVSec runs use Docker and an emulator).

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # add ,anthropic for the Anthropic provider
cp .env.example .env              # then fill in OPENAI_API_KEY (or ANTHROPIC_API_KEY)
```

`GITHUB_TOKEN` is only needed to publish approved pull requests or issues and to
collect maintainer responses.

## Use

```bash
cognalys init                      # write a starter configuration
cognalys doctor                    # check the environment
cognalys scan ...                  # produce findings from a repository
cognalys run ...                   # analyze findings and prepare patches
cognalys results / cost / diff     # inspect outcomes, cost, patches
cognalys review / apply            # review or apply a prepared patch
cognalys propose-prs ...           # publish an approved finding (human approval required)
cognalys pr-outcomes               # refresh maintainer responses
```

Run `cognalys <command> --help` for options. Findings can also be imported from
CSV, JSON, SARIF, or Semgrep output; RVSec reports are imported directly.

## Tests

```bash
PYTHONPATH=src python -m pytest -q tests
```

## License

MIT (see `LICENSE`).
