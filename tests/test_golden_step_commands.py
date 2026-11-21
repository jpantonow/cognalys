"""The step commands of three real runs, rebuilt from their arguments.

Each fixture in tests/fixtures/golden_commands/ holds the top-level arguments
a real run was started with (decoded from its log by bash itself, since the
launcher prints them with printf %q) and the command every pipeline step
builds from them, with the interpreter written as PYTHON and the checkout as
ROOT. They were generated from the code at tag `pre-biblioteca`.

The library migration (docs/PLANO_BIBLIOTECA_PYTHON.md) moves every module;
this test is what says the pipeline still asks each step for the same thing.
A step that is meant to change regenerates its fixture, with the reason in
the commit, rather than having it edited by hand.
"""
import importlib.util
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: E402,F401  (scripts/ and src/ on sys.path)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "golden_commands"
MODULE_PATH = ROOT / "src" / "cognalys" / "orchestration" / "run_pipeline.py"
SPEC = importlib.util.spec_from_file_location("run_pipeline_golden", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

def canonical(argv, root: Path) -> list:
    """An argv with the machine-specific parts named."""
    out = []
    for part in argv:
        part = str(part)
        if part == sys.executable:
            part = "PYTHON"
        out.append(part.replace(f"{root}/", "ROOT/").replace(str(root), "ROOT"))
    return out


def rebuild(argv: list, csv_copy: Path) -> dict:
    """Every step's command for a run started with ``argv``.

    Two builders read the disk: repository_setup scopes itself to the
    projects the findings CSV names, and llm passes the migration policies
    only when that file exists. Both are laid out in a scratch root, from the
    CSV stored beside the fixture, so the test does not depend on outputs/.
    """
    with patch.object(sys, "argv", ["run_pipeline.py", *argv]):
        args = MODULE.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        csv_path = root / args.csv_file
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(csv_copy, csv_path)
        policies = root / "data" / "migration_policies.json"
        policies.parent.mkdir(parents=True, exist_ok=True)
        policies.write_text("{}", encoding="utf-8")
        # The run root had its specifications when these were recorded.
        (root / "data" / "specifications").mkdir()
        paths = MODULE.resolve_paths(args, root)
        steps = {}
        for step in MODULE.PIPELINE_STEPS:
            try:
                steps[step] = canonical(
                    MODULE.command_for_step(step, args, paths), root)
            except Exception as exc:  # noqa: BLE001 -- recorded, compared too
                steps[step] = [f"ERROR: {type(exc).__name__}"]
    return steps


_SOURCE_SCRIPT = re.compile(r"^ROOT/src/(\w+)/(\w+)\.py$")

# Step scripts that moved into the package (move_step_entry_points.py), and
# the four that were already facades of a package module.
_SCRIPT_MODULES = {
    "filtro_v3": "cognalys.corpus.filtro_v3",
    "import_rv_misuses": "cognalys.corpus.import_rv_misuses",
    "generate_specifications": "cognalys.specifications.generate_specifications",
    "enrich_spec_context": "cognalys.specifications.enrich_spec_context",
    "cleanup_pipeline": "cognalys.maintenance.cleanup_pipeline",
    "prune_unused_repositories": "cognalys.maintenance.prune_unused_repositories",
    "prepare_repository_branches": "cognalys.extraction.prepare_repository_branches",
    "propose_detector_rules": "cognalys.validation.propose_detector_rules",
    "generate_github_previews": "cognalys.prs.generate_github_previews",
    "run_apply": "cognalys.solutions.run_apply",
    "run_prs": "cognalys.prs.run_prs",
    "build_apks_no_proguard": "cognalys.builds.apk_build",
    "validate_applied_solutions": "cognalys.validation.applied_solutions",
    "repair_validation_failures": "cognalys.validation.repair",
    "fix_prs": "cognalys.prs.pr_feedback",
}
_STEP_SCRIPT = re.compile(r"^ROOT/scripts/(\w+)\.py$")
_BUILD_SCRIPT = ["--build-script", "ROOT/scripts/build_apks_no_proguard.py"]


def _without_build_script(command: list) -> list:
    out, index = [], 0
    while index < len(command):
        if command[index:index + 2] == _BUILD_SCRIPT:
            index += 2
            continue
        out.append(command[index])
        index += 1
    return out


def as_package_module(command: list) -> list:
    """A pre-migration command, as the cognalys package runs that step.

    The fixtures were recorded before the move. A step whose code lived in
    src/ was started as a file there (`ROOT/src/llm/generate_error_fixes.py`),
    and a step script as `ROOT/scripts/run_apply.py`; both now start a module
    of the package (`-m cognalys.llm.generate_error_fixes`, `-m
    cognalys.solutions.run_apply`). The build stage was also handed as a
    script path (`--build-script ROOT/scripts/build_apks_no_proguard.py`);
    the package now runs its own build stage, so that pair is dropped. Those
    are the only differences allowed: every other argument must be the same.
    """
    command = _without_build_script(command)
    if len(command) > 1:
        match = _SOURCE_SCRIPT.match(command[1])
        if match:
            return [command[0], "-m", f"cognalys.{match[1]}.{match[2]}", *command[2:]]
        match = _STEP_SCRIPT.match(command[1])
        if match and match[1] in _SCRIPT_MODULES:
            return [command[0], "-m", _SCRIPT_MODULES[match[1]], *command[2:]]
    return command


class GoldenStepCommandTests(unittest.TestCase):

    def _check(self, name: str) -> None:
        recorded = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        rebuilt = rebuild(recorded["argv"], FIXTURES / name.replace(".json", ".csv"))
        self.assertEqual(sorted(rebuilt), sorted(recorded["steps"]))
        for step, command in recorded["steps"].items():
            with self.subTest(step=step):
                self.assertEqual(rebuilt[step], as_package_module(command))

    def test_unanalysed_run_of_11_october(self):
        self._check("unanalysed_20261011.json")

    def test_relocated_findings_rerun(self):
        self._check("realocados_20261011.json")

    def test_pipeline_improvements_rerun(self):
        self._check("melhorias_20261011.json")


if __name__ == "__main__":
    unittest.main()
