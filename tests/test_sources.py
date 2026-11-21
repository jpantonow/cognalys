import csv
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


import _paths  # noqa: E402,F401  (project import paths)

from cognalys import api  # noqa: E402
from cognalys.extraction.extract_methods_single_csv import SingleCsvMethodExtractor  # noqa: E402
from cognalys.models import Finding, RunConfig  # noqa: E402
from cognalys.orchestration import run_pipeline  # noqa: E402
from cognalys.reporting.finding_statistics import read_findings  # noqa: E402
from cognalys.sources import SOURCE_PROBLEM, read_rows, write_rows  # noqa: E402
from cognalys.utils.corpus_rows import row_problems  # noqa: E402

FINDING = Finding(
    apk="org.example.notes_13.apk",
    class_name="org.example.PinTab",
    method="getHashedPin",
    spec="MessageDigestSpec",
    message="expecting one of SHA-256 but found SHA-1",
    repo_url="https://github.com/example/notes",
    commit="0a9e080f9cc5e1f62af5545f06abd9f154341f21",
    tool="ape",
    detector={"code": "MESSAGEDIGEST-ALG-02", "label": "violation"},
    extra={"rep": "1", "timeout": "300", "time": "297"},
)


def _write_csv(path: Path, rows: list[dict]) -> Path:
    columns = list(dict.fromkeys(key for row in rows for key in row))
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    return path


class SourceEquivalenceTests(unittest.TestCase):
    """The same finding from a CSV, a JSON Lines file, a JSON array or a
    Python list reaches the steps as the same row."""

    def _sources(self, directory: str) -> dict[str, Path]:
        root = Path(directory)
        row = FINDING.to_row()
        (root / "findings.json").write_text(json.dumps([row]), encoding="utf-8")
        return {
            "csv": _write_csv(root / "findings.csv", [row]),
            "jsonl": write_rows([FINDING], root / "findings.jsonl"),
            "json": root / "findings.json",
        }

    def test_every_format_reads_as_the_same_row(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = {name: read_rows(path) for name, path in self._sources(directory).items()}
        self.assertEqual(rows["csv"], rows["jsonl"])
        self.assertEqual(rows["csv"], rows["json"])
        self.assertEqual(rows["csv"][0]["detector_code"], "MESSAGEDIGEST-ALG-02")
        self.assertEqual(row_problems(rows["jsonl"][0]), [])

    def test_the_extractor_loads_the_same_rows_from_each_format(self):
        loaded = {}
        with tempfile.TemporaryDirectory() as directory:
            for name, path in self._sources(directory).items():
                extractor = SingleCsvMethodExtractor(
                    output_dir=str(Path(directory) / "out"),
                    methods_output_dir=str(Path(directory) / "methods"),
                )
                self.assertTrue(extractor.read_csv(str(path)))
                loaded[name] = (extractor.rows, extractor.apk_urls)
        self.assertEqual(loaded["csv"], loaded["jsonl"])
        self.assertEqual(loaded["csv"], loaded["json"])

    def test_steps_that_scope_by_project_and_statistics_read_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._sources(directory)["jsonl"]
            self.assertEqual(run_pipeline.csv_project_names(path), [FINDING.apk])
            self.assertEqual(list(read_findings(path)), [FINDING.key])

    def test_an_unreadable_record_is_reported_not_dropped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.jsonl"
            path.write_text(json.dumps(FINDING.to_row()) + "\n{not json\n[1, 2]\n",
                            encoding="utf-8")
            rows = read_rows(path)
        self.assertEqual(len(rows), 3)
        self.assertEqual(row_problems(rows[0]), [])
        self.assertIn("line 2 is not JSON", row_problems(rows[1])[0])
        self.assertEqual(row_problems(rows[2]), ["record is a list, not an object"])
        self.assertIn(SOURCE_PROBLEM, rows[2])

    def test_findings_is_an_alias_of_csv_file(self):
        config = RunConfig.from_legacy_args(["--llm-provider", "openai", "--findings", "x.jsonl"])
        self.assertEqual(config.namespace().csv_file, "x.jsonl")


class ColumnMapTests(unittest.TestCase):
    """A findings CSV exported by another tool, with its own column names."""

    MAP = {"apk": "package", "class": "className", "method": "methodName",
           "spec": "rule", "repo_url": "repository"}

    def _foreign_csv(self, root: Path, extra_line: str = "") -> Path:
        path = root / "foreign.csv"
        path.write_text(
            "package,className,methodName,rule,repository,severity\n"
            "org.example.notes_13.apk,org.example.PinTab,getHashedPin,"
            "MessageDigestSpec,https://github.com/example/notes,high\n" + extra_line,
            encoding="utf-8")
        (root / "map.json").write_text(json.dumps(self.MAP), encoding="utf-8")
        return path

    def test_a_mapped_file_is_converted_once_into_the_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self._foreign_csv(root)
            args = run_pipeline.parse_args(["--llm-provider", "openai", 
                "--csv-file", "foreign.csv", "--column-map", "map.json",
                "--extracted-methods-dir", "outputs/run_z/error_methods",
            ])
            written = run_pipeline.materialize_mapped_findings(args, root)
            [row] = read_rows(written)
        self.assertEqual(written, root / "outputs" / "run_z" / "findings.jsonl")
        self.assertEqual((row["apk"], row["class"], row["method"], row["spec"]),
                         FINDING.key)
        self.assertEqual(row["repo_url"], "https://github.com/example/notes")
        self.assertEqual(row["severity"], "high")
        self.assertEqual(row_problems(row), [])

    def test_a_shifted_row_keeps_its_problem_through_the_conversion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self._foreign_csv(root, "a.apk,C,m,S,https://x,high,surplus\n")
            args = run_pipeline.parse_args(["--llm-provider", "openai", 
                "--csv-file", "foreign.csv", "--column-map", "map.json",
                "--extracted-methods-dir", "outputs/run_z/error_methods",
            ])
            rows = read_rows(run_pipeline.materialize_mapped_findings(args, root))
        self.assertEqual(row_problems(rows[0]), [])
        self.assertEqual(row_problems(rows[1]), ["1 more field(s) than the header"])


class RunWithFindingsTests(unittest.TestCase):

    def test_a_list_of_findings_reaches_the_run_as_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            seen = {}

            def fake_main(argv):
                args = run_pipeline.parse_args(["--llm-provider", "openai", *argv])
                seen["csv_file"] = args.csv_file
                seen["rows"] = read_rows(args.csv_file)
                return 0

            config = RunConfig.from_legacy_args(
                ["--llm-provider", "openai", "--extracted-methods-dir", "outputs/run_y/error_methods"])
            with patch.object(run_pipeline, "main", side_effect=fake_main), \
                    patch.dict(os.environ, {}):
                api.run(config, workspace=root, findings=[FINDING])

        self.assertEqual(seen["csv_file"], str(root / "outputs" / "run_y" / "findings.jsonl"))
        self.assertEqual(seen["rows"], [{key: str(value) for key, value in FINDING.to_row().items()}])


if __name__ == "__main__":
    unittest.main()
