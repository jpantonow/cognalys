"""A findings row whose columns shifted is kept aside, not analysed.

A backslash-escaped quote in a findings CSV is read without error and
shifts every later column; one such row read as spec="35" (its `time`
value). These tests parse real CSV text so the shift happens the way it
does in the corpus, rather than being simulated with a hand-built dict.
"""
import csv
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.utils.corpus_rows import INPUT_INVALID, invalid_row_record, row_problems  # noqa: E402

HEADER = "priority,reason,apk,rep,timeout,tool,time,spec,class,method\n"


def _rows(text: str):
    return list(csv.DictReader(io.StringIO(HEADER + text)))


class RowProblemTests(unittest.TestCase):

    def test_a_well_formed_row_has_no_problem(self):
        row = _rows('2,"uses ""TLS"", not TLSv1.2",app_1.apk,1,180,ape,35,'
                    'SSLContextSpec,app.Net,connect\n')[0]
        self.assertEqual(row_problems(row), [])
        self.assertEqual(row["spec"], "SSLContextSpec")

    def test_a_backslash_escaped_quote_is_caught(self):
        row = _rows('2,"getInstance(\\"TLS\\") is weak, and more",app_1.apk,'
                    '1,180,ape,35,SSLContextSpec,app.Net,connect\n')[0]
        problems = row_problems(row)
        self.assertTrue(problems)
        self.assertTrue(any("backslash" in problem for problem in problems))

    def test_a_short_row_is_caught(self):
        row = _rows("2,reason,app_1.apk,1\n")[0]
        self.assertIn("fewer field", " ".join(row_problems(row)))

    def test_a_non_numeric_time_is_caught_without_a_backslash(self):
        row = _rows("2,reason,app_1.apk,1,180,ape,slow,Spec,app.C,m\n")[0]
        problems = row_problems(row)
        self.assertEqual(len(problems), 1)
        self.assertIn("time column", problems[0])

    def test_a_backslash_alone_is_not_a_problem(self):
        # Messages legitimately contain backslashes (regexes, paths).
        row = _rows('2,"matches \\\\d+ here",app_1.apk,1,180,ape,35,Spec,'
                    'app.C,m\n')[0]
        self.assertEqual(row_problems(row), [])


class RecordTests(unittest.TestCase):

    def test_the_record_keeps_the_original_values(self):
        row = _rows("2,reason,app_1.apk,1,180,ape,35,Spec,app.C,m,EXTRA\n")[0]
        record = invalid_row_record(4, row, row_problems(row))
        self.assertEqual(record["reason"], INPUT_INVALID)
        self.assertEqual(record["row_index"], 4)
        self.assertEqual(record["original_row"]["__extra_fields__"], ["EXTRA"])
        self.assertEqual(record["original_row"]["spec"], "Spec")


if __name__ == "__main__":
    unittest.main()
