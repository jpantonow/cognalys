import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import _paths  # noqa: E402,F401  (project import paths)

from cognalys.solutions.solution_applicator import (  # noqa: E402
    validate_coordinated_edit_authorization,
)


class PatchPlanAuthorizationTests(unittest.TestCase):
    def _solution(self):
        return {
            "llm_architecture": {"version": "v2"},
            "authorized_patch_plan": {"required_edits": [{
                "source_file_path": "src/A.java", "symbol": "A",
                "create_new_file": False, "edit_category": "implementation",
            }]},
            "coordinated_edits": [{
                "source_file_path": "src/A.java", "edit_kind": "method",
            }],
        }

    def test_authorized_edit_is_accepted(self):
        self.assertEqual(validate_coordinated_edit_authorization(self._solution()), [])

    def test_path_outside_plan_is_rejected(self):
        solution = self._solution()
        solution["coordinated_edits"][0]["source_file_path"] = "src/B.java"
        self.assertIn(
            "EDIT_OUTSIDE_AUTHORIZED_PLAN:src/B.java",
            validate_coordinated_edit_authorization(solution),
        )

    def test_unplanned_creation_and_sensitive_config_are_rejected(self):
        solution = self._solution()
        solution["authorized_patch_plan"]["required_edits"][0].update({
            "source_file_path": "build.gradle", "edit_category": "implementation",
        })
        solution["coordinated_edits"][0].update({
            "source_file_path": "build.gradle", "edit_kind": "create",
        })
        issues = validate_coordinated_edit_authorization(solution)
        self.assertTrue(any("UNAUTHORIZED_FILE_CREATION" in issue for issue in issues))
        self.assertTrue(any("SENSITIVE_FILE_CATEGORY" in issue for issue in issues))

    def test_legacy_solution_remains_compatible(self):
        self.assertEqual(validate_coordinated_edit_authorization({
            "coordinated_edits": [{"source_file_path": "anything"}]
        }), [])


if __name__ == "__main__":
    unittest.main()
