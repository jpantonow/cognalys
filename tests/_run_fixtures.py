"""A run directory as the pipeline writes it, for tests that read one back."""
import json
from pathlib import Path

KEY = ("app.example_1.apk", "org.example.Hasher", "digest", "MessageDigestSpec")


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def run_directory(root: Path) -> Path:
    """A run with one analysed finding whose fix built and was committed."""
    run = root / "outputs" / "run_x"
    apk, csv_class, method, spec = KEY
    write(run / "error_methods" / apk / f"0_{method}.json", {
        "extraction_metadata": {"apk_name": apk, "csv_index": 0,
                                "extraction_status": "success"},
        "error": {"csv_class": csv_class, "csv_method": method, "spec": spec},
        "source_code": {"method_body": "byte[] digest() {}"},
    })
    write(run / "error_solutions" / "evidence_reviews" / apk / f"0_{method}_evidence.json", {
        "apk_name": apk, "csv_class": csv_class, "method_name": method, "spec": spec,
        "analysis": {"decision": "MULTI_FILE_FIX_PROPOSED_FOR_REVIEW",
                     "detector_violation": "confirmed"},
    })
    write(run / "error_solutions" / apk / f"0_{method}_solution.json", {})
    write(run / "application_results" / "execution_report.json", {"per_solution_details": [{
        "apk_name": apk, "csv_class": csv_class, "method_name": method, "spec": spec,
        "status": "SUCCESS", "build_validation": {"status": "success"},
    }]})
    write(run / "pull_requests" / f"{apk}_{method}_pr.json", {
        "csv_class": csv_class, "method_name": method, "spec": spec,
        "title": "Use SHA-256", "commit_hash": "abc123", "diff": "+a\n-b\n",
    })
    return run
