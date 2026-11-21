"""Import paths for the test suite, set once (`import _paths` in each test).

The pipeline is the cognalys package under src/, put on the path here so
the suite runs from a checkout whether or not the package is installed.

A module rather than a conftest.py: the documented command and CI run the
suite with `python -m unittest discover -s tests`, which never reads a
conftest. Both runners put tests/ itself on the path, so `import _paths`
resolves under either.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# The cognalys command reads the workspace's .env.* files; tests that call
# it must not pick up the developer's real token and git author.
os.environ["COGNALYS_NO_CREDENTIAL_FILES"] = "1"
# A pipeline run records the library's identity (run_status.py), which reads
# every source file; the tests that run the pipeline record this one instead.
os.environ.setdefault("COGNALYS_LIBRARY_IDENTITY", "test-suite")

_SRC = str(ROOT / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
