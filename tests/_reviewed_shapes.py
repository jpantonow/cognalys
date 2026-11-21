"""The shipped specifications as if their false-positive shapes were reviewed.

A deterministic false-positive trigger resolves only for a specification
whose shapes went through the shape review (P14), and no stored
specification carries that stamp yet. Tests of the trigger routes
themselves (the curated message, the unmodelled call) stamp the shipped
data here instead of depending on which specifications were reviewed.
"""
from contextlib import contextmanager
from copy import deepcopy
from unittest.mock import patch

import _paths  # noqa: F401  (project import paths)

from cognalys.llm import false_positive_rules as fp

STAMP = {"version": 1, "moved": []}


def stamped(specification: dict) -> dict:
    """A copy of `specification` carrying the shape-review stamp."""
    specification = deepcopy(specification or {})
    evidence = specification.setdefault("generation_evidence", {})
    evidence["false_positive_shape_review"] = dict(STAMP)
    return specification


@contextmanager
def reviewed_false_positive_shapes():
    """Rebuild the trigger tables from stamped copies of the shipped specifications."""
    shipped = fp._specification
    with patch.object(fp, "_specification", lambda spec_id: stamped(shipped(spec_id))):
        tables = {
            "KNOWN_FALSE_POSITIVE_MESSAGES": fp._curated_messages(),
            "UNMODELLED_CALL_SHAPES": fp._unmodelled_call_shapes(),
        }
    with patch.multiple(fp, **tables):
        yield
