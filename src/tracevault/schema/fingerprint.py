"""Deterministic canonical JSON serialization and SHA-256 request fingerprinting."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from tracevault.schema.errors import UnsafeTraceError
from tracevault.schema.models import BoundaryType
from tracevault.schema.validation import validate_json_safe


def canonical_json(data: Any) -> str:
    """Serialize JSON-safe data deterministically with sorted keys and compact separators."""
    validate_json_safe(data)
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def compute_fingerprint(boundary: BoundaryType | str, request: dict[str, Any]) -> str:
    """Compute a deterministic 64-char lowercase SHA-256 hex digest for a boundary request."""
    if isinstance(boundary, BoundaryType):
        boundary_str = boundary.value
    elif isinstance(boundary, str) and boundary:
        boundary_str = boundary
    else:
        raise UnsafeTraceError(
            f"boundary must be a BoundaryType or non-empty str, got {boundary!r}"
        )

    if not isinstance(request, dict):
        raise UnsafeTraceError(f"request must be a dict, got {type(request).__name__}")

    serialized = canonical_json({"boundary": boundary_str, "request": request})
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


__all__ = [
    "canonical_json",
    "compute_fingerprint",
]
