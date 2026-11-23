"""Validation primitives for TraceVault canonical schemas."""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime
from typing import Any

from tracevault.schema.errors import InvalidTraceIdError, UnsafeTraceError

SCHEMA_VERSION = "1.0.0"
SUPPORTED_SCHEMA_MAJOR = 1

TRACE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")

DEFAULT_MAX_JSON_DEPTH = 64


def validate_trace_id(trace_id: str) -> str:
    """Validate a canonical trace identifier for charset, length, and path safety."""
    if not isinstance(trace_id, str):
        raise InvalidTraceIdError(f"trace_id must be a string, got {type(trace_id).__name__}")
    if not trace_id:
        raise InvalidTraceIdError("trace_id must not be empty")
    if (
        "\x00" in trace_id
        or "/" in trace_id
        or "\\" in trace_id
        or ".." in trace_id
        or "\n" in trace_id
        or "\r" in trace_id
    ):
        raise InvalidTraceIdError(
            f"trace_id contains forbidden path or control characters: {trace_id!r}"
        )
    if len(trace_id) > 128 or not TRACE_ID_PATTERN.fullmatch(trace_id):
        raise InvalidTraceIdError(f"trace_id {trace_id!r} must match {TRACE_ID_PATTERN.pattern}")
    return trace_id


def validate_json_safe(data: Any, *, max_depth: int = DEFAULT_MAX_JSON_DEPTH) -> Any:
    """Validate that data contains only JSON-safe primitives, finite floats, and bounded nesting."""
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 0:
        raise UnsafeTraceError("max_depth must be a non-negative integer")

    active_containers: set[int] = set()

    def _walk(value: Any, depth: int) -> None:
        if value is None or isinstance(value, (bool, str)):
            return
        if isinstance(value, int):
            return
        if isinstance(value, float):
            if not math.isfinite(value):
                raise UnsafeTraceError(f"Non-finite float value is not JSON-safe: {value!r}")
            return
        if isinstance(value, (list, tuple)):
            next_depth = depth + 1
            if next_depth > max_depth:
                raise UnsafeTraceError(f"JSON nesting depth exceeds maximum allowed ({max_depth})")
            obj_id = id(value)
            if obj_id in active_containers:
                raise UnsafeTraceError("Cyclic container reference detected in trace data")
            active_containers.add(obj_id)
            try:
                for item in value:
                    _walk(item, next_depth)
            finally:
                active_containers.discard(obj_id)
            return
        if isinstance(value, dict):
            next_depth = depth + 1
            if next_depth > max_depth:
                raise UnsafeTraceError(f"JSON nesting depth exceeds maximum allowed ({max_depth})")
            obj_id = id(value)
            if obj_id in active_containers:
                raise UnsafeTraceError("Cyclic container reference detected in trace data")
            active_containers.add(obj_id)
            try:
                for key, item in value.items():
                    if not isinstance(key, str):
                        raise UnsafeTraceError(
                            f"JSON object keys must be strings, got {type(key).__name__}"
                        )
                    _walk(item, next_depth)
            finally:
                active_containers.discard(obj_id)
            return
        raise UnsafeTraceError(
            f"Unsupported non-JSON-safe type in trace data: {type(value).__name__}"
        )

    _walk(data, 0)
    return data


def validate_schema_version(version: str) -> str:
    """Validate SemVer format and major-version compatibility."""
    if (
        not isinstance(version, str)
        or "\n" in version
        or "\r" in version
        or not SEMVER_PATTERN.fullmatch(version)
    ):
        raise UnsafeTraceError(
            f"Invalid schema_version {version!r}: expected SemVer 'MAJOR.MINOR.PATCH'"
        )
    major = int(version.split(".", 1)[0])
    if major != SUPPORTED_SCHEMA_MAJOR:
        raise UnsafeTraceError(
            f"Unsupported schema_version {version!r}: major version {major} "
            f"does not match supported major version {SUPPORTED_SCHEMA_MAJOR}"
        )
    return version


def ensure_utc_datetime(dt: datetime) -> datetime:
    """Validate that a datetime is timezone-aware and normalize it to UTC."""
    if not isinstance(dt, datetime):
        raise ValueError(f"Expected datetime, got {type(dt).__name__}")
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("Datetime must be timezone-aware (naive datetimes are rejected)")
    return dt.astimezone(UTC)


def validate_finite_float(value: float) -> float:
    """Ensure a floating-point value is finite (not NaN or Infinity)."""
    if not math.isfinite(value):
        raise UnsafeTraceError(f"Non-finite float value is not allowed: {value!r}")
    return value


def validate_fingerprint(fingerprint: str) -> str:
    """Ensure a fixture fingerprint is a 64-character lowercase hexadecimal SHA-256 digest."""
    if (
        not isinstance(fingerprint, str)
        or "\n" in fingerprint
        or "\r" in fingerprint
        or not FINGERPRINT_PATTERN.fullmatch(fingerprint)
    ):
        raise ValueError("fingerprint must be a 64-character lowercase hexadecimal SHA-256 digest")
    return fingerprint


__all__ = [
    "SCHEMA_VERSION",
    "SUPPORTED_SCHEMA_MAJOR",
    "TRACE_ID_PATTERN",
    "SEMVER_PATTERN",
    "FINGERPRINT_PATTERN",
    "DEFAULT_MAX_JSON_DEPTH",
    "validate_trace_id",
    "validate_json_safe",
    "validate_schema_version",
    "ensure_utc_datetime",
    "validate_finite_float",
    "validate_fingerprint",
]
