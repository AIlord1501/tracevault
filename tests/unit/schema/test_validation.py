"""Tests for schema validation primitives."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from tracevault.schema import (
    InvalidTraceIdError,
    UnsafeTraceError,
    ensure_utc_datetime,
    validate_fingerprint,
    validate_finite_float,
    validate_json_safe,
    validate_schema_version,
    validate_trace_id,
)


@pytest.mark.parametrize(
    "valid_id",
    [
        "a",
        "0",
        "tr_9f8e7d6c5b4a3210",
        "Trace-01_ABC",
        "A" + "b" * 127,
    ],
)
def test_validate_trace_id_accepts_valid_ids(valid_id: str) -> None:
    assert validate_trace_id(valid_id) == valid_id


@pytest.mark.parametrize(
    "invalid_id",
    [
        "",
        " ",
        "-starts-with-dash",
        "_starts-with-underscore",
        "../escape",
        "a/b",
        "a\\b",
        "a..b",
        "abc\x00def",
        "abc\n",
        "abc\r",
        "has space",
        "has.dot",
        "A" * 129,
        123,
        None,
    ],
)
def test_validate_trace_id_rejects_invalid_ids(invalid_id: Any) -> None:
    with pytest.raises(InvalidTraceIdError):
        validate_trace_id(invalid_id)


def test_validate_json_safe_accepts_primitives_and_nested_structures() -> None:
    shared = {"k": [1, 2, 3]}
    payload = {
        "none": None,
        "bool": True,
        "int": 42,
        "float": 3.14,
        "str": "hello",
        "list": [1, "two", (3, 4)],
        "shared_a": shared,
        "shared_b": shared,
    }
    assert validate_json_safe(payload) is payload


@pytest.mark.parametrize(
    "bad_value",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        {"nested": [float("nan")]},
        {1: "non-string-key"},
        b"bytes",
        {1, 2, 3},
        object(),
        datetime.now(UTC),
    ],
)
def test_validate_json_safe_rejects_unsafe_values(bad_value: Any) -> None:
    with pytest.raises(UnsafeTraceError):
        validate_json_safe(bad_value)


def test_validate_json_safe_enforces_max_depth() -> None:
    nested: Any = "leaf"
    for _ in range(64):
        nested = [nested]
    assert validate_json_safe(nested, max_depth=64) is nested

    too_deep = [nested]
    with pytest.raises(UnsafeTraceError, match="depth"):
        validate_json_safe(too_deep, max_depth=64)

    with pytest.raises(UnsafeTraceError):
        validate_json_safe([1], max_depth=0)

    with pytest.raises(UnsafeTraceError):
        validate_json_safe(1, max_depth=-1)


def test_validate_json_safe_detects_cyclic_list_and_dict() -> None:
    cyclic_list: list[Any] = []
    cyclic_list.append(cyclic_list)
    with pytest.raises(UnsafeTraceError, match="Cyclic"):
        validate_json_safe(cyclic_list)

    cyclic_dict: dict[str, Any] = {}
    cyclic_dict["self"] = cyclic_dict
    with pytest.raises(UnsafeTraceError, match="Cyclic"):
        validate_json_safe(cyclic_dict)


@pytest.mark.parametrize("version", ["1.0.0", "1.2.3", "1.99.0"])
def test_validate_schema_version_accepts_major_1(version: str) -> None:
    assert validate_schema_version(version) == version


@pytest.mark.parametrize(
    "bad_version",
    ["0.9.0", "2.0.0", "1.0", "1.0.0-alpha", "v1.0.0", "1.0.0\n", "", 100],
)
def test_validate_schema_version_rejects_invalid_or_incompatible(bad_version: Any) -> None:
    with pytest.raises(UnsafeTraceError):
        validate_schema_version(bad_version)


def test_ensure_utc_datetime_normalizes_aware_and_rejects_naive() -> None:
    tz_plus_5 = timezone(timedelta(hours=5))
    dt = datetime(2026, 11, 24, 5, 30, 0, tzinfo=tz_plus_5)
    normalized = ensure_utc_datetime(dt)
    assert normalized.tzinfo == UTC
    assert normalized == datetime(2026, 11, 24, 0, 30, 0, tzinfo=UTC)

    naive = datetime(2026, 11, 24, 0, 0, 0)
    with pytest.raises(ValueError, match="timezone-aware"):
        ensure_utc_datetime(naive)


def test_validate_finite_float_and_fingerprint() -> None:
    assert validate_finite_float(0.5) == 0.5
    with pytest.raises(UnsafeTraceError):
        validate_finite_float(float("inf"))

    valid_fp = "a" * 64
    assert validate_fingerprint(valid_fp) == valid_fp
    for bad_fp in ("a" * 63, "A" * 64, "g" * 64, "a" * 64 + "\n"):
        with pytest.raises(ValueError):
            validate_fingerprint(bad_fp)
