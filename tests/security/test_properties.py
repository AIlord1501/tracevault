"""Hypothesis property-based tests for TraceVault schema security invariants."""

from __future__ import annotations

import re
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from conftest import make_valid_run, make_valid_trace
from tracevault.schema import (
    BoundaryType,
    InvalidTraceIdError,
    Trace,
    compute_fingerprint,
    redact_data,
    validate_trace_id,
)

VALID_TRACE_ID_REGEX = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")

# JSON-safe recursive strategy bounded well within DEFAULT_MAX_JSON_DEPTH (64).
JSON_PRIMITIVES = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.floats(allow_nan=False, allow_infinity=False, width=64),
    st.text(max_size=40),
)

JSON_VALUES: st.SearchStrategy[Any] = st.recursive(
    JSON_PRIMITIVES,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(max_size=20), children, max_size=5),
    ),
    max_leaves=25,
)

JSON_DICTS: st.SearchStrategy[dict[str, Any]] = st.dictionaries(
    st.text(max_size=20), JSON_VALUES, max_size=8
)

VALID_TRACE_ID_STRATEGY = st.from_regex(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", fullmatch=True)


@settings(max_examples=150)
@given(trace_id=VALID_TRACE_ID_STRATEGY)
def test_property_validate_trace_id_accepts_all_valid_ids(trace_id: str) -> None:
    """Every string matching ^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$ is accepted."""
    assert validate_trace_id(trace_id) == trace_id


@settings(max_examples=150)
@given(candidate=st.text(max_size=160))
def test_property_validate_trace_id_matches_canonical_regex(candidate: str) -> None:
    """validate_trace_id accepts iff candidate matches the exact ASCII canonical pattern."""
    if VALID_TRACE_ID_REGEX.fullmatch(candidate):
        assert validate_trace_id(candidate) == candidate
    else:
        with pytest.raises(InvalidTraceIdError):
            validate_trace_id(candidate)


@settings(max_examples=100)
@given(
    boundary=st.sampled_from(list(BoundaryType)),
    items=st.lists(
        st.tuples(st.text(max_size=20), JSON_VALUES),
        min_size=1,
        max_size=10,
        unique_by=lambda kv: kv[0],
    ),
    data=st.data(),
)
def test_property_compute_fingerprint_deterministic_across_key_orders(
    boundary: BoundaryType,
    items: list[tuple[str, Any]],
    data: st.DataObject,
) -> None:
    """compute_fingerprint is invariant to dictionary key insertion order."""
    permuted = data.draw(st.permutations(items))
    dict_a = dict(items)
    dict_b = dict(permuted)

    fp_a = compute_fingerprint(boundary, dict_a)
    fp_b = compute_fingerprint(boundary, dict_b)
    assert fp_a == fp_b
    assert len(fp_a) == 64
    assert fp_a == fp_a.lower()


@settings(max_examples=100)
@given(payload=JSON_VALUES)
def test_property_redact_data_is_idempotent(payload: Any) -> None:
    """Applying redact_data twice yields the exact same result as applying it once."""
    once = redact_data(payload)
    twice = redact_data(once)
    assert twice == once


@settings(max_examples=75)
@given(
    trace_id=VALID_TRACE_ID_STRATEGY,
    frozen=st.booleans(),
    inputs=JSON_DICTS,
    outputs=JSON_DICTS,
    metadata=JSON_DICTS,
    tags=st.lists(
        st.text(min_size=1, max_size=20).filter(lambda s: bool(s.strip())),
        max_size=5,
    ),
)
def test_property_trace_json_round_trip(
    trace_id: str,
    frozen: bool,
    inputs: dict[str, Any],
    outputs: dict[str, Any],
    metadata: dict[str, Any],
    tags: list[str],
) -> None:
    """Any valid Trace round-trips cleanly through to_json() and from_json()."""
    trace = make_valid_trace(
        trace_id=trace_id,
        frozen=frozen,
        runs=[
            make_valid_run(
                trace_id=trace_id,
                inputs=inputs,
                outputs=outputs,
                tags=tags,
                metadata=metadata,
            )
        ],
        metadata=metadata,
    )
    restored = Trace.from_json(trace.to_json())
    assert restored == trace
