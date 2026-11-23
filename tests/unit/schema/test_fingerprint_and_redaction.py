"""Tests for canonical JSON fingerprinting and idempotent secret redaction."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from tracevault.schema import (
    REDACTED_VALUE,
    BoundaryType,
    RedactionConfig,
    UnsafeTraceError,
    canonical_json,
    compute_fingerprint,
    redact_data,
)


def test_canonical_json_is_deterministic_and_compact() -> None:
    a = {"b": 1, "a": [3, 2, {"y": "café", "x": True}]}
    b = {"a": [3, 2, {"x": True, "y": "café"}], "b": 1}
    assert canonical_json(a) == canonical_json(b)
    assert canonical_json(a) == '{"a":[3,2,{"x":true,"y":"café"}],"b":1}'


def test_canonical_json_rejects_unsafe_values() -> None:
    with pytest.raises(UnsafeTraceError):
        canonical_json({"bad": float("nan")})
    with pytest.raises(UnsafeTraceError):
        canonical_json({1: "int-key"})


def test_compute_fingerprint_determinism_and_boundary_separation() -> None:
    req1 = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
    req2 = {"messages": [{"content": "hi", "role": "user"}], "model": "gpt-4o-mini"}

    fp1 = compute_fingerprint(BoundaryType.MODEL, req1)
    fp2 = compute_fingerprint("model", req2)
    fp_tool = compute_fingerprint(BoundaryType.TOOL, req1)

    assert fp1 == fp2
    assert len(fp1) == 64
    assert fp1 == fp1.lower()
    assert fp1 != fp_tool


def test_compute_fingerprint_rejects_invalid_inputs() -> None:
    with pytest.raises(UnsafeTraceError):
        compute_fingerprint("", {"a": 1})
    with pytest.raises(UnsafeTraceError):
        compute_fingerprint(BoundaryType.MODEL, ["not-a-dict"])  # type: ignore[arg-type]


def test_redact_data_sensitive_keys_and_synthetic_patterns() -> None:
    synthetic_sk = "sk-TESTPLACEHOLDER0123456789"
    synthetic_aws = "AKIAIOSFODNN7EXAMPLE"
    synthetic_gh = "ghp_0123456789abcdefghij012345"
    synthetic_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signatureplaceholder"
    synthetic_bearer = "Bearer synthetic-token-value-123"

    payload = {
        "api_key": "synthetic-key-val",
        "X-API-Key": "synthetic-header-val",
        "Authorization": synthetic_bearer,
        "OPENAI_API_KEY": synthetic_sk,
        "nested": {
            "user_password": "synthetic-password",
            "safe": "hello world",
            "items": [
                f"key={synthetic_sk}",
                f"aws={synthetic_aws}",
                f"gh={synthetic_gh}",
                f"jwt={synthetic_jwt}",
                f"hdr={synthetic_bearer}",
            ],
            "tuple_val": (synthetic_sk, 42, True, None),
        },
    }

    redacted = redact_data(payload)
    assert redacted["api_key"] == REDACTED_VALUE
    assert redacted["X-API-Key"] == REDACTED_VALUE
    assert redacted["Authorization"] == REDACTED_VALUE
    assert redacted["OPENAI_API_KEY"] == REDACTED_VALUE
    assert redacted["nested"]["user_password"] == REDACTED_VALUE
    assert redacted["nested"]["safe"] == "hello world"
    assert redacted["nested"]["items"] == [
        f"key={REDACTED_VALUE}",
        f"aws={REDACTED_VALUE}",
        f"gh={REDACTED_VALUE}",
        f"jwt={REDACTED_VALUE}",
        f"hdr={REDACTED_VALUE}",
    ]
    assert redacted["nested"]["tuple_val"] == (REDACTED_VALUE, 42, True, None)

    # Idempotency check
    assert redact_data(redacted) == redacted


def test_redact_data_handles_cycles_safely() -> None:
    cyclic_dict: dict[str, Any] = {"safe": "ok"}
    cyclic_dict["self"] = cyclic_dict
    redacted = redact_data(cyclic_dict)
    assert redacted == {"safe": "ok", "self": REDACTED_VALUE}
    assert redact_data(redacted) == redacted

    cyclic_list: list[Any] = ["ok"]
    cyclic_list.append(cyclic_list)
    redacted_list = redact_data(cyclic_list)
    assert redacted_list == ["ok", REDACTED_VALUE]


def test_redaction_config_custom_and_immutable() -> None:
    cfg = RedactionConfig(
        sensitive_keys=frozenset({"custom_secret"}),
        redact_patterns=(r"TOK_[0-9]{6}",),
        replacement="***",
    )
    assert redact_data({"custom_secret": "abc", "text": "use TOK_123456"}, cfg) == {
        "custom_secret": "***",
        "text": "use ***",
    }
    with pytest.raises(ValidationError):
        RedactionConfig(unknown_field=True)  # type: ignore[call-arg]


_json_primitives = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-10_000, max_value=10_000),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=40),
)
_json_values = st.recursive(
    _json_primitives,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=12), children, max_size=4),
    ),
    max_leaves=12,
)


@given(data=_json_values)
def test_redact_data_is_idempotent_property(data: Any) -> None:
    once = redact_data(data)
    twice = redact_data(once)
    assert once == twice
