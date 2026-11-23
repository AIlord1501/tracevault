"""Adversarial and hostile-input security tests for tracevault.schema."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import pytest
from pydantic import ValidationError

from conftest import (
    HOSTILE_TRACE_IDS,
    make_deeply_nested_dict,
    make_utc_timestamp,
    make_valid_event,
    make_valid_run,
    make_valid_span,
    make_valid_trace,
)
from tracevault.schema import (
    DEFAULT_MAX_JSON_DEPTH,
    REDACTED_VALUE,
    ExecutionError,
    InvalidTraceIdError,
    RetrievedDocument,
    Span,
    Trace,
    UnsafeTraceError,
    redact_data,
    validate_json_safe,
    validate_schema_version,
    validate_trace_id,
)


class TestHostileTraceIds:
    """Path traversal, control-char, length, unicode, and type attacks on trace_id."""

    @pytest.mark.parametrize("bad_id", HOSTILE_TRACE_IDS)
    def test_validate_trace_id_rejects_hostile_ids(self, bad_id: Any) -> None:
        with pytest.raises(InvalidTraceIdError):
            validate_trace_id(bad_id)

    @pytest.mark.parametrize(
        "bad_id",
        [
            "../etc/passwd",
            "..\\windows\\system32",
            "a/b",
            "a\\b",
            "foo\x00bar",
            ".",
            "..",
            "",
            "a" * 129,
            "tr_\u0430bc",
        ],
    )
    def test_trace_from_json_preserves_invalid_trace_id_error(self, bad_id: str) -> None:
        trace_dict = make_valid_trace().model_dump(mode="json")
        trace_dict["trace_id"] = bad_id
        trace_dict["runs"][0]["trace_id"] = bad_id
        raw = json.dumps(trace_dict)
        with pytest.raises(InvalidTraceIdError):
            Trace.from_json(raw)

    @pytest.mark.parametrize("bad_parent_id", ["../escape", "..\\escape", "bad\x00id", "a" * 129])
    def test_parent_trace_id_rejects_traversal(self, bad_parent_id: str) -> None:
        trace_dict = make_valid_trace().model_dump(mode="json")
        trace_dict["parent_trace_id"] = bad_parent_id
        with pytest.raises(InvalidTraceIdError):
            Trace.from_json(json.dumps(trace_dict))

    def test_boundary_length_128_accepted_129_rejected(self) -> None:
        valid_128 = "a" * 128
        assert validate_trace_id(valid_128) == valid_128
        with pytest.raises(InvalidTraceIdError):
            validate_trace_id("a" * 129)


class TestMalformedAndNonFiniteJson:
    """Malformed JSON, invalid UTF-8, non-object roots, and NaN/Infinity rejection."""

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "{not valid json",
            '{"unclosed": [1, 2, 3',
            "[]",
            '"just a string"',
            "42",
            "null",
            b"\xff\xfe\xfd",
        ],
    )
    def test_from_json_rejects_malformed_and_non_object_payloads(self, raw: str | bytes) -> None:
        with pytest.raises(UnsafeTraceError):
            Trace.from_json(raw)

    def test_from_json_rejects_non_str_non_bytes(self) -> None:
        with pytest.raises(UnsafeTraceError):
            Trace.from_json({"trace_id": "tr_001"})  # type: ignore[arg-type]

    @pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
    def test_from_json_rejects_non_finite_constants(self, token: str) -> None:
        raw = make_valid_trace().to_json()
        # Inject non-finite constant into metadata
        injected = raw.replace('"metadata": {}', f'"metadata": {{"bad_num": {token}}}', 1)
        assert token in injected
        with pytest.raises(UnsafeTraceError):
            Trace.from_json(injected)

    @pytest.mark.parametrize("bad_float", [float("nan"), float("inf"), float("-inf")])
    def test_validate_json_safe_rejects_non_finite_floats(self, bad_float: float) -> None:
        with pytest.raises(UnsafeTraceError):
            validate_json_safe({"score": bad_float})

    @pytest.mark.parametrize("bad_float", [float("nan"), float("inf"), float("-inf")])
    def test_retrieved_document_rejects_non_finite_score(self, bad_float: float) -> None:
        with pytest.raises(UnsafeTraceError):
            RetrievedDocument(doc_id="doc_1", content="hello", score=bad_float)


class TestNestingDepthAndCycles:
    """Nesting depth caps (>64) and cyclic Python container guards."""

    def test_validate_json_safe_allows_exact_max_depth_and_rejects_exceeding(self) -> None:
        ok_nested = make_deeply_nested_dict(DEFAULT_MAX_JSON_DEPTH)
        assert validate_json_safe(ok_nested) is ok_nested

        too_deep_dict = make_deeply_nested_dict(DEFAULT_MAX_JSON_DEPTH + 1)
        with pytest.raises(UnsafeTraceError, match="nesting depth"):
            validate_json_safe(too_deep_dict)

        too_deep_list: Any = "leaf"
        for _ in range(DEFAULT_MAX_JSON_DEPTH + 1):
            too_deep_list = [too_deep_list]
        with pytest.raises(UnsafeTraceError, match="nesting depth"):
            validate_json_safe(too_deep_list)

    def test_from_json_rejects_deeply_nested_raw_json(self) -> None:
        trace_dict = make_valid_trace().model_dump(mode="json")
        # Root trace object is depth 1, metadata is depth 2, + 64 nested = depth 66 > 64.
        trace_dict["metadata"] = make_deeply_nested_dict(DEFAULT_MAX_JSON_DEPTH)
        raw = json.dumps(trace_dict)
        with pytest.raises(UnsafeTraceError, match="nesting depth"):
            Trace.from_json(raw)

    def test_cyclic_list_rejected_by_validate_and_handled_by_redact(self) -> None:
        cyclic_list: list[Any] = []
        cyclic_list.append(cyclic_list)

        with pytest.raises(UnsafeTraceError, match="Cyclic"):
            validate_json_safe(cyclic_list)

        redacted = redact_data(cyclic_list)
        assert redacted == [REDACTED_VALUE]

    def test_cyclic_dict_rejected_by_validate_and_handled_by_redact(self) -> None:
        cyclic_dict: dict[str, Any] = {}
        cyclic_dict["self"] = cyclic_dict

        with pytest.raises(UnsafeTraceError, match="Cyclic"):
            validate_json_safe(cyclic_dict)

        redacted = redact_data(cyclic_dict)
        assert redacted == {"self": REDACTED_VALUE}

    def test_mutual_cycle_rejected_by_validate_and_handled_by_redact(self) -> None:
        node_a: dict[str, Any] = {"name": "a"}
        node_b: list[Any] = [node_a]
        node_a["children"] = node_b

        with pytest.raises(UnsafeTraceError, match="Cyclic"):
            validate_json_safe(node_a)

        redacted = redact_data(node_a)
        assert redacted == {"name": "a", "children": [REDACTED_VALUE]}


class TestUnsupportedTypesAndKeys:
    """Unsupported Python types and non-string dictionary keys."""

    @pytest.mark.parametrize(
        "bad_value",
        [
            object(),
            {1, 2, 3},
            b"raw bytes",
            lambda x: x,
            type("CustomClass", (), {})(),
        ],
    )
    def test_validate_json_safe_rejects_unsupported_types(self, bad_value: Any) -> None:
        with pytest.raises(UnsafeTraceError):
            validate_json_safe({"payload": bad_value})

    @pytest.mark.parametrize(
        "bad_dict",
        [
            {1: "a"},
            {(1, 2): "b"},
            {None: "c"},
            {"nested": {42: "int-key"}},
        ],
    )
    def test_validate_json_safe_rejects_non_string_dict_keys(
        self, bad_dict: dict[Any, Any]
    ) -> None:
        with pytest.raises(UnsafeTraceError, match="keys must be strings"):
            validate_json_safe(bad_dict)


class TestOversizedPayloads:
    """Payload byte-size limit enforcement in Trace.from_json."""

    def test_from_json_rejects_oversized_str_and_bytes(self) -> None:
        raw_str = make_valid_trace(metadata={"blob": "x" * 2048}).to_json()
        raw_bytes = raw_str.encode("utf-8")

        with pytest.raises(UnsafeTraceError, match="exceeds max_bytes"):
            Trace.from_json(raw_str, max_bytes=512)

        with pytest.raises(UnsafeTraceError, match="exceeds max_bytes"):
            Trace.from_json(raw_bytes, max_bytes=512)

    def test_from_json_checks_utf8_byte_length_not_char_count(self) -> None:
        # Each 4-byte emoji makes UTF-8 byte size much larger than character count.
        raw_str = make_valid_trace(metadata={"pad": "\U0001f680" * 100}).to_json()
        char_len = len(raw_str)
        byte_len = len(raw_str.encode("utf-8"))
        assert byte_len > char_len
        with pytest.raises(UnsafeTraceError, match="exceeds max_bytes"):
            Trace.from_json(raw_str, max_bytes=char_len)


class TestStrictSchemaAndInvariants:
    """extra='forbid', schema_version, naive datetimes, temporal inversions, and graph cycles."""

    def test_unknown_fields_rejected_across_models_and_json(self) -> None:
        with pytest.raises(ValidationError):
            ExecutionError(error_type="ValueError", message="boom", injected="evil")  # type: ignore[call-arg]

        trace_dict = make_valid_trace().model_dump(mode="json")
        trace_dict["unexpected_root_field"] = "injected"
        with pytest.raises(UnsafeTraceError):
            Trace.from_json(json.dumps(trace_dict))

        trace_dict = make_valid_trace().model_dump(mode="json")
        trace_dict["runs"][0]["__class__"] = "os.system"
        with pytest.raises(UnsafeTraceError):
            Trace.from_json(json.dumps(trace_dict))

    @pytest.mark.parametrize("bad_version", ["2.0.0", "0.9.0", "not-semver", "1.0", "1.0.0\n", 100])
    def test_incompatible_schema_version_rejected(self, bad_version: Any) -> None:
        with pytest.raises(UnsafeTraceError):
            validate_schema_version(bad_version)

        trace_dict = make_valid_trace().model_dump(mode="json")
        trace_dict["schema_version"] = bad_version
        with pytest.raises(UnsafeTraceError):
            Trace.from_json(json.dumps(trace_dict))

    def test_naive_datetimes_rejected(self) -> None:
        naive = datetime(2026, 11, 24, 12, 0, 0)
        with pytest.raises(ValidationError, match="timezone-aware"):
            make_valid_run(started_at=naive)
        with pytest.raises(ValidationError, match="timezone-aware"):
            make_valid_span(started_at=naive)
        with pytest.raises(ValidationError, match="timezone-aware"):
            make_valid_event(timestamp=naive)

    def test_temporal_inversions_rejected(self) -> None:
        t_start = make_utc_timestamp(10.0)
        t_before = make_utc_timestamp(5.0)
        with pytest.raises(ValidationError, match="ended_at"):
            make_valid_run(started_at=t_start, ended_at=t_before)
        with pytest.raises(ValidationError, match="ended_at"):
            make_valid_span(started_at=t_start, ended_at=t_before)

    def test_run_parent_cycles_rejected(self) -> None:
        # Self-cycle
        with pytest.raises(ValidationError, match="reference itself"):
            make_valid_run(run_id="run_a", parent_run_id="run_a")

        # 2-node mutual cycle
        run_a = make_valid_run(run_id="run_a", trace_id="tr_cycle_001", parent_run_id="run_b")
        run_b = make_valid_run(run_id="run_b", trace_id="tr_cycle_001", parent_run_id="run_a")
        with pytest.raises(ValidationError, match="Cyclic"):
            make_valid_trace(trace_id="tr_cycle_001", runs=[run_a, run_b], spans=[], events=[])

    def test_span_parent_cycles_rejected(self) -> None:
        # Self-cycle
        with pytest.raises(ValidationError, match="reference itself"):
            make_valid_span(span_id="sp_a", parent_span_id="sp_a", event_ids=[])

        # 2-node mutual cycle
        sp_a = make_valid_span(span_id="sp_a", parent_span_id="sp_b", event_ids=[])
        sp_b = make_valid_span(span_id="sp_b", parent_span_id="sp_a", event_ids=[])
        with pytest.raises(ValidationError, match="Cyclic"):
            make_valid_trace(spans=[sp_a, sp_b], events=[])

    def test_code_injection_strings_remain_inert_data(self) -> None:
        payload_str = "__import__('os').system('echo pwned'); raise SystemExit(1)"
        trace = make_valid_trace(
            runs=[make_valid_run(name=payload_str, inputs={"cmd": payload_str})],
            spans=[
                Span(
                    span_id="sp_001",
                    run_id="run_001",
                    span_type="custom",
                    name=payload_str,
                    started_at=make_utc_timestamp(0.1),
                    ended_at=make_utc_timestamp(0.2),
                    attributes={"expr": payload_str},
                )
            ],
            events=[],
            metadata={"note": payload_str},
        )
        restored = Trace.from_json(trace.to_json())
        assert restored == trace
        assert restored.runs[0].name == payload_str
