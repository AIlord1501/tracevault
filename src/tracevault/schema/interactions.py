"""Canonical interaction payload contracts for TraceVault events."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, field_validator

from tracevault.schema.models import BoundaryType, ExecutionError, TraceVaultModel
from tracevault.schema.validation import validate_finite_float, validate_json_safe


class ModelRequestPayload(TraceVaultModel):
    """Canonical payload for a model/LLM request event."""

    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    messages: list[dict[str, Any]] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    stream: bool = False

    @field_validator("messages", "parameters", "tools")
    @classmethod
    def _validate_json_fields(cls, value: Any) -> Any:
        validate_json_safe(value)
        return value


class ModelResponsePayload(TraceVaultModel):
    """Canonical payload for a model/LLM response event."""

    model: str = Field(min_length=1)
    content: str | None = None
    output_messages: list[dict[str, Any]] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    finish_reason: str | None = None
    usage: dict[str, int] = Field(default_factory=dict)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("output_messages", "tool_calls", "raw_metadata")
    @classmethod
    def _validate_json_fields(cls, value: Any) -> Any:
        validate_json_safe(value)
        return value


class ToolCallPayload(TraceVaultModel):
    """Canonical payload for a tool invocation event."""

    tool_name: str = Field(min_length=1)
    call_id: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)

    @field_validator("arguments")
    @classmethod
    def _validate_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        validate_json_safe(value)
        return value


class ToolResultPayload(TraceVaultModel):
    """Canonical payload for a tool result event."""

    tool_name: str = Field(min_length=1)
    call_id: str | None = None
    result: Any = None
    is_error: bool = False

    @field_validator("result")
    @classmethod
    def _validate_result(cls, value: Any) -> Any:
        validate_json_safe(value)
        return value


class RetrievalQueryPayload(TraceVaultModel):
    """Canonical payload for a retrieval query event."""

    retriever: str = Field(min_length=1)
    query: str
    top_k: int = Field(default=5, ge=1)
    filters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("filters")
    @classmethod
    def _validate_filters(cls, value: dict[str, Any]) -> dict[str, Any]:
        validate_json_safe(value)
        return value


class RetrievedDocument(TraceVaultModel):
    """Single retrieved document entry inside a retrieval result."""

    doc_id: str
    content: str
    score: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("score")
    @classmethod
    def _validate_score(cls, value: float | None) -> float | None:
        if value is None:
            return None
        return validate_finite_float(value)

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        validate_json_safe(value)
        return value


class RetrievalResultPayload(TraceVaultModel):
    """Canonical payload for a retrieval result event."""

    retriever: str = Field(min_length=1)
    documents: list[RetrievedDocument] = Field(default_factory=list)


class AgentTransitionPayload(TraceVaultModel):
    """Canonical payload for a multi-agent handoff/transition event."""

    from_agent: str | None = None
    to_agent: str = Field(min_length=1)
    reason: str | None = None
    handoff_state: dict[str, Any] = Field(default_factory=dict)

    @field_validator("handoff_state")
    @classmethod
    def _validate_handoff_state(cls, value: dict[str, Any]) -> dict[str, Any]:
        validate_json_safe(value)
        return value


class StateChangePayload(TraceVaultModel):
    """Canonical payload for an execution state mutation event."""

    key_path: str = Field(min_length=1)
    operation: Literal["set", "delete", "merge"]
    before: Any = None
    after: Any = None

    @field_validator("before", "after")
    @classmethod
    def _validate_values(cls, value: Any) -> Any:
        validate_json_safe(value)
        return value


class ExceptionPayload(TraceVaultModel):
    """Canonical payload for a recorded exception event."""

    error: ExecutionError
    boundary: BoundaryType | None = None
    recoverable: bool = False


class StreamChunkPayload(TraceVaultModel):
    """Canonical payload for an incremental streaming output chunk."""

    stream_id: str = Field(min_length=1)
    chunk_index: int = Field(ge=0)
    delta: dict[str, Any] = Field(default_factory=dict)
    is_final: bool = False
    finish_reason: str | None = None
    usage: dict[str, int] | None = None

    @field_validator("delta")
    @classmethod
    def _validate_delta(cls, value: dict[str, Any]) -> dict[str, Any]:
        validate_json_safe(value)
        return value


__all__ = [
    "ModelRequestPayload",
    "ModelResponsePayload",
    "ToolCallPayload",
    "ToolResultPayload",
    "RetrievalQueryPayload",
    "RetrievedDocument",
    "RetrievalResultPayload",
    "AgentTransitionPayload",
    "StateChangePayload",
    "ExceptionPayload",
    "StreamChunkPayload",
]
