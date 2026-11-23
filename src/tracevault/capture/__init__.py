"""Public capture and instrumentation API for TraceVault."""

from __future__ import annotations

from tracevault.capture.config import CaptureConfig
from tracevault.capture.context import (
    acapture,
    capture,
    get_current_run_id,
    get_current_session,
    get_current_span_id,
)
from tracevault.capture.decorators import (
    trace_model,
    trace_retrieval,
    trace_span,
    trace_tool,
)
from tracevault.capture.session import CaptureSession

__all__ = [
    "CaptureConfig",
    "CaptureSession",
    "capture",
    "acapture",
    "get_current_session",
    "get_current_span_id",
    "get_current_run_id",
    "trace_span",
    "trace_model",
    "trace_tool",
    "trace_retrieval",
]
