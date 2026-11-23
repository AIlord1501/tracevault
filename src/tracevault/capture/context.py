"""ContextVar-based execution context propagation for TraceVault capture."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tracevault.capture.session import CaptureSession

_CURRENT_SESSION: ContextVar[CaptureSession | None] = ContextVar(
    "tracevault_current_session",
    default=None,
)
_SPAN_STACK: ContextVar[tuple[str, ...]] = ContextVar(
    "tracevault_span_stack",
    default=(),
)
_RUN_STACK: ContextVar[tuple[str, ...]] = ContextVar(
    "tracevault_run_stack",
    default=(),
)


def get_current_session() -> CaptureSession | None:
    """Return the active CaptureSession in the current execution context, if any."""
    return _CURRENT_SESSION.get()


def get_current_span_id() -> str | None:
    """Return the active span_id at the top of the current span stack, if any."""
    stack = _SPAN_STACK.get()
    return stack[-1] if stack else None


def get_current_run_id() -> str | None:
    """Return the active run_id at the top of the current run stack, if any."""
    stack = _RUN_STACK.get()
    return stack[-1] if stack else None


def _enter_session_context(
    session: CaptureSession,
    root_run_id: str,
) -> tuple[Token[CaptureSession | None], Token[tuple[str, ...]], Token[tuple[str, ...]]]:
    """Bind a CaptureSession and isolated run/span stacks into the current context."""
    session_token = _CURRENT_SESSION.set(session)
    run_token = _RUN_STACK.set((root_run_id,))
    span_token = _SPAN_STACK.set(())
    return session_token, run_token, span_token


def _exit_session_context(
    tokens: tuple[Token[CaptureSession | None], Token[tuple[str, ...]], Token[tuple[str, ...]]],
) -> None:
    """Reset session, run, and span ContextVar tokens in reverse order."""
    session_token, run_token, span_token = tokens
    _SPAN_STACK.reset(span_token)
    _RUN_STACK.reset(run_token)
    _CURRENT_SESSION.reset(session_token)


def _push_span(span_id: str) -> Token[tuple[str, ...]]:
    """Push a span_id onto the current immutable ContextVar span stack."""
    current = _SPAN_STACK.get()
    return _SPAN_STACK.set((*current, span_id))


def _reset_span(token: Token[tuple[str, ...]]) -> None:
    """Restore the span stack to its state prior to _push_span."""
    _SPAN_STACK.reset(token)


def _push_run(run_id: str) -> Token[tuple[str, ...]]:
    """Push a run_id onto the current immutable ContextVar run stack."""
    current = _RUN_STACK.get()
    return _RUN_STACK.set((*current, run_id))


def _reset_run(token: Token[tuple[str, ...]]) -> None:
    """Restore the run stack to its state prior to _push_run."""
    _RUN_STACK.reset(token)


@contextmanager
def capture(name: str, **kwargs: Any) -> Iterator[CaptureSession]:
    """Synchronously capture an AI execution trace in the current context."""
    from tracevault.capture.session import CaptureSession

    session = CaptureSession(name, **kwargs)
    with session:
        yield session


@asynccontextmanager
async def acapture(name: str, **kwargs: Any) -> AsyncIterator[CaptureSession]:
    """Asynchronously capture an AI execution trace in the current context."""
    from tracevault.capture.session import CaptureSession

    session = CaptureSession(name, **kwargs)
    async with session:
        yield session


__all__ = [
    "capture",
    "acapture",
    "get_current_session",
    "get_current_span_id",
    "get_current_run_id",
]
