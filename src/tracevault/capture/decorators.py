"""Sync and async instrumentation decorators for TraceVault capture."""

from __future__ import annotations

import functools
import inspect
import math
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any, ParamSpec, TypeVar, cast

from pydantic import BaseModel

from tracevault.capture.context import get_current_session
from tracevault.capture.session import CaptureSession
from tracevault.schema import BoundaryType, SpanType

P = ParamSpec("P")
R = TypeVar("R")


def _safe_serialize(
    value: Any,
    *,
    _depth: int = 0,
    _active: set[int] | None = None,
    _max_depth: int = 32,
) -> Any:
    """Convert arbitrary Python values into JSON-safe structures for decorator capture."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if _depth >= _max_depth:
        return "<max-depth-exceeded>"
    if isinstance(value, Enum):
        return _safe_serialize(value.value, _depth=_depth + 1, _active=_active)
    if isinstance(value, BaseModel):
        return _safe_serialize(
            value.model_dump(mode="json"),
            _depth=_depth + 1,
            _active=_active,
        )
    if isinstance(value, dict):
        active = _active if _active is not None else set()
        obj_id = id(value)
        if obj_id in active:
            return "<circular-reference>"
        active.add(obj_id)
        try:
            return {
                str(k): _safe_serialize(v, _depth=_depth + 1, _active=active)
                for k, v in value.items()
            }
        finally:
            active.discard(obj_id)
    if isinstance(value, (list, tuple)):
        active = _active if _active is not None else set()
        obj_id = id(value)
        if obj_id in active:
            return "<circular-reference>"
        active.add(obj_id)
        try:
            return [_safe_serialize(item, _depth=_depth + 1, _active=active) for item in value]
        finally:
            active.discard(obj_id)
    return repr(value)


def _extract_call_args(
    func: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    """Bind positional and keyword arguments into a deterministic JSON-safe dictionary."""
    try:
        bound = inspect.signature(func).bind(*args, **kwargs)
        bound.apply_defaults()
        result: dict[str, Any] = {}
        for key, value in bound.arguments.items():
            if key in ("self", "cls") and not isinstance(
                value, (type(None), bool, int, float, str, dict, list, tuple)
            ):
                continue
            result[key] = _safe_serialize(value)
        return result
    except (TypeError, ValueError):
        return {
            "args": [_safe_serialize(arg) for arg in args],
            "kwargs": {str(k): _safe_serialize(v) for k, v in kwargs.items()},
        }


def _to_response_dict(value: Any, *, list_key: str = "result") -> dict[str, Any]:
    """Normalize a function return value into a JSON-safe response mapping."""
    serialized = _safe_serialize(value)
    if isinstance(serialized, dict):
        return serialized
    if isinstance(serialized, list):
        return {list_key: serialized}
    return {"result": serialized}


def _resolve_session(explicit: CaptureSession | None) -> CaptureSession | None:
    return explicit if explicit is not None else get_current_session()


def trace_span(
    name: str | None = None,
    *,
    span_type: SpanType = SpanType.CUSTOM,
    boundary: BoundaryType | None = None,
    session: CaptureSession | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Instrument a sync or async function as a TraceVault span (no-op when inactive)."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        span_name = name or func.__name__

        if inspect.iscoroutinefunction(func):
            async_func = cast(Callable[P, Awaitable[Any]], func)

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                active_session = _resolve_session(session)
                if active_session is None:
                    return await async_func(*args, **kwargs)
                async with active_session.aspan(
                    span_name,
                    span_type=span_type,
                    boundary=boundary,
                ):
                    return await async_func(*args, **kwargs)

            return cast(Callable[P, R], async_wrapper)

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            active_session = _resolve_session(session)
            if active_session is None:
                return func(*args, **kwargs)
            with active_session.span(
                span_name,
                span_type=span_type,
                boundary=boundary,
            ):
                return func(*args, **kwargs)

        return sync_wrapper

    return decorator


def trace_model(
    name: str | None = None,
    *,
    session: CaptureSession | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Instrument a sync or async model call function with span + fixture capture."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        call_name = name or func.__name__

        if inspect.iscoroutinefunction(func):
            async_func = cast(Callable[P, Awaitable[Any]], func)

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                active_session = _resolve_session(session)
                if active_session is None:
                    return await async_func(*args, **kwargs)
                request_dict = _extract_call_args(func, args, kwargs)
                async with active_session.aspan(
                    call_name,
                    span_type=SpanType.MODEL,
                    boundary=BoundaryType.MODEL,
                ):
                    try:
                        result = await async_func(*args, **kwargs)
                    except BaseException as exc:
                        active_session.record_model_call(
                            request_dict,
                            None,
                            error=exc,
                            name=call_name,
                        )
                        raise
                    active_session.record_model_call(
                        request_dict,
                        _to_response_dict(result),
                        name=call_name,
                    )
                    return result

            return cast(Callable[P, R], async_wrapper)

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            active_session = _resolve_session(session)
            if active_session is None:
                return func(*args, **kwargs)
            request_dict = _extract_call_args(func, args, kwargs)
            with active_session.span(
                call_name,
                span_type=SpanType.MODEL,
                boundary=BoundaryType.MODEL,
            ):
                try:
                    result = func(*args, **kwargs)
                except BaseException as exc:
                    active_session.record_model_call(
                        request_dict,
                        None,
                        error=exc,
                        name=call_name,
                    )
                    raise
                active_session.record_model_call(
                    request_dict,
                    _to_response_dict(result),
                    name=call_name,
                )
                return result

        return sync_wrapper

    return decorator


def trace_tool(
    name: str | None = None,
    *,
    session: CaptureSession | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Instrument a sync or async tool function with span + fixture capture."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        tool_name = name or func.__name__

        if inspect.iscoroutinefunction(func):
            async_func = cast(Callable[P, Awaitable[Any]], func)

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                active_session = _resolve_session(session)
                if active_session is None:
                    return await async_func(*args, **kwargs)
                args_dict = _extract_call_args(func, args, kwargs)
                async with active_session.aspan(
                    tool_name,
                    span_type=SpanType.TOOL,
                    boundary=BoundaryType.TOOL,
                ):
                    try:
                        result = await async_func(*args, **kwargs)
                    except BaseException as exc:
                        active_session.record_tool_call(
                            tool_name,
                            args_dict,
                            None,
                            error=exc,
                        )
                        raise
                    active_session.record_tool_call(
                        tool_name,
                        args_dict,
                        _to_response_dict(result),
                    )
                    return result

            return cast(Callable[P, R], async_wrapper)

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            active_session = _resolve_session(session)
            if active_session is None:
                return func(*args, **kwargs)
            args_dict = _extract_call_args(func, args, kwargs)
            with active_session.span(
                tool_name,
                span_type=SpanType.TOOL,
                boundary=BoundaryType.TOOL,
            ):
                try:
                    result = func(*args, **kwargs)
                except BaseException as exc:
                    active_session.record_tool_call(
                        tool_name,
                        args_dict,
                        None,
                        error=exc,
                    )
                    raise
                active_session.record_tool_call(
                    tool_name,
                    args_dict,
                    _to_response_dict(result),
                )
                return result

        return sync_wrapper

    return decorator


def trace_retrieval(
    name: str | None = None,
    *,
    session: CaptureSession | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Instrument a sync or async retrieval function with span + fixture capture."""

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        retriever_name = name or func.__name__

        if inspect.iscoroutinefunction(func):
            async_func = cast(Callable[P, Awaitable[Any]], func)

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                active_session = _resolve_session(session)
                if active_session is None:
                    return await async_func(*args, **kwargs)
                query_dict = _extract_call_args(func, args, kwargs)
                async with active_session.aspan(
                    retriever_name,
                    span_type=SpanType.RETRIEVAL,
                    boundary=BoundaryType.RETRIEVAL,
                ):
                    try:
                        result = await async_func(*args, **kwargs)
                    except BaseException as exc:
                        active_session.record_retrieval(
                            query_dict,
                            None,
                            error=exc,
                            name=retriever_name,
                        )
                        raise
                    active_session.record_retrieval(
                        query_dict,
                        _to_response_dict(result, list_key="documents"),
                        name=retriever_name,
                    )
                    return result

            return cast(Callable[P, R], async_wrapper)

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            active_session = _resolve_session(session)
            if active_session is None:
                return func(*args, **kwargs)
            query_dict = _extract_call_args(func, args, kwargs)
            with active_session.span(
                retriever_name,
                span_type=SpanType.RETRIEVAL,
                boundary=BoundaryType.RETRIEVAL,
            ):
                try:
                    result = func(*args, **kwargs)
                except BaseException as exc:
                    active_session.record_retrieval(
                        query_dict,
                        None,
                        error=exc,
                        name=retriever_name,
                    )
                    raise
                active_session.record_retrieval(
                    query_dict,
                    _to_response_dict(result, list_key="documents"),
                    name=retriever_name,
                )
                return result

        return sync_wrapper

    return decorator


__all__ = [
    "trace_span",
    "trace_model",
    "trace_tool",
    "trace_retrieval",
]
