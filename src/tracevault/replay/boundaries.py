"""Policy-governed boundary replay and typed boundary adapters for TraceVault."""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

from tracevault.replay.engine import ReplayEngine
from tracevault.schema import (
    BoundaryMode,
    BoundaryPolicyDecision,
    BoundaryType,
    PolicyViolationError,
    ReplayConfig,
    ReplayError,
    ReplayMode,
    SafetyPolicy,
    UnsafeTraceError,
    redact_data,
    validate_json_safe,
)

LiveHandler = Callable[[dict[str, Any]], dict[str, Any]]


class BoundaryExecutor:
    """Fail-closed policy executor for RECORDED, DENY, and authorized LIVE boundaries."""

    def __init__(self, engine: ReplayEngine) -> None:
        self._engine = engine

    @property
    def engine(self) -> ReplayEngine:
        """Return the underlying ReplayEngine."""
        return self._engine

    @property
    def config(self) -> ReplayConfig:
        """Return the ReplayConfig governing boundary execution."""
        return self._engine.config

    @property
    def policy(self) -> SafetyPolicy:
        """Return the SafetyPolicy governing live boundary authorization."""
        return self._engine.config.safety_policy

    def evaluate_policy(
        self,
        boundary: BoundaryType,
        *,
        tool_name: str | None = None,
        host: str | None = None,
    ) -> BoundaryPolicyDecision:
        """Evaluate SafetyPolicy fail-closed for a boundary invocation."""
        config = self._engine.config
        policy = config.safety_policy
        mode = config.boundary_modes.get(boundary, BoundaryMode.RECORDED)

        if mode == BoundaryMode.DENY:
            return BoundaryPolicyDecision(
                boundary=boundary,
                mode=mode,
                allowed=False,
                reason=f"Boundary '{boundary.value}' is denied by ReplayConfig.boundary_modes",
            )

        if mode == BoundaryMode.RECORDED:
            return BoundaryPolicyDecision(
                boundary=boundary,
                mode=mode,
                allowed=True,
                reason="Offline recorded fixture replay",
            )

        # BoundaryMode.LIVE — fail closed on every policy requirement
        if config.mode != ReplayMode.BOUNDARY_GOVERNED:
            return BoundaryPolicyDecision(
                boundary=boundary,
                mode=mode,
                allowed=False,
                reason=(
                    f"Live boundary execution requires ReplayMode.BOUNDARY_GOVERNED "
                    f"(got {config.mode.value!r})"
                ),
            )

        if boundary not in policy.allow_live_boundaries:
            return BoundaryPolicyDecision(
                boundary=boundary,
                mode=mode,
                allowed=False,
                reason=(
                    f"Boundary '{boundary.value}' is not authorized in "
                    f"SafetyPolicy.allow_live_boundaries"
                ),
            )

        if policy.require_explicit_opt_in and policy.max_live_calls <= 0:
            return BoundaryPolicyDecision(
                boundary=boundary,
                mode=mode,
                allowed=False,
                reason="Live boundary execution requires explicit opt-in with max_live_calls > 0",
            )

        if self._engine.live_calls >= policy.max_live_calls:
            return BoundaryPolicyDecision(
                boundary=boundary,
                mode=mode,
                allowed=False,
                reason=(
                    f"Live call limit reached ({self._engine.live_calls}/{policy.max_live_calls})"
                ),
            )

        if boundary == BoundaryType.TOOL and (
            tool_name is None or tool_name not in policy.allowed_tools
        ):
            return BoundaryPolicyDecision(
                boundary=boundary,
                mode=mode,
                allowed=False,
                reason=f"Tool {tool_name!r} is not authorized in SafetyPolicy.allowed_tools",
            )

        if boundary in (BoundaryType.MODEL, BoundaryType.RETRIEVAL):
            if host is not None and host not in policy.allowed_hosts:
                return BoundaryPolicyDecision(
                    boundary=boundary,
                    mode=mode,
                    allowed=False,
                    reason=f"Host {host!r} is not authorized in SafetyPolicy.allowed_hosts",
                )
            if host is None and len(policy.allowed_hosts) > 0:
                return BoundaryPolicyDecision(
                    boundary=boundary,
                    mode=mode,
                    allowed=False,
                    reason=(
                        "Host is required when SafetyPolicy.allowed_hosts is configured "
                        "for live model/retrieval boundaries"
                    ),
                )

        return BoundaryPolicyDecision(
            boundary=boundary,
            mode=mode,
            allowed=True,
            reason="Live boundary execution authorized by SafetyPolicy",
        )

    def execute(
        self,
        boundary: BoundaryType,
        request: dict[str, Any],
        *,
        live_fn: LiveHandler | None = None,
        name: str | None = None,
        tool_name: str | None = None,
        host: str | None = None,
    ) -> dict[str, Any]:
        """Execute a boundary interaction according to ReplayConfig and SafetyPolicy."""
        mode = self._engine.config.boundary_modes.get(boundary, BoundaryMode.RECORDED)

        if mode == BoundaryMode.RECORDED:
            # Strict offline guarantee: never invoke live_fn and never fall back on miss.
            return self._engine.replay_interaction(
                boundary,
                request,
                name=name if name is not None else tool_name,
            )

        decision = self.evaluate_policy(boundary, tool_name=tool_name, host=host)
        if not decision.allowed:
            raise PolicyViolationError(decision.reason)

        if live_fn is None:
            raise ReplayError("live_fn is required for LIVE boundary execution")

        if not isinstance(request, dict):
            raise UnsafeTraceError("Boundary request must be a dict")
        validate_json_safe(request)

        raw_result = live_fn(copy.deepcopy(request))
        if not isinstance(raw_result, dict):
            raise ReplayError("live_fn must return a JSON-safe dict")
        validate_json_safe(raw_result)

        redacted_result: dict[str, Any] = redact_data(raw_result)
        self._engine._record_live_interaction(
            boundary=boundary,
            request=request,
            response=redacted_result,
            name=name if name is not None else tool_name,
        )
        return copy.deepcopy(redacted_result)


class ModelBoundary:
    """Typed boundary adapter for model invocations."""

    def __init__(self, executor: BoundaryExecutor) -> None:
        self._executor = executor

    def invoke(
        self,
        request: dict[str, Any],
        *,
        live_fn: LiveHandler | None = None,
        name: str | None = None,
        host: str | None = None,
    ) -> dict[str, Any]:
        """Invoke a model boundary using recorded replay or authorized live execution."""
        return self._executor.execute(
            BoundaryType.MODEL,
            request,
            live_fn=live_fn,
            name=name,
            host=host,
        )


class ToolBoundary:
    """Typed boundary adapter for tool invocations."""

    def __init__(self, executor: BoundaryExecutor) -> None:
        self._executor = executor

    def invoke(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        live_fn: LiveHandler | None = None,
    ) -> dict[str, Any]:
        """Invoke a tool boundary using recorded replay or authorized live execution."""
        if not isinstance(args, dict):
            raise UnsafeTraceError("Tool arguments must be a dict")
        request: dict[str, Any] = {
            "tool_name": tool_name,
            "arguments": args,
        }
        return self._executor.execute(
            BoundaryType.TOOL,
            request,
            live_fn=live_fn,
            name=tool_name,
            tool_name=tool_name,
        )


class RetrievalBoundary:
    """Typed boundary adapter for retrieval invocations."""

    def __init__(self, executor: BoundaryExecutor) -> None:
        self._executor = executor

    def invoke(
        self,
        query: dict[str, Any],
        *,
        live_fn: LiveHandler | None = None,
        name: str | None = None,
        host: str | None = None,
    ) -> dict[str, Any]:
        """Invoke a retrieval boundary using recorded replay or authorized live execution."""
        return self._executor.execute(
            BoundaryType.RETRIEVAL,
            query,
            live_fn=live_fn,
            name=name,
            host=host,
        )


__all__ = [
    "BoundaryExecutor",
    "ModelBoundary",
    "ToolBoundary",
    "RetrievalBoundary",
]
