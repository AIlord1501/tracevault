"""Canonical exception hierarchy for TraceVault."""

from __future__ import annotations


class TraceVaultError(Exception):
    """Base exception for all TraceVault errors."""


class InvalidTraceIdError(TraceVaultError):
    """Raised when a trace_id violates naming, charset, length, or path-safety rules."""


class UnsafeTraceError(TraceVaultError):
    """Raised when trace data violates JSON safety, size, depth, schema version, or containment."""


class TraceNotFoundError(TraceVaultError):
    """Raised when a requested trace_id does not exist in the repository."""


class TraceFrozenError(TraceVaultError):
    """Raised when attempting to overwrite a frozen trace or delete it without force=True."""


class FixtureNotFoundError(TraceVaultError):
    """Raised when replay cannot locate a matching fixture and fail_on_missing_fixture=True."""


class PolicyViolationError(TraceVaultError):
    """Raised when a replay boundary violates SafetyPolicy or BoundaryMode.DENY."""


class ReplayError(TraceVaultError):
    """Raised when replay configuration is invalid or a recorded error fixture is replayed."""


class AdapterError(TraceVaultError):
    """Raised when an adapter fails to attach, sanitize, capture, or reconstruct an SDK response."""


class AdapterUnavailableError(AdapterError):
    """Raised when an optional third-party SDK dependency for an adapter is not installed."""


__all__ = [
    "TraceVaultError",
    "InvalidTraceIdError",
    "UnsafeTraceError",
    "TraceNotFoundError",
    "TraceFrozenError",
    "FixtureNotFoundError",
    "PolicyViolationError",
    "ReplayError",
    "AdapterError",
    "AdapterUnavailableError",
]
