"""Deterministic offline fixture matching and override resolution for TraceVault."""

from __future__ import annotations

import copy
import threading
from typing import Any

from tracevault.schema import (
    BoundaryType,
    ExecutionError,
    FixtureEntry,
    FixtureNotFoundError,
    FixtureSet,
    ReplayConfig,
    ReplayError,
    ReplayMode,
    ReplayOverride,
    TraceVaultModel,
    UnsafeTraceError,
    compute_fingerprint,
    redact_data,
    validate_json_safe,
)


class FixtureMatchResult(TraceVaultModel):
    """Immutable result of a single fixture lookup against a FixtureSet."""

    entry: FixtureEntry | None = None
    fingerprint: str
    call_index: int
    matched: bool
    overridden: bool
    match_strategy: str
    response: dict[str, Any] | None = None
    error: ExecutionError | None = None


class FixtureMatcher:
    """Thread-safe, deterministic fixture matcher that never mutates its source FixtureSet."""

    def __init__(self, fixtures: FixtureSet, config: ReplayConfig) -> None:
        self._config = config
        self._entries: tuple[FixtureEntry, ...] = tuple(fixtures.entries)
        self._lock = threading.Lock()

        # Index exact lookup keys: (boundary, fingerprint, call_index) -> entry indices
        self._exact_index: dict[tuple[BoundaryType, str, int], list[int]] = {}
        self._ambiguous_exact_keys: set[tuple[BoundaryType, str, int]] = set()
        for idx, entry in enumerate(self._entries):
            key = (entry.boundary, entry.fingerprint, entry.call_index)
            bucket = self._exact_index.setdefault(key, [])
            bucket.append(idx)
            if len(bucket) > 1:
                self._ambiguous_exact_keys.add(key)

        # Mutable replay-pass consumption state (isolated to this matcher instance)
        self._fp_counts: dict[tuple[BoundaryType, str], int] = {}
        self._name_counts: dict[tuple[BoundaryType, str], int] = {}
        self._boundary_counts: dict[BoundaryType, int] = {}
        self._consumed: set[int] = set()

    @property
    def ambiguous_keys(self) -> frozenset[tuple[BoundaryType, str, int]]:
        """Return exact keys that appear more than once in the source FixtureSet."""
        return frozenset(self._ambiguous_exact_keys)

    def match(
        self,
        boundary: BoundaryType,
        request: dict[str, Any],
        *,
        name: str | None = None,
    ) -> FixtureMatchResult:
        """Resolve a boundary request against recorded fixtures and configured overrides."""
        if not isinstance(request, dict):
            raise UnsafeTraceError("Fixture match request must be a dict")
        validate_json_safe(request)
        redacted_request: dict[str, Any] = redact_data(request)
        fp = compute_fingerprint(boundary, redacted_request)

        with self._lock:
            fp_key = (boundary, fp)
            call_index = self._fp_counts.get(fp_key, 0)
            self._fp_counts[fp_key] = call_index + 1

            self._boundary_counts[boundary] = self._boundary_counts.get(boundary, 0) + 1
            if name is not None:
                name_key = (boundary, name)
                self._name_counts[name_key] = self._name_counts.get(name_key, 0) + 1

            entry, strategy = self._select_entry_locked(
                boundary=boundary,
                fp=fp,
                call_index=call_index,
                name=name,
            )

        override_applied, override_response, override_error = self._resolve_override(
            entry=entry,
            boundary=boundary,
            fp=fp,
            call_index=call_index,
            name=name,
        )

        if override_applied:
            return FixtureMatchResult(
                entry=entry,
                fingerprint=fp,
                call_index=call_index,
                matched=True,
                overridden=True,
                match_strategy="override",
                response=copy.deepcopy(override_response)
                if override_response is not None
                else None,
                error=override_error,
            )

        if entry is not None:
            return FixtureMatchResult(
                entry=entry,
                fingerprint=fp,
                call_index=call_index,
                matched=True,
                overridden=False,
                match_strategy=strategy,
                response=copy.deepcopy(entry.response) if entry.response is not None else None,
                error=entry.error,
            )

        if self._config.fail_on_missing_fixture:
            available = sum(1 for item in self._entries if item.boundary == boundary)
            raise FixtureNotFoundError(
                f"No matching fixture for boundary={boundary.value!r}, "
                f"name={name!r}, fingerprint={fp[:12]}, call_index={call_index} "
                f"(available fixtures for boundary: {available})"
            )

        return FixtureMatchResult(
            entry=None,
            fingerprint=fp,
            call_index=call_index,
            matched=False,
            overridden=False,
            match_strategy="miss",
            response={},
            error=None,
        )

    def _select_entry_locked(
        self,
        *,
        boundary: BoundaryType,
        fp: str,
        call_index: int,
        name: str | None,
    ) -> tuple[FixtureEntry | None, str]:
        exact_key = (boundary, fp, call_index)
        candidates = self._exact_index.get(exact_key, [])

        if self._config.mode in (ReplayMode.OFFLINE_STRICT, ReplayMode.BOUNDARY_GOVERNED):
            if exact_key in self._ambiguous_exact_keys:
                raise ReplayError(
                    f"Ambiguous fixture match for boundary={boundary.value!r}, "
                    f"fingerprint={fp[:12]}, call_index={call_index}: "
                    f"{len(candidates)} entries share this exact key"
                )
            if len(candidates) == 1 and candidates[0] not in self._consumed:
                idx = candidates[0]
                self._consumed.add(idx)
                return self._entries[idx], "exact"
            return None, "miss"

        # OFFLINE_LENIENT: exact -> (boundary, name) -> boundary; never double-consume
        for idx in candidates:
            if idx not in self._consumed:
                self._consumed.add(idx)
                return self._entries[idx], "exact"

        if name is not None:
            for idx, candidate in enumerate(self._entries):
                if (
                    idx not in self._consumed
                    and candidate.boundary == boundary
                    and candidate.name == name
                ):
                    self._consumed.add(idx)
                    return candidate, "lenient_name"

        for idx, candidate in enumerate(self._entries):
            if idx not in self._consumed and candidate.boundary == boundary:
                self._consumed.add(idx)
                return candidate, "lenient_boundary"

        return None, "miss"

    def _resolve_override(
        self,
        *,
        entry: FixtureEntry | None,
        boundary: BoundaryType,
        fp: str,
        call_index: int,
        name: str | None,
    ) -> tuple[bool, dict[str, Any] | None, ExecutionError | None]:
        for rule in self._config.override_rules:
            if self._rule_matches(
                rule,
                entry=entry,
                boundary=boundary,
                fp=fp,
                call_index=call_index,
                name=name,
            ):
                if rule.response is not None or rule.error is not None:
                    return True, rule.response, rule.error
                return True, {}, None

        overrides = self._config.overrides
        if overrides:
            override_val: Any = None
            found = False
            if entry is not None and entry.fixture_id in overrides:
                override_val = overrides[entry.fixture_id]
                found = True
            elif fp in overrides:
                override_val = overrides[fp]
                found = True
            elif entry is not None and entry.fingerprint in overrides:
                override_val = overrides[entry.fingerprint]
                found = True

            if found:
                if override_val is None:
                    return True, {}, None
                if not isinstance(override_val, dict):
                    raise ReplayError(
                        "ReplayConfig.overrides values must be JSON-safe dicts or None"
                    )
                return True, override_val, None

        return False, None, None

    @staticmethod
    def _rule_matches(
        rule: ReplayOverride,
        *,
        entry: FixtureEntry | None,
        boundary: BoundaryType,
        fp: str,
        call_index: int,
        name: str | None,
    ) -> bool:
        if rule.fixture_id is not None and (entry is None or entry.fixture_id != rule.fixture_id):
            return False
        if (
            rule.fingerprint is not None
            and rule.fingerprint != fp
            and (entry is None or entry.fingerprint != rule.fingerprint)
        ):
            return False
        if rule.boundary is not None and rule.boundary != boundary:
            return False
        if rule.name is not None:
            entry_name = entry.name if entry is not None else None
            if rule.name != name and rule.name != entry_name:
                return False
        return rule.call_index is None or rule.call_index == call_index


__all__ = [
    "FixtureMatchResult",
    "FixtureMatcher",
]
