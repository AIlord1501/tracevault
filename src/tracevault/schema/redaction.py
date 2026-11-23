"""Recursive, cycle-safe, idempotent secret redaction for TraceVault data."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from tracevault.schema.models import TraceVaultModel

REDACTED_VALUE = "[REDACTED]"

DEFAULT_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "auth_token",
        "access_token",
        "refresh_token",
        "secret",
        "password",
        "passwd",
        "credential",
        "private_key",
        "bearer",
        "x-api-key",
        "openai_api_key",
    }
)

DEFAULT_REDACT_PATTERNS: tuple[str, ...] = (
    r"sk-[A-Za-z0-9_-]{10,}",
    r"Bearer\s+\S+",
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[A-Za-z0-9]{20,}",
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
)


class RedactionConfig(TraceVaultModel):
    """Configuration controlling key-based and regex-based secret redaction."""

    sensitive_keys: frozenset[str] = DEFAULT_SENSITIVE_KEYS
    redact_patterns: tuple[str, ...] = DEFAULT_REDACT_PATTERNS
    replacement: str = REDACTED_VALUE


@lru_cache(maxsize=32)
def _compile_patterns(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern) for pattern in patterns)


def _is_sensitive_key(key: str, normalized_keys: frozenset[str]) -> bool:
    lowered = key.lower()
    return any(sensitive in lowered for sensitive in normalized_keys)


def _redact_string(
    value: str,
    compiled_patterns: tuple[re.Pattern[str], ...],
    replacement: str,
) -> str:
    if value == replacement:
        return value
    result = value
    for pattern in compiled_patterns:
        result = pattern.sub(replacement, result)
    return result


def redact_data(data: Any, config: RedactionConfig | None = None) -> Any:
    """Recursively and idempotently redact sensitive keys and credential patterns."""
    cfg = config if config is not None else RedactionConfig()
    normalized_keys = frozenset(key.lower() for key in cfg.sensitive_keys)
    compiled_patterns = _compile_patterns(cfg.redact_patterns)
    replacement = cfg.replacement
    active_containers: set[int] = set()

    def _walk(value: Any) -> Any:
        if isinstance(value, str):
            return _redact_string(value, compiled_patterns, replacement)
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, dict):
            obj_id = id(value)
            if obj_id in active_containers:
                return replacement
            active_containers.add(obj_id)
            try:
                redacted_dict: dict[Any, Any] = {}
                for k, v in value.items():
                    if isinstance(k, str) and _is_sensitive_key(k, normalized_keys):
                        redacted_dict[k] = replacement
                    else:
                        redacted_dict[k] = _walk(v)
                return redacted_dict
            finally:
                active_containers.discard(obj_id)
        if isinstance(value, list):
            obj_id = id(value)
            if obj_id in active_containers:
                return replacement
            active_containers.add(obj_id)
            try:
                return [_walk(item) for item in value]
            finally:
                active_containers.discard(obj_id)
        if isinstance(value, tuple):
            obj_id = id(value)
            if obj_id in active_containers:
                return replacement
            active_containers.add(obj_id)
            try:
                return tuple(_walk(item) for item in value)
            finally:
                active_containers.discard(obj_id)
        return value

    return _walk(data)


__all__ = [
    "REDACTED_VALUE",
    "DEFAULT_SENSITIVE_KEYS",
    "DEFAULT_REDACT_PATTERNS",
    "RedactionConfig",
    "redact_data",
]
