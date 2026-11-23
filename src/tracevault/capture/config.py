"""Configuration models for TraceVault capture sessions."""

from __future__ import annotations

from pydantic import Field

from tracevault.schema import RedactionConfig, TraceVaultModel


class CaptureConfig(TraceVaultModel):
    """Configuration controlling TraceVault capture session behavior."""

    redact: bool = True
    redaction_config: RedactionConfig | None = None
    auto_save: bool = False
    overwrite: bool = False
    capture_environment: bool = True
    default_tags: list[str] = Field(default_factory=list)


__all__ = ["CaptureConfig"]
