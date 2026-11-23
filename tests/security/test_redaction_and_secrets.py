"""Secret redaction and zero-leakage security tests for tracevault.schema."""

from __future__ import annotations

import json
from typing import Any

import pytest

from conftest import (
    SYNTHETIC_SECRETS,
    make_valid_event,
    make_valid_fixture_entry,
    make_valid_fixture_set,
    make_valid_run,
    make_valid_span,
    make_valid_trace,
)
from tracevault.schema import (
    REDACTED_VALUE,
    BoundaryType,
    EventKind,
    ExecutionError,
    RedactionConfig,
    redact_data,
)


class TestSensitiveKeyRedaction:
    """Case-insensitive substring key matching across nested containers."""

    @pytest.mark.parametrize(
        "key",
        [
            "api_key",
            "API_KEY",
            "ApiKey",
            "openai_api_key",
            "OPENAI_API_KEY",
            "Authorization",
            "x-api-key",
            "X-API-KEY",
            "auth_token",
            "access_token",
            "refresh_token",
            "client_secret",
            "PASSWORD",
            "user_passwd",
            "service_credential",
            "private_key_pem",
            "bearer_header",
        ],
    )
    def test_sensitive_keys_redacted_regardless_of_case(self, key: str) -> None:
        payload = {
            key: "synthetic-placeholder-value-12345",
            "safe_field": "keep-me",
        }
        redacted = redact_data(payload)
        assert redacted[key] == REDACTED_VALUE
        assert redacted["safe_field"] == "keep-me"

    def test_nested_dicts_and_lists_redact_sensitive_keys(self) -> None:
        payload = {
            "headers": {
                "Authorization": "Basic synthetic-fake-creds",
                "Accept": "application/json",
            },
            "items": [
                {"user": "alice", "ApiKey": "fake-val-1"},
                {"nested": {"db_password": {"raw": "fake-val-2"}}},
            ],
        }
        redacted = redact_data(payload)
        assert redacted["headers"]["Authorization"] == REDACTED_VALUE
        assert redacted["headers"]["Accept"] == "application/json"
        assert redacted["items"][0]["ApiKey"] == REDACTED_VALUE
        assert redacted["items"][0]["user"] == "alice"
        assert redacted["items"][1]["nested"]["db_password"] == REDACTED_VALUE


class TestCredentialPatternRedaction:
    """Regex pattern redaction for known token formats inside arbitrary strings."""

    @pytest.mark.parametrize("secret_name,secret_value", list(SYNTHETIC_SECRETS.items()))
    def test_standalone_and_embedded_secret_patterns_redacted(
        self, secret_name: str, secret_value: str
    ) -> None:
        assert secret_value not in redact_data(secret_value), f"{secret_name} leaked standalone"

        embedded = f"Request failed with token={secret_value} during upstream call"
        redacted = redact_data(embedded)
        assert secret_value not in redacted, f"{secret_name} leaked when embedded"
        assert REDACTED_VALUE in redacted

    def test_multiple_secrets_in_single_string_all_redacted(self) -> None:
        combined = (
            f"key1={SYNTHETIC_SECRETS['openai_key']} "
            f"key2={SYNTHETIC_SECRETS['openai_proj_key']} "
            f"aws={SYNTHETIC_SECRETS['aws_access_key']} "
            f"gh={SYNTHETIC_SECRETS['github_pat']} "
            f"jwt={SYNTHETIC_SECRETS['jwt_token']} "
            f"hdr={SYNTHETIC_SECRETS['bearer_token']}"
        )
        redacted = redact_data(combined)
        for name, secret in SYNTHETIC_SECRETS.items():
            assert secret not in redacted, f"Secret {name} survived combined redaction"


class TestEndToEndTraceZeroSecretLeakage:
    """Verify no synthetic secret survives redaction + Trace JSON serialization."""

    def test_no_secret_survives_request_response_metadata_and_exception_serialization(self) -> None:
        raw_request: dict[str, Any] = {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "headers": {
                "Authorization": SYNTHETIC_SECRETS["bearer_token"],
                "X-Api-Key": SYNTHETIC_SECRETS["openai_key"],
            },
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"Check AWS {SYNTHETIC_SECRETS['aws_access_key']} "
                        f"and GitHub {SYNTHETIC_SECRETS['github_pat']}"
                    ),
                }
            ],
        }
        raw_response: dict[str, Any] = {
            "content": f"Echoing jwt {SYNTHETIC_SECRETS['jwt_token']}",
            "raw_metadata": {"openai_api_key": SYNTHETIC_SECRETS["openai_proj_key"]},
        }
        raw_error_details: dict[str, Any] = {
            "upstream_header": SYNTHETIC_SECRETS["bearer_token"],
            "token_hint": SYNTHETIC_SECRETS["openai_key"],
        }
        raw_metadata: dict[str, Any] = {
            "service_secret": "synthetic-super-secret",
            "debug_note": f"using {SYNTHETIC_SECRETS['openai_proj_key']}",
        }

        redacted_request = redact_data(raw_request)
        redacted_response = redact_data(raw_response)
        redacted_error = ExecutionError(
            error_type="UpstreamAuthError",
            message=redact_data(f"Auth failed for {SYNTHETIC_SECRETS['openai_key']}"),
            traceback_summary=redact_data(
                f"File 'client.py', line 10: header='{SYNTHETIC_SECRETS['bearer_token']}'"
            ),
            details=redact_data(raw_error_details),
        )
        redacted_metadata = redact_data(raw_metadata)

        trace = make_valid_trace(
            runs=[
                make_valid_run(
                    inputs=redact_data({"api_key": SYNTHETIC_SECRETS["openai_key"], "q": "hi"}),
                    outputs=redacted_response,
                    error=redacted_error,
                    metadata=redacted_metadata,
                )
            ],
            spans=[
                make_valid_span(
                    attributes=redact_data({"auth_token": SYNTHETIC_SECRETS["jwt_token"]}),
                    error=redacted_error,
                    event_ids=["ev_001"],
                )
            ],
            events=[
                make_valid_event(
                    event_id="ev_001",
                    event_type=EventKind.MODEL_REQUEST,
                    boundary=BoundaryType.MODEL,
                    payload=redacted_request,
                    metadata=redacted_metadata,
                )
            ],
            fixtures=make_valid_fixture_set(
                [
                    make_valid_fixture_entry(
                        request=redacted_request,
                        response=redacted_response,
                    )
                ]
            ),
            metadata=redacted_metadata,
        )

        serialized = trace.to_json()
        # Verify serialized JSON is valid and contains zero synthetic secrets.
        json.loads(serialized)
        for name, secret in SYNTHETIC_SECRETS.items():
            assert secret not in serialized, f"Synthetic secret '{name}' leaked into Trace JSON"
        assert "synthetic-super-secret" not in serialized


class TestRedactionIdempotencyAndConfig:
    """Idempotency and custom RedactionConfig guarantees."""

    def test_redact_data_is_idempotent(self) -> None:
        sample: dict[str, Any] = {
            "api_key": SYNTHETIC_SECRETS["openai_key"],
            "nested": [
                {"note": f"Token: {SYNTHETIC_SECRETS['bearer_token']}"},
                {"jwt": SYNTHETIC_SECRETS["jwt_token"]},
                {"already": REDACTED_VALUE},
                {"count": 42, "ok": True, "empty": None},
            ],
        }
        once = redact_data(sample)
        twice = redact_data(once)
        assert twice == once

    def test_custom_redaction_config(self) -> None:
        cfg = RedactionConfig(
            sensitive_keys=frozenset({"custom_pin"}),
            redact_patterns=(r"PIN-\d{6}",),
            replacement="<MASKED>",
        )
        data = {"custom_pin": "999999", "msg": "Code is PIN-123456", "safe": "ok"}
        redacted = redact_data(data, config=cfg)
        assert redacted == {"custom_pin": "<MASKED>", "msg": "Code is <MASKED>", "safe": "ok"}
        assert redact_data(redacted, config=cfg) == redacted
