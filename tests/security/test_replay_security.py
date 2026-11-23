"""Adversarial security, policy-enforcement, and secret-redaction tests for tracevault.replay."""

from __future__ import annotations

from typing import Any

import pytest

from conftest import (
    HOSTILE_TRACE_IDS,
    SYNTHETIC_SECRETS,
    make_deeply_nested_dict,
    make_valid_fixture_entry,
    make_valid_fixture_set,
    make_valid_trace,
)
from tracevault.replay import (
    BoundaryExecutor,
    ModelBoundary,
    ReplayEngine,
    RetrievalBoundary,
    ToolBoundary,
)
from tracevault.schema import (
    DEFAULT_MAX_JSON_DEPTH,
    BoundaryMode,
    BoundaryType,
    FixtureNotFoundError,
    InvalidTraceIdError,
    PolicyViolationError,
    ReplayConfig,
    ReplayMode,
    SafetyPolicy,
    UnsafeTraceError,
    redact_data,
)

NON_NONE_HOSTILE_TRACE_IDS: list[Any] = [tid for tid in HOSTILE_TRACE_IDS if tid is not None]


class TestNoSilentFallbackInRecordedMode:
    """RECORDED mode must never invoke live_fn — even on missing fixtures."""

    def test_recorded_mode_never_calls_live_fn_on_hit_or_miss(self) -> None:
        calls = 0

        def _forbidden_live_fn(req: dict[str, Any]) -> dict[str, Any]:
            nonlocal calls
            calls += 1
            return {"should": "never run", "req": req}

        trace = make_valid_trace(trace_id="tr_no_fallback_001")

        # 1. Strict miss (fail_on_missing_fixture=True) -> FixtureNotFoundError, zero live calls
        strict_engine = ReplayEngine(trace, ReplayConfig(fail_on_missing_fixture=True))
        strict_exec = BoundaryExecutor(strict_engine)

        with pytest.raises(FixtureNotFoundError):
            ModelBoundary(strict_exec).invoke(
                {"model": "missing"},
                live_fn=_forbidden_live_fn,
                host="api.example.test",
            )
        with pytest.raises(FixtureNotFoundError):
            ToolBoundary(strict_exec).invoke(
                "missing_tool",
                {"x": 1},
                live_fn=_forbidden_live_fn,
            )
        with pytest.raises(FixtureNotFoundError):
            RetrievalBoundary(strict_exec).invoke(
                {"query": "missing"},
                live_fn=_forbidden_live_fn,
                host="search.example.test",
            )
        assert calls == 0

        # 2. Miss with fail_on_missing_fixture=False -> returns {}, zero live calls
        lenient_miss_engine = ReplayEngine(trace, ReplayConfig(fail_on_missing_fixture=False))
        lenient_miss_exec = BoundaryExecutor(lenient_miss_engine)
        assert (
            ModelBoundary(lenient_miss_exec).invoke(
                {"model": "missing"},
                live_fn=_forbidden_live_fn,
            )
            == {}
        )
        assert (
            ToolBoundary(lenient_miss_exec).invoke(
                "missing_tool",
                {"x": 1},
                live_fn=_forbidden_live_fn,
            )
            == {}
        )
        assert (
            RetrievalBoundary(lenient_miss_exec).invoke(
                {"query": "missing"},
                live_fn=_forbidden_live_fn,
            )
            == {}
        )
        assert calls == 0

        # 3. Exact hit -> returns recorded fixture, zero live calls
        hit_engine = ReplayEngine(trace)
        hit_exec = BoundaryExecutor(hit_engine)
        recorded_req = trace.fixtures.entries[0].request
        resp = ModelBoundary(hit_exec).invoke(recorded_req, live_fn=_forbidden_live_fn)
        assert resp == trace.fixtures.entries[0].response
        assert calls == 0


class TestFailClosedPolicyEnforcement:
    """Every unauthorized LIVE or DENY condition must raise PolicyViolationError fail-closed."""

    def test_deny_mode_blocks_engine_and_executor(self) -> None:
        live_called = False

        def _live_fn(_req: dict[str, Any]) -> dict[str, Any]:
            nonlocal live_called
            live_called = True
            return {"ok": True}

        trace = make_valid_trace(trace_id="tr_deny_001")
        cfg = ReplayConfig(boundary_modes={BoundaryType.MODEL: BoundaryMode.DENY})
        engine = ReplayEngine(trace, cfg)
        executor = BoundaryExecutor(engine)

        with pytest.raises(PolicyViolationError):
            engine.replay_interaction(BoundaryType.MODEL, {"model": "gpt-4o-mini"})
        with pytest.raises(PolicyViolationError):
            engine.replay_trace()
        with pytest.raises(PolicyViolationError):
            ModelBoundary(executor).invoke({"model": "gpt-4o-mini"}, live_fn=_live_fn)
        assert live_called is False

    def test_replay_engine_directly_rejects_live_boundary_mode(self) -> None:
        trace = make_valid_trace(trace_id="tr_engine_live_001")
        cfg = ReplayConfig(
            mode=ReplayMode.BOUNDARY_GOVERNED,
            boundary_modes={BoundaryType.MODEL: BoundaryMode.LIVE},
            safety_policy=SafetyPolicy(
                allow_live_boundaries={BoundaryType.MODEL},
                allowed_hosts={"api.example.test"},
                max_live_calls=5,
            ),
        )
        engine = ReplayEngine(trace, cfg)
        with pytest.raises(PolicyViolationError):
            engine.replay_interaction(BoundaryType.MODEL, {"model": "gpt-4o-mini"})
        with pytest.raises(PolicyViolationError):
            engine.replay_trace()

    def test_unauthorized_live_conditions_all_fail_closed(self) -> None:
        live_called = 0

        def _live_fn(_req: dict[str, Any]) -> dict[str, Any]:
            nonlocal live_called
            live_called += 1
            return {"ok": True}

        trace = make_valid_trace(trace_id="tr_policy_matrix_001")

        # 1. Default SafetyPolicy with LIVE boundary
        cfg_default = ReplayConfig(
            mode=ReplayMode.BOUNDARY_GOVERNED,
            boundary_modes={BoundaryType.MODEL: BoundaryMode.LIVE},
        )
        with pytest.raises(PolicyViolationError):
            ModelBoundary(BoundaryExecutor(ReplayEngine(trace, cfg_default))).invoke(
                {"q": "hi"}, live_fn=_live_fn, host="api.example.test"
            )

        # 2. Wrong ReplayMode (OFFLINE_STRICT / OFFLINE_LENIENT) even with permissive SafetyPolicy
        for wrong_mode in (ReplayMode.OFFLINE_STRICT, ReplayMode.OFFLINE_LENIENT):
            cfg_wrong_mode = ReplayConfig(
                mode=wrong_mode,
                boundary_modes={BoundaryType.MODEL: BoundaryMode.LIVE},
                safety_policy=SafetyPolicy(
                    allow_live_boundaries={BoundaryType.MODEL},
                    allowed_hosts={"api.example.test"},
                    max_live_calls=5,
                ),
            )
            with pytest.raises(PolicyViolationError):
                ModelBoundary(BoundaryExecutor(ReplayEngine(trace, cfg_wrong_mode))).invoke(
                    {"q": "hi"}, live_fn=_live_fn, host="api.example.test"
                )

        # 3. Boundary not in allow_live_boundaries
        cfg_wrong_boundary = ReplayConfig(
            mode=ReplayMode.BOUNDARY_GOVERNED,
            boundary_modes={BoundaryType.TOOL: BoundaryMode.LIVE},
            safety_policy=SafetyPolicy(
                allow_live_boundaries={BoundaryType.MODEL},
                allowed_tools={"calc"},
                max_live_calls=5,
            ),
        )
        with pytest.raises(PolicyViolationError):
            ToolBoundary(BoundaryExecutor(ReplayEngine(trace, cfg_wrong_boundary))).invoke(
                "calc", {"x": 1}, live_fn=_live_fn
            )

        # 4. max_live_calls=0 with require_explicit_opt_in=True
        cfg_zero_cap = ReplayConfig(
            mode=ReplayMode.BOUNDARY_GOVERNED,
            boundary_modes={BoundaryType.MODEL: BoundaryMode.LIVE},
            safety_policy=SafetyPolicy(
                allow_live_boundaries={BoundaryType.MODEL},
                allowed_hosts={"api.example.test"},
                max_live_calls=0,
                require_explicit_opt_in=True,
            ),
        )
        with pytest.raises(PolicyViolationError):
            ModelBoundary(BoundaryExecutor(ReplayEngine(trace, cfg_zero_cap))).invoke(
                {"q": "hi"}, live_fn=_live_fn, host="api.example.test"
            )

        # 5. Tool not in allowed_tools
        cfg_bad_tool = ReplayConfig(
            mode=ReplayMode.BOUNDARY_GOVERNED,
            boundary_modes={BoundaryType.TOOL: BoundaryMode.LIVE},
            safety_policy=SafetyPolicy(
                allow_live_boundaries={BoundaryType.TOOL},
                allowed_tools={"safe_tool"},
                max_live_calls=5,
            ),
        )
        with pytest.raises(PolicyViolationError):
            ToolBoundary(BoundaryExecutor(ReplayEngine(trace, cfg_bad_tool))).invoke(
                "shell_exec", {"cmd": "id"}, live_fn=_live_fn
            )

        # 6. Host not in allowed_hosts (and empty allowed_hosts when host supplied)
        cfg_bad_host = ReplayConfig(
            mode=ReplayMode.BOUNDARY_GOVERNED,
            boundary_modes={
                BoundaryType.MODEL: BoundaryMode.LIVE,
                BoundaryType.RETRIEVAL: BoundaryMode.LIVE,
            },
            safety_policy=SafetyPolicy(
                allow_live_boundaries={BoundaryType.MODEL, BoundaryType.RETRIEVAL},
                allowed_hosts={"allowed.example.test"},
                max_live_calls=5,
            ),
        )
        exec_bad_host = BoundaryExecutor(ReplayEngine(trace, cfg_bad_host))
        with pytest.raises(PolicyViolationError):
            ModelBoundary(exec_bad_host).invoke(
                {"q": "hi"}, live_fn=_live_fn, host="evil.example.test"
            )
        with pytest.raises(PolicyViolationError):
            RetrievalBoundary(exec_bad_host).invoke(
                {"q": "hi"}, live_fn=_live_fn, host="evil.example.test"
            )
        # Missing host when allowed_hosts is configured also fails closed
        with pytest.raises(PolicyViolationError):
            ModelBoundary(exec_bad_host).invoke({"q": "hi"}, live_fn=_live_fn, host=None)

        assert live_called == 0

    def test_max_live_calls_cap_enforced(self) -> None:
        calls = 0

        def _live_fn(req: dict[str, Any]) -> dict[str, Any]:
            nonlocal calls
            calls += 1
            return {"echo": req["q"]}

        trace = make_valid_trace(trace_id="tr_cap_001")
        cfg = ReplayConfig(
            mode=ReplayMode.BOUNDARY_GOVERNED,
            boundary_modes={BoundaryType.MODEL: BoundaryMode.LIVE},
            safety_policy=SafetyPolicy(
                allow_live_boundaries={BoundaryType.MODEL},
                allowed_hosts={"api.example.test"},
                max_live_calls=1,
            ),
        )
        executor = BoundaryExecutor(ReplayEngine(trace, cfg))
        model = ModelBoundary(executor)

        assert model.invoke({"q": "first"}, live_fn=_live_fn, host="api.example.test") == {
            "echo": "first"
        }
        assert calls == 1

        with pytest.raises(PolicyViolationError, match="limit reached"):
            model.invoke({"q": "second"}, live_fn=_live_fn, host="api.example.test")
        assert calls == 1


class TestMaliciousFixturesAndImmutability:
    """Malicious fixture payloads remain inert and source Trace is never mutated."""

    def test_malicious_payloads_inert_and_source_trace_immutable(self) -> None:
        hostile_str = (
            "__import__('os').system('echo pwned'); $(whoami); `id`; {{7*7}}; ${jndi:ldap://x}"
        )
        entry = make_valid_fixture_entry(
            fixture_id="fix_hostile_001",
            boundary=BoundaryType.MODEL,
            request={"prompt": hostile_str, "nested": {"expr": hostile_str}},
            response={"content": hostile_str, "items": [{"val": hostile_str}]},
        )
        trace = make_valid_trace(
            trace_id="tr_inert_replay_001",
            fixtures=make_valid_fixture_set([entry]),
        )
        before_json = trace.to_json()

        engine = ReplayEngine(trace)
        returned = engine.replay_interaction(
            BoundaryType.MODEL,
            {"prompt": hostile_str, "nested": {"expr": hostile_str}},
        )
        assert returned["content"] == hostile_str

        # Mutate returned response dict aggressively to verify defensive deepcopy
        returned["content"] = "MUTATED"
        returned["items"][0]["val"] = "MUTATED"
        returned["injected"] = True

        result = engine.replay_trace(fork=True)
        assert result.success is True
        assert result.candidate_trace.fixtures.entries[0].response is not None
        assert result.candidate_trace.fixtures.entries[0].response["content"] == hostile_str

        # Source trace must be byte-for-byte identical
        assert trace.to_json() == before_json


class TestHostileReplayInputs:
    """Cyclic, non-finite, non-JSON-safe, deep payloads and hostile trace IDs rejected."""

    def test_hostile_request_payloads_rejected_with_unsafe_trace_error(self) -> None:
        trace = make_valid_trace(trace_id="tr_hostile_req_001")
        engine = ReplayEngine(trace)
        executor = BoundaryExecutor(engine)

        cyclic_dict: dict[str, Any] = {}
        cyclic_dict["self"] = cyclic_dict

        cyclic_list: list[Any] = []
        cyclic_list.append(cyclic_list)

        hostile_requests: list[Any] = [
            cyclic_dict,
            {"items": cyclic_list},
            {"nan": float("nan")},
            {"inf": float("inf")},
            {"neg_inf": float("-inf")},
            {"obj": object()},
            {"set": {1, 2}},
            {"bytes": b"raw"},
            {1: "non-string-key"},
            make_deeply_nested_dict(DEFAULT_MAX_JSON_DEPTH + 1),
            "not-a-dict",
        ]

        for bad_req in hostile_requests:
            with pytest.raises(UnsafeTraceError):
                engine.replay_interaction(BoundaryType.MODEL, bad_req)
            with pytest.raises(UnsafeTraceError):
                executor.execute(BoundaryType.MODEL, bad_req)

    @pytest.mark.parametrize("bad_id", NON_NONE_HOSTILE_TRACE_IDS)
    def test_hostile_new_trace_id_rejected_across_replay_methods(self, bad_id: Any) -> None:
        trace = make_valid_trace(trace_id="tr_valid_base_001")
        engine = ReplayEngine(trace)

        with pytest.raises(InvalidTraceIdError):
            engine.replay_trace(fork=True, new_trace_id=bad_id)
        with pytest.raises(InvalidTraceIdError):
            engine.fork(new_trace_id=bad_id)
        with pytest.raises(InvalidTraceIdError):
            engine.build_result(fork=True, new_trace_id=bad_id)


class TestReplaySecretRedaction:
    """Synthetic secrets in replay requests, error diagnostics, and live responses never leak."""

    def test_secrets_in_missing_request_do_not_leak_in_error_or_candidate_trace(self) -> None:
        trace = make_valid_trace(trace_id="tr_secret_replay_001")
        secret_req: dict[str, Any] = {
            "api_key": SYNTHETIC_SECRETS["openai_key"],
            "authorization": SYNTHETIC_SECRETS["bearer_token"],
            "prompt": (
                f"aws={SYNTHETIC_SECRETS['aws_access_key']} "
                f"gh={SYNTHETIC_SECRETS['github_pat']} "
                f"jwt={SYNTHETIC_SECRETS['jwt_token']}"
            ),
        }

        # 1. FixtureNotFoundError diagnostic must not leak secrets
        strict_engine = ReplayEngine(trace, ReplayConfig(fail_on_missing_fixture=True))
        with pytest.raises(FixtureNotFoundError) as exc_info:
            strict_engine.replay_interaction(BoundaryType.MODEL, secret_req, name="secret_call")
        err_msg = str(exc_info.value)
        for name, secret in SYNTHETIC_SECRETS.items():
            assert secret not in err_msg, f"Secret '{name}' leaked in FixtureNotFoundError"

        # 2. Candidate trace JSON from lenient miss must not leak secrets
        lenient_engine = ReplayEngine(trace, ReplayConfig(fail_on_missing_fixture=False))
        lenient_engine.replay_interaction(BoundaryType.MODEL, secret_req, name="secret_call")
        candidate_json = lenient_engine.build_result(fork=True).candidate_trace.to_json()
        for name, secret in SYNTHETIC_SECRETS.items():
            assert secret not in candidate_json, f"Secret '{name}' leaked in candidate trace JSON"

    def test_secrets_in_authorized_live_response_redacted_everywhere(self) -> None:
        trace = make_valid_trace(trace_id="tr_secret_live_001")
        cfg = ReplayConfig(
            mode=ReplayMode.BOUNDARY_GOVERNED,
            boundary_modes={BoundaryType.MODEL: BoundaryMode.LIVE},
            safety_policy=SafetyPolicy(
                allow_live_boundaries={BoundaryType.MODEL},
                allowed_hosts={"api.example.test"},
                max_live_calls=2,
            ),
        )
        engine = ReplayEngine(trace, cfg)
        model = ModelBoundary(BoundaryExecutor(engine))

        def _local_mock_live_handler(_req: dict[str, Any]) -> dict[str, Any]:
            return {
                "content": f"Leaked {SYNTHETIC_SECRETS['openai_proj_key']}",
                "headers": {"Authorization": SYNTHETIC_SECRETS["bearer_token"]},
                "token": SYNTHETIC_SECRETS["github_pat"],
                "jwt": SYNTHETIC_SECRETS["jwt_token"],
                "aws": SYNTHETIC_SECRETS["aws_access_key"],
            }

        req_with_secret = {"api_key": SYNTHETIC_SECRETS["openai_key"], "prompt": "hello"}
        returned = model.invoke(
            req_with_secret,
            live_fn=_local_mock_live_handler,
            host="api.example.test",
            name="live_mock",
        )
        returned_str = str(returned)
        candidate_json = engine.build_result(fork=True).candidate_trace.to_json()

        for name, secret in SYNTHETIC_SECRETS.items():
            assert secret not in returned_str, f"Secret '{name}' leaked in live response"
            assert secret not in candidate_json, f"Secret '{name}' leaked in live candidate trace"

        # Verify request was also redacted before fingerprinting
        assert redact_data(req_with_secret)["api_key"] == "[REDACTED]"
