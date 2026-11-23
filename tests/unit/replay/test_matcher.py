"""Unit tests for FixtureMatcher and override resolution."""

from __future__ import annotations

import pytest

from tracevault.replay import FixtureMatcher
from tracevault.schema import (
    REDACTED_VALUE,
    BoundaryType,
    ExecutionError,
    FixtureEntry,
    FixtureNotFoundError,
    FixtureSet,
    ReplayConfig,
    ReplayError,
    ReplayMode,
    ReplayOverride,
    UnsafeTraceError,
    compute_fingerprint,
    redact_data,
)


def _make_entry(
    fixture_id: str,
    boundary: BoundaryType,
    request: dict[str, object],
    response: dict[str, object] | None = None,
    *,
    call_index: int = 0,
    name: str | None = None,
    error: ExecutionError | None = None,
) -> FixtureEntry:
    redacted_req = redact_data(request)
    fp = compute_fingerprint(boundary, redacted_req)
    return FixtureEntry(
        fixture_id=fixture_id,
        boundary=boundary,
        fingerprint=fp,
        call_index=call_index,
        request=redacted_req,
        response=response,
        error=error,
        name=name,
    )


def test_strict_exact_matching_and_key_order_equivalence() -> None:
    entry = _make_entry(
        "fix_001",
        BoundaryType.MODEL,
        {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}], "temp": 0},
        {"content": "hello"},
        name="openai.chat",
    )
    fixtures = FixtureSet(entries=[entry])
    matcher = FixtureMatcher(fixtures, ReplayConfig(mode=ReplayMode.OFFLINE_STRICT))

    # Reordered keys must produce identical fingerprint
    res = matcher.match(
        BoundaryType.MODEL,
        {"temp": 0, "messages": [{"content": "hi", "role": "user"}], "model": "gpt-4o-mini"},
        name="openai.chat",
    )
    assert res.matched is True
    assert res.overridden is False
    assert res.match_strategy == "exact"
    assert res.call_index == 0
    assert res.entry == entry
    assert res.response == {"content": "hello"}


def test_secret_redaction_before_fingerprinting_and_safe_diagnostics() -> None:
    secret = "sk-live-secret-1234567890abcdef"
    entry = _make_entry(
        "fix_001",
        BoundaryType.MODEL,
        {"model": "gpt-4o-mini", "api_key": secret},
        {"content": "ok"},
    )
    assert entry.request["api_key"] == REDACTED_VALUE

    matcher = FixtureMatcher(FixtureSet(entries=[entry]), ReplayConfig())
    # Matching with a different raw secret still matches because both redact to [REDACTED]
    res = matcher.match(
        BoundaryType.MODEL,
        {"model": "gpt-4o-mini", "api_key": "sk-different-secret-9999999999"},
    )
    assert res.matched is True
    assert res.response == {"content": "ok"}

    # Missing fixture diagnostics must never include secret values
    with pytest.raises(FixtureNotFoundError) as exc_info:
        matcher.match(
            BoundaryType.MODEL,
            {"model": "unseen-model", "api_key": secret},
            name="openai.chat",
        )
    msg = str(exc_info.value)
    assert secret not in msg
    assert "boundary='model'" in msg
    assert "available fixtures for boundary: 1" in msg


def test_repeated_identical_calls_increment_call_index() -> None:
    req = {"query": "invoice 42"}
    e0 = _make_entry("fix_0", BoundaryType.RETRIEVAL, req, {"docs": ["v1"]}, call_index=0)
    e1 = _make_entry("fix_1", BoundaryType.RETRIEVAL, req, {"docs": ["v2"]}, call_index=1)
    matcher = FixtureMatcher(FixtureSet(entries=[e0, e1]), ReplayConfig())

    r0 = matcher.match(BoundaryType.RETRIEVAL, req)
    r1 = matcher.match(BoundaryType.RETRIEVAL, req)
    assert r0.call_index == 0
    assert r0.response == {"docs": ["v1"]}
    assert r1.call_index == 1
    assert r1.response == {"docs": ["v2"]}

    with pytest.raises(FixtureNotFoundError):
        matcher.match(BoundaryType.RETRIEVAL, req)


def test_lenient_matching_by_name_and_boundary_without_double_consumption() -> None:
    e0 = _make_entry(
        "fix_0",
        BoundaryType.TOOL,
        {"tool_name": "search", "arguments": {"q": "alpha"}},
        {"hits": 1},
        name="search",
    )
    e1 = _make_entry(
        "fix_1",
        BoundaryType.TOOL,
        {"tool_name": "calc", "arguments": {"expr": "1+1"}},
        {"result": 2},
        name="calc",
    )
    fixtures = FixtureSet(entries=[e0, e1])
    matcher = FixtureMatcher(
        fixtures,
        ReplayConfig(mode=ReplayMode.OFFLINE_LENIENT, fail_on_missing_fixture=True),
    )

    # Different args, same name -> matches by lenient_name
    r0 = matcher.match(
        BoundaryType.TOOL,
        {"tool_name": "search", "arguments": {"q": "beta"}},
        name="search",
    )
    assert r0.matched is True
    assert r0.match_strategy == "lenient_name"
    assert r0.response == {"hits": 1}

    # Different args & unknown name -> falls back to next unconsumed boundary entry (e1)
    r1 = matcher.match(
        BoundaryType.TOOL,
        {"tool_name": "other", "arguments": {}},
        name="other",
    )
    assert r1.matched is True
    assert r1.match_strategy == "lenient_boundary"
    assert r1.response == {"result": 2}

    # All entries consumed -> must not double-consume
    with pytest.raises(FixtureNotFoundError):
        matcher.match(BoundaryType.TOOL, {"tool_name": "calc", "arguments": {}}, name="calc")


def test_ambiguous_strict_fixtures_raise_replay_error() -> None:
    req = {"prompt": "hello"}
    e0 = _make_entry("fix_a", BoundaryType.MODEL, req, {"content": "one"}, call_index=0)
    e1 = _make_entry("fix_b", BoundaryType.MODEL, req, {"content": "two"}, call_index=0)
    fixtures = FixtureSet(entries=[e0, e1])
    matcher = FixtureMatcher(fixtures, ReplayConfig(mode=ReplayMode.OFFLINE_STRICT))

    assert len(matcher.ambiguous_keys) == 1
    with pytest.raises(ReplayError, match="Ambiguous fixture match"):
        matcher.match(BoundaryType.MODEL, req)


def test_missing_fixture_when_fail_on_missing_false() -> None:
    matcher = FixtureMatcher(
        FixtureSet(entries=[]),
        ReplayConfig(fail_on_missing_fixture=False),
    )
    res = matcher.match(BoundaryType.MODEL, {"prompt": "missing"}, name="chat")
    assert res.matched is False
    assert res.overridden is False
    assert res.match_strategy == "miss"
    assert res.response == {}
    assert res.error is None


def test_defensive_deepcopy_protects_source_fixtures() -> None:
    entry = _make_entry(
        "fix_001",
        BoundaryType.MODEL,
        {"prompt": "hi"},
        {"nested": {"items": [1, 2]}},
    )
    fixtures = FixtureSet(entries=[entry])
    matcher = FixtureMatcher(fixtures, ReplayConfig())

    res = matcher.match(BoundaryType.MODEL, {"prompt": "hi"})
    assert res.response is not None
    res.response["nested"]["items"].append(999)

    assert entry.response == {"nested": {"items": [1, 2]}}


def test_override_rules_and_overrides_dict_precedence() -> None:
    req = {"prompt": "classify"}
    entry = _make_entry("fix_001", BoundaryType.MODEL, req, {"label": "old"}, name="classifier")
    fixtures = FixtureSet(entries=[entry])

    # 1. override_rules take precedence over overrides dict
    cfg = ReplayConfig(
        overrides={"fix_001": {"label": "from_dict"}},
        override_rules=[
            ReplayOverride(
                boundary=BoundaryType.MODEL,
                name="classifier",
                call_index=0,
                response={"label": "from_rule"},
            ),
        ],
    )
    res = FixtureMatcher(fixtures, cfg).match(BoundaryType.MODEL, req, name="classifier")
    assert res.matched is True
    assert res.overridden is True
    assert res.match_strategy == "override"
    assert res.response == {"label": "from_rule"}

    # 2. overrides dict resolves fixture_id before fingerprint
    cfg_dict = ReplayConfig(
        overrides={
            "fix_001": {"label": "by_id"},
            entry.fingerprint: {"label": "by_fp"},
        },
    )
    res_id = FixtureMatcher(fixtures, cfg_dict).match(BoundaryType.MODEL, req, name="classifier")
    assert res_id.overridden is True
    assert res_id.response == {"label": "by_id"}

    # 3. overrides dict by fingerprint when fixture_id absent
    cfg_fp = ReplayConfig(overrides={entry.fingerprint: {"label": "by_fp"}})
    res_fp = FixtureMatcher(fixtures, cfg_fp).match(BoundaryType.MODEL, req, name="classifier")
    assert res_fp.overridden is True
    assert res_fp.response == {"label": "by_fp"}


def test_override_rule_can_inject_error_or_recover_error_fixture() -> None:
    req = {"prompt": "fail_me"}
    err = ExecutionError(error_type="RateLimitError", message="429 too many requests")
    err_entry = _make_entry("fix_err", BoundaryType.MODEL, req, response=None, error=err)
    ok_entry = _make_entry("fix_ok", BoundaryType.MODEL, {"prompt": "ok"}, response={"ok": True})

    # Recover error fixture with an override response
    cfg_recover = ReplayConfig(
        override_rules=[ReplayOverride(fixture_id="fix_err", response={"recovered": True})]
    )
    r_rec = FixtureMatcher(FixtureSet(entries=[err_entry]), cfg_recover).match(
        BoundaryType.MODEL, req
    )
    assert r_rec.overridden is True
    assert r_rec.error is None
    assert r_rec.response == {"recovered": True}

    # Inject error onto a normal fixture
    injected_err = ExecutionError(error_type="TimeoutError", message="simulated timeout")
    cfg_inject = ReplayConfig(
        override_rules=[ReplayOverride(fixture_id="fix_ok", error=injected_err)]
    )
    r_inj = FixtureMatcher(FixtureSet(entries=[ok_entry]), cfg_inject).match(
        BoundaryType.MODEL, {"prompt": "ok"}
    )
    assert r_inj.overridden is True
    assert r_inj.response is None
    assert r_inj.error == injected_err


def test_non_json_safe_request_raises_unsafe_trace_error() -> None:
    matcher = FixtureMatcher(FixtureSet(entries=[]), ReplayConfig())
    with pytest.raises(UnsafeTraceError):
        matcher.match(BoundaryType.MODEL, {"bad": float("nan")})
