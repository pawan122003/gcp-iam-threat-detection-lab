"""Tests for enterprise multi-level triage runner."""

from __future__ import annotations

from pathlib import Path

import app.enterprise_agent_runner as runner


def _dummy_paths() -> tuple[Path, Path, Path, Path]:
    return (
        Path("semgrep.json"),
        Path("gitleaks.json"),
        Path("opa.json"),
        Path("docs/architecture.md"),
    )


def test_execute_uses_hive_when_enabled(monkeypatch):
    semgrep, gitleaks, opa, architecture = _dummy_paths()

    monkeypatch.setenv("ENABLE_HIVE_ENTERPRISE_AGENT", "true")
    monkeypatch.setattr(
        runner,
        "_run_hive_enterprise",
        lambda **_kwargs: {
            "agent_summary": "hive success",
            "overall_risk": "low",
            "blocking_reasons": [],
            "findings": [],
            "block_merge": False,
            "block_reasons": [],
            "used_llm": True,
            "fallback_reason": None,
            "execution_mode": "hive_enterprise_multi_level",
        },
    )
    monkeypatch.setattr(
        runner,
        "_run_local_fallback",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("local should not run")),
    )

    decision, note = runner.execute_enterprise_triage(
        semgrep=semgrep,
        gitleaks=gitleaks,
        opa=opa,
        architecture=architecture,
        threshold=0.80,
        api_key="dummy",
        model="gpt-5.4",
        no_llm=False,
        force_local=False,
    )

    assert note is None
    assert decision["execution_mode"] == "hive_enterprise_multi_level"


def test_execute_falls_back_when_hive_fails(monkeypatch):
    semgrep, gitleaks, opa, architecture = _dummy_paths()
    monkeypatch.setenv("ENABLE_HIVE_ENTERPRISE_AGENT", "true")

    monkeypatch.setattr(
        runner,
        "_run_hive_enterprise",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("hive unavailable")),
    )
    monkeypatch.setattr(
        runner,
        "_run_local_fallback",
        lambda **_kwargs: {
            "agent_summary": "local fallback",
            "overall_risk": "medium",
            "blocking_reasons": [],
            "findings": [],
            "block_merge": False,
            "block_reasons": [],
            "used_llm": True,
            "fallback_reason": None,
            "execution_mode": "local_single_agent",
        },
    )

    decision, note = runner.execute_enterprise_triage(
        semgrep=semgrep,
        gitleaks=gitleaks,
        opa=opa,
        architecture=architecture,
        threshold=0.80,
        api_key="dummy",
        model="gpt-5.4",
        no_llm=False,
        force_local=False,
    )

    assert note is not None
    assert "hive unavailable" in note
    assert decision["execution_mode"] == "local_fallback_from_hive"
    assert "Hive enterprise execution failed" in decision["fallback_reason"]


def test_validate_ci_context_policies() -> None:
    context = {
        "source": "github_actions",
        "is_fork_pr": True,
        "api_key_present": False,
        "provenance_verified": True,
    }
    original = runner._read_json_dict
    try:
        runner._read_json_dict = lambda _path: context
        valid = runner._validate_ci_context(
            Path("ci-context.json"),
            no_llm=True,
            api_key="",
            require_signed_provenance=True,
        )
        assert valid["valid"] is True

        invalid = runner._validate_ci_context(
            Path("ci-context.json"),
            no_llm=False,
            api_key="dummy",
            require_signed_provenance=True,
        )
        assert invalid["valid"] is False
        assert any("fork pull requests" in reason for reason in invalid["reasons"])
    finally:
        runner._read_json_dict = original


def test_validate_scanner_status() -> None:
    original = runner._read_json_dict
    try:
        runner._read_json_dict = lambda _path: {
            "all_valid": True,
            "semgrep": {"exists": True, "json_valid": True},
            "gitleaks": {"exists": True, "json_valid": True},
            "opa": {"exists": True, "json_valid": True},
        }
        status = runner._validate_scanner_status(Path("scanner-status.json"))
        assert status["valid"] is True

        runner._read_json_dict = lambda _path: {
            "all_valid": False,
            "semgrep": {"exists": True, "json_valid": True},
            "gitleaks": {"exists": False, "json_valid": True},
            "opa": {"exists": True, "json_valid": False},
        }
        bad = runner._validate_scanner_status(Path("scanner-status.json"))
        assert bad["valid"] is False
        assert bad["reasons"]
    finally:
        runner._read_json_dict = original


def test_apply_fail_closed_blocks() -> None:
    decision = {
        "block_merge": False,
        "block_reasons": [],
        "findings": [],
        "used_llm": True,
        "execution_mode": "local_single_agent",
    }
    out = runner._apply_fail_closed(
        decision=decision,
        trust_validation={"status": "invalid", "valid": False, "reasons": ["policy mismatch"], "provenance_verified": False},
        scanner_integrity={"status": "valid", "valid": True, "reasons": []},
        require_signed_provenance=True,
    )
    assert out["fail_closed"] is True
    assert out["block_merge"] is True
    assert out["block_reasons"]


def test_build_failure_decision_shape() -> None:
    decision = runner._build_failure_decision("boom", execution_mode="bootstrap_failure")
    assert decision["block_merge"] is True
    assert decision["overall_risk"] == "critical"
    assert decision["execution_mode"] == "bootstrap_failure"
