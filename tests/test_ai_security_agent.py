"""Tests for AI security triage agent."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import app.ai_security_agent as agent


def test_parse_semgrep_json() -> None:
    payload = {
        "results": [
            {
                "check_id": "gcp-service-account-key-hardcoded",
                "path": "app/demo.py",
                "start": {"line": 9},
                "extra": {"severity": "ERROR", "message": "Hardcoded GCP service account key detected."},
            }
        ]
    }
    findings = agent.parse_semgrep_payload(payload)

    assert len(findings) == 1
    assert findings[0].source == "semgrep"
    assert findings[0].rule_id == "gcp-service-account-key-hardcoded"
    assert findings[0].file == "app/demo.py"
    assert findings[0].line == 9
    assert findings[0].severity == "high"


def test_parse_gitleaks_json() -> None:
    payload = [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "src/config.py",
            "StartLine": 14,
            "Match": "AIzaSyAABBCCDDEE1122334455667788990011223",
        }
    ]
    findings = agent.parse_gitleaks_payload(payload)

    assert len(findings) == 1
    assert findings[0].source == "gitleaks"
    assert findings[0].severity == "critical"
    assert findings[0].confidence == pytest.approx(0.95)
    assert findings[0].file == "src/config.py"


def test_parse_opa_json() -> None:
    payload = {
        "result": [
            {
                "expressions": [
                    {
                        "value": {
                            "deny": [
                                "Owner role grants excessive permissions.",
                                "Public access (allUsers) detected.",
                            ],
                            "warn": ["Service account has admin role."],
                        }
                    }
                ]
            }
        ]
    }
    findings = agent.parse_opa_payload(payload)

    assert len(findings) == 3
    severities = sorted(item.severity for item in findings)
    assert severities == ["critical", "high", "medium"]


def test_load_validated_scanner_payloads_rejects_bad_shape() -> None:
    with pytest.raises(ValueError):
        agent._validate_semgrep_payload({"oops": []})


def test_should_block_on_critical_threshold() -> None:
    decision = {
        "findings": [
            {
                "source": "opa",
                "rule_id": "opa.deny",
                "severity": "critical",
                "confidence": 0.82,
                "file": "policies/opa/iam_least_privilege.rego",
                "line": 1,
                "evidence": "Public access (allUsers) detected.",
                "remediation": "Remove public members.",
                "category": "iam-policy",
            },
            {
                "source": "semgrep",
                "rule_id": "iam-policy-overpermissive-role",
                "severity": "high",
                "confidence": 0.99,
                "file": "infra/terraform/main.tf",
                "line": 22,
                "evidence": "roles/owner found",
                "remediation": "Use least privilege roles.",
                "category": "iam-policy",
            },
        ],
        "blocking_reasons": [],
    }

    blocked, reasons = agent.should_block_merge(decision, threshold=0.80)
    assert blocked is True
    assert reasons

    blocked_high_threshold, _ = agent.should_block_merge(decision, threshold=0.90)
    assert blocked_high_threshold is False


def test_validate_triage_response_rejects_bad_schema() -> None:
    with pytest.raises(ValueError):
        agent.validate_triage_response({"findings": "not-a-list"})

    with pytest.raises(ValueError):
        agent.validate_triage_response(
            {
                "agent_summary": "bad confidence",
                "overall_risk": "high",
                "blocking_reasons": [],
                "findings": [
                    {
                        "source": "semgrep",
                        "rule_id": "x",
                        "severity": "critical",
                        "confidence": 1.4,
                        "file": "a.py",
                        "line": 1,
                        "evidence": "x",
                        "remediation": "x",
                        "category": "x",
                    }
                ],
            }
        )


def test_run_triage_fallback_on_llm_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    semgrep_payload = {
        "results": [
            {
                "check_id": "gcp-api-key-hardcoded",
                "path": "app/settings.py",
                "start": {"line": 12},
                "extra": {"severity": "ERROR", "message": "Hardcoded API key detected"},
            }
        ]
    }
    monkeypatch.setattr(
        agent,
        "load_validated_scanner_payloads",
        lambda *_args, **_kwargs: (semgrep_payload, [], {"result": []}),
    )

    def broken_api(*_args, **_kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("simulated API outage")

    decision = agent.run_triage(
        semgrep_path=Path("semgrep.json"),
        gitleaks_path=Path("gitleaks.json"),
        opa_path=Path("opa.json"),
        architecture_path=Path("docs/architecture.md"),
        threshold=0.80,
        model="gpt-5.4",
        use_llm=True,
        api_key="dummy",
        api_caller=broken_api,
    )

    assert decision["used_llm"] is False
    assert decision["fallback_reason"]
    assert isinstance(decision["findings"], list)
    assert decision["block_merge"] is False


def test_run_triage_with_mocked_llm_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        agent,
        "load_validated_scanner_payloads",
        lambda *_args, **_kwargs: ({"results": []}, [], {"result": []}),
    )

    advisory_response = {
        "agent_summary": "No blocking issues.",
        "overall_risk": "low",
        "blocking_reasons": [],
        "findings": [
            {
                "source": "semgrep",
                "rule_id": "sample.rule",
                "severity": "medium",
                "confidence": 0.65,
                "file": "x.tf",
                "line": 4,
                "evidence": "example",
                "remediation": "example",
                "category": "iac-misconfig",
            }
        ],
    }
    critical_response = {
        "agent_summary": "Critical issue found.",
        "overall_risk": "critical",
        "blocking_reasons": [],
        "findings": [
            {
                "source": "gitleaks",
                "rule_id": "generic-api-key",
                "severity": "critical",
                "confidence": 0.91,
                "file": "secrets.py",
                "line": 10,
                "evidence": "API key",
                "remediation": "Rotate key",
                "category": "secret-exposure",
            }
        ],
    }

    decision_advisory = agent.run_triage(
        semgrep_path=Path("semgrep.json"),
        gitleaks_path=Path("gitleaks.json"),
        opa_path=Path("opa.json"),
        architecture_path=Path("docs/architecture.md"),
        threshold=0.80,
        model="gpt-5.4",
        use_llm=True,
        api_key="dummy",
        api_caller=lambda *_: advisory_response,
    )
    assert decision_advisory["used_llm"] is True
    assert decision_advisory["block_merge"] is False

    decision_critical = agent.run_triage(
        semgrep_path=Path("semgrep.json"),
        gitleaks_path=Path("gitleaks.json"),
        opa_path=Path("opa.json"),
        architecture_path=Path("docs/architecture.md"),
        threshold=0.80,
        model="gpt-5.4",
        use_llm=True,
        api_key="dummy",
        api_caller=lambda *_: critical_response,
    )
    assert decision_critical["used_llm"] is True
    assert decision_critical["block_merge"] is True


def test_build_sarif_shape() -> None:
    decision = {
        "findings": [
            {
                "source": "gitleaks",
                "rule_id": "generic-api-key",
                "severity": "critical",
                "confidence": 0.92,
                "file": "secrets.py",
                "line": 10,
                "evidence": "Detected API key",
                "remediation": "Rotate key",
                "category": "secret-exposure",
            }
        ]
    }
    sarif = agent.build_sarif(decision)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_build_toon_payload_is_deterministic() -> None:
    decision = {
        "overall_risk": "critical",
        "block_merge": True,
        "used_llm": True,
        "fail_closed": False,
        "provenance_verified": True,
        "execution_mode": "hive_enterprise_multi_level",
        "threshold": 0.80,
        "findings": [
            {
                "source": "opa",
                "rule_id": "opa.deny",
                "severity": "critical",
                "confidence": 0.91,
                "file": "p.rego",
                "line": 1,
                "evidence": "allUsers",
                "remediation": "remove",
                "category": "iam-policy",
            }
        ],
    }

    one = agent.build_toon_payload(decision)
    two = agent.build_toon_payload(decision)

    assert one == two
    assert one["schema"] == "toon.v1"
    assert one["objects"][0]["object_type"] == "decision"
    for obj in one["objects"]:
        for pair in obj["pairs"]:
            assert 0 <= pair[0] < len(one["token_table"])
            assert 0 <= pair[1] < len(one["token_table"])
