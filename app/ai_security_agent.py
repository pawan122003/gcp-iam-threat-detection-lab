"""AI security triage agent for GitHub-centric CI workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

MARKER = "<!-- ai-security-triage-agent -->"
DEFAULT_MODEL = "gpt-5.4"
DEFAULT_THRESHOLD = 0.80
DEFAULT_TIMEOUT_SECONDS = 30
OPENAI_MAX_ATTEMPTS = 3
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass
class Finding:
    source: str
    rule_id: str
    severity: str
    confidence: float
    file: str
    line: int
    evidence: str
    remediation: str
    category: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": round(float(self.confidence), 2),
            "file": self.file,
            "line": int(self.line),
            "evidence": self.evidence,
            "remediation": self.remediation,
            "category": self.category,
        }


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        try:
            return json.load(handle)
        except json.JSONDecodeError:
            return default


def _read_json_strict(path: Path) -> Any:
    if not path.exists():
        raise ValueError(f"Scanner artifact missing: {path}")
    with path.open("r", encoding="utf-8") as handle:
        try:
            return json.load(handle)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Scanner artifact is not valid JSON: {path}") from exc


def _to_int(value: Any, default: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _normalize_severity(value: str) -> str:
    raw = (value or "").strip().lower()
    mapping = {
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "note": "low",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    return mapping.get(raw, "low")


def _infer_category(source: str, rule_id: str, evidence: str) -> str:
    text = f"{source} {rule_id} {evidence}".lower()
    if "secret" in text or "key" in text or "token" in text:
        return "secret-exposure"
    if "iam" in text or "role" in text or "binding" in text:
        return "iam-policy"
    if "terraform" in text or "hcl" in text:
        return "iac-misconfig"
    return "security-posture"


def _infer_remediation(source: str, rule_id: str, evidence: str) -> str:
    text = f"{source} {rule_id} {evidence}".lower()
    if "owner" in text or "editor" in text:
        return "Replace broad IAM roles with least-privilege custom or predefined roles."
    if "allusers" in text or "allauthenticatedusers" in text:
        return "Remove public IAM members and scope access to explicit identities."
    if "secret" in text or "private key" in text or "apikey" in text or "api key" in text:
        return "Rotate exposed credentials immediately and move secrets to Secret Manager."
    return "Review finding context and apply least-privilege and secure-secret handling controls."


def _validate_semgrep_payload(payload: Any, artifact_hash: str | None = None) -> None:
    if not isinstance(payload, dict):
        raise ValueError("Semgrep artifact must be a JSON object")
    
    # Validate SHA-256 hash if provided
    if artifact_hash:
        computed_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        if computed_hash != artifact_hash:
            raise ValueError("Semgrep artifact hash validation failed")
    
    results = payload.get("results")
    if not isinstance(results, list):
        raise ValueError("Semgrep artifact must contain a results list")
    
    required_fields = {"check_id", "path", "start", "extra"}
    for item in results:
        if not isinstance(item, dict):
            raise ValueError("Semgrep results must contain JSON objects")
        if not required_fields.issubset(item.keys()):
            raise ValueError("Semgrep result missing required fields")
        
        start = item.get("start", {})
        if not isinstance(start, dict) or "line" not in start:
            raise ValueError("Semgrep result missing 'start.line'")
        
        extra = item.get("extra", {})
        if not isinstance(extra, dict) or "message" not in extra or "severity" not in extra:
            raise ValueError("Semgrep result missing 'extra.message' or 'extra.severity'")


def _validate_gitleaks_payload(payload: Any, artifact_hash: str | None = None) -> None:
    if not isinstance(payload, list):
        raise ValueError("Gitleaks artifact must be a JSON array")
    
    # Validate SHA-256 hash if provided
    if artifact_hash:
        computed_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        if computed_hash != artifact_hash:
            raise ValueError("Gitleaks artifact hash validation failed")
    
    required_fields = {"RuleID", "Description", "File", "StartLine", "Match"}
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("Gitleaks entries must be JSON objects")
        if not required_fields.issubset(item.keys()):
            raise ValueError("Gitleaks entry missing required fields")


def _validate_opa_payload(payload: Any, artifact_hash: str | None = None) -> None:
    if not isinstance(payload, dict):
        raise ValueError("OPA artifact must be a JSON object")
    
    # Validate SHA-256 hash if provided
    if artifact_hash:
        computed_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        if computed_hash != artifact_hash:
            raise ValueError("OPA artifact hash validation failed")
    
    result = payload.get("result")
    if not isinstance(result, list):
        raise ValueError("OPA artifact must contain a result list")
    
    for item in result:
        if not isinstance(item, dict):
            raise ValueError("OPA result items must be JSON objects")
        expressions = item.get("expressions", [])
        if not isinstance(expressions, list):
            raise ValueError("OPA result must contain an 'expressions' list")
        for expr in expressions:
            if not isinstance(expr, dict) or "value" not in expr:
                raise ValueError("OPA expression must contain a 'value' field")


def load_validated_scanner_payloads(
    semgrep_path: Path,
    gitleaks_path: Path,
    opa_path: Path,
    semgrep_hash: str | None = None,
    gitleaks_hash: str | None = None,
    opa_hash: str | None = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    semgrep_payload = _read_json_strict(semgrep_path)
    gitleaks_payload = _read_json_strict(gitleaks_path)
    opa_payload = _read_json_strict(opa_path)
    _validate_semgrep_payload(semgrep_payload, semgrep_hash)
    _validate_gitleaks_payload(gitleaks_payload, gitleaks_hash)
    _validate_opa_payload(opa_payload, opa_hash)
    return semgrep_payload, gitleaks_payload, opa_payload


def parse_semgrep_payload(payload: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    for result in payload.get("results", []):
        extra = result.get("extra", {})
        message = extra.get("message", "Semgrep finding")
        severity = _normalize_severity(str(extra.get("severity", "warning")))
        findings.append(
            Finding(
                source="semgrep",
                rule_id=str(result.get("check_id", "semgrep.unknown")),
                severity=severity,
                confidence=0.70 if severity in {"high", "critical"} else 0.60,
                file=str(result.get("path", "unknown")),
                line=_to_int(result.get("start", {}).get("line"), 1),
                evidence=message.strip(),
                remediation=_infer_remediation("semgrep", str(result.get("check_id", "")), message),
                category=_infer_category("semgrep", str(result.get("check_id", "")), message),
            )
        )
    return findings


def parse_semgrep(path: Path) -> List[Finding]:
    payload = _read_json(path, default={})
    return parse_semgrep_payload(payload if isinstance(payload, dict) else {"results": []})


def parse_gitleaks_payload(payload: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    for leak in payload:
        rule_id = str(leak.get("RuleID", "gitleaks.unknown"))
        description = str(leak.get("Description", "Potential secret exposed"))
        file_path = str(leak.get("File", "unknown"))
        line = _to_int(leak.get("StartLine"), 1)
        evidence = str(leak.get("Match", ""))[:160]
        message = f"{description}. {evidence}".strip()
        findings.append(
            Finding(
                source="gitleaks",
                rule_id=rule_id,
                severity="critical",
                confidence=0.95,
                file=file_path,
                line=line,
                evidence=message,
                remediation=_infer_remediation("gitleaks", rule_id, message),
                category="secret-exposure",
            )
        )
    return findings


def parse_gitleaks(path: Path) -> List[Finding]:
    payload = _read_json(path, default=[])
    if not isinstance(payload, list):
        return []
    return parse_gitleaks_payload([item for item in payload if isinstance(item, dict)])


def _extract_opa_value(payload: Dict[str, Any]) -> Any:
    result = payload.get("result")
    if not isinstance(result, list) or not result:
        return {}
    expressions = result[0].get("expressions")
    if not isinstance(expressions, list) or not expressions:
        return {}
    return expressions[0].get("value", {})


def parse_opa_payload(payload: Dict[str, Any]) -> List[Finding]:
    value = _extract_opa_value(payload)
    findings: List[Finding] = []
    denies: Iterable[str] = []
    warns: Iterable[str] = []

    if isinstance(value, dict):
        denies = value.get("deny", [])
        warns = value.get("warn", [])
    elif isinstance(value, list):
        denies = value

    for message in denies:
        text = str(message)
        severity = "high"
        confidence = 0.85
        if "allusers" in text.lower() or "allauthenticatedusers" in text.lower():
            severity = "critical"
            confidence = 0.90
        findings.append(
            Finding(
                source="opa",
                rule_id="opa.deny",
                severity=severity,
                confidence=confidence,
                file="policies/opa/iam_least_privilege.rego",
                line=1,
                evidence=text,
                remediation=_infer_remediation("opa", "opa.deny", text),
                category="iam-policy",
            )
        )

    for message in warns:
        text = str(message)
        findings.append(
            Finding(
                source="opa",
                rule_id="opa.warn",
                severity="medium",
                confidence=0.65,
                file="policies/opa/iam_least_privilege.rego",
                line=1,
                evidence=text,
                remediation=_infer_remediation("opa", "opa.warn", text),
                category="iam-policy",
            )
        )
    return findings


def parse_opa(path: Path) -> List[Finding]:
    payload = _read_json(path, default={})
    return parse_opa_payload(payload if isinstance(payload, dict) else {"result": []})


def dedupe_findings(findings: Iterable[Finding]) -> List[Finding]:
    deduped: List[Finding] = []
    seen = set()
    for finding in findings:
        key = (
            finding.source,
            finding.rule_id,
            finding.file,
            finding.line,
            finding.evidence.strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _severity_rank(severity: str) -> int:
    ranking = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return ranking.get(severity, 1)


def deterministic_triage(findings: List[Finding]) -> Dict[str, Any]:
    triaged: List[Finding] = []
    for finding in findings:
        text = f"{finding.rule_id} {finding.evidence}".lower()
        severity = finding.severity
        confidence = finding.confidence
        if "private key" in text or "api key" in text or "secret" in text:
            severity = "critical"
            confidence = max(confidence, 0.90)
        if "roles/owner" in text or "allusers" in text:
            severity = "critical"
            confidence = max(confidence, 0.88)
        triaged.append(
            Finding(
                source=finding.source,
                rule_id=finding.rule_id,
                severity=severity,
                confidence=confidence,
                file=finding.file,
                line=finding.line,
                evidence=finding.evidence,
                remediation=finding.remediation,
                category=finding.category,
            )
        )

    overall = "low"
    if triaged:
        top = max(triaged, key=lambda item: _severity_rank(item.severity))
        overall = top.severity

    return {
        "agent_summary": "Deterministic triage completed from scanner outputs.",
        "overall_risk": overall,
        "blocking_reasons": [],
        "findings": [item.to_dict() for item in triaged],
    }


def _extract_response_text(payload: Dict[str, Any]) -> str:
    output_text = payload.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text

    if isinstance(payload.get("choices"), list):
        for choice in payload["choices"]:
            message = choice.get("message", {})
            content = message.get("content")
            if isinstance(content, str) and content.strip():
                return content

    output = payload.get("output", [])
    if isinstance(output, list):
        for item in output:
            if item.get("type") == "message":
                content = item.get("content", [])
                if isinstance(content, list):
                    for block in content:
                        if block.get("type") in {"output_text", "text"}:
                            text = block.get("text", "")
                            if isinstance(text, str) and text.strip():
                                return text
    raise ValueError("No response text found from OpenAI response payload")


def _openai_request(request_payload: Dict[str, Any], api_key: str, timeout_seconds: int) -> Dict[str, Any]:
    req = Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(request_payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urlopen(req, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8")
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError("OpenAI API returned non-JSON response body") from exc


def call_openai_triage(
    findings: List[Dict[str, Any]],
    architecture_context: str,
    api_key: str,
    model: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_attempts: int = OPENAI_MAX_ATTEMPTS,
    base_backoff_seconds: float = 1.0,
) -> Dict[str, Any]:
    system_prompt = (
        "You are a cloud security triage agent for GCP IAM.\n"
        "Return ONLY JSON with keys: agent_summary, overall_risk, blocking_reasons, findings.\n"
        "Each finding must include source, rule_id, severity, confidence, file, line, evidence, remediation, category.\n"
        "Severity must be one of critical/high/medium/low/info.\n"
        "confidence must be a float in [0,1]. Keep output concise and evidence-grounded."
    )
    user_payload = {
        "architecture_context": architecture_context,
        "scanner_findings": findings,
        "rules": {
            "focus": "GCP IAM misconfigurations and secret exposure",
            "gate_condition": "critical with confidence >= 0.80 should block merge",
        },
    }
    request_payload = {
        "model": model,
        "input": [
            {
                "role": "system",
                "content": [{"type": "text", "text": system_prompt}],
            },
            {
                "role": "user",
                "content": [{"type": "text", "text": json.dumps(user_payload)}],
            },
        ],
        "text": {"format": {"type": "json_object"}},
    }

    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            raw = _openai_request(request_payload, api_key=api_key, timeout_seconds=timeout_seconds)
            text = _extract_response_text(raw)
            return json.loads(text)
        except (HTTPError, URLError, TimeoutError, RuntimeError, json.JSONDecodeError, ValueError) as exc:
            last_error = exc
            if attempt >= max_attempts:
                break
            delay = min(base_backoff_seconds * (2 ** (attempt - 1)), 4.0)
            time.sleep(delay)

    raise RuntimeError(f"OpenAI API request failed after {max_attempts} attempts: {last_error}")


def _coerce_finding(raw: Dict[str, Any]) -> Finding:
    if not isinstance(raw, dict):
        raise ValueError("Each finding must be a JSON object")

    finding = Finding(
        source=str(raw.get("source", "ai")),
        rule_id=str(raw.get("rule_id", "ai.inferred")),
        severity=_normalize_severity(str(raw.get("severity", "low"))),
        confidence=float(raw.get("confidence", 0.5)),
        file=str(raw.get("file", "unknown")),
        line=_to_int(raw.get("line"), 1),
        evidence=str(raw.get("evidence", "No evidence provided")),
        remediation=str(raw.get("remediation", "Review and remediate.")),
        category=str(raw.get("category", "security-posture")),
    )
    if finding.severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity: {finding.severity}")
    if not (0.0 <= finding.confidence <= 1.0):
        raise ValueError("confidence must be between 0 and 1")
    return finding


def validate_triage_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Triage response must be a JSON object")

    required_keys = {"agent_summary", "overall_risk", "blocking_reasons", "findings"}
    missing = [key for key in required_keys if key not in payload]
    if missing:
        raise ValueError(f"Triage response missing required keys: {', '.join(sorted(missing))}")

    findings_payload = payload.get("findings")
    if not isinstance(findings_payload, list):
        raise ValueError("findings must be a list")

    findings = []
    for item in findings_payload:
        finding = _coerce_finding(item).to_dict()
        # Validate required fields in each finding
        required_finding_fields = {
            "source", "rule_id", "severity", "confidence", 
            "file", "line", "evidence", "remediation", "category"
        }
        if not required_finding_fields.issubset(finding.keys()):
            raise ValueError("Finding missing required fields")
        findings.append(finding)

    overall_risk = _normalize_severity(str(payload.get("overall_risk", "low")))
    if overall_risk not in VALID_SEVERITIES:
        raise ValueError(f"Invalid overall_risk: {overall_risk}")

    summary = str(payload.get("agent_summary", "")).strip()
    if not summary:
        raise ValueError("agent_summary must be a non-empty string")

    blocking = payload.get("blocking_reasons")
    if not isinstance(blocking, list):
        raise ValueError("blocking_reasons must be a list")

    return {
        "agent_summary": summary,
        "overall_risk": overall_risk,
        "blocking_reasons": [str(item) for item in blocking],
        "findings": findings,
    }


def should_block_merge(decision: Dict[str, Any], threshold: float) -> Tuple[bool, List[str]]:
    blocking_reasons = list(decision.get("blocking_reasons", []))
    blocking_findings: List[str] = []
    for finding in decision.get("findings", []):
        severity = _normalize_severity(str(finding.get("severity", "low")))
        confidence = float(finding.get("confidence", 0.0))
        if severity == "critical" and confidence >= threshold:
            file_path = str(finding.get("file", "unknown"))
            line = _to_int(finding.get("line"), 1)
            rule_id = str(finding.get("rule_id", "unknown"))
            blocking_findings.append(f"{rule_id} at {file_path}:{line} ({confidence:.2f})")

    reasons = blocking_reasons + blocking_findings
    return bool(blocking_findings), reasons


def _sarif_level(severity: str) -> str:
    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return level_map.get(severity, "note")


def build_sarif(decision: Dict[str, Any]) -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in decision.get("findings", []):
        source = str(finding.get("source", "ai"))
        rule_id = str(finding.get("rule_id", "ai.inferred"))
        full_rule_id = f"{source}.{rule_id}"
        severity = _normalize_severity(str(finding.get("severity", "low")))
        evidence = str(finding.get("evidence", "No evidence provided"))
        remediation = str(finding.get("remediation", "Review finding"))
        category = str(finding.get("category", "security-posture"))
        file_path = str(finding.get("file", "unknown"))
        line = _to_int(finding.get("line"), 1)

        if full_rule_id not in rules:
            rules[full_rule_id] = {
                "id": full_rule_id,
                "name": rule_id,
                "shortDescription": {"text": category},
                "fullDescription": {"text": remediation},
                "properties": {"security-severity": severity},
            }

        results.append(
            {
                "ruleId": full_rule_id,
                "level": _sarif_level(severity),
                "message": {"text": evidence},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file_path},
                            "region": {"startLine": line},
                        }
                    }
                ],
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ai-security-triage-agent",
                        "informationUri": "https://github.com",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _token_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return json.dumps(value, separators=(",", ":"))
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


def build_toon_payload(decision: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(decision, dict):
        raise ValueError("Decision must be a JSON object")

    token_table: List[str] = []
    token_index: Dict[str, int] = {}

    def _token_id(token: str) -> int:
        if not isinstance(token, str):
            raise ValueError("Token must be a string")
        if token in token_index:
            return token_index[token]
        index = len(token_table)
        token_table.append(token)
        token_index[token] = index
        return index

    def _object(object_id: str, object_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("Payload must be a JSON object")
        pairs: List[List[int]] = []
        for key in sorted(payload):
            k_idx = _token_id(str(key))
            v_idx = _token_id(_token_scalar(payload[key]))
            pairs.append([k_idx, v_idx])
        return {
            "object_id": object_id,
            "object_type": object_type,
            "pairs": pairs,
        }

    decision_payload = {
        "overall_risk": decision.get("overall_risk", "low"),
        "block_merge": bool(decision.get("block_merge", False)),
        "used_llm": bool(decision.get("used_llm", False)),
        "fail_closed": bool(decision.get("fail_closed", False)),
        "provenance_verified": bool(decision.get("provenance_verified", False)),
        "execution_mode": str(decision.get("execution_mode", "unknown")),
        "threshold": decision.get("threshold", DEFAULT_THRESHOLD),
    }
    objects: List[Dict[str, Any]] = [_object("decision-1", "decision", decision_payload)]

    findings = sorted(
        list(decision.get("findings", [])),
        key=lambda item: (
            -_severity_rank(str(item.get("severity", "low"))),
            -float(item.get("confidence", 0.0)),
            str(item.get("source", "")),
            str(item.get("rule_id", "")),
            str(item.get("file", "")),
            _to_int(item.get("line"), 1),
        ),
    )
    
    # Validate token_table and objects determinism
    for index, finding in enumerate(findings, start=1):
        payload = {
            "source": str(finding.get("source", "")),
            "rule_id": str(finding.get("rule_id", "")),
            "severity": _normalize_severity(str(finding.get("severity", "low"))),
            "confidence": float(finding.get("confidence", 0.0)),
            "file": str(finding.get("file", "unknown")),
            "line": _to_int(finding.get("line"), 1),
            "evidence": str(finding.get("evidence", "")),
            "remediation": str(finding.get("remediation", "")),
            "category": str(finding.get("category", "security-posture")),
        }
        objects.append(_object(f"finding-{index}", "finding", payload))

    # Validate token_table and objects
    if not isinstance(token_table, list) or not all(isinstance(token, str) for token in token_table):
        raise ValueError("token_table must be a list of strings")
    if not isinstance(objects, list) or not all(isinstance(obj, dict) for obj in objects):
        raise ValueError("objects must be a list of JSON objects")

    return {"schema": "toon.v1", "token_table": token_table, "objects": objects}


def build_markdown_summary(
    decision: Dict[str, Any],
    threshold: float,
    block_merge: bool,
    block_reasons: List[str],
    used_llm: bool,
    fallback_reason: str | None,
    skipped_reason: str | None,
) -> str:
    findings = decision.get("findings", [])
    summary_lines = [
        MARKER,
        "## AI Security Triage Summary",
        "",
        f"- Overall risk: `{decision.get('overall_risk', 'low')}`",
        f"- Findings analyzed: `{len(findings)}`",
        f"- LLM used: `{'yes' if used_llm else 'no'}`",
        f"- Gate policy: `block on critical confidence >= {threshold:.2f}`",
        f"- Merge blocked: `{'yes' if block_merge else 'no'}`",
        f"- Fail-closed: `{'yes' if decision.get('fail_closed') else 'no'}`",
        f"- Provenance verified: `{'yes' if decision.get('provenance_verified') else 'no'}`",
    ]
    if skipped_reason:
        summary_lines.append(f"- AI mode: `{skipped_reason}`")
    if fallback_reason:
        summary_lines.append(f"- Fallback reason: `{fallback_reason}`")

    trust_validation = decision.get("trust_validation", {})
    if isinstance(trust_validation, dict):
        summary_lines.append(f"- Trust validation: `{trust_validation.get('status', 'unknown')}`")

    scanner_integrity = decision.get("scanner_integrity", {})
    if isinstance(scanner_integrity, dict):
        summary_lines.append(f"- Scanner integrity: `{scanner_integrity.get('status', 'unknown')}`")

    summary_lines.extend(["", decision.get("agent_summary", "No summary provided."), ""])

    if block_reasons:
        summary_lines.append("### Blocking Reasons")
        for reason in block_reasons:
            summary_lines.append(f"- {reason}")
        summary_lines.append("")

    summary_lines.append("### Top Findings")
    summary_lines.append("| Severity | Confidence | Source | Rule | Location |")
    summary_lines.append("|---|---:|---|---|---|")
    sorted_findings = sorted(
        findings,
        key=lambda item: (_severity_rank(str(item.get("severity", "low"))), float(item.get("confidence", 0.0))),
        reverse=True,
    )
    for finding in sorted_findings[:20]:
        severity = _normalize_severity(str(finding.get("severity", "low")))
        confidence = float(finding.get("confidence", 0.0))
        source = str(finding.get("source", "unknown"))
        rule_id = str(finding.get("rule_id", "unknown"))
        file_path = str(finding.get("file", "unknown"))
        line = _to_int(finding.get("line"), 1)
        summary_lines.append(
            f"| {severity} | {confidence:.2f} | {source} | `{rule_id}` | `{file_path}:{line}` |"
        )
    if not sorted_findings:
        summary_lines.append("| info | 0.00 | agent | `none` | `n/a` |")
    return "\n".join(summary_lines) + "\n"


def _ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _load_architecture_context(path: Path, max_chars: int = 6000) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8")
    clean = re.sub(r"\s+", " ", text).strip()
    return clean[:max_chars]


def _read_scanner_hashes(scanner_status_path: Path | None) -> Tuple[str | None, str | None, str | None]:
    if not scanner_status_path or not scanner_status_path.exists():
        return None, None, None
    
    try:
        payload = json.loads(scanner_status_path.read_text(encoding="utf-8"))
        semgrep_hash = payload.get("semgrep", {}).get("sha256")
        gitleaks_hash = payload.get("gitleaks", {}).get("sha256")
        opa_hash = payload.get("opa", {}).get("sha256")
        
        return (
            semgrep_hash if isinstance(semgrep_hash, str) else None,
            gitleaks_hash if isinstance(gitleaks_hash, str) else None,
            opa_hash if isinstance(opa_hash, str) else None,
        )
    except Exception:
        return None, None, None


def run_triage(
    semgrep_path: Path,
    gitleaks_path: Path,
    opa_path: Path,
    architecture_path: Path,
    threshold: float,
    model: str,
    use_llm: bool,
    api_key: str,
    api_caller: Callable[[List[Dict[str, Any]], str, str, str], Dict[str, Any]] | None = None,
    scanner_status_path: Path | None = None,
) -> Dict[str, Any]:
    semgrep_hash, gitleaks_hash, opa_hash = _read_scanner_hashes(scanner_status_path)
    semgrep_payload, gitleaks_payload, opa_payload = load_validated_scanner_payloads(
        semgrep_path,
        gitleaks_path,
        opa_path,
        semgrep_hash,
        gitleaks_hash,
        opa_hash,
    )
    scanner_findings = dedupe_findings(
        parse_semgrep_payload(semgrep_payload)
        + parse_gitleaks_payload(gitleaks_payload)
        + parse_opa_payload(opa_payload)
    )
    finding_dicts = [item.to_dict() for item in scanner_findings]

    fallback_reason = None
    used_llm = False
    decision: Dict[str, Any]

    if use_llm and api_key:
        architecture_context = _load_architecture_context(architecture_path)
        caller = api_caller or call_openai_triage
        try:
            response = caller(finding_dicts, architecture_context, api_key, model)
            decision = validate_triage_response(response)
            used_llm = True
        except Exception as exc:  # noqa: BLE001
            fallback_reason = f"LLM triage failed: {exc}"
            decision = deterministic_triage(scanner_findings)
    else:
        fallback_reason = "LLM disabled or OPENAI_API_KEY missing."
        decision = deterministic_triage(scanner_findings)

    block_merge, block_reasons = should_block_merge(decision, threshold=threshold)
    if not used_llm:
        block_merge = False
        block_reasons = []
    decision.update(
        {
            "block_merge": block_merge,
            "block_reasons": block_reasons,
            "used_llm": used_llm,
            "fallback_reason": fallback_reason,
        }
    )
    return decision


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    _ensure_dir(path)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def _write_text(path: Path, text: str) -> None:
    _ensure_dir(path)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run AI security triage over scanner JSON outputs.")
    parser.add_argument("--semgrep", required=True, type=Path, help="Path to Semgrep JSON output.")
    parser.add_argument("--gitleaks", required=True, type=Path, help="Path to Gitleaks JSON output.")
    parser.add_argument("--opa", required=True, type=Path, help="Path to OPA JSON output.")
    parser.add_argument(
        "--architecture",
        type=Path,
        default=Path("docs/architecture.md"),
        help="Architecture context markdown path.",
    )
    parser.add_argument("--markdown-out", required=True, type=Path, help="Output markdown summary path.")
    parser.add_argument("--sarif-out", required=True, type=Path, help="Output SARIF file path.")
    parser.add_argument("--decision-out", required=True, type=Path, help="Output decision JSON path.")
    parser.add_argument("--toon-out", type=Path, help="Optional TOON v1 output JSON path.")
    parser.add_argument(
        "--confidence-threshold",
        default=DEFAULT_THRESHOLD,
        type=float,
        help="Merge gate threshold for critical findings.",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("AI_MODEL", DEFAULT_MODEL),
        help="OpenAI model name to use.",
    )
    parser.add_argument("--no-llm", action="store_true", help="Disable OpenAI calls and run deterministic mode.")
    parser.add_argument("--enforce-gate", action="store_true", help="Exit non-zero when gate blocks merge.")
    parser.add_argument(
        "--skip-reason",
        default="",
        help="Optional reason string displayed in markdown when AI is skipped.",
    )
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    threshold = float(args.confidence_threshold)
    api_key = os.getenv("OPENAI_API_KEY", "")
    use_llm = not args.no_llm

    decision = run_triage(
        semgrep_path=args.semgrep,
        gitleaks_path=args.gitleaks,
        opa_path=args.opa,
        architecture_path=args.architecture,
        threshold=threshold,
        model=args.model,
        use_llm=use_llm,
        api_key=api_key,
        scanner_status_path=None,  # Not available in local mode
    )
    decision.setdefault("trust_validation", {"status": "not_applicable", "valid": True, "reasons": []})
    decision.setdefault("scanner_integrity", {"status": "not_applicable", "valid": True, "reasons": []})
    decision.setdefault("provenance_verified", False)
    decision.setdefault("fail_closed", False)
    decision.setdefault("execution_mode", "local_single_agent")

    sarif_payload = build_sarif(decision)
    markdown = build_markdown_summary(
        decision=decision,
        threshold=threshold,
        block_merge=decision["block_merge"],
        block_reasons=decision["block_reasons"],
        used_llm=decision["used_llm"],
        fallback_reason=decision["fallback_reason"],
        skipped_reason=args.skip_reason or None,
    )
    final_decision = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "threshold": threshold,
        "model": args.model,
        **decision,
    }
    _write_json(args.decision_out, final_decision)
    _write_json(args.sarif_out, sarif_payload)
    _write_text(args.markdown_out, markdown)
    if args.toon_out:
        _write_json(args.toon_out, build_toon_payload(final_decision))

    if args.enforce_gate and decision["block_merge"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
