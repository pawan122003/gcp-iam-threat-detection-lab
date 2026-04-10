"""Enterprise multi-level security triage runner."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from app import ai_security_agent as local

DEFAULT_ENABLE_HIVE = "true"


def _is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_architecture_context(path: Path, max_chars: int = 6000) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8")
    clean = re.sub(r"\s+", " ", text).strip()
    return clean[:max_chars]


def _coerce_json_dict(payload: Any) -> Dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str) and payload.strip():
        parsed = json.loads(payload)
        if isinstance(parsed, dict):
            return parsed
    return {}


def _coerce_json_list(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, str) and payload.strip():
        parsed = json.loads(payload)
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
    return []


def _read_json_dict(path: Path | None) -> Dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    if isinstance(payload, dict):
        return payload
    return {}


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(text)


def _build_scanner_findings(semgrep: Path, gitleaks: Path, opa: Path) -> List[Dict[str, Any]]:
    semgrep_payload, gitleaks_payload, opa_payload = local.load_validated_scanner_payloads(semgrep, gitleaks, opa)
    findings = local.dedupe_findings(
        local.parse_semgrep_payload(semgrep_payload)
        + local.parse_gitleaks_payload(gitleaks_payload)
        + local.parse_opa_payload(opa_payload)
    )
    return [item.to_dict() for item in findings]


def _run_hive_enterprise(
    semgrep: Path,
    gitleaks: Path,
    opa: Path,
    architecture: Path,
    threshold: float,
    api_key: str,
    model: str,
) -> Dict[str, Any]:
    hive_core_path = os.getenv("HIVE_CORE_PATH", "").strip()
    if hive_core_path:
        hive_core = Path(hive_core_path).resolve()
        if hive_core.exists():
            core_str = str(hive_core)
            if core_str not in sys.path:
                sys.path.insert(0, core_str)

    from hive_exports.gcp_iam_enterprise_triage.agent import GCPIAMEnterpriseTriageAgent

    findings = _build_scanner_findings(semgrep, gitleaks, opa)
    architecture_context = _load_architecture_context(architecture)

    if api_key:
        os.environ["OPENAI_API_KEY"] = api_key
    if model:
        os.environ["AI_MODEL"] = model

    context = {
        "scanner_findings_json": json.dumps(findings),
        "architecture_context": architecture_context,
        "confidence_threshold": str(threshold),
    }

    mock_mode = not bool(api_key)
    agent = GCPIAMEnterpriseTriageAgent()
    result = asyncio.run(agent.run(context, mock_mode=mock_mode))
    if not result.success:
        raise RuntimeError(f"Hive enterprise agent failed: {result.error}")

    output = result.output or {}
    triaged_findings = _coerce_json_list(output.get("triaged_findings_json", []))
    governance = _coerce_json_dict(output.get("governance_decision_json", {}))

    triage_payload = {
        "agent_summary": governance.get("agent_summary")
        or output.get("executive_summary_md")
        or "Hive enterprise multi-level triage completed.",
        "overall_risk": governance.get("overall_risk", "low"),
        "blocking_reasons": governance.get("blocking_reasons", []),
        "findings": triaged_findings,
    }
    decision = local.validate_triage_response(triage_payload)
    block_merge, reasons = local.should_block_merge(decision, threshold=threshold)

    governance_block = governance.get("block_merge")
    if isinstance(governance_block, bool):
        block_merge = governance_block
        if block_merge and not reasons:
            reasons = [str(item) for item in governance.get("blocking_reasons", [])]

    if mock_mode:
        block_merge = False
        reasons = []

    decision.update(
        {
            "block_merge": block_merge,
            "block_reasons": reasons,
            "used_llm": not mock_mode,
            "fallback_reason": None if not mock_mode else "Hive ran in mock mode (no OPENAI_API_KEY).",
            "execution_mode": "hive_enterprise_multi_level",
        }
    )
    return decision


def _run_local_fallback(
    semgrep: Path,
    gitleaks: Path,
    opa: Path,
    architecture: Path,
    threshold: float,
    api_key: str,
    model: str,
    no_llm: bool,
    scanner_status: Path | None = None,
) -> Dict[str, Any]:
    decision = local.run_triage(
        semgrep_path=semgrep,
        gitleaks_path=gitleaks,
        opa_path=opa,
        architecture_path=architecture,
        threshold=threshold,
        model=model,
        use_llm=not no_llm,
        api_key=api_key,
        scanner_status_path=scanner_status,
    )
    decision["execution_mode"] = "local_single_agent"
    return decision


def execute_enterprise_triage(
    semgrep: Path,
    gitleaks: Path,
    opa: Path,
    architecture: Path,
    threshold: float,
    api_key: str,
    model: str,
    no_llm: bool,
    force_local: bool,
) -> Tuple[Dict[str, Any], str | None]:
    enable_hive = _is_truthy(os.getenv("ENABLE_HIVE_ENTERPRISE_AGENT", DEFAULT_ENABLE_HIVE))
    if not force_local and enable_hive:
        try:
            decision = _run_hive_enterprise(
                semgrep=semgrep,
                gitleaks=gitleaks,
                opa=opa,
                architecture=architecture,
                threshold=threshold,
                api_key=api_key,
                model=model,
            )
            return decision, None
        except Exception as exc:  # noqa: BLE001
    decision = _run_local_fallback(
        semgrep=semgrep,
        gitleaks=gitleaks,
        opa=opa,
        architecture=architecture,
        threshold=threshold,
        api_key=api_key,
        model=model,
        no_llm=no_llm,
        scanner_status=args.scanner_status if 'args' in locals() else None,
    )
            decision["execution_mode"] = "local_fallback_from_hive"
            fallback_note = f"Hive enterprise execution failed, local fallback used: {exc}"
            existing = decision.get("fallback_reason")
            if existing:
                decision["fallback_reason"] = f"{existing} {fallback_note}"
            else:
                decision["fallback_reason"] = fallback_note
            return decision, fallback_note

    decision = _run_local_fallback(
        semgrep=semgrep,
        gitleaks=gitleaks,
        opa=opa,
        architecture=architecture,
        threshold=threshold,
        api_key=api_key,
        model=model,
        no_llm=no_llm,
        scanner_status=args.scanner_status if 'args' in locals() else None,
    )
    return decision, None


def _validate_scanner_status(path: Path | None) -> Dict[str, Any]:
    payload = _read_json_dict(path)
    if not payload:
        return {"status": "missing", "valid": False, "reasons": ["scanner status artifact missing or invalid JSON"]}

    reasons: List[str] = []
    for scanner in ("semgrep", "gitleaks", "opa"):
        item = payload.get(scanner, {})
        if not isinstance(item, dict):
            reasons.append(f"{scanner} status entry missing")
            continue
        if not bool(item.get("exists")):
            reasons.append(f"{scanner} artifact missing")
        if not bool(item.get("json_valid")):
            reasons.append(f"{scanner} artifact invalid JSON")
        
        # Validate SHA-256 hash if provided
        artifact_hash = item.get("sha256")
        if isinstance(artifact_hash, str) and artifact_hash.strip():
            try:
                artifact_path = Path(item.get("path", ""))
                if artifact_path.exists():
                    artifact_content = artifact_path.read_text(encoding="utf-8")
                    computed_hash = hashlib.sha256(artifact_content.encode()).hexdigest()
                    if computed_hash != artifact_hash:
                        reasons.append(f"{scanner} artifact hash validation failed")
            except Exception:
                reasons.append(f"{scanner} artifact hash validation error")

    all_valid = bool(payload.get("all_valid")) and not reasons
    return {
        "status": "valid" if all_valid else "invalid",
        "valid": all_valid,
        "reasons": reasons if reasons else [],
    }


def _validate_ci_context(
    path: Path | None,
    no_llm: bool,
    api_key: str,
    require_signed_provenance: bool,
) -> Dict[str, Any]:
    from app.trust_context import validate_ci_context
    
    running_in_ci = _is_truthy(os.getenv("GITHUB_ACTIONS"))
    payload = _read_json_dict(path)
    github_event_path = os.getenv("GITHUB_EVENT_PATH", "")

    if running_in_ci and not payload:
        return {
            "status": "missing",
            "valid": False,
            "reasons": ["ci context artifact missing or invalid JSON"],
            "is_fork_pr": False,
            "provenance_verified": False,
            "oidc_token_valid": False,
            "oidc_validation_reasons": [],
        }

    if not payload:
        return {
            "status": "not_provided",
            "valid": True,
            "reasons": [],
            "is_fork_pr": False,
            "provenance_verified": False,
            "oidc_token_valid": False,
            "oidc_validation_reasons": [],
        }

    # Use trust_context for OIDC validation
    if running_in_ci and not bool(payload.get("is_fork_pr", False)):
        trust_validation = validate_ci_context(
            ci_context_path=str(path) if path else "",
            github_event_path=github_event_path,
            expected_repository=os.getenv("GITHUB_REPOSITORY", ""),
            expected_ref=os.getenv("GITHUB_REF", ""),
        )
        return {
            "status": trust_validation.get("status", "unknown"),
            "valid": trust_validation.get("valid", False),
            "reasons": trust_validation.get("reasons", []),
            "is_fork_pr": trust_validation.get("is_fork_pr", False),
            "provenance_verified": bool(payload.get("provenance_verified", False)),
            "oidc_token_valid": trust_validation.get("oidc_token_valid", False),
            "oidc_validation_reasons": trust_validation.get("oidc_validation_reasons", []),
        }

    reasons: List[str] = []
    source = str(payload.get("source", "unknown"))
    if source not in {"github_actions", "local"}:
        reasons.append("ci context source must be github_actions or local")

    is_fork_pr = bool(payload.get("is_fork_pr", False))
    provenance_verified = bool(payload.get("provenance_verified", False))
    api_key_present = bool(payload.get("api_key_present", False))

    if source == "local":
        if require_signed_provenance and not provenance_verified:
            reasons.append("signed provenance verification is required but missing/false")
        return {
            "status": "valid" if not reasons else "invalid",
            "valid": not reasons,
            "reasons": reasons,
            "is_fork_pr": is_fork_pr,
            "provenance_verified": provenance_verified,
            "oidc_token_valid": False,
            "oidc_validation_reasons": [],
        }

    if is_fork_pr:
        if not no_llm:
            reasons.append("fork pull requests must run with --no-llm")
        if api_key_present or bool(api_key):
            reasons.append("fork pull requests must not use OPENAI_API_KEY")
    else:
        if not bool(api_key):
            reasons.append("non-fork executions require OPENAI_API_KEY")
        if no_llm:
            reasons.append("non-fork executions must not force --no-llm")
        if api_key_present != bool(api_key):
            reasons.append("api_key_present mismatch between CI context and runtime")

    if require_signed_provenance and not provenance_verified:
        reasons.append("signed provenance verification is required but missing/false")

    return {
        "status": "valid" if not reasons else "invalid",
        "valid": not reasons,
        "reasons": reasons,
        "is_fork_pr": is_fork_pr,
        "provenance_verified": provenance_verified,
        "oidc_token_valid": False,
        "oidc_validation_reasons": [],
    }


def _apply_fail_closed(
    decision: Dict[str, Any],
    trust_validation: Dict[str, Any],
    scanner_integrity: Dict[str, Any],
    require_signed_provenance: bool,
) -> Dict[str, Any]:
    fail_reasons: List[str] = []
    if not bool(trust_validation.get("valid")):
        fail_reasons.extend([f"trust validation failed: {item}" for item in trust_validation.get("reasons", [])])
    if not bool(scanner_integrity.get("valid")):
        fail_reasons.extend([f"scanner integrity failed: {item}" for item in scanner_integrity.get("reasons", [])])
    if require_signed_provenance and not bool(trust_validation.get("provenance_verified")):
        fail_reasons.append("provenance verification failed")

    if fail_reasons:
        decision["block_merge"] = True
        existing = list(decision.get("block_reasons", []))
        merged = existing + fail_reasons
        # Preserve order while de-duplicating.
        decision["block_reasons"] = list(dict.fromkeys(str(item) for item in merged))
        decision["fail_closed"] = True
    else:
        decision["fail_closed"] = False

    decision["trust_validation"] = {
        "status": trust_validation.get("status", "unknown"),
        "valid": bool(trust_validation.get("valid")),
        "reasons": [str(item) for item in trust_validation.get("reasons", [])],
    }
    decision["scanner_integrity"] = {
        "status": scanner_integrity.get("status", "unknown"),
        "valid": bool(scanner_integrity.get("valid")),
        "reasons": [str(item) for item in scanner_integrity.get("reasons", [])],
    }
    decision["provenance_verified"] = bool(trust_validation.get("provenance_verified", False))
    return decision


def _build_failure_decision(reason: str, execution_mode: str) -> Dict[str, Any]:
    return {
        "agent_summary": f"Triage failed before completion: {reason}",
        "overall_risk": "critical",
        "blocking_reasons": [reason],
        "findings": [],
        "block_merge": True,
        "block_reasons": [reason],
        "used_llm": False,
        "fallback_reason": reason,
        "execution_mode": execution_mode,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run enterprise multi-level security triage with Hive (fallback to local)."
    )
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
    parser.add_argument("--sarif-out", required=True, type=Path, help="Output SARIF path.")
    parser.add_argument("--decision-out", required=True, type=Path, help="Output decision JSON path.")
    parser.add_argument("--toon-out", required=True, type=Path, help="Output TOON v1 path.")
    parser.add_argument("--ci-context", type=Path, help="Path to CI trust context JSON.")
    parser.add_argument("--scanner-status", type=Path, help="Path to scanner integrity JSON.")
    parser.add_argument("--require-signed-provenance", action="store_true", help="Fail closed if provenance is not verified.")
    parser.add_argument(
        "--confidence-threshold",
        default=local.DEFAULT_THRESHOLD,
        type=float,
        help="Merge gate threshold for critical findings.",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("AI_MODEL", local.DEFAULT_MODEL),
        help="Primary model name.",
    )
    parser.add_argument("--no-llm", action="store_true", help="Disable local LLM mode for fallback execution.")
    parser.add_argument("--force-local", action="store_true", help="Skip Hive mode and force local execution.")
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

    try:
        decision, mode_note = execute_enterprise_triage(
            semgrep=args.semgrep,
            gitleaks=args.gitleaks,
            opa=args.opa,
            architecture=args.architecture,
            threshold=threshold,
            api_key=api_key,
            model=args.model,
            no_llm=args.no_llm,
            force_local=args.force_local,
        )
    except Exception as exc:  # noqa: BLE001
        decision = _build_failure_decision(str(exc), execution_mode="bootstrap_failure")
        mode_note = None

    execution_mode = decision.get("execution_mode", "unknown")
    agent_summary = decision.get("agent_summary", "").strip()
    decision["agent_summary"] = f"[Execution mode: {execution_mode}] {agent_summary}".strip()
    if mode_note and not decision.get("fallback_reason"):
        decision["fallback_reason"] = mode_note

    trust_validation = _validate_ci_context(
        args.ci_context,
        no_llm=args.no_llm,
        api_key=api_key,
        require_signed_provenance=args.require_signed_provenance,
    )
    scanner_integrity = _validate_scanner_status(args.scanner_status)
    decision = _apply_fail_closed(
        decision,
        trust_validation=trust_validation,
        scanner_integrity=scanner_integrity,
        require_signed_provenance=args.require_signed_provenance,
    )

    sarif_payload = local.build_sarif(decision)
    markdown = local.build_markdown_summary(
        decision=decision,
        threshold=threshold,
        block_merge=bool(decision.get("block_merge")),
        block_reasons=list(decision.get("block_reasons", [])),
        used_llm=bool(decision.get("used_llm")),
        fallback_reason=decision.get("fallback_reason"),
        skipped_reason=args.skip_reason or None,
    )
    final_decision = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "threshold": threshold,
        "model": args.model,
        **decision,
    }
    toon_payload = local.build_toon_payload(final_decision)

    _write_json(args.decision_out, final_decision)
    _write_json(args.sarif_out, sarif_payload)
    _write_json(args.toon_out, toon_payload)
    _write_text(args.markdown_out, markdown)

    if args.enforce_gate and bool(final_decision.get("block_merge")):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
