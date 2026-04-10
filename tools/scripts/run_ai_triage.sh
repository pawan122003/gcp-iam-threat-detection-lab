#!/bin/bash

set -euo pipefail

ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts}"
CONFIDENCE_THRESHOLD="${CONFIDENCE_THRESHOLD:-0.80}"
ENABLE_HIVE_ENTERPRISE_AGENT="${ENABLE_HIVE_ENTERPRISE_AGENT:-true}"
REQUIRE_SIGNED_PROVENANCE="${REQUIRE_SIGNED_PROVENANCE:-false}"
export ENABLE_HIVE_ENTERPRISE_AGENT
export ARTIFACT_DIR

mkdir -p "${ARTIFACT_DIR}"

echo "==> Safe cleanup of local temp artifacts (non-fatal)"
rm -rf .pytest_tmp .test_tmp 2>/dev/null || true
find . -maxdepth 1 -type d -name 'pytest-cache-files-*' -exec rm -rf {} + 2>/dev/null || true

echo "==> Generating scanner JSON artifacts in ${ARTIFACT_DIR}"

if command -v semgrep >/dev/null 2>&1; then
  semgrep --config detection/rules/semgrep.yaml --json --output "${ARTIFACT_DIR}/semgrep.json" . || true
else
  echo '{"results":[]}' > "${ARTIFACT_DIR}/semgrep.json"
fi

if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source . --report-format json --report-path "${ARTIFACT_DIR}/gitleaks.json" --exit-code 0 || true
else
  echo "[]" > "${ARTIFACT_DIR}/gitleaks.json"
fi

if command -v opa >/dev/null 2>&1; then
  opa eval -d policies/opa -i input.json 'data.gcp.iam.least_privilege' --format json > "${ARTIFACT_DIR}/opa.json" || echo '{"result":[]}' > "${ARTIFACT_DIR}/opa.json"
else
  echo '{"result":[]}' > "${ARTIFACT_DIR}/opa.json"
fi

echo "==> Building scanner-status and local ci-context artifacts"
python - <<'PY'
import hashlib
import json
import os
from pathlib import Path

artifacts = Path(os.getenv("ARTIFACT_DIR", "artifacts"))

def inspect(path: Path):
    item = {"path": str(path), "exists": path.exists(), "json_valid": False, "sha256": ""}
    if not path.exists():
        return item
    raw = path.read_bytes()
    item["sha256"] = hashlib.sha256(raw).hexdigest()
    try:
        json.loads(raw.decode("utf-8"))
        item["json_valid"] = True
    except Exception:
        item["json_valid"] = False
    return item

status = {
    "schema": "scanner-status.v1",
    "semgrep": inspect(artifacts / "semgrep.json"),
    "gitleaks": inspect(artifacts / "gitleaks.json"),
    "opa": inspect(artifacts / "opa.json"),
}
status["all_valid"] = all([
    status["semgrep"]["exists"], status["semgrep"]["json_valid"],
    status["gitleaks"]["exists"], status["gitleaks"]["json_valid"],
    status["opa"]["exists"], status["opa"]["json_valid"],
])
(artifacts / "scanner-status.json").write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")

ci_context = {
    "schema": "ci-context.v1",
    "source": "local",
    "event_name": "local",
    "repository": "local",
    "head_repository": "local",
    "workflow_ref": "local",
    "workflow_sha": "",
    "ref": "local",
    "actor": os.getenv("USER", "local"),
    "run_id": "local",
    "run_attempt": "1",
    "is_fork_pr": False,
    "api_key_present": bool(os.getenv("OPENAI_API_KEY", "")),
    "no_llm_expected": False,
    "provenance_verified": False,
}
(artifacts / "ci-context.json").write_text(json.dumps(ci_context, indent=2) + "\n", encoding="utf-8")

provenance = {
    "schema": "triage-provenance.v1",
    "source": "local",
    "unsigned_local": True,
    "artifacts": {
        "semgrep": status["semgrep"]["sha256"],
        "gitleaks": status["gitleaks"]["sha256"],
        "opa": status["opa"]["sha256"],
        "scanner_status": hashlib.sha256((artifacts / "scanner-status.json").read_bytes()).hexdigest(),
        "ci_context": hashlib.sha256((artifacts / "ci-context.json").read_bytes()).hexdigest(),
    },
}
(artifacts / "triage-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
(artifacts / "triage-provenance.sig").write_text("local-unsigned\n", encoding="utf-8")
(artifacts / "triage-provenance.pem").write_text("local-unsigned\n", encoding="utf-8")
PY

echo "==> Running enterprise multi-level security triage"

AI_ARGS=(
  --semgrep "${ARTIFACT_DIR}/semgrep.json"
  --gitleaks "${ARTIFACT_DIR}/gitleaks.json"
  --opa "${ARTIFACT_DIR}/opa.json"
  --markdown-out "${ARTIFACT_DIR}/ai-summary.md"
  --sarif-out "${ARTIFACT_DIR}/ai-findings.sarif"
  --decision-out "${ARTIFACT_DIR}/ai-decision.json"
  --toon-out "${ARTIFACT_DIR}/ai-triage.toon.json"
  --ci-context "${ARTIFACT_DIR}/ci-context.json"
  --scanner-status "${ARTIFACT_DIR}/scanner-status.json"
  --confidence-threshold "${CONFIDENCE_THRESHOLD}"
)

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
  AI_ARGS+=(--no-llm --skip-reason "OPENAI_API_KEY not set in local environment")
fi

if [[ "${ENFORCE_GATE:-false}" == "true" ]]; then
  AI_ARGS+=(--enforce-gate)
fi
if [[ "${REQUIRE_SIGNED_PROVENANCE}" == "true" ]]; then
  AI_ARGS+=(--require-signed-provenance)
fi

python -m app.enterprise_agent_runner "${AI_ARGS[@]}"

echo "==> Completed"
echo "    Markdown: ${ARTIFACT_DIR}/ai-summary.md"
echo "    SARIF:    ${ARTIFACT_DIR}/ai-findings.sarif"
echo "    Decision: ${ARTIFACT_DIR}/ai-decision.json"
echo "    TOON:     ${ARTIFACT_DIR}/ai-triage.toon.json"
