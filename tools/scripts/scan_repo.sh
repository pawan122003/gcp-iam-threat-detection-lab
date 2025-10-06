#!/bin/bash

set -e

echo "=== GCP IAM Threat Detection Lab - Security Scanner ==="
echo ""

# Run Semgrep
if command -v semgrep &> /dev/null; then
  echo "[*] Running Semgrep..."
  semgrep --config detection/rules/semgrep.yaml . || true
else
  echo "[!] Semgrep not installed. Skipping..."
fi

echo ""

# Run Gitleaks
if command -v gitleaks &> /dev/null; then
  echo "[*] Running Gitleaks secret scanner..."
  gitleaks detect --source . --verbose || true
else
  echo "[!] Gitleaks not installed. Skipping..."
fi

echo ""

# Run OPA policy checks
if command -v opa &> /dev/null; then
  echo "[*] Running OPA policy checks..."
  opa test policies/opa/ || true
else
  echo "[!] OPA not installed. Skipping..."
fi

echo ""
echo "=== Scan Complete ==="
