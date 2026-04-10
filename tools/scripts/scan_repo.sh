#!/bin/bash

set -euo pipefail

echo "=== GCP IAM Threat Detection Lab - Security Scanner ==="
echo "Delegating to enterprise multi-level triage dry-run workflow..."
echo ""

bash tools/scripts/run_ai_triage.sh

echo ""
echo "=== Scan Complete ==="
