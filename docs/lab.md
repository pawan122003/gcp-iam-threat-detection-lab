# GCP IAM Threat Detection Lab - Hands-On Guide

This lab guide walks through IAM threat detection with scanner evidence and enterprise multi-level AI triage.

## Prerequisites

- GCP account with billing enabled
- `gcloud` CLI installed and configured
- Terraform >= 1.5
- Python 3.11+
- Optional Hive framework core for Hive-first execution

## Lab Setup

### 1. Clone and initialize

```bash
git clone https://github.com/pawan122003/gcp-iam-threat-detection-lab.git
cd gcp-iam-threat-detection-lab
```

### 2. Configure GCP project

```bash
gcloud auth application-default login
export GOOGLE_PROJECT="your-project-id"
```

### 3. Deploy infrastructure

```bash
cd infra/terraform
terraform init
terraform plan -var="project_id=$GOOGLE_PROJECT"
terraform apply -var="project_id=$GOOGLE_PROJECT"
```

## Scenario 1: Detect over-permissive IAM roles

### Objective
Validate least-privilege policy enforcement.

### Steps

1. Create test policy input:

```bash
cat > input.json <<'EOF'
{
  "bindings": [
    {
      "role": "roles/owner",
      "members": ["user:test@example.com"]
    }
  ]
}
EOF
```

2. Run OPA policy evaluation:

```bash
opa eval -d policies/opa/iam_least_privilege.rego -i input.json 'data.gcp.iam.least_privilege'
```

3. Confirm deny output is present.

## Scenario 2: Run enterprise triage locally

### Objective
Generate decision JSON, SARIF, TOON, and markdown summary using enterprise runner.

### Steps

1. Run full local triage:

```bash
bash tools/scripts/run_ai_triage.sh
```

2. Review outputs:

- `artifacts/ai-decision.json`
- `artifacts/ai-findings.sarif`
- `artifacts/ai-summary.md`
- `artifacts/ai-triage.toon.json`
- `artifacts/scanner-status.json`
- `artifacts/ci-context.json`
- `artifacts/triage-provenance.json`

3. Validate gate result:

```bash
cat artifacts/ai-decision.json
```

4. Inspect token-oriented output:

```bash
cat artifacts/ai-triage.toon.json
```

## Scenario 3: Hive-native multi-level run (optional)

### Objective
Execute the Hive export directly when Hive core is installed.

### Steps

1. Ensure Hive core is available and export path is importable.
2. Validate export:

```bash
python -m hive_exports.gcp_iam_enterprise_triage validate
```

3. Execute with context file:

```bash
python -m hive_exports.gcp_iam_enterprise_triage run --input-json enterprise_input.json
```

## Scenario 4: Audit log analysis

### Objective
Monitor IAM policy changes in GCP audit logs.

### Steps

```bash
gcloud logging read \
  'protoPayload.methodName="SetIamPolicy"' \
  --limit 10 \
  --format json
```

Inspect for unexpected principals, role grants, or high-frequency policy mutations.

## Scenario 5: CI trust + provenance controls

### Objective
Verify fail-closed trust behavior and signed provenance requirements in CI.

### Checks

1. Non-fork PRs must provide `OPENAI_API_KEY`.
2. Fork PRs must run with `--no-llm` and no secret usage.
3. CI must produce:
   - `artifacts/triage-provenance.json`
   - `artifacts/triage-provenance.sig`
   - `artifacts/triage-provenance.pem`
4. Merge gate fails closed if trust/scanner/provenance validation is invalid.

## Cleanup

```bash
cd infra/terraform
terraform destroy -var="project_id=$GOOGLE_PROJECT"
```

## Additional resources

- [Aden Hive Framework](https://github.com/aden-hive/hive)
- [GCP IAM Best Practices](https://cloud.google.com/iam/docs/best-practices)
- [OPA Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
