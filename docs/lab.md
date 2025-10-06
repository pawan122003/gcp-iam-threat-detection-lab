# GCP IAM Threat Detection Lab - Hands-On Guide

This lab guide walks you through hands-on scenarios to detect and prevent IAM security threats in GCP.

## Prerequisites

- GCP account with billing enabled
- `gcloud` CLI installed and configured
- Terraform >= 1.5
- Basic knowledge of GCP IAM

## Lab Setup

### 1. Clone and Initialize

```bash
git clone https://github.com/pawan122003/gcp-iam-threat-detection-lab.git
cd gcp-iam-threat-detection-lab
```

### 2. Configure GCP Project

```bash
gcloud auth application-default login
export GOOGLE_PROJECT="your-project-id"
```

### 3. Deploy Infrastructure

```bash
cd infra/terraform
terraform init
terraform plan -var="project_id=$GOOGLE_PROJECT"
terraform apply -var="project_id=$GOOGLE_PROJECT"
```

## Scenario 1: Detecting Overly Permissive IAM Roles

### Objective
Learn how OPA policies prevent assignment of overly permissive roles.

### Steps

1. **Create a test IAM binding with Owner role:**

```bash
echo '
{
  "bindings": [
    {
      "role": "roles/owner",
      "members": ["user:test@example.com"]
    }
  ]
}' > test_policy.json
```

2. **Test with OPA:**

```bash
opa eval -d policies/opa/iam_least_privilege.rego \
  -i test_policy.json \
  'data.gcp.iam.least_privilege.deny'
```

3. **Expected Result:** Policy violation detected

## Scenario 2: Secret Scanning with Semgrep

### Objective
Detect hardcoded GCP service account keys in code.

### Steps

1. **Run Semgrep scan:**

```bash
semgrep --config detection/rules/semgrep.yaml .
```

2. **Trigger CI/CD pipeline** by pushing code changes

3. **Review findings** in GitHub Actions

## Scenario 3: Audit Log Analysis

### Objective
Monitor IAM policy changes in GCP audit logs.

### Steps

1. **Enable audit logging** (already configured in Terraform)

2. **Query recent IAM changes:**

```bash
gcloud logging read \
  'protoPayload.methodName="SetIamPolicy"' \
  --limit 10 \
  --format json
```

3. **Analyze results** for suspicious activity

## Cleanup

```bash
cd infra/terraform
terraform destroy -var="project_id=$GOOGLE_PROJECT"
```

## Additional Resources

- [GCP IAM Best Practices](https://cloud.google.com/iam/docs/best-practices)
- [OPA Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
