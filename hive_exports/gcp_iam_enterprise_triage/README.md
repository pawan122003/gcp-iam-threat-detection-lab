# GCP IAM Enterprise Multi-Level Triage (Hive Export)

Hive-native enterprise triage graph for this repository.

## Design

Graph levels:
1. `governance-intake`
2. `iam-specialist`
3. `secret-specialist`
4. `correlation-committee`
5. `risk-committee`
6. `executive-reporting`

This provides policy-governed specialization and final committee decisioning for merge gates.

## Outputs

- `triaged_findings_json`: normalized list of findings
- `governance_decision_json`: merge block/pass decision and reasons
- `executive_summary_md`: concise operator summary

## Usage

When Hive core is available in `PYTHONPATH`:

```bash
python -m hive_exports.gcp_iam_enterprise_triage run --input-json path/to/context.json
```

Validation:

```bash
python -m hive_exports.gcp_iam_enterprise_triage validate
```

## Context contract

Input context should include:

```json
{
  "scanner_findings_json": "[...]",
  "architecture_context": "...",
  "confidence_threshold": "0.80"
}
```
