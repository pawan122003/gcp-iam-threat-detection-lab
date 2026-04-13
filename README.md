# GCP IAM Threat Detection Lab

![License](https://img.shields.io/badge/license-MIT-blue.svg)

Enterprise-focused lab for GCP IAM threat detection with scanner evidence, policy-as-code, and multi-level AI triage.

## Architecture

- Full architecture: [docs/architecture.md](docs/architecture.md)
- Hive export package: `hive_exports/gcp_iam_enterprise_triage`

## What is implemented

1. **Static Security Inputs**
   - Terraform validation
   - Semgrep JSON
   - Gitleaks JSON
   - OPA JSON
   - CodeQL
2. **Enterprise Multi-Level Agent**
   - Level 1: governance intake
   - Level 2: IAM specialist + secrets specialist
   - Level 3: correlation committee + risk committee + executive reporting
3. **Execution Strategy**
   - Hive-first execution when framework core is available
   - Automatic local fallback for reliability
4. **Trust + Verification**
    - GitHub OIDC keyless provenance signing/verification (`cosign`)
    - CI trust context and fork-safe policy validation (OIDC token validation, fork detection)
    - Scanner integrity contract (`scanner-status.json`) with SHA-256 hash validation
    - Fail-closed enforcement for missing/invalid OIDC tokens, unverified provenance, or invalid scanner artifacts
5. **Gate Policy**
   - Merge blocked only when finding is `critical` and confidence `>= 0.80`
   - Fail-closed when trust/scanner/provenance validation is invalid

## Repository Layout

- `app/ai_security_agent.py`: local triage implementation (reliable fallback core)
- `app/enterprise_agent_runner.py`: Hive-first runner with fallback behavior
- `hive_exports/gcp_iam_enterprise_triage/`: Hive template-style multi-level agent export
- `.github/workflows/security.yml`: CI pipeline and gate
- `tools/scripts/run_ai_triage.sh`: local end-to-end execution

## Local Usage

### Standard local run

```bash
bash tools/scripts/run_ai_triage.sh
```

Artifacts (default `artifacts/`):
- `semgrep.json` (scanner output)
- `gitleaks.json` (scanner output)
- `opa.json` (scanner output)
- `scanner-status.json` (SHA-256 hash validation, schema validation)
- `ci-context.json` (OIDC token validation, fork detection, provenance state)
- `triage-provenance.json` (signed provenance manifest)
- `triage-provenance.sig` (provenance signature)
- `triage-provenance.pem` (provenance certificate)
- `ai-summary.md` (markdown summary for PR comments)
- `ai-findings.sarif` (SARIF output for GitHub Code Scanning)
- `ai-decision.json` (merge gate decision, trust validation, scanner integrity)
- `ai-triage.toon.json` (Token-Oriented Object Notation v1)

### Force local runner (skip Hive mode)

```bash
python -m app.enterprise_agent_runner \
  --semgrep artifacts/semgrep.json \
  --gitleaks artifacts/gitleaks.json \
  --opa artifacts/opa.json \
  --architecture docs/architecture.md \
  --markdown-out artifacts/ai-summary.md \
  --sarif-out artifacts/ai-findings.sarif \
  --decision-out artifacts/ai-decision.json \
  --toon-out artifacts/ai-triage.toon.json \
  --ci-context artifacts/ci-context.json \
  --scanner-status artifacts/scanner-status.json \
  --confidence-threshold 0.80 \
  --force-local
```

### Run Hive export directly (when Hive core is available)

```bash
python -m hive_exports.gcp_iam_enterprise_triage validate
python -m hive_exports.gcp_iam_enterprise_triage run --input-json enterprise_input.json
```

## CI/CD behavior

`security.yml`:
1. Runs scanner stages and emits JSON artifacts.
2. Builds scanner integrity (`scanner-status.json`) with SHA-256 hash validation.
3. Builds CI trust context (`ci-context.json`) with OIDC token validation and fork detection.
4. Signs provenance manifest (`triage-provenance.json`) with GitHub OIDC and verifies signer identity.
5. Enforces fork-safe behavior: fork PRs run with `--no-llm` and skip provenance verification.
6. Tries enterprise Hive multi-level mode first for non-fork PRs.
7. Falls back to local triage when Hive runtime is missing/failing.
8. Uploads SARIF, PR summary, and TOON artifacts.
9. Applies fail-closed merge gate using `ai-decision.json` (blocks merge for invalid OIDC, provenance, or scanner artifacts).

## Environment variables

- `OPENAI_API_KEY`: Required for non-mock LLM execution (non-fork PRs only).
- `AI_MODEL`: Optional model override (default: `gpt-5.4`).
- `ENABLE_HIVE_ENTERPRISE_AGENT`: `true`/`false`, default `true`.
- `HIVE_CORE_PATH`: Optional path to Hive `core` directory for imports.
- `CONFIDENCE_THRESHOLD`: Local script threshold override (default: `0.80`).
- `ARTIFACT_DIR`: Local script artifact directory (default: `artifacts/`).
- `REQUIRE_SIGNED_PROVENANCE`: Fail-closed if provenance is not verified (default: `false`).

## TOON Contract

The token-oriented artifact (`ai-triage.toon.json`) uses:

- `schema: "toon.v1"`
- `token_table`: deterministic deduplicated token list
- `objects`: array of normalized objects
- object fields:
  - `object_id`
  - `object_type`
  - `pairs` as `[key_token_index, value_token_index]`

It contains one decision object and one object per finding.

## Testing

```bash
python -m pytest -q tests -p no:cacheprovider
```

## Resources

- [Aden Hive Framework](https://github.com/aden-hive/hive)
- [GCP IAM Best Practices](https://cloud.google.com/iam/docs/best-practices)
- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Semgrep Docs](https://semgrep.dev/docs/)

## License

MIT License. See [LICENSE](LICENSE).

## Security Note

Rotate any previously exposed API key and replace the repository secret before production usage.
