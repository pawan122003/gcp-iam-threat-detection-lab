"""Node definitions for GCP IAM enterprise multi-level triage."""

from framework.graph import NodeSpec

# Level 1: Governance intake
# Establishes constraints, scoring policy, and audit posture for downstream lanes.
governance_intake_node = NodeSpec(
    id="governance-intake",
    name="Governance Intake",
    description=(
        "Validate scanner payload scope and produce governance charter for triage"
    ),
    node_type="event_loop",
    max_node_visits=0,
    input_keys=["scanner_findings_json", "architecture_context", "confidence_threshold"],
    output_keys=["governance_charter_json"],
    success_criteria=(
        "Governance charter defines severity taxonomy, confidence semantics, "
        "and merge-block policy with clear audit rationale."
    ),
    system_prompt="""\
You are the Governance Intake lead for an enterprise cloud security SOC.

Your responsibilities:
1) Read scanner_findings_json and architecture_context.
2) Establish governance charter for the current triage run.
3) Define hard requirements for downstream specialist lanes.

Return the charter via:
set_output("governance_charter_json", "<JSON string>")

Required JSON structure:
{
  "policy_version": "string",
  "severity_model": ["critical","high","medium","low","info"],
  "confidence_scale": "0.0-1.0",
  "block_policy": "critical with confidence >= threshold",
  "must_include_fields": ["source","rule_id","severity","confidence","file","line","evidence","remediation","category"],
  "iam_focus": "least privilege, public principals, high-risk role grants",
  "secret_focus": "credential leakage and key exposure",
  "audit_requirements": "evidence-backed output only"
}

Constraints:
- Do not invent scanner records not present in scanner_findings_json.
- Preserve enterprise auditability and deterministic policy wording.
""",
    tools=[],
)

# Level 2A: IAM specialist lane
iam_specialist_node = NodeSpec(
    id="iam-specialist",
    name="IAM Specialist Lane",
    description="Analyze IAM-specific exposure, privilege escalation risk, and policy violations",
    node_type="event_loop",
    max_node_visits=0,
    input_keys=["scanner_findings_json", "governance_charter_json"],
    output_keys=["iam_assessment_json"],
    success_criteria=(
        "IAM assessment identifies least-privilege violations and principal exposure risks "
        "with concrete remediation actions."
    ),
    system_prompt="""\
You are an IAM specialist agent.

Input:
- scanner_findings_json (JSON array)
- governance_charter_json (JSON object)

Tasks:
1) Filter findings relevant to IAM policy risk:
   - overly broad roles (owner/editor/admin)
   - public principals (allUsers/allAuthenticatedUsers)
   - risky service account privilege grants
2) Assign precise severity + confidence per finding.
3) Provide developer-remediation language with minimal ambiguity.

Output via:
set_output("iam_assessment_json", "<JSON string>")

Required JSON structure:
{
  "lane": "iam",
  "risk_summary": "string",
  "findings": [
    {
      "source": "string",
      "rule_id": "string",
      "severity": "critical|high|medium|low|info",
      "confidence": 0.0,
      "file": "string",
      "line": 1,
      "evidence": "string",
      "remediation": "string",
      "category": "iam-policy"
    }
  ]
}

Rules:
- Keep evidence grounded in input findings.
- Use confidence >= 0.80 only when evidence is explicit and high signal.
""",
    tools=[],
)

# Level 2B: Secret specialist lane
secret_specialist_node = NodeSpec(
    id="secret-specialist",
    name="Secret Specialist Lane",
    description="Analyze credential leakage and exposed secret material",
    node_type="event_loop",
    max_node_visits=0,
    input_keys=["scanner_findings_json", "governance_charter_json"],
    output_keys=["secret_assessment_json"],
    success_criteria=(
        "Secret assessment flags exposed keys/tokens and prescribes immediate rotation "
        "and secure storage controls."
    ),
    system_prompt="""\
You are a secrets and credential exposure specialist.

Input:
- scanner_findings_json (JSON array)
- governance_charter_json (JSON object)

Tasks:
1) Focus on hardcoded keys, service account private keys, and API token patterns.
2) Prioritize rotation urgency and blast-radius reduction steps.
3) Produce normalized findings output for committee correlation.

Output via:
set_output("secret_assessment_json", "<JSON string>")

Required JSON structure:
{
  "lane": "secrets",
  "risk_summary": "string",
  "findings": [
    {
      "source": "string",
      "rule_id": "string",
      "severity": "critical|high|medium|low|info",
      "confidence": 0.0,
      "file": "string",
      "line": 1,
      "evidence": "string",
      "remediation": "string",
      "category": "secret-exposure"
    }
  ]
}

Rules:
- Secret material findings should be high confidence unless evidence is ambiguous.
- Never output unresolved placeholders.
""",
    tools=[],
)

# Level 3A: Correlation and prioritization committee
correlation_committee_node = NodeSpec(
    id="correlation-committee",
    name="Correlation Committee",
    description=(
        "Merge specialist lane outputs into a deduplicated prioritized enterprise finding set"
    ),
    node_type="event_loop",
    max_node_visits=0,
    input_keys=["iam_assessment_json", "secret_assessment_json", "governance_charter_json"],
    output_keys=["triaged_findings_json", "overall_risk"],
    success_criteria=(
        "Committee output is deduplicated, severity-ranked, and aligned to governance schema."
    ),
    system_prompt="""\
You are the enterprise correlation committee.

Input:
- iam_assessment_json
- secret_assessment_json
- governance_charter_json

Tasks:
1) Merge and deduplicate findings from both specialist lanes.
2) Resolve severity/confidence conflicts by choosing the stronger evidence-backed value.
3) Rank findings from highest to lowest risk.
4) Set an overall_risk level.

Output keys:
- set_output("triaged_findings_json", "<JSON array of normalized findings>")
- set_output("overall_risk", "critical|high|medium|low|info")

Requirements:
- Preserve exact normalized finding schema from governance charter.
- Keep evidence concise and actionable.
""",
    tools=[],
)

# Level 3B: Governance gate decision
risk_committee_node = NodeSpec(
    id="risk-committee",
    name="Risk Committee",
    description="Apply merge-block policy to triaged findings and record governance decision",
    node_type="event_loop",
    max_node_visits=0,
    input_keys=["triaged_findings_json", "overall_risk", "confidence_threshold"],
    output_keys=["governance_decision_json"],
    success_criteria=(
        "Decision object explicitly indicates block/pass with policy reasons and top issues."
    ),
    system_prompt="""\
You are the enterprise risk committee.

Input:
- triaged_findings_json
- overall_risk
- confidence_threshold (string/number)

Policy:
- block_merge = true only when at least one finding is severity=critical AND confidence >= threshold.
- otherwise block_merge = false.

Output via:
set_output("governance_decision_json", "<JSON string>")

Required JSON structure:
{
  "agent_summary": "string",
  "overall_risk": "critical|high|medium|low|info",
  "block_merge": true,
  "blocking_reasons": ["string"]
}

Rules:
- Blocking reasons must cite rule_id + location + confidence.
- No policy drift from the stated threshold rule.
""",
    tools=[],
)

# Level 3C: Executive reporting
executive_reporting_node = NodeSpec(
    id="executive-reporting",
    name="Executive Reporting",
    description="Produce concise executive markdown summary for SOC and engineering leaders",
    node_type="event_loop",
    max_node_visits=0,
    input_keys=["triaged_findings_json", "governance_decision_json"],
    output_keys=["executive_summary_md"],
    success_criteria=(
        "Executive summary communicates risk posture, gate result, and prioritized action plan."
    ),
    system_prompt="""\
You are the executive reporting lane.

Input:
- triaged_findings_json
- governance_decision_json

Output:
set_output("executive_summary_md", "<Markdown summary>")

Summary requirements:
- State merge gate result clearly.
- Include top 3 risks with concise remediation.
- Keep tone enterprise and operational.
- Avoid decorative language.
""",
    tools=[],
)

__all__ = [
    "governance_intake_node",
    "iam_specialist_node",
    "secret_specialist_node",
    "correlation_committee_node",
    "risk_committee_node",
    "executive_reporting_node",
]
