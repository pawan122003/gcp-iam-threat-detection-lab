# GCP IAM Threat Detection Lab

![Security Pipeline](https://github.com/pawan122003/gcp-iam-threat-detection-lab/actions/workflows/security.yml/badge.svg)
![Security](https://img.shields.io/badge/Security-GCP%20IAM-blue) ![Terraform](https://img.shields.io/badge/IaC-Terraform-purple) ![OPA](https://img.shields.io/badge/Policy-OPA-orange) ![Semgrep](https://img.shields.io/badge/SAST-Semgrep-green)

Detect leaked keys & privilege abuse on GCP using policy-as-code, detection-as-code, and CI security gates.

## 🎯 Project Overview

This lab demonstrates a comprehensive security detection and prevention framework for Google Cloud Platform (GCP) IAM. It combines multiple security layers:

- **Infrastructure as Code (IaC)** with Terraform
- **Policy as Code** with Open Policy Agent (OPA)
- **Detection as Code** with Semgrep and custom Python detectors
- **CI/CD Security Gates** with automated scanning
- **Secret Detection** with Gitleaks

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CI/CD Pipeline (GitHub Actions)          │
├─────────────────────────────────────────────────────────────┤
│  Terraform Validate → TFSec → OPA Policy Check → Semgrep   │
│  → Gitleaks → Custom Detectors → Security Report          │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│               Google Cloud Platform Infrastructure           │
├─────────────────────────────────────────────────────────────┤
│  • IAM Roles & Bindings  • Service Accounts                │
│  • Cloud Logging         • Security Command Center         │
│  • Secret Manager        • Audit Logs                      │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
gcp-iam-threat-detection-lab/
├── infra/
│   └── terraform/
│       ├── main.tf              # GCP provider & IAM resources
│       ├── variables.tf         # Input variables
│       ├── outputs.tf           # Output values
│       └── iam.tf              # IAM policy definitions
├── policies/
│   └── opa/
│       ├── iam_least_privilege.rego  # Least privilege policies
│       └── iam_security.rego         # IAM security rules
├── detection/
│   └── rules/
│       ├── semgrep.yaml             # Semgrep detection rules
│       └── custom_detectors.py     # Python-based detectors
├── pipelines/
│   └── .github/
│       └── workflows/
│           └── security.yml         # CI/CD security pipeline
├── tools/
│   └── scripts/
│       ├── scan_repo.sh            # Repository security scanner
│       └── detect_threats.py       # Threat detection script
├── docs/
│   ├── lab.md                      # Hands-on lab guide
│   └── architecture.md             # Architecture documentation
└── README.md
```

## 🚀 Quick Start

### Prerequisites

- **Google Cloud account** with billing enabled
- **Terraform** >= 1.5
- **Docker** (for OPA and Semgrep)
- **Python 3.9+**
- **gcloud CLI**

### Installation

```bash
# Clone the repository
git clone https://github.com/pawan122003/gcp-iam-threat-detection-lab.git
cd gcp-iam-threat-detection-lab

# Set up GCP authentication
gcloud auth application-default login
export GOOGLE_PROJECT="your-project-id"

# Initialize Terraform
cd infra/terraform
terraform init
terraform plan

# Run security scans locally
bash tools/scripts/scan_repo.sh
```

## 🚢 Codespaces & Previews

This repository is configured with a **devcontainer** for GitHub Codespaces, providing a pre-configured development environment with all security tools installed:

- **Terraform**, **OPA**, **Semgrep**, **Gitleaks**, **tfsec**, and **gcloud CLI**
- VS Code extensions for Terraform, OPA, Semgrep, Python, and YAML
- Automatic tool version display on container creation

### Quick Start with Codespaces

1. Click the **Code** button on this repository
2. Select **Codespaces** tab
3. Click **Create codespace on demo/pr-violation**
4. Wait for the container to build (first time takes ~3-5 minutes)
5. Start scanning: `bash tools/scripts/scan_repo.sh`

### Local Development with Dev Container

```bash
# Using VS Code with Dev Containers extension
code .
# Press F1 → "Dev Containers: Reopen in Container"
```

The devcontainer automatically validates your environment and displays installed tool versions.

## 🔐 Security Detection Capabilities

### 1. IAM Policy Violations

- **Detects overly permissive roles** (Owner, Editor)
- **Identifies service accounts** with excessive permissions
- **Flags public IAM bindings**

### 2. Secret Leakage

- **Scans for GCP service account keys**
- **Detects API keys and tokens** in code
- **Identifies hardcoded credentials**

### 3. Privilege Escalation

- **Monitors for dangerous permission combinations**
- **Detects attempts to modify IAM policies**
- **Tracks service account impersonation**

### 4. Compliance Checks

- **CIS GCP Foundations Benchmark**
- **Least privilege principle enforcement**
- **Separation of duties validation**

## 🧪 Hands-On Lab Scenarios

### Scenario 1: Leaked Service Account Key Detection

Simulate accidental commit of a GCP service account key and watch the detection pipeline identify and block it.

### Scenario 2: Privilege Escalation Attempt

Create an IAM policy that grants excessive permissions and see OPA policy engine reject it.

### Scenario 3: Audit Log Analysis

Analyze GCP audit logs to detect suspicious IAM activity patterns.

See [docs/lab.md](docs/lab.md) for detailed lab exercises.

## 📊 CI/CD Security Pipeline

The GitHub Actions workflow (.github/workflows/security.yml) automatically runs:

1. **Terraform Security**
   - terraform fmt -check
   - terraform validate
   - tfsec for Terraform static analysis

2. **Policy Evaluation**
   - OPA policy checks against IAM configurations
   - Least privilege validation

3. **Code Scanning**
   - Semgrep for SAST
   - Custom Python detectors
   - Gitleaks for secret scanning

4. **Reporting**
   - Security findings aggregation
   - SARIF report generation
   - GitHub Security tab integration

## 🛠️ Technologies Used

| Category | Tools |
|----------|-------|
| IaC | Terraform, Google Cloud Platform |
| Policy as Code | Open Policy Agent (OPA), Rego |
| SAST | Semgrep, TFSec |
| Secret Detection | Gitleaks |
| CI/CD | GitHub Actions |
| Languages | Python, Bash, HCL |

## 📈 Metrics & Monitoring

- **Detection Rate**: Percentage of malicious patterns caught
- **False Positive Rate**: Accuracy of detection rules
- **Time to Detection**: Speed of identifying threats
- **Remediation Time**: Time to fix identified issues

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add detection rules or improve existing ones
4. Submit a pull request

## 📚 Resources

- [GCP IAM Best Practices](https://cloud.google.com/iam/docs/best-practices)
- [CIS GCP Foundations Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)
- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Semgrep Rules](https://semgrep.dev/r)

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 👤 Author

**Pawan Bharambe**

- DevOps Engineer specializing in GCP & Security
- GitHub: [@pawan122003](https://github.com/pawan122003)
- Focus: Cloud Security, Infrastructure as Code, DevSecOps

## ⭐ Show Your Support

Give a ⭐️ if this project helped you learn about GCP security!

**Note**: This is a lab environment for educational purposes. Always follow your organization's security policies in production.
