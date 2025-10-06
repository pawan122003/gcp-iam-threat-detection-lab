# GCP IAM Threat Detection Lab

![Security Checks](https://github.com/pawan122003/gcp-iam-threat-detection-lab/workflows/Security%20Checks/badge.svg)
![CodeQL](https://github.com/pawan122003/gcp-iam-threat-detection-lab/workflows/CodeQL/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 🏗️ Architecture

For detailed architecture documentation, see [docs/architecture.md](docs/architecture.md).

## 🔍 Features

1. **Terraform Configuration**
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
