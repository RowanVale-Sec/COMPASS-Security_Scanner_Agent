# COMPASS Security Scanner Agent

AI-powered security scanning system that analyzes Infrastructure as Code (IaC), source code, and containers using multiple security tools with intelligent deduplication and MITRE ATT&CK mapping.

## 🏗️ Architecture

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│  Security Scanner   │    │   MITRE MCP Server  │    │   External Services │
│                     │    │                     │    │                     │
│  ┌─────────────────┐│    │  ┌─────────────────┐│    │  ┌─────────────────┐│
│  │ Checkov         ││    │  │ ATT&CK Database ││    │  │ Azure OpenAI    ││
│  │ Trivy           ││────┼──│ Threat Intel    ││    │  │ AWS S3          ││
│  │ Bandit          ││    │  └─────────────────┘│    │  └─────────────────┘│
│  │ Semgrep         ││    └─────────────────────┘    └─────────────────────┘
│  └─────────────────┘│
│  ┌─────────────────┐│
│  │ AI Deduplication││
│  │ MITRE Mapping   ││
│  └─────────────────┘│
└─────────────────────┘
```

## 🚀 Features

- **Multi-Tool Scanning**: Checkov, Trivy, Bandit, Semgrep
- **AI Deduplication**: Removes duplicate findings using embeddings
- **MITRE ATT&CK Mapping**: Maps findings to threat techniques
- **S3 Storage**: Automatic results upload
- **Docker Deployment**: Container orchestration

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Azure OpenAI account
- AWS S3 bucket

### Setup

1. **Create `.env` file**:
```bash
# Azure OpenAI
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_API_KEY=your-api-key
AZURE_OPENAI_CHAT_DEPLOYMENT_NAME=gpt-4o

# AWS S3
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
S3_BUCKET=your-bucket-name
```

2. **Run the scanner**:
```bash
docker-compose up --build
```

## 📊 Output

### Results JSON Structure
```json
{
  "metadata": {
    "analysis_date": "2025-10-26T23:31:52.733516",
    "total_findings": 31,
    "mitre_mcp_url": "http://mitre-mcp:8000/mcp",
    "source_file": "s3://my-security-scans/scan-results/agent-scan-20251026-233056-deduplicated.json",
    "tool_distribution": {
      "C": 12,
      "T": 13,
      "B": 1,
      "S": 5
    }
  },
  "FND-C-1": {
    "finding": {
      "tool_name": "Checkov",
      "file_path": "/terraform/data.tf",
      "finding_title": "Reduce potential for WhoAMI cloud image name confusion attack",
      "description": "N/A",
      "recommendation": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-supply-chain-policies/bc-aws-386",
      "resource_type": "aws_ami",
      "resource_name": "amazon-linux-2023",
      "severity": "N/A",
      "scan_type": "IaC"
    },
    "mitre_analysis": {
      "technique_id": "T1036.005",
      "technique_name": "Match Legitimate Resource Name or Location",
      "tactic": "Defense Evasion",
      "adjusted_severity": "HIGH",
      "confidence": "HIGH",
      "rationale": "This finding highlights the risk of cloud resources being misnamed..."
    }
  }
}
```

### S3 Storage
```
s3://your-bucket/
├── mitre-mapped-findings/
│   └── agent-scan-20251026-233056-mitre-mapped.json
└── scan-results/
    ├── agent-scan-20251026-233056.json
    └── agent-scan-20251026-233056-deduplicated.json
```

## � Configuration

### Scan Different Folder
```yaml
# docker-compose.yml
services:
  security-agent:
    volumes:
      - /path/to/your/code:/scan:ro
```

### Security Tools
- **Checkov**: IaC security (Terraform, CloudFormation, K8s)
- **Trivy**: Container and IaC vulnerabilities
- **Bandit**: Python code security
- **Semgrep**: Multi-language SAST

## 🚨 Troubleshooting

### Common Issues

**Azure OpenAI Error**:
```bash
# Check deployment name
az cognitiveservices account deployment list --name your-resource --resource-group your-rg
```

**S3 Permission Error**:
```json
{
  "Effect": "Allow",
  "Action": ["s3:PutObject", "s3:GetObject"],
  "Resource": "arn:aws:s3:::your-bucket/*"
}
```

**View Logs**:
```bash
docker-compose logs -f security-agent
docker-compose logs -f mitre-mcp
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file.