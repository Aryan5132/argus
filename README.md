# 🛡️ Argus (formerly Sentinel) – Cloud Misconfiguration Detection System

Argus is a lightweight, real-time cloud security dashboard designed to automatically detect, score, and monitor misconfigurations in your AWS environment. Built with a fast Python backend and a responsive, dark-themed vanilla frontend, Argus provides instant visibility into your cloud security posture.

## Quick Start

### 1. Install Dependencies
```bash
cd sentinel
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
copy .env.example .env
# Edit .env with your AWS credentials and optional alert settings
```

### 3. Run
```bash
python run.py
```

Open your browser at: **http://localhost:8000**

---

## What It Scans

| Resource | Rules |
|---|---|
| **S3** | Public access, encryption, versioning, logging |
| **IAM** | Wildcard permissions, MFA, unused credentials, root account |
| **Security Groups** | SSH/RDP/DB ports open to 0.0.0.0/0, all-traffic rules |
| **EC2** | Public IPs, IMDSv2, unencrypted EBS volumes |

## API Docs
Swagger UI available at: **http://localhost:8000/docs**

## Severity Levels

| Level | Examples |
|---|---|
| 🔴 CRITICAL | Root MFA disabled, wildcard IAM permissions |
| 🟠 HIGH | SSH/RDP open to internet, MFA not enabled |
| 🟡 MEDIUM | Encryption disabled, unused credentials |
| 🟢 LOW | Versioning/logging disabled |

## ML Risk Score
Each finding receives a **0.0–1.0 risk score** from a Random Forest model trained on 10,000 synthetic samples. The model considers: public_access, encryption_enabled, ip_open, sensitive_port, wildcard_permission, mfa_enabled, public_ip.

## AWS Permissions Required
Attach **SecurityAudit** managed policy (read-only) to your IAM user.

