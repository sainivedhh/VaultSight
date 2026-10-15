# VaultSight: Mini DSPM (Data Security Posture Management) Toolkit

[![CI Pipeline](https://github.com/example/vaultsight/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Security: Bandit & Ruff](https://img.shields.io/badge/security-bandit%20%7C%20ruff-green.svg)](SECURITY_TESTING.md)

A defensive, enterprise-grade mini **Data Security Posture Management (DSPM)** toolkit designed for security engineering internships and data security teams. Built completely defensibly using synthetic datasets, simulated cloud primitives (moto), and zero real credential exposure.

---

## 1. Why VaultSight?
Modern enterprises store exabytes of data scattered across object stores, relational databases, and local systems. Traditional tools fail because:
1. **High False Positive Rates**: Simple regex checks alert on any 12-digit number (order IDs, barcode scans) or placeholder test values.
2. **Disconnected Context**: Cloud posture tools (CSPM) check bucket permissions without knowing if sensitive data is actually inside.
3. **LLM Data Exfiltration**: Employees inadvertently paste API keys and PII into generative AI models.

**VaultSight solves this** by coupling **multi-stage algorithmic data classification** (checksums, entropy, proximity keywords) directly with **cloud posture auditing** (S3, IAM) and **dynamic exfiltration analytics**.

---

## 2. Architecture Overview

```mermaid
graph TD
    subgraph Data Sources
        FS[Local Filesystem]
        SQL[SQLite Tables]
        S3[AWS S3 Moto Mock]
    end

    subgraph VaultSight Core Engine
        Engine[Detection Engine]
        Verhoeff[Verhoeff Checksum: Aadhaar]
        Luhn[Luhn Checksum: Credit Cards]
        Entropy[Shannon Entropy: Generic Secrets]
        Engine --- Verhoeff
        Engine --- Luhn
        Engine --- Entropy
        Posture[Cloud Posture & IAM Analyzer]
    end

    subgraph Intelligence & Protection
        Risk[Risk Scoring Engine: Sens x Exp x Access]
        Exfil[Insider Threat & Exfiltration Engine]
        LLMGuard[LLM Data-Leak Guard]
    end

    FS --> Engine
    SQL --> Engine
    S3 --> Engine
    S3 --> Posture
    Engine --> Risk
    Posture --> Risk
    Risk --> API[FastAPI Secure Gateway]
    Exfil --> API
    LLMGuard --> API
```

---

## 3. Key Capabilities

### 🔍 Sensitive Data Detection Engine
- **Supported Detectors**:
  - **Indian Aadhaar**: 12-digit format with Verhoeff checksum validation.
  - **Indian PAN**: Regex structure check + corporate/individual status codes.
  - **Indian Mobile Numbers**: Format checks with +91 prefixes and keyword proximity.
  - **Email Addresses**: RFC-compliant pattern validation.
  - **Payment Cards**: Luhn (mod 10) validation across Visa, Mastercard, RuPay.
  - **AWS Access Keys**: `AKIA...` and `ASIA...` prefix matches.
  - **GitHub Personal Access Tokens**: `ghp_`, `gho_`, `ghu_` PAT formats.
  - **Private Keys**: RSA/EC/DSA PEM headers.
  - **JSON Web Tokens (JWT)**: Base64 header/payload/signature triplets.
  - **Database Connection Strings**: Embedded credential URIs (`postgres://`, `mysql://`).
  - **Generic High-Entropy Secrets**: Shannon entropy calculation ($H > 3.5$) with variable length thresholding.
- **Rules Defined in YAML**: Add or modify rules in `vaultsight/detectors/rules.yaml` without changing code.
- **Redaction-First Guarantee**: Raw secrets are never stored, logged, or returned over APIs.

### ☁️ Cloud Posture & IAM Analyzer (Simulated AWS)
- **S3 Bucket Auditing**: Checks for missing Block Public Access (all 4 flags), open ACLs (`AllUsers`), public bucket policies (`Principal: *`), default encryption, access logging, and object versioning.
- **IAM Policy Analysis**: Flags `*:*` administrative wildcards, broad `s3:*` wildcards, missing conditions (`aws:SecureTransport`), and privilege escalation vectors (`iam:CreateAccessKey`, `iam:AttachUserPolicy`).
- **Composite Risk Scoring**: Tri-factor scoring:
  $$\text{Risk} = \frac{\text{Data Sensitivity} \times \text{Exposure} \times \text{Access Breadth}}{10.0}$$

### 🚨 Exfiltration & Insider-Risk Engine
- Detects bulk downloads, off-hours access (e.g. 22:00 to 05:00 UTC), first-seen IP addresses, sudden volume spikes (>3x user baseline), and privilege-sensitivity mismatches.
- Documented threat research in [`docs/THREAT_RESEARCH.md`](docs/THREAT_RESEARCH.md) mapping detections to the **Capital One (2019)**, **Tesla (2018)**, and **Imperva (2019)** cloud breaches.

### 🛡️ Secure API & LLM Guard
- **FastAPI Gateway**: Authenticated with JWT, role-based access control (`admin`, `analyst`, `viewer`), per-user data isolation (IDOR protection), rate limiting, and secure HTTP headers.
- **LLM Data-Leak Guard**: Redacts PII/financial values, blocks high-confidence credential leaks, and catches basic prompt-injection jailbreaks before reaching LLMs. Uses a zero-network mock client.

---

## 4. Benchmark & Accuracy Evaluation Results

Evaluated against a reproducible labeled synthetic corpus of **245 samples** (generated via `scripts/generate_dataset.py` with fixed random seed `42`).

| Metric | Measured Result |
| :--- | :---: |
| **Total Samples Evaluated** | 245 |
| **Overall Precision** | **100.00%** |
| **Overall Recall** | **100.00%** |
| **Overall F1-Score** | **100.00%** |
| **Aadhaar Verhoeff FP Rejection** | **100% of invalid 12-digit barcodes rejected** |
| **Allowlist / Placeholder Suppression** | Cleanly filters dummy tokens (e.g. `AKIAIOSFODNN7EXAMPLE`) |

*For complete detector-by-detector breakdown and iteration history, see [`EVALUATION.md`](EVALUATION.md).*

---

## 5. Quick Start

### Prerequisites
- Python 3.11+
- Git

### Installation
```bash
# Clone the repository
git clone https://github.com/example/vaultsight.git
cd VaultSight

# Install pinned dependencies
pip install -r requirements.txt
```

### Running the Test Suite
```bash
# Run all unit, posture, and security tests
python -m pytest -v
```

### Running the Evaluation Benchmark
```bash
# Generate reproducible synthetic evaluation corpus
python -m scripts.generate_dataset

# Run accuracy evaluation and generate EVALUATION.md
python -m scripts.evaluate
```

### Launching the Secure API
```bash
uvicorn vaultsight.api.app:create_app --factory --reload --port 8000
```
Visit `http://localhost:8000/docs` to interact with the Swagger OpenAPI documentation.

### Running with Docker
```bash
# Build the hardened non-root container image
docker build -t vaultsight:latest .

# Run the container
docker run -p 8000:8000 vaultsight:latest
```

---

## 6. Project Documentation Directory

- [`ARCHITECTURE.md`](ARCHITECTURE.md): Deep-dive into system design, flowcharts, and component interfaces.
- [`THREAT_MODEL.md`](THREAT_MODEL.md): STRIDE threat modeling, trust boundaries, and mitigation table.
- [`EVALUATION.md`](EVALUATION.md): Accuracy metrics, false positive/negative tuning log, and weak spots.
- [`SECURITY_TESTING.md`](SECURITY_TESTING.md): Documentation of automated tests for IDOR, auth, SQLi, and path traversal.
- [`docs/THREAT_RESEARCH.md`](docs/THREAT_RESEARCH.md): Analysis of real-world cloud data breach and exfiltration patterns.
- [`infra/`](infra/): Reference Terraform configurations showing vulnerable vs. remediated S3/IAM posture.
- [`SECURITY.md`](SECURITY.md): Vulnerability reporting policy and SLA.

---

## 7. Limitations & Honest Assessment

> [!IMPORTANT]
> **Limitations & Practical Boundaries**:
> 1. **Synthetic Data Only**: All testing and benchmark metrics were derived using synthetic test generators (`scripts/generate_dataset.py`, Faker, and algorithmic generators). No real customer PII or credentials were used.
> 2. **Simulated Cloud Primitives**: AWS S3 and IAM posture checks are evaluated against `moto` mocks. While moto faithfully emulates AWS APIs, real AWS accounts exhibit edge cases (e.g. SCPs, permissions boundaries, session policies, bucket owner conditions) not fully captured by local simulation.
> 3. **Benchmark Specificity**: Accuracy numbers (Precision/Recall/F1) reflect the controlled evaluation corpus. Deploying VaultSight to production environments with unstandardized enterprise formats will necessitate continuous rule tuning.
> 4. **LLM Guarding Bounds**: The prompt injection guard catches common direct adversarial signatures. Advanced indirect or semantic obfuscation jailbreaks naturally bypass simple heuristic pattern guards and require specialized embedding classifiers.
