# VaultSight: Architecture & Engineering Design

## 1. High-Level Architecture

VaultSight implements a modular, decoupled pipeline for Data Security Posture Management (DSPM). Each component maintains a single, defense-in-depth responsibility:

```mermaid
graph TB
    subgraph Ingestion & Connectors
        FS[Local Filesystem]
        SQL[SQLite Database]
        S3[AWS S3 Moto]
    end

    subgraph Core Detection & Posture
        Rules[YAML Detection Rules] --> Engine[Detection Engine]
        Engine --> Checksums[Verhoeff & Luhn]
        Engine --> Entropy[Shannon Entropy]
        Engine --> Context[Proximity Keyword Weighting]
        Engine --> Redact[Safe Redaction]
        Posture[Cloud Posture Analyzer]
        IAM[IAM Policy Analyzer]
    end

    subgraph Analytics & Protection
        Risk[Risk Scoring Engine: Sens x Exp x Access]
        Exfil[Exfiltration & Insider-Risk Engine]
        LLMGuard[LLM Data-Leak Guard]
    end

    subgraph Presentation & Control
        FastAPI[FastAPI Gateway]
        Auth[JWT & RBAC Isolation]
    end

    FS --> Engine
    SQL --> Engine
    S3 --> Engine
    S3 --> Posture
    Engine --> Risk
    Posture --> Risk
    IAM --> Risk
    Risk --> FastAPI
    Exfil --> FastAPI
    LLMGuard --> FastAPI
```

---

## 2. Core Modules & Responsibilities

### `vaultsight.detectors`
- **`engine.py`**: Compiles YAML rules and executes scans against text. Combines regex matching, allowlist suppression, checksum checks, entropy analysis, and proximity keyword boosting.
- **`checksums.py`**: Pure Python implementations of the **Verhoeff** permutation algorithm (for Indian Aadhaar validation) and **Luhn** algorithm (mod 10 check for credit cards).
- **`entropy.py`**: Shannon entropy calculation ($H(X) = -\sum p(x) \log_2 p(x)$) for uncovering generic high-entropy API secrets and tokens.
- **`redact.py`**: Implements safe secret masking and placeholder allowlisting.

### `vaultsight.connectors`
- **`LocalFilesystemConnector`**: Walks filesystem directories with path-traversal prevention (`safe_resolve`), verifying all targets remain within the allowed scan root.
- **`SQLiteConnector`**: Connects via read-only URI (`?mode=ro`) to enumerate user tables, columns, and records.
- **`S3Connector`**: Integrates with `boto3` and moto to list buckets and paginate S3 object bodies safely.

### `vaultsight.posture`
- **`S3PostureAnalyzer`**: Audits S3 buckets for missing Block Public Access, public ACLs (`AllUsers`), public bucket policies (`Principal: *`), default encryption, server access logging, and object versioning.
- **`IAMPolicyAnalyzer`**: Analyzes IAM policy JSON documents for administrative wildcards (`*:*`), service wildcards (`s3:*` on `*`), and privilege escalation vectors (`iam:CreateAccessKey`, `iam:AttachUserPolicy`).

### `vaultsight.risk`
- **`RiskScoringEngine`**: Computes normalized DSPM risk scores using the formula:
  $$\text{Risk Score} = \frac{\text{Data Sensitivity} \times \text{Exposure} \times \text{Access Breadth}}{10.0}$$
  Outputs normalized scores (0 to 100), severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), and actionable remediation steps.

### `vaultsight.exfiltration`
- **`ExfiltrationDetector`**: Audits synthetic access logs for bulk downloads, off-hours access, first-seen IP addresses, volume spikes (>3x baseline), and role-sensitivity privilege mismatches.

### `vaultsight.api`
- **FastAPI Gateway**: Provides authenticated endpoints for starting scans, inspecting findings, and viewing reports. Implements JWT authentication, role-based access control (`admin`, `analyst`, `viewer`), per-user data isolation (IDOR protection), and secure HTTP headers.

### `vaultsight.llm_guard`
- **`LLMDataGuard`**: Intercepts prompts intended for LLMs, redacts sensitive PII and financial numbers, blocks transmission if high-confidence credentials are discovered, and prevents basic prompt-injection jailbreaks.
