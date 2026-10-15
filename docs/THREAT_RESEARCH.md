# Threat Research: Data Breach & Exfiltration Patterns

This document details **three real-world, historically documented cloud data breach and exfiltration incidents**, detailing their technical mechanics and mapping each to the corresponding detection control implemented in **VaultSight**.

---

## Case 1: Capital One AWS S3 Data Breach (2019)

### Technical Incident Breakdown
- **Incident Summary**: In July 2019, an attacker exploited a Server-Side Request Forgery (SSRF) vulnerability on a misconfigured open-source Web Application Firewall (ModSecurity running on an EC2 instance) within Capital One's AWS environment.
- **Exfiltration Mechanics**:
  1. The SSRF allowed querying the EC2 instance metadata service (IMDSv1) at `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
  2. The instance's attached IAM role possessed overly broad permissions (`s3:ListAllMyBuckets`, `s3:Sync`, and wildcard `s3:*` read access across customer S3 buckets).
  3. The adversary leveraged AWS CLI `aws s3 sync` to systematically copy over 700 S3 buckets containing credit card applications, Social Security numbers, and bank account details.
- **VaultSight Detection Mapping**:
  - **`IAM-BROAD-SERVICE-WILDCARD` & `IAM-ADMIN-WILDCARD`**: Flags overly broad wildcard statements (`s3:*` across `*`) attached to roles, enforcing least-privilege scoping.
  - **`BULK_EXFILTRATION`**: Triggers critical alerts when automated sync/copy routines exceed baseline thresholds for records or byte transfer.
  - **`S3-BPA-DISABLED`**: Flags bucket posture where public or cross-account access protections are not uniformly enforced.

---

## Case 2: Tesla Kubernetes Dashboard & Unsecured S3 Bucket Exposure (2018)

### Technical Incident Breakdown
- **Incident Summary**: In February 2018, RedLock security researchers discovered an unauthenticated Kubernetes dashboard deployed on AWS belonging to Tesla.
- **Exfiltration Mechanics**:
  1. The cluster management console lacked password protection or IAM authentication.
  2. Adversaries extracted plaintext AWS root/admin access keys and API credentials stored in unsecured Kubernetes pods.
  3. These long-lived credentials granted unrestricted read access to Amazon S3 telemetry buckets storing vehicle telemetry, proprietary mapping data, and employee records.
- **VaultSight Detection Mapping**:
  - **`aws_access_key` detector**: Scans code repositories, configuration files, and database rows for hardcoded `AKIA...` access key patterns, immediately redacting them.
  - **`S3-NO-DEFAULT-ENCRYPTION` & `S3-LOGGING-DISABLED`**: Enforces default KMS encryption and logging so any unauthorized reading of objects leaves an immutable CloudTrail/S3 server audit log.
  - **`FIRST_SEEN_IP` & `OFF_HOURS_ACCESS`**: Detects when stolen administrative credentials authenticate from unobserved foreign IPs or during abnormal hours.

---

## Case 3: Imperva Cloud Web Application Firewall API Key Compromise (2019)

### Technical Incident Breakdown
- **Incident Summary**: In August 2019, cybersecurity firm Imperva disclosed that an exposed AWS API key led to the unauthorized access of customer SSL certificates, API keys, and hashed passwords.
- **Exfiltration Mechanics**:
  1. An internal AWS compute instance was created containing an embedded AWS API key.
  2. The instance was unintentionally exposed to the public Internet, allowing external entities to retrieve the embedded credentials.
  3. The stolen API key allowed querying AWS snapshots and downloading database backup files containing sensitive customer tokens and configuration data.
- **VaultSight Detection Mapping**:
  - **`generic_high_entropy_secret` & `db_connection_string`**: Automatically detects high-entropy secrets and database URIs with embedded passwords in configuration files before deployment.
  - **`PRIVILEGE_SENSITIVITY_MISMATCH`**: Triggers immediate alerts when low-privilege roles or compute identities access production database snapshots or sensitive customer storage tiers.
  - **`SUDDEN_VOLUME_SPIKE`**: Alarms on sudden deviations where an identity begins querying massive database backup volumes.

---

## Mapping Matrix Summary

| Incident | Threat Vector | Primary Misconfiguration / Action | VaultSight Control ID |
| :--- | :--- | :--- | :--- |
| **Capital One (2019)** | SSRF to Instance Metadata | Wildcard `s3:*` IAM role + bulk `s3 sync` | `IAM-BROAD-SERVICE-WILDCARD`, `BULK_EXFILTRATION` |
| **Tesla (2018)** | Unsecured K8s Console | Exposed plaintext `AKIA` keys in config | `aws_access_key`, `S3-BPA-DISABLED` |
| **Imperva (2019)** | Exposed Compute Key | Stolen API key reading DB backups | `generic_high_entropy_secret`, `PRIVILEGE_SENSITIVITY_MISMATCH` |
