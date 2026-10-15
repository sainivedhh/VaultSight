# Security Testing & Threat Verification Report

This document outlines the automated security tests implemented in `tests/security/test_api_security.py` against the VaultSight API, detailing the threat vector, security risk, and technical mitigation in the codebase.

---

## Security Test Matrix

| Test Function | Vulnerability / Threat | Risk Severity | VaultSight Mitigation Architecture |
| :--- | :--- | :---: | :--- |
| `test_broken_authentication_missing_and_tampered_tokens` | **Broken Object/User Authentication (OWASP API1)** | **CRITICAL** | `get_current_user` dependency parses Bearer JWTs via `jose.jwt`. Missing or forged tokens return `401 Unauthorized` without leaking server state. |
| `test_token_expiration` | **Session Replay / Indefinite Token Validity** | **HIGH** | JWT tokens include an `exp` claim (default 60 minutes). Expired tokens are immediately invalidated during signature verification. |
| `test_idor_user_isolation` | **Broken Object-Level Authorization / IDOR (OWASP API1)** | **CRITICAL** | User A cannot query `/scans/{id}` or `/scans/{id}/findings` created by User B. Database queries enforce ownership `filter(ScanDB.owner_id == current_user.id)` unless user has `admin` role. |
| `test_rbac_viewer_blocked_from_initiating_scans` | **Broken Function Level Authorization (OWASP API5)** | **HIGH** | `require_analyst_or_admin` dependency gates the `/scans` execution endpoint. Accounts with role `viewer` receive `403 Forbidden`. |
| `test_path_traversal_in_scan_request` | **Path Traversal / Local File Inclusion (CWE-22)** | **CRITICAL** | Dual mitigation: (1) Pydantic `@field_validator("target_path")` rejects `..`, absolute slashes, and drive letters. (2) `LocalFilesystemConnector.safe_resolve()` asserts `Path.resolve().relative_to(base_dir)`. |
| `test_sqli_payload_resilience` | **SQL Injection (CWE-89)** | **HIGH** | All persistence uses SQLAlchemy 2.0 ORM with parameterized prepared statements, preventing syntax breakout and authentication bypass via `' OR '1'='1'`. |
| `test_secure_headers_presence` | **MIME-Sniffing, Clickjacking & Insecure Transport** | **MEDIUM** | Custom FastAPI HTTP middleware injects: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and strict CSP headers on all responses. |
| Rate Limiting & Body Limits | **Denial of Service (DoS) & Resource Exhaustion** | **MEDIUM** | Requests exceeding 10MB are rejected with `413 Payload Too Large`. An in-memory sliding window throttles clients exceeding 120 req/min with `429 Too Many Requests`. |

---

## Defensive Coding Standards Enforced
1. **Never Log or Store Raw Secrets**: Findings always store `redacted_preview` (e.g. `AK************LE`).
2. **Deterministic Role Checking**: Role checking is verified at the route handler dependency level, never trusted from client-controlled request parameters.
3. **Fail-Closed Design**: Any parsing or decoding anomaly raises structured HTTP exceptions (`401`/`403`/`400`) instead of raw stack traces.
