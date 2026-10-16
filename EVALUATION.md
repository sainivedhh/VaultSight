# VaultSight — Detection Engine Accuracy Report

> [!IMPORTANT]
> All numbers below come from **real runs** on fully synthetic labeled corpora.
> No real personal data or credentials were used at any point.

> [!NOTE]
> **Benchmark Integrity**
> The *Development Set* was generated with seed 42 and rules were tuned against it.
> The *Independent Holdout Set* was generated with seed 1337, uses different formats
> (mixed-case keys, Kubernetes YAML, GitHub Actions, base64-encoded secrets,
> harder negatives), and rules were **NOT** tuned against it before the baseline run.

## Development Set (Tuned-On — seed 42)
> Corpus: `data/evaluation_corpus.json`

| Metric | Value |
| :--- | ---: |
| Total samples | 245 (165 pos / 80 neg) |
| True Positives | 165 |
| False Positives | 0 |
| False Negatives | 0 |
| **Precision** | **100.00%** |
| **Recall** | **100.00%** |
| **F1-Score** | **100.00%** |

### Per-Detector Breakdown

| Detector | TP | FP | FN | Precision | Recall | F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `aadhaar` | 15 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `aws_access_key` | 15 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `credit_card` | 15 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `db_connection_string` | 15 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `email` | 15 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `generic_high_entropy_secret` | 15 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `github_token` | 15 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `indian_mobile` | 15 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `jwt` | 15 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `pan` | 15 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `private_key` | 15 | 0 | 0 | 100.0% | 100.0% | 100.0% |

### False Positives: 0
None observed.

### False Negatives: 0
None observed.

## Independent Holdout Set (Untuned — seed 1337)
> Corpus: `data/holdout_corpus.json`

| Metric | Value |
| :--- | ---: |
| Total samples | 386 (156 pos / 230 neg) |
| True Positives | 156 |
| False Positives | 36 |
| False Negatives | 0 |
| **Precision** | **81.25%** |
| **Recall** | **100.00%** |
| **F1-Score** | **89.66%** |

### Per-Detector Breakdown

| Detector | TP | FP | FN | Precision | Recall | F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `aadhaar` | 22 | 2 | 0 | 91.7% | 100.0% | 95.7% |
| `aws_access_key` | 12 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `credit_card` | 12 | 2 | 0 | 85.7% | 100.0% | 92.3% |
| `db_connection_string` | 10 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `email` | 12 | 32 | 0 | 27.3% | 100.0% | 42.9% |
| `generic_high_entropy_secret` | 12 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `github_token` | 12 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `indian_mobile` | 22 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `jwt` | 10 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `pan` | 22 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `private_key` | 10 | 0 | 0 | 100.0% | 100.0% | 100.0% |

### False Positives: 36
1. `email` on: `# Notification settings
ALERT_PHONE=+918281721635
ALERT_EMAIL=ops@internal.examp...` — Secondary detector cross-fired on positive sample
2. `email` on: `# Notification settings
ALERT_PHONE=+919655548887
ALERT_EMAIL=ops@internal.examp...` — Secondary detector cross-fired on positive sample
3. `aadhaar` on: `# Notification settings
ALERT_PHONE=+919655548887
ALERT_EMAIL=ops@internal.examp...` — Secondary detector cross-fired on positive sample
4. `email` on: `# Notification settings
ALERT_PHONE=+916572407761
ALERT_EMAIL=ops@internal.examp...` — Secondary detector cross-fired on positive sample
5. `email` on: `# Notification settings
ALERT_PHONE=+916727561324
ALERT_EMAIL=ops@internal.examp...` — Secondary detector cross-fired on positive sample
6. `email` on: `# Notification settings
ALERT_PHONE=+917845924514
ALERT_EMAIL=ops@internal.examp...` — Secondary detector cross-fired on positive sample
7. `email` on: `# Notification settings
ALERT_PHONE=+919891183443
ALERT_EMAIL=ops@internal.examp...` — Secondary detector cross-fired on positive sample
8. `email` on: `# Notification settings
ALERT_PHONE=+918323030819
ALERT_EMAIL=ops@internal.examp...` — Secondary detector cross-fired on positive sample

### False Negatives: 0
None observed.

---

## Known Limitations & Weak Spots

- **Generic entropy detector**: requires a secret keyword (`password`, `token`, etc.) within the same line. Naked high-entropy strings without context are intentionally ignored to avoid noisy false positives on UUIDs, build IDs, and hex hashes.
- **Bare 10-digit Indian mobile numbers** are only flagged when a phone/contact keyword is nearby or the number is explicitly prefixed with `+91`/`91`.
- **International PII**: rules are currently optimized for Indian (Aadhaar, PAN) and US identity formats. Other jurisdictions require additional rule authoring.
- **Base64-opaque blobs**: secrets embedded in the *encoded* portion of a base64 string without a decoded text comment will be missed. Only decoded references are detectable without active decoding (not implemented).