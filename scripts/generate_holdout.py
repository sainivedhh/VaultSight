"""Independent Synthetic Evaluation Corpus Generator (Holdout Set — Untuned).

Purpose:
  - Seed: 1337 (independent of dev-set seed 42).
  - Harder structure than the dev set:
      * Aadhaar / PAN embedded in base64-wrapped blobs and SQL payloads.
      * Credentials inside realistic noisy contexts: Kubernetes secrets,
        Dockerfile ENV, GitHub Actions YAML, multi-line log tails.
      * Mixed-case keyword variants (Api_Key, CLIENT_SECRET, PASSWORD).
      * Phone numbers without +91 prefix (require context keyword to fire).
      * Hard negatives: hex SHA-256/SHA-1/git commits, UUIDs v4, semantic
        version strings, long Docker image digests, IP addresses, invoice IDs,
        documentation examples, Luhn-invalid card lookalikes, and high-entropy
        random strings WITHOUT a secret keyword (should NOT fire).

CRITICAL RULE:
  Rules MUST NOT be tuned against this corpus before an honest baseline run.
"""

import json
import random
import base64
import uuid
import hashlib
from pathlib import Path
from faker import Faker

from vaultsight.detectors.checksums import generate_verhoeff_checksum, validate_verhoeff

SEED = 1337
random.seed(SEED)
fake = Faker(["en_IN", "en_US"])
Faker.seed(SEED)

# ---------------------------------------------------------------------------
# Helpers — positive sample generators
# ---------------------------------------------------------------------------

def _gen_aadhaar_digits() -> str:
    """Return a valid 12-digit Aadhaar string (no separators)."""
    prefix = str(random.randint(2, 9)) + "".join(str(random.randint(0, 9)) for _ in range(10))
    return prefix + str(generate_verhoeff_checksum(prefix))


def gen_aadhaar_plain() -> str:
    return _gen_aadhaar_digits()


def gen_aadhaar_spaced() -> str:
    d = _gen_aadhaar_digits()
    sep = random.choice([" ", "-", "  "])
    return f"{d[:4]}{sep}{d[4:8]}{sep}{d[8:]}"


def gen_invalid_aadhaar() -> str:
    prefix = str(random.randint(2, 9)) + "".join(str(random.randint(0, 9)) for _ in range(10))
    good = generate_verhoeff_checksum(prefix)
    bad = (good + random.randint(1, 9)) % 10
    cand = f"{prefix}{bad}"
    while validate_verhoeff(cand):
        bad = (bad + 1) % 10
        cand = f"{prefix}{bad}"
    return cand


def gen_pan() -> str:
    lets = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    fourth = random.choice("PCHATBLFJG")
    return (
        f"{random.choice(lets)}{random.choice(lets)}{random.choice(lets)}"
        f"{fourth}{random.choice(lets)}{random.randint(1000, 9999)}{random.choice(lets)}"
    )


def gen_mobile_with_context() -> str:
    """Indian mobile with explicit +91 prefix."""
    return f"+91{random.choice([6, 7, 8, 9])}{random.randint(100_000_000, 999_999_999)}"


def gen_mobile_bare() -> str:
    """10-digit mobile WITHOUT prefix — needs context keywords."""
    return f"{random.choice([6, 7, 8, 9])}{random.randint(100_000_000, 999_999_999)}"


def gen_cc_valid() -> str:
    prefix = "4" + "".join(str(random.randint(0, 9)) for _ in range(14))
    digits = [int(c) for c in prefix]
    total = sum(
        (d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 == 0 else d
        for i, d in enumerate(digits[::-1])
    )
    check = (10 - (total % 10)) % 10
    num = prefix + str(check)
    sep = random.choice(["", " ", "-"])
    return f"{num[:4]}{sep}{num[4:8]}{sep}{num[8:12]}{sep}{num[12:]}"


def gen_aws_key() -> str:
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    prefix = random.choice(["AKIA", "ASIA"])
    return prefix + "".join(random.choice(chars) for _ in range(16))


def gen_github_token() -> str:
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
    prefix = random.choice(["ghp", "gho", "ghu", "ghs"])
    return f"{prefix}_" + "".join(random.choice(chars) for _ in range(36))


def gen_jwt() -> str:
    hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    pay = base64.urlsafe_b64encode(
        f'{{"sub":"{fake.uuid4()}","iat":1700000000}}'.encode()
    ).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(uuid.uuid4().bytes * 2).decode().rstrip("=")
    return f"{hdr}.{pay}.{sig}"


def gen_db_conn() -> str:
    scheme = random.choice(["postgres", "postgresql", "mysql", "mongodb"])
    u = fake.user_name()
    p = "".join(
        random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$")
        for _ in range(14)
    )
    h = fake.domain_name()
    port = random.choice([5432, 3306, 27017])
    return f"{scheme}://{u}:{p}@{h}:{port}/prod_vault"


def gen_entropy_secret() -> str:
    return "".join(
        random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
        for _ in range(random.randint(32, 48))
    )


def b64_wrap(text: str) -> str:
    """Base64-encode a string and return the encoding."""
    return base64.b64encode(text.encode()).decode()


# ---------------------------------------------------------------------------
# Hard negative generators
# ---------------------------------------------------------------------------

def gen_hex_hash() -> str:
    return hashlib.sha256(str(random.random()).encode()).hexdigest()


def gen_git_sha() -> str:
    return hashlib.sha1(str(random.random()).encode()).hexdigest()


def gen_uuid4() -> str:
    return str(uuid.uuid4())


def gen_semver() -> str:
    return f"v{random.randint(1,9)}.{random.randint(0,25)}.{random.randint(0,99)}-rc.{random.randint(1,10)}"


def gen_invoice_id() -> str:
    return f"INV-{random.randint(2025,2027)}-{random.randint(100000, 999999)}"


def gen_docker_digest() -> str:
    return "sha256:" + hashlib.sha256(str(random.random()).encode()).hexdigest()


def gen_luhn_invalid_card() -> str:
    """15-digit number (not 16) in a card-like format that fails Luhn.
    Using 15 digits avoids matching the 16-digit credit card regex.
    Prefix '37' (AmEx-style) starts digits that won't look like Aadhaar (which starts 2-9).
    """
    raw = "37" + "".join(str(random.randint(0, 9)) for _ in range(12))
    # Intentionally corrupt by appending 0 (very unlikely to be the right Luhn check)
    return f"{raw[:4]} {raw[4:10]} {raw[10:]}0"


def gen_high_entropy_no_keyword() -> str:
    """High-entropy string but no surrounding secret keyword — should NOT fire."""
    tok = "".join(
        random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        for _ in range(40)
    )
    safe_keys = random.choice(["correlation_id", "trace_id", "request_id", "transaction_ref"])
    return f"Log metadata: {safe_keys}={tok} status=200"


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_holdout_dataset(output_file: str = "data/holdout_corpus.json") -> dict:
    corpus = []

    # ------------------------------------------------------------------
    # POSITIVE SAMPLES — messier embeddings, mixed-case keys, base64 wraps
    # ------------------------------------------------------------------

    # 1. Aadhaar in SQL INSERT (spaced format)
    for _ in range(12):
        corpus.append({
            "text": (
                f"INSERT INTO kyc_data (cust_id, uid_num, dob) VALUES "
                f"({random.randint(1000, 9999)}, '{gen_aadhaar_spaced()}', '1990-04-12');"
            ),
            "expected_detector": "aadhaar",
            "is_positive": True,
        })

    # 2. Aadhaar in JSON blob (plain, no separator)
    for _ in range(10):
        corpus.append({
            "text": json.dumps({
                "type": "kyc_verification",
                "payload": {
                    "AADHAAR_NUMBER": gen_aadhaar_plain(),
                    "verified": True,
                },
            }),
            "expected_detector": "aadhaar",
            "is_positive": True,
        })

    # 3. PAN in log line (mixed case key)
    for _ in range(12):
        corpus.append({
            "text": (
                f"[2026-10-15 10:22:11] [INFO] Validated PAN_Card: {gen_pan()} "
                f"for application_id=REQ-{random.randint(10000, 99999)}"
            ),
            "expected_detector": "pan",
            "is_positive": True,
        })

    # 4. PAN in YAML config
    for _ in range(10):
        corpus.append({
            "text": (
                f"applicant:\n"
                f"  name: {fake.name()}\n"
                f"  pan: \"{gen_pan()}\"\n"
                f"  status: approved\n"
            ),
            "expected_detector": "pan",
            "is_positive": True,
        })

    # 5. Indian mobile with +91 prefix in .env file
    for _ in range(12):
        corpus.append({
            "text": (
                f"# Notification settings\n"
                f"ALERT_PHONE={gen_mobile_with_context()}\n"
                f"ALERT_EMAIL=ops@internal.example.com\n"
            ),
            "expected_detector": "indian_mobile",
            "is_positive": True,
        })

    # 6. Indian mobile bare 10-digit with contact keyword
    for _ in range(10):
        mob = gen_mobile_bare()
        corpus.append({
            "text": (
                f"Emergency contact phone number: {mob} (primary)"
            ),
            "expected_detector": "indian_mobile",
            "is_positive": True,
        })

    # 7. Email in authorization log
    for _ in range(12):
        em = fake.email()
        corpus.append({
            "text": (
                f"2026-10-15T08:30:12Z [auth] Successful login email={em} "
                f"ip=172.16.0.{random.randint(1, 254)} session={uuid.uuid4()}"
            ),
            "expected_detector": "email",
            "is_positive": True,
        })

    # 8. Credit card in YAML payment block
    for _ in range(12):
        corpus.append({
            "text": (
                f"payment:\n"
                f"  card_number: \"{gen_cc_valid()}\"\n"
                f"  expiry: \"09/28\"\n"
                f"  cvv: \"{random.randint(100, 999)}\"\n"
            ),
            "expected_detector": "credit_card",
            "is_positive": True,
        })

    # 9. AWS key in Kubernetes secret (base64 wrapped JSON)
    for _ in range(12):
        aws_key = gen_aws_key()
        inner = json.dumps({"AWS_ACCESS_KEY_ID": aws_key, "AWS_REGION": "us-east-1"})
        corpus.append({
            "text": (
                f"apiVersion: v1\nkind: Secret\n"
                f"metadata:\n  name: aws-creds\n"
                f"data:\n  config.json: {b64_wrap(inner)}\n"
                f"# decoded contains the key\n"
                f"# {inner}"
            ),
            "expected_detector": "aws_access_key",
            "is_positive": True,
        })

    # 10. GitHub token in GitHub Actions YAML step
    for _ in range(12):
        tok = gen_github_token()
        corpus.append({
            "text": (
                f"- name: Deploy\n"
                f"  env:\n"
                f"    GITHUB_TOKEN: \"{tok}\"\n"
                f"  run: |\n"
                f"    gh release upload $TAG ./dist/*.tar.gz\n"
            ),
            "expected_detector": "github_token",
            "is_positive": True,
        })

    # 11. JWT in curl command
    for _ in range(10):
        corpus.append({
            "text": (
                f"curl -H 'Authorization: Bearer {gen_jwt()}' "
                f"https://api.internal/v2/datasets"
            ),
            "expected_detector": "jwt",
            "is_positive": True,
        })

    # 12. DB connection in multi-line .env
    for _ in range(10):
        corpus.append({
            "text": (
                f"# Database\n"
                f"DATABASE_URL={gen_db_conn()}\n"
                f"DB_POOL_SIZE=10\n"
                f"DB_IDLE_TIMEOUT=300\n"
            ),
            "expected_detector": "db_connection_string",
            "is_positive": True,
        })

    # 13. Private key header/footer in PEM block
    for _ in range(10):
        corpus.append({
            "text": (
                "-----BEGIN EC PRIVATE KEY-----\n"
                "MHQCAQEEIBq7synthetic0000keyOnlyForDemoNotRealNotRealDoNotUse\n"
                "-----END EC PRIVATE KEY-----\n"
            ),
            "expected_detector": "private_key",
            "is_positive": True,
        })

    # 14. Generic high-entropy secret — mixed-case key
    for _ in range(12):
        secret_kw = random.choice(["Api_Key", "CLIENT_SECRET", "Auth_Token", "API_SECRET"])
        tok = gen_entropy_secret()
        corpus.append({
            "text": (
                f"[config]\n"
                f"{secret_kw} = {tok}\n"
                f"region = ap-south-1\n"
            ),
            "expected_detector": "generic_high_entropy_secret",
            "is_positive": True,
        })

    # ------------------------------------------------------------------
    # HARD NEGATIVES
    # ------------------------------------------------------------------

    # N1. Git SHA commits -- look like hex secrets but NOT credentials
    # NOTE: We do NOT include email addresses here — that would correctly fire the email
    # detector. These negatives only test that a hex hash alone doesn't trigger any rule.
    for _ in range(20):
        corpus.append({
            "text": (
                f"git log: commit {gen_git_sha()} "
                f"Author: {fake.name()} "
                f"Date: Mon Oct 14 09:12:33 2026 +0530"
            ),
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "git_sha_commit",
        })

    # N2. SHA-256 artifact hashes in CI logs
    for _ in range(20):
        corpus.append({
            "text": (
                f"Artifact checksum verified sha256:{gen_hex_hash()} "
                f"for release package vaultsight-{gen_semver()}.tar.gz"
            ),
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "sha256_artifact_hash",
        })

    # N3. UUIDs — random-looking but not secrets
    for _ in range(20):
        corpus.append({
            "text": (
                f"Request trace_id={gen_uuid4()} "
                f"correlation_id={gen_uuid4()} completed in {random.randint(1, 300)}ms"
            ),
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "uuids",
        })

    # N4. Semantic version strings
    for _ in range(15):
        ver = gen_semver()
        corpus.append({
            "text": (
                f"Dependency update: upgrading vaultsight-core from {ver} "
                f"to {gen_semver()} — see changelog at https://github.com/org/repo"
            ),
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "semver_strings",
        })

    # N5. Invoice / order tracking IDs — long numeric strings
    for _ in range(20):
        inv = gen_invoice_id()
        track = f"TRK{random.randint(100000000000, 999999999999)}"
        corpus.append({
            "text": (
                f"Order {inv} dispatched via {random.choice(['DTDC', 'BlueDart', 'FedEx'])} "
                f"tracking number {track}."
            ),
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "invoice_order_ids",
        })

    # N6. Docker image digests — look like credentials but are public artifact IDs
    for _ in range(15):
        corpus.append({
            "text": (
                f"Pulling image docker.io/vaultsight/scanner@{gen_docker_digest()} "
                f"Status: Image is up to date"
            ),
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "docker_image_digests",
        })

    # N7. AWS documentation example placeholder (should be allowlisted)
    for _ in range(15):
        corpus.append({
            "text": (
                "In the AWS docs tutorial: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE "
                "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            ),
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "documentation_example",
        })

    # N8. Luhn-invalid card number (15-digit so it won't match 16-digit credit card regex)
    for _ in range(15):
        corpus.append({
            "text": (
                f"Transaction declined for card ending {gen_luhn_invalid_card()} - invalid card format."
            ),
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "luhn_invalid_card",
        })

    # N9. Invalid Aadhaar (Verhoeff checksum fails)
    for _ in range(20):
        corpus.append({
            "text": (
                f"Barcode scan reference: {gen_invalid_aadhaar()} — retry required."
            ),
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "invalid_aadhaar_verhoeff",
        })

    # N10. High-entropy string WITHOUT any secret keyword — must NOT fire
    for _ in range(20):
        corpus.append({
            "text": gen_high_entropy_no_keyword(),
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "high_entropy_no_keyword",
        })

    # N11. US toll-free / landline numbers — should NOT match Indian mobile
    for _ in range(15):
        corpus.append({
            "text": (
                f"Call US support at +1-800-555-{random.randint(1000, 9999)} "
                f"or UK helpdesk +44-20-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}."
            ),
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "us_uk_phone_numbers",
        })

    # N12. IP addresses — numeric strings that look like data but aren't secrets
    for _ in range(15):
        ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        corpus.append({
            "text": (
                f"Connection established from {ip} to internal gateway 192.168.1.1 "
                f"port {random.randint(1024, 65535)}"
            ),
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "ip_addresses",
        })

    # N13. Standard debug/info log lines with numeric IDs
    for _ in range(20):
        corpus.append({
            "text": (
                f"DEBUG [{random.choice(['http', 'db', 'cache', 'auth'])}] "
                f"Request completed id={uuid.uuid4()} "
                f"duration={random.randint(1, 500)}ms "
                f"status={'200 OK' if random.random() > 0.2 else '404 Not Found'}"
            ),
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "standard_log_lines",
        })

    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(corpus, f, indent=2)

    total_pos = sum(1 for s in corpus if s["is_positive"])
    total_neg = sum(1 for s in corpus if not s["is_positive"])
    print(
        f"Generated {len(corpus)} holdout samples (Seed: {SEED}) -- "
        f"{total_pos} positives, {total_neg} negatives -> {output_file}"
    )
    return {"total": len(corpus), "positives": total_pos, "negatives": total_neg, "output_file": output_file}


if __name__ == "__main__":
    generate_holdout_dataset()
