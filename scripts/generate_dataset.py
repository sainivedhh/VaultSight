"""Generate labeled synthetic evaluation corpus (Development Set - Tuned-On) for VaultSight detectors.

Creates:
- Positives for each detector
- Hard negatives (Verhoeff checksum failures, UUIDs, order numbers, random base64 strings, lorem text)
All with a fixed random seed (42).

NOTE: This is the development set against which detector rules were initially developed and tuned.
"""

import json
import random
import base64
import uuid
from pathlib import Path
from faker import Faker

from vaultsight.detectors.checksums import generate_verhoeff_checksum, validate_verhoeff

SEED = 42
random.seed(SEED)
fake = Faker(["en_IN", "en_US"])
Faker.seed(SEED)


def generate_valid_aadhaar() -> str:
    # 12 digits, starting with 2-9
    prefix = str(random.randint(2, 9)) + "".join([str(random.randint(0, 9)) for _ in range(10)])
    checksum = generate_verhoeff_checksum(prefix)
    return f"{prefix}{checksum}"


def generate_invalid_aadhaar() -> str:
    # 12 digits starting with 2-9, but intentionally failing Verhoeff checksum
    prefix = str(random.randint(2, 9)) + "".join([str(random.randint(0, 9)) for _ in range(10)])
    valid_checksum = generate_verhoeff_checksum(prefix)
    # Pick a corrupted digit
    corrupted_checksum = (valid_checksum + random.randint(1, 9)) % 10
    cand = f"{prefix}{corrupted_checksum}"
    # Double check it is indeed invalid
    while validate_verhoeff(cand):
        cand = f"{prefix}{(int(cand[-1]) + 1) % 10}"
    return cand


def generate_valid_pan() -> str:
    letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    fourth = random.choice(["P", "C", "H", "F", "A", "T", "B", "L", "J", "G"])
    prefix = f"{random.choice(letters)}{random.choice(letters)}{random.choice(letters)}{fourth}{random.choice(letters)}"
    digits = f"{random.randint(1000, 9999)}"
    suffix = random.choice(letters)
    return f"{prefix}{digits}{suffix}"


def generate_valid_indian_mobile() -> str:
    first_digit = str(random.choice([6, 7, 8, 9]))
    rest = "".join([str(random.randint(0, 9)) for _ in range(9)])
    prefix = random.choice(["+91 ", "+91-", ""])
    return f"{prefix}{first_digit}{rest}"


def generate_valid_credit_card() -> str:
    # Visa prefix 4 + 14 digits + Luhn check digit
    prefix = "4" + "".join([str(random.randint(0, 9)) for _ in range(14)])
    # Calculate Luhn checksum digit
    clean_digits = [int(d) for d in prefix]
    total = 0
    # The check digit will be at index 0 in reverse (index 15, which is even in 0-indexed reverse)
    # The prefix digits will be shifted by 1 in reverse: index 1, 2, ...
    for idx, digit in enumerate(clean_digits[::-1]):
        if idx % 2 == 0:  # corresponds to odd index in 16-digit card
            doubled = digit * 2
            total += doubled if doubled < 10 else (doubled - 9)
        else:
            total += digit
    check_digit = (10 - (total % 10)) % 10
    return f"{prefix}{check_digit}"


def generate_valid_aws_key() -> str:
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    suffix = "".join(random.choice(chars) for _ in range(16))
    return f"AKIA{suffix}"


def generate_valid_github_token() -> str:
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
    suffix = "".join(random.choice(chars) for _ in range(36))
    return f"ghp_{suffix}"


def generate_valid_jwt() -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b'{"sub":"user123","role":"analyst"}').decode().rstrip("=")
    sig = base64.urlsafe_b64encode(uuid.uuid4().bytes * 2).decode().rstrip("=")
    return f"{header}.{payload}.{sig}"


def generate_valid_db_conn() -> str:
    user = fake.user_name()
    pwd = "".join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$") for _ in range(16))
    host = fake.domain_name()
    return f"postgres://{user}:{pwd}@{host}:5432/appdb"


def generate_valid_private_key() -> str:
    return "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0syntheticKey\n-----END RSA PRIVATE KEY-----"


def generate_dataset(output_file: str = "data/evaluation_corpus.json") -> dict:
    corpus = []

    # 1. POSITIVES FOR EACH DETECTOR (15 samples each = 150 samples)
    generators = [
        ("aadhaar", lambda: f"User KYC Aadhaar identification document number: {generate_valid_aadhaar()}"),
        ("pan", lambda: f"Customer tax filing PAN card reference: {generate_valid_pan()} submitted to IT Dept"),
        ("indian_mobile", lambda: f"Emergency contact mobile phone number: {generate_valid_indian_mobile()}"),
        ("email", lambda: f"Primary employee notification email address is {fake.email()}"),
        ("credit_card", lambda: f"Payment billing card account: {generate_valid_credit_card()} cvv: 912"),
        ("aws_access_key", lambda: f"AWS cloud credentials key id: {generate_valid_aws_key()}"),
        ("github_token", lambda: f"CI automation token: {generate_valid_github_token()} for repo access"),
        ("jwt", lambda: f"Authorization: Bearer {generate_valid_jwt()} session active"),
        ("db_connection_string", lambda: f"Production database connection dsn: {generate_valid_db_conn()}"),
        ("private_key", lambda: f"SSL certificate TLS bundle:\n{generate_valid_private_key()}\n"),
        ("generic_high_entropy_secret", lambda: f"api_key: \"{base64.b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes).decode()}\""),
    ]

    for det_id, gen_func in generators:
        for _ in range(15):
            corpus.append({
                "text": gen_func(),
                "expected_detector": det_id,
                "is_positive": True,
            })

    # 2. HARD NEGATIVES (100 samples)
    # Negative 1: 12-digit integers failing Verhoeff
    for _ in range(15):
        corpus.append({
            "text": f"Tracking package shipment barcode ID #{generate_invalid_aadhaar()}",
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "invalid_aadhaar_verhoeff"
        })

    # Negative 2: Order IDs and UUIDs
    for _ in range(15):
        corpus.append({
            "text": f"Transaction GUID {uuid.uuid4()} processed order ORD-{random.randint(10000000, 99999999)}",
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "uuid_and_order_id"
        })

    # Negative 3: Random base64 blobs without JWT/secret context
    for _ in range(15):
        blob = base64.b64encode(f"chunk-{random.randint(1000, 9999)}-data".encode()).decode()
        corpus.append({
            "text": f"Base64 image asset thumbnail payload: data:image/png;base64,{blob}== end",
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "generic_base64"
        })

    # Negative 4: Dummy / placeholder strings (allowlisted)
    placeholders = [
        "aws_key: AKIAIOSFODNN7EXAMPLE",
        "github_pat: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "test email: test@example.com",
        "dummy aadhaar: 123456789012",
        "db_url: postgres://user:password@localhost:5432/db",
    ]
    for p in placeholders:
        corpus.append({
            "text": f"Template config example: {p}",
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "allowlisted_placeholder"
        })

    # Negative 5: Normal text / Lorem ipsum / Log lines
    for _ in range(30):
        corpus.append({
            "text": f"INFO 2026-10-15 10:14:22 [system.worker] {fake.sentence(nb_words=12)} status=OK latency=42ms",
            "expected_detector": None,
            "is_positive": False,
            "negative_type": "normal_log_line"
        })

    # Save to disk
    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(corpus, f, indent=2)

    print(f"Generated {len(corpus)} labeled evaluation samples at {output_file}")
    return {"total": len(corpus), "output_file": output_file}


if __name__ == "__main__":
    generate_dataset()
