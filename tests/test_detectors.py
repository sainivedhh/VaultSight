from vaultsight.detectors.checksums import validate_verhoeff, generate_verhoeff_checksum, validate_luhn
from vaultsight.detectors.entropy import calculate_shannon_entropy
from vaultsight.detectors.redact import redact_secret
from vaultsight.detectors.engine import DetectionEngine


def test_verhoeff_algorithm():
    # Valid Aadhaar 12-digit number generation & validation
    prefix_11 = "21839485721"
    check_digit = generate_verhoeff_checksum(prefix_11)
    full_aadhaar = f"{prefix_11}{check_digit}"
    assert len(full_aadhaar) == 12
    assert validate_verhoeff(full_aadhaar) is True

    # Mutating a single digit must fail checksum
    corrupted = full_aadhaar[:-1] + str((check_digit + 1) % 10)
    assert validate_verhoeff(corrupted) is False

    # Transposition error (swapping two adjacent digits) must fail
    transposed = full_aadhaar[:3] + full_aadhaar[4] + full_aadhaar[3] + full_aadhaar[5:]
    assert validate_verhoeff(transposed) is False


def test_luhn_algorithm():
    # Test valid Visa prefix
    assert validate_luhn("4532015112830366") is True
    # Mutated digit should fail
    assert validate_luhn("4532015112830367") is False


def test_entropy_calculation():
    # High entropy random string
    high_ent = "k9#Jp$82mL!vN9@xQ1*z"
    low_ent = "aaaaaaaaaaaaaaaaaaaa"
    assert calculate_shannon_entropy(high_ent) > 3.8
    assert calculate_shannon_entropy(low_ent) == 0.0


def test_redaction():
    assert redact_secret("AKIAIOSFODNN7EXAMPLE") == "AK************LE"
    assert redact_secret("short") == "s***t"
    assert redact_secret("abc") == "***"


def test_engine_detects_aadhaar_with_verhoeff():
    engine = DetectionEngine()
    prefix = "36918274619"
    aadhaar = f"{prefix}{generate_verhoeff_checksum(prefix)}"
    
    text = f"Customer UID Aadhaar number is {aadhaar} for KYC."
    findings = engine.scan_text(text)
    
    assert any(f.detector == "aadhaar" for f in findings)
    aadhaar_finding = next(f for f in findings if f.detector == "aadhaar")
    assert aadhaar_finding.confidence >= 0.90
    assert "36" in aadhaar_finding.redacted_preview


def test_engine_rejects_invalid_aadhaar_checksum():
    engine = DetectionEngine()
    # Random 12 digits that fail Verhoeff
    invalid_aadhaar = "369182746190"
    if validate_verhoeff(invalid_aadhaar):
        invalid_aadhaar = "369182746191"
    
    text = f"Reference order ID: {invalid_aadhaar}"
    findings = engine.scan_text(text)
    assert not any(f.detector == "aadhaar" for f in findings)


def test_engine_detects_credentials():
    engine = DetectionEngine()
    aws_sample = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMP99"
    jwt_sample = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    db_sample = "DATABASE_URL=postgres://app_user:sUp3rS3cr3tP@ssw0rd!@db.internal:5432/production"
    
    findings_aws = engine.scan_text(aws_sample)
    assert any(f.detector == "aws_access_key" for f in findings_aws)
    
    findings_jwt = engine.scan_text(jwt_sample)
    assert any(f.detector == "jwt" for f in findings_jwt)
    
    findings_db = engine.scan_text(db_sample)
    assert any(f.detector == "db_connection_string" for f in findings_db)


def test_allowlist_filtering():
    engine = DetectionEngine()
    dummy_text = "aws_key: AKIAIOSFODNN7EXAMPLE and email: test@example.com"
    findings = engine.scan_text(dummy_text)
    # Allowlisted placeholders should be ignored
    assert not any(f.detector == "aws_access_key" for f in findings)
