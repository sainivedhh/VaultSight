import sqlite3
import pytest
import boto3
from moto import mock_aws

from vaultsight.connectors import LocalFilesystemConnector, SQLiteConnector, S3Connector, PathTraversalError
from vaultsight.posture import S3PostureAnalyzer, IAMPolicyAnalyzer
from vaultsight.risk import RiskScoringEngine, RiskLevel
from vaultsight.detectors.models import Finding, DetectorCategory


def test_local_filesystem_connector_path_traversal(tmp_path):
    safe_root = tmp_path / "safe_root"
    safe_root.mkdir()
    secret_file = safe_root / "confidential.txt"
    secret_file.write_text("Hello secure data")

    connector = LocalFilesystemConnector(str(safe_root))

    # Legitimate read
    files = list(connector.read_files())
    assert len(files) == 1
    assert files[0][0] == "confidential.txt"

    # Attempt path traversal outside safe_root
    with pytest.raises(PathTraversalError):
        connector.safe_resolve("../../etc/passwd")


def test_sqlite_connector(tmp_path):
    db_file = tmp_path / "app.db"
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INT, email TEXT, notes TEXT);")
    cur.execute("INSERT INTO users VALUES (1, 'alice@example.com', 'Admin key backup');")
    conn.commit()
    conn.close()

    connector = SQLiteConnector(str(db_file))
    records = list(connector.read_records())
    assert len(records) == 3  # 3 columns for 1 row
    assert any("alice@example.com" in val for loc, val in records)


@mock_aws
def test_s3_connector_and_posture_analyzer():
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket_name = "test-posture-bucket"
    s3.create_bucket(Bucket=bucket_name)

    # Put a synthetic object
    s3.put_object(Bucket=bucket_name, Key="test.txt", Body=b"sample sensitive line")

    # Verify S3 Connector
    connector = S3Connector(s3)
    objs = list(connector.read_bucket_objects(bucket_name))
    assert len(objs) == 1
    assert objs[0][0] == f"s3://{bucket_name}/test.txt"

    # Verify S3 Posture Analyzer flags unhardened bucket
    analyzer = S3PostureAnalyzer(s3)
    findings = analyzer.audit_bucket(bucket_name)
    
    check_ids = [f.check_id for f in findings]
    assert "S3-BPA-DISABLED" in check_ids
    assert "S3-NO-DEFAULT-ENCRYPTION" in check_ids
    assert "S3-VERSIONING-DISABLED" in check_ids


def test_iam_policy_analyzer():
    analyzer = IAMPolicyAnalyzer()
    
    # Insecure policy with Admin wildcard and privilege escalation
    bad_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["*"],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey"],
                "Resource": "*"
            }
        ]
    }

    findings = analyzer.analyze_policy_doc("BadAdminPolicy", bad_policy)
    check_ids = [f.check_id for f in findings]
    assert "IAM-ADMIN-WILDCARD" in check_ids
    assert "IAM-PRIVILEGE-ESCALATION" in check_ids


def test_risk_scoring_engine():
    engine = RiskScoringEngine()

    dummy_finding = Finding(
        detector="aws_access_key",
        category=DetectorCategory.CREDENTIAL,
        confidence=0.95,
        location="s3://bucket/creds.env",
        redacted_preview="AK************LE"
    )

    scored = engine.calculate_risk(
        target_id="s3://prod-customer-data",
        findings=[dummy_finding],
        posture_findings=[],
        is_publicly_accessible=True,
        access_grant_count=100
    )

    assert scored.risk_score >= 65.0
    assert scored.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]
    assert len(scored.remediation_steps) > 0
