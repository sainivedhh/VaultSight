"""Cloud security posture checks for AWS S3 buckets and IAM policies.

Evaluates:
- S3 Bucket Public ACL
- S3 Bucket Policy (Principal "*")
- S3 Block Public Access status
- S3 Default Encryption missing
- S3 Server Access Logging missing
- S3 Versioning disabled
- IAM policy wildcard actions ("*") / privilege escalation paths
"""

import json
from enum import Enum
from typing import List, Dict, Any
from pydantic import BaseModel
from botocore.exceptions import ClientError


class PostureSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PostureFinding(BaseModel):
    """Represents a cloud infrastructure misconfiguration finding."""
    check_id: str
    resource_id: str
    resource_type: str  # "S3_BUCKET" | "IAM_POLICY"
    severity: PostureSeverity
    title: str
    description: str
    remediation: str


class S3PostureAnalyzer:
    """Evaluates posture and misconfigurations of S3 buckets."""

    def __init__(self, s3_client):
        self.s3_client = s3_client

    def audit_bucket(self, bucket_name: str) -> List[PostureFinding]:
        findings: List[PostureFinding] = []

        # 1. Check Block Public Access Configuration
        bpa_blocked = False
        try:
            pab = self.s3_client.get_public_access_block(Bucket=bucket_name)
            cfg = pab.get("PublicAccessBlockConfiguration", {})
            if (
                cfg.get("BlockPublicAcls")
                and cfg.get("IgnorePublicAcls")
                and cfg.get("BlockPublicPolicy")
                and cfg.get("RestrictPublicBuckets")
            ):
                bpa_blocked = True
        except ClientError:
            bpa_blocked = False

        if not bpa_blocked:
            findings.append(
                PostureFinding(
                    check_id="S3-BPA-DISABLED",
                    resource_id=bucket_name,
                    resource_type="S3_BUCKET",
                    severity=PostureSeverity.HIGH,
                    title="S3 Block Public Access Disabled",
                    description=f"Bucket '{bucket_name}' does not have all 4 Block Public Access settings enabled.",
                    remediation="Enable S3 PublicAccessBlockConfiguration with BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets set to True."
                )
            )

        # 2. Check Public ACL
        try:
            acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    findings.append(
                        PostureFinding(
                            check_id="S3-PUBLIC-ACL",
                            resource_id=bucket_name,
                            resource_type="S3_BUCKET",
                            severity=PostureSeverity.CRITICAL,
                            title="S3 Bucket Has Public ACL Grant",
                            description=f"Bucket '{bucket_name}' grants permissions to {grantee.get('URI')}.",
                            remediation="Remove public grants from Bucket ACL and enforce bucket owner enforced object ownership."
                        )
                    )
                    break
        except ClientError:
            pass

        # 3. Check Public Bucket Policy
        try:
            pol_resp = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(pol_resp.get("Policy", "{}"))
            statements = policy_doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                if stmt.get("Effect") == "Allow":
                    principal = stmt.get("Principal")
                    if principal == "*" or principal == {"AWS": "*"}:
                        findings.append(
                            PostureFinding(
                                check_id="S3-PUBLIC-POLICY",
                                resource_id=bucket_name,
                                resource_type="S3_BUCKET",
                                severity=PostureSeverity.CRITICAL,
                                title="S3 Bucket Policy Allows Public Access",
                                description=f"Bucket '{bucket_name}' policy contains statement allowing Effect=Allow for Principal='*'.",
                                remediation="Restrict statement Principal to specific IAM ARNs or delete open access policy statements."
                            )
                        )
                        break
        except ClientError:
            pass

        # 4. Check Default Encryption
        try:
            self.s3_client.get_bucket_encryption(Bucket=bucket_name)
        except ClientError:
            # ServerSideEncryptionConfigurationNotFoundError
            findings.append(
                PostureFinding(
                    check_id="S3-NO-DEFAULT-ENCRYPTION",
                    resource_id=bucket_name,
                    resource_type="S3_BUCKET",
                    severity=PostureSeverity.MEDIUM,
                    title="S3 Bucket Lacks Default Encryption",
                    description=f"Bucket '{bucket_name}' does not have AWS server-side default encryption configured.",
                    remediation="Enable SSE-S3 (AES256) or SSE-KMS default encryption on the bucket."
                )
            )

        # 5. Check Server Access Logging
        try:
            log_resp = self.s3_client.get_bucket_logging(Bucket=bucket_name)
            if "LoggingEnabled" not in log_resp:
                findings.append(
                    PostureFinding(
                        check_id="S3-LOGGING-DISABLED",
                        resource_id=bucket_name,
                        resource_type="S3_BUCKET",
                        severity=PostureSeverity.LOW,
                        title="S3 Server Access Logging Disabled",
                        description=f"Bucket '{bucket_name}' does not send server access logs to a target log bucket.",
                        remediation="Configure ServerAccessLogging to record bucket read/write audit trails."
                    )
                )
        except ClientError:
            pass

        # 6. Check Versioning
        try:
            ver_resp = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            if ver_resp.get("Status") != "Enabled":
                findings.append(
                    PostureFinding(
                        check_id="S3-VERSIONING-DISABLED",
                        resource_id=bucket_name,
                        resource_type="S3_BUCKET",
                        severity=PostureSeverity.LOW,
                        title="S3 Object Versioning Disabled",
                        description=f"Bucket '{bucket_name}' has versioning status Suspended or Disabled.",
                        remediation="Enable S3 bucket versioning to protect against accidental object overwrite or ransomware deletion."
                    )
                )
        except ClientError:
            pass

        return findings


class IAMPolicyAnalyzer:
    """Analyzes IAM policy JSON documents for privilege escalation and overly permissive access."""

    PRIV_ESC_ACTIONS = {
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:PassRole",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutGroupPolicy",
        "iam:PutRolePolicy",
        "sts:AssumeRole",
    }

    def analyze_policy_doc(self, policy_name: str, policy_doc: Dict[str, Any]) -> List[PostureFinding]:
        findings: List[PostureFinding] = []
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for idx, stmt in enumerate(statements):
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            conditions = stmt.get("Condition")

            # 1. Wildcard Action & Resource (Admin Equivalent)
            if "*" in actions and "*" in resources:
                findings.append(
                    PostureFinding(
                        check_id="IAM-ADMIN-WILDCARD",
                        resource_id=policy_name,
                        resource_type="IAM_POLICY",
                        severity=PostureSeverity.CRITICAL,
                        title="IAM Policy Grants Full Admin Wildcard (*:*)",
                        description=f"Statement {idx+1} in policy '{policy_name}' allows Action='*' on Resource='*'.",
                        remediation="Follow principle of least privilege: scope actions to exact API methods and specific resource ARNs."
                    )
                )

            # 2. Overly Permissive Actions on All Resources
            elif any(act.endswith(":*") or act == "*" for act in actions) and "*" in resources:
                findings.append(
                    PostureFinding(
                        check_id="IAM-BROAD-SERVICE-WILDCARD",
                        resource_id=policy_name,
                        resource_type="IAM_POLICY",
                        severity=PostureSeverity.HIGH,
                        title="Overly Broad Service Wildcard on Resource='*'",
                        description=f"Statement {idx+1} permits broad wildcards ({actions}) across all cloud resources.",
                        remediation="Explicitly enumerate required action methods and bind them to specific resource ARNs."
                    )
                )

            # 3. Privilege Escalation Methods
            matching_priv_esc = [act for act in actions if act in self.PRIV_ESC_ACTIONS]
            if matching_priv_esc and "*" in resources:
                findings.append(
                    PostureFinding(
                        check_id="IAM-PRIVILEGE-ESCALATION",
                        resource_id=policy_name,
                        resource_type="IAM_POLICY",
                        severity=PostureSeverity.CRITICAL,
                        title="IAM Privilege Escalation Vulnerability",
                        description=f"Statement {idx+1} grants dangerous privilege escalation actions: {matching_priv_esc}.",
                        remediation="Restrict IAM modification permissions to administrative break-glass roles with strict MFA."
                    )
                )

            # 4. Sensitive Actions Missing Conditions
            if ("s3:GetObject" in actions or "s3:*" in actions) and not conditions:
                findings.append(
                    PostureFinding(
                        check_id="IAM-MISSING-CONDITIONS",
                        resource_id=policy_name,
                        resource_type="IAM_POLICY",
                        severity=PostureSeverity.MEDIUM,
                        title="Sensitive Data Access Lacks Condition Constraints",
                        description=f"Statement {idx+1} grants S3 read access without MFA, IP restriction, or SecureTransport conditions.",
                        remediation="Enforce conditions such as 'aws:SecureTransport': 'true' or 'aws:SourceIp'."
                    )
                )

        return findings
