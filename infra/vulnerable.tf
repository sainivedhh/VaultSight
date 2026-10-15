# ==============================================================================
# DEMO ONLY - INTENTIONALLY INSECURE TERRAFORM INFRASTRUCTURE
# DO NOT RUN OR DEPLOY TO REAL AWS ACCOUNTS.
# Demonstrates common S3 & IAM misconfigurations detected by VaultSight.
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
}

# 1. Insecure S3 Bucket: Public ACL, No BPA, No Encryption, No Versioning, No Logging
resource "aws_s3_bucket" "vulnerable_customer_data" {
  bucket        = "vaultsight-demo-vulnerable-bucket-public"
  force_destroy = true

  tags = {
    Environment = "demo-insecure"
    Project     = "VaultSight"
  }
}

# Misconfiguration: Public ACL grant
resource "aws_s3_bucket_acl" "vulnerable_acl" {
  bucket = aws_s3_bucket.vulnerable_customer_data.id
  acl    = "public-read"
}

# Misconfiguration: Open Bucket Policy with Principal="*"
resource "aws_s3_bucket_policy" "vulnerable_policy" {
  bucket = aws_s3_bucket.vulnerable_customer_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicAnonymousAccess"
        Effect    = "Allow"
        Principal = "*"
        Action    = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.vulnerable_customer_data.arn,
          "${aws_s3_bucket.vulnerable_customer_data.arn}/*"
        ]
      }
    ]
  })
}

# Misconfiguration: Overly permissive IAM Policy with full Admin Wildcards and Privilege Escalation
resource "aws_iam_policy" "vulnerable_app_policy" {
  name        = "vaultsight-insecure-app-policy"
  description = "Intentionally insecure IAM policy with wildcard access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WildcardAdminAndPrivEsc"
        Effect = "Allow"
        Action = [
          "s3:*",
          "iam:CreateAccessKey",
          "iam:AttachUserPolicy"
        ]
        Resource = "*"
      }
    ]
  })
}
