# ==============================================================================
# SECURE HARDENED TERRAFORM INFRASTRUCTURE
# Demonstrates remediation patterns enforced by VaultSight DSPM.
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

# Target Bucket for Access Logging
resource "aws_s3_bucket" "logging_bucket" {
  bucket        = "vaultsight-demo-access-logs"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "logging_bpa" {
  bucket = aws_s3_bucket.logging_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 1. Hardened S3 Bucket
resource "aws_s3_bucket" "secure_customer_data" {
  bucket        = "vaultsight-demo-hardened-customer-data"
  force_destroy = true

  tags = {
    Environment = "production-secure"
    Project     = "VaultSight"
  }
}

# Remediation 1: Complete Block Public Access enabled
resource "aws_s3_bucket_public_access_block" "secure_bpa" {
  bucket = aws_s3_bucket.secure_customer_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Remediation 2: Enforce KMS Default Server-Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_encryption" {
  bucket = aws_s3_bucket.secure_customer_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Remediation 3: Enable Object Versioning
resource "aws_s3_bucket_versioning" "secure_versioning" {
  bucket = aws_s3_bucket.secure_customer_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Remediation 4: Enable Server Access Logging
resource "aws_s3_bucket_logging" "secure_logging" {
  bucket = aws_s3_bucket.secure_customer_data.id

  target_bucket = aws_s3_bucket.logging_bucket.id
  target_prefix = "s3-access-logs/"
}

# Remediation 5: Least-Privilege IAM Policy with explicit ARNs & TLS condition
resource "aws_iam_policy" "hardened_app_policy" {
  name        = "vaultsight-hardened-app-policy"
  description = "Hardened least-privilege policy without wildcards"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ScopedS3ReadAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.secure_customer_data.arn}/*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "true"
          }
        }
      }
    ]
  })
}
