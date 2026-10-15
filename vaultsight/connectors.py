"""Data store connectors for VaultSight DSPM.

Connectors:
1. Local Filesystem Connector (with strict path-traversal prevention)
2. SQLite Database Connector (schema, table, and row extraction)
3. AWS S3 Connector (using boto3 against moto mock / simulated buckets)
"""

import os
import sqlite3
from pathlib import Path
from typing import Generator, Tuple
import boto3
from botocore.exceptions import ClientError


class PathTraversalError(PermissionError):
    """Raised when an attempted path escapes the authorized scan root."""
    pass


class LocalFilesystemConnector:
    """Connects to and scans local directories with rigorous path-traversal defenses."""

    def __init__(self, base_directory: str):
        self.base_dir = Path(base_directory).resolve()
        if not self.base_dir.exists() or not self.base_dir.is_dir():
            raise ValueError(f"Base directory does not exist or is not a directory: {base_directory}")

    def safe_resolve(self, subpath: str) -> Path:
        """Resolve subpath and assert it cannot escape the base directory (path traversal defense)."""
        target = (self.base_dir / subpath).resolve()
        try:
            target.relative_to(self.base_dir)
        except ValueError:
            raise PathTraversalError(f"Access denied: Path traversal attempted outside root: {subpath}")
        return target

    def read_files(self, subpath: str = "") -> Generator[Tuple[str, str], None, None]:
        """Yields (relative_path, content_text) for text files within safe boundaries."""
        target_dir = self.safe_resolve(subpath)
        
        for root, _, files in os.walk(target_dir):
            for file_name in files:
                full_path = Path(root) / file_name
                # Ensure resolved file path is still within base_dir
                try:
                    full_path.resolve().relative_to(self.base_dir)
                except ValueError:
                    continue

                # Skip binary/executable extensions
                if full_path.suffix.lower() in [".exe", ".dll", ".so", ".bin", ".pyc"]:
                    continue

                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    rel_path = str(full_path.relative_to(self.base_dir)).replace("\\", "/")
                    yield rel_path, content
                except Exception:
                    continue


class SQLiteConnector:
    """Connects to SQLite database and extracts text from tables and columns."""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path).resolve()
        if not self.db_path.exists():
            raise ValueError(f"SQLite database file not found: {db_path}")

    def read_records(self) -> Generator[Tuple[str, str], None, None]:
        """Yields (table_col_location, text_content) across all user tables."""
        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
            tables = [row[0] for row in cursor.fetchall()]

            for tbl in tables:
                # Security: assert tbl contains only alphanumeric or underscore table names from sqlite_master
                if not tbl.replace("_", "").isalnum():
                    continue
                cursor.execute(f"PRAGMA table_info('{tbl}');")  # nosec B608
                columns = [c[1] for c in cursor.fetchall()]

                cursor.execute(f"SELECT * FROM \"{tbl}\" LIMIT 500;")  # nosec B608
                rows = cursor.fetchall()
                for row_idx, row in enumerate(rows):
                    for col_idx, col_name in enumerate(columns):
                        val = row[col_idx]
                        if val is not None:
                            val_str = str(val)
                            loc = f"sqlite:{self.db_path.name}/{tbl}#{col_name}:row{row_idx+1}"
                            yield loc, val_str
        finally:
            conn.close()


class S3Connector:
    """Connects to simulated AWS S3 buckets (moto or local mock)."""

    def __init__(self, s3_client=None, region: str = "us-east-1"):
        if s3_client is None:
            self.s3_client = boto3.client("s3", region_name=region)
        else:
            self.s3_client = s3_client

    def list_buckets(self) -> list:
        resp = self.s3_client.list_buckets()
        return [b["Name"] for b in resp.get("Buckets", [])]

    def read_bucket_objects(self, bucket_name: str) -> Generator[Tuple[str, str], None, None]:
        """Yields (s3_uri, object_content) for objects stored in the bucket."""
        try:
            paginator = self.s3_client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket_name):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    resp = self.s3_client.get_object(Bucket=bucket_name, Key=key)
                    body_bytes = resp["Body"].read()
                    try:
                        content = body_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        content = body_bytes.decode("utf-8", errors="ignore")
                    
                    yield f"s3://{bucket_name}/{key}", content
        except ClientError:
            return
