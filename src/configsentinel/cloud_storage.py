"""S3-compatible blob storage adapter for durable evidence persistence.

This module provides an adapter to securely store configuration files,
audit JSON artifacts, and generated PDFs in a cloud blob store.
"""

from __future__ import annotations

import json
import os
from typing import Any

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


class StorageError(Exception):
    """Base exception for storage adapter failures."""


class S3StorageAdapter:
    """Adapter for S3-compatible object storage."""
    
    def __init__(
        self,
        bucket_name: str | None = None,
        endpoint_url: str | None = None,
        region_name: str | None = None,
    ) -> None:
        """Initialize the S3 storage adapter.
        
        Args:
            bucket_name: Target bucket (defaults to CONFIGSENTINEL_S3_BUCKET)
            endpoint_url: Optional custom endpoint (for MinIO, R2, etc.)
            region_name: Optional explicit region
        """
        self.bucket_name = bucket_name or os.getenv("CONFIGSENTINEL_S3_BUCKET", "configsentinel-evidence")
        self.endpoint_url = endpoint_url or os.getenv("CONFIGSENTINEL_S3_ENDPOINT")
        self.region_name = region_name or os.getenv("CONFIGSENTINEL_S3_REGION", "us-east-1")
        
        if not BOTO3_AVAILABLE:
            raise StorageError("boto3 is not installed. Run pip install -e '.[enterprise]'")
            
        self.client = boto3.client(
            "s3",
            endpoint_url=self.endpoint_url,
            region_name=self.region_name,
        )

    def upload_artifact(self, artifact_id: str, data: bytes, content_type: str = "application/json") -> str:
        """Upload raw artifact data.
        
        Args:
            artifact_id: Unique identifier for the object
            data: Raw bytes to upload
            content_type: MIME type of the payload
            
        Returns:
            The key used in the bucket
        """
        key = f"artifacts/{artifact_id}"
        try:
            self.client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=data,
                ContentType=content_type,
                ServerSideEncryption="AES256"
            )
            return key
        except ClientError as e:
            raise StorageError(f"Failed to upload artifact {artifact_id}: {e}") from e

    def download_artifact(self, key: str) -> bytes:
        """Download artifact data by key.
        
        Args:
            key: The S3 object key
            
        Returns:
            The raw bytes of the object
        """
        try:
            response = self.client.get_object(Bucket=self.bucket_name, Key=key)
            return response["Body"].read()
        except ClientError as e:
            raise StorageError(f"Failed to download artifact {key}: {e}") from e

    def upload_report_json(self, report_id: str, report_data: dict[str, Any]) -> str:
        """Upload a structured audit report as JSON.
        
        Args:
            report_id: Unique identifier for the report
            report_data: The JSON-serializable report dictionary
            
        Returns:
            The key used in the bucket
        """
        data = json.dumps(report_data, sort_keys=True).encode("utf-8")
        return self.upload_artifact(
            artifact_id=f"{report_id}.json",
            data=data,
            content_type="application/json"
        )
