"""
S3 / S3-compatible storage connector (AWS S3, MinIO, Wasabi, …).

Config keys:
  bucket       : str   - bucket name (required)
  region       : str   - AWS region (e.g. "us-east-1"); optional for S3-compatible
  endpoint_url : str   - custom endpoint, e.g. "https://minio.example.com"; empty for AWS
  access_key   : str   - AWS access key ID
  secret_key   : str   - AWS secret access key
  prefix       : str   - key prefix to scope the scan (default "")
"""
import logging
from datetime import timezone
from typing import Iterator

import boto3
import botocore.exceptions

from .base import StorageConnector, FileEntry

logger = logging.getLogger(__name__)

_MAX_KEYS_PER_PAGE = 1000


class S3Connector(StorageConnector):
    def __init__(self, config: dict) -> None:
        self._bucket: str = config.get("bucket", "")
        self._prefix: str = config.get("prefix", "")
        self._kwargs = {
            "region_name": config.get("region") or None,
            "aws_access_key_id": config.get("access_key") or None,
            "aws_secret_access_key": config.get("secret_key") or None,
        }
        endpoint = config.get("endpoint_url", "").strip()
        if endpoint:
            self._kwargs["endpoint_url"] = endpoint

    def _client(self):
        return boto3.client("s3", **self._kwargs)

    def test_connection(self) -> dict:
        try:
            client = self._client()
            client.head_bucket(Bucket=self._bucket)
            return {"ok": True, "message": f"Connected to bucket '{self._bucket}'"}
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            return {"ok": False, "message": f"S3 error ({code}): {exc}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    def list_files(
        self,
        path: str = "",
        recursive: bool = True,
        max_files: int = 100_000,
    ) -> Iterator[FileEntry]:
        prefix = (self._prefix + path).lstrip("/")
        client = self._client()
        paginator = client.get_paginator("list_objects_v2")
        kwargs: dict = {"Bucket": self._bucket, "Prefix": prefix}
        if not recursive:
            kwargs["Delimiter"] = "/"
        count = 0
        for page in paginator.paginate(**kwargs):
            for obj in page.get("Contents", []):
                key: str = obj["Key"]
                if key.endswith("/"):
                    continue  # skip "directory" entries
                mtime = obj.get("LastModified")
                if mtime and mtime.tzinfo is not None:
                    mtime = mtime.astimezone(timezone.utc).replace(tzinfo=None)
                yield FileEntry(
                    path=key,
                    size=obj.get("Size", 0),
                    mtime=mtime,
                    etag=(obj.get("ETag") or "").strip('"'),
                )
                count += 1
                if count >= max_files:
                    return

    def get_file_bytes(self, file_path: str, max_bytes: int = 50 * 1024 * 1024) -> bytes:
        client = self._client()
        response = client.get_object(Bucket=self._bucket, Key=file_path, Range=f"bytes=0-{max_bytes - 1}")
        return response["Body"].read()

    def get_metadata(self, file_path: str) -> FileEntry:
        client = self._client()
        try:
            obj = client.head_object(Bucket=self._bucket, Key=file_path)
            mtime = obj.get("LastModified")
            if mtime and mtime.tzinfo is not None:
                mtime = mtime.astimezone(timezone.utc).replace(tzinfo=None)
            return FileEntry(
                path=file_path,
                size=obj.get("ContentLength", 0),
                mtime=mtime,
                etag=(obj.get("ETag") or "").strip('"'),
                content_type=obj.get("ContentType", ""),
            )
        except botocore.exceptions.ClientError as exc:
            raise FileNotFoundError(file_path) from exc
