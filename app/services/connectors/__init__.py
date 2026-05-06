"""
Storage connector package for External Storage Sources.
"""
from .base import StorageConnector, FileEntry
from .s3_connector import S3Connector
from .sftp_connector import SFTPConnector
from .webdav_connector import WebDAVConnector

__all__ = [
    "StorageConnector",
    "FileEntry",
    "S3Connector",
    "SFTPConnector",
    "WebDAVConnector",
    "get_connector",
]


def get_connector(source_type: str, config: dict) -> "StorageConnector":
    """Return the appropriate connector instance for the given source type."""
    source_type = source_type.lower()
    if source_type == "s3":
        return S3Connector(config)
    if source_type == "sftp":
        return SFTPConnector(config)
    if source_type == "webdav":
        return WebDAVConnector(config)
    raise ValueError(f"Unknown storage source type: {source_type!r}")
