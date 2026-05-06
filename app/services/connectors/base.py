"""
Base interface for all storage connectors.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Optional


@dataclass
class FileEntry:
    """Metadata for a single file discovered during listing."""
    path: str                             # remote key / path
    size: int = 0
    mtime: Optional[datetime] = None
    etag: str = ""                        # ETag or hash if available
    content_type: str = ""


class StorageConnector(ABC):
    """Abstract connector for an external storage backend."""

    @abstractmethod
    def test_connection(self) -> dict:
        """
        Verify that the configured credentials and endpoint are reachable.

        Returns a dict with at least:
          {"ok": bool, "message": str}
        Must never raise; catch all errors and return ok=False.
        """

    @abstractmethod
    def list_files(
        self,
        path: str = "",
        recursive: bool = True,
        max_files: int = 100_000,
    ) -> Iterator[FileEntry]:
        """
        Yield FileEntry objects for every file found at *path*.

        :param path:       root prefix / directory to scan
        :param recursive:  recurse into subdirectories
        :param max_files:  hard limit on number of items yielded
        """

    @abstractmethod
    def get_file_bytes(self, file_path: str, max_bytes: int = 50 * 1024 * 1024) -> bytes:
        """
        Download *file_path* and return its raw bytes.

        :param max_bytes: maximum number of bytes to read (safety limit)
        """

    def get_metadata(self, file_path: str) -> FileEntry:
        """
        Return metadata for a single file.
        Default implementation lists the parent directory and filters by path.
        Override for more efficient single-object lookup.
        """
        parent = "/".join(file_path.rstrip("/").split("/")[:-1])
        for entry in self.list_files(parent, recursive=False):
            if entry.path == file_path:
                return entry
        raise FileNotFoundError(file_path)
