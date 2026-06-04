"""
Local filesystem storage connector.

Config keys:
  base_path  : str   - local directory to scan
"""
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .base import FileEntry, StorageConnector


class LocalFSConnector(StorageConnector):
    def __init__(self, config: dict) -> None:
        self._base_path = Path(config.get("base_path") or ".").expanduser().resolve()

    def _resolve(self, file_path: str) -> Path:
        target = (self._base_path / file_path).resolve()
        try:
            target.relative_to(self._base_path)
        except ValueError as exc:
            raise FileNotFoundError(file_path) from exc
        return target

    def test_connection(self) -> dict:
        if not self._base_path.exists():
            return {"ok": False, "message": f"Path does not exist: {self._base_path}"}
        if not self._base_path.is_dir():
            return {"ok": False, "message": f"Path is not a directory: {self._base_path}"}
        return {"ok": True, "message": f"Connected to local path '{self._base_path}'"}

    def list_files(
        self,
        path: str = "",
        recursive: bool = True,
        max_files: int = 100_000,
    ) -> Iterator[FileEntry]:
        root = self._resolve(path or ".")
        if not root.exists():
            return
        iterator = root.rglob("*") if recursive else root.glob("*")
        count = 0
        for entry in iterator:
            if not entry.is_file():
                continue
            stat = entry.stat()
            yield FileEntry(
                path=entry.relative_to(self._base_path).as_posix(),
                size=stat.st_size,
                mtime=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).replace(tzinfo=None),
            )
            count += 1
            if count >= max_files:
                return

    def get_file_bytes(self, file_path: str, max_bytes: int = 50 * 1024 * 1024) -> bytes:
        path = self._resolve(file_path)
        with open(path, "rb") as fh:
            return fh.read(max_bytes)
