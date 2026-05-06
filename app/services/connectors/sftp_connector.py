"""
SFTP storage connector (SSH File Transfer Protocol).

Config keys:
  host         : str   - hostname or IP
  port         : int   - port (default 22)
  username     : str   - SSH username
  auth_type    : str   - "password" | "key"  (default "password")
  password     : str   - password (used when auth_type == "password")
  private_key  : str   - PEM private key string (used when auth_type == "key")
  base_path    : str   - remote base directory (default "/")
"""
import io
import logging
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

import paramiko

from .base import StorageConnector, FileEntry

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 15   # seconds


class SFTPConnector(StorageConnector):
    def __init__(self, config: dict) -> None:
        self._host: str = config.get("host", "")
        self._port: int = int(config.get("port") or 22)
        self._username: str = config.get("username", "")
        self._auth_type: str = config.get("auth_type", "password")
        self._password: str = config.get("password", "")
        self._private_key: str = config.get("private_key", "")
        self._base_path: str = config.get("base_path", "/") or "/"

    @contextmanager
    def _connect(self):
        transport = paramiko.Transport((self._host, self._port))
        try:
            transport.connect(
                username=self._username,
                **self._auth_kwargs(),
            )
            sftp = paramiko.SFTPClient.from_transport(transport)
            try:
                yield sftp
            finally:
                sftp.close()
        finally:
            transport.close()

    def _auth_kwargs(self) -> dict:
        if self._auth_type == "key" and self._private_key:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(self._private_key))
            return {"pkey": pkey}
        return {"password": self._password}

    def test_connection(self) -> dict:
        try:
            with self._connect() as sftp:
                sftp.listdir(self._base_path)
            return {"ok": True, "message": f"Connected to {self._host}:{self._port}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    def list_files(
        self,
        path: str = "",
        recursive: bool = True,
        max_files: int = 100_000,
    ) -> Iterator[FileEntry]:
        base = (self._base_path.rstrip("/") + "/" + path.lstrip("/")).rstrip("/") or "/"
        with self._connect() as sftp:
            yield from self._walk(sftp, base, recursive, [0], max_files)

    def _walk(self, sftp, directory: str, recursive: bool, counter: list, max_files: int) -> Iterator[FileEntry]:
        try:
            entries = sftp.listdir_attr(directory)
        except Exception as exc:
            logger.warning("[sftp] listdir_attr(%s) failed: %s", directory, exc)
            return

        for entry in entries:
            if counter[0] >= max_files:
                return
            entry_path = directory.rstrip("/") + "/" + entry.filename
            if stat.S_ISDIR(entry.st_mode or 0):
                if recursive:
                    yield from self._walk(sftp, entry_path, recursive, counter, max_files)
            elif stat.S_ISREG(entry.st_mode or 0):
                mtime = None
                if entry.st_mtime:
                    mtime = datetime.fromtimestamp(entry.st_mtime, tz=timezone.utc).replace(tzinfo=None)
                yield FileEntry(
                    path=entry_path,
                    size=entry.st_size or 0,
                    mtime=mtime,
                )
                counter[0] += 1

    def get_file_bytes(self, file_path: str, max_bytes: int = 50 * 1024 * 1024) -> bytes:
        with self._connect() as sftp:
            buf = io.BytesIO()
            with sftp.open(file_path, "rb") as fh:
                remaining = max_bytes
                while remaining > 0:
                    chunk = fh.read(min(65536, remaining))
                    if not chunk:
                        break
                    buf.write(chunk)
                    remaining -= len(chunk)
            return buf.getvalue()
