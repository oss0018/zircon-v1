"""
Generic HTTP API storage connector.

Config keys:
  base_url            : str   - API endpoint that returns a JSON listing
  method              : str   - GET or POST (default GET)
  auth_type           : str   - bearer | api_key | basic | none
  bearer_token        : str   - bearer token value
  api_token           : str   - API token / key value
  api_key_header      : str   - Header name for api_key auth (default X-API-Key)
  username            : str   - Username for basic auth
  password            : str   - Password for basic auth
  payload             : dict  - Optional JSON body for POST
  items_json_path     : str   - Dot path to the file list in the JSON response
  item_path_field     : str   - Path field name for each item (default path)
  item_size_field     : str   - Size field name (default size)
  item_mtime_field    : str   - Modified time field name (default mtime)
"""
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import urljoin

import httpx

from .base import FileEntry, StorageConnector

_CONNECT_TIMEOUT = 15
_READ_TIMEOUT = 60


def _extract_path(payload: Any, path: str) -> Any:
    current = payload
    for part in [segment for segment in (path or "").split(".") if segment]:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return []
    return current


def _parse_mtime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).replace(tzinfo=None)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            return None
    return None


class APISourceConnector(StorageConnector):
    def __init__(self, config: dict) -> None:
        self._base_url = str(config.get("base_url") or "").strip()
        self._method = str(config.get("method") or "GET").upper()
        self._auth_type = str(config.get("auth_type") or "none").lower()
        self._payload = config.get("payload") if isinstance(config.get("payload"), dict) else None
        self._items_json_path = str(config.get("items_json_path") or "").strip()
        self._item_path_field = str(config.get("item_path_field") or "path")
        self._item_size_field = str(config.get("item_size_field") or "size")
        self._item_mtime_field = str(config.get("item_mtime_field") or "mtime")
        self._download_url_field = str(config.get("download_url_field") or "download_url")
        self._headers = self._build_headers(config)
        self._auth = self._build_auth(config)

    def _build_headers(self, config: dict) -> dict:
        headers = {"Accept": "application/json"}
        if self._auth_type == "bearer" and config.get("bearer_token"):
            headers["Authorization"] = "Bearer " + str(config["bearer_token"])
        elif self._auth_type == "api_key" and config.get("api_token"):
            headers[str(config.get("api_key_header") or "X-API-Key")] = str(config["api_token"])
        return headers

    def _build_auth(self, config: dict):
        if self._auth_type == "basic" and config.get("username"):
            return (str(config.get("username") or ""), str(config.get("password") or ""))
        return None

    def _client(self) -> httpx.Client:
        return httpx.Client(
            auth=self._auth,
            headers=self._headers,
            timeout=httpx.Timeout(_READ_TIMEOUT, connect=_CONNECT_TIMEOUT),
            follow_redirects=True,
        )

    def _request(self) -> httpx.Response:
        with self._client() as client:
            if self._method == "POST":
                response = client.post(self._base_url, json=self._payload or {})
            else:
                response = client.get(self._base_url)
        response.raise_for_status()
        return response

    def test_connection(self) -> dict:
        try:
            self._request()
            return {"ok": True, "message": f"Connected to API '{self._base_url}'"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    def list_files(
        self,
        path: str = "",
        recursive: bool = True,
        max_files: int = 100_000,
    ) -> Iterator[FileEntry]:
        del path, recursive
        response = self._request()
        payload = response.json()
        items = _extract_path(payload, self._items_json_path) if self._items_json_path else payload
        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, list):
            return
        count = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            item_path = item.get(self._item_path_field) or item.get("url") or item.get("id")
            if not item_path:
                continue
            download_url = item.get(self._download_url_field) or item.get("url") or item_path
            yield FileEntry(
                path=str(download_url),
                size=int(item.get(self._item_size_field) or 0),
                mtime=_parse_mtime(item.get(self._item_mtime_field)),
                content_type=str(item.get("content_type") or ""),
            )
            count += 1
            if count >= max_files:
                return

    def get_file_bytes(self, file_path: str, max_bytes: int = 50 * 1024 * 1024) -> bytes:
        target_url = file_path if str(file_path).startswith(("http://", "https://")) else urljoin(self._base_url, str(file_path))
        with self._client() as client:
            with client.stream("GET", target_url) as response:
                response.raise_for_status()
                chunks = []
                total = 0
                for chunk in response.iter_bytes(chunk_size=65536):
                    total += len(chunk)
                    if total > max_bytes:
                        chunks.append(chunk[: max_bytes - (total - len(chunk))])
                        break
                    chunks.append(chunk)
        return b"".join(chunks)
