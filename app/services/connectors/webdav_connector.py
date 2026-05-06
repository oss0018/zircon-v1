"""
WebDAV storage connector.

Config keys:
  base_url   : str   - root WebDAV URL, e.g. "https://dav.example.com/remote.php/dav/files/user"
  username   : str   - username for Basic auth
  password   : str   - password for Basic auth
  token      : str   - Bearer token (used instead of username/password if provided)
  base_path  : str   - sub-path appended to base_url when scanning (default "/")
"""
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Iterator
from urllib.parse import urljoin, urlparse, quote, unquote

import httpx

from .base import StorageConnector, FileEntry

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 15
_READ_TIMEOUT = 60

# WebDAV XML namespaces
_NS_DAV = "DAV:"
_PROPFIND_BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<D:propfind xmlns:D="DAV:">'
    "<D:prop>"
    "<D:displayname/>"
    "<D:resourcetype/>"
    "<D:getcontentlength/>"
    "<D:getlastmodified/>"
    "<D:getetag/>"
    "<D:getcontenttype/>"
    "</D:prop>"
    "</D:propfind>"
)


def _dav_tag(name: str) -> str:
    return f"{{{_NS_DAV}}}{name}"


def _parse_size(text: str | None) -> int:
    try:
        return int(text or "0")
    except (ValueError, TypeError):
        return 0


def _parse_mtime(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        dt = parsedate_to_datetime(text)
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        return None


class WebDAVConnector(StorageConnector):
    def __init__(self, config: dict) -> None:
        self._base_url: str = config.get("base_url", "").rstrip("/")
        self._base_path: str = config.get("base_path", "/") or "/"
        username = config.get("username", "")
        password = config.get("password", "")
        token = config.get("token", "")

        headers: dict = {}
        auth = None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif username:
            auth = (username, password)

        self._auth = auth
        self._headers = headers

    def _client(self) -> httpx.Client:
        return httpx.Client(
            auth=self._auth,
            headers=self._headers,
            timeout=httpx.Timeout(_READ_TIMEOUT, connect=_CONNECT_TIMEOUT),
            follow_redirects=True,
            verify=True,
        )

    def _url(self, path: str) -> str:
        """Build a full WebDAV URL for the given *path*."""
        clean = path.lstrip("/")
        if not clean:
            return self._base_url + "/"
        # percent-encode each path segment but leave "/" separators intact
        encoded = "/".join(quote(seg, safe="") for seg in clean.split("/"))
        return self._base_url + "/" + encoded

    def test_connection(self) -> dict:
        try:
            url = self._url(self._base_path)
            with self._client() as client:
                resp = client.request(
                    "PROPFIND",
                    url,
                    headers={"Depth": "0", "Content-Type": "application/xml"},
                    content=_PROPFIND_BODY.encode(),
                )
            if resp.status_code in (207, 200):
                return {"ok": True, "message": f"Connected to {self._base_url}"}
            return {"ok": False, "message": f"HTTP {resp.status_code}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    def list_files(
        self,
        path: str = "",
        recursive: bool = True,
        max_files: int = 100_000,
    ) -> Iterator[FileEntry]:
        root = (self._base_path.rstrip("/") + "/" + path.lstrip("/")).rstrip("/") or "/"
        with self._client() as client:
            yield from self._propfind(client, root, recursive, [0], max_files)

    def _propfind(
        self,
        client: httpx.Client,
        path: str,
        recursive: bool,
        counter: list,
        max_files: int,
    ) -> Iterator[FileEntry]:
        url = self._url(path)
        depth = "1"  # we handle recursion manually to enforce max_files
        try:
            resp = client.request(
                "PROPFIND",
                url,
                headers={"Depth": depth, "Content-Type": "application/xml"},
                content=_PROPFIND_BODY.encode(),
            )
        except Exception as exc:
            logger.warning("[webdav] PROPFIND %s failed: %s", url, exc)
            return

        if resp.status_code != 207:
            logger.warning("[webdav] PROPFIND %s returned %s", url, resp.status_code)
            return

        try:
            root_el = ET.fromstring(resp.content)
        except ET.ParseError as exc:
            logger.warning("[webdav] XML parse error for %s: %s", url, exc)
            return

        for response_el in root_el.findall(_dav_tag("response")):
            href_el = response_el.find(_dav_tag("href"))
            if href_el is None or href_el.text is None:
                continue
            href = unquote(href_el.text)

            # Determine entry path relative to base_url
            parsed_base = urlparse(self._base_url)
            base_path_prefix = parsed_base.path.rstrip("/")
            entry_path = href
            if entry_path.startswith(base_path_prefix):
                entry_path = entry_path[len(base_path_prefix):]
            entry_path = entry_path or "/"

            props = response_el.find(
                f".//{_dav_tag('propstat')}/{_dav_tag('prop')}"
            )
            if props is None:
                continue

            rt = props.find(_dav_tag("resourcetype"))
            is_collection = rt is not None and rt.find(_dav_tag("collection")) is not None

            # Skip the directory itself (depth=1 includes the queried dir)
            if entry_path.rstrip("/") == path.rstrip("/"):
                continue

            if is_collection:
                if recursive and counter[0] < max_files:
                    yield from self._propfind(client, entry_path, recursive, counter, max_files)
            else:
                if counter[0] >= max_files:
                    return
                size = _parse_size(
                    getattr(props.find(_dav_tag("getcontentlength")), "text", None)
                )
                mtime = _parse_mtime(
                    getattr(props.find(_dav_tag("getlastmodified")), "text", None)
                )
                etag = getattr(props.find(_dav_tag("getetag")), "text", None) or ""
                content_type = (
                    getattr(props.find(_dav_tag("getcontenttype")), "text", None) or ""
                )
                yield FileEntry(
                    path=entry_path,
                    size=size,
                    mtime=mtime,
                    etag=etag.strip('"'),
                    content_type=content_type,
                )
                counter[0] += 1

    def get_file_bytes(self, file_path: str, max_bytes: int = 50 * 1024 * 1024) -> bytes:
        url = self._url(file_path)
        with self._client() as client:
            with client.stream("GET", url) as resp:
                resp.raise_for_status()
                chunks = []
                total = 0
                for chunk in resp.iter_bytes(chunk_size=65536):
                    total += len(chunk)
                    if total > max_bytes:
                        chunks.append(chunk[: max_bytes - (total - len(chunk))])
                        break
                    chunks.append(chunk)
        return b"".join(chunks)
