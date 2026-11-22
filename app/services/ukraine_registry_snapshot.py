"""Streaming reader for NAIS legal-entity XML snapshots."""
import re
import zipfile
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException


class SnapshotError(ValueError):
    """A snapshot is invalid or cannot be read safely."""


@dataclass
class SnapshotStats:
    missing_edrpou: int = 0
    invalid_edrpou: int = 0


def _records(stream: BinaryIO, stats: SnapshotStats | None) -> Iterator[dict]:
    try:
        root = None
        for event, element in ElementTree.iterparse(stream, events=("start", "end")):
            if root is None:
                root = element
                if element.tag != "DATA":
                    raise SnapshotError("Expected an official DATA XML document")
            elif event == "end" and element.tag == "SUBJECT":
                code = (element.findtext("EDRPOU") or "").strip()
                if not code and stats is not None:
                    stats.missing_edrpou += 1
                elif not re.fullmatch(r"[0-9]{8}", code):
                    if stats is None:
                        raise SnapshotError("Company record has an invalid or missing EDRPOU code")
                    stats.invalid_edrpou += 1
                signers = element.find("SIGNERS")
                yield {
                    "edrpou": code or None,
                    "name": (element.findtext("NAME") or "").strip(),
                    "short_name": (element.findtext("SHORT_NAME") or "").strip(),
                    "status": (element.findtext("STAN") or "").strip(),
                    "signatories": sorted(
                        text for item in (signers.findall("SIGNER") if signers is not None else [])
                        if (text := (item.text or "").strip())
                    ),
                }
                root.clear()
    except (ElementTree.ParseError, DefusedXmlException, UnicodeError) as exc:
        raise SnapshotError("Invalid snapshot XML") from exc


def read_company_snapshot(path, stats: SnapshotStats | None = None) -> Iterator[dict]:
    """Read company records only; reject archives that do not identify their company member."""
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                files = [item for item in archive.infolist()
                         if re.search(r"(?:^|[_-])UO(?:[_-]|[.])", item.filename.rsplit("/", 1)[-1], re.I)
                         and item.filename.lower().endswith(".xml") and not item.is_dir()]
                if len(files) != 1:
                    raise SnapshotError("Archive must contain exactly one UO company XML file")
                if files[0].file_size > 12 * 1024**3:
                    raise SnapshotError("Company XML exceeds the 12 GiB limit")
                with archive.open(files[0]) as stream:
                    yield from _records(stream, stats)
        else:
            if hasattr(path, "read"):
                path.seek(0)
                yield from _records(path, stats)
            else:
                with path.open("rb") as stream:
                    yield from _records(stream, stats)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise SnapshotError("Could not read the snapshot file") from exc
