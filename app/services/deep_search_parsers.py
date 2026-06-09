from pathlib import Path

from app.services.storage_indexer import _extract_text_from_bytes as _legacy_extract_text_from_bytes

_OFFICE_EXTENSIONS = {".doc", ".docx", ".odt", ".xls", ".xlsx"}
_CODE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".json",
    ".kt",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".swift",
    ".ts",
    ".tsx",
    ".xml",
    ".yaml",
    ".yml",
}
_ARCHIVE_EXTENSIONS = {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".xz", ".zip"}
_TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".csv",
    ".env",
    ".html",
    ".htm",
    ".ini",
    ".log",
    ".md",
    ".rtf",
    ".txt",
}


def extract_text_from_bytes(data: bytes, filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    if not data or suffix in _ARCHIVE_EXTENSIONS:
        return ""
    if b"\x00" in data[:4096] and suffix not in (_TEXT_EXTENSIONS | _CODE_EXTENSIONS | {".pdf"} | _OFFICE_EXTENSIONS):
        return ""
    return _legacy_extract_text_from_bytes(data, filename) or ""


def determine_parse_mode(filename: str, text: str, data: bytes | None = None) -> str:
    suffix = Path(filename).suffix.lower()
    if not text.strip():
        return "empty"
    if suffix == ".pdf":
        return "pdf"
    if suffix in _OFFICE_EXTENSIONS:
        return "office"
    if suffix in _CODE_EXTENSIONS:
        return "code"
    if suffix in _ARCHIVE_EXTENSIONS:
        return "archive"
    if data and b"\x00" in data[:4096]:
        return "binary"
    return "text"
