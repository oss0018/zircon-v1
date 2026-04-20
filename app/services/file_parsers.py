"""
Text extractors for supported file types.
"""
import json
import csv
import io
import re
from pathlib import Path
from typing import Optional

MAX_INDEX_BYTES = 50 * 1024 * 1024  # 50 MB max content to index


def _is_credential_log(p: Path) -> bool:
    """Detect if a file looks like a url:login:password credential log."""
    # Check if file is inside a leaked_accounts directory
    parts = p.parts
    if "leaked_accounts" in parts:
        return True
    # Sample first few lines to detect the pattern
    if p.suffix.lower() in (".txt", ".log", ""):
        try:
            with open(p, "r", errors="replace") as f:
                for _ in range(10):
                    line = f.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Match url:login:pass or email:password patterns
                    if re.match(r'^https?://[^\s:]+[:].+[:].+$', line):
                        return True
                    if re.match(r'^[\w.+-]+@[\w-]+\.[\w.]+[:].+$', line):
                        return True
        except Exception:
            pass
    return False


def extract_credential_log(file_path: str, max_bytes: int = MAX_INDEX_BYTES) -> str:
    """Parse url:login:password logs, extract searchable tokens."""
    domains: set = set()
    emails: set = set()
    usernames: set = set()
    raw_lines = []

    bytes_read = 0
    try:
        with open(file_path, "r", errors="replace") as f:
            for line in f:
                bytes_read += len(line.encode("utf-8", errors="replace"))
                if bytes_read > max_bytes:
                    break
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                raw_lines.append(line)
                # Reconstruct URL:login:pass — handle http:// prefix
                raw_parts = line.split(":")
                if len(raw_parts) >= 3 and raw_parts[0].lower() in ("http", "https"):
                    # URL format: https://domain/path:login:pass
                    url_part = f"{raw_parts[0]}:{raw_parts[1]}"
                    rest = raw_parts[2:]
                else:
                    url_part = raw_parts[0]
                    rest = raw_parts[1:]

                # Extract domain from URL
                m = re.search(r"(?:https?://)?([^/:]+\.[^/:]+)", url_part)
                if m:
                    domains.add(m.group(1).lower())
                elif "." in url_part and "@" not in url_part:
                    domains.add(url_part.lower())

                # Extract emails and usernames from all parts
                for part in [url_part] + rest:
                    em = re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", part)
                    if em:
                        emails.add(em.group(0).lower())
                        usernames.add(em.group(0).split("@")[0].lower())
    except Exception as e:
        return f"[credential log error: {e}]"

    parts_out = []
    parts_out.append("=== RAW LINES (sample) ===")
    parts_out.extend(raw_lines[:10000])
    parts_out.append("\n=== EXTRACTED DOMAINS ===")
    parts_out.extend(sorted(domains))
    parts_out.append("\n=== EXTRACTED EMAILS ===")
    parts_out.extend(sorted(emails))
    parts_out.append("\n=== EXTRACTED USERNAMES ===")
    parts_out.extend(sorted(usernames))

    return "\n".join(parts_out)


def extract_text_streaming(file_path: str, max_bytes: int = MAX_INDEX_BYTES) -> Optional[str]:
    """Read large files in chunks: first + middle + last chunk."""
    p = Path(file_path)
    if not p.exists():
        return None
    file_size = p.stat().st_size

    if file_size <= max_bytes:
        return extract_text(file_path)

    chunks = []
    chunk_size = max_bytes // 3

    try:
        with open(file_path, "rb") as f:
            chunks.append(f.read(chunk_size).decode("utf-8", errors="replace"))
            f.seek(file_size // 2)
            chunks.append(f.read(chunk_size).decode("utf-8", errors="replace"))
            f.seek(max(0, file_size - chunk_size))
            chunks.append(f.read(chunk_size).decode("utf-8", errors="replace"))
    except Exception as e:
        return f"[large file read error: {e}]"

    size_gb = file_size / (1024 ** 3)
    header = f"[LARGE FILE: {size_gb:.2f} GB, partial index]\n"
    return header + "\n...[TRUNCATED]...\n".join(chunks)


def extract_text(file_path: str) -> Optional[str]:
    p = Path(file_path)
    if not p.exists():
        return None

    # Check for large files first
    try:
        file_size = p.stat().st_size
    except Exception:
        file_size = 0

    # Detect credential log files and use specialized parser
    if _is_credential_log(p):
        if file_size > MAX_INDEX_BYTES:
            return extract_credential_log(file_path)
        return extract_credential_log(file_path)

    # For large plain-text files, use streaming extraction
    if file_size > MAX_INDEX_BYTES:
        return extract_text_streaming(file_path)

    suffix = p.suffix.lower()
    try:
        if suffix in (".txt", ".md", ".log", ".sql", ".xml", ".html", ".htm", ".yaml", ".yml", ".ini", ".cfg", ".conf"):
            return p.read_text(errors="ignore")
        elif suffix == ".json":
            return _extract_json(p)
        elif suffix == ".csv":
            return _extract_csv(p)
        elif suffix in (".xlsx", ".xls"):
            return _extract_excel(p)
        elif suffix == ".pdf":
            return _extract_pdf(p)
        elif suffix == ".docx":
            return _extract_docx(p)
        else:
            # Try reading as plain text
            try:
                return p.read_text(errors="ignore")
            except Exception:
                return None
    except Exception as e:
        return f"[extraction error: {e}]"


def _extract_json(p: Path) -> str:
    try:
        data = json.loads(p.read_text(errors="ignore"))
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception:
        return p.read_text(errors="ignore")


def _extract_csv(p: Path) -> str:
    rows = []
    try:
        with p.open(newline="", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                rows.append(" ".join(row))
    except Exception:
        pass
    return "\n".join(rows)


def _extract_excel(p: Path) -> str:
    try:
        import pandas as pd
        dfs = pd.read_excel(p, sheet_name=None, engine="openpyxl")
        parts = []
        for sheet_name, df in dfs.items():
            parts.append(f"[Sheet: {sheet_name}]")
            parts.append(df.to_string(index=False))
        return "\n".join(parts)
    except Exception as e:
        return f"[excel error: {e}]"


def _extract_pdf(p: Path) -> str:
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(str(p))
        pages = []
        for page in doc:
            pages.append(page.get_text())
        doc.close()
        return "\n".join(pages)
    except Exception as e:
        return f"[pdf error: {e}]"


def _extract_docx(p: Path) -> str:
    try:
        from docx import Document
        doc = Document(str(p))
        return "\n".join(p.text for p in doc.paragraphs)
    except Exception as e:
        return f"[docx error: {e}]"
