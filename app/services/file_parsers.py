"""
Text extractors for supported file types.
"""
import json
import csv
import io
from pathlib import Path
from typing import Optional


def extract_text(file_path: str) -> Optional[str]:
    p = Path(file_path)
    if not p.exists():
        return None
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
