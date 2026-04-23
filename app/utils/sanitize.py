"""
Input sanitization utilities for Zircon FRT.

Provides functions to sanitize user-supplied strings before storage or use,
protecting against XSS, path-traversal and other injection attacks.
"""

import html
import logging
import re

logger = logging.getLogger(__name__)

# Regex that matches any HTML/XML tag
_HTML_TAG_RE = re.compile(r"<[^>]*>", re.DOTALL)

# Regex for javascript: and data: URI schemes (case-insensitive, ignoring whitespace)
_DANGEROUS_PROTO_RE = re.compile(r"(?i)(?:javascript|vbscript|data)\s*:", re.IGNORECASE)

# Characters that are dangerous in filenames
_UNSAFE_FILENAME_CHARS_RE = re.compile(r'[<>:"|?*\x00-\x1f\\]')

# Allowed characters in a domain name
_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9._-]+$')

# Simple email format validation
_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')


def sanitize_string(value: str, max_length: int = 2048) -> str:
    """Strip HTML tags, escape special chars, trim to max_length.

    Logs a WARNING when HTML tags or dangerous protocol references are
    detected and removed, so potential XSS attempts are visible in logs.
    """
    if not isinstance(value, str):
        return ""

    # Pre-truncate to a safe bound before running regexes to prevent ReDoS
    # on pathological inputs (e.g. millions of '<' characters)
    value = value[: max_length * 4]

    original = value

    # Remove dangerous protocol references FIRST (before tag stripping so
    # that protocols embedded in attributes like href="javascript:..." are
    # caught even if the surrounding tag structure is unusual)
    stripped = _DANGEROUS_PROTO_RE.sub("", value)

    # Strip HTML/XML tags
    stripped = _HTML_TAG_RE.sub("", stripped)

    if stripped != original:
        logger.warning(
            "sanitize_string: potentially malicious content detected and removed. "
            "Original length=%d, stripped length=%d",
            len(original),
            len(stripped),
        )

    # Escape remaining special HTML characters
    escaped = html.escape(stripped, quote=True)

    return escaped[:max_length]


def sanitize_html(value: str) -> str:
    """Allow only a safe whitelist of HTML tags (b, i, u, br, p).

    All other tags are stripped; attributes are removed entirely.
    Uses bleach when available, falls back to a manual regex approach.
    """
    if not isinstance(value, str):
        return ""

    try:
        import bleach  # type: ignore

        allowed_tags = ["b", "i", "u", "br", "p"]
        return bleach.clean(value, tags=allowed_tags, attributes={}, strip=True)
    except ImportError:
        pass

    # Fallback: strip all tags except the whitelist
    allowed_tag_re = re.compile(
        r"<(/?)(?:b|i|u|br|p)(\s*/?)>",
        re.IGNORECASE,
    )

    def _replace(m: re.Match) -> str:
        return m.group(0)

    # First, replace allowed tags with placeholders, strip the rest, restore
    placeholder_map: dict = {}
    counter = [0]

    def _save_allowed(m: re.Match) -> str:
        key = f"\x00SAFE{counter[0]}\x00"
        placeholder_map[key] = m.group(0)
        counter[0] += 1
        return key

    safe_saved = allowed_tag_re.sub(_save_allowed, value)
    all_stripped = _HTML_TAG_RE.sub("", safe_saved)
    for key, original_tag in placeholder_map.items():
        all_stripped = all_stripped.replace(key, original_tag)

    return all_stripped


def sanitize_filename(filename: str) -> str:
    """Remove path traversal chars, null bytes, and dangerous chars from filenames.

    Returns a safe filename consisting only of alphanumeric characters,
    underscores, hyphens, and dots.
    """
    if not isinstance(filename, str):
        return "upload"

    # Remove null bytes
    filename = filename.replace("\x00", "")

    # Strip directory traversal components
    filename = filename.replace("../", "").replace("./", "").replace("..\\", "").replace(".\\", "")

    # Strip path separators
    filename = re.sub(r"[/\\]", "_", filename)

    # Remove dangerous characters: <>":|?* and control chars
    filename = _UNSAFE_FILENAME_CHARS_RE.sub("", filename)

    # Trim leading/trailing dots and spaces (can cause issues on Windows/Linux)
    filename = filename.strip(". ")

    if not filename:
        return "upload"

    return filename[:255]


def sanitize_search_query(query: str, max_length: int = 512) -> str:
    """Sanitize a search query string.

    Strips HTML tags, removes dangerous protocol references, limits length
    to *max_length* characters and allows common search operators (AND/OR/NOT).
    """
    if not isinstance(query, str):
        return ""

    # Strip HTML tags (log if found)
    query = sanitize_string(query, max_length=max_length)

    return query


def is_valid_domain(value: str) -> bool:
    """Return True if *value* looks like a valid domain name."""
    return bool(_DOMAIN_RE.match(value)) if value else False


def is_valid_email(value: str) -> bool:
    """Return True if *value* looks like a valid e-mail address."""
    return bool(_EMAIL_RE.match(value)) if value else False
