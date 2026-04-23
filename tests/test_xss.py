"""
Tests for XSS protection utilities in Zircon FRT.
"""

import pytest
from app.utils.sanitize import (
    sanitize_string,
    sanitize_filename,
    sanitize_search_query,
    sanitize_html,
    is_valid_domain,
    is_valid_email,
)


# ── sanitize_string ────────────────────────────────────────────────────────────

def test_script_tag_stripped():
    result = sanitize_string("<script>alert(1)</script>")
    assert "<script>" not in result
    assert "alert(1)" in result  # text content preserved (escaped)


def test_img_onerror_stripped():
    result = sanitize_string("<img src=x onerror=alert(1)>")
    assert "onerror" not in result.lower()
    assert "<img" not in result


def test_javascript_protocol_stripped():
    result = sanitize_string("javascript:alert(1)")
    assert "javascript:" not in result


def test_vbscript_protocol_stripped():
    result = sanitize_string("vbscript:MsgBox(1)")
    assert "vbscript:" not in result


def test_html_special_chars_escaped():
    result = sanitize_string('<b>Hello "World"</b>')
    assert "&lt;" in result or "<b>" not in result
    assert "&amp;" not in result  # amp-encoded & stays or raw & is escaped


def test_max_length_respected():
    long_str = "a" * 3000
    result = sanitize_string(long_str, max_length=2048)
    assert len(result) <= 2048


def test_plain_text_preserved():
    text = "kyivstar search query AND/OR something"
    result = sanitize_string(text)
    assert "kyivstar" in result
    assert "search" in result


# ── sanitize_filename ──────────────────────────────────────────────────────────

def test_filename_traversal_stripped():
    result = sanitize_filename("../../../etc/passwd")
    assert "../" not in result
    assert "etc" in result or result == "passwd" or "etc" in result


def test_filename_null_byte_stripped():
    result = sanitize_filename("file\x00.txt")
    assert "\x00" not in result


def test_filename_dangerous_chars_stripped():
    result = sanitize_filename("file<script>.txt")
    assert "<" not in result
    assert ">" not in result


def test_filename_absolute_path_stripped():
    result = sanitize_filename("/etc/passwd")
    assert "/" not in result or result.startswith("etc")


def test_filename_empty_becomes_upload():
    assert sanitize_filename("") == "upload"
    assert sanitize_filename("\x00") == "upload"


def test_filename_safe_preserved():
    result = sanitize_filename("my_document-2024.pdf")
    assert result == "my_document-2024.pdf"


# ── sanitize_search_query ──────────────────────────────────────────────────────

def test_search_query_length_limited():
    result = sanitize_search_query("a" * 1000)
    assert len(result) <= 512


def test_search_query_script_stripped():
    result = sanitize_search_query("<script>xss</script> kyivstar")
    assert "<script>" not in result
    assert "kyivstar" in result


# ── sanitize_html ──────────────────────────────────────────────────────────────

def test_sanitize_html_allows_safe_tags():
    result = sanitize_html("<b>bold</b> and <i>italic</i>")
    assert "bold" in result
    assert "italic" in result


def test_sanitize_html_strips_dangerous_tags():
    result = sanitize_html("<script>alert(1)</script><b>safe</b>")
    assert "<script>" not in result
    assert "safe" in result


# ── is_valid_domain / is_valid_email ──────────────────────────────────────────

def test_valid_domain():
    assert is_valid_domain("example.com")
    assert is_valid_domain("kyivstar.ua")
    assert not is_valid_domain("<script>")
    assert not is_valid_domain("domain with spaces")


def test_valid_email():
    assert is_valid_email("user@example.com")
    assert not is_valid_email("<script>@bad.com")
    assert not is_valid_email("notanemail")
