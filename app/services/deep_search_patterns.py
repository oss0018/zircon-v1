from dataclasses import dataclass
import re


@dataclass(frozen=True)
class LeakPattern:
    name: str
    category: str
    severity: int
    regex: str


@dataclass(frozen=True)
class LeakRecord:
    file_id: int
    chunk_id: int
    pattern_name: str
    category: str
    severity: int
    matched_value: str
    matched_value_masked: str
    context_before: str
    context_after: str
    line_number: int
    char_offset: int
    email: str = ""
    email_domain: str = ""
    password_plain: str = ""


PATTERN_REGISTRY: list[LeakPattern] = [
    LeakPattern(name="aws_access_key_id", category="api_keys", severity=95, regex=r"AKIA[0-9A-Z]{16}"),
    LeakPattern(
        name="aws_secret_access_key",
        category="api_keys",
        severity=95,
        regex=r"(?i)aws(.{0,20})?(secret|private).{0,3}[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
    ),
    LeakPattern(name="github_pat", category="api_keys", severity=95, regex=r"gh[pousr]_[A-Za-z0-9_]{36,251}"),
    LeakPattern(name="slack_token", category="api_keys", severity=85, regex=r"xox[abprs]-[A-Za-z0-9-]{10,48}"),
    LeakPattern(name="google_api_key", category="api_keys", severity=85, regex=r"AIza[0-9A-Za-z\-_]{35}"),
    LeakPattern(
        name="private_key_pem",
        category="credentials",
        severity=100,
        regex=r"-----BEGIN ((RSA|EC|OPENSSH|DSA|PGP) )?PRIVATE KEY-----",
    ),
    LeakPattern(
        name="jwt",
        category="credentials",
        severity=70,
        regex=r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    ),
    LeakPattern(
        name="generic_password_assign",
        category="credentials",
        severity=60,
        regex=r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{6,128})['\"]",
    ),
    LeakPattern(
        name="email_address",
        category="pii",
        severity=30,
        regex=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    ),
    LeakPattern(
        name="us_ssn",
        category="pii",
        severity=80,
        regex=r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
    ),
    LeakPattern(
        name="credit_card",
        category="pii",
        severity=85,
        regex=r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)([ -]?\d{4}){2}[ -]?\d{4}\b",
    ),
]


def _mask_value(value: str) -> str:
    if len(value) <= 4:
        return value
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def _trim_before(value: str) -> str:
    if len(value) <= 60:
        return value
    value = value[-60:]
    if " " in value:
        value = value.split(" ", 1)[-1]
    return value


def _trim_after(value: str) -> str:
    if len(value) <= 60:
        return value
    value = value[:60]
    if " " in value:
        value = value.rsplit(" ", 1)[0]
    return value


def scan_chunk(content: str, chunk_id: int, file_id: int) -> list[LeakRecord]:
    matches: list[LeakRecord] = []
    for pattern in PATTERN_REGISTRY:
        for match in re.finditer(pattern.regex, content):
            matched_value = match.group(0)
            email = matched_value if pattern.name == "email_address" else ""
            password_plain = match.group(2) if pattern.name == "generic_password_assign" else ""
            matches.append(
                LeakRecord(
                    file_id=file_id,
                    chunk_id=chunk_id,
                    pattern_name=pattern.name,
                    category=pattern.category,
                    severity=pattern.severity,
                    matched_value=matched_value,
                    matched_value_masked=_mask_value(matched_value),
                    context_before=_trim_before(content[max(0, match.start() - 60):match.start()]),
                    context_after=_trim_after(content[match.end():match.end() + 60]),
                    line_number=content.count("\n", 0, match.start()) + 1,
                    char_offset=match.start(),
                    email=email,
                    email_domain=email.split("@", 1)[1].lower() if email and "@" in email else "",
                    password_plain=password_plain,
                )
            )
    return matches


def rollup_leak_records(records: list[LeakRecord]) -> dict:
    categories = {record.category for record in records}
    return {
        "leak_count": len(records),
        "severity_max": max((record.severity for record in records), default=0),
        "has_api_keys": "api_keys" in categories,
        "has_credentials": "credentials" in categories,
        "has_pii": "pii" in categories,
        "pattern_names": sorted({record.pattern_name for record in records}),
    }
