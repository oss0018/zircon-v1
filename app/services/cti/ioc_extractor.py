import re
import ipaddress

_DEFANG_REPLACEMENTS = [
    (r"hxxps?://", lambda m: "http://" if m.group(0).startswith("hxxp://") else "https://"),
    (r"\[\.\]", "."),
    (r"\(\.\)", "."),
    (r"\[:\]", ":"),
]


def refang_text(text: str) -> str:
    out = text or ""
    for pattern, repl in _DEFANG_REPLACEMENTS:
        out = re.sub(pattern, repl, out, flags=re.IGNORECASE)
    return out


def extract_iocs(text: str) -> dict[str, list[str]]:
    content = refang_text(text)
    ip_candidates = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content))
    ips = sorted({ip for ip in ip_candidates if _is_valid_ipv4(ip)})
    domains = sorted(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b", content)))
    urls = sorted(set(re.findall(r"\bhttps?://[^\s<>'\"]+", content, flags=re.IGNORECASE)))
    emails = sorted(set(re.findall(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}\b", content)))
    hashes = sorted(set(re.findall(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b", content)))
    return {
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "emails": emails,
        "hashes": hashes,
    }


def _is_valid_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False
