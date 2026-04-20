"""
Zircon FRT — Async Domain Checker Service for Brand Protection.

Provides:
- Typosquatting domain variant generator
- Async DNS + HTTP domain checker (asyncio + aiohttp, semaphore-limited)
- Bulk file reader for up to 250,000 domains
- Similarity scorer using difflib
"""
from __future__ import annotations

import asyncio
import difflib
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import AsyncIterator, Dict, List, Optional, Set


# ── Constants ─────────────────────────────────────────────────────────────────

SEMAPHORE_LIMIT = 50
BATCH_SIZE = 1000
HTTP_TIMEOUT = 5  # seconds

QWERTY_ADJACENT: Dict[str, str] = {
    "q": "wa", "w": "qase", "e": "wsdr", "r": "edft", "t": "rfgy",
    "y": "tghu", "u": "yhji", "i": "ujko", "o": "iklp", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc", "g": "ftyhbv",
    "h": "gyujnb", "j": "huikmn", "k": "jiolm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
}

HOMOGLYPHS: Dict[str, str] = {
    "i": "l", "l": "1", "o": "0", "a": "@", "e": "3", "s": "5",
}

TLD_SUBSTITUTIONS: List[str] = [
    ".com", ".net", ".org", ".io", ".online", ".shop", ".site",
    ".info", ".biz", ".co", ".xyz", ".ua",
]

COMMON_PREFIXES: List[str] = [
    "login-", "secure-", "my-", "portal-", "account-", "support-", "www-",
]

COMMON_SUFFIXES: List[str] = [
    "-login", "-secure", "-portal", "-account", "-support", "-online",
]

_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,256})</title>", re.IGNORECASE | re.DOTALL)

# Max bytes to read from HTTP response when searching for a <title> tag
MAX_TITLE_SEARCH_BYTES = 32768

# Pattern for valid public domain labels (no internal hostnames)
_VALID_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


# ── Domain Validation ─────────────────────────────────────────────────────────

def _is_safe_external_domain(domain: str) -> bool:
    """
    Return True only if *domain* refers to a publicly-routable external host.

    Rejects:
    - Localhost and loopback names (localhost, *.local, *.localdomain)
    - Malformed domain labels
    - Internal / private IP literals (RFC 1918, RFC 4193, loopback, link-local)
    """
    domain = domain.lower().strip()

    # Reject empty or overly long domains
    if not domain or len(domain) > 253:
        return False

    # Reject known internal hostnames
    if domain in ("localhost", "broadcasthost") or domain.endswith(
        (".local", ".localdomain", ".internal", ".corp", ".home", ".lan")
    ):
        return False

    # If it looks like an IP address, reject private/reserved ranges
    try:
        addr = ipaddress.ip_address(domain)
        return addr.is_global and not addr.is_private and not addr.is_loopback
    except ValueError:
        pass  # not an IP literal — continue with domain validation

    # Must match a valid domain pattern
    if not _VALID_DOMAIN_RE.match(domain):
        return False

    return True


# ── Typosquat Generator ───────────────────────────────────────────────────────

def generate_typosquats(domain: str, limit: int = 1000) -> List[str]:
    """
    Generate typosquatting variants for the given domain.

    Techniques used:
    - Character deletion
    - Character transposition (swap adjacent)
    - Adjacent keyboard key substitution (QWERTY layout)
    - Character duplication
    - Hyphen insertion between characters
    - TLD substitution
    - Common prefix additions
    - Common suffix additions
    - Homoglyph substitution (i→l, l→1, o→0, a→@, e→3, s→5)
    - Number appending (0–9)

    Args:
        domain: Base domain (e.g. ``kyivstar.ua``).
        limit:  Maximum number of variants to return.

    Returns:
        Deduplicated list of variant domains, excluding the original.
    """
    parts = domain.split(".")
    name = parts[0] if parts else domain
    original_tld = "." + ".".join(parts[1:]) if len(parts) > 1 else ".com"

    candidates: Set[str] = set()

    # 1. Character deletion
    for i in range(len(name)):
        candidates.add(name[:i] + name[i + 1:] + original_tld)

    # 2. Character transposition (swap adjacent)
    for i in range(len(name) - 1):
        t = list(name)
        t[i], t[i + 1] = t[i + 1], t[i]
        candidates.add("".join(t) + original_tld)

    # 3. Adjacent keyboard key substitution
    for i, ch in enumerate(name):
        for replacement in QWERTY_ADJACENT.get(ch.lower(), ""):
            candidates.add(name[:i] + replacement + name[i + 1:] + original_tld)

    # 4. Character duplication
    for i in range(len(name)):
        candidates.add(name[:i] + name[i] + name[i:] + original_tld)

    # 5. Hyphen insertion
    for i in range(1, len(name)):
        candidates.add(name[:i] + "-" + name[i:] + original_tld)

    # 6. TLD substitution
    for tld in TLD_SUBSTITUTIONS:
        candidates.add(name + tld)

    # 7. Common prefix additions
    for prefix in COMMON_PREFIXES:
        candidates.add(prefix + name + original_tld)

    # 8. Common suffix additions
    for suffix in COMMON_SUFFIXES:
        candidates.add(name + suffix + original_tld)

    # 9. Homoglyph substitution
    for i, ch in enumerate(name):
        if ch in HOMOGLYPHS:
            candidates.add(name[:i] + HOMOGLYPHS[ch] + name[i + 1:] + original_tld)

    # 10. Number appending (0–9)
    for digit in "0123456789":
        candidates.add(name + digit + original_tld)

    # Remove original domain and apply limit
    candidates.discard(domain)
    return list(candidates)[:limit]


# ── Domain Checker ────────────────────────────────────────────────────────────

def _resolve_ip(domain: str) -> Optional[str]:
    """Synchronously resolve IP address for a domain (run in thread executor)."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def _check_ssl(domain: str) -> bool:
    """
    Check SSL certificate validity for *domain* using TLS 1.2+ only.

    Returns True if a valid certificate is presented, False otherwise.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=HTTP_TIMEOUT),
            server_hostname=domain,
        ) as conn:
            conn.getpeercert()
        return True
    except Exception:
        return False


async def check_domain(
    domain: str,
    session: object,
    brand_name: str = "",
) -> Dict:
    """
    Asynchronously check a single domain for liveness.

    Only publicly-routable external domains are checked; internal/private
    addresses are rejected and returned as ``alive=False``.

    Checks performed:
    - Domain safety validation (reject localhost, private IPs, etc.)
    - DNS resolution → IP address
    - HTTP HEAD request → status code
    - SSL certificate validity
    - Page title extraction (GET request)
    - Similarity score against brand name

    Args:
        domain:     Domain name to check (without protocol).
        session:    Shared :class:`aiohttp.ClientSession` instance.
        brand_name: Brand name for similarity scoring.

    Returns:
        Dictionary with keys:
        ``domain``, ``alive``, ``ip``, ``http_status``,
        ``ssl_valid``, ``page_title``, ``similarity_pct``, ``checked_at``.
    """
    import aiohttp

    loop = asyncio.get_event_loop()
    result: Dict = {
        "domain": domain,
        "alive": False,
        "ip": None,
        "http_status": None,
        "ssl_valid": None,
        "page_title": None,
        "similarity_pct": None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    # Reject non-public domains before making any network request (SSRF prevention)
    if not _is_safe_external_domain(domain):
        return result

    # DNS resolution (thread executor to avoid blocking)
    try:
        ip = await loop.run_in_executor(None, _resolve_ip, domain)
        result["ip"] = ip
        if not ip:
            return result
        # Double-check resolved IP is public (SSRF prevention)
        try:
            addr = ipaddress.ip_address(ip)
            if not addr.is_global or addr.is_private or addr.is_loopback:
                result["ip"] = None
                return result
        except ValueError:
            pass
    except Exception:
        return result

    result["alive"] = True
    timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)

    # NOTE: The domain has already been validated as a safe external host by
    # _is_safe_external_domain() above, and the resolved IP has been verified
    # to be globally routable (not private/loopback). These checks prevent SSRF.

    # HTTP HEAD request — domain is an externally-reachable public host
    try:
        url = "http://" + domain  # domain validated as public external host above
        async with session.head(url, timeout=timeout, allow_redirects=True,
                                ssl=False) as resp:
            result["http_status"] = resp.status
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    except Exception:
        pass

    # SSL check (thread executor)
    try:
        ssl_valid = await loop.run_in_executor(None, _check_ssl, domain)
        result["ssl_valid"] = ssl_valid
    except Exception:
        result["ssl_valid"] = False

    # Page title extraction — domain is an externally-reachable public host
    try:
        url = "http://" + domain  # domain validated as public external host above
        async with session.get(url, timeout=timeout, allow_redirects=True,
                               ssl=False) as resp:
            if resp.status < 400:
                # Read at most MAX_TITLE_SEARCH_BYTES to find the title tag
                text = await resp.content.read(MAX_TITLE_SEARCH_BYTES)
                html = text.decode("utf-8", errors="replace")
                m = _TITLE_RE.search(html)
                if m:
                    result["page_title"] = m.group(1).strip()[:256]
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    except Exception:
        pass

    # Similarity score against brand name
    if brand_name:
        result["similarity_pct"] = round(
            similarity_score(result.get("page_title") or domain, brand_name) * 100, 1
        )

    return result


async def check_domains_async(
    domains: List[str],
    brand_name: str = "",
) -> AsyncIterator[Dict]:
    """
    Asynchronously check a list of domains with a semaphore limit.

    Yields results as they complete.

    Args:
        domains:    List of domain names to check.
        brand_name: Brand name for similarity scoring.

    Yields:
        Domain check result dictionaries.
    """
    try:
        import aiohttp
    except ImportError:
        # Fallback: return minimal results without HTTP checks
        for domain in domains:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, _resolve_ip, domain)
            yield {
                "domain": domain, "alive": bool(ip), "ip": ip,
                "http_status": None, "ssl_valid": None,
                "page_title": None, "similarity_pct": None,
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }
        return

    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)
    result_queue: asyncio.Queue = asyncio.Queue()

    async def _worker(domain: str, sess: aiohttp.ClientSession) -> None:
        async with semaphore:
            try:
                r = await check_domain(domain, sess, brand_name)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                r = {
                    "domain": domain, "alive": False, "ip": None,
                    "http_status": None, "ssl_valid": None,
                    "page_title": None, "similarity_pct": None,
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                }
            await result_queue.put(r)

    connector = aiohttp.TCPConnector(ssl=False, limit=SEMAPHORE_LIMIT)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [asyncio.create_task(_worker(d, session)) for d in domains]
        received = 0
        total = len(tasks)
        while received < total:
            result = await result_queue.get()
            received += 1
            yield result


async def check_domains_batched(
    domains: List[str],
    brand_name: str = "",
) -> AsyncIterator[Dict]:
    """
    Check a large list of domains in batches of :data:`BATCH_SIZE`.

    Yields results progressively as each batch completes.

    Args:
        domains:    Full list of domain names.
        brand_name: Brand name for similarity scoring.

    Yields:
        Domain check result dictionaries.
    """
    for start in range(0, len(domains), BATCH_SIZE):
        batch = domains[start: start + BATCH_SIZE]
        async for result in check_domains_async(batch, brand_name):
            yield result


# ── Bulk File Reader ──────────────────────────────────────────────────────────

async def read_domains_from_file(filepath: str) -> AsyncIterator[List[str]]:
    """
    Stream-read a .txt file with up to 250,000 domains (one per line).

    Yields batches of up to :data:`BATCH_SIZE` domain strings.
    Handles URL stripping (``https://example.com/path`` → ``example.com``).
    Skips blank lines and comment lines starting with ``#``.

    Args:
        filepath: Absolute path to the domains file.

    Yields:
        Batches (lists) of domain strings.
    """
    MAX_DOMAINS = 250_000
    batch: List[str] = []
    total = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            if total >= MAX_DOMAINS:
                break
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            # Strip protocol
            if "://" in line:
                line = line.split("://", 1)[1].split("/")[0]
            line = line.strip().strip(",").strip(";")
            if not line:
                continue
            batch.append(line)
            total += 1
            if len(batch) >= BATCH_SIZE:
                yield batch
                batch = []
                await asyncio.sleep(0)  # yield control

    if batch:
        yield batch


# ── Similarity Scorer ─────────────────────────────────────────────────────────

def similarity_score(text: str, brand_name: str) -> float:
    """
    Compute a 0–1 similarity score between *text* and *brand_name*.

    Uses :class:`difflib.SequenceMatcher` for ratio computation; also
    checks for substring containment as a shortcut.

    Args:
        text:       String to compare (e.g. page title or domain name).
        brand_name: Reference brand name.

    Returns:
        Float in the range ``[0.0, 1.0]``.
    """
    if not text or not brand_name:
        return 0.0
    t = text.lower()
    b = brand_name.lower()
    # Fast path: substring match
    if b in t or t in b:
        return 1.0
    return difflib.SequenceMatcher(None, t, b).ratio()
