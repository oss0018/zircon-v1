"""
Look-alike Domain Generation Engine — TS-LAD-001 v1.1 §6.

Implements all 25 permutation algorithms plus the PermutationEngine class.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

# ── RFC 1123 domain label validation ──────────────────────────────────────────
_VALID_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
_VALID_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# ── ALG-03: Keyboard adjacency map (QWERTY) ───────────────────────────────────
KEYBOARD_ADJACENCY: Dict[str, str] = {
    "q": "wa2",      "w": "qase3",    "e": "wsdr4",    "r": "edft5",
    "t": "rfgy6",    "y": "tghu7",    "u": "yhji8",    "i": "ujko9",
    "o": "iklp0",    "p": "ol",
    "a": "qwsz",     "s": "awedxz",   "d": "serfcx",   "f": "drtgvc",
    "g": "ftyhbv",   "h": "gyujnb",   "j": "huikmn",   "k": "jiolm",
    "l": "kop",
    "z": "asx",      "x": "zsdc",     "c": "xdfv",     "v": "cfgb",
    "b": "vghn",     "n": "bhjm",     "m": "njk",
    "1": "q2",       "2": "qw13",     "3": "we24",      "4": "er35",
    "5": "rt46",     "6": "ty57",     "7": "yu68",      "8": "ui79",
    "9": "io80",     "0": "op9",
}

# ── ALG-10: Subdomain words ────────────────────────────────────────────────────
SUBDOMAIN_WORDS: List[str] = [
    "www", "webmail", "mail", "remote", "vpn", "login", "secure", "portal",
    "account", "support", "app", "api", "cdn", "m", "mobile", "admin",
    "auth", "office", "myaccount", "my", "payments", "payment", "checkout",
    "store", "shop", "web", "gateway", "sso", "signin", "signup", "id",
    "identity", "connect", "svc", "service", "beta", "dev", "test",
]

# ── ALG-11 / ALG-24: Attack words ─────────────────────────────────────────────
ATTACK_WORDS_CORE: List[str] = [
    "login", "secure", "account", "bank", "pay", "service", "support",
    "help", "auth", "verify", "update", "confirm", "security", "online",
    "access", "password", "banking", "signin", "signup", "portal",
    "billing", "invoice", "wallet", "transfer", "recovery",
]

ATTACK_WORDS_EXTENDED: List[str] = ATTACK_WORDS_CORE + [
    "info", "news", "official", "group", "inc", "corp", "mail",
    "customer", "shop", "store", "checkout", "deals", "promo",
    "mobile", "app", "web", "digital", "network", "connect",
    "limited", "global", "international", "services", "solutions",
    "download", "install", "upgrade", "renew", "alert", "notice",
]

# ── ALG-12: TLD lists ──────────────────────────────────────────────────────────
TLD_TOP30: List[str] = [
    "com", "net", "org", "info", "biz", "online", "site", "web", "app",
    "io", "co", "me", "tv", "us", "eu", "shop", "store", "xyz", "top",
    "club", "live", "space", "ru", "ua", "uk", "de", "fr", "cn", "pl", "by",
]

TLD_TOP100: List[str] = TLD_TOP30 + [
    "ca", "au", "jp", "br", "in", "mx", "nl", "se", "no", "fi",
    "dk", "ch", "at", "be", "cz", "sk", "hu", "ro", "bg", "hr",
    "lt", "lv", "ee", "si", "pt", "es", "it", "gr", "tr", "il",
    "za", "ng", "ke", "eg", "sa", "ae", "pk", "bd", "th", "vn",
    "id", "ph", "sg", "my", "nz", "ar", "cl", "co", "pe", "ve",
    "pro", "mobi", "name", "tel", "travel", "jobs", "academy", "agency",
    "cash", "click", "cloud", "digital", "expert", "finance", "fund",
    "global", "health", "media", "network", "news", "solutions", "tech",
]

# For top500 and full1500 we fall back to top100 for now
TLD_TOP500 = TLD_TOP100
TLD_FULL1500 = TLD_TOP100

TLD_LISTS: Dict[str, List[str]] = {
    "top30": TLD_TOP30,
    "top100": TLD_TOP100,
    "top500": TLD_TOP500,
    "full1500": TLD_FULL1500,
}

# ── ALG-14: Consonant substitutions ───────────────────────────────────────────
CONSONANT_SUBS: Dict[str, List[str]] = {
    "ph": ["f"],
    "f": ["ph"],
    "ck": ["k", "c"],
    "k": ["c", "ck"],
    "c": ["k", "s"],
    "s": ["c", "z"],
    "z": ["s"],
    "x": ["ks", "cs"],
    "qu": ["kw", "k"],
    "gh": ["g", "f"],
    "tion": ["shun", "sion"],
    "sion": ["tion"],
    "ight": ["ite", "it"],
    "ough": ["off", "uf"],
    "th": ["t", "d"],
    "wh": ["w"],
    "wr": ["r"],
    "kn": ["n"],
    "gn": ["n"],
    "mb": ["m"],
    "mn": ["n"],
    "dg": ["j", "g"],
    "tch": ["ch"],
}

# ── ALG-15: Bitsquatting helper ────────────────────────────────────────────────
def _bitsquat_variants(label: str) -> List[str]:
    """Flip each bit of each ASCII char in the label."""
    variants = []
    for i, ch in enumerate(label):
        code = ord(ch)
        for bit in range(8):
            flipped = code ^ (1 << bit)
            if 32 <= flipped <= 126:  # printable ASCII only
                new_ch = chr(flipped)
                # Must remain a valid label char
                if re.match(r"[a-zA-Z0-9\-]", new_ch):
                    variant = label[:i] + new_ch.lower() + label[i + 1:]
                    if variant != label:
                        variants.append(variant)
    return list(dict.fromkeys(variants))  # deduplicate, preserve order

# ── ALG-16: ASCII homoglyphs ───────────────────────────────────────────────────
ASCII_HOMOGLYPHS: Dict[str, List[str]] = {
    "a": ["4", "@"],
    "b": ["6", "d"],
    "c": ["("],
    "d": ["b", "cl"],
    "e": ["3"],
    "g": ["9", "q"],
    "h": ["n"],
    "i": ["1", "l", "!"],
    "l": ["1", "i"],
    "m": ["rn", "nn"],
    "n": ["m", "ii"],
    "o": ["0", "q"],
    "q": ["9", "g"],
    "rn": ["m"],
    "s": ["5", "z"],
    "t": ["7"],
    "u": ["v"],
    "v": ["u"],
    "w": ["vv", "uu"],
    "z": ["2", "s"],
}

# ── ALG-17: Unicode homoglyphs (Cyrillic/Greek ↔ Latin) ───────────────────────
# Maps protected_domain Latin char → list of Unicode lookalike chars
UNICODE_HOMOGLYPHS: Dict[str, List[str]] = {
    "a": ["\u0430"],          # Cyrillic а
    "b": ["\u0432"],          # Cyrillic в (approximate)
    "c": ["\u0441"],          # Cyrillic с
    "d": ["\u0501"],          # Cyrillic d-like
    "e": ["\u0435", "\u04bd"],# Cyrillic е, Ё approx
    "g": ["\u0261"],          # Latin small g with hook
    "h": ["\u04bb"],          # Cyrillic shha
    "i": ["\u0456", "\u04cf"],# Cyrillic і, і
    "j": ["\u0458"],          # Cyrillic je
    "k": ["\u043a"],          # Cyrillic к
    "l": ["\u04c0", "\u0031"],# Cyrillic palochka, digit 1
    "m": ["\u043c"],          # Cyrillic м
    "n": ["\u0578", "\u0459"],# Armenian vo, Cyrillic lje
    "o": ["\u043e", "\u03bf"],# Cyrillic о, Greek ο
    "p": ["\u0440", "\u03c1"],# Cyrillic р, Greek ρ
    "q": ["\u0563"],          # Armenian ben
    "r": ["\u0433"],          # Cyrillic г (approximate)
    "s": ["\u0455"],          # Cyrillic dze
    "t": ["\u0442"],          # Cyrillic т
    "u": ["\u0446", "\u03c5"],# Cyrillic ц, Greek υ
    "v": ["\u03bd"],          # Greek ν
    "w": ["\u0448"],          # Cyrillic ш (approximate)
    "x": ["\u0445", "\u03c7"],# Cyrillic х, Greek χ
    "y": ["\u0443", "\u03b3"],# Cyrillic у, Greek γ
    "z": ["\u0290"],          # Latin small z with retroflex hook
}

# ── ALG-18: Script mixing (Cyrillic/Latin whole-word) ─────────────────────────
# Full label substitution: replace all Latin chars with Cyrillic equivalents
CYRILLIC_MAP: Dict[str, str] = {
    "a": "\u0430", "b": "\u0432", "c": "\u0441", "e": "\u0435",
    "h": "\u0570", "i": "\u0456", "j": "\u0458", "k": "\u043a",
    "m": "\u043c", "o": "\u043e", "p": "\u0440", "r": "\u0433",
    "s": "\u0455", "t": "\u0442", "u": "\u0446", "v": "\u03bd",
    "x": "\u0445", "y": "\u0443",
}

# ── ALG-21: Phonetic substitutions ────────────────────────────────────────────
PHONETIC_SUBSTITUTIONS: Dict[str, List[str]] = {
    "ph": ["f"],
    "f": ["ph"],
    "ck": ["k"],
    "k": ["ck", "c"],
    "qu": ["kw"],
    "x": ["z", "ks"],
    "z": ["x", "s"],
    "c": ["s", "k"],
    "s": ["z", "c"],
    "th": ["d", "t"],
    "tion": ["shun"],
    "sion": ["shun"],
    "ight": ["ite"],
    "ough": ["uf", "off"],
    "ew": ["oo", "u"],
    "oo": ["ew", "u"],
    "ei": ["ay", "ee"],
    "ie": ["ee", "i"],
    "ea": ["ee", "e"],
    "ai": ["ay", "a"],
    "ay": ["ai", "ey"],
}

# ── ALG-23: Leet substitution map ────────────────────────────────────────────
LEET_MAP: Dict[str, List[str]] = {
    "a": ["4", "@"],
    "b": ["8", "6"],
    "c": ["("],
    "e": ["3"],
    "g": ["9"],
    "h": ["#"],
    "i": ["1", "!"],
    "l": ["1", "|"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7", "+"],
    "z": ["2"],
}

# ── Zone extensions for ALG-25 ────────────────────────────────────────────────
ZONE_EXTENSIONS: Dict[str, List[str]] = {
    "ua": ["ua.com", "com.ua", "in.ua", "kiev.ua", "kharkiv.ua"],
    "ru": ["ru.com", "com.ru", "msk.ru", "spb.ru"],
    "uk": ["co.uk", "org.uk", "me.uk", "net.uk"],
    "de": ["de.com"],
    "fr": ["fr.com"],
    "au": ["com.au", "net.au", "org.au"],
    "br": ["com.br", "net.br", "org.br"],
    "cn": ["com.cn", "net.cn", "org.cn"],
    "in": ["co.in", "net.in", "org.in"],
    "us": ["us.com"],
}

# ── Common phishing keywords ──────────────────────────────────────────────────
PHISHING_KEYWORDS: List[str] = [
    "login", "signin", "bank", "secure", "verify", "account", "update",
    "password", "credential", "auth", "billing", "invoice", "payment",
    "wallet", "transfer", "support", "helpdesk", "recovery", "reset",
]


# ── Configuration dataclass ────────────────────────────────────────────────────

@dataclass
class GenerationConfig:
    """Configuration for the PermutationEngine."""
    tld_list: str = "top100"               # top30|top100|top500|full1500
    attack_words: str = "core"             # core|extended
    include_idn: bool = True
    include_bitsquatting: bool = True
    max_variants: int = 10000
    similarity_threshold_pct: int = 70     # 30–100
    algorithms: List[str] = field(default_factory=list)  # empty = all
    custom_tlds: List[str] = field(default_factory=list)


# ── Generation result dataclass ────────────────────────────────────────────────

@dataclass
class GenerationResult:
    """Result of generate_and_filter()."""
    variants: List[dict]
    raw_count: int
    filtered_count: int
    threshold_pct: int
    filtered_out: int


# ── PermutationEngine ──────────────────────────────────────────────────────────

class PermutationEngine:
    """
    25-algorithm lookalike domain permutation engine (§6.2–6.4).

    Usage::

        engine = PermutationEngine(config)
        result = engine.generate_and_filter("kyivstar.ua")
        # result.variants → list of variant dicts
    """

    def __init__(self, config: Optional[GenerationConfig] = None) -> None:
        self.config = config or GenerationConfig()
        self._tlds = (
            self.config.custom_tlds
            if self.config.custom_tlds
            else TLD_LISTS.get(self.config.tld_list, TLD_TOP100)
        )
        self._attack_words = (
            ATTACK_WORDS_EXTENDED
            if self.config.attack_words == "extended"
            else ATTACK_WORDS_CORE
        )
        self._active_algs: Optional[Set[str]] = (
            set(self.config.algorithms) if self.config.algorithms else None
        )  # None means all algorithms

    def _alg_enabled(self, alg_id: str) -> bool:
        return self._active_algs is None or alg_id in self._active_algs

    # ── Public API ──────────────────────────────────────────────────────────

    def generate(self, domain: str) -> List[dict]:
        """
        Generate variant dicts for *domain*.

        Returns list of dicts with keys:
        ``fqdn``, ``label``, ``tld``, ``algorithms``,
        ``levenshtein_distance``, ``is_idn``, ``unicode_form``.
        """
        domain = domain.lower().strip().rstrip(".")
        if not domain:
            return []

        parts = domain.split(".")
        if len(parts) < 2:
            return []

        protected_label = parts[0]
        original_tld = ".".join(parts[1:])

        seen: Set[str] = {domain}
        variants: List[dict] = []

        def _emit(
            label: str,
            tld: str,
            alg_ids: List[str],
            is_idn: bool = False,
            unicode_form: Optional[str] = None,
        ) -> None:
            fqdn = f"{label}.{tld}"
            key = fqdn.lower()
            if key in seen or not self._is_valid_domain(fqdn):
                return
            seen.add(key)
            try:
                from Levenshtein import distance as lev_dist  # type: ignore
                dist = lev_dist(label, protected_label)
            except ImportError:
                dist = _simple_levenshtein(label, protected_label)
            variants.append({
                "fqdn": fqdn,
                "label": label,
                "tld": tld,
                "algorithms": alg_ids,
                "levenshtein_distance": dist,
                "is_idn": is_idn,
                "unicode_form": unicode_form,
            })

        # ALG-01: char_omission
        if self._alg_enabled("ALG-01"):
            for i in range(len(protected_label)):
                variant = protected_label[:i] + protected_label[i + 1:]
                if len(variant) >= 2:
                    _emit(variant, original_tld, ["ALG-01"])
                    for tld in self._tlds[:15]:
                        _emit(variant, tld, ["ALG-01"])

        # ALG-02: char_transposition
        if self._alg_enabled("ALG-02"):
            for i in range(len(protected_label) - 1):
                t = list(protected_label)
                t[i], t[i + 1] = t[i + 1], t[i]
                variant = "".join(t)
                _emit(variant, original_tld, ["ALG-02"])
                for tld in self._tlds[:10]:
                    _emit(variant, tld, ["ALG-02"])

        # ALG-03: char_replacement_keyboard
        if self._alg_enabled("ALG-03"):
            for i, ch in enumerate(protected_label):
                for adj in KEYBOARD_ADJACENCY.get(ch, ""):
                    variant = protected_label[:i] + adj + protected_label[i + 1:]
                    _emit(variant, original_tld, ["ALG-03"])
                    for tld in self._tlds[:10]:
                        _emit(variant, tld, ["ALG-03"])

        # ALG-04: char_repetition
        if self._alg_enabled("ALG-04"):
            for i, ch in enumerate(protected_label):
                variant = protected_label[:i] + ch + protected_label[i:]
                _emit(variant, original_tld, ["ALG-04"])

        # ALG-05: char_insertion
        if self._alg_enabled("ALG-05"):
            for i in range(len(protected_label) - 1):
                ch = protected_label[i]
                for ins in KEYBOARD_ADJACENCY.get(ch, "")[:3]:
                    variant = protected_label[:i + 1] + ins + protected_label[i + 1:]
                    _emit(variant, original_tld, ["ALG-05"])

        # ALG-06: missing_dot
        if self._alg_enabled("ALG-06") and "." in original_tld:
            # Remove dots: merge label + tld parts
            merged = protected_label + original_tld.replace(".", "")
            for tld in self._tlds[:20]:
                _emit(merged, tld, ["ALG-06"])

        # ALG-07: dot_insertion
        if self._alg_enabled("ALG-07"):
            for i in range(1, len(protected_label)):
                left = protected_label[:i]
                right = protected_label[i:]
                _emit(f"{left}.{right}", original_tld, ["ALG-07"])

        # ALG-08: hyphenation
        if self._alg_enabled("ALG-08"):
            for i in range(1, len(protected_label)):
                variant = protected_label[:i] + "-" + protected_label[i:]
                _emit(variant, original_tld, ["ALG-08"])
                for tld in self._tlds[:10]:
                    _emit(variant, tld, ["ALG-08"])

        # ALG-09: hyphen_omission
        if self._alg_enabled("ALG-09") and "-" in protected_label:
            variant = protected_label.replace("-", "")
            _emit(variant, original_tld, ["ALG-09"])
            for tld in self._tlds[:20]:
                _emit(variant, tld, ["ALG-09"])

        # ALG-10: subdomain_injection
        if self._alg_enabled("ALG-10"):
            for sub in SUBDOMAIN_WORDS:
                label = f"{sub}-{protected_label}"
                _emit(label, original_tld, ["ALG-10"])
                for tld in self._tlds[:10]:
                    _emit(label, tld, ["ALG-10"])

        # ALG-11: keyword_append_prepend
        if self._alg_enabled("ALG-11"):
            for word in self._attack_words:
                for tld in self._tlds[:15]:
                    _emit(f"{protected_label}-{word}", tld, ["ALG-11"])
                    _emit(f"{word}-{protected_label}", tld, ["ALG-11"])
                    _emit(f"{protected_label}{word}", tld, ["ALG-11"])
                    _emit(f"{word}{protected_label}", tld, ["ALG-11"])

        # ALG-12: tld_swap
        if self._alg_enabled("ALG-12"):
            for tld in self._tlds:
                if tld != original_tld:
                    _emit(protected_label, tld, ["ALG-12"])

        # ALG-13: vowel_swap
        if self._alg_enabled("ALG-13"):
            vowels = "aeiou"
            for i, ch in enumerate(protected_label):
                if ch.lower() in vowels:
                    for v in vowels:
                        if v != ch.lower():
                            variant = protected_label[:i] + v + protected_label[i + 1:]
                            _emit(variant, original_tld, ["ALG-13"])
                            for tld in self._tlds[:10]:
                                _emit(variant, tld, ["ALG-13"])

        # ALG-14: consonant_replacement
        if self._alg_enabled("ALG-14"):
            for src, replacements in CONSONANT_SUBS.items():
                if src in protected_label:
                    for rep in replacements:
                        variant = protected_label.replace(src, rep, 1)
                        _emit(variant, original_tld, ["ALG-14"])
                        for tld in self._tlds[:10]:
                            _emit(variant, tld, ["ALG-14"])

        # ALG-15: bitsquatting
        if self._alg_enabled("ALG-15") and self.config.include_bitsquatting:
            for bsq in _bitsquat_variants(protected_label):
                _emit(bsq, original_tld, ["ALG-15"])
                for tld in self._tlds[:10]:
                    _emit(bsq, tld, ["ALG-15"])

        # ALG-16: ascii_homoglyph
        if self._alg_enabled("ALG-16"):
            for src, replacements in ASCII_HOMOGLYPHS.items():
                if src in protected_label:
                    for rep in replacements:
                        variant = protected_label.replace(src, rep, 1)
                        if self._is_valid_label(variant):
                            _emit(variant, original_tld, ["ALG-16"])
                            for tld in self._tlds[:10]:
                                _emit(variant, tld, ["ALG-16"])

        # ALG-17: unicode_homoglyph (generate both punycode and unicode forms)
        if self._alg_enabled("ALG-17") and self.config.include_idn:
            for src, uni_chars in UNICODE_HOMOGLYPHS.items():
                if src in protected_label:
                    for uc in uni_chars:
                        unicode_label = protected_label.replace(src, uc, 1)
                        try:
                            punycode_label = unicode_label.encode("idna").decode("ascii").rstrip(".")
                        except (UnicodeError, UnicodeDecodeError):
                            continue
                        # punycode_label may include .xn-- prefix for the label only
                        # For fqdn use punycode form
                        fqdn_puny = f"{punycode_label}.{original_tld}"
                        fqdn_uni = f"{unicode_label}.{original_tld}"
                        key = fqdn_puny.lower()
                        if key not in seen:
                            seen.add(key)
                            try:
                                from Levenshtein import distance as lev_dist  # type: ignore
                                dist = lev_dist(unicode_label, protected_label)
                            except ImportError:
                                dist = _simple_levenshtein(unicode_label, protected_label)
                            variants.append({
                                "fqdn": fqdn_puny,
                                "label": punycode_label,
                                "tld": original_tld,
                                "algorithms": ["ALG-17"],
                                "levenshtein_distance": dist,
                                "is_idn": True,
                                "unicode_form": fqdn_uni,
                            })

        # ALG-18: script_mixing (Cyrillic/Latin whole-word)
        if self._alg_enabled("ALG-18") and self.config.include_idn:
            mixed = "".join(CYRILLIC_MAP.get(ch, ch) for ch in protected_label)
            if mixed != protected_label:
                try:
                    puny = mixed.encode("idna").decode("ascii").rstrip(".")
                    fqdn_puny = f"{puny}.{original_tld}"
                    fqdn_uni = f"{mixed}.{original_tld}"
                    key = fqdn_puny.lower()
                    if key not in seen:
                        seen.add(key)
                        variants.append({
                            "fqdn": fqdn_puny,
                            "label": puny,
                            "tld": original_tld,
                            "algorithms": ["ALG-18"],
                            "levenshtein_distance": 0,
                            "is_idn": True,
                            "unicode_form": fqdn_uni,
                        })
                except (UnicodeError, UnicodeDecodeError):
                    pass

        # ALG-19: domain_level_addition (append TLD as extra label)
        if self._alg_enabled("ALG-19"):
            tld_as_label = original_tld.replace(".", "-")
            for tld in self._tlds[:20]:
                _emit(f"{protected_label}-{tld_as_label}", tld, ["ALG-19"])
                _emit(f"{protected_label}.{original_tld.split('.')[0]}", tld, ["ALG-19"])

        # ALG-20: brand_in_subdomain
        if self._alg_enabled("ALG-20"):
            for word in self._attack_words[:10]:
                for tld in self._tlds[:10]:
                    # brand as subdomain: brand.attacker.tld
                    _emit(f"{protected_label}.{word}", tld, ["ALG-20"])
                    _emit(f"{protected_label}-{word}", tld, ["ALG-20"])

        # ALG-21: soundalike (phonetic substitutions)
        if self._alg_enabled("ALG-21"):
            for src, replacements in PHONETIC_SUBSTITUTIONS.items():
                if src in protected_label:
                    for rep in replacements:
                        variant = protected_label.replace(src, rep, 1)
                        if variant != protected_label and len(variant) >= 2:
                            _emit(variant, original_tld, ["ALG-21"])
                            for tld in self._tlds[:10]:
                                _emit(variant, tld, ["ALG-21"])

        # ALG-22: abbreviations (singular/plural/abbreviation variants)
        if self._alg_enabled("ALG-22"):
            # Plural/singular
            if protected_label.endswith("s") and len(protected_label) > 3:
                _emit(protected_label[:-1], original_tld, ["ALG-22"])
            else:
                _emit(protected_label + "s", original_tld, ["ALG-22"])
            # Abbreviation: first letters of hyphen-separated parts
            if "-" in protected_label:
                abbrev = "".join(p[0] for p in protected_label.split("-") if p)
                if len(abbrev) >= 2:
                    for tld in self._tlds[:20]:
                        _emit(abbrev, tld, ["ALG-22"])
            # Remove doubled letters
            dedup = re.sub(r"(.)\1+", r"\1", protected_label)
            if dedup != protected_label:
                _emit(dedup, original_tld, ["ALG-22"])

        # ALG-23: leet_substitution
        if self._alg_enabled("ALG-23"):
            for src, replacements in LEET_MAP.items():
                if src in protected_label:
                    for rep in replacements:
                        variant = protected_label.replace(src, rep, 1)
                        if self._is_valid_label(variant):
                            _emit(variant, original_tld, ["ALG-23"])
                            for tld in self._tlds[:10]:
                                _emit(variant, tld, ["ALG-23"])

        # ALG-24: combosquatting (full combinatorial brand × attack_words × TLDs)
        if self._alg_enabled("ALG-24"):
            for word in self._attack_words:
                for tld in self._tlds[:20]:
                    _emit(f"{protected_label}-{word}", tld, ["ALG-24"])
                    _emit(f"{word}-{protected_label}", tld, ["ALG-24"])

        # ALG-25: zone_extension (country-specific zone extensions)
        if self._alg_enabled("ALG-25"):
            for _tld, zone_list in ZONE_EXTENSIONS.items():
                for zone in zone_list:
                    # e.g. brand.ua.com
                    zone_parts = zone.split(".")
                    if len(zone_parts) == 2:
                        _emit(protected_label, zone, ["ALG-25"])
                    elif len(zone_parts) >= 3:
                        # e.g. brand.com.ua → label=brand-com, tld=ua
                        _emit(f"{protected_label}-{zone_parts[0]}", ".".join(zone_parts[1:]), ["ALG-25"])

        return variants

    def _prioritise(self, variants: List[dict]) -> List[dict]:
        """When over ceiling keep lowest Levenshtein distance first."""
        return sorted(variants, key=lambda v: (v.get("levenshtein_distance") or 999, v["fqdn"]))

    def _is_valid_domain(self, fqdn: str) -> bool:
        """RFC 1123 domain validation."""
        if not fqdn or len(fqdn) > 253:
            return False
        labels = fqdn.split(".")
        if len(labels) < 2:
            return False
        for label in labels:
            if not label or len(label) > 63:
                return False
            if not _VALID_LABEL_RE.match(label):
                return False
        return True

    def _is_valid_label(self, label: str) -> bool:
        """Check that *label* is a valid DNS label."""
        if not label or len(label) > 63:
            return False
        return bool(_VALID_LABEL_RE.match(label))

    def generate_and_filter(
        self,
        domain: str,
        simulate_threshold: Optional[int] = None,
    ) -> "GenerationResult":
        """
        Generate variants, filter by similarity threshold, apply ceiling (§6.5.3).

        ALG-12 (tld_swap only) variants always pass regardless of threshold.
        """
        from app.services.lookalike.similarity import SimilarityCalculator

        raw = self.generate(domain)
        raw_count = len(raw)

        threshold = simulate_threshold if simulate_threshold is not None else self.config.similarity_threshold_pct
        threshold_ratio = threshold / 100.0

        # Extract the protected label (part before TLD)
        parts = domain.lower().split(".")
        protected_label = parts[0]

        calc = SimilarityCalculator()
        filtered: List[dict] = []
        filtered_out: List[dict] = []

        for v in raw:
            # ALG-12 variants always pass
            if v["algorithms"] == ["ALG-12"]:
                filtered.append(v)
                continue
            score = calc.compute(v["label"], protected_label)
            v["similarity_score"] = round(score, 4)
            if score >= threshold_ratio:
                filtered.append(v)
            else:
                filtered_out.append(v)

        # Apply ceiling
        prioritised = self._prioritise(filtered)
        if len(prioritised) > self.config.max_variants:
            prioritised = prioritised[: self.config.max_variants]

        return GenerationResult(
            variants=prioritised,
            raw_count=raw_count,
            filtered_count=len(prioritised),
            threshold_pct=threshold,
            filtered_out=len(filtered_out),
        )


# ── Simple Levenshtein fallback ────────────────────────────────────────────────

def _simple_levenshtein(s1: str, s2: str) -> int:
    """Pure-Python Levenshtein distance (fallback when python-Levenshtein not installed)."""
    if len(s1) < len(s2):
        return _simple_levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(
                prev[j + 1] + 1,
                curr[j] + 1,
                prev[j] + (0 if c1 == c2 else 1),
            ))
        prev = curr
    return prev[-1]
