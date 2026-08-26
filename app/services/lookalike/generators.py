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
# The lists below are organised the way IANA itself classifies top-level
# domains in the DNS root zone (see https://www.iana.org/domains/root/db),
# plus an IDN bucket for internationalized (non-ASCII) TLDs. TLD_TOP30/
# TLD_TOP100 remain small curated "most abused" shortlists for fast scans;
# everything else below widens coverage so a rule can search essentially
# every real TLD that a look-alike domain could be registered under.
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

# ── Generic TLDs (gTLD) ────────────────────────────────────────────────────────
# Unrestricted generic TLDs (legacy + new gTLD program), e.g. .com, .app,
# .dev, .blog. Snapshot derived from the IANA Root Zone Database, minus the
# sponsored / restricted-generic / infrastructure strings tracked separately
# below (~1,000+ entries).
TLD_GENERIC: List[str] = [
    "aaa", "aarp", "abb", "abbott", "abbvie", "abc", "able", "abogado", "abudhabi",
    "academy", "accenture", "accountant", "accountants", "aco", "actor", "ads",
    "adult", "aeg", "aetna", "afl", "africa", "agakhan", "agency", "aig", "airbus",
    "airforce", "airtel", "akdn", "alibaba", "alipay", "allfinanz", "allstate", "ally",
    "alsace", "alstom", "amazon", "americanexpress", "americanfamily", "amex", "amfam",
    "amica", "amsterdam", "analytics", "android", "anquan", "anz", "aol", "apartments",
    "app", "apple", "aquarelle", "arab", "aramco", "archi", "army", "art", "arte",
    "asda", "associates", "athleta", "attorney", "auction", "audi", "audible", "audio",
    "auspost", "author", "auto", "autos", "aws", "axa", "azure", "baby", "baidu",
    "banamex", "band", "bank", "bar", "barcelona", "barclaycard", "barclays",
    "barefoot", "bargains", "baseball", "basketball", "bauhaus", "bayern", "bbc",
    "bbt", "bbva", "bcg", "bcn", "beats", "beauty", "beer", "berlin", "best",
    "bestbuy", "bet", "bharti", "bible", "bid", "bike", "bing", "bingo", "bio",
    "black", "blackfriday", "blockbuster", "blog", "bloomberg", "blue", "bms", "bmw",
    "bnpparibas", "boats", "boehringer", "bofa", "bom", "bond", "boo", "book",
    "booking", "bosch", "bostik", "boston", "bot", "boutique", "box", "bradesco",
    "bridgestone", "broadway", "broker", "brother", "brussels", "build", "builders",
    "business", "buy", "buzz", "bzh", "cab", "cafe", "cal", "call", "calvinklein",
    "cam", "camera", "camp", "canon", "capetown", "capital", "capitalone", "car",
    "caravan", "cards", "care", "career", "careers", "cars", "casa", "case", "cash",
    "casino", "catering", "catholic", "cba", "cbn", "cbre", "center", "ceo", "cern",
    "cfa", "cfd", "chanel", "channel", "charity", "chase", "chat", "cheap", "chintai",
    "christmas", "chrome", "church", "cipriani", "circle", "cisco", "citadel", "citi",
    "citic", "city", "claims", "cleaning", "click", "clinic", "clinique", "clothing",
    "cloud", "club", "clubmed", "coach", "codes", "coffee", "college", "cologne",
    "com", "commbank", "community", "company", "compare", "computer", "comsec",
    "condos", "construction", "consulting", "contact", "contractors", "cooking",
    "cool", "corsica", "country", "coupon", "coupons", "courses", "cpa", "credit",
    "creditcard", "creditunion", "cricket", "crown", "crs", "cruise", "cruises",
    "cuisinella", "cymru", "cyou", "dad", "dance", "data", "date", "dating", "datsun",
    "day", "dclk", "dds", "deal", "dealer", "deals", "degree", "delivery", "dell",
    "deloitte", "delta", "democrat", "dental", "dentist", "desi", "design", "dev",
    "dhl", "diamonds", "diet", "digital", "direct", "directory", "discount",
    "discover", "dish", "diy", "dnp", "docs", "doctor", "dog", "domains", "dot",
    "download", "drive", "dtv", "dubai", "dupont", "durban", "dvag", "dvr", "earth",
    "eat", "eco", "edeka", "education", "email", "emerck", "energy", "engineer",
    "engineering", "enterprises", "epson", "equipment", "ericsson", "erni", "esq",
    "estate", "eurovision", "eus", "events", "exchange", "expert", "exposed",
    "express", "extraspace", "fage", "fail", "fairwinds", "faith", "family", "fan",
    "fans", "farm", "farmers", "fashion", "fast", "fedex", "feedback", "ferrari",
    "ferrero", "fidelity", "fido", "film", "final", "finance", "financial", "fire",
    "firestone", "firmdale", "fish", "fishing", "fit", "fitness", "flickr", "flights",
    "flir", "florist", "flowers", "fly", "foo", "food", "football", "ford", "forex",
    "forsale", "forum", "foundation", "fox", "free", "fresenius", "frl", "frogans",
    "frontier", "ftr", "fujitsu", "fun", "fund", "furniture", "futbol", "fyi", "gal",
    "gallery", "gallo", "gallup", "game", "games", "gap", "garden", "gay", "gbiz",
    "gdn", "gea", "gent", "genting", "george", "ggee", "gift", "gifts", "gives",
    "giving", "glass", "gle", "global", "globo", "gmail", "gmbh", "gmo", "gmx",
    "godaddy", "gold", "goldpoint", "golf", "goodyear", "goog", "google", "gop", "got",
    "grainger", "graphics", "gratis", "green", "gripe", "grocery", "group", "gucci",
    "guge", "guide", "guitars", "guru", "hair", "hamburg", "hangout", "haus", "hbo",
    "hdfc", "hdfcbank", "health", "healthcare", "help", "helsinki", "here", "hermes",
    "hiphop", "hisamitsu", "hitachi", "hiv", "hkt", "hockey", "holdings", "holiday",
    "homedepot", "homegoods", "homes", "homesense", "honda", "horse", "hospital",
    "host", "hosting", "hot", "hotels", "hotmail", "house", "how", "hsbc", "hughes",
    "hyatt", "hyundai", "ibm", "icbc", "ice", "icu", "ieee", "ifm", "ikano", "imamat",
    "imdb", "immo", "immobilien", "inc", "industries", "infiniti", "info", "ing",
    "ink", "institute", "insurance", "insure", "international", "intuit",
    "investments", "ipiranga", "irish", "ismaili", "ist", "istanbul", "itau", "itv",
    "jaguar", "java", "jcb", "jeep", "jetzt", "jewelry", "jio", "jll", "jmp", "jnj",
    "joburg", "jot", "joy", "jpmorgan", "jprs", "juegos", "juniper", "kaufen", "kddi",
    "kerryhotels", "kerryproperties", "kfh", "kia", "kids", "kim", "kindle", "kitchen",
    "kiwi", "koeln", "komatsu", "kosher", "kpmg", "kpn", "krd", "kred", "kuokgroup",
    "kyoto", "lacaixa", "lamborghini", "lamer", "land", "landrover", "lanxess",
    "lasalle", "lat", "latino", "latrobe", "law", "lawyer", "lds", "lease", "leclerc",
    "lefrak", "legal", "lego", "lexus", "lgbt", "lidl", "life", "lifeinsurance",
    "lifestyle", "lighting", "like", "lilly", "limited", "limo", "lincoln", "link",
    "live", "living", "llc", "llp", "loan", "loans", "locker", "locus", "lol",
    "london", "lotte", "lotto", "love", "lpl", "lplfinancial", "ltd", "ltda",
    "lundbeck", "luxe", "luxury", "madrid", "maif", "maison", "makeup", "man",
    "management", "mango", "map", "market", "marketing", "markets", "marriott",
    "marshalls", "mattel", "mba", "mckinsey", "med", "media", "meet", "melbourne",
    "meme", "memorial", "men", "menu", "merck", "merckmsd", "miami", "microsoft",
    "mini", "mint", "mit", "mitsubishi", "mlb", "mls", "mma", "mobi", "mobile", "moda",
    "moe", "moi", "mom", "monash", "money", "monster", "mormon", "mortgage", "moscow",
    "moto", "motorcycles", "mov", "movie", "msd", "mtn", "mtr", "music", "nab",
    "nagoya", "navy", "nba", "nec", "net", "netbank", "netflix", "network", "neustar",
    "new", "news", "next", "nextdirect", "nexus", "nfl", "ngo", "nhk", "nico", "nike",
    "nikon", "ninja", "nissan", "nissay", "nokia", "norton", "now", "nowruz", "nowtv",
    "nra", "nrw", "ntt", "nyc", "obi", "observer", "office", "okinawa", "olayan",
    "olayangroup", "ollo", "omega", "one", "ong", "onl", "online", "ooo", "open",
    "oracle", "orange", "org", "organic", "origins", "osaka", "otsuka", "ott", "ovh",
    "page", "panasonic", "paris", "pars", "partners", "parts", "party", "pay", "pccw",
    "pet", "pfizer", "pharmacy", "phd", "philips", "phone", "photo", "photography",
    "photos", "physio", "pics", "pictet", "pictures", "pid", "pin", "ping", "pink",
    "pioneer", "pizza", "place", "play", "playstation", "plumbing", "plus", "pnc",
    "pohl", "poker", "politie", "porn", "praxi", "press", "prime", "prod",
    "productions", "prof", "progressive", "promo", "properties", "property",
    "protection", "pru", "prudential", "pub", "pwc", "qpon", "quebec", "quest",
    "racing", "radio", "read", "realestate", "realtor", "realty", "recipes", "red",
    "redumbrella", "rehab", "reise", "reisen", "reit", "reliance", "ren", "rent",
    "rentals", "repair", "report", "republican", "rest", "restaurant", "review",
    "reviews", "rexroth", "rich", "richardli", "ricoh", "ril", "rio", "rip", "rocks",
    "rodeo", "rogers", "room", "rsvp", "rugby", "ruhr", "run", "rwe", "ryukyu",
    "saarland", "safe", "safety", "sakura", "sale", "salon", "samsclub", "samsung",
    "sandvik", "sandvikcoromant", "sanofi", "sap", "sarl", "sas", "save", "saxo",
    "sbi", "sbs", "scb", "schaeffler", "schmidt", "scholarships", "school", "schule",
    "schwarz", "science", "scot", "search", "seat", "secure", "security", "seek",
    "select", "sener", "services", "seven", "sew", "sex", "sexy", "sfr", "shangrila",
    "sharp", "shell", "shia", "shiksha", "shoes", "shop", "shopping", "shouji", "show",
    "silk", "sina", "singles", "site", "ski", "skin", "sky", "skype", "sling", "smart",
    "smile", "sncf", "soccer", "social", "softbank", "software", "sohu", "solar",
    "solutions", "song", "sony", "soy", "spa", "space", "sport", "spot", "srl",
    "stada", "staples", "star", "statebank", "statefarm", "stc", "stcgroup",
    "stockholm", "storage", "store", "stream", "studio", "study", "style", "sucks",
    "supplies", "supply", "support", "surf", "surgery", "suzuki", "swatch", "swiss",
    "sydney", "systems", "tab", "taipei", "talk", "taobao", "target", "tatamotors",
    "tatar", "tattoo", "tax", "taxi", "tci", "tdk", "team", "tech", "technology",
    "temasek", "tennis", "teva", "thd", "theater", "theatre", "tiaa", "tickets",
    "tienda", "tips", "tires", "tirol", "tjmaxx", "tjx", "tkmaxx", "tmall", "today",
    "tokyo", "tools", "top", "toray", "toshiba", "total", "tours", "town", "toyota",
    "toys", "trade", "trading", "training", "travelers", "travelersinsurance", "trust",
    "trv", "tube", "tui", "tunes", "tushu", "tvs", "ubank", "ubs", "unicom",
    "university", "uno", "uol", "ups", "vacations", "vana", "vanguard", "vegas",
    "ventures", "verisign", "versicherung", "vet", "viajes", "video", "vig", "viking",
    "villas", "vin", "vip", "virgin", "visa", "vision", "viva", "vivo", "vlaanderen",
    "vodka", "volvo", "vote", "voting", "voto", "voyage", "wales", "walmart", "walter",
    "wang", "wanggou", "watch", "watches", "weather", "weatherchannel", "web",
    "webcam", "weber", "website", "wed", "wedding", "weibo", "weir", "whoswho", "wien",
    "wiki", "williamhill", "win", "windows", "wine", "winners", "wme", "woodside",
    "work", "works", "world", "wow", "wtc", "wtf", "xbox", "xerox", "xihuan", "xin",
    "xyz", "yachts", "yahoo", "yamaxun", "yandex", "yodobashi", "yoga", "yokohama",
    "you", "youtube", "yun", "zappos", "zara", "zero", "zip", "zone", "zuerich",
]

# ── Country-Code TLDs (ccTLD) ──────────────────────────────────────────────────
# All two-letter ISO 3166-1 based ccTLDs currently delegated in the root
# zone (e.g. .ua, .ru, .de, .fr, .uk), plus the exceptionally reserved .eu.
# IANA reserves every two-letter string exclusively for ccTLD use, so
# length == 2 is a reliable, authoritative classifier (~250 entries).
TLD_COUNTRY_CODE: List[str] = [
    "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar", "as", "at", "au",
    "aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bm", "bn",
    "bo", "br", "bs", "bt", "bv", "bw", "by", "bz", "ca", "cc", "cd", "cf", "cg", "ch",
    "ci", "ck", "cl", "cm", "cn", "co", "cr", "cu", "cv", "cw", "cx", "cy", "cz", "de",
    "dj", "dk", "dm", "do", "dz", "ec", "ee", "eg", "er", "es", "et", "eu", "fi", "fj",
    "fk", "fm", "fo", "fr", "ga", "gb", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm",
    "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht",
    "hu", "id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it", "je", "jm", "jo",
    "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz", "la", "lb",
    "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mg",
    "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw",
    "mx", "my", "mz", "na", "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu",
    "nz", "om", "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt",
    "pw", "py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg",
    "sh", "si", "sj", "sk", "sl", "sm", "sn", "so", "sr", "ss", "st", "su", "sv", "sx",
    "sy", "sz", "tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", "tr",
    "tt", "tv", "tw", "tz", "ua", "ug", "uk", "us", "uy", "uz", "va", "vc", "ve", "vg",
    "vi", "vn", "vu", "wf", "ws", "ye", "yt", "za", "zm", "zw",
]

# ── Sponsored TLDs (sTLD) ──────────────────────────────────────────────────────
# Restricted TLDs backed by a sponsoring organisation representing a
# specific community. ``int`` is included alongside the community-specific
# strings since IANA classifies it as sponsored as well.
TLD_SPONSORED: List[str] = [
    "aero", "asia", "cat", "coop", "edu", "gov", "int", "jobs", "mil",
    "museum", "post", "tel", "travel", "xxx",
]

# ── Infrastructure domains ─────────────────────────────────────────────────────
# Reserved for Internet infrastructure use only (reverse DNS, ENUM, etc.).
TLD_INFRASTRUCTURE: List[str] = ["arpa"]

# ── Restricted generic domains ─────────────────────────────────────────────────
# Generic TLDs with registration restrictions tighter than open gTLDs.
TLD_RESTRICTED_GENERIC: List[str] = ["biz", "name", "pro"]

# ── Test / developer domains ───────────────────────────────────────────────────
# RFC 2606 / RFC 6761 special-use names reserved for documentation and
# local testing (never delegated in the root zone, so they can't collide
# with a real registration, but attackers and internal tooling both use
# them for staging look-alike infrastructure). IANA's historical root-zone
# "test" TLD type (the 2007 IDN ccTLD fast-track test strings) has since
# been retired/removed from the root, so these RFC-reserved names are the
# actual "test domains" developers rely on today.
TLD_TEST: List[str] = ["test", "example", "invalid", "localhost"]

# ── IDN (Internationalized Domain Name) TLDs ───────────────────────────────────
# Every currently delegated IDN TLD, in its ASCII-Compatible Encoding (ACE /
# punycode "xn--" form), spanning Chinese (Simplified & Traditional), Arabic,
# Cyrillic, Devanagari and other Indic scripts, Thai, Lao, Korean Hangul,
# Armenian, Georgian, Greek, Japanese and more. The ACE form is what's
# actually registered/resolved in DNS, so it's what gets searched; the
# Unicode form (for display / homograph matching) is derived below.
TLD_IDN: List[str] = [
    "xn--11b4c3d", "xn--1ck2e1b", "xn--1qqw23a", "xn--2scrj9c", "xn--30rr7y",
    "xn--3bst00m", "xn--3ds443g", "xn--3e0b707e", "xn--3hcrj9c", "xn--3pxu8k",
    "xn--42c2d9a", "xn--45br5cyl", "xn--45brj9c", "xn--45q11c", "xn--4dbrk0ce",
    "xn--4gbrim", "xn--54b7fta0cc", "xn--55qw42g", "xn--55qx5d", "xn--5su34j936bgsg",
    "xn--5tzm5g", "xn--6frz82g", "xn--6qq986b3xl", "xn--80adxhks", "xn--80ao21a",
    "xn--80aqecdr1a", "xn--80asehdb", "xn--80aswg", "xn--8y0a063a", "xn--90a3ac",
    "xn--90ae", "xn--90ais", "xn--9dbq2a", "xn--9et52u", "xn--9krt00a",
    "xn--b4w605ferd", "xn--bck1b9a5dre4c", "xn--c1avg", "xn--c2br7g", "xn--cck2b3b",
    "xn--cckwcxetd", "xn--cg4bki", "xn--clchc0ea0b2g2a9gcd", "xn--czr694b",
    "xn--czrs0t", "xn--czru2d", "xn--d1acj3b", "xn--d1alf", "xn--e1a4c",
    "xn--eckvdtc9d", "xn--efvy88h", "xn--fct429k", "xn--fhbei", "xn--fiq228c5hs",
    "xn--fiq64b", "xn--fiqs8s", "xn--fiqz9s", "xn--fjq720a", "xn--flw351e",
    "xn--fpcrj9c3d", "xn--fzc2c9e2c", "xn--fzys8d69uvgm", "xn--g2xx48c",
    "xn--gckr3f0f", "xn--gecrj9c", "xn--gk3at1e", "xn--h2breg3eve", "xn--h2brj9c",
    "xn--h2brj9c8c", "xn--hxt814e", "xn--i1b6b1a6a2e", "xn--imr513n", "xn--io0a7i",
    "xn--j1aef", "xn--j1amh", "xn--j6w193g", "xn--jlq480n2rg", "xn--jvr189m",
    "xn--kcrx77d1x4a", "xn--kprw13d", "xn--kpry57d", "xn--kput3i", "xn--l1acc",
    "xn--lgbbat1ad8j", "xn--mgb9awbf", "xn--mgba3a3ejt", "xn--mgba3a4f16a",
    "xn--mgba7c0bbn0a", "xn--mgbaam7a8h", "xn--mgbab2bd", "xn--mgbah1a3hjkrd",
    "xn--mgbai9azgqp6j", "xn--mgbayh7gpa", "xn--mgbbh1a", "xn--mgbbh1a71e",
    "xn--mgbc0a9azcg", "xn--mgbca7dzdo", "xn--mgbcpq6gpa1a", "xn--mgberp4a5d4ar",
    "xn--mgbgu82a", "xn--mgbi4ecexp", "xn--mgbpl2fh", "xn--mgbt3dhd", "xn--mgbtx2b",
    "xn--mgbx4cd0ab", "xn--mix891f", "xn--mk1bu44c", "xn--mxtq1m", "xn--ngbc5azd",
    "xn--ngbe9e0a", "xn--ngbrx", "xn--node", "xn--nqv7f", "xn--nqv7fs00ema",
    "xn--nyqy26a", "xn--o3cw4h", "xn--ogbpf8fl", "xn--otu796d", "xn--p1acf",
    "xn--p1ai", "xn--pgbs0dh", "xn--pssy2u", "xn--q7ce6a", "xn--q9jyb4c",
    "xn--qcka1pmc", "xn--qxa6a", "xn--qxam", "xn--rhqv96g", "xn--rovu88b",
    "xn--rvc1e0am3e", "xn--s9brj9c", "xn--ses554g", "xn--t60b56a", "xn--tckwe",
    "xn--tiq49xqyj", "xn--unup4y", "xn--vermgensberater-ctb",
    "xn--vermgensberatung-pwb", "xn--vhquv", "xn--vuq861b", "xn--w4r85el8fhu5dnra",
    "xn--w4rs40l", "xn--wgbh1c", "xn--wgbl6a", "xn--xhq521b", "xn--xkc2al3hye2a",
    "xn--xkc2dl3a5ee0h", "xn--y9a3aq", "xn--yfro4i67o", "xn--ygbi2ammx", "xn--zfr164b",
]

# Punycode (ACE) -> native Unicode rendering, decoded from TLD_IDN via the
# standard IDNA codec so variants built from these TLDs can be flagged
# ``is_idn`` and carry a human-readable ``unicode_form`` (see _emit()).
TLD_IDN_UNICODE_MAP: Dict[str, str] = {
    "xn--11b4c3d": "कॉम",
    "xn--1ck2e1b": "セール",
    "xn--1qqw23a": "佛山",
    "xn--2scrj9c": "ಭಾರತ",
    "xn--30rr7y": "慈善",
    "xn--3bst00m": "集团",
    "xn--3ds443g": "在线",
    "xn--3e0b707e": "한국",
    "xn--3hcrj9c": "ଭାରତ",
    "xn--3pxu8k": "点看",
    "xn--42c2d9a": "คอม",
    "xn--45br5cyl": "ভাৰত",
    "xn--45brj9c": "ভারত",
    "xn--45q11c": "八卦",
    "xn--4dbrk0ce": "ישראל",
    "xn--4gbrim": "موقع",
    "xn--54b7fta0cc": "বাংলা",
    "xn--55qw42g": "公益",
    "xn--55qx5d": "公司",
    "xn--5su34j936bgsg": "香格里拉",
    "xn--5tzm5g": "网站",
    "xn--6frz82g": "移动",
    "xn--6qq986b3xl": "我爱你",
    "xn--80adxhks": "москва",
    "xn--80ao21a": "қаз",
    "xn--80aqecdr1a": "католик",
    "xn--80asehdb": "онлайн",
    "xn--80aswg": "сайт",
    "xn--8y0a063a": "联通",
    "xn--90a3ac": "срб",
    "xn--90ae": "бг",
    "xn--90ais": "бел",
    "xn--9dbq2a": "קום",
    "xn--9et52u": "时尚",
    "xn--9krt00a": "微博",
    "xn--b4w605ferd": "淡马锡",
    "xn--bck1b9a5dre4c": "ファッション",
    "xn--c1avg": "орг",
    "xn--c2br7g": "नेट",
    "xn--cck2b3b": "ストア",
    "xn--cckwcxetd": "アマゾン",
    "xn--cg4bki": "삼성",
    "xn--clchc0ea0b2g2a9gcd": "சிங்கப்பூர்",
    "xn--czr694b": "商标",
    "xn--czrs0t": "商店",
    "xn--czru2d": "商城",
    "xn--d1acj3b": "дети",
    "xn--d1alf": "мкд",
    "xn--e1a4c": "ею",
    "xn--eckvdtc9d": "ポイント",
    "xn--efvy88h": "新闻",
    "xn--fct429k": "家電",
    "xn--fhbei": "كوم",
    "xn--fiq228c5hs": "中文网",
    "xn--fiq64b": "中信",
    "xn--fiqs8s": "中国",
    "xn--fiqz9s": "中國",
    "xn--fjq720a": "娱乐",
    "xn--flw351e": "谷歌",
    "xn--fpcrj9c3d": "భారత్",
    "xn--fzc2c9e2c": "ලංකා",
    "xn--fzys8d69uvgm": "電訊盈科",
    "xn--g2xx48c": "购物",
    "xn--gckr3f0f": "クラウド",
    "xn--gecrj9c": "ભારત",
    "xn--gk3at1e": "通販",
    "xn--h2breg3eve": "भारतम्",
    "xn--h2brj9c": "भारत",
    "xn--h2brj9c8c": "भारोत",
    "xn--hxt814e": "网店",
    "xn--i1b6b1a6a2e": "संगठन",
    "xn--imr513n": "餐厅",
    "xn--io0a7i": "网络",
    "xn--j1aef": "ком",
    "xn--j1amh": "укр",
    "xn--j6w193g": "香港",
    "xn--jlq480n2rg": "亚马逊",
    "xn--jvr189m": "食品",
    "xn--kcrx77d1x4a": "飞利浦",
    "xn--kprw13d": "台湾",
    "xn--kpry57d": "台灣",
    "xn--kput3i": "手机",
    "xn--l1acc": "мон",
    "xn--lgbbat1ad8j": "الجزائر",
    "xn--mgb9awbf": "عمان",
    "xn--mgba3a3ejt": "ارامكو",
    "xn--mgba3a4f16a": "ایران",
    "xn--mgba7c0bbn0a": "العليان",
    "xn--mgbaam7a8h": "امارات",
    "xn--mgbab2bd": "بازار",
    "xn--mgbah1a3hjkrd": "موريتانيا",
    "xn--mgbai9azgqp6j": "پاکستان",
    "xn--mgbayh7gpa": "الاردن",
    "xn--mgbbh1a": "بارت",
    "xn--mgbbh1a71e": "بھارت",
    "xn--mgbc0a9azcg": "المغرب",
    "xn--mgbca7dzdo": "ابوظبي",
    "xn--mgbcpq6gpa1a": "البحرين",
    "xn--mgberp4a5d4ar": "السعودية",
    "xn--mgbgu82a": "ڀارت",
    "xn--mgbi4ecexp": "كاثوليك",
    "xn--mgbpl2fh": "سودان",
    "xn--mgbt3dhd": "همراه",
    "xn--mgbtx2b": "عراق",
    "xn--mgbx4cd0ab": "مليسيا",
    "xn--mix891f": "澳門",
    "xn--mk1bu44c": "닷컴",
    "xn--mxtq1m": "政府",
    "xn--ngbc5azd": "شبكة",
    "xn--ngbe9e0a": "بيتك",
    "xn--ngbrx": "عرب",
    "xn--node": "გე",
    "xn--nqv7f": "机构",
    "xn--nqv7fs00ema": "组织机构",
    "xn--nyqy26a": "健康",
    "xn--o3cw4h": "ไทย",
    "xn--ogbpf8fl": "سورية",
    "xn--otu796d": "招聘",
    "xn--p1acf": "рус",
    "xn--p1ai": "рф",
    "xn--pgbs0dh": "تونس",
    "xn--pssy2u": "大拿",
    "xn--q7ce6a": "ລາວ",
    "xn--q9jyb4c": "みんな",
    "xn--qcka1pmc": "グーグル",
    "xn--qxa6a": "ευ",
    "xn--qxam": "ελ",
    "xn--rhqv96g": "世界",
    "xn--rovu88b": "書籍",
    "xn--rvc1e0am3e": "ഭാരതം",
    "xn--s9brj9c": "ਭਾਰਤ",
    "xn--ses554g": "网址",
    "xn--t60b56a": "닷넷",
    "xn--tckwe": "コム",
    "xn--tiq49xqyj": "天主教",
    "xn--unup4y": "游戏",
    "xn--vermgensberater-ctb": "vermögensberater",
    "xn--vermgensberatung-pwb": "vermögensberatung",
    "xn--vhquv": "企业",
    "xn--vuq861b": "信息",
    "xn--w4r85el8fhu5dnra": "嘉里大酒店",
    "xn--w4rs40l": "嘉里",
    "xn--wgbh1c": "مصر",
    "xn--wgbl6a": "قطر",
    "xn--xhq521b": "广东",
    "xn--xkc2al3hye2a": "இலங்கை",
    "xn--xkc2dl3a5ee0h": "இந்தியா",
    "xn--y9a3aq": "հայ",
    "xn--yfro4i67o": "新加坡",
    "xn--ygbi2ammx": "فلسطين",
    "xn--zfr164b": "政务",
}

# Every real TLD known above, deduplicated in category order. Backs the
# "all" / "full1500" presets so a rule can search the entire root zone.
TLD_ALL: List[str] = (
    TLD_GENERIC
    + TLD_COUNTRY_CODE
    + TLD_SPONSORED
    + TLD_RESTRICTED_GENERIC
    + TLD_INFRASTRUCTURE
    + TLD_TEST
    + TLD_IDN
)


def _build_tier(base: List[str], pool: List[str], size: int) -> List[str]:
    """Extend *base* with items from *pool* (skipping dupes) up to *size*."""
    result = list(dict.fromkeys(base))
    for item in pool:
        if len(result) >= size:
            break
        if item not in result:
            result.append(item)
    return result


# top500: TOP100 topped up with more generic + country-code TLDs.
TLD_TOP500: List[str] = _build_tier(
    TLD_TOP100, TLD_GENERIC + TLD_COUNTRY_CODE, 500
)
# full1500: the complete, comprehensive TLD universe (all categories above).
TLD_FULL1500: List[str] = TLD_ALL

TLD_LISTS: Dict[str, List[str]] = {
    "top30": TLD_TOP30,
    "top100": TLD_TOP100,
    "top500": TLD_TOP500,
    "full1500": TLD_FULL1500,
    "generic": TLD_GENERIC,
    "country_code": TLD_COUNTRY_CODE,
    "sponsored": TLD_SPONSORED,
    "infrastructure": TLD_INFRASTRUCTURE,
    "restricted_generic": TLD_RESTRICTED_GENERIC,
    "test": TLD_TEST,
    "idn": TLD_IDN,
    "all": TLD_ALL,
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
    tld_list: str = "top100"               # top30|top100|top500|full1500|
                                            # generic|country_code|sponsored|
                                            # infrastructure|restricted_generic|
                                            # test|idn|all
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
            # Auto-detect TLD swaps onto a real IDN (xn--) TLD, e.g. ALG-12
            # picking "xn--p1ai" from the idn/full1500/all TLD presets, so
            # these variants are flagged consistently with ALG-17/ALG-18.
            if not is_idn and not unicode_form:
                idn_tld_unicode = TLD_IDN_UNICODE_MAP.get(tld.lower())
                if idn_tld_unicode:
                    is_idn = True
                    unicode_form = f"{label}.{idn_tld_unicode}"
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
