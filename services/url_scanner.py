"""URL scanner: checks the TEXT of a link for warning signs.

It never opens the link and never contacts the website. It only reads the
characters of the address, so it is safe to use on dangerous links.
The score is the total of the points of the warning signs found (rule-based, no AI).
"""
import ipaddress
import re
from urllib.parse import urlsplit

from services.risk_engine import (
    calculate_score,
    get_risk_level,
    make_indicator,
    summarize_result,
)

MAX_URL_LENGTH = 2000   # longer text is refused
LONG_URL_LENGTH = 100   # a link longer than this is a warning sign
MANY_SUBDOMAINS = 3     # this many parts before the main domain is a warning sign

# ---------- The rules: how many points each warning sign adds ----------
POINTS = {
    "no_https": 15,
    "ip_address": 20,
    "keywords": 15,
    "subdomains": 10,
    "at_sign": 10,
    "lookalike_chars": 10,
    "long_url": 10,
    "shortener": 10,
    "risky_tld": 10,
    "brand_impersonation": 30,
}

# ---------- Lists the rules use ----------
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "verification", "secure", "account", "update",
    "confirm", "bank", "password", "wallet", "payment", "invoice", "unlock",
    "suspended", "recover", "billing", "prize", "reward",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
}

# Website endings that are cheap and used in many scams (many honest sites use them too)
RISKY_ENDINGS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "mov",
    "icu", "buzz", "loan", "work", "rest",
}

# Endings made of two parts, so "bbc.co.uk" counts as ONE main domain
TWO_PART_ENDINGS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.in", "org.in", "net.in", "gov.in", "ac.in", "nic.in", "co.jp",
    "com.br", "co.za", "com.cn", "co.nz", "com.sg",
}

# Well-known names and the real websites that belong to them (a small example list)
OFFICIAL_DOMAINS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.co.in"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "netflix": {"netflix.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "irctc": {"irctc.co.in"},
}

# Scammers swap letters for numbers: paypa1 -> paypal
DIGIT_TO_LETTER = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"})

# ---------- Texts shown to the user ----------
WHY = {
    "no_https": "HTTPS protects what you type. Without it, others on the network can read or change it. Many scam pages skip it.",
    "ip_address": "Real companies use names like example.com. Scammers often use plain numbers so nobody recognises the website.",
    "keywords": "Scam links often use words like login, verify or secure to make the page feel official.",
    "subdomains": "Scammers put many parts in front of the real domain so the link looks like a known website.",
    "at_sign": "A browser ignores everything before the @ sign and goes to what comes after it. Scammers use this to fake a trusted name.",
    "lookalike_chars": "Letters from other alphabets can look like English letters, so a fake address can look exactly like a real one.",
    "long_url": "Very long links can hide the real destination far to the right, where people do not look.",
    "shortener": "A short link hides where it really goes, and this check cannot open it to find out.",
    "risky_tld": "Some website endings are cheap or free and are used in many scams. Honest sites use them too, so this is only a small clue.",
    "brand_impersonation": "The address uses the name of a well-known company, but the website belongs to someone else.",
}

ADVICE_BY_CODE = {
    "no_https": "Never type a password or card number on a page that does not use HTTPS.",
    "ip_address": "Be suspicious of links that are only numbers. Real services use names.",
    "keywords": "Do not log in through a link. Open the official website by typing its address yourself.",
    "subdomains": "Check the main domain, which is the last two parts of the website name. Anyone can make up everything before it.",
    "at_sign": "Ignore everything before the @ sign. The real website is what comes after it.",
    "lookalike_chars": "Type the website address yourself instead of using this link.",
    "long_url": "Look at the beginning of the address to see the real website, and ignore the long tail.",
    "shortener": "Ask the sender for the full link, or use a link-expander service before opening a short link.",
    "risky_tld": "Check the website very carefully before you trust it.",
    "brand_impersonation": "Go to the real company's website by typing its address yourself, not through this link.",
}

ADVICE_BY_LEVEL = {
    "Safe": [
        "No strong warning signs were found, but this check only reads the text of the link. "
        "Open links from people you trust and be careful with passwords.",
    ],
    "Low": [
        "Be careful. Do not type passwords or card details unless you are sure about the website.",
        "If the link came in a message, check with the sender in another way, such as a phone call.",
    ],
    "Medium": [
        "Do not open this link unless you can confirm it is real.",
        "Never type a password, OTP or card details on the page it leads to.",
        "If someone sent it to you, ask them in another way (for example by phone) if they really sent it.",
    ],
    "High": [
        "Do not open this link.",
        "If you already opened it, do not type any password, OTP or card details.",
        "If you already typed a password there, change it now and turn on two-step verification.",
        "Report the message that contained the link to your email provider, your bank or your country's "
        "cybercrime reporting service, then delete it.",
    ],
}
ADVICE_BY_LEVEL["Critical"] = ADVICE_BY_LEVEL["High"]

SCAN_NOTE = (
    "The checker only reads the text of the link and never opens the website, "
    "so a low score does not prove a link is safe."
)


class UrlError(ValueError):
    """The text is not a link we can check. The message is safe to show to the user."""


# ---------- Step 1: read and clean the link ----------
def parse_url(raw_url):
    """Check the text and split it into parts. Raises UrlError if it is not a usable link."""
    url = (raw_url or "").strip()

    if not url:
        raise UrlError("Please paste a link to check.")
    if len(url) > MAX_URL_LENGTH:
        raise UrlError(f"That link is too long. The limit is {MAX_URL_LENGTH} characters.")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise UrlError("A link cannot contain spaces or line breaks.")
    if "://" not in url:
        raise UrlError("Please start the link with http:// or https://")

    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise UrlError("That does not look like a valid link.")

    if parts.scheme not in ("http", "https"):
        raise UrlError("Only http:// and https:// links can be checked.")
    if not host:
        raise UrlError("That link has no website name in it.")

    return {
        "url": url,
        "scheme": parts.scheme,
        "host": host.rstrip("."),
        "netloc": parts.netloc.lower(),  # includes anything before an @ sign
        "port": port,
        "path": parts.path,
    }


# ---------- Step 2: small helper checks ----------
def is_ip_host(host):
    """True for 192.168.1.1, IPv6 addresses and number-only tricks like 3232235777."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return host.isdigit() or re.fullmatch(r"0x[0-9a-f]+", host) is not None


def split_host(host):
    """Split a website name into (subdomains, main domain, ending).

    "a.b.example.co.in" -> (["a", "b"], "example.co.in", "co.in")
    """
    labels = host.split(".")
    if len(labels) < 2:
        return [], host, ""

    if ".".join(labels[-2:]) in TWO_PART_ENDINGS and len(labels) >= 3:
        return labels[:-3], ".".join(labels[-3:]), ".".join(labels[-2:])
    return labels[:-2], ".".join(labels[-2:]), labels[-1]


def find_suspicious_words(host, path):
    """The suspicious words found in the website name and the path (each word counted once)."""
    text = (host + path).lower().replace("-", "")
    return [word for word in SUSPICIOUS_WORDS if word in text]


def has_lookalike_characters(host):
    """True for punycode (xn--) or letters outside the English alphabet."""
    return host.startswith("xn--") or ".xn--" in host or any(ord(ch) > 127 for ch in host)


def find_brand_impersonation(netloc, main_domain):
    """Name of a well-known company used in an address that does not belong to it, or None."""
    text = netloc.translate(DIGIT_TO_LETTER)
    pieces = re.split(r"[.\-@:]", text)

    for brand, official in OFFICIAL_DOMAINS.items():
        # Short names (like "sbi") must be a whole piece, or they would match inside other words
        mentioned = brand in text if len(brand) >= 5 else brand in pieces
        if mentioned and main_domain not in official:
            return brand
    return None


# ---------- Step 3: find the warning signs ----------
def find_warning_signs(parsed):
    """Return a list of warning signs. Each one is a dictionary made by make_indicator()."""
    host = parsed["host"]
    signs = []

    def add(code, text):
        signs.append(make_indicator(code, text, POINTS[code], WHY[code]))

    if parsed["scheme"] != "https":
        add("no_https", "The link does not use HTTPS")

    is_ip = is_ip_host(host)
    if is_ip:
        add("ip_address", "The address is an IP number, not a normal website name")
        subdomains, main_domain, ending = [], "", ""
    else:
        subdomains, main_domain, ending = split_host(host)

    words = find_suspicious_words(host, parsed["path"])
    if words:
        add("keywords", "Suspicious words found: " + ", ".join(words))

    if len(subdomains) >= MANY_SUBDOMAINS:
        add("subdomains", f"Too many subdomains ({len(subdomains)} parts before the main domain)")

    if "@" in parsed["netloc"]:
        add("at_sign", "The address contains an @ sign")

    if has_lookalike_characters(host):
        add("lookalike_chars", "The website name has letters that can look like other letters")

    if len(parsed["url"]) > LONG_URL_LENGTH:
        add("long_url", f"The link is {len(parsed['url'])} characters long")

    if main_domain in URL_SHORTENERS:
        add("shortener", "This is a link-shortener, so the real destination is hidden")

    if ending and ending.split(".")[-1] in RISKY_ENDINGS:
        add("risky_tld", f"The website ending .{ending.split('.')[-1]} is often used in scams")

    brand = find_brand_impersonation(parsed["netloc"], main_domain)
    if brand:
        add("brand_impersonation", f"The name '{brand}' is used, but this is not the real {brand} website")

    return signs


# ---------- Step 4: link details, advice and the final result ----------
def describe_parsed(parsed):
    """Facts about the link for the 'Link details' box. They do not add points."""
    host = parsed["host"]
    is_ip = is_ip_host(host)
    subdomains, main_domain, ending = ([], "", "") if is_ip else split_host(host)
    return {
        "protocol": parsed["scheme"],
        "host": host,
        "is_ip": is_ip,
        "main_domain": main_domain,
        "ending": ending,
        "subdomains": subdomains,
        "port": parsed["port"],
    }


def describe_url(url):
    """Link details for a saved link. Raises UrlError if the text is not a usable link."""
    return describe_parsed(parse_url(url))


def get_recommendations(risk_level, codes):
    """Advice for the user: general advice for the level, then advice for each warning sign."""
    advice = list(ADVICE_BY_LEVEL.get(risk_level, []))
    for code in codes:
        line = ADVICE_BY_CODE.get(code)
        if line and line not in advice:
            advice.append(line)
    return advice


def scan_url(raw_url):
    """Check one link and return the whole result. Raises UrlError for unusable text."""
    parsed = parse_url(raw_url)

    indicators = find_warning_signs(parsed)
    indicators.sort(key=lambda item: item["points"], reverse=True)

    score = calculate_score(indicators)
    level = get_risk_level(score)

    return {
        "url": parsed["url"],
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "details": describe_parsed(parsed),
        "explanation": summarize_result("link", score, level, len(indicators), SCAN_NOTE),
        "recommendations": get_recommendations(level, [item["code"] for item in indicators]),
    }