"""Scam message detector: reads the TEXT of an SMS or WhatsApp-style message.

It never opens links, never calls numbers and never replies. It is rule-based
(word lists and patterns), not AI. It knows English and some common Hinglish phrases.
Links inside the message are checked with the URL scanner from Phase 3, and
several helpers are shared with the email analyzer from Phase 4.
The score is the total of the points of the warning signs found.
"""
import re
from urllib.parse import urlsplit

from services.email_analyzer import (
    GENERIC_GREETINGS,
    LINK_PATTERN,
    MAX_DETAILS_SHOWN,
    NEGATIONS,
    RISKY_LINK_SCORE,
    SOCIAL_PHRASES,
    SUSPICIOUS_LINK_SCORE,
    URGENCY_PHRASES,
    check_links,
    describe_link,
    find_links,
    find_phrases,
    find_secret_request,
    normalize,
)
from services.risk_engine import (
    calculate_score,
    get_risk_level,
    make_indicator,
    summarize_result,
)
from services.url_scanner import OFFICIAL_DOMAINS, URL_SHORTENERS, is_ip_host, split_host

MIN_MESSAGE_LENGTH = 8
MAX_MESSAGE_LENGTH = 3000
PREVIEW_LENGTH = 50  # how many characters of the message are kept as a label

# ---------- The rules: how many points each warning sign adds ----------
POINTS = {
    "otp_request": 30,
    "brand_link_mismatch": 30,
    "payment_request": 25,
    "app_install": 30,
    "authority_impersonation": 25,
    "suspicious_links": 25,   # at least one link scored Medium or higher in the URL scanner
    "account_threats": 20,
    "reward_scam": 20,
    "job_scam": 20,
    "urgency": 15,
    "delivery_scam": 15,
    "shortened_link": 15,
    "social_engineering": 15,
    "generic_greeting": 10,
    "risky_links": 10,        # the worst link scored Low
}

# ---------- Word lists (all lower case, English and some Hinglish) ----------
OTP_PHRASES = [
    "send otp", "share otp", "forward otp", "tell me the otp", "give me the otp",
    "otp batao", "otp bhejo", "otp share karo", "otp dijiye", "pin batao",
]

ACCOUNT_THREAT_PHRASES = [
    "will be blocked", "will be suspended", "will be deactivated",
    "will be disconnected", "will be closed", "has been blocked",
    "has been suspended", "is blocked", "is suspended", "kyc expired",
    "kyc has expired", "kyc is expired", "kyc pending", "kyc update",
    "kyc is not updated", "update your kyc", "complete your kyc",
    "pan is not linked", "service will be stopped", "last warning",
    "band ho jayega", "block ho jayega", "suspend ho jayega",
]

AUTHORITY_PHRASES = [
    "income tax department", "income tax dept", "trai", "rbi", "cbi",
    "cyber cell", "cyber crime", "customs department", "customs officer",
    "narcotics", "enforcement directorate", "digital arrest", "police",
    "arrest", "court", "warrant", "money laundering", "illegal items",
    "bank manager",
]

PAYMENT_PHRASES = [
    "gift card", "gift cards", "bitcoin", "crypto", "usdt", "western union",
    "moneygram", "wire transfer", "collect request", "payment request",
    "scan this qr", "scan the qr", "scan qr", "qr code to receive",
    "accept the request", "approve the request", "upi request",
    "refundable deposit", "security deposit", "registration fee",
    "processing fee", "token amount", "advance payment", "bank details",
    "send money", "money transfer", "paise bhejo", "paisa bhejo",
    "paise transfer karo", "paise send karo",
]

# "pay a small fee", "send rs 500", "pay the fine" ...
PAYMENT_PATTERN = re.compile(
    r"\b(?:send|transfer|pay|deposit|remit|wire)\b(?:\W+\w+){0,3}?\W+"
    r"(?:rs|inr|money|funds|fee|fees|deposit|tax|charges|amount|fine)(?!\w)"
)

REWARD_PHRASES = [
    "you have won", "you've won", "you won", "lucky winner", "lucky draw",
    "lottery", "lottery lagi", "kbc", "jackpot", "cash prize", "prize money",
    "claim your prize", "claim your reward", "claim your gift", "free gift",
    "free recharge", "you have been selected", "you are selected", "inaam",
    "jeet gaye",
]

JOB_PHRASES = [
    "work from home", "part time job", "part-time job", "online job",
    "easy money", "earn money from home", "daily income", "daily payment",
    "no experience needed", "no interview", "like and earn", "review and earn",
    "typing job", "data entry job", "earn up to", "earn rs",
    "ghar baithe kamao", "ghar baithe paise",
]

DELIVERY_PHRASES = [
    "delivery failed", "could not be delivered", "couldn't be delivered",
    "package on hold", "parcel on hold", "customs fee", "customs duty",
    "address incomplete", "incomplete address", "update your address",
    "reschedule your delivery", "reschedule delivery", "redeliver",
    "delivery fee", "unable to deliver",
]

APP_PHRASES = [
    "anydesk", "teamviewer", "quicksupport", "rustdesk", "install this app",
    "install the app", "download this app", "download the app",
    "install the apk", "download the apk", "enable accessibility",
    "screen sharing", "share your screen", "remote access",
]
APK_PATTERN = re.compile(r"\.apk\b")

# The urgency and social lists from the email analyzer, plus phrases common in messages
URGENT_MESSAGE_PHRASES = URGENCY_PHRASES + [
    "today itself", "tonight", "before midnight", "last date", "click now",
    "turant", "jaldi se", "abhi karo", "aaj hi",
]
SOCIAL_MESSAGE_PHRASES = SOCIAL_PHRASES + [
    "hi mum", "hi mom", "hi dad", "new number", "lost my phone", "wrong number",
    "do you remember me", "i need your help", "can you do me a favour",
    "can you do me a favor", "hello dear", "hi dear",
]

# What people write in a message -> the name used in OFFICIAL_DOMAINS (url_scanner.py)
BRAND_ALIASES = {
    "paypal": "paypal", "google": "google", "microsoft": "microsoft",
    "apple": "apple", "amazon": "amazon", "facebook": "facebook",
    "instagram": "instagram", "whatsapp": "whatsapp", "netflix": "netflix",
    "paytm": "paytm", "phonepe": "phonepe", "sbi": "sbi", "state bank": "sbi",
    "hdfc": "hdfcbank", "icici": "icicibank", "irctc": "irctc",
}

# Web addresses typed without http:// , like  bit.ly/3xYz  or  sbi-kyc-update.com
BARE_LINK_PATTERN = re.compile(
    r"(?<![@\w.-])(?:[a-z0-9-]+\.)+"
    r"(?:com|net|org|in|co|info|biz|xyz|top|click|link|live|online|site|shop|store|"
    r"app|me|io|ly|gl|ws|cc|tk|ml|ga|cf|gq|icu|buzz|us|uk)"
    r"(?![\w@-])(?:/[^\s<>\"')\]]*)?",
    re.IGNORECASE,
)

# "share the verification code", "send the 6-digit code" ...
CODE_PATTERN = re.compile(
    r"\b(?:enter|send|share|provide|give|tell|forward|reply with|read out)\b(?:\W+\w+){0,4}?\W+"
    r"(?:verification|security|confirmation|login|one[- ]time|\d[- ]digit)\W+code\b"
)

# ---------- Texts shown to the user ----------
WHY = {
    "otp_request": "An OTP or PIN is the last lock on your money. Real banks and companies never ask you to send it by message or phone.",
    "brand_link_mismatch": "The message uses the name of a known company, but the link goes to a different website. That is how fake pages are made.",
    "payment_request": "Scammers ask for money, fees, deposits or QR payments because they are hard to trace and hard to get back.",
    "app_install": "Apps from links can take over your phone and your bank app. Remote-access apps let a scammer see your screen.",
    "authority_impersonation": "Scammers pretend to be police, tax or government officers to frighten you. Real offices do not threaten people by message.",
    "suspicious_links": "Scam messages lead you to fake websites. The link checker found strong warning signs in a link.",
    "risky_links": "The link checker found some warning signs in a link, so be careful before opening it.",
    "account_threats": "Threats that your account, card, SIM or KYC will be blocked are used to scare you into clicking or paying.",
    "reward_scam": "Prize and lottery messages are a very common trick to get your details or a fee.",
    "job_scam": "Fake job offers promise easy money, then ask for a fee or for paid 'tasks'.",
    "urgency": "Scammers rush you so you do not stop to think or check.",
    "delivery_scam": "Fake delivery messages ask for a small fee or an address update on a fake page.",
    "shortened_link": "A short link hides where it really goes, and this check cannot open it to find out.",
    "social_engineering": "Messages like 'Hi Mum, this is my new number' or 'keep this secret' are used to build trust or stop you from checking.",
    "generic_greeting": "Real companies usually use your name. 'Dear customer' is a sign of a mass message.",
}

ADVICE_BY_CODE = {
    "otp_request": "Never share an OTP, PIN or password. Real banks never ask for them by message or phone.",
    "brand_link_mismatch": "Do not use the link. Open the official app or type the website address yourself.",
    "payment_request": "Do not send money or accept a payment request because of a message. Check with the person or company in another way.",
    "app_install": "Do not install apps from links in messages. Apps from outside the official app store can steal your data.",
    "authority_impersonation": "Real police, tax or government offices do not threaten people by message or ask for money. Contact the office yourself.",
    "suspicious_links": "Do not click the links. Open the official website or app yourself.",
    "risky_links": "Do not click links in this message until you are sure who sent it.",
    "account_threats": "Check your account by opening your official app or website yourself, not through the message.",
    "reward_scam": "You cannot win a contest you did not enter. Ignore prize messages like this.",
    "job_scam": "Real employers do not ask you to pay a fee or do paid 'tasks'. Check the company on its official website.",
    "urgency": "Slow down. Scammers rush you so you do not check.",
    "delivery_scam": "Check your parcel in the courier's official app or website, not through the link in the message.",
    "shortened_link": "Short links hide the real address. Do not open them if you do not know the sender.",
    "social_engineering": "Check the request by calling the person on the number you already have.",
    "generic_greeting": "Be careful with messages that do not use your name.",
}

ADVICE_BY_LEVEL = {
    "Safe": [
        "No strong warning signs were found, but this check only reads the text. "
        "Never share an OTP or PIN with anyone, even if a message looks real.",
    ],
    "Low": [
        "Be careful. Do not click links or call numbers in the message until you are sure it is real.",
        "If it says it is from your bank or a company, contact them using the number on their official website or your card.",
    ],
    "Medium": [
        "Do not click any link in this message.",
        "Do not reply, and do not share any OTP, PIN or card details.",
        "Check with the company or person using a phone number or app you already trust.",
    ],
    "High": [
        "Do not click any link, call any number or reply.",
        "Never share an OTP, PIN or password, even with someone who says they are from your bank.",
        "If you already shared an OTP or paid money, call your bank right away to block the payment or card, "
        "and report it to your country's cybercrime reporting service.",
        "Block the sender and delete the message.",
    ],
}
ADVICE_BY_LEVEL["Critical"] = ADVICE_BY_LEVEL["High"]

SCAN_NOTE = (
    "The checker only reads the text of the message. It never opens links, calls numbers or replies, "
    "so a low score does not prove a message is safe."
)


class MessageError(ValueError):
    """The text is not a message we can check. The message is safe to show to the user."""


# ---------- Step 1: read and clean the message ----------
def clean_message_text(raw_text):
    """Check the pasted text. Raises MessageError if it cannot be checked."""
    text = (raw_text or "").strip()
    if not text:
        raise MessageError("Please paste the message you want to check.")
    if len(text) < MIN_MESSAGE_LENGTH:
        raise MessageError("That is too short to check. Please paste the whole message.")
    if len(text) > MAX_MESSAGE_LENGTH:
        raise MessageError(f"That message is too long. The limit is {MAX_MESSAGE_LENGTH:,} characters.")
    # Remove hidden control characters but keep line breaks and tabs
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)


def build_target(text):
    """The short label saved with the scan: the start of the message, with long numbers hidden.

    Pasted messages often contain real OTPs or phone numbers, so any run of 4 or more
    digits is replaced by **** before anything is saved. The rest of the message is never saved.
    """
    preview = re.sub(r"\s+", " ", text).strip()
    preview = re.sub(r"\d{4,}", "****", preview)
    if len(preview) > PREVIEW_LENGTH:
        preview = preview[:PREVIEW_LENGTH].rstrip() + "..."
    return f"Message: {preview}"


# ---------- Step 2: small helper checks ----------
def find_requests(text, phrases):
    """Phrases that ask for something. "never send otp" does not count: that is advice."""
    found = []
    for phrase in find_phrases(text, phrases):
        for match in re.finditer(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", text):
            before = text[max(0, match.start() - 40):match.start()]
            if not any(word in before for word in NEGATIONS):
                found.append(phrase)
                break
    return found


def find_code_request(text):
    """A request for a verification or login code, or None."""
    for match in CODE_PATTERN.finditer(text):
        before = text[max(0, match.start() - 40):match.start()]
        if not any(word in before for word in NEGATIONS):
            return match.group(0)
    return None


def find_payment_request(text):
    """Words that ask for money, fees, deposits or QR payments."""
    found = find_phrases(text, PAYMENT_PHRASES)
    match = PAYMENT_PATTERN.search(text)
    if match and not any(phrase in match.group(0) for phrase in found):
        found.append(match.group(0))
    return found


def find_app_install(text):
    """Words about installing an app or giving remote access."""
    found = find_phrases(text, APP_PHRASES)
    if APK_PATTERN.search(text):
        found.append(".apk file")
    return found


def find_message_links(text):
    """The web addresses in the message, with or without http://, without repeats."""
    links = find_links(text)
    remaining = LINK_PATTERN.sub(" ", text)  # so the same address is not found twice
    for match in BARE_LINK_PATTERN.finditer(remaining):
        link = "https://" + match.group(0).rstrip(".,;:!?")  # no http:// typed: do not punish a missing HTTPS
        if link not in links:
            links.append(link)
    return links


def link_main_domain(link):
    """The main domain of a link, for example 'bit.ly'. An IP number is returned as it is."""
    host = (urlsplit(link).hostname or "").rstrip(".")
    return host if is_ip_host(host) else split_host(host)[1]


def find_brand_mismatch(lowered_text, links):
    """(name used, domain the link goes to) if the message names a known company but links elsewhere."""
    for alias, brand in BRAND_ALIASES.items():
        if not find_phrases(lowered_text, [alias]):
            continue
        for link in links:
            domain = link_main_domain(link)
            if domain not in OFFICIAL_DOMAINS[brand]:
                return alias, domain
    return None


# ---------- Step 3: find the warning signs ----------
def find_warning_signs(text):
    """Return (signs, links_checked). Each sign is a dictionary made by make_indicator()."""
    signs = []

    def add(code, label, details=None):
        sign = make_indicator(code, label, POINTS[code], WHY[code])
        if details:
            sign["details"] = details
        signs.append(sign)

    lowered = normalize(text)

    # Asking for an OTP, PIN or code
    asked = []
    secret = find_secret_request(lowered)
    if secret:
        asked.append(secret)
    code_request = find_code_request(lowered)
    if code_request:
        asked.append(code_request)
    asked += [phrase for phrase in find_requests(lowered, OTP_PHRASES) if phrase not in asked]
    if asked:
        add("otp_request", "Asks for an OTP, PIN or password: " + ", ".join(f'"{item}"' for item in asked[:3]))

    # Asking for money or an app
    money = find_payment_request(lowered)
    if money:
        add("payment_request", "Asks for money or payment details: " + ", ".join(money[:4]))
    apps = find_app_install(lowered)
    if apps:
        add("app_install", "Asks you to install an app or give remote access: " + ", ".join(apps[:3]))

    # Who the message pretends to be, and what it threatens, offers or says
    for code, phrases, label in (
        ("authority_impersonation", AUTHORITY_PHRASES, "Mentions police, tax or government officers"),
        ("account_threats", ACCOUNT_THREAT_PHRASES, "Threatens to block your account, card or KYC"),
        ("reward_scam", REWARD_PHRASES, "Offers a prize or lottery win"),
        ("job_scam", JOB_PHRASES, "Offers an easy job or income"),
        ("delivery_scam", DELIVERY_PHRASES, "Talks about a failed delivery or a delivery fee"),
        ("urgency", URGENT_MESSAGE_PHRASES, "Pushes you to act quickly"),
        ("social_engineering", SOCIAL_MESSAGE_PHRASES, "Uses a trust or secrecy trick"),
        ("generic_greeting", GENERIC_GREETINGS, "Uses a generic greeting"),
    ):
        found = find_phrases(lowered, phrases)
        if found:
            add(code, f"{label}: " + ", ".join(found[:4]))

    # Links, checked with the URL scanner
    links = find_message_links(text)
    checked = check_links(links)

    mismatch = find_brand_mismatch(lowered, links)
    if mismatch:
        alias, domain = mismatch
        add("brand_link_mismatch", f"The message mentions '{alias}', but its link goes to {domain}")

    shortened = [link for link in links if link_main_domain(link) in URL_SHORTENERS]
    if shortened:
        add("shortened_link", "The message has a shortened link", [link[:120] for link in shortened[:MAX_DETAILS_SHOWN]])

    if checked:
        worst = max(item["score"] for item in checked)
        dangerous = [item for item in checked if item["score"] >= RISKY_LINK_SCORE]
        details = [describe_link(item) for item in dangerous[:MAX_DETAILS_SHOWN]]
        if worst >= SUSPICIOUS_LINK_SCORE:
            add("suspicious_links", "A link in the message looks dangerous", details)
        elif worst >= RISKY_LINK_SCORE:
            add("risky_links", "A link in the message has some warning signs", details)

    return signs, len(checked)


# ---------- Step 4: advice and the final result ----------
def get_recommendations(risk_level, codes):
    """Advice for the user: general advice for the level, then advice for each warning sign."""
    advice = list(ADVICE_BY_LEVEL.get(risk_level, []))
    for code in codes:
        line = ADVICE_BY_CODE.get(code)
        if line and line not in advice:
            advice.append(line)
    return advice


def analyze_message(raw_text):
    """Check one message and return the whole result. Raises MessageError for unusable text."""
    text = clean_message_text(raw_text)

    indicators, links_checked = find_warning_signs(text)
    indicators.sort(key=lambda item: item["points"], reverse=True)

    score = calculate_score(indicators)
    level = get_risk_level(score)

    return {
        "target": build_target(text),
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "explanation": summarize_result("message", score, level, len(indicators), SCAN_NOTE),
        "recommendations": get_recommendations(level, [item["code"] for item in indicators]),
        "links_checked": links_checked,
    }